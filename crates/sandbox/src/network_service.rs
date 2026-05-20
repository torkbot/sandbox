use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::ToSocketAddrs;
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as StdInstant};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use crate::http_flow::HttpInterceptRuntime;
use crate::network::{CidrRange, OutboundRulePlan};

const HOST_HTTP_PROBE_PORT: u16 = 8080;
const HOST_HTTP_PORT: u16 = 80;
const HOST_HTTPS_PORT: u16 = 443;
const HOST_ALT_HTTPS_PORT: u16 = 8443;
const HOST_DNS_PORT: u16 = 53;
const HTTP_LISTENERS_PER_PORT: usize = 16;
const HTTP_SOCKET_BUFFER_BYTES: usize = 256 * 1024;
const TLS_READ_BUFFER_BYTES: usize = 16 * 1024;
const DNS_PACKET_BUFFER_BYTES: usize = 4096;
const DNS_PROTECTED_TEST_IP: [u8; 4] = [10, 1, 2, 3];
const DNS_PUBLIC_TEST_IP: [u8; 4] = [93, 184, 216, 34];
const NAT_FLOW_IDLE_TTL: Duration = Duration::from_secs(300);
const NAT_FLOW_CLOSING_TTL: Duration = Duration::from_secs(30);
const NETWORK_IDLE_WAKE_INTERVAL: Duration = Duration::from_millis(100);
const HOST_HTTP_PROBE_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-length: 25\r\nconnection: close\r\n\r\nsandbox explicit network\n";
const OUTBOUND_DENIED_RESPONSE: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\ncontent-length: 15\r\nconnection: close\r\n\r\noutbound denied";
static SPECIAL_USE_IPV4_RANGES: LazyLock<Vec<CidrRange>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
    ]
    .into_iter()
    .map(|range| CidrRange::parse(range).expect("valid special-use range"))
    .collect()
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTlsMetadata {
    pub server_name: Option<String>,
    pub alpn_protocol: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MitmTlsConfig {
    pub ca_certificate_pem: String,
    pub ca_private_key_pem: String,
}

/// Host-owned endpoint for libkrun's explicit virtio-net unixstream backend.
#[derive(Debug)]
pub struct HostNetwork {
    guest_fd: RawFd,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HostNetwork {
    pub fn new(
        tls_config: Option<MitmTlsConfig>,
        outbound_rules: Option<Vec<OutboundRulePlan>>,
        http: Option<Arc<dyn HttpInterceptRuntime>>,
    ) -> io::Result<Self> {
        let (host, guest) = UnixStream::pair()?;
        let tls_enabled = tls_config.is_some();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            run_network_service(
                host,
                worker_shutdown,
                tls_enabled,
                outbound_rules,
                http,
            )
        });
        Ok(Self {
            guest_fd: guest.into_raw_fd(),
            shutdown,
            worker: Some(worker),
        })
    }

    pub fn guest_fd(&self) -> RawFd {
        self.guest_fd
    }
}

impl Drop for HostNetwork {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_network_service(
    stream: UnixStream,
    shutdown: Arc<AtomicBool>,
    tls_enabled: bool,
    outbound_rules: Option<Vec<OutboundRulePlan>>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
) {
    let _ = stream.set_nonblocking(true);
    let tx = match stream.try_clone() {
        Ok(tx) => tx,
        Err(_) => return,
    };
    let mut device = LibkrunNetDevice::new(stream, tx, Ipv4Address::new(10, 0, 2, 1));
    let mut iface = Interface::new(
        Config::new(EthernetAddress([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xf0]).into()),
        &mut device,
        Instant::now(),
    );
    iface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::new(Ipv4Address::new(10, 0, 2, 1).into(), 24));
    });
    let mut sockets = SocketSet::new(Vec::new());
    let dns_handle = add_dns_socket(&mut sockets);
    let mut http_sockets = HashMap::new();
    let mut http_responses = HashMap::new();
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PORT);
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PROBE_PORT);
    if tls_enabled {
        add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);
        add_http_listener(&mut sockets, &mut http_sockets, HOST_ALT_HTTPS_PORT);
    }

    while !shutdown.load(Ordering::Acquire) {
        let timestamp = Instant::now();
        let _ = iface.poll(timestamp, &mut device, &mut sockets);
        poll_dns_socket(&mut sockets, dns_handle, outbound_rules.as_deref());
        device.nat.prune_expired_flows();
        let active_nat_ports = device.nat.host_ports().collect::<HashSet<_>>();
        for port in &active_nat_ports {
            add_http_listener(&mut sockets, &mut http_sockets, *port);
        }
        prune_dynamic_http_listeners(
            &mut sockets,
            &mut http_sockets,
            &active_nat_ports,
            &http_responses,
        );
        for (port, handle) in http_sockets
            .iter()
            .flat_map(|(port, handles)| handles.iter().map(|handle| (*port, *handle)))
            .collect::<Vec<_>>()
        {
            poll_http_socket(
                &mut sockets,
                handle,
                port,
                &device.nat,
                tls_enabled,
                outbound_rules.as_deref(),
                http.as_deref(),
                &mut http_responses,
            );
        }
        wait_for_network_event(&device, iface.poll_delay(Instant::now(), &sockets));
    }
}

fn wait_for_network_event(device: &LibkrunNetDevice, poll_delay: Option<smoltcp::time::Duration>) {
    let timeout_ms = poll_timeout_millis(poll_delay);
    if timeout_ms == 0 {
        return;
    }

    let mut events = libc::POLLIN;
    if device.has_pending_tx() {
        events |= libc::POLLOUT;
    }
    let mut poll_fd = libc::pollfd {
        fd: device.raw_fd(),
        events,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
        if result >= 0 {
            return;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return;
        }
    }
}

fn poll_timeout_millis(poll_delay: Option<smoltcp::time::Duration>) -> i32 {
    let delay = poll_delay
        .map(|delay| Duration::from_micros(delay.total_micros()))
        .unwrap_or(NETWORK_IDLE_WAKE_INTERVAL)
        .min(NETWORK_IDLE_WAKE_INTERVAL);
    i32::try_from(delay.as_millis()).unwrap_or(i32::MAX)
}

fn add_dns_socket(sockets: &mut SocketSet<'_>) -> SocketHandle {
    let rx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; 8],
        vec![0; DNS_PACKET_BUFFER_BYTES],
    );
    let tx = udp::PacketBuffer::new(
        vec![udp::PacketMetadata::EMPTY; 8],
        vec![0; DNS_PACKET_BUFFER_BYTES],
    );
    let mut socket = udp::Socket::new(rx, tx);
    let _ = socket.bind(HOST_DNS_PORT);
    sockets.add(socket)
}

fn poll_dns_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    outbound_rules: Option<&[OutboundRulePlan]>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);
    while socket.can_recv() && socket.can_send() {
        let Ok((request, remote)) = socket.recv() else {
            return;
        };
        if outbound_rules
            .is_some_and(|rules| !is_allowed_outbound_udp("10.0.2.1", HOST_DNS_PORT, rules))
        {
            continue;
        }
        let Some(response) = dns_response(request) else {
            continue;
        };
        let _ = socket.send_slice(
            &response,
            IpEndpoint::new(remote.endpoint.addr, remote.endpoint.port),
        );
    }
}

fn add_http_listener(
    sockets: &mut SocketSet<'_>,
    http_sockets: &mut HashMap<u16, Vec<SocketHandle>>,
    port: u16,
) {
    http_sockets.entry(port).or_insert_with(|| {
        (0..HTTP_LISTENERS_PER_PORT)
            .map(|_| {
                sockets.add(tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; HTTP_SOCKET_BUFFER_BYTES]),
                    tcp::SocketBuffer::new(vec![0; HTTP_SOCKET_BUFFER_BYTES]),
                ))
            })
            .collect()
    });
}

fn prune_dynamic_http_listeners(
    sockets: &mut SocketSet<'_>,
    http_sockets: &mut HashMap<u16, Vec<SocketHandle>>,
    active_nat_ports: &HashSet<u16>,
    http_responses: &HashMap<SocketHandle, HttpResponseConnection>,
) {
    let stale_ports = http_sockets
        .iter()
        .filter_map(|(port, handles)| {
            (!is_static_listener_port(*port)
                && !active_nat_ports.contains(port)
                && handles.iter().all(|handle| {
                    !http_responses.contains_key(handle)
                        && !sockets.get::<tcp::Socket>(*handle).is_active()
                }))
            .then_some(*port)
        })
        .collect::<Vec<_>>();

    for port in stale_ports {
        if let Some(handles) = http_sockets.remove(&port) {
            for handle in handles {
                sockets.remove(handle);
            }
        }
    }
}

fn is_static_listener_port(port: u16) -> bool {
    matches!(
        port,
        HOST_HTTP_PORT | HOST_HTTP_PROBE_PORT | HOST_HTTPS_PORT | HOST_ALT_HTTPS_PORT
    )
}

fn poll_http_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    port: u16,
    nat: &TransparentTcpNat,
    tls_enabled: bool,
    outbound_rules: Option<&[OutboundRulePlan]>,
    _http: Option<&dyn HttpInterceptRuntime>,
    http_responses: &mut HashMap<SocketHandle, HttpResponseConnection>,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        http_responses.remove(&handle);
        let _ = socket.listen(port);
        return;
    }

    if let Some(response) = http_responses.get_mut(&handle) {
        flush_http_response(socket, response);
        if response.close_after_response && response.to_guest.is_empty() {
            socket.close();
        }
        return;
    }

    if is_prelistened_tls_port(port) {
        socket.close();
        return;
    }

    let mut initial = [0; TLS_READ_BUFFER_BYTES];
    let received = if socket.can_recv() {
        socket.recv_slice(&mut initial).unwrap_or(0)
    } else {
        0
    };
    if received > 0 && looks_like_tls(&initial[..received]) && tls_enabled {
        socket.close();
        return;
    }
    poll_plain_http_socket(
        socket,
        handle,
        nat,
        outbound_rules,
        http_responses,
    );
}

fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x16))
}

fn is_prelistened_tls_port(port: u16) -> bool {
    port == HOST_HTTPS_PORT || port == HOST_ALT_HTTPS_PORT
}

#[derive(Clone)]
struct HttpDestination {
    ip: String,
    port: u16,
}

fn original_http_destination(
    socket: &tcp::Socket<'_>,
    nat: &TransparentTcpNat,
) -> Option<HttpDestination> {
    let remote = socket.remote_endpoint()?;
    let local = socket.local_endpoint()?;
    let ip = nat.original_destination(remote.addr, remote.port, local.port)?;
    Some(HttpDestination {
        ip,
        port: local.port,
    })
}

fn poll_plain_http_socket(
    socket: &mut tcp::Socket<'_>,
    handle: SocketHandle,
    nat: &TransparentTcpNat,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http_responses: &mut HashMap<SocketHandle, HttpResponseConnection>,
) {
    let Some(destination) = original_http_destination(socket, nat) else {
        socket.close();
        return;
    };
    if outbound_rules
        .is_some_and(|rules| !is_allowed_outbound_tcp(&destination.ip, destination.port, rules))
    {
        let response = http_responses.entry(handle).or_default();
        response
            .to_guest
            .extend_from_slice(OUTBOUND_DENIED_RESPONSE);
        response.close_after_response = true;
        flush_http_response(socket, response);
        if response.to_guest.is_empty() {
            socket.close();
        }
        return;
    }

    let response = http_responses.entry(handle).or_default();
    response.to_guest.extend_from_slice(HOST_HTTP_PROBE_RESPONSE);
    response.close_after_response = true;
    flush_http_response(socket, response);
    if response.to_guest.is_empty() {
        socket.close();
    }
}

fn flush_http_response(socket: &mut tcp::Socket<'_>, response: &mut HttpResponseConnection) {
    while socket.can_send() && !response.to_guest.is_empty() {
        let sent = socket.send_slice(&response.to_guest).unwrap_or(0);
        if sent == 0 {
            break;
        }
        response.to_guest.drain(..sent);
    }
}

fn is_allowed_outbound_tcp(
    destination_ip: &str,
    destination_port: u16,
    rules: &[OutboundRulePlan],
) -> bool {
    rules.iter().any(|rule| match rule {
        OutboundRulePlan::AcceptTcp { cidr, ports } => {
            port_matches(ports, destination_port) && cidr_contains(cidr, destination_ip)
        }
        OutboundRulePlan::AcceptUdp { .. } => false,
        OutboundRulePlan::AcceptPublicInternet { ports } => {
            port_matches(ports, destination_port) && is_public_ipv4_destination(destination_ip)
        }
    })
}

fn is_allowed_outbound_udp(
    destination_ip: &str,
    destination_port: u16,
    rules: &[OutboundRulePlan],
) -> bool {
    rules.iter().any(|rule| match rule {
        OutboundRulePlan::AcceptUdp { cidr, ports } => {
            port_matches(ports, destination_port) && cidr_contains(cidr, destination_ip)
        }
        OutboundRulePlan::AcceptTcp { .. } | OutboundRulePlan::AcceptPublicInternet { .. } => false,
    })
}

fn port_matches(ports: &[u16], destination_port: u16) -> bool {
    ports.is_empty() || ports.contains(&destination_port)
}

fn cidr_contains(cidr: &CidrRange, destination_ip: &str) -> bool {
    destination_ip
        .parse::<std::net::IpAddr>()
        .is_ok_and(|destination| cidr.contains(destination))
}

fn is_public_ipv4_destination(destination_ip: &str) -> bool {
    destination_ip
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|destination| {
            !SPECIAL_USE_IPV4_RANGES
                .iter()
                .any(|range| range.contains(std::net::IpAddr::V4(destination)))
        })
}

fn dns_response(request: &[u8]) -> Option<Vec<u8>> {
    if request.len() < 12 {
        return None;
    }

    let query_count = u16::from_be_bytes([request[4], request[5]]);
    if query_count != 1 {
        return None;
    }

    let (name, question_end) = parse_dns_name(request, 12)?;
    if request.len() < question_end + 4 {
        return None;
    }
    let qtype = u16::from_be_bytes([request[question_end], request[question_end + 1]]);
    let qclass = u16::from_be_bytes([request[question_end + 2], request[question_end + 3]]);

    let supported_question = qclass == 1 && qtype == 1;
    let answer = if supported_question {
        dns_address(&name)
    } else {
        None
    };
    let name_exists = if supported_question {
        answer.is_some()
    } else {
        dns_address(&name).is_some()
    };

    let mut response = Vec::new();
    response.extend_from_slice(&request[0..2]);
    response.extend_from_slice(if answer.is_some() || name_exists {
        &[0x81, 0x80]
    } else {
        &[0x81, 0x83]
    });
    response.extend_from_slice(&request[4..6]);
    response.extend_from_slice(&(answer.is_some() as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&request[12..question_end + 4]);

    if let Some(address) = answer {
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&address);
    }

    Some(response)
}

fn parse_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*packet.get(offset)?);
        offset += 1;
        if len == 0 {
            return Some((labels.join("."), offset));
        }
        if len > 63 || packet.len() < offset + len {
            return None;
        }
        let label = std::str::from_utf8(&packet[offset..offset + len]).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset += len;
    }
}

fn dns_address(name: &str) -> Option<[u8; 4]> {
    if name == "protected.sandbox.test" {
        return Some(DNS_PROTECTED_TEST_IP);
    }
    if name == "public.sandbox.test" {
        return Some(DNS_PUBLIC_TEST_IP);
    }
    if name.ends_with(".sandbox.test") {
        return None;
    }
    (name, 0)
        .to_socket_addrs()
        .ok()?
        .find_map(|addr| match addr.ip() {
            std::net::IpAddr::V4(address) => Some(address.octets()),
            std::net::IpAddr::V6(_) => None,
        })
}

struct LibkrunNetDevice {
    rx: UnixStream,
    tx: UnixStream,
    nat: TransparentTcpNat,
    rx_buffer: Vec<u8>,
    pending_tx: Vec<u8>,
}

impl LibkrunNetDevice {
    fn new(rx: UnixStream, tx: UnixStream, host_ip: Ipv4Address) -> Self {
        Self {
            rx,
            tx,
            nat: TransparentTcpNat::new(host_ip),
            rx_buffer: Vec::new(),
            pending_tx: Vec::new(),
        }
    }

    fn raw_fd(&self) -> RawFd {
        self.rx.as_raw_fd()
    }

    fn has_pending_tx(&self) -> bool {
        !self.pending_tx.is_empty()
    }

    fn read_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        loop {
            let mut chunk = [0; 16 * 1024];
            match self.rx.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => self.rx_buffer.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }
        if self.rx_buffer.len() < 4 {
            return Ok(None);
        }
        let frame_len = u32::from_be_bytes([
            self.rx_buffer[0],
            self.rx_buffer[1],
            self.rx_buffer[2],
            self.rx_buffer[3],
        ]) as usize;
        let packet_len = 4 + frame_len;
        if self.rx_buffer.len() < packet_len {
            return Ok(None);
        }
        self.rx_buffer.drain(..4);
        Ok(Some(self.rx_buffer.drain(..frame_len).collect()))
    }

    fn flush_pending_tx(&mut self) {
        while !self.pending_tx.is_empty() {
            match self.tx.write(&self.pending_tx) {
                Ok(0) => return,
                Ok(written) => {
                    self.pending_tx.drain(..written);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.pending_tx.clear();
                    return;
                }
            }
        }
    }
}

impl Device for LibkrunNetDevice {
    type RxToken<'a> = LibkrunRxToken;
    type TxToken<'a> = LibkrunTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.flush_pending_tx();
        match self.read_frame() {
            Ok(frame) => {
                let mut frame = frame?;
                self.nat.rewrite_guest_frame(&mut frame);
                Some((
                    LibkrunRxToken { frame },
                    LibkrunTxToken {
                        pending_tx: &mut self.pending_tx,
                        nat: &mut self.nat,
                    },
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        self.flush_pending_tx();
        Some(LibkrunTxToken {
            pending_tx: &mut self.pending_tx,
            nat: &mut self.nat,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.max_transmission_unit = 1536;
        capabilities.max_burst_size = Some(1);
        capabilities.medium = Medium::Ethernet;
        capabilities
    }
}

struct LibkrunRxToken {
    frame: Vec<u8>,
}

impl phy::RxToken for LibkrunRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

struct LibkrunTxToken<'a> {
    pending_tx: &'a mut Vec<u8>,
    nat: &'a mut TransparentTcpNat,
}

impl phy::TxToken for LibkrunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.nat.rewrite_host_frame(&mut frame);
        if let Ok(frame_len) = u32::try_from(frame.len()) {
            self.pending_tx.extend_from_slice(&frame_len.to_be_bytes());
            self.pending_tx.extend_from_slice(&frame);
        }
        result
    }
}

#[derive(Default)]
struct HttpResponseConnection {
    to_guest: Vec<u8>,
    close_after_response: bool,
}

#[derive(Debug)]
struct TransparentTcpNat {
    host_ip: [u8; 4],
    flows: HashMap<TcpFlow, NatFlow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlow {
    guest_ip: [u8; 4],
    guest_port: u16,
    host_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct NatFlow {
    destination_ip: [u8; 4],
    last_seen: StdInstant,
    closing: bool,
}

impl TransparentTcpNat {
    fn new(host_ip: Ipv4Address) -> Self {
        Self {
            host_ip: host_ip.octets(),
            flows: HashMap::new(),
        }
    }

    fn rewrite_guest_frame(&mut self, frame: &mut [u8]) {
        self.prune_expired_flows();
        let Some(packet) = Ipv4TcpPacket::parse(frame) else {
            return;
        };
        if packet.destination_ip(frame) == self.host_ip {
            return;
        }

        let flow = TcpFlow {
            guest_ip: packet.source_ip(frame),
            guest_port: packet.source_port(frame),
            host_port: packet.destination_port(frame),
        };
        let flags = packet.tcp_flags(frame);
        if flags.rst {
            self.flows.remove(&flow);
        } else {
            self.flows.insert(
                flow,
                NatFlow {
                    destination_ip: packet.destination_ip(frame),
                    last_seen: StdInstant::now(),
                    closing: flags.fin,
                },
            );
        }
        packet.set_destination_ip(frame, self.host_ip);
        packet.recompute_checksums(frame);
    }

    fn rewrite_host_frame(&mut self, frame: &mut [u8]) {
        self.prune_expired_flows();
        let Some(packet) = Ipv4TcpPacket::parse(frame) else {
            return;
        };
        if packet.source_ip(frame) != self.host_ip {
            return;
        }

        let flow = TcpFlow {
            guest_ip: packet.destination_ip(frame),
            guest_port: packet.destination_port(frame),
            host_port: packet.source_port(frame),
        };
        let Some(nat_flow) = self.flows.get_mut(&flow) else {
            return;
        };
        nat_flow.last_seen = StdInstant::now();
        let original_destination = nat_flow.destination_ip;
        let flags = packet.tcp_flags(frame);
        packet.set_source_ip(frame, original_destination);
        packet.recompute_checksums(frame);
        if flags.fin || flags.rst {
            self.flows.remove(&flow);
        }
    }

    fn original_destination(
        &self,
        guest_ip: IpAddress,
        guest_port: u16,
        host_port: u16,
    ) -> Option<String> {
        let guest_ip = match guest_ip {
            IpAddress::Ipv4(guest_ip) => guest_ip.octets(),
        };
        let flow = TcpFlow {
            guest_ip,
            guest_port,
            host_port,
        };
        self.flows.get(&flow).map(|flow| {
            let address = flow.destination_ip;
            Ipv4Address::new(address[0], address[1], address[2], address[3]).to_string()
        })
    }

    fn host_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.flows.keys().map(|flow| flow.host_port)
    }

    fn prune_expired_flows(&mut self) {
        let now = StdInstant::now();
        self.flows.retain(|_, flow| {
            now.duration_since(flow.last_seen)
                < if flow.closing {
                    NAT_FLOW_CLOSING_TTL
                } else {
                    NAT_FLOW_IDLE_TTL
                }
        });
    }
}

#[derive(Debug, Clone, Copy)]
struct Ipv4TcpPacket {
    ip_start: usize,
    tcp_start: usize,
}

impl Ipv4TcpPacket {
    fn parse(frame: &[u8]) -> Option<Self> {
        if frame.len() < 14 + 20 {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
            return None;
        }
        let ip_start = 14;
        let version = frame[ip_start] >> 4;
        let ihl = usize::from(frame[ip_start] & 0x0f) * 4;
        if version != 4 || ihl < 20 || frame.len() < ip_start + ihl {
            return None;
        }
        if frame[ip_start + 9] != 6 {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([
            frame[ip_start + 2],
            frame[ip_start + 3],
        ]));
        if total_len < ihl || frame.len() < ip_start + total_len {
            return None;
        }
        let tcp_start = ip_start + ihl;
        if frame.len() < tcp_start + 20 {
            return None;
        }
        Some(Self {
            ip_start,
            tcp_start,
        })
    }

    fn source_ip(self, frame: &[u8]) -> [u8; 4] {
        frame[self.ip_start + 12..self.ip_start + 16]
            .try_into()
            .unwrap()
    }

    fn destination_ip(self, frame: &[u8]) -> [u8; 4] {
        frame[self.ip_start + 16..self.ip_start + 20]
            .try_into()
            .unwrap()
    }

    fn set_source_ip(self, frame: &mut [u8], address: [u8; 4]) {
        frame[self.ip_start + 12..self.ip_start + 16].copy_from_slice(&address);
    }

    fn set_destination_ip(self, frame: &mut [u8], address: [u8; 4]) {
        frame[self.ip_start + 16..self.ip_start + 20].copy_from_slice(&address);
    }

    fn source_port(self, frame: &[u8]) -> u16 {
        u16::from_be_bytes([frame[self.tcp_start], frame[self.tcp_start + 1]])
    }

    fn destination_port(self, frame: &[u8]) -> u16 {
        u16::from_be_bytes([frame[self.tcp_start + 2], frame[self.tcp_start + 3]])
    }

    fn tcp_flags(self, frame: &[u8]) -> TcpFlags {
        let flags = frame[self.tcp_start + 13];
        TcpFlags {
            fin: flags & 0x01 != 0,
            rst: flags & 0x04 != 0,
        }
    }

    fn recompute_checksums(self, frame: &mut [u8]) {
        let total_len = usize::from(u16::from_be_bytes([
            frame[self.ip_start + 2],
            frame[self.ip_start + 3],
        ]));
        let ip_header_len = self.tcp_start - self.ip_start;
        frame[self.ip_start + 10] = 0;
        frame[self.ip_start + 11] = 0;
        let ip_checksum = internet_checksum(&frame[self.ip_start..self.tcp_start]);
        frame[self.ip_start + 10..self.ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let tcp_len = total_len - ip_header_len;
        frame[self.tcp_start + 16] = 0;
        frame[self.tcp_start + 17] = 0;
        let tcp_checksum = tcp_ipv4_checksum(
            self.source_ip(frame),
            self.destination_ip(frame),
            &frame[self.tcp_start..self.tcp_start + tcp_len],
        );
        frame[self.tcp_start + 16..self.tcp_start + 18]
            .copy_from_slice(&tcp_checksum.to_be_bytes());
    }
}

#[derive(Debug, Clone, Copy)]
struct TcpFlags {
    fin: bool,
    rst: bool,
}

fn tcp_ipv4_checksum(source: [u8; 4], destination: [u8; 4], tcp: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + tcp.len());
    pseudo_header.extend_from_slice(&source);
    pseudo_header.extend_from_slice(&destination);
    pseudo_header.push(0);
    pseudo_header.push(6);
    pseudo_header.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(tcp);
    internet_checksum(&pseudo_header)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

#[cfg(test)]
fn read_ethernet_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let frame_len = u32::from_be_bytes(len) as usize;
    let mut frame = vec![0; frame_len];
    reader.read_exact(&mut frame)?;
    Ok(frame)
}

#[cfg(test)]
fn write_ethernet_frame(writer: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    let frame_len = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "ethernet frame too large"))?;
    writer.write_all(&frame_len.to_be_bytes())?;
    writer.write_all(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn reads_libkrun_unixstream_ethernet_frame() {
        let ethernet = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xef, 0x08, 0x06,
        ];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(ethernet.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&ethernet);

        let frame = read_ethernet_frame(&mut Cursor::new(bytes)).unwrap();
        assert_eq!(frame, ethernet);
        assert_eq!(&frame[..6], &[0xff; 6]);
    }

    #[test]
    fn writes_libkrun_unixstream_ethernet_frame() {
        let ethernet = [0u8; 14];
        let mut bytes = Vec::new();

        write_ethernet_frame(&mut bytes, &ethernet).unwrap();

        assert_eq!(&bytes[..4], &(ethernet.len() as u32).to_be_bytes());
        assert_eq!(&bytes[4..], ethernet);
    }

    #[test]
    fn libkrun_net_device_preserves_partial_nonblocking_frames() {
        let (rx, mut rx_writer) = UnixStream::pair().unwrap();
        let (tx, _tx_reader) = UnixStream::pair().unwrap();
        rx.set_nonblocking(true).unwrap();
        let mut device = LibkrunNetDevice::new(rx, tx, Ipv4Address::new(10, 0, 2, 1));
        let ethernet = [0u8; 14];
        let mut packet = Vec::new();
        packet.extend_from_slice(&(ethernet.len() as u32).to_be_bytes());
        packet.extend_from_slice(&ethernet);

        rx_writer.write_all(&packet[..2]).unwrap();
        assert!(device.read_frame().unwrap().is_none());
        rx_writer.write_all(&packet[2..]).unwrap();

        assert_eq!(device.read_frame().unwrap(), Some(ethernet.to_vec()));
    }

    #[test]
    fn network_poll_timeout_uses_smoltcp_deadline() {
        assert_eq!(
            poll_timeout_millis(Some(smoltcp::time::Duration::from_millis(17))),
            17,
        );
    }

    #[test]
    fn network_poll_timeout_caps_idle_wakeups() {
        assert_eq!(poll_timeout_millis(None), 100);
        assert_eq!(
            poll_timeout_millis(Some(smoltcp::time::Duration::from_secs(30))),
            100,
        );
    }

    #[test]
    fn network_poll_timeout_preserves_immediate_repoll() {
        assert_eq!(
            poll_timeout_millis(Some(smoltcp::time::Duration::from_millis(0))),
            0,
        );
    }

    #[test]
    fn outbound_rules_deny_unmatched_tcp_destinations() {
        let rules = vec![OutboundRulePlan::AcceptTcp {
            cidr: CidrRange::parse("93.184.216.34/32").unwrap(),
            ports: vec![80],
        }];

        assert!(is_allowed_outbound_tcp("93.184.216.34", 80, &rules));
        assert!(!is_allowed_outbound_tcp("93.184.216.35", 80, &rules));
        assert!(!is_allowed_outbound_tcp("93.184.216.34", 443, &rules));
    }

    #[test]
    fn outbound_rules_honor_udp_protocol_and_port() {
        let rules = vec![OutboundRulePlan::AcceptUdp {
            cidr: CidrRange::parse("10.0.2.1/32").unwrap(),
            ports: vec![53],
        }];

        assert!(is_allowed_outbound_udp("10.0.2.1", 53, &rules));
        assert!(!is_allowed_outbound_udp("10.0.2.1", 5353, &rules));
        assert!(!is_allowed_outbound_tcp("10.0.2.1", 53, &rules));
    }

    #[test]
    fn public_internet_rules_exclude_special_use_ranges() {
        let rules = vec![OutboundRulePlan::AcceptPublicInternet { ports: vec![80] }];

        assert!(is_allowed_outbound_tcp("93.184.216.34", 80, &rules));
        for address in [
            "0.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.0.1",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.0.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!is_allowed_outbound_tcp(address, 80, &rules), "{address}");
        }
    }

    #[test]
    fn transparent_nat_prunes_flow_after_host_fin() {
        let mut nat = TransparentTcpNat::new(Ipv4Address::new(10, 0, 2, 1));
        let mut guest_frame = tcp_frame([10, 0, 2, 15], [93, 184, 216, 34], 50_000, 443, 0x02);

        nat.rewrite_guest_frame(&mut guest_frame);
        assert_eq!(
            nat.original_destination(IpAddress::v4(10, 0, 2, 15), 50_000, 443),
            Some("93.184.216.34".to_string()),
        );

        let mut host_frame = tcp_frame([10, 0, 2, 1], [10, 0, 2, 15], 443, 50_000, 0x01);
        nat.rewrite_host_frame(&mut host_frame);

        assert_eq!(
            nat.original_destination(IpAddress::v4(10, 0, 2, 15), 50_000, 443),
            None
        );
        assert_eq!(nat.host_ports().count(), 0);
    }

    #[test]
    fn dns_unsupported_query_type_returns_nodata_for_known_name() {
        let response = dns_response(&dns_query("public.sandbox.test", 28)).unwrap();

        assert_eq!(&response[2..4], &[0x81, 0x80]);
        assert_eq!(&response[6..8], &[0, 0]);
    }

    #[test]
    fn dns_unknown_name_returns_nxdomain() {
        let response = dns_response(&dns_query("missing.sandbox.test", 1)).unwrap();

        assert_eq!(&response[2..4], &[0x81, 0x83]);
        assert_eq!(&response[6..8], &[0, 0]);
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&0x1234u16.to_be_bytes());
        query.extend_from_slice(&0x0100u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        query.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        query
    }

    fn tcp_frame(
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        source_port: u16,
        destination_port: u16,
        tcp_flags: u8,
    ) -> Vec<u8> {
        let mut frame = vec![0; 14 + 20 + 20];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip_start = 14;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&40u16.to_be_bytes());
        frame[ip_start + 9] = 6;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&source_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&destination_ip);
        let tcp_start = ip_start + 20;
        frame[tcp_start..tcp_start + 2].copy_from_slice(&source_port.to_be_bytes());
        frame[tcp_start + 2..tcp_start + 4].copy_from_slice(&destination_port.to_be_bytes());
        frame[tcp_start + 12] = 5 << 4;
        frame[tcp_start + 13] = tcp_flags;
        frame
    }
}
