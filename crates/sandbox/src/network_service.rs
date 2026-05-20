use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as StdInstant};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use crate::http_interception::HttpRequestProtocol;
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
const MITM_CERT_CACHE_LIMIT: usize = 256;
const NAT_FLOW_IDLE_TTL: Duration = Duration::from_secs(300);
const NAT_FLOW_CLOSING_TTL: Duration = Duration::from_secs(30);
const HOST_HTTP_PROBE_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-length: 25\r\nconnection: close\r\n\r\nsandbox explicit network\n";
const OUTBOUND_DENIED_RESPONSE: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\ncontent-length: 15\r\nconnection: close\r\n\r\noutbound denied";
const UPSTREAM_FAILURE_RESPONSE: &[u8] =
    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 20\r\nconnection: close\r\n\r\nupstream unavailable";
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

#[derive(Debug, Clone)]
pub struct HttpRequestHeaderHookInput {
    pub protocol: HttpRequestProtocol,
    pub method: String,
    pub url: String,
    pub original_destination_ip: String,
    pub original_destination_port: u16,
    pub upstream_dial_ip: String,
    pub upstream_dial_port: u16,
    pub headers: Vec<(String, String)>,
    pub tls: Option<HostTlsMetadata>,
}

pub trait HttpRequestHeaderHookService: Send + Sync + fmt::Debug {
    fn apply_request_headers(
        &self,
        input: HttpRequestHeaderHookInput,
    ) -> io::Result<Vec<(String, String)>>;
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
        http_request_headers: Option<Arc<dyn HttpRequestHeaderHookService>>,
    ) -> io::Result<Self> {
        let (host, guest) = UnixStream::pair()?;
        let tls_acceptor = tls_config.map(TlsAcceptor::new).transpose()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            run_network_service(
                host,
                worker_shutdown,
                tls_acceptor,
                outbound_rules,
                http_request_headers,
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
    tls_acceptor: Option<TlsAcceptor>,
    outbound_rules: Option<Vec<OutboundRulePlan>>,
    http_request_headers: Option<Arc<dyn HttpRequestHeaderHookService>>,
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
    let mut http_connections = HashMap::new();
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PORT);
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PROBE_PORT);
    if tls_acceptor.is_some() {
        add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);
        add_http_listener(&mut sockets, &mut http_sockets, HOST_ALT_HTTPS_PORT);
    }
    let mut tls_connections = HashMap::new();

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
            &http_connections,
            &tls_connections,
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
                tls_acceptor.as_ref(),
                outbound_rules.as_deref(),
                http_request_headers.as_deref(),
                &mut http_connections,
                &mut tls_connections,
            );
        }
        thread::sleep(Duration::from_millis(1));
    }
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
    http_connections: &HashMap<SocketHandle, HttpConnection>,
    tls_connections: &HashMap<SocketHandle, TlsConnection>,
) {
    let stale_ports = http_sockets
        .iter()
        .filter_map(|(port, handles)| {
            (!is_static_listener_port(*port)
                && !active_nat_ports.contains(port)
                && handles.iter().all(|handle| {
                    !http_connections.contains_key(handle)
                        && !tls_connections.contains_key(handle)
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
    tls_acceptor: Option<&TlsAcceptor>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    _http_request_headers: Option<&dyn HttpRequestHeaderHookService>,
    http_connections: &mut HashMap<SocketHandle, HttpConnection>,
    tls_connections: &mut HashMap<SocketHandle, TlsConnection>,
) {
    let http_proxy_port = None;
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        http_connections.remove(&handle);
        tls_connections.remove(&handle);
        let _ = socket.listen(port);
        return;
    }

    if tls_connections.contains_key(&handle) {
        poll_tls_http_socket(
            socket,
            handle,
            nat,
            http_proxy_port,
            tls_acceptor,
            tls_connections,
            &[],
        );
        return;
    }
    if http_connections.contains_key(&handle) {
        poll_plain_http_socket(
            socket,
            handle,
            nat,
            http_proxy_port,
            outbound_rules,
            http_connections,
            &[],
        );
        return;
    }

    if is_prelistened_tls_port(port) {
        if socket.can_recv() {
            let mut request = [0; TLS_READ_BUFFER_BYTES];
            let received = socket.recv_slice(&mut request).unwrap_or(0);
            if received > 0 {
                poll_tls_http_socket(
                    socket,
                    handle,
                    nat,
                    http_proxy_port,
                    tls_acceptor,
                    tls_connections,
                    &request[..received],
                );
            }
        }
        return;
    }

    let mut initial = [0; TLS_READ_BUFFER_BYTES];
    let received = if socket.can_recv() {
        socket.recv_slice(&mut initial).unwrap_or(0)
    } else {
        0
    };
    if received > 0 && looks_like_tls(&initial[..received]) && tls_acceptor.is_some() {
        poll_tls_http_socket(
            socket,
            handle,
            nat,
            http_proxy_port,
            tls_acceptor,
            tls_connections,
            &initial[..received],
        );
        return;
    }
    poll_plain_http_socket(
        socket,
        handle,
        nat,
        http_proxy_port,
        outbound_rules,
        http_connections,
        &initial[..received],
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
    http_proxy_port: Option<u16>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http_connections: &mut HashMap<SocketHandle, HttpConnection>,
    received: &[u8],
) {
    let Some(destination) = original_http_destination(socket, nat) else {
        socket.close();
        return;
    };
    if outbound_rules
        .is_some_and(|rules| !is_allowed_outbound_tcp(&destination.ip, destination.port, rules))
    {
        let connection = http_connections.entry(handle).or_default();
        connection
            .to_guest
            .extend_from_slice(OUTBOUND_DENIED_RESPONSE);
        connection.close_after_response = true;
        flush_plain_proxy_response(socket, connection);
        if connection.to_guest.is_empty() {
            socket.close();
        }
        return;
    }

    let Some(proxy_port) = http_proxy_port else {
        let connection = http_connections.entry(handle).or_default();
        connection
            .to_guest
            .extend_from_slice(HOST_HTTP_PROBE_RESPONSE);
        connection.close_after_response = true;
        flush_plain_proxy_response(socket, connection);
        if connection.to_guest.is_empty() {
            socket.close();
        }
        return;
    };

    let connection = http_connections.entry(handle).or_insert_with(|| {
        HttpConnection::connect_proxy(proxy_port, destination, None)
            .unwrap_or_else(|_| HttpConnection::failed())
    });
    if connection.failed {
        connection
            .to_guest
            .extend_from_slice(UPSTREAM_FAILURE_RESPONSE);
        connection.close_after_response = true;
    } else {
        connection.flush_to_proxy();
        if !received.is_empty() {
            connection.write_to_proxy(received);
        }
        connection.flush_to_proxy();
        while socket.can_recv() {
            let mut chunk = [0; TLS_READ_BUFFER_BYTES];
            let received = socket.recv_slice(&mut chunk).unwrap_or(0);
            if received == 0 {
                break;
            }
            connection.write_to_proxy(&chunk[..received]);
            connection.flush_to_proxy();
        }
        connection.read_from_proxy();
    }
    flush_plain_proxy_response(socket, connection);
    if connection.close_after_response && connection.to_guest.is_empty() {
        socket.close();
    }
}

fn poll_tls_http_socket(
    socket: &mut tcp::Socket<'_>,
    handle: SocketHandle,
    nat: &TransparentTcpNat,
    http_proxy_port: Option<u16>,
    tls_acceptor: Option<&TlsAcceptor>,
    tls_connections: &mut HashMap<SocketHandle, TlsConnection>,
    received: &[u8],
) {
    let Some(tls_acceptor) = tls_acceptor else {
        socket.close();
        return;
    };
    let Some(proxy_port) = http_proxy_port else {
        socket.close();
        return;
    };
    let connection = tls_connections
        .entry(handle)
        .or_insert_with(|| tls_acceptor.connection());
    if !received.is_empty() {
        let mut reader = Cursor::new(received);
        if connection.tls.read_tls(&mut reader).is_err()
            || connection.tls.process_new_packets().is_err()
        {
            socket.close();
            return;
        }
    }
    while socket.can_recv() {
        let mut chunk = [0; 8192];
        let received = socket.recv_slice(&mut chunk).unwrap_or(0);
        if received == 0 {
            break;
        }
        let mut reader = Cursor::new(&chunk[..received]);
        if connection.tls.read_tls(&mut reader).is_err()
            || connection.tls.process_new_packets().is_err()
        {
            socket.close();
            return;
        }
    }
    let mut plaintext = Vec::new();
    let _ = connection.tls.reader().read_to_end(&mut plaintext);
    if connection.proxy.is_none() {
        let Some(destination) = original_http_destination(socket, nat) else {
            socket.close();
            return;
        };
        connection.proxy = Some(
            HttpConnection::connect_proxy(proxy_port, destination, tls_metadata(&connection.tls))
                .unwrap_or_else(|_| HttpConnection::failed()),
        );
    }
    if let Some(proxy) = connection.proxy.as_mut() {
        proxy.flush_to_proxy();
        if !plaintext.is_empty() {
            proxy.write_to_proxy(&plaintext);
        }
        proxy.flush_to_proxy();
        proxy.read_from_proxy();
        if !proxy.to_guest.is_empty() {
            let _ = connection.tls.writer().write_all(&proxy.to_guest);
            proxy.to_guest.clear();
        }
        if proxy.close_after_response {
            connection.tls.send_close_notify();
        }
    }

    let mut encrypted = Vec::new();
    let _ = connection.tls.write_tls(&mut encrypted);
    if !encrypted.is_empty() {
        connection.encrypted_to_guest.extend_from_slice(&encrypted);
    }
    while socket.can_send() && !connection.encrypted_to_guest.is_empty() {
        let sent = socket
            .send_slice(&connection.encrypted_to_guest)
            .unwrap_or(0);
        if sent == 0 {
            break;
        }
        connection.encrypted_to_guest.drain(..sent);
    }
    if connection
        .proxy
        .as_ref()
        .is_some_and(|proxy| proxy.close_after_response)
        && connection.encrypted_to_guest.is_empty()
    {
        socket.close();
    }
}

fn flush_plain_proxy_response(socket: &mut tcp::Socket<'_>, connection: &mut HttpConnection) {
    while socket.can_send() && !connection.to_guest.is_empty() {
        let sent = socket.send_slice(&connection.to_guest).unwrap_or(0);
        if sent == 0 {
            break;
        }
        connection.to_guest.drain(..sent);
    }
}

fn tls_metadata(connection: &rustls::ServerConnection) -> Option<HostTlsMetadata> {
    Some(HostTlsMetadata {
        server_name: connection.server_name().map(str::to_string),
        alpn_protocol: connection
            .alpn_protocol()
            .map(|value| String::from_utf8_lossy(value).to_string()),
        protocol: connection
            .protocol_version()
            .map(|version| format!("{version:?}")),
    })
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

struct TlsAcceptor {
    config: Arc<rustls::ServerConfig>,
}

struct HttpConnection {
    proxy: Option<TcpStream>,
    to_proxy: PendingWriteBuffer,
    to_guest: Vec<u8>,
    close_after_response: bool,
    failed: bool,
}

impl Default for HttpConnection {
    fn default() -> Self {
        Self {
            proxy: None,
            to_proxy: PendingWriteBuffer::default(),
            to_guest: Vec::new(),
            close_after_response: false,
            failed: false,
        }
    }
}

struct TlsConnection {
    tls: rustls::ServerConnection,
    proxy: Option<HttpConnection>,
    encrypted_to_guest: Vec<u8>,
}

impl HttpConnection {
    fn connect_proxy(
        proxy_port: u16,
        destination: HttpDestination,
        tls: Option<HostTlsMetadata>,
    ) -> io::Result<Self> {
        let mut proxy = TcpStream::connect(("127.0.0.1", proxy_port))?;
        let preface = proxy_preface(destination, tls);
        proxy.write_all(preface.as_bytes())?;
        proxy.set_nonblocking(true)?;
        Ok(Self {
            proxy: Some(proxy),
            to_proxy: PendingWriteBuffer::default(),
            to_guest: Vec::new(),
            close_after_response: false,
            failed: false,
        })
    }

    fn failed() -> Self {
        Self {
            proxy: None,
            to_proxy: PendingWriteBuffer::default(),
            to_guest: Vec::new(),
            close_after_response: true,
            failed: true,
        }
    }

    fn write_to_proxy(&mut self, bytes: &[u8]) {
        self.to_proxy.push(bytes);
        self.flush_to_proxy();
    }

    fn flush_to_proxy(&mut self) {
        let Some(proxy) = self.proxy.as_mut() else {
            return;
        };
        match self.to_proxy.flush(proxy) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {
                self.close_after_response = true;
            }
        }
    }

    fn read_from_proxy(&mut self) {
        let Some(proxy) = self.proxy.as_mut() else {
            return;
        };
        let mut buffer = [0; 16 * 1024];
        loop {
            match proxy.read(&mut buffer) {
                Ok(0) => {
                    self.close_after_response = true;
                    return;
                }
                Ok(read) => self.to_guest.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => {
                    self.close_after_response = true;
                    return;
                }
            }
        }
    }
}

#[derive(Default)]
struct PendingWriteBuffer {
    bytes: Vec<u8>,
}

impl PendingWriteBuffer {
    fn push(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn flush(&mut self, writer: &mut impl Write) -> io::Result<()> {
        while !self.bytes.is_empty() {
            match writer.write(&self.bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "buffered write closed",
                    ));
                }
                Ok(written) => {
                    self.bytes.drain(..written);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Err(error),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

fn proxy_preface(destination: HttpDestination, tls: Option<HostTlsMetadata>) -> String {
    let tls = tls.unwrap_or(HostTlsMetadata {
        server_name: None,
        alpn_protocol: None,
        protocol: None,
    });
    format!(
        "SANDBOX_HTTP_PROXY 1 {} {} {} {} {}\n",
        destination.ip,
        destination.port,
        tls.server_name.unwrap_or_else(|| "-".to_string()),
        tls.alpn_protocol.unwrap_or_else(|| "-".to_string()),
        tls.protocol.unwrap_or_else(|| "-".to_string()),
    )
}

impl TlsAcceptor {
    fn new(config: MitmTlsConfig) -> io::Result<Self> {
        let ca_key = rcgen::KeyPair::from_pem(&config.ca_private_key_pem)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let ca = rcgen::Issuer::from_ca_cert_pem(&config.ca_certificate_pem, ca_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DynamicMitmCertResolver::new(ca)));
        let mut config = config;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config: Arc::new(config),
        })
    }

    fn connection(&self) -> TlsConnection {
        TlsConnection {
            tls: rustls::ServerConnection::new(self.config.clone())
                .expect("TLS server config should create connections"),
            proxy: None,
            encrypted_to_guest: Vec::new(),
        }
    }
}

struct DynamicMitmCertResolver {
    issuer: Mutex<MitmCertIssuer>,
}

struct MitmCertIssuer {
    ca: rcgen::Issuer<'static, rcgen::KeyPair>,
    cache: HashMap<String, Arc<CertifiedKey>>,
    cache_order: VecDeque<String>,
}

impl DynamicMitmCertResolver {
    fn new(ca: rcgen::Issuer<'static, rcgen::KeyPair>) -> Self {
        Self {
            issuer: Mutex::new(MitmCertIssuer {
                ca,
                cache: HashMap::new(),
                cache_order: VecDeque::new(),
            }),
        }
    }
}

impl fmt::Debug for DynamicMitmCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DynamicMitmCertResolver")
    }
}

impl ResolvesServerCert for DynamicMitmCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name().unwrap_or("127.0.0.1");
        self.issuer.lock().ok()?.certificate_for(server_name).ok()
    }
}

impl MitmCertIssuer {
    fn certificate_for(&mut self, server_name: &str) -> io::Result<Arc<CertifiedKey>> {
        if let Some(certificate) = self.cache.get(server_name) {
            return Ok(certificate.clone());
        }

        let certificate = Arc::new(self.generate_certificate(server_name)?);
        self.insert_cached_certificate(server_name.to_string(), certificate.clone());
        Ok(certificate)
    }

    fn insert_cached_certificate(&mut self, server_name: String, certificate: Arc<CertifiedKey>) {
        if self.cache.contains_key(&server_name) {
            self.cache.insert(server_name, certificate);
            return;
        }
        while self.cache.len() >= MITM_CERT_CACHE_LIMIT {
            let Some(evicted) = self.cache_order.pop_front() else {
                break;
            };
            self.cache.remove(&evicted);
        }
        self.cache_order.push_back(server_name.clone());
        self.cache.insert(server_name, certificate);
    }

    fn generate_certificate(&self, server_name: &str) -> io::Result<CertifiedKey> {
        let leaf_key = rcgen::KeyPair::generate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let mut leaf_params = rcgen::CertificateParams::new(vec![server_name.to_string()])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        leaf_params.distinguished_name = rcgen::DistinguishedName::new();
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, server_name.to_string());
        leaf_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.insert_extended_key_usage(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let leaf = leaf_params
            .signed_by(&leaf_key, &self.ca)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let cert_chain = vec![CertificateDer::from(leaf.der().to_vec())];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key_der)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(CertifiedKey::new(cert_chain, signing_key))
    }
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
    fn pending_write_buffer_preserves_unwritten_suffix_after_would_block() {
        let mut buffer = PendingWriteBuffer::default();
        buffer.push(b"abcdef");
        let mut writer = PartialWouldBlockWriter {
            first_write_len: 2,
            writes: Vec::new(),
            blocked: false,
        };

        assert_eq!(
            buffer.flush(&mut writer).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(writer.writes, vec![b"ab".to_vec()]);
        assert!(!buffer.is_empty());

        let mut writer = Vec::new();
        buffer.flush(&mut writer).unwrap();

        assert_eq!(writer, b"cdef");
        assert!(buffer.is_empty());
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

    struct PartialWouldBlockWriter {
        first_write_len: usize,
        writes: Vec<Vec<u8>>,
        blocked: bool,
    }

    impl Write for PartialWouldBlockWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.blocked {
                return Err(io::Error::new(io::ErrorKind::WouldBlock, "blocked"));
            }
            let written = self.first_write_len.min(bytes.len());
            self.writes.push(bytes[..written].to_vec());
            self.blocked = true;
            Ok(written)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
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
