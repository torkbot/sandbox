use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as StdInstant};

use hickory_proto::op::{Message as DnsMessage, MessageType as DnsMessageType, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use rama_core::extensions::Extensions;
use rama_core::rt::Executor;
use rama_core::service::Service;
use rama_http::layer::version_adapter::RequestVersionAdapter;
use rama_http::{Body, Request as RamaRequest, Response as RamaResponse, Version as RamaVersion};
use rama_http_backend::client::http_connect;
use rama_http_backend::server::HttpServer;
use rama_net::client::EstablishedClientConnection;
use rama_tcp::stream::TcpStream as RamaTcpStream;
use rama_tls_rustls::client::{TlsConnector, TlsConnectorData};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address};

use crate::async_bridge::SyncAsyncBridge;
use crate::http_flow::{HttpInterceptRuntime, InterceptedDestination, InterceptedHttpRequest};
use crate::http_interception::HttpRequestProtocol;
use crate::network::{CidrRange, OutboundRulePlan};
use rustls::pki_types::pem::PemObject;

const HOST_HTTP_PROBE_PORT: u16 = 8080;
const HOST_HTTP_PORT: u16 = 80;
const HOST_ALT_HTTP_PORT: u16 = 8000;
const HOST_HTTPS_PORT: u16 = 443;
const HOST_ALT_HTTPS_PORT: u16 = 8443;
const HOST_DNS_PORT: u16 = 53;
const HTTP_LISTENERS_PER_PORT: usize = 16;
const HTTP_MAX_SOCKETS_PER_PORT: usize = 256;
const HTTP_SOCKET_BUFFER_BYTES: usize = 256 * 1024;
const HTTP_BRIDGE_BUFFER_BYTES: usize = 256 * 1024;
const TLS_READ_BUFFER_BYTES: usize = 16 * 1024;
const MAX_INTERCEPT_HEAD_BYTES: usize = 64 * 1024;
const DNS_PACKET_BUFFER_BYTES: usize = 4096;
const DNS_DEFAULT_TTL_SECS: u32 = 60;
const UDP_RELAY_BUFFER_BYTES: usize = 64 * 1024;
const UDP_INTERCEPT_PORT_START: u16 = 40_000;
const UDP_INTERCEPT_PORT_END: u16 = 60_999;
const INTERCEPT_FLOW_IDLE_TTL: Duration = Duration::from_secs(300);
const INTERCEPT_FLOW_CLOSING_TTL: Duration = Duration::from_secs(30);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkEndpoint {
    pub ip: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkConnectionAttempt {
    pub protocol: NetworkProtocol,
    pub transport: NetworkProtocol,
    pub src: NetworkEndpoint,
    pub dst: NetworkEndpoint,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyDecision {
    pub action: NetworkPolicyAction,
    pub dns_resolvers: Vec<DnsResolver>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkPolicyAction {
    Deny,
    Accept,
    AcceptHttp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolver {
    pub ip: String,
    pub port: u16,
}

pub trait NetworkPolicyRuntime: Send + Sync + std::fmt::Debug {
    fn decide_connection(
        &self,
        connection: NetworkConnectionAttempt,
    ) -> io::Result<NetworkPolicyDecision>;

    fn connection_closed(&self, _connection: NetworkConnectionAttempt) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct MitmTlsAuthority {
    ca_certificate_pem: String,
    ca_private_key_pem: String,
}

impl MitmTlsAuthority {
    fn new(config: MitmTlsConfig) -> io::Result<Self> {
        let _ca_certificate =
            rustls::pki_types::CertificateDer::from_pem_slice(config.ca_certificate_pem.as_bytes())
                .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        Ok(Self {
            ca_certificate_pem: config.ca_certificate_pem,
            ca_private_key_pem: config.ca_private_key_pem,
        })
    }

    fn server_connection(&self, server_name: &str) -> io::Result<rustls::ServerConnection> {
        let key_pair = rcgen::KeyPair::generate()
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        let ca_key = rcgen::KeyPair::from_pem(&self.ca_private_key_pem)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        let ca = rcgen::Issuer::from_ca_cert_pem(&self.ca_certificate_pem, ca_key)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        let mut params = rcgen::CertificateParams::new(vec![server_name.to_string()])
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, server_name);
        let certificate = params
            .signed_by(&key_pair, &ca)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        let private_key = rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        let mut config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.der().clone()], private_key)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        rustls::ServerConnection::new(Arc::new(config))
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))
    }
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
        policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    ) -> io::Result<Self> {
        let (host, guest) = UnixStream::pair()?;
        let tls_authority = tls_config
            .map(MitmTlsAuthority::new)
            .transpose()?
            .map(Arc::new);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            run_network_service(
                host,
                worker_shutdown,
                tls_authority,
                outbound_rules,
                http,
                policy,
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
    tls_authority: Option<Arc<MitmTlsAuthority>>,
    outbound_rules: Option<Vec<OutboundRulePlan>>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
) {
    let _ = stream.set_nonblocking(true);
    let tx = match stream.try_clone() {
        Ok(tx) => tx,
        Err(_) => return,
    };
    let mut device = LibkrunNetDevice::new(
        stream,
        tx,
        Ipv4Address::new(10, 0, 2, 1),
        outbound_rules.clone(),
        policy.clone(),
    );
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
    let tcp_dns_handles = add_tcp_dns_listeners(&mut sockets);
    let mut tcp_dns_connections = HashMap::new();
    let mut http_sockets = HashMap::new();
    let mut http_connections = HashMap::new();
    let mut udp_sockets = HashMap::new();
    let mut udp_relays = HashMap::new();
    add_static_http_listeners(&mut sockets, &mut http_sockets, tls_authority.is_some());
    while !shutdown.load(Ordering::Acquire) {
        let timestamp = Instant::now();
        add_static_http_listeners(&mut sockets, &mut http_sockets, tls_authority.is_some());
        let _ = iface.poll(timestamp, &mut device, &mut sockets);
        poll_dns_socket(
            &mut sockets,
            dns_handle,
            outbound_rules.as_deref(),
            policy.as_deref(),
            &mut device.interception,
        );
        for handle in &tcp_dns_handles {
            poll_tcp_dns_socket(
                &mut sockets,
                *handle,
                outbound_rules.as_deref(),
                policy.as_deref(),
                &mut tcp_dns_connections,
                &mut device.interception,
            );
        }
        device.interception.prune_expired_flows();
        let active_tcp_intercept_ports =
            device.interception.tcp_host_ports().collect::<HashSet<_>>();
        for port in &active_tcp_intercept_ports {
            add_http_listener(&mut sockets, &mut http_sockets, *port);
        }
        prune_dynamic_http_listeners(
            &mut sockets,
            &mut http_sockets,
            &active_tcp_intercept_ports,
            &http_connections,
        );
        let active_udp_intercept_ports =
            device.interception.udp_host_ports().collect::<HashSet<_>>();
        for port in &active_udp_intercept_ports {
            add_udp_relay_socket(&mut sockets, &mut udp_sockets, *port);
        }
        prune_dynamic_udp_relays(
            &mut sockets,
            &mut udp_sockets,
            &mut udp_relays,
            &active_udp_intercept_ports,
        );
        for (port, handle) in udp_sockets
            .iter()
            .map(|(port, handle)| (*port, *handle))
            .collect::<Vec<_>>()
        {
            poll_udp_relay_socket(
                &mut sockets,
                handle,
                port,
                &mut device.interception,
                outbound_rules.as_deref(),
                policy.as_deref(),
                &mut udp_relays,
            );
        }
        for (port, handle) in http_sockets
            .iter()
            .flat_map(|(port, handles)| handles.iter().map(|handle| (*port, *handle)))
            .collect::<Vec<_>>()
        {
            poll_http_socket(
                &mut sockets,
                handle,
                port,
                &mut device.interception,
                outbound_rules.as_deref(),
                http.clone(),
                policy.clone(),
                tls_authority.clone(),
                &mut http_connections,
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

fn add_tcp_dns_listeners(sockets: &mut SocketSet<'_>) -> Vec<SocketHandle> {
    (0..HTTP_LISTENERS_PER_PORT)
        .map(|_| {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; HTTP_SOCKET_BUFFER_BYTES]),
                tcp::SocketBuffer::new(vec![0; HTTP_SOCKET_BUFFER_BYTES]),
            );
            let _ = socket.listen(HOST_DNS_PORT);
            sockets.add(socket)
        })
        .collect()
}

fn poll_dns_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    outbound_rules: Option<&[OutboundRulePlan]>,
    policy: Option<&dyn NetworkPolicyRuntime>,
    interception: &mut TransparentInterception,
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
        let src = NetworkEndpoint {
            ip: remote.endpoint.addr.to_string(),
            port: remote.endpoint.port,
        };
        let dst = NetworkEndpoint {
            ip: "10.0.2.1".to_string(),
            port: HOST_DNS_PORT,
        };
        let decision = match decide_dns(policy, NetworkProtocol::Udp, src, dst) {
            Ok(decision) if decision.action != NetworkPolicyAction::Deny => decision,
            _ => continue,
        };
        let Some(answer) = dns_response(request, NetworkProtocol::Udp, &decision.dns_resolvers)
        else {
            continue;
        };
        for pin in answer.answer_pins() {
            interception.record_dns_answer(remote.endpoint.addr, pin);
        }
        let _ = socket.send_slice(
            &answer.packet,
            IpEndpoint::new(remote.endpoint.addr, remote.endpoint.port),
        );
    }
}

fn add_udp_relay_socket(
    sockets: &mut SocketSet<'_>,
    udp_sockets: &mut HashMap<u16, SocketHandle>,
    port: u16,
) {
    udp_sockets.entry(port).or_insert_with(|| {
        let rx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 8],
            vec![0; UDP_RELAY_BUFFER_BYTES],
        );
        let tx = udp::PacketBuffer::new(
            vec![udp::PacketMetadata::EMPTY; 8],
            vec![0; UDP_RELAY_BUFFER_BYTES],
        );
        let mut socket = udp::Socket::new(rx, tx);
        let _ = socket.bind(port);
        sockets.add(socket)
    });
}

fn prune_dynamic_udp_relays(
    sockets: &mut SocketSet<'_>,
    udp_sockets: &mut HashMap<u16, SocketHandle>,
    relays: &mut HashMap<UdpFlow, UdpRelay>,
    active_intercept_ports: &HashSet<u16>,
) {
    let stale_ports = udp_sockets
        .keys()
        .copied()
        .filter(|port| !active_intercept_ports.contains(port))
        .collect::<Vec<_>>();
    for port in stale_ports {
        if let Some(handle) = udp_sockets.remove(&port) {
            sockets.remove(handle);
        }
    }
    relays.retain(|flow, _| active_intercept_ports.contains(&flow.host_port));
}

fn poll_udp_relay_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    host_port: u16,
    interception: &mut TransparentInterception,
    outbound_rules: Option<&[OutboundRulePlan]>,
    policy: Option<&dyn NetworkPolicyRuntime>,
    relays: &mut HashMap<UdpFlow, UdpRelay>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);
    while socket.can_recv() {
        let Ok((payload, remote)) = socket.recv() else {
            break;
        };
        let Some(destination) = interception.udp_original_destination(
            remote.endpoint.addr,
            remote.endpoint.port,
            host_port,
        ) else {
            continue;
        };
        let decision = decide_transport(
            policy,
            outbound_rules,
            NetworkProtocol::Udp,
            NetworkEndpoint {
                ip: remote.endpoint.addr.to_string(),
                port: remote.endpoint.port,
            },
            NetworkEndpoint {
                ip: destination.ip.clone(),
                port: destination.port,
            },
            None,
        );
        if decision.action == NetworkPolicyAction::Deny {
            continue;
        }
        let flow = UdpFlow {
            guest_ip: remote.endpoint.addr,
            guest_port: remote.endpoint.port,
            host_port,
            destination_ip: destination.ip.clone(),
            destination_port: destination.port,
        };
        let relay = relays.entry(flow).or_insert_with(|| {
            UdpRelay::connect(&destination.ip, destination.port)
                .unwrap_or_else(|_| UdpRelay::closed())
        });
        relay.send(payload);
    }

    let stale = relays
        .iter_mut()
        .filter_map(|(flow, relay)| {
            if flow.host_port != host_port {
                return None;
            }
            relay.recv().map(|payload| (flow.clone(), payload))
        })
        .collect::<Vec<_>>();
    for (flow, payload) in stale {
        let _ = socket.send_slice(&payload, IpEndpoint::new(flow.guest_ip, flow.guest_port));
    }
    relays.retain(|_, relay| !relay.is_expired());
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct UdpFlow {
    guest_ip: IpAddress,
    guest_port: u16,
    host_port: u16,
    destination_ip: String,
    destination_port: u16,
}

struct UdpRelay {
    socket: Option<UdpSocket>,
    last_seen: StdInstant,
}

impl UdpRelay {
    fn connect(destination_ip: &str, destination_port: u16) -> io::Result<Self> {
        let socket = UdpSocket::bind(("0.0.0.0", 0))?;
        socket.connect(upstream_socket_addr(destination_ip, destination_port))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: Some(socket),
            last_seen: StdInstant::now(),
        })
    }

    fn closed() -> Self {
        Self {
            socket: None,
            last_seen: StdInstant::now(),
        }
    }

    fn send(&mut self, payload: &[u8]) {
        self.last_seen = StdInstant::now();
        if let Some(socket) = &self.socket {
            let _ = socket.send(payload);
        }
    }

    fn recv(&mut self) -> Option<Vec<u8>> {
        let socket = self.socket.as_ref()?;
        let mut buffer = [0; UDP_RELAY_BUFFER_BYTES];
        match socket.recv(&mut buffer) {
            Ok(read) => {
                self.last_seen = StdInstant::now();
                Some(buffer[..read].to_vec())
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn is_expired(&self) -> bool {
        StdInstant::now().duration_since(self.last_seen) > INTERCEPT_FLOW_IDLE_TTL
    }
}

fn poll_tcp_dns_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    outbound_rules: Option<&[OutboundRulePlan]>,
    policy: Option<&dyn NetworkPolicyRuntime>,
    connections: &mut HashMap<SocketHandle, TcpDnsConnection>,
    interception: &mut TransparentInterception,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        connections.remove(&handle);
        let _ = socket.listen(HOST_DNS_PORT);
        return;
    }

    let connection = connections.entry(handle).or_default();
    while socket.can_recv() {
        let mut buffer = [0; 4096];
        let received = socket.recv_slice(&mut buffer).unwrap_or(0);
        if received == 0 {
            break;
        }
        connection.from_guest.extend_from_slice(&buffer[..received]);
    }
    while connection.from_guest.len() >= 2 {
        let request_len =
            u16::from_be_bytes([connection.from_guest[0], connection.from_guest[1]]) as usize;
        if connection.from_guest.len() < 2 + request_len {
            break;
        }
        let request = connection.from_guest[2..2 + request_len].to_vec();
        connection.from_guest.drain(..2 + request_len);
        let response =
            handle_tcp_dns_request(socket, outbound_rules, policy, interception, &request);
        if let Some(response) = response {
            connection
                .to_guest
                .extend_from_slice(&(response.packet.len() as u16).to_be_bytes());
            connection.to_guest.extend_from_slice(&response.packet);
        } else {
            connection.close_after_flush = true;
            break;
        }
    }
    while socket.can_send() && !connection.to_guest.is_empty() {
        let sent = socket.send_slice(&connection.to_guest).unwrap_or(0);
        if sent == 0 {
            break;
        }
        connection.to_guest.drain(..sent);
    }
    if connection.close_after_flush && connection.to_guest.is_empty() {
        connections.remove(&handle);
        socket.close();
    }
}

fn handle_tcp_dns_request(
    socket: &tcp::Socket<'_>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    policy: Option<&dyn NetworkPolicyRuntime>,
    interception: &mut TransparentInterception,
    request: &[u8],
) -> Option<DnsResponse> {
    if outbound_rules
        .is_some_and(|rules| !is_allowed_outbound_tcp("10.0.2.1", HOST_DNS_PORT, rules))
    {
        return None;
    }
    let remote = socket.remote_endpoint()?;
    let src = NetworkEndpoint {
        ip: remote.addr.to_string(),
        port: remote.port,
    };
    let dst = NetworkEndpoint {
        ip: "10.0.2.1".to_string(),
        port: HOST_DNS_PORT,
    };
    let decision = match decide_dns(policy, NetworkProtocol::Tcp, src, dst) {
        Ok(decision) if decision.action != NetworkPolicyAction::Deny => decision,
        _ => return None,
    };
    let response = dns_response(request, NetworkProtocol::Tcp, &decision.dns_resolvers)?;
    for pin in response.answer_pins() {
        interception.record_dns_answer(remote.addr, pin);
    }
    Some(response)
}

#[derive(Default)]
struct TcpDnsConnection {
    from_guest: Vec<u8>,
    to_guest: Vec<u8>,
    close_after_flush: bool,
}

fn add_http_listener(
    sockets: &mut SocketSet<'_>,
    http_sockets: &mut HashMap<u16, Vec<SocketHandle>>,
    port: u16,
) {
    let handles = http_sockets.entry(port).or_default();
    let listening = handles
        .iter()
        .filter(|handle| sockets.get::<tcp::Socket>(**handle).is_listening())
        .count();
    let needed = HTTP_LISTENERS_PER_PORT
        .saturating_sub(listening)
        .min(HTTP_MAX_SOCKETS_PER_PORT.saturating_sub(handles.len()));
    handles.extend((0..needed).map(|_| {
        let handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; HTTP_SOCKET_BUFFER_BYTES]),
            tcp::SocketBuffer::new(vec![0; HTTP_SOCKET_BUFFER_BYTES]),
        ));
        let _ = sockets.get_mut::<tcp::Socket>(handle).listen(port);
        handle
    }));
}

fn add_static_http_listeners(
    sockets: &mut SocketSet<'_>,
    http_sockets: &mut HashMap<u16, Vec<SocketHandle>>,
    tls_enabled: bool,
) {
    add_http_listener(sockets, http_sockets, HOST_HTTP_PORT);
    add_http_listener(sockets, http_sockets, HOST_ALT_HTTP_PORT);
    add_http_listener(sockets, http_sockets, HOST_HTTP_PROBE_PORT);
    if tls_enabled {
        add_http_listener(sockets, http_sockets, HOST_HTTPS_PORT);
        add_http_listener(sockets, http_sockets, HOST_ALT_HTTPS_PORT);
    }
}

fn prune_dynamic_http_listeners(
    sockets: &mut SocketSet<'_>,
    http_sockets: &mut HashMap<u16, Vec<SocketHandle>>,
    active_intercept_ports: &HashSet<u16>,
    http_connections: &HashMap<SocketHandle, HttpConnection>,
) {
    let stale_ports = http_sockets
        .iter()
        .filter_map(|(port, handles)| {
            (!is_static_listener_port(*port)
                && !active_intercept_ports.contains(port)
                && handles.iter().all(|handle| {
                    !http_connections.contains_key(handle)
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
        HOST_HTTP_PORT
            | HOST_ALT_HTTP_PORT
            | HOST_HTTP_PROBE_PORT
            | HOST_HTTPS_PORT
            | HOST_ALT_HTTPS_PORT
    )
}

fn poll_http_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    port: u16,
    interception: &mut TransparentInterception,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    tls_authority: Option<Arc<MitmTlsAuthority>>,
    http_connections: &mut HashMap<SocketHandle, HttpConnection>,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        if let Some(connection) = http_connections.remove(&handle) {
            notify_connection_closed(policy.as_deref(), NetworkProtocol::Tcp, &connection);
        }
        let _ = socket.listen(port);
        return;
    }

    if let Some(connection) = http_connections.get_mut(&handle) {
        poll_http_connection(socket, connection);
        if connection.is_finished() {
            if let Some(connection) = http_connections.remove(&handle) {
                notify_connection_closed(policy.as_deref(), NetworkProtocol::Tcp, &connection);
            }
            socket.close();
        }
        return;
    }

    poll_plain_http_socket(
        socket,
        handle,
        interception,
        outbound_rules,
        http,
        policy,
        tls_authority,
        http_connections,
    );
}

fn notify_connection_closed(
    policy: Option<&dyn NetworkPolicyRuntime>,
    protocol: NetworkProtocol,
    connection: &HttpConnection,
) {
    let Some(policy) = policy else {
        return;
    };
    let Some(destination) = connection.destination() else {
        return;
    };
    let _ = policy.connection_closed(NetworkConnectionAttempt {
        protocol,
        transport: protocol,
        src: NetworkEndpoint {
            ip: destination.source_ip.clone(),
            port: destination.source_port,
        },
        dst: NetworkEndpoint {
            ip: destination.ip.clone(),
            port: destination.port,
        },
        hostname: destination.hostname.clone(),
    });
}

fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x16))
}

fn is_plain_http_port(port: u16) -> bool {
    port == HOST_HTTP_PORT || port == HOST_ALT_HTTP_PORT
}

fn is_https_port(port: u16) -> bool {
    port == HOST_HTTPS_PORT || port == HOST_ALT_HTTPS_PORT
}

#[derive(Debug, Clone)]
struct HttpDestination {
    source_ip: String,
    source_port: u16,
    ip: String,
    port: u16,
    hostname: Option<String>,
}

fn original_http_destination(
    socket: &tcp::Socket<'_>,
    interception: &mut TransparentInterception,
) -> Option<HttpDestination> {
    let remote = socket.remote_endpoint()?;
    let local = socket.local_endpoint()?;
    let ip = interception.original_destination(remote.addr, remote.port, local.port)?;
    let hostname = interception.resolved_hostname(remote.addr, &ip);
    Some(HttpDestination {
        source_ip: remote.addr.to_string(),
        source_port: remote.port,
        ip,
        port: local.port,
        hostname,
    })
}

fn poll_plain_http_socket(
    socket: &mut tcp::Socket<'_>,
    handle: SocketHandle,
    interception: &mut TransparentInterception,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    tls_authority: Option<Arc<MitmTlsAuthority>>,
    http_connections: &mut HashMap<SocketHandle, HttpConnection>,
) {
    let Some(destination) = original_http_destination(socket, interception) else {
        socket.abort();
        return;
    };
    let Some(remote) = socket.remote_endpoint() else {
        socket.abort();
        return;
    };
    let decision = decide_transport(
        policy.as_deref(),
        outbound_rules,
        NetworkProtocol::Tcp,
        NetworkEndpoint {
            ip: remote.addr.to_string(),
            port: remote.port,
        },
        NetworkEndpoint {
            ip: destination.ip.clone(),
            port: destination.port,
        },
        destination.hostname.clone(),
    );
    if decision.action == NetworkPolicyAction::Deny {
        http_connections.remove(&handle);
        socket.abort();
        return;
    }

    let connection = match (port_is_probe(destination.port), decision.action) {
        (true, _) => HttpConnection::response(HOST_HTTP_PROBE_RESPONSE),
        (_, NetworkPolicyAction::Accept) => HttpConnection::raw_relay(destination),
        (_, NetworkPolicyAction::AcceptHttp) => {
            HttpConnection::intercept(destination, http, tls_authority)
        }
        (_, NetworkPolicyAction::Deny) => {
            unreachable!("deny decision returned before connection creation")
        }
    };
    let connection = http_connections.entry(handle).or_insert(connection);
    poll_http_connection(socket, connection);
}

fn port_is_probe(port: u16) -> bool {
    port == HOST_HTTP_PROBE_PORT
}

fn poll_http_connection(socket: &mut tcp::Socket<'_>, connection: &mut HttpConnection) {
    match connection {
        HttpConnection::Response(response) => {
            flush_http_response(socket, response);
        }
        HttpConnection::Intercept(intercept) => {
            intercept.poll(socket);
        }
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

fn tls_client_hello_sni(bytes: &[u8]) -> Option<String> {
    tls_client_hello_extension(bytes, 0).and_then(tls_sni_from_extension)
}

fn tls_client_hello_extension(bytes: &[u8], requested_type: u16) -> Option<&[u8]> {
    if bytes.len() < 5 || bytes[0] != 0x16 {
        return None;
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len || bytes.get(5) != Some(&0x01) {
        return None;
    }
    let handshake_len =
        ((bytes[6] as usize) << 16) | ((bytes[7] as usize) << 8) | bytes[8] as usize;
    if bytes.len() < 9 + handshake_len {
        return None;
    }
    let mut offset = 9 + 2 + 32;
    if bytes.len() <= offset {
        return None;
    }
    let session_id_len = bytes[offset] as usize;
    offset += 1 + session_id_len;
    if bytes.len() < offset + 2 {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2 + cipher_suites_len;
    if bytes.len() <= offset {
        return None;
    }
    let compression_methods_len = bytes[offset] as usize;
    offset += 1 + compression_methods_len;
    if bytes.len() < offset + 2 {
        return None;
    }
    let extensions_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
    offset += 2;
    let extensions_end = offset + extensions_len;
    if bytes.len() < extensions_end {
        return None;
    }
    while offset + 4 <= extensions_end {
        let extension_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let extension_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        offset += 4;
        if offset + extension_len > extensions_end {
            return None;
        }
        if extension_type == requested_type {
            return Some(&bytes[offset..offset + extension_len]);
        }
        offset += extension_len;
    }
    None
}

fn tls_client_hello_complete(bytes: &[u8]) -> bool {
    if bytes.len() < 9 || bytes[0] != 0x16 || bytes.get(5) != Some(&0x01) {
        return false;
    }
    let handshake_len =
        ((bytes[6] as usize) << 16) | ((bytes[7] as usize) << 8) | bytes[8] as usize;
    bytes.len() >= 9 + handshake_len
}

fn tls_intercept_server_name(destination: &HttpDestination, sni: Option<&str>) -> String {
    sni.map(str::to_string)
        .unwrap_or_else(|| destination.ip.clone())
}

fn tls_sni_from_extension(extension: &[u8]) -> Option<String> {
    if extension.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
    let mut offset = 2;
    let end = offset + list_len;
    if extension.len() < end {
        return None;
    }
    while offset + 3 <= end {
        let name_type = extension[offset];
        let name_len = u16::from_be_bytes([extension[offset + 1], extension[offset + 2]]) as usize;
        offset += 3;
        if offset + name_len > end {
            return None;
        }
        if name_type == 0 {
            return std::str::from_utf8(&extension[offset..offset + name_len])
                .ok()
                .map(str::to_string);
        }
        offset += name_len;
    }
    None
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
        OutboundRulePlan::AcceptTcp { .. } => false,
        OutboundRulePlan::AcceptPublicInternet { ports } => {
            port_matches(ports, destination_port) && is_public_ipv4_destination(destination_ip)
        }
    })
}

fn policy_decision(
    policy: Option<&dyn NetworkPolicyRuntime>,
    protocol: NetworkProtocol,
    src: NetworkEndpoint,
    dst: NetworkEndpoint,
    hostname: Option<String>,
) -> io::Result<Option<NetworkPolicyDecision>> {
    policy
        .map(|policy| {
            policy.decide_connection(NetworkConnectionAttempt {
                protocol,
                transport: protocol,
                src,
                dst,
                hostname,
            })
        })
        .transpose()
}

fn dns_policy_decision(
    policy: Option<&dyn NetworkPolicyRuntime>,
    transport: NetworkProtocol,
    src: NetworkEndpoint,
    dst: NetworkEndpoint,
) -> io::Result<Option<NetworkPolicyDecision>> {
    policy
        .map(|policy| {
            policy.decide_connection(NetworkConnectionAttempt {
                protocol: NetworkProtocol::Dns,
                transport,
                src,
                dst,
                hostname: None,
            })
        })
        .transpose()
}

fn default_allowed_decision() -> NetworkPolicyDecision {
    NetworkPolicyDecision {
        action: NetworkPolicyAction::Accept,
        dns_resolvers: Vec::new(),
    }
}

fn denied_decision() -> NetworkPolicyDecision {
    NetworkPolicyDecision {
        action: NetworkPolicyAction::Deny,
        dns_resolvers: Vec::new(),
    }
}

fn decide_transport(
    policy: Option<&dyn NetworkPolicyRuntime>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    protocol: NetworkProtocol,
    src: NetworkEndpoint,
    dst: NetworkEndpoint,
    hostname: Option<String>,
) -> NetworkPolicyDecision {
    if is_loopback_destination(&dst.ip) {
        return denied_decision();
    }
    let Some(decision) = policy_decision(policy, protocol, src, dst.clone(), hostname)
        .unwrap_or_else(|_| Some(denied_decision()))
    else {
        let allowed = match protocol {
            NetworkProtocol::Tcp => outbound_rules
                .is_some_and(|rules| is_allowed_outbound_tcp(&dst.ip, dst.port, rules)),
            NetworkProtocol::Udp => outbound_rules
                .is_some_and(|rules| is_allowed_outbound_udp(&dst.ip, dst.port, rules)),
            NetworkProtocol::Dns => true,
        };
        return NetworkPolicyDecision {
            action: if allowed {
                NetworkPolicyAction::Accept
            } else {
                NetworkPolicyAction::Deny
            },
            dns_resolvers: Vec::new(),
        };
    };
    if decision.action != NetworkPolicyAction::Deny {
        return decision;
    }
    decision
}

fn decide_dns(
    policy: Option<&dyn NetworkPolicyRuntime>,
    transport: NetworkProtocol,
    src: NetworkEndpoint,
    dst: NetworkEndpoint,
) -> io::Result<NetworkPolicyDecision> {
    dns_policy_decision(policy, transport, src, dst)
        .map(|decision| decision.unwrap_or_else(default_allowed_decision))
        .or_else(|_| Ok(denied_decision()))
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

fn is_loopback_destination(destination_ip: &str) -> bool {
    destination_ip
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|destination| destination.is_loopback())
}

fn upstream_socket_addr(destination_ip: &str, destination_port: u16) -> (String, u16) {
    (destination_ip.to_string(), destination_port)
}

fn tcp_reset_frame_for_syn(frame: &[u8], packet: Ipv4TcpPacket) -> Option<Vec<u8>> {
    if frame.len() < 14 {
        return None;
    }
    let mut reset = vec![0; 14 + 20 + 20];
    reset[0..6].copy_from_slice(&frame[6..12]);
    reset[6..12].copy_from_slice(&frame[0..6]);
    reset[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

    let ip_start = 14;
    reset[ip_start] = 0x45;
    reset[ip_start + 2..ip_start + 4].copy_from_slice(&40u16.to_be_bytes());
    reset[ip_start + 8] = 64;
    reset[ip_start + 9] = 6;
    reset[ip_start + 12..ip_start + 16].copy_from_slice(&packet.destination_ip(frame));
    reset[ip_start + 16..ip_start + 20].copy_from_slice(&packet.source_ip(frame));

    let tcp_start = ip_start + 20;
    reset[tcp_start..tcp_start + 2].copy_from_slice(&packet.destination_port(frame).to_be_bytes());
    reset[tcp_start + 2..tcp_start + 4].copy_from_slice(&packet.source_port(frame).to_be_bytes());
    reset[tcp_start + 8..tcp_start + 12]
        .copy_from_slice(&packet.sequence_number(frame).wrapping_add(1).to_be_bytes());
    reset[tcp_start + 12] = 5 << 4;
    reset[tcp_start + 13] = 0x14;

    let reset_packet = Ipv4TcpPacket {
        ip_start,
        tcp_start,
    };
    reset_packet.recompute_checksums(&mut reset);
    Some(reset)
}

#[derive(Debug, Clone)]
struct DnsResponse {
    packet: Vec<u8>,
    pins: Vec<DnsAnswerPin>,
}

impl DnsResponse {
    fn answer_pins(&self) -> impl Iterator<Item = &DnsAnswerPin> {
        self.pins.iter()
    }
}

fn dns_response(
    request: &[u8],
    transport: NetworkProtocol,
    resolvers: &[DnsResolver],
) -> Option<DnsResponse> {
    if !resolvers.is_empty() {
        let request_message = DnsMessage::from_vec(request).ok()?;
        let packet = resolve_dns_with_upstreams(request, transport, resolvers)?;
        let response_message = DnsMessage::from_vec(&packet).ok()?;
        return Some(DnsResponse {
            packet,
            pins: dns_answer_pins(&request_message, &response_message),
        });
    }

    let request_message = DnsMessage::from_vec(request).ok()?;
    let query = single_dns_query(&request_message)?;
    let name = dns_name_string(query.name());
    let supported_question =
        query.query_class() == DNSClass::IN && query.query_type() == RecordType::A;
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

    let mut response_message = DnsMessage::new(
        request_message.metadata.id,
        DnsMessageType::Response,
        request_message.metadata.op_code,
    );
    response_message.metadata =
        hickory_proto::op::Metadata::response_from_request(&request_message.metadata);
    response_message.metadata.recursion_available = true;
    if !name_exists {
        response_message.metadata.response_code = ResponseCode::NXDomain;
    }
    response_message.add_query(query.clone());

    if let Some(address) = answer {
        response_message.add_answer(Record::from_rdata(
            query.name().clone(),
            DNS_DEFAULT_TTL_SECS,
            RData::A(A(Ipv4Addr::from(address))),
        ));
    }

    let packet = response_message.to_vec().ok()?;
    Some(DnsResponse {
        packet,
        pins: dns_answer_pins(&request_message, &response_message),
    })
}

fn single_dns_query(message: &DnsMessage) -> Option<&hickory_proto::op::Query> {
    match message.queries.as_slice() {
        [query] => Some(query),
        _ => None,
    }
}

fn resolve_dns_with_upstreams(
    request: &[u8],
    transport: NetworkProtocol,
    resolvers: &[DnsResolver],
) -> Option<Vec<u8>> {
    for resolver in resolvers {
        let Ok(ip) = resolver.ip.parse::<std::net::IpAddr>() else {
            continue;
        };
        let address = std::net::SocketAddr::new(ip, resolver.port);
        let response = match transport {
            NetworkProtocol::Udp => resolve_dns_with_udp_upstream(request, address),
            NetworkProtocol::Tcp => resolve_dns_with_tcp_upstream(request, address),
            NetworkProtocol::Dns => None,
        };
        if response.is_some() {
            return response;
        }
    }
    None
}

fn resolve_dns_with_udp_upstream(request: &[u8], address: std::net::SocketAddr) -> Option<Vec<u8>> {
    let ip = address.ip();
    let bind_address = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let Ok(socket) = UdpSocket::bind(bind_address) else {
        return None;
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = socket.set_write_timeout(Some(Duration::from_secs(1)));
    if socket.connect(address).is_err() {
        return None;
    }
    if socket.send(request).is_err() {
        return None;
    }
    let mut response = vec![0; DNS_PACKET_BUFFER_BYTES];
    let Ok(received) = socket.recv(&mut response) else {
        return None;
    };
    response.truncate(received);
    Some(response)
}

fn resolve_dns_with_tcp_upstream(request: &[u8], address: std::net::SocketAddr) -> Option<Vec<u8>> {
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
        return None;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let request_len = u16::try_from(request.len()).ok()?;
    if stream.write_all(&request_len.to_be_bytes()).is_err() {
        return None;
    }
    if stream.write_all(request).is_err() {
        return None;
    }
    let mut response_len = [0; 2];
    if stream.read_exact(&mut response_len).is_err() {
        return None;
    }
    let response_len = u16::from_be_bytes(response_len) as usize;
    if response_len > DNS_PACKET_BUFFER_BYTES {
        return None;
    }
    let mut response = vec![0; response_len];
    if stream.read_exact(&mut response).is_err() {
        return None;
    }
    Some(response)
}

fn dns_answer_pins(request: &DnsMessage, response: &DnsMessage) -> Vec<DnsAnswerPin> {
    let Some(query) = single_dns_query(request) else {
        return Vec::new();
    };
    let name = dns_name_string(query.name());
    let answer_names = dns_answer_names_for_query(query.name(), response);
    response
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(address)
                if record.dns_class == DNSClass::IN && answer_names.contains(&record.name) =>
            {
                Some(DnsAnswerPin {
                    hostname: name.clone(),
                    address: address.0.octets(),
                    ttl: Duration::from_secs(record.ttl.into()),
                })
            }
            _ => None,
        })
        .collect()
}

fn dns_answer_names_for_query(query_name: &Name, response: &DnsMessage) -> HashSet<Name> {
    let mut names = HashSet::from([query_name.clone()]);
    for _ in 0..8 {
        let mut changed = false;
        for record in &response.answers {
            let RData::CNAME(target) = &record.data else {
                continue;
            };
            if record.dns_class == DNSClass::IN
                && names.contains(&record.name)
                && names.insert((**target).clone())
            {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    names
}

fn dns_name_string(name: &hickory_proto::rr::Name) -> String {
    name.to_ascii().trim_end_matches('.').to_ascii_lowercase()
}

fn dns_address(name: &str) -> Option<[u8; 4]> {
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
    interception: TransparentInterception,
    outbound_rules: Option<Vec<OutboundRulePlan>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    rx_buffer: Vec<u8>,
    staged_rx: Option<Vec<u8>>,
    pending_tx: Vec<u8>,
}

impl LibkrunNetDevice {
    fn new(
        rx: UnixStream,
        tx: UnixStream,
        host_ip: Ipv4Address,
        outbound_rules: Option<Vec<OutboundRulePlan>>,
        policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    ) -> Self {
        Self {
            rx,
            tx,
            interception: TransparentInterception::new(host_ip),
            outbound_rules,
            policy,
            rx_buffer: Vec::new(),
            staged_rx: None,
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

    fn reject_denied_tcp_syn(&mut self, frame: &[u8]) -> bool {
        let Some(packet) = Ipv4TcpPacket::parse(frame) else {
            return false;
        };
        if packet.destination_ip(frame) == self.interception.host_ip {
            return false;
        }
        let flags = packet.tcp_flags(frame);
        if !flags.syn || flags.ack {
            return false;
        }
        let source_ip = packet.source_ip(frame);
        let destination_ip = packet.destination_ip(frame);
        let src = NetworkEndpoint {
            ip: Ipv4Address::new(source_ip[0], source_ip[1], source_ip[2], source_ip[3])
                .to_string(),
            port: packet.source_port(frame),
        };
        let dst = NetworkEndpoint {
            ip: Ipv4Address::new(
                destination_ip[0],
                destination_ip[1],
                destination_ip[2],
                destination_ip[3],
            )
            .to_string(),
            port: packet.destination_port(frame),
        };
        let decision = decide_transport(
            self.policy.as_deref(),
            self.outbound_rules.as_deref(),
            NetworkProtocol::Tcp,
            src,
            dst,
            self.interception.resolved_hostname(
                IpAddress::v4(source_ip[0], source_ip[1], source_ip[2], source_ip[3]),
                &Ipv4Address::new(
                    destination_ip[0],
                    destination_ip[1],
                    destination_ip[2],
                    destination_ip[3],
                )
                .to_string(),
            ),
        );
        if decision.action == NetworkPolicyAction::Accept
            || decision.action == NetworkPolicyAction::AcceptHttp
        {
            return false;
        }
        let Some(reset) = tcp_reset_frame_for_syn(frame, packet) else {
            return false;
        };
        if let Ok(frame_len) = u32::try_from(reset.len()) {
            self.pending_tx.extend_from_slice(&frame_len.to_be_bytes());
            self.pending_tx.extend_from_slice(&reset);
        }
        true
    }
}

impl Device for LibkrunNetDevice {
    type RxToken<'a> = LibkrunRxToken;
    type TxToken<'a> = LibkrunTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.flush_pending_tx();
        if let Some(frame) = self.staged_rx.take() {
            return Some((
                LibkrunRxToken { frame },
                LibkrunTxToken {
                    pending_tx: &mut self.pending_tx,
                    interception: &mut self.interception,
                },
            ));
        }
        match self.read_frame() {
            Ok(frame) => {
                let mut frame = frame?;
                if self.reject_denied_tcp_syn(&frame) {
                    return None;
                }
                if self.interception.rewrite_guest_frame(&mut frame) {
                    self.staged_rx = Some(frame);
                    return None;
                }
                Some((
                    LibkrunRxToken { frame },
                    LibkrunTxToken {
                        pending_tx: &mut self.pending_tx,
                        interception: &mut self.interception,
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
            interception: &mut self.interception,
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
    interception: &'a mut TransparentInterception,
}

impl phy::TxToken for LibkrunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        self.interception.rewrite_host_frame(&mut frame);
        if let Ok(frame_len) = u32::try_from(frame.len()) {
            self.pending_tx.extend_from_slice(&frame_len.to_be_bytes());
            self.pending_tx.extend_from_slice(&frame);
        }
        result
    }
}

enum HttpConnection {
    Response(HttpResponseConnection),
    Intercept(InterceptConnection),
}

impl HttpConnection {
    fn response(response: &'static [u8]) -> Self {
        Self::Response(HttpResponseConnection {
            to_guest: response.to_vec(),
            close_after_response: true,
        })
    }

    fn intercept(
        destination: HttpDestination,
        runtime: Option<Arc<dyn HttpInterceptRuntime>>,
        tls_authority: Option<Arc<MitmTlsAuthority>>,
    ) -> Self {
        Self::Intercept(InterceptConnection {
            destination,
            runtime,
            tls_authority,
            http_enforced: true,
            state: InterceptState::ReadingHead {
                guest_head: Vec::new(),
            },
            upstream: None,
            to_guest: Vec::new(),
            to_upstream: Vec::new(),
            close_after_flush: false,
        })
    }

    fn raw_relay(destination: HttpDestination) -> Self {
        let mut connection = InterceptConnection {
            destination,
            runtime: None,
            tls_authority: None,
            http_enforced: false,
            state: InterceptState::ReadingHead {
                guest_head: Vec::new(),
            },
            upstream: None,
            to_guest: Vec::new(),
            to_upstream: Vec::new(),
            close_after_flush: false,
        };
        connection.start_raw_relay(Vec::new());
        Self::Intercept(connection)
    }

    fn is_finished(&self) -> bool {
        match self {
            Self::Response(response) => {
                response.close_after_response && response.to_guest.is_empty()
            }
            Self::Intercept(intercept) => {
                intercept.close_after_flush && intercept.to_guest.is_empty()
            }
        }
    }

    fn destination(&self) -> Option<&HttpDestination> {
        match self {
            Self::Response(_) => None,
            Self::Intercept(intercept) => Some(&intercept.destination),
        }
    }
}

#[derive(Default)]
struct HttpResponseConnection {
    to_guest: Vec<u8>,
    close_after_response: bool,
}

enum InterceptState {
    ReadingHead { guest_head: Vec<u8> },
    RamaHttp(RamaHttpConnection),
    Tls(TlsInterceptConnection),
    Relaying,
    Closing,
}

struct InterceptConnection {
    destination: HttpDestination,
    runtime: Option<Arc<dyn HttpInterceptRuntime>>,
    tls_authority: Option<Arc<MitmTlsAuthority>>,
    http_enforced: bool,
    state: InterceptState,
    upstream: Option<TcpStream>,
    to_guest: Vec<u8>,
    to_upstream: Vec<u8>,
    close_after_flush: bool,
}

struct TlsInterceptConnection {
    server: rustls::ServerConnection,
    bridge: SyncAsyncBridge,
    to_guest: Vec<u8>,
    close_after_flush: bool,
    sent_close_notify: bool,
}

struct RamaHttpConnection {
    bridge: SyncAsyncBridge,
    to_guest: Vec<u8>,
    close_after_flush: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpScheme {
    Http,
    Https,
}

impl HttpScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Debug, Clone)]
struct HttpFlowContext {
    scheme: HttpScheme,
    destination: HttpDestination,
    tls: Option<HostTlsMetadata>,
}

impl HttpFlowContext {
    fn authority(&self) -> String {
        let host = self
            .tls
            .as_ref()
            .and_then(|tls| tls.server_name.as_deref())
            .or(self.destination.hostname.as_deref())
            .unwrap_or(&self.destination.ip);
        format!("{}:{}", host, self.destination.port)
    }
}

#[derive(Debug, Clone)]
struct FixedDestinationConnector {
    destination: HttpDestination,
}

impl<B> Service<RamaRequest<B>> for FixedDestinationConnector
where
    B: Send + 'static,
{
    type Output = EstablishedClientConnection<RamaTcpStream, RamaRequest<B>>;
    type Error = io::Error;

    async fn serve(&self, _request: RamaRequest<B>) -> Result<Self::Output, Self::Error> {
        let request = _request;
        let upstream = TcpStream::connect(upstream_socket_addr(
            &self.destination.ip,
            self.destination.port,
        ))?;
        upstream.set_nonblocking(true)?;
        let conn = RamaTcpStream::try_from_std_tcp_stream(upstream, Extensions::new())?;
        Ok(EstablishedClientConnection {
            input: request,
            conn,
        })
    }
}

fn apply_rama_http_policy(
    mut request: RamaRequest<Body>,
    context: &HttpFlowContext,
    runtime: Option<&dyn HttpInterceptRuntime>,
) -> io::Result<RamaRequest<Body>> {
    let authority = context.authority();
    let policy_headers = request
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_ascii_lowercase(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect::<Vec<_>>();
    let mut intercepted = InterceptedHttpRequest {
        protocol: match request.version() {
            RamaVersion::HTTP_2 => HttpRequestProtocol::Http2,
            _ => HttpRequestProtocol::Http1,
        },
        method: request.method().as_str().to_string(),
        url: format!(
            "{}://{}{}",
            context.scheme.as_str(),
            authority,
            request_path(&request)
        ),
        original_destination: InterceptedDestination {
            ip: context.destination.ip.clone(),
            port: context.destination.port,
            hostname: context.destination.hostname.clone(),
        },
        source: InterceptedDestination {
            ip: context.destination.source_ip.clone(),
            port: context.destination.source_port,
            hostname: None,
        },
        headers: policy_headers.clone(),
        tls: context.tls.clone(),
    };
    if !intercepted
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        intercepted
            .headers
            .push(("host".to_string(), authority.clone()));
    }
    let intercepted = match runtime {
        Some(runtime) => runtime.handle_request_head(intercepted)?,
        None => intercepted,
    };
    if intercepted.headers == policy_headers {
        return Ok(request);
    }
    let is_h2 = request.version() == RamaVersion::HTTP_2;
    let headers = request.headers_mut();
    headers.clear();
    for (name, value) in intercepted.headers {
        if is_h2 && name.eq_ignore_ascii_case("connection") {
            continue;
        }
        headers.insert(
            name.parse::<rama_http::HeaderName>()
                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?,
            value
                .parse::<rama_http::HeaderValue>()
                .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?,
        );
    }
    Ok(request)
}

async fn serve_rama_http_request(
    request: RamaRequest<Body>,
    context: &HttpFlowContext,
    runtime: Option<&dyn HttpInterceptRuntime>,
) -> RamaResponse {
    let mut request = match apply_rama_http_policy(request, context, runtime) {
        Ok(request) => request,
        Err(_) => return rama_response(403, "network policy denied"),
    };

    if normalize_rama_request_uri(&mut request, context).is_err() {
        return rama_response(403, "network policy denied");
    }

    let connector = FixedDestinationConnector {
        destination: context.destination.clone(),
    };
    match context.scheme {
        HttpScheme::Http => serve_rama_upstream(connector, request).await,
        HttpScheme::Https => {
            let Ok(tls) = TlsConnectorData::try_new_http_auto() else {
                return rama_response(502, "upstream tls connect failed");
            };
            let connector = TlsConnector::auto(connector).with_connector_data(tls);
            let connector = RequestVersionAdapter::new(connector);
            serve_rama_upstream(connector, request).await
        }
    }
}

async fn serve_rama_upstream<C>(connector: C, request: RamaRequest<Body>) -> RamaResponse
where
    C: Service<RamaRequest<Body>, Error: Into<rama_core::error::BoxError>>,
    C::Output: IntoRamaEstablishedConnection<RamaRequest<Body>>,
{
    let guest_version = request.version();
    let established = match connector.serve(request).await {
        Ok(established) => established.into_established_connection(),
        Err(_) => return rama_response(502, "upstream connect failed"),
    };
    let connection =
        match http_connect(established.conn, established.input, Executor::default()).await {
            Ok(connection) => connection,
            Err(_) => return rama_response(502, "upstream http connect failed"),
        };
    match connection.conn.serve(connection.input).await {
        Ok(mut response) => {
            *response.version_mut() = guest_version;
            response
        }
        Err(_) => rama_response(502, "upstream request failed"),
    }
}

trait IntoRamaEstablishedConnection<Input> {
    type Connection: rama_core::io::Io + Unpin + rama_core::extensions::ExtensionsRef;

    fn into_established_connection(self) -> EstablishedClientConnection<Self::Connection, Input>;
}

impl<Connection, Input> IntoRamaEstablishedConnection<Input>
    for EstablishedClientConnection<Connection, Input>
where
    Connection: rama_core::io::Io + Unpin + rama_core::extensions::ExtensionsRef,
{
    type Connection = Connection;

    fn into_established_connection(self) -> EstablishedClientConnection<Self::Connection, Input> {
        self
    }
}

fn normalize_rama_request_uri(
    request: &mut RamaRequest<Body>,
    context: &HttpFlowContext,
) -> io::Result<()> {
    let authority = context.authority();
    let uri = format!(
        "{}://{}{}",
        context.scheme.as_str(),
        authority,
        request_path(request)
    )
    .parse()
    .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    *request.uri_mut() = uri;
    Ok(())
}

fn rama_response(status: u16, body: &'static str) -> RamaResponse {
    RamaResponse::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap()
}

fn request_path(request: &RamaRequest<Body>) -> &str {
    request
        .uri()
        .path_and_query()
        .map(|path| path.as_str())
        .unwrap_or("/")
}

impl RamaHttpConnection {
    fn start(
        context: HttpFlowContext,
        initial_guest_bytes: Vec<u8>,
        runtime: Option<Arc<dyn HttpInterceptRuntime>>,
    ) -> io::Result<Self> {
        let (bridge, async_io) = SyncAsyncBridge::new(HTTP_BRIDGE_BUFFER_BYTES);
        if !initial_guest_bytes.is_empty() {
            bridge.push_from_sync(&initial_guest_bytes);
        }
        thread::spawn(move || {
            let Ok(tokio_runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            tokio_runtime.block_on(async move {
                let server = HttpServer::auto(Executor::default());
                let context = Arc::new(context);
                let service = rama_core::service::service_fn(move |request: RamaRequest<Body>| {
                    let context = context.clone();
                    let runtime = runtime.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            serve_rama_http_request(request, &context, runtime.as_deref()).await,
                        )
                    }
                });
                let _ = server.serve(async_io, service).await;
            });
        });
        Ok(Self {
            bridge,
            to_guest: Vec::new(),
            close_after_flush: false,
        })
    }

    fn poll(&mut self, socket: &mut tcp::Socket<'_>) {
        while socket.can_recv() {
            let writable = self.bridge.sync_write_capacity();
            if writable == 0 {
                break;
            }
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let received = socket
                .recv_slice(&mut buffer[..writable.min(TLS_READ_BUFFER_BYTES)])
                .unwrap_or(0);
            if received == 0 {
                self.bridge.close_sync();
                break;
            }
            if self.bridge.push_from_sync(&buffer[..received]) != received {
                break;
            }
        }
        while self.to_guest.len() < HTTP_BRIDGE_BUFFER_BYTES {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let read = self.bridge.pull_to_sync(&mut buffer);
            if read == 0 {
                break;
            }
            self.to_guest.extend_from_slice(&buffer[..read]);
        }
        while socket.can_send() && !self.to_guest.is_empty() {
            let sent = socket.send_slice(&self.to_guest).unwrap_or(0);
            if sent == 0 {
                break;
            }
            self.to_guest.drain(..sent);
        }
        if self.bridge.async_is_closed() && self.bridge.async_to_sync_is_empty() {
            self.close_after_flush = true;
        }
    }

    fn is_finished(&self) -> bool {
        self.close_after_flush && self.to_guest.is_empty()
    }
}

impl TlsInterceptConnection {
    fn new(
        authority: Arc<MitmTlsAuthority>,
        server_name: &str,
        sni: Option<String>,
        initial_guest_tls: &[u8],
        destination: HttpDestination,
        runtime: Option<Arc<dyn HttpInterceptRuntime>>,
    ) -> io::Result<Self> {
        let (bridge, async_io) = SyncAsyncBridge::new(HTTP_BRIDGE_BUFFER_BYTES);
        let metadata = HostTlsMetadata {
            server_name: sni,
            alpn_protocol: None,
            protocol: Some("tls".to_string()),
        };
        thread::spawn(move || {
            let Ok(tokio_runtime) = tokio::runtime::Runtime::new() else {
                return;
            };
            tokio_runtime.block_on(async move {
                let server = HttpServer::auto(Executor::default());
                let context = Arc::new(HttpFlowContext {
                    scheme: HttpScheme::Https,
                    destination,
                    tls: Some(metadata),
                });
                let service = rama_core::service::service_fn(move |request: RamaRequest<Body>| {
                    let context = context.clone();
                    let runtime = runtime.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            serve_rama_http_request(request, &context, runtime.as_deref()).await,
                        )
                    }
                });
                let _ = server.serve(async_io, service).await;
            });
        });
        let mut connection = Self {
            server: authority.server_connection(server_name)?,
            bridge,
            to_guest: Vec::new(),
            close_after_flush: false,
            sent_close_notify: false,
        };
        connection.read_guest_tls(initial_guest_tls);
        Ok(connection)
    }

    fn poll(&mut self, socket: &mut tcp::Socket<'_>) {
        while socket.can_recv() {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let received = socket.recv_slice(&mut buffer).unwrap_or(0);
            if received == 0 {
                break;
            }
            self.read_guest_tls(&buffer[..received]);
        }
        self.flush_guest_tls(socket);
        self.flush_rama_plaintext();
        self.flush_guest_tls(socket);
    }

    fn read_guest_tls(&mut self, bytes: &[u8]) {
        let mut cursor = std::io::Cursor::new(bytes);
        while cursor.position() < bytes.len() as u64 {
            match self.server.read_tls(&mut cursor) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    self.close_after_flush = true;
                    return;
                }
            }
            if self.server.process_new_packets().is_err() {
                self.close_after_flush = true;
                return;
            }
        }
        self.drain_server_tls();
        let mut plaintext = Vec::new();
        loop {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            match self.server.reader().read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => plaintext.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close_after_flush = true;
                    return;
                }
            }
        }
        if plaintext.is_empty() {
            return;
        }
        if self.bridge.push_from_sync(&plaintext) != plaintext.len() {
            self.close_after_flush = true;
        }
    }

    fn drain_server_tls(&mut self) {
        let _ = self.server.write_tls(&mut self.to_guest);
    }

    fn flush_rama_plaintext(&mut self) {
        while self.to_guest.len() < TLS_READ_BUFFER_BYTES {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let read = self.bridge.pull_to_sync(&mut buffer);
            if read == 0 {
                break;
            }
            if self.server.writer().write_all(&buffer[..read]).is_err() {
                self.close_after_flush = true;
                return;
            }
            self.drain_server_tls();
        }
        if self.bridge.async_is_closed() && self.bridge.async_to_sync_is_empty() {
            self.close_after_clean_tls_shutdown();
        }
    }

    fn flush_guest_tls(&mut self, socket: &mut tcp::Socket<'_>) {
        self.drain_server_tls();
        while socket.can_send() && !self.to_guest.is_empty() {
            let sent = socket.send_slice(&self.to_guest).unwrap_or(0);
            if sent == 0 {
                break;
            }
            self.to_guest.drain(..sent);
        }
    }

    fn close_after_clean_tls_shutdown(&mut self) {
        if !self.sent_close_notify {
            self.server.send_close_notify();
            self.sent_close_notify = true;
            self.drain_server_tls();
        }
        self.close_after_flush = true;
    }

    fn is_finished(&self) -> bool {
        self.close_after_flush && self.to_guest.is_empty()
    }
}

impl InterceptConnection {
    fn poll(&mut self, socket: &mut tcp::Socket<'_>) {
        if matches!(self.state, InterceptState::ReadingHead { .. }) {
            self.read_guest_head(socket);
        }
        if let InterceptState::RamaHttp(relay) = &mut self.state {
            relay.poll(socket);
            if relay.is_finished() {
                self.close_after_flush = true;
            }
            return;
        }
        if let InterceptState::Tls(tls) = &mut self.state {
            tls.poll(socket);
            if tls.is_finished() {
                self.close_after_flush = true;
            }
            return;
        }
        self.flush_upstream();
        self.read_upstream();
        self.flush_guest(socket);
        if matches!(self.state, InterceptState::Relaying) {
            self.relay_guest_body(socket);
        }
        self.flush_upstream();
        self.read_upstream();
        self.flush_guest(socket);
    }

    fn read_guest_head(&mut self, socket: &mut tcp::Socket<'_>) {
        if is_plain_http_port(self.destination.port) {
            self.start_rama_http(Vec::new());
            return;
        }
        if !self.http_enforced && !is_https_port(self.destination.port) {
            self.start_raw_relay(Vec::new());
            return;
        }
        if !self.http_enforced && self.tls_authority.is_none() {
            self.start_raw_relay(Vec::new());
            return;
        }

        while socket.can_recv() {
            let InterceptState::ReadingHead { guest_head } = &mut self.state else {
                return;
            };
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let received = socket.recv_slice(&mut buffer).unwrap_or(0);
            if received == 0 {
                break;
            }
            guest_head.extend_from_slice(&buffer[..received]);
            if guest_head.len() > MAX_INTERCEPT_HEAD_BYTES {
                self.to_guest.extend_from_slice(OUTBOUND_DENIED_RESPONSE);
                self.close_after_flush = true;
                self.state = InterceptState::Closing;
                return;
            }
            if !looks_like_tls(guest_head) {
                if self.http_enforced {
                    let initial_bytes = std::mem::take(guest_head);
                    self.start_rama_http(initial_bytes);
                    return;
                }
                self.close_after_flush = true;
                self.state = InterceptState::Closing;
                return;
            }
            if self.tls_authority.is_none() {
                self.close_after_flush = true;
                self.state = InterceptState::Closing;
                return;
            }
            if !tls_client_hello_complete(guest_head) {
                continue;
            }
            let sni = tls_client_hello_sni(guest_head);
            let server_name = tls_intercept_server_name(&self.destination, sni.as_deref());
            let authority = self
                .tls_authority
                .as_ref()
                .expect("HTTPS interception checked TLS authority before reading ClientHello");
            match TlsInterceptConnection::new(
                authority.clone(),
                &server_name,
                sni,
                guest_head,
                self.destination.clone(),
                self.runtime.clone(),
            ) {
                Ok(tls) => {
                    self.state = InterceptState::Tls(tls);
                }
                Err(_) => {
                    self.close_after_flush = true;
                    self.state = InterceptState::Closing;
                }
            }
            return;
        }
    }

    fn start_rama_http(&mut self, initial_bytes: Vec<u8>) {
        match RamaHttpConnection::start(
            HttpFlowContext {
                scheme: HttpScheme::Http,
                destination: self.destination.clone(),
                tls: None,
            },
            initial_bytes,
            self.runtime.clone(),
        ) {
            Ok(relay) => {
                self.state = InterceptState::RamaHttp(relay);
            }
            Err(_) => {
                self.to_guest.extend_from_slice(OUTBOUND_DENIED_RESPONSE);
                self.close_after_flush = true;
                self.state = InterceptState::Closing;
            }
        }
    }

    fn start_raw_relay(&mut self, initial_bytes: Vec<u8>) {
        match TcpStream::connect(upstream_socket_addr(
            &self.destination.ip,
            self.destination.port,
        )) {
            Ok(upstream) => {
                let _ = upstream.set_nonblocking(true);
                self.to_upstream.extend_from_slice(&initial_bytes);
                self.upstream = Some(upstream);
                self.state = InterceptState::Relaying;
            }
            Err(_) => {
                self.to_guest.extend_from_slice(OUTBOUND_DENIED_RESPONSE);
                self.close_after_flush = true;
                self.state = InterceptState::Closing;
            }
        }
    }

    fn relay_guest_body(&mut self, socket: &mut tcp::Socket<'_>) {
        while socket.can_recv() {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let received = socket.recv_slice(&mut buffer).unwrap_or(0);
            if received == 0 {
                break;
            }
            self.to_upstream.extend_from_slice(&buffer[..received]);
        }
    }

    fn flush_upstream(&mut self) {
        let Some(upstream) = &mut self.upstream else {
            return;
        };
        while !self.to_upstream.is_empty() {
            match upstream.write(&self.to_upstream) {
                Ok(0) => break,
                Ok(written) => {
                    self.to_upstream.drain(..written);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close_after_flush = true;
                    break;
                }
            }
        }
    }

    fn read_upstream(&mut self) {
        let Some(upstream) = &mut self.upstream else {
            return;
        };
        loop {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            match upstream.read(&mut buffer) {
                Ok(0) => {
                    self.close_after_flush = true;
                    let _ = upstream.shutdown(Shutdown::Both);
                    break;
                }
                Ok(read) => self.to_guest.extend_from_slice(&buffer[..read]),
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close_after_flush = true;
                    break;
                }
            }
        }
    }

    fn flush_guest(&mut self, socket: &mut tcp::Socket<'_>) {
        while socket.can_send() && !self.to_guest.is_empty() {
            let sent = socket.send_slice(&self.to_guest).unwrap_or(0);
            if sent == 0 {
                break;
            }
            self.to_guest.drain(..sent);
        }
    }
}

#[derive(Debug)]
struct TransparentInterception {
    host_ip: [u8; 4],
    tcp_flows: HashMap<TcpFlow, InterceptedFlow>,
    udp_flows: HashMap<UdpInterceptedFlow, InterceptedFlow>,
    dns_pins: DnsPins,
    next_udp_host_port: u16,
}

#[derive(Debug, Default)]
struct DnsPins {
    pins: Vec<DnsPin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsAnswerPin {
    hostname: String,
    address: [u8; 4],
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct DnsPin {
    guest_ip: [u8; 4],
    hostname: String,
    address: [u8; 4],
    expires_at: StdInstant,
    observed_at: StdInstant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlow {
    guest_ip: [u8; 4],
    guest_port: u16,
    host_port: u16,
}

#[derive(Debug, Clone, Copy)]
struct InterceptedFlow {
    destination_ip: [u8; 4],
    destination_port: u16,
    last_seen: StdInstant,
    closing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpInterceptedFlow {
    guest_ip: [u8; 4],
    guest_port: u16,
    host_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpDestination {
    ip: String,
    port: u16,
}

impl TransparentInterception {
    fn new(host_ip: Ipv4Address) -> Self {
        Self {
            host_ip: host_ip.octets(),
            tcp_flows: HashMap::new(),
            udp_flows: HashMap::new(),
            dns_pins: DnsPins::default(),
            next_udp_host_port: UDP_INTERCEPT_PORT_START,
        }
    }

    fn rewrite_guest_frame(&mut self, frame: &mut [u8]) -> bool {
        self.prune_expired_flows();
        if let Some(packet) = Ipv4TcpPacket::parse(frame) {
            if packet.destination_ip(frame) == self.host_ip {
                return false;
            }

            let flow = TcpFlow {
                guest_ip: packet.source_ip(frame),
                guest_port: packet.source_port(frame),
                host_port: packet.destination_port(frame),
            };
            let new_host_port = !self.tcp_flows.contains_key(&flow);
            let flags = packet.tcp_flags(frame);
            if flags.rst {
                self.tcp_flows.remove(&flow);
            } else {
                self.tcp_flows.insert(
                    flow,
                    InterceptedFlow {
                        destination_ip: packet.destination_ip(frame),
                        destination_port: packet.destination_port(frame),
                        last_seen: StdInstant::now(),
                        closing: flags.fin,
                    },
                );
            }
            packet.set_destination_ip(frame, self.host_ip);
            packet.recompute_checksums(frame);
            return new_host_port;
        }

        let Some(packet) = Ipv4UdpPacket::parse(frame) else {
            return false;
        };
        if packet.destination_ip(frame) == self.host_ip {
            return false;
        }
        let guest_ip = packet.source_ip(frame);
        let guest_port = packet.source_port(frame);
        let destination_ip = packet.destination_ip(frame);
        let destination_port = packet.destination_port(frame);
        let Some(host_port) = self.udp_host_port_for_destination(
            guest_ip,
            guest_port,
            destination_ip,
            destination_port,
        ) else {
            return false;
        };
        let flow = UdpInterceptedFlow {
            guest_ip,
            guest_port,
            host_port,
        };
        let new_host_port = !self.udp_flows.contains_key(&flow);
        self.udp_flows.insert(
            flow,
            InterceptedFlow {
                destination_ip,
                destination_port,
                last_seen: StdInstant::now(),
                closing: false,
            },
        );
        packet.set_destination_ip(frame, self.host_ip);
        packet.set_destination_port(frame, host_port);
        packet.recompute_checksums(frame);
        new_host_port
    }

    fn rewrite_host_frame(&mut self, frame: &mut [u8]) {
        self.prune_expired_flows();
        if let Some(packet) = Ipv4TcpPacket::parse(frame) {
            if packet.source_ip(frame) != self.host_ip {
                return;
            }

            let flow = TcpFlow {
                guest_ip: packet.destination_ip(frame),
                guest_port: packet.destination_port(frame),
                host_port: packet.source_port(frame),
            };
            let Some(intercepted_flow) = self.tcp_flows.get_mut(&flow) else {
                return;
            };
            intercepted_flow.last_seen = StdInstant::now();
            let original_destination = intercepted_flow.destination_ip;
            let flags = packet.tcp_flags(frame);
            packet.set_source_ip(frame, original_destination);
            packet.recompute_checksums(frame);
            if flags.fin || flags.rst {
                self.tcp_flows.remove(&flow);
            }
            return;
        }

        let Some(packet) = Ipv4UdpPacket::parse(frame) else {
            return;
        };
        if packet.source_ip(frame) != self.host_ip {
            return;
        }
        let flow = UdpInterceptedFlow {
            guest_ip: packet.destination_ip(frame),
            guest_port: packet.destination_port(frame),
            host_port: packet.source_port(frame),
        };
        if let Some(intercepted_flow) = self.udp_flows.get_mut(&flow) {
            intercepted_flow.last_seen = StdInstant::now();
            packet.set_source_ip(frame, intercepted_flow.destination_ip);
            packet.set_source_port(frame, intercepted_flow.destination_port);
            packet.recompute_checksums(frame);
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
        self.tcp_flows.get(&flow).map(|flow| {
            let address = flow.destination_ip;
            Ipv4Address::new(address[0], address[1], address[2], address[3]).to_string()
        })
    }

    fn record_dns_answer(&mut self, guest_ip: IpAddress, answer: &DnsAnswerPin) {
        let guest_ip = match guest_ip {
            IpAddress::Ipv4(guest_ip) => guest_ip.octets(),
        };
        let now = StdInstant::now();
        self.dns_pins.pins.retain(|pin| {
            !(pin.guest_ip == guest_ip
                && pin.hostname == answer.hostname
                && pin.address == answer.address)
        });
        self.dns_pins.pins.push(DnsPin {
            guest_ip,
            hostname: answer.hostname.clone(),
            address: answer.address,
            expires_at: now + answer.ttl,
            observed_at: now,
        });
    }

    fn resolved_hostname(&mut self, guest_ip: IpAddress, ip: &str) -> Option<String> {
        self.prune_expired_dns_pins();
        let guest_ip = match guest_ip {
            IpAddress::Ipv4(guest_ip) => guest_ip.octets(),
        };
        let address = ip.parse::<std::net::Ipv4Addr>().ok()?.octets();
        self.dns_pins
            .pins
            .iter()
            .filter(|pin| pin.guest_ip == guest_ip && pin.address == address)
            .max_by_key(|pin| pin.observed_at)
            .map(|pin| pin.hostname.clone())
    }

    fn udp_original_destination(
        &self,
        guest_ip: IpAddress,
        guest_port: u16,
        host_port: u16,
    ) -> Option<UdpDestination> {
        let guest_ip = match guest_ip {
            IpAddress::Ipv4(guest_ip) => guest_ip.octets(),
        };
        let flow = UdpInterceptedFlow {
            guest_ip,
            guest_port,
            host_port,
        };
        self.udp_flows.get(&flow).map(|flow| {
            let address = flow.destination_ip;
            UdpDestination {
                ip: Ipv4Address::new(address[0], address[1], address[2], address[3]).to_string(),
                port: flow.destination_port,
            }
        })
    }

    fn tcp_host_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.tcp_flows.keys().map(|flow| flow.host_port)
    }

    fn udp_host_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.udp_flows.keys().map(|flow| flow.host_port)
    }

    fn prune_expired_flows(&mut self) {
        let now = StdInstant::now();
        self.tcp_flows.retain(|_, flow| {
            now.duration_since(flow.last_seen)
                < if flow.closing {
                    INTERCEPT_FLOW_CLOSING_TTL
                } else {
                    INTERCEPT_FLOW_IDLE_TTL
                }
        });
        self.udp_flows
            .retain(|_, flow| now.duration_since(flow.last_seen) < INTERCEPT_FLOW_IDLE_TTL);
        self.prune_expired_dns_pins();
    }

    fn prune_expired_dns_pins(&mut self) {
        let now = StdInstant::now();
        self.dns_pins.pins.retain(|pin| pin.expires_at > now);
    }

    fn udp_host_port_for_destination(
        &mut self,
        guest_ip: [u8; 4],
        guest_port: u16,
        destination_ip: [u8; 4],
        destination_port: u16,
    ) -> Option<u16> {
        if let Some((flow, _)) = self.udp_flows.iter().find(|(flow, intercepted_flow)| {
            flow.guest_ip == guest_ip
                && flow.guest_port == guest_port
                && intercepted_flow.destination_ip == destination_ip
                && intercepted_flow.destination_port == destination_port
        }) {
            return Some(flow.host_port);
        }

        for _ in UDP_INTERCEPT_PORT_START..=UDP_INTERCEPT_PORT_END {
            let candidate = self.next_udp_host_port;
            self.next_udp_host_port = if self.next_udp_host_port == UDP_INTERCEPT_PORT_END {
                UDP_INTERCEPT_PORT_START
            } else {
                self.next_udp_host_port + 1
            };
            if is_static_listener_port(candidate)
                || self
                    .udp_flows
                    .keys()
                    .any(|flow| flow.host_port == candidate)
            {
                continue;
            }
            return Some(candidate);
        }
        None
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

    fn sequence_number(self, frame: &[u8]) -> u32 {
        u32::from_be_bytes([
            frame[self.tcp_start + 4],
            frame[self.tcp_start + 5],
            frame[self.tcp_start + 6],
            frame[self.tcp_start + 7],
        ])
    }

    fn tcp_flags(self, frame: &[u8]) -> TcpFlags {
        let flags = frame[self.tcp_start + 13];
        TcpFlags {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            ack: flags & 0x10 != 0,
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
    syn: bool,
    rst: bool,
    ack: bool,
}

#[derive(Debug, Clone, Copy)]
struct Ipv4UdpPacket {
    ip_start: usize,
    udp_start: usize,
}

impl Ipv4UdpPacket {
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
        if frame[ip_start + 9] != 17 {
            return None;
        }
        let fragment = u16::from_be_bytes([frame[ip_start + 6], frame[ip_start + 7]]);
        if fragment & 0x3fff != 0 {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([
            frame[ip_start + 2],
            frame[ip_start + 3],
        ]));
        if total_len < ihl + 8 || frame.len() < ip_start + total_len {
            return None;
        }
        let udp_start = ip_start + ihl;
        Some(Self {
            ip_start,
            udp_start,
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
        u16::from_be_bytes([frame[self.udp_start], frame[self.udp_start + 1]])
    }

    fn set_source_port(self, frame: &mut [u8], port: u16) {
        frame[self.udp_start..self.udp_start + 2].copy_from_slice(&port.to_be_bytes());
    }

    fn destination_port(self, frame: &[u8]) -> u16 {
        u16::from_be_bytes([frame[self.udp_start + 2], frame[self.udp_start + 3]])
    }

    fn set_destination_port(self, frame: &mut [u8], port: u16) {
        frame[self.udp_start + 2..self.udp_start + 4].copy_from_slice(&port.to_be_bytes());
    }

    fn recompute_checksums(self, frame: &mut [u8]) {
        let total_len = usize::from(u16::from_be_bytes([
            frame[self.ip_start + 2],
            frame[self.ip_start + 3],
        ]));
        frame[self.ip_start + 10] = 0;
        frame[self.ip_start + 11] = 0;
        let ip_header_len = self.udp_start - self.ip_start;
        let ip_checksum = internet_checksum(&frame[self.ip_start..self.udp_start]);
        frame[self.ip_start + 10..self.ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

        let udp_len = total_len - ip_header_len;
        frame[self.udp_start + 6] = 0;
        frame[self.udp_start + 7] = 0;
        let checksum = udp_ipv4_checksum(
            self.source_ip(frame),
            self.destination_ip(frame),
            &frame[self.udp_start..self.udp_start + udp_len],
        );
        frame[self.udp_start + 6..self.udp_start + 8].copy_from_slice(&checksum.to_be_bytes());
    }
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

fn udp_ipv4_checksum(source: [u8; 4], destination: [u8; 4], udp: &[u8]) -> u16 {
    let mut pseudo_header = Vec::with_capacity(12 + udp.len());
    pseudo_header.extend_from_slice(&source);
    pseudo_header.extend_from_slice(&destination);
    pseudo_header.push(0);
    pseudo_header.push(17);
    pseudo_header.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo_header.extend_from_slice(udp);
    let checksum = internet_checksum(&pseudo_header);
    if checksum == 0 { 0xffff } else { checksum }
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

    #[derive(Debug)]
    struct ErrorPolicyRuntime;

    impl NetworkPolicyRuntime for ErrorPolicyRuntime {
        fn decide_connection(
            &self,
            _connection: NetworkConnectionAttempt,
        ) -> io::Result<NetworkPolicyDecision> {
            Err(io::Error::other("policy callback failed"))
        }
    }

    #[derive(Debug, Default)]
    struct CapturePolicyRuntime {
        attempts: std::sync::Mutex<Vec<NetworkConnectionAttempt>>,
    }

    impl NetworkPolicyRuntime for CapturePolicyRuntime {
        fn decide_connection(
            &self,
            connection: NetworkConnectionAttempt,
        ) -> io::Result<NetworkPolicyDecision> {
            self.attempts.lock().unwrap().push(connection);
            Ok(NetworkPolicyDecision {
                action: NetworkPolicyAction::Deny,
                dns_resolvers: Vec::new(),
            })
        }
    }

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
        let mut device = LibkrunNetDevice::new(rx, tx, Ipv4Address::new(10, 0, 2, 1), None, None);
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
    fn transport_policy_errors_fail_closed_before_native_defaults() {
        let decision = decide_transport(
            Some(&ErrorPolicyRuntime),
            Some(&[OutboundRulePlan::AcceptPublicInternet { ports: Vec::new() }]),
            NetworkProtocol::Tcp,
            NetworkEndpoint {
                ip: "10.0.2.15".to_string(),
                port: 50_000,
            },
            NetworkEndpoint {
                ip: "93.184.216.34".to_string(),
                port: 443,
            },
            None,
        );

        assert_eq!(decision.action, NetworkPolicyAction::Deny);
    }

    #[test]
    fn dns_policy_errors_fail_closed_before_default_resolver() {
        let decision = decide_dns(
            Some(&ErrorPolicyRuntime),
            NetworkProtocol::Udp,
            NetworkEndpoint {
                ip: "10.0.2.15".to_string(),
                port: 50_000,
            },
            NetworkEndpoint {
                ip: "10.0.2.1".to_string(),
                port: 53,
            },
        )
        .unwrap();

        assert_eq!(decision.action, NetworkPolicyAction::Deny);
    }

    #[test]
    fn tls_intercept_server_name_falls_back_to_destination_ip_without_sni() {
        let destination = HttpDestination {
            source_ip: "10.0.2.15".to_string(),
            source_port: 50_000,
            ip: "93.184.216.34".to_string(),
            port: 443,
            hostname: None,
        };

        assert_eq!(
            tls_intercept_server_name(&destination, Some("api.github.test")),
            "api.github.test",
        );
        assert_eq!(
            tls_intercept_server_name(&destination, None),
            "93.184.216.34",
        );
    }

    #[test]
    fn transparent_interception_prunes_flow_after_host_fin() {
        let mut interception = TransparentInterception::new(Ipv4Address::new(10, 0, 2, 1));
        let mut guest_frame = tcp_frame([10, 0, 2, 15], [93, 184, 216, 34], 50_000, 443, 0x02);

        interception.rewrite_guest_frame(&mut guest_frame);
        assert_eq!(
            interception.original_destination(IpAddress::v4(10, 0, 2, 15), 50_000, 443),
            Some("93.184.216.34".to_string()),
        );

        let mut host_frame = tcp_frame([10, 0, 2, 1], [10, 0, 2, 15], 443, 50_000, 0x01);
        interception.rewrite_host_frame(&mut host_frame);

        assert_eq!(
            interception.original_destination(IpAddress::v4(10, 0, 2, 15), 50_000, 443),
            None
        );
        assert_eq!(interception.tcp_host_ports().count(), 0);
    }

    #[test]
    fn http_listener_pool_replenishes_idle_accept_capacity() {
        let mut sockets = SocketSet::new(Vec::new());
        let mut http_sockets = HashMap::new();

        add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);
        let handles = http_sockets.get(&HOST_HTTPS_PORT).unwrap().clone();
        assert_eq!(handles.len(), HTTP_LISTENERS_PER_PORT);
        for handle in &handles {
            assert!(sockets.get::<tcp::Socket>(*handle).is_listening());
        }

        for handle in handles {
            sockets.get_mut::<tcp::Socket>(handle).close();
        }
        add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);

        let handles = http_sockets.get(&HOST_HTTPS_PORT).unwrap();
        assert_eq!(handles.len(), HTTP_LISTENERS_PER_PORT * 2);
        assert_eq!(
            handles
                .iter()
                .filter(|handle| sockets.get::<tcp::Socket>(**handle).is_listening())
                .count(),
            HTTP_LISTENERS_PER_PORT,
        );
    }

    #[test]
    fn http_listener_pool_stops_at_total_socket_cap() {
        let mut sockets = SocketSet::new(Vec::new());
        let mut http_sockets = HashMap::new();

        for _ in 0..(HTTP_MAX_SOCKETS_PER_PORT / HTTP_LISTENERS_PER_PORT + 2) {
            add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);
            let handles = http_sockets.get(&HOST_HTTPS_PORT).unwrap().clone();
            for handle in handles {
                sockets.get_mut::<tcp::Socket>(handle).close();
            }
        }

        assert_eq!(
            http_sockets.get(&HOST_HTTPS_PORT).unwrap().len(),
            HTTP_MAX_SOCKETS_PER_PORT,
        );
    }

    #[test]
    fn transparent_interception_assigns_distinct_udp_ports_for_distinct_destinations() {
        let mut interception = TransparentInterception::new(Ipv4Address::new(10, 0, 2, 1));
        let mut first = udp_frame([10, 0, 2, 15], [1, 1, 1, 1], 50_000, 53);
        let mut second = udp_frame([10, 0, 2, 15], [8, 8, 8, 8], 50_000, 53);

        interception.rewrite_guest_frame(&mut first);
        interception.rewrite_guest_frame(&mut second);

        let first_packet = Ipv4UdpPacket::parse(&first).unwrap();
        let second_packet = Ipv4UdpPacket::parse(&second).unwrap();
        let first_host_port = first_packet.destination_port(&first);
        let second_host_port = second_packet.destination_port(&second);
        assert_ne!(first_host_port, second_host_port);
        assert_eq!(
            interception.udp_original_destination(
                IpAddress::v4(10, 0, 2, 15),
                50_000,
                first_host_port
            ),
            Some(UdpDestination {
                ip: "1.1.1.1".to_string(),
                port: 53,
            }),
        );
        assert_eq!(
            interception.udp_original_destination(
                IpAddress::v4(10, 0, 2, 15),
                50_000,
                second_host_port
            ),
            Some(UdpDestination {
                ip: "8.8.8.8".to_string(),
                port: 53,
            }),
        );

        let mut response = udp_frame([10, 0, 2, 1], [10, 0, 2, 15], first_host_port, 50_000);
        interception.rewrite_host_frame(&mut response);
        let response_packet = Ipv4UdpPacket::parse(&response).unwrap();
        assert_eq!(response_packet.source_ip(&response), [1, 1, 1, 1]);
        assert_eq!(response_packet.source_port(&response), 53);
    }

    #[test]
    fn ipv4_udp_parser_rejects_fragments() {
        let mut first_fragment = udp_frame([10, 0, 2, 15], [8, 8, 8, 8], 50_000, 53);
        first_fragment[14 + 6..14 + 8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(Ipv4UdpPacket::parse(&first_fragment).is_none());

        let mut later_fragment = udp_frame([10, 0, 2, 15], [8, 8, 8, 8], 50_000, 53);
        later_fragment[14 + 6..14 + 8].copy_from_slice(&0x0001u16.to_be_bytes());
        assert!(Ipv4UdpPacket::parse(&later_fragment).is_none());
    }

    #[test]
    fn transparent_interception_reports_udp_port_exhaustion() {
        let mut interception = TransparentInterception::new(Ipv4Address::new(10, 0, 2, 1));
        for host_port in UDP_INTERCEPT_PORT_START..=UDP_INTERCEPT_PORT_END {
            interception.udp_flows.insert(
                UdpInterceptedFlow {
                    guest_ip: [10, 0, 2, 15],
                    guest_port: host_port,
                    host_port,
                },
                InterceptedFlow {
                    destination_ip: [192, 0, 2, 1],
                    destination_port: 53,
                    last_seen: StdInstant::now(),
                    closing: false,
                },
            );
        }

        assert_eq!(
            interception.udp_host_port_for_destination([10, 0, 2, 16], 50_000, [192, 0, 2, 2], 53),
            None,
        );
    }

    #[test]
    fn dns_unsupported_query_type_returns_nodata_for_known_name() {
        let response =
            dns_response(&dns_query("localhost", 28), NetworkProtocol::Udp, &[]).unwrap();

        assert_eq!(&response.packet[2..4], &[0x81, 0x80]);
        assert_eq!(&response.packet[6..8], &[0, 0]);
    }

    #[test]
    fn custom_dns_response_records_all_a_answers() {
        let request = DnsMessage::from_vec(&dns_query("multi.example", 1)).unwrap();
        let response = DnsMessage::from_vec(&dns_answer(
            &request,
            &[[203, 0, 113, 44], [203, 0, 113, 45]],
        ))
        .unwrap();

        assert_eq!(
            dns_answer_pins(&request, &response)
                .into_iter()
                .map(|pin| pin.address)
                .collect::<Vec<_>>(),
            vec![[203, 0, 113, 44], [203, 0, 113, 45]],
        );
    }

    #[test]
    fn custom_dns_response_records_cname_backed_a_answers_for_query_name() {
        let request = DnsMessage::from_vec(&dns_query("alias.example", 1)).unwrap();
        let query = single_dns_query(&request).unwrap();
        let canonical_name = Name::from_ascii("target.example").unwrap();
        let mut response = dns_response_message(&request);
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            DNS_DEFAULT_TTL_SECS,
            RData::CNAME(hickory_proto::rr::rdata::CNAME(canonical_name.clone())),
        ));
        response.add_answer(Record::from_rdata(
            canonical_name,
            DNS_DEFAULT_TTL_SECS,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 46))),
        ));

        assert_eq!(
            dns_answer_pins(&request, &response),
            vec![DnsAnswerPin {
                hostname: "alias.example".to_string(),
                address: [203, 0, 113, 46],
                ttl: Duration::from_secs(DNS_DEFAULT_TTL_SECS.into()),
            }],
        );
    }

    #[test]
    fn custom_dns_response_ignores_non_in_a_answers() {
        let request = DnsMessage::from_vec(&dns_query("class.example", 1)).unwrap();
        let query = single_dns_query(&request).unwrap();
        let mut response = dns_response_message(&request);
        let mut record = Record::from_rdata(
            query.name().clone(),
            DNS_DEFAULT_TTL_SECS,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 47))),
        );
        record.dns_class = DNSClass::CH;
        response.add_answer(record);

        assert_eq!(dns_answer_pins(&request, &response), Vec::new());
    }

    #[test]
    fn dns_pins_keep_latest_guest_scoped_hostname_mapping_for_address() {
        let mut interception = TransparentInterception::new(Ipv4Address::new(10, 0, 2, 1));
        let guest = IpAddress::v4(10, 0, 2, 15);
        let other_guest = IpAddress::v4(10, 0, 2, 16);

        interception.record_dns_answer(guest, &dns_pin("first.example", [192, 0, 2, 10]));
        interception.record_dns_answer(other_guest, &dns_pin("other.example", [192, 0, 2, 10]));
        interception.record_dns_answer(guest, &dns_pin("second.example", [192, 0, 2, 10]));

        assert_eq!(
            interception.resolved_hostname(guest, "192.0.2.10"),
            Some("second.example".to_string()),
        );
        assert_eq!(
            interception.resolved_hostname(other_guest, "192.0.2.10"),
            Some("other.example".to_string()),
        );
        assert_eq!(interception.resolved_hostname(guest, "192.0.2.11"), None);
    }

    #[test]
    fn transport_policy_receives_dns_pinned_hostname() {
        let policy = CapturePolicyRuntime::default();

        let decision = decide_transport(
            Some(&policy),
            None,
            NetworkProtocol::Tcp,
            NetworkEndpoint {
                ip: "10.0.2.15".to_string(),
                port: 50_000,
            },
            NetworkEndpoint {
                ip: "192.0.2.10".to_string(),
                port: 443,
            },
            Some("api.example.com".to_string()),
        );

        assert_eq!(decision.action, NetworkPolicyAction::Deny);
        let attempts = policy.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].hostname.as_deref(), Some("api.example.com"));
    }

    #[test]
    fn https_upstream_adapter_uses_negotiated_http_version() {
        let connector = rama_core::service::service_fn(|request: RamaRequest<Body>| async move {
            let connection = Extensions::new();
            connection.insert(rama_http::conn::TargetHttpVersion(RamaVersion::HTTP_2));
            Ok::<_, std::convert::Infallible>(EstablishedClientConnection {
                input: request,
                conn: connection,
            })
        });
        let adapter = RequestVersionAdapter::new(connector);
        let request = RamaRequest::builder()
            .version(RamaVersion::HTTP_11)
            .uri("https://example.test/")
            .body(Body::empty())
            .unwrap();

        let established = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(adapter.serve(request))
            .unwrap();

        assert_eq!(established.input.version(), RamaVersion::HTTP_2);
    }

    #[test]
    fn upstream_response_is_adapted_back_to_guest_http_version() {
        let mut response = RamaResponse::builder()
            .version(RamaVersion::HTTP_2)
            .body(Body::empty())
            .unwrap();

        *response.version_mut() = RamaVersion::HTTP_11;

        assert_eq!(response.version(), RamaVersion::HTTP_11);
    }

    #[test]
    fn tls_intercept_shutdown_sends_close_notify_before_finishing() {
        let authority = test_mitm_tls_authority();
        let (bridge, _async_io) = SyncAsyncBridge::new(HTTP_BRIDGE_BUFFER_BYTES);
        let mut connection = TlsInterceptConnection {
            server: authority.server_connection("example.test").unwrap(),
            bridge,
            to_guest: Vec::new(),
            close_after_flush: false,
            sent_close_notify: false,
        };

        connection.close_after_clean_tls_shutdown();

        assert!(connection.close_after_flush);
        assert!(connection.sent_close_notify);
        assert!(!connection.to_guest.is_empty());
        assert_eq!(connection.to_guest[0], 0x15);
    }

    #[test]
    fn tls_intercept_waits_for_pending_plaintext_before_close_notify() {
        let authority = test_mitm_tls_authority();
        let (bridge, mut async_io) = SyncAsyncBridge::new(HTTP_BRIDGE_BUFFER_BYTES);
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            tokio::io::AsyncWriteExt::write_all(&mut async_io, b"pending response")
                .await
                .unwrap();
            tokio::io::AsyncWriteExt::shutdown(&mut async_io)
                .await
                .unwrap();
        });
        let mut connection = TlsInterceptConnection {
            server: authority.server_connection("example.test").unwrap(),
            bridge,
            to_guest: vec![0; TLS_READ_BUFFER_BYTES],
            close_after_flush: false,
            sent_close_notify: false,
        };

        connection.flush_rama_plaintext();

        assert!(!connection.close_after_flush);
        assert!(!connection.sent_close_notify);
    }

    fn dns_pin(hostname: &str, address: [u8; 4]) -> DnsAnswerPin {
        DnsAnswerPin {
            hostname: hostname.to_string(),
            address,
            ttl: Duration::from_secs(DNS_DEFAULT_TTL_SECS.into()),
        }
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let query_type = match qtype {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            _ => panic!("unsupported test query type: {qtype}"),
        };
        let mut message = DnsMessage::new(
            0x1234,
            DnsMessageType::Query,
            hickory_proto::op::OpCode::Query,
        );
        message.metadata.recursion_desired = true;
        message.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii(name).unwrap(),
            query_type,
        ));
        message.to_vec().unwrap()
    }

    fn test_mitm_tls_authority() -> MitmTlsAuthority {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["Sandbox HTTP Interception CA".to_string()])
                .unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Sandbox HTTP Interception CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let certificate = params.self_signed(&key).unwrap();
        MitmTlsAuthority::new(MitmTlsConfig {
            ca_certificate_pem: certificate.pem(),
            ca_private_key_pem: key.serialize_pem(),
        })
        .unwrap()
    }

    fn dns_answer(request: &DnsMessage, addresses: &[[u8; 4]]) -> Vec<u8> {
        let mut response = dns_response_message(request);
        let query = single_dns_query(request).unwrap();
        for address in addresses {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                DNS_DEFAULT_TTL_SECS,
                RData::A(A(Ipv4Addr::from(*address))),
            ));
        }
        response.to_vec().unwrap()
    }

    fn dns_response_message(request: &DnsMessage) -> DnsMessage {
        let query = single_dns_query(request).unwrap();
        let mut response = DnsMessage::new(
            request.metadata.id,
            DnsMessageType::Response,
            request.metadata.op_code,
        );
        response.metadata = hickory_proto::op::Metadata::response_from_request(&request.metadata);
        response.metadata.recursion_available = true;
        response.add_query(query.clone());
        response
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

    fn udp_frame(
        source_ip: [u8; 4],
        destination_ip: [u8; 4],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0; 14 + 20 + 8];
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        let ip_start = 14;
        frame[ip_start] = 0x45;
        frame[ip_start + 2..ip_start + 4].copy_from_slice(&28u16.to_be_bytes());
        frame[ip_start + 9] = 17;
        frame[ip_start + 12..ip_start + 16].copy_from_slice(&source_ip);
        frame[ip_start + 16..ip_start + 20].copy_from_slice(&destination_ip);
        let udp_start = ip_start + 20;
        frame[udp_start..udp_start + 2].copy_from_slice(&source_port.to_be_bytes());
        frame[udp_start + 2..udp_start + 4].copy_from_slice(&destination_port.to_be_bytes());
        frame[udp_start + 4..udp_start + 6].copy_from_slice(&8u16.to_be_bytes());
        frame
    }
}
