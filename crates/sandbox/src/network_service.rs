use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant as StdInstant};

use rama_core::extensions::Extensions;
use rama_core::rt::Executor;
use rama_core::service::Service;
use rama_http::header::HOST;
use rama_http::{Body, Request as RamaRequest, Response as RamaResponse, Version as RamaVersion};
use rama_http_backend::client::http_connect;
use rama_http_backend::server::HttpServer;
use rama_tcp::stream::TcpStream as RamaTcpStream;
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::UnixTime;
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

const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HOST_HTTP_PROBE_PORT: u16 = 8080;
const HOST_HTTP_PORT: u16 = 80;
const HOST_HTTPS_PORT: u16 = 443;
const HOST_ALT_HTTPS_PORT: u16 = 8443;
const HOST_DNS_PORT: u16 = 53;
const HTTP_LISTENERS_PER_PORT: usize = 16;
const HTTP_SOCKET_BUFFER_BYTES: usize = 256 * 1024;
const HTTP_BRIDGE_BUFFER_BYTES: usize = 256 * 1024;
const TLS_READ_BUFFER_BYTES: usize = 16 * 1024;
const MAX_INTERCEPT_HEAD_BYTES: usize = 64 * 1024;
const DNS_PACKET_BUFFER_BYTES: usize = 4096;
const UDP_RELAY_BUFFER_BYTES: usize = 64 * 1024;
const UDP_NAT_PORT_START: u16 = 40_000;
const UDP_NAT_PORT_END: u16 = 60_999;
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
    pub questions: Vec<DnsQuestion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub type_name: String,
    pub class_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPolicyAnswer {
    pub answer_type: String,
    pub name: Option<String>,
    pub address: Option<String>,
    pub target: Option<String>,
    pub values: Vec<String>,
    pub ttl: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPolicyResponse {
    pub code: String,
    pub answers: Vec<DnsPolicyAnswer>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicyDecision {
    pub allowed: bool,
    pub dns_response: Option<DnsPolicyResponse>,
}

pub trait NetworkPolicyRuntime: Send + Sync + std::fmt::Debug {
    fn decide_connection(
        &self,
        connection: NetworkConnectionAttempt,
    ) -> io::Result<NetworkPolicyDecision>;
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
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        rustls::ServerConnection::new(Arc::new(config))
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))
    }

    fn client_connection(
        &self,
        server_name: &str,
        alpn_protocol: Option<&str>,
    ) -> io::Result<rustls::ClientConnection> {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TransparentUpstreamVerifier))
            .with_no_client_auth();
        if let Some(alpn_protocol) = alpn_protocol {
            config.alpn_protocols = vec![alpn_protocol.as_bytes().to_vec()];
        }
        let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))
    }
}

#[derive(Debug)]
struct TransparentUpstreamVerifier;

impl ServerCertVerifier for TransparentUpstreamVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
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
    let tcp_dns_handles = add_tcp_dns_listeners(&mut sockets);
    let mut tcp_dns_connections = HashMap::new();
    let mut http_sockets = HashMap::new();
    let mut http_connections = HashMap::new();
    let mut udp_sockets = HashMap::new();
    let mut udp_relays = HashMap::new();
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PORT);
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PROBE_PORT);
    if tls_authority.is_some() {
        add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);
        add_http_listener(&mut sockets, &mut http_sockets, HOST_ALT_HTTPS_PORT);
    }

    while !shutdown.load(Ordering::Acquire) {
        let timestamp = Instant::now();
        let _ = iface.poll(timestamp, &mut device, &mut sockets);
        poll_dns_socket(
            &mut sockets,
            dns_handle,
            outbound_rules.as_deref(),
            policy.as_deref(),
        );
        for handle in &tcp_dns_handles {
            poll_tcp_dns_socket(
                &mut sockets,
                *handle,
                outbound_rules.as_deref(),
                policy.as_deref(),
                &mut tcp_dns_connections,
            );
        }
        device.nat.prune_expired_flows();
        let active_tcp_nat_ports = device.nat.tcp_host_ports().collect::<HashSet<_>>();
        for port in &active_tcp_nat_ports {
            add_http_listener(&mut sockets, &mut http_sockets, *port);
        }
        prune_dynamic_http_listeners(
            &mut sockets,
            &mut http_sockets,
            &active_tcp_nat_ports,
            &http_connections,
        );
        let active_udp_nat_ports = device.nat.udp_host_ports().collect::<HashSet<_>>();
        for port in &active_udp_nat_ports {
            add_udp_relay_socket(&mut sockets, &mut udp_sockets, *port);
        }
        prune_dynamic_udp_relays(&mut sockets, &mut udp_sockets, &active_udp_nat_ports);
        for (port, handle) in udp_sockets
            .iter()
            .map(|(port, handle)| (*port, *handle))
            .collect::<Vec<_>>()
        {
            poll_udp_relay_socket(
                &mut sockets,
                handle,
                port,
                &device.nat,
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
                &device.nat,
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
        let decision = match decide_dns(policy, NetworkProtocol::Udp, src, dst, request) {
            Ok(decision) if decision.allowed => decision,
            _ => continue,
        };
        let Some(response) = dns_response_with_decision(request, decision.dns_response.as_ref())
        else {
            continue;
        };
        let _ = socket.send_slice(
            &response,
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
    active_nat_ports: &HashSet<u16>,
) {
    let stale_ports = udp_sockets
        .keys()
        .copied()
        .filter(|port| !active_nat_ports.contains(port))
        .collect::<Vec<_>>();
    for port in stale_ports {
        if let Some(handle) = udp_sockets.remove(&port) {
            sockets.remove(handle);
        }
    }
}

fn poll_udp_relay_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    host_port: u16,
    nat: &TransparentNat,
    outbound_rules: Option<&[OutboundRulePlan]>,
    policy: Option<&dyn NetworkPolicyRuntime>,
    relays: &mut HashMap<UdpFlow, UdpRelay>,
) {
    let socket = sockets.get_mut::<udp::Socket>(handle);
    while socket.can_recv() {
        let Ok((payload, remote)) = socket.recv() else {
            break;
        };
        let Some(destination) =
            nat.udp_original_destination(remote.endpoint.addr, remote.endpoint.port, host_port)
        else {
            continue;
        };
        if outbound_rules
            .is_some_and(|rules| !is_allowed_outbound_udp(&destination.ip, destination.port, rules))
        {
            continue;
        }
        if policy.is_some_and(|policy| {
            !policy_allows_connection(
                policy,
                NetworkProtocol::Udp,
                NetworkEndpoint {
                    ip: remote.endpoint.addr.to_string(),
                    port: remote.endpoint.port,
                },
                NetworkEndpoint {
                    ip: destination.ip.clone(),
                    port: destination.port,
                },
            )
        }) {
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
        StdInstant::now().duration_since(self.last_seen) > NAT_FLOW_IDLE_TTL
    }
}

fn poll_tcp_dns_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    outbound_rules: Option<&[OutboundRulePlan]>,
    policy: Option<&dyn NetworkPolicyRuntime>,
    connections: &mut HashMap<SocketHandle, TcpDnsConnection>,
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
        let response = handle_tcp_dns_request(socket, outbound_rules, policy, &request);
        if let Some(response) = response {
            connection
                .to_guest
                .extend_from_slice(&(response.len() as u16).to_be_bytes());
            connection.to_guest.extend_from_slice(&response);
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
    request: &[u8],
) -> Option<Vec<u8>> {
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
    let decision = match decide_dns(policy, NetworkProtocol::Tcp, src, dst, request) {
        Ok(decision) if decision.allowed => decision,
        _ => return None,
    };
    dns_response_with_decision(request, decision.dns_response.as_ref())
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
) {
    let stale_ports = http_sockets
        .iter()
        .filter_map(|(port, handles)| {
            (!is_static_listener_port(*port)
                && !active_nat_ports.contains(port)
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
        HOST_HTTP_PORT | HOST_HTTP_PROBE_PORT | HOST_HTTPS_PORT | HOST_ALT_HTTPS_PORT
    )
}

fn poll_http_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    port: u16,
    nat: &TransparentNat,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    tls_authority: Option<Arc<MitmTlsAuthority>>,
    http_connections: &mut HashMap<SocketHandle, HttpConnection>,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        http_connections.remove(&handle);
        let _ = socket.listen(port);
        return;
    }

    if let Some(connection) = http_connections.get_mut(&handle) {
        poll_http_connection(socket, connection);
        if connection.is_finished() {
            let _ = http_connections.remove(&handle);
            socket.close();
        }
        return;
    }

    poll_plain_http_socket(
        socket,
        handle,
        nat,
        outbound_rules,
        http,
        policy,
        tls_authority,
        http_connections,
    );
}

fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x16))
}

fn should_use_raw_tcp_relay(bytes: &[u8]) -> bool {
    !bytes_could_be_http_request(bytes)
}

fn bytes_could_be_http_request(bytes: &[u8]) -> bool {
    if bytes.starts_with(H2_PREFACE) {
        return false;
    }
    if H2_PREFACE.starts_with(bytes) {
        return true;
    }
    if bytes.is_empty() {
        return true;
    }
    let mut saw_method_byte = false;
    for byte in bytes {
        if is_http_method_token_byte(*byte) {
            saw_method_byte = true;
            continue;
        }
        return saw_method_byte && *byte == b' ';
    }
    saw_method_byte
}

fn is_http_method_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
    )
}

#[derive(Clone)]
struct HttpDestination {
    source_ip: String,
    source_port: u16,
    ip: String,
    port: u16,
}

fn original_http_destination(
    socket: &tcp::Socket<'_>,
    nat: &TransparentNat,
) -> Option<HttpDestination> {
    let remote = socket.remote_endpoint()?;
    let local = socket.local_endpoint()?;
    let ip = nat.original_destination(remote.addr, remote.port, local.port)?;
    Some(HttpDestination {
        source_ip: remote.addr.to_string(),
        source_port: remote.port,
        ip,
        port: local.port,
    })
}

fn poll_plain_http_socket(
    socket: &mut tcp::Socket<'_>,
    handle: SocketHandle,
    nat: &TransparentNat,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
    policy: Option<Arc<dyn NetworkPolicyRuntime>>,
    tls_authority: Option<Arc<MitmTlsAuthority>>,
    http_connections: &mut HashMap<SocketHandle, HttpConnection>,
) {
    let Some(destination) = original_http_destination(socket, nat) else {
        socket.close();
        return;
    };
    if outbound_rules
        .is_some_and(|rules| !is_allowed_outbound_tcp(&destination.ip, destination.port, rules))
    {
        let connection = http_connections
            .entry(handle)
            .or_insert_with(|| HttpConnection::response(OUTBOUND_DENIED_RESPONSE));
        poll_http_connection(socket, connection);
        return;
    }
    let Some(remote) = socket.remote_endpoint() else {
        socket.close();
        return;
    };
    if policy.as_deref().is_some_and(|policy| {
        !policy_allows_connection(
            policy,
            NetworkProtocol::Tcp,
            NetworkEndpoint {
                ip: remote.addr.to_string(),
                port: remote.port,
            },
            NetworkEndpoint {
                ip: destination.ip.clone(),
                port: destination.port,
            },
        )
    }) {
        let connection = http_connections
            .entry(handle)
            .or_insert_with(|| HttpConnection::response(OUTBOUND_DENIED_RESPONSE));
        poll_http_connection(socket, connection);
        return;
    }

    let connection = if port_is_probe(destination.port) {
        HttpConnection::response(HOST_HTTP_PROBE_RESPONSE)
    } else {
        HttpConnection::intercept(
            destination,
            http,
            tls_authority,
            outbound_rules.map(<[OutboundRulePlan]>::to_vec),
        )
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

struct RewrittenHead {
    bytes: Vec<u8>,
    upstream_ip: String,
    upstream_port: u16,
    upstream_server_name: String,
}

struct UpstreamEndpoint {
    ip: String,
    port: u16,
}

fn rewrite_intercepted_head(
    guest_head: &[u8],
    destination: &HttpDestination,
    scheme: &str,
    tls: Option<HostTlsMetadata>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    runtime: Option<&dyn HttpInterceptRuntime>,
) -> io::Result<Option<RewrittenHead>> {
    if guest_head.starts_with(H2_PREFACE) {
        return Err(io::Error::new(
            ErrorKind::Unsupported,
            "HTTP/2 interception requires the Rama HTTP proxy pipeline",
        ));
    }
    rewrite_h1_head(
        guest_head,
        destination,
        scheme,
        tls,
        outbound_rules,
        runtime,
    )
}

fn rewrite_h1_head(
    guest_head: &[u8],
    destination: &HttpDestination,
    scheme: &str,
    tls: Option<HostTlsMetadata>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    runtime: Option<&dyn HttpInterceptRuntime>,
) -> io::Result<Option<RewrittenHead>> {
    let Some(head_end) = find_header_end(guest_head) else {
        return Ok(None);
    };
    let mut headers = [httparse::EMPTY_HEADER; 128];
    let mut request = httparse::Request::new(&mut headers);
    let status = request
        .parse(&guest_head[..head_end])
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?;
    if !status.is_complete() {
        return Ok(None);
    }
    let method = request.method.unwrap_or("GET").to_string();
    let path = request.path.unwrap_or("/").to_string();
    let host_headers = request
        .headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"))
        .collect::<Vec<_>>();
    if host_headers.len() != 1 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP/1.1 request must contain exactly one host header",
        ));
    }
    let authority = std::str::from_utf8(host_headers[0].value)
        .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?
        .to_string();
    let (upstream_server_name, _) = split_authority(&authority, default_port_for_scheme(scheme))?;
    let upstream = UpstreamEndpoint {
        ip: destination.ip.clone(),
        port: destination.port,
    };
    validate_upstream_allowed(&upstream, outbound_rules)?;
    let mut pairs = request
        .headers
        .iter()
        .filter(|header| !header.name.eq_ignore_ascii_case("connection"))
        .map(|header| {
            Ok((
                header.name.to_ascii_lowercase(),
                std::str::from_utf8(header.value)
                    .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?
                    .to_string(),
            ))
        })
        .collect::<io::Result<Vec<_>>>()?;
    pairs.push(("connection".to_string(), "close".to_string()));
    let request = InterceptedHttpRequest {
        protocol: HttpRequestProtocol::Http1,
        method,
        url: format!("{scheme}://{authority}{path}"),
        original_destination: InterceptedDestination {
            ip: destination.ip.clone(),
            port: destination.port,
        },
        source: InterceptedDestination {
            ip: destination.source_ip.clone(),
            port: destination.source_port,
        },
        upstream_dial: InterceptedDestination {
            ip: upstream.ip.clone(),
            port: upstream.port,
        },
        headers: std::mem::take(&mut pairs),
        tls,
    };
    let request = match runtime {
        Some(runtime) => {
            if runtime.rejects_rebound_authority(
                scheme,
                &authority,
                &request.original_destination,
                &request.upstream_dial,
            ) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "request authority resolved to a rebound destination",
                ));
            }
            runtime.handle_request_head(request)?
        }
        None => request,
    };
    let mut rewritten = Vec::new();
    rewritten.extend_from_slice(&guest_head[..request_line_end(guest_head).unwrap_or(0)]);
    for (name, value) in request.headers {
        rewritten.extend_from_slice(name.as_bytes());
        rewritten.extend_from_slice(b": ");
        rewritten.extend_from_slice(value.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"\r\n");
    rewritten.extend_from_slice(&guest_head[head_end..]);
    Ok(Some(RewrittenHead {
        bytes: rewritten,
        upstream_ip: upstream.ip,
        upstream_port: upstream.port,
        upstream_server_name,
    }))
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn request_line_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|position| position + 2)
}

fn split_authority(authority: &str, default_port: u16) -> io::Result<(String, u16)> {
    if let Some((host, port)) = authority.rsplit_once(':') {
        if let Ok(port) = port.parse() {
            return Ok((host.to_string(), port));
        }
    }
    Ok((authority.to_string(), default_port))
}

fn validate_upstream_allowed(
    upstream: &UpstreamEndpoint,
    outbound_rules: Option<&[OutboundRulePlan]>,
) -> io::Result<()> {
    if outbound_rules
        .is_some_and(|rules| is_allowed_outbound_tcp(&upstream.ip, upstream.port, rules))
    {
        return Ok(());
    }
    Err(io::Error::new(
        ErrorKind::PermissionDenied,
        "rewritten upstream destination is not allowed by outbound policy",
    ))
}

fn default_port_for_scheme(scheme: &str) -> u16 {
    if scheme == "https" { 443 } else { 80 }
}

fn tls_client_hello_sni(bytes: &[u8]) -> Option<String> {
    tls_client_hello_extension(bytes, 0).and_then(tls_sni_from_extension)
}

fn tls_client_hello_offers_http(bytes: &[u8]) -> bool {
    tls_client_hello_extension(bytes, 16).is_some_and(|extension| {
        tls_alpn_protocols(extension)
            .iter()
            .any(|protocol| protocol == "http/1.1")
    })
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

fn tls_alpn_protocols(extension: &[u8]) -> Vec<String> {
    if extension.len() < 2 {
        return Vec::new();
    }
    let list_len = u16::from_be_bytes([extension[0], extension[1]]) as usize;
    let mut offset = 2;
    let end = offset + list_len;
    if extension.len() < end {
        return Vec::new();
    }
    let mut protocols = Vec::new();
    while offset < end {
        let Some(len) = extension.get(offset).copied().map(usize::from) else {
            return Vec::new();
        };
        offset += 1;
        if offset + len > end {
            return Vec::new();
        }
        if let Ok(protocol) = std::str::from_utf8(&extension[offset..offset + len]) {
            protocols.push(protocol.to_string());
        }
        offset += len;
    }
    protocols
}

fn tls_record_complete(bytes: &[u8]) -> bool {
    bytes.len() >= 5 && bytes.len() >= 5 + u16::from_be_bytes([bytes[3], bytes[4]]) as usize
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

fn policy_allows_connection(
    policy: &dyn NetworkPolicyRuntime,
    protocol: NetworkProtocol,
    src: NetworkEndpoint,
    dst: NetworkEndpoint,
) -> bool {
    policy
        .decide_connection(NetworkConnectionAttempt {
            protocol,
            transport: protocol,
            src,
            dst,
            questions: Vec::new(),
        })
        .map(|decision| decision.allowed)
        .unwrap_or(false)
}

fn decide_dns(
    policy: Option<&dyn NetworkPolicyRuntime>,
    transport: NetworkProtocol,
    src: NetworkEndpoint,
    dst: NetworkEndpoint,
    request: &[u8],
) -> io::Result<NetworkPolicyDecision> {
    let Some(policy) = policy else {
        return Ok(NetworkPolicyDecision {
            allowed: true,
            dns_response: None,
        });
    };
    policy.decide_connection(NetworkConnectionAttempt {
        protocol: NetworkProtocol::Dns,
        transport,
        src,
        dst,
        questions: dns_questions(request).unwrap_or_default(),
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

fn upstream_socket_addr(destination_ip: &str, destination_port: u16) -> (String, u16) {
    let public_test_ip = Ipv4Address::new(
        DNS_PUBLIC_TEST_IP[0],
        DNS_PUBLIC_TEST_IP[1],
        DNS_PUBLIC_TEST_IP[2],
        DNS_PUBLIC_TEST_IP[3],
    )
    .to_string();
    let upstream_ip = if destination_ip == public_test_ip {
        "127.0.0.1".to_string()
    } else {
        destination_ip.to_string()
    };
    (upstream_ip, destination_port)
}

#[cfg(test)]
fn dns_response(request: &[u8]) -> Option<Vec<u8>> {
    dns_response_with_decision(request, None)
}

fn dns_response_with_decision(
    request: &[u8],
    policy_response: Option<&DnsPolicyResponse>,
) -> Option<Vec<u8>> {
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

    if let Some(policy_response) = policy_response {
        return dns_policy_response(request, question_end, &name, policy_response);
    }

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

fn dns_policy_response(
    request: &[u8],
    question_end: usize,
    question_name: &str,
    policy_response: &DnsPolicyResponse,
) -> Option<Vec<u8>> {
    let mut answers = Vec::new();
    for answer in &policy_response.answers {
        let name = answer.name.as_deref().unwrap_or(question_name);
        let encoded_name = encode_dns_answer_name(name, question_name)?;
        let record = match answer.answer_type.as_str() {
            "A" => {
                let address = answer
                    .address
                    .as_deref()
                    .and_then(|address| address.parse::<std::net::Ipv4Addr>().ok())?;
                Some((encoded_name, 1u16, address.octets().to_vec()))
            }
            "AAAA" => {
                let address = answer
                    .address
                    .as_deref()
                    .and_then(|address| address.parse::<std::net::Ipv6Addr>().ok())?;
                Some((encoded_name, 28u16, address.octets().to_vec()))
            }
            "CNAME" => {
                let target = answer.target.as_deref()?;
                Some((encoded_name, 5u16, encode_dns_name(target)?))
            }
            "TXT" => {
                let mut rdata = Vec::new();
                for value in &answer.values {
                    let bytes = value.as_bytes();
                    if bytes.len() > u8::MAX as usize {
                        return None;
                    }
                    rdata.push(bytes.len() as u8);
                    rdata.extend_from_slice(bytes);
                }
                Some((encoded_name, 16u16, rdata))
            }
            _ => None,
        };
        if let Some((name, record_type, rdata)) = record {
            answers.push((name, answer.ttl, record_type, rdata));
        }
    }
    let rcode = match policy_response.code.as_str() {
        "NXDOMAIN" => 3,
        "SERVFAIL" => 2,
        "REFUSED" => 5,
        _ => 0,
    };
    let mut response = Vec::new();
    response.extend_from_slice(&request[0..2]);
    response.extend_from_slice(&[0x81, 0x80 | rcode]);
    response.extend_from_slice(&request[4..6]);
    response.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    response.extend_from_slice(&[0, 0, 0, 0]);
    response.extend_from_slice(&request[12..question_end + 4]);
    for (name, ttl, record_type, rdata) in answers {
        response.extend_from_slice(&name);
        response.extend_from_slice(&record_type.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        response.extend_from_slice(&rdata);
    }
    Some(response)
}

fn encode_dns_answer_name(name: &str, question_name: &str) -> Option<Vec<u8>> {
    if name.eq_ignore_ascii_case(question_name) {
        Some(vec![0xc0, 0x0c])
    } else {
        encode_dns_name(name)
    }
}

fn encode_dns_name(name: &str) -> Option<Vec<u8>> {
    let mut encoded = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        encoded.push(bytes.len() as u8);
        encoded.extend_from_slice(bytes);
    }
    encoded.push(0);
    Some(encoded)
}

fn dns_questions(request: &[u8]) -> Option<Vec<DnsQuestion>> {
    if request.len() < 12 {
        return None;
    }
    let query_count = u16::from_be_bytes([request[4], request[5]]);
    let mut questions = Vec::new();
    let mut offset = 12;
    for _ in 0..query_count {
        let (name, question_end) = parse_dns_name(request, offset)?;
        if request.len() < question_end + 4 {
            return None;
        }
        let qtype = u16::from_be_bytes([request[question_end], request[question_end + 1]]);
        let qclass = u16::from_be_bytes([request[question_end + 2], request[question_end + 3]]);
        questions.push(DnsQuestion {
            name,
            type_name: dns_type_name(qtype).to_string(),
            class_name: if qclass == 1 { "IN" } else { "UNKNOWN" }.to_string(),
        });
        offset = question_end + 4;
    }
    Some(questions)
}

fn dns_type_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        257 => "CAA",
        _ => "UNKNOWN",
    }
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
    nat: TransparentNat,
    rx_buffer: Vec<u8>,
    staged_rx: Option<Vec<u8>>,
    pending_tx: Vec<u8>,
}

impl LibkrunNetDevice {
    fn new(rx: UnixStream, tx: UnixStream, host_ip: Ipv4Address) -> Self {
        Self {
            rx,
            tx,
            nat: TransparentNat::new(host_ip),
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
                    nat: &mut self.nat,
                },
            ));
        }
        match self.read_frame() {
            Ok(frame) => {
                let mut frame = frame?;
                if self.nat.rewrite_guest_frame(&mut frame) {
                    self.staged_rx = Some(frame);
                    return None;
                }
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
    nat: &'a mut TransparentNat,
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
        outbound_rules: Option<Vec<OutboundRulePlan>>,
    ) -> Self {
        Self::Intercept(InterceptConnection {
            destination,
            runtime,
            tls_authority,
            outbound_rules,
            state: InterceptState::ReadingHead {
                guest_head: Vec::new(),
            },
            upstream: None,
            to_guest: Vec::new(),
            to_upstream: Vec::new(),
            close_after_flush: false,
        })
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
    outbound_rules: Option<Vec<OutboundRulePlan>>,
    state: InterceptState,
    upstream: Option<TcpStream>,
    to_guest: Vec<u8>,
    to_upstream: Vec<u8>,
    close_after_flush: bool,
}

struct TlsInterceptConnection {
    authority: Arc<MitmTlsAuthority>,
    sni: Option<String>,
    server: rustls::ServerConnection,
    client: Option<rustls::ClientConnection>,
    upstream: Option<TcpStream>,
    plaintext_head: Vec<u8>,
    pending_upstream_plaintext: Vec<u8>,
    to_guest: Vec<u8>,
    to_upstream: Vec<u8>,
    close_after_flush: bool,
}

struct RamaHttpConnection {
    bridge: SyncAsyncBridge,
    to_guest: Vec<u8>,
    close_after_flush: bool,
}

fn apply_rama_http_policy(
    mut request: RamaRequest<Body>,
    destination: &HttpDestination,
    outbound_rules: Option<&[OutboundRulePlan]>,
    runtime: Option<&dyn HttpInterceptRuntime>,
) -> io::Result<RamaRequest<Body>> {
    let authority = request_authority(&request, default_port_for_scheme("http"))?;
    let _ = split_authority(&authority, default_port_for_scheme("http"))?;
    let upstream = UpstreamEndpoint {
        ip: destination.ip.clone(),
        port: destination.port,
    };
    validate_upstream_allowed(&upstream, outbound_rules)?;
    let mut intercepted = InterceptedHttpRequest {
        protocol: match request.version() {
            RamaVersion::HTTP_2 => HttpRequestProtocol::Http2,
            _ => HttpRequestProtocol::Http1,
        },
        method: request.method().as_str().to_string(),
        url: format!("http://{}{}", authority, request_path(&request)),
        original_destination: InterceptedDestination {
            ip: destination.ip.clone(),
            port: destination.port,
        },
        source: InterceptedDestination {
            ip: destination.source_ip.clone(),
            port: destination.source_port,
        },
        upstream_dial: InterceptedDestination {
            ip: upstream.ip.clone(),
            port: upstream.port,
        },
        headers: request
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                Some((
                    name.as_str().to_ascii_lowercase(),
                    value.to_str().ok()?.to_string(),
                ))
            })
            .collect(),
        tls: None,
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
        Some(runtime) => {
            if runtime.rejects_rebound_authority(
                "http",
                &authority,
                &intercepted.original_destination,
                &intercepted.upstream_dial,
            ) {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "request authority resolved to a rebound destination",
                ));
            }
            runtime.handle_request_head(intercepted)?
        }
        None => intercepted,
    };
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
    destination: &HttpDestination,
    runtime: Option<&dyn HttpInterceptRuntime>,
    outbound_rules: Option<&[OutboundRulePlan]>,
) -> RamaResponse {
    let request = match apply_rama_http_policy(request, destination, outbound_rules, runtime) {
        Ok(request) => request,
        Err(_) => return rama_response(403, "network policy denied"),
    };
    let upstream = match TcpStream::connect(upstream_socket_addr(&destination.ip, destination.port))
    {
        Ok(upstream) => upstream,
        Err(_) => return rama_response(502, "upstream connect failed"),
    };
    if upstream.set_nonblocking(true).is_err() {
        return rama_response(502, "upstream connect failed");
    }
    let upstream = match RamaTcpStream::try_from_std_tcp_stream(upstream, Extensions::new()) {
        Ok(upstream) => upstream,
        Err(_) => return rama_response(502, "upstream connect failed"),
    };
    let connection = match http_connect(upstream, request, Executor::default()).await {
        Ok(connection) => connection,
        Err(_) => return rama_response(502, "upstream http connect failed"),
    };
    match connection.conn.serve(connection.input).await {
        Ok(response) => response,
        Err(_) => rama_response(502, "upstream request failed"),
    }
}

fn rama_response(status: u16, body: &'static str) -> RamaResponse {
    RamaResponse::builder()
        .status(status)
        .body(Body::from(body))
        .unwrap()
}

fn request_authority(request: &RamaRequest<Body>, default_port: u16) -> io::Result<String> {
    if let Some(authority) = request.uri().authority() {
        return Ok(authority.as_str().to_string());
    }
    if let Some(host) = request.headers().get(HOST) {
        return host
            .to_str()
            .map(str::to_string)
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error));
    }
    if let Some(host) = request.uri().host() {
        return Ok(format!("{}:{}", host, default_port));
    }
    Err(io::Error::new(
        ErrorKind::InvalidData,
        "HTTP request is missing authority",
    ))
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
        destination: HttpDestination,
        initial_guest_bytes: Vec<u8>,
        runtime: Option<Arc<dyn HttpInterceptRuntime>>,
        outbound_rules: Option<Vec<OutboundRulePlan>>,
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
                let destination = Arc::new(destination);
                let outbound_rules = outbound_rules.map(Arc::new);
                let service = rama_core::service::service_fn(move |request: RamaRequest<Body>| {
                    let destination = destination.clone();
                    let runtime = runtime.clone();
                    let outbound_rules = outbound_rules.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            serve_rama_http_request(
                                request,
                                &destination,
                                runtime.as_deref(),
                                outbound_rules.as_deref().map(|rules| rules.as_slice()),
                            )
                            .await,
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
        while self.to_guest.len() < TLS_READ_BUFFER_BYTES {
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
        if self.bridge.async_is_closed() {
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
    ) -> io::Result<Self> {
        let mut connection = Self {
            server: authority.server_connection(server_name)?,
            authority,
            sni,
            client: None,
            upstream: None,
            plaintext_head: Vec::new(),
            pending_upstream_plaintext: Vec::new(),
            to_guest: Vec::new(),
            to_upstream: Vec::new(),
            close_after_flush: false,
        };
        connection.read_guest_tls(initial_guest_tls);
        Ok(connection)
    }

    fn poll(
        &mut self,
        socket: &mut tcp::Socket<'_>,
        destination: &HttpDestination,
        runtime: Option<&dyn HttpInterceptRuntime>,
        outbound_rules: Option<&[OutboundRulePlan]>,
    ) {
        while socket.can_recv() {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            let received = socket.recv_slice(&mut buffer).unwrap_or(0);
            if received == 0 {
                break;
            }
            self.read_guest_tls(&buffer[..received]);
        }
        self.flush_guest_tls(socket);
        self.maybe_connect_upstream(destination, runtime, outbound_rules);
        self.flush_upstream_tls();
        self.read_upstream_tls();
        self.flush_upstream_tls();
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
        if let Some(client) = &mut self.client {
            if client.is_handshaking() {
                self.pending_upstream_plaintext
                    .extend_from_slice(&plaintext);
            } else {
                if client.writer().write_all(&plaintext).is_err() {
                    self.close_after_flush = true;
                    return;
                }
                let _ = client.write_tls(&mut self.to_upstream);
            }
        } else {
            self.plaintext_head.extend_from_slice(&plaintext);
            if self.plaintext_head.len() > MAX_INTERCEPT_HEAD_BYTES {
                self.close_after_flush = true;
            }
        }
    }

    fn maybe_connect_upstream(
        &mut self,
        destination: &HttpDestination,
        runtime: Option<&dyn HttpInterceptRuntime>,
        outbound_rules: Option<&[OutboundRulePlan]>,
    ) {
        if self.client.is_some() {
            return;
        }
        let alpn = self
            .server
            .alpn_protocol()
            .and_then(|protocol| std::str::from_utf8(protocol).ok())
            .unwrap_or("http/1.1")
            .to_string();
        let metadata = HostTlsMetadata {
            server_name: self.sni.clone(),
            alpn_protocol: Some(alpn.clone()),
            protocol: Some("tls".to_string()),
        };
        let rewrite = match rewrite_intercepted_head(
            &self.plaintext_head,
            destination,
            "https",
            Some(metadata),
            outbound_rules,
            runtime,
        ) {
            Ok(Some(rewrite)) => rewrite,
            Ok(None) => return,
            Err(_) => {
                self.close_after_flush = true;
                return;
            }
        };
        let upstream = match TcpStream::connect(upstream_socket_addr(
            &rewrite.upstream_ip,
            rewrite.upstream_port,
        )) {
            Ok(upstream) => upstream,
            Err(_) => {
                self.close_after_flush = true;
                return;
            }
        };
        let _ = upstream.set_nonblocking(true);
        let mut client = match self.authority.client_connection(
            self.sni
                .as_deref()
                .filter(|server_name| server_name.parse::<std::net::IpAddr>().is_err())
                .unwrap_or(rewrite.upstream_server_name.as_str()),
            Some(&alpn),
        ) {
            Ok(client) => client,
            Err(_) => {
                self.close_after_flush = true;
                return;
            }
        };
        self.pending_upstream_plaintext
            .extend_from_slice(&rewrite.bytes);
        let _ = client.write_tls(&mut self.to_upstream);
        self.client = Some(client);
        self.upstream = Some(upstream);
        self.plaintext_head.clear();
    }

    fn flush_upstream_tls(&mut self) {
        self.flush_pending_upstream_plaintext();
        let Some(upstream) = &mut self.upstream else {
            return;
        };
        if let Some(client) = &mut self.client {
            let _ = client.write_tls(&mut self.to_upstream);
        }
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

    fn read_upstream_tls(&mut self) {
        let (Some(upstream), Some(client)) = (&mut self.upstream, &mut self.client) else {
            return;
        };
        let mut flush_pending = false;
        loop {
            let mut buffer = [0; TLS_READ_BUFFER_BYTES];
            match upstream.read(&mut buffer) {
                Ok(0) => {
                    self.close_after_flush = true;
                    let _ = upstream.shutdown(Shutdown::Both);
                    break;
                }
                Ok(read) => {
                    let mut cursor = std::io::Cursor::new(&buffer[..read]);
                    while cursor.position() < read as u64 {
                        match client.read_tls(&mut cursor) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(_) => {
                                self.close_after_flush = true;
                                break;
                            }
                        }
                        if client.process_new_packets().is_err() {
                            self.close_after_flush = true;
                            break;
                        }
                    }
                    if self.close_after_flush {
                        break;
                    }
                    let mut plaintext = Vec::new();
                    loop {
                        let mut buffer = [0; TLS_READ_BUFFER_BYTES];
                        match client.reader().read(&mut buffer) {
                            Ok(0) => break,
                            Ok(read) => plaintext.extend_from_slice(&buffer[..read]),
                            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                self.close_after_flush = true;
                                break;
                            }
                        }
                    }
                    if self.close_after_flush {
                        break;
                    }
                    if !plaintext.is_empty() && self.server.writer().write_all(&plaintext).is_err()
                    {
                        self.close_after_flush = true;
                        break;
                    }
                    flush_pending = true;
                    let _ = self.server.write_tls(&mut self.to_guest);
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.close_after_flush = true;
                    break;
                }
            }
        }
        if flush_pending {
            self.flush_pending_upstream_plaintext();
        }
    }

    fn drain_server_tls(&mut self) {
        let _ = self.server.write_tls(&mut self.to_guest);
    }

    fn flush_pending_upstream_plaintext(&mut self) {
        let Some(client) = &mut self.client else {
            return;
        };
        if client.is_handshaking() || self.pending_upstream_plaintext.is_empty() {
            return;
        }
        if client
            .writer()
            .write_all(&self.pending_upstream_plaintext)
            .is_err()
        {
            self.close_after_flush = true;
            return;
        }
        self.pending_upstream_plaintext.clear();
        let _ = client.write_tls(&mut self.to_upstream);
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
            tls.poll(
                socket,
                &self.destination,
                self.runtime.as_deref(),
                self.outbound_rules.as_deref(),
            );
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
        let mut raw_relay = None;
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
            if looks_like_tls(guest_head) {
                let maybe_server_name = tls_client_hello_sni(guest_head);
                if !tls_record_complete(guest_head) {
                    continue;
                }
                if !tls_client_hello_offers_http(guest_head) {
                    raw_relay = Some(std::mem::take(guest_head));
                    break;
                }
                let Some(authority) = self.tls_authority.as_ref() else {
                    raw_relay = Some(std::mem::take(guest_head));
                    break;
                };
                let sni = maybe_server_name;
                let server_name = tls_intercept_server_name(&self.destination, sni.as_deref());
                match TlsInterceptConnection::new(authority.clone(), &server_name, sni, guest_head)
                {
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
            if guest_head.starts_with(H2_PREFACE) {
                let initial_bytes = std::mem::take(guest_head);
                match RamaHttpConnection::start(
                    self.destination.clone(),
                    initial_bytes,
                    self.runtime.clone(),
                    self.outbound_rules.clone(),
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
                return;
            }
            if should_use_raw_tcp_relay(guest_head) {
                raw_relay = Some(std::mem::take(guest_head));
                break;
            }
            match rewrite_intercepted_head(
                guest_head,
                &self.destination,
                "http",
                None,
                self.outbound_rules.as_deref(),
                self.runtime.as_deref(),
            ) {
                Ok(Some(rewritten)) => {
                    match TcpStream::connect(upstream_socket_addr(
                        &rewritten.upstream_ip,
                        rewritten.upstream_port,
                    )) {
                        Ok(upstream) => {
                            let _ = upstream.set_nonblocking(true);
                            self.to_upstream.extend_from_slice(&rewritten.bytes);
                            self.upstream = Some(upstream);
                            self.state = InterceptState::Relaying;
                        }
                        Err(_) => {
                            self.to_guest.extend_from_slice(OUTBOUND_DENIED_RESPONSE);
                            self.close_after_flush = true;
                            self.state = InterceptState::Closing;
                        }
                    }
                    return;
                }
                Ok(None) => {}
                Err(_) => {
                    self.to_guest.extend_from_slice(OUTBOUND_DENIED_RESPONSE);
                    self.close_after_flush = true;
                    self.state = InterceptState::Closing;
                    return;
                }
            }
        }
        if let Some(initial_bytes) = raw_relay {
            self.start_raw_relay(initial_bytes);
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
struct TransparentNat {
    host_ip: [u8; 4],
    tcp_flows: HashMap<TcpFlow, NatFlow>,
    udp_flows: HashMap<UdpNatFlow, NatFlow>,
    next_udp_host_port: u16,
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
    destination_port: u16,
    last_seen: StdInstant,
    closing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpNatFlow {
    guest_ip: [u8; 4],
    guest_port: u16,
    host_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UdpDestination {
    ip: String,
    port: u16,
}

impl TransparentNat {
    fn new(host_ip: Ipv4Address) -> Self {
        Self {
            host_ip: host_ip.octets(),
            tcp_flows: HashMap::new(),
            udp_flows: HashMap::new(),
            next_udp_host_port: UDP_NAT_PORT_START,
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
                    NatFlow {
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
        let flow = UdpNatFlow {
            guest_ip,
            guest_port,
            host_port,
        };
        let new_host_port = !self.udp_flows.contains_key(&flow);
        self.udp_flows.insert(
            flow,
            NatFlow {
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
            let Some(nat_flow) = self.tcp_flows.get_mut(&flow) else {
                return;
            };
            nat_flow.last_seen = StdInstant::now();
            let original_destination = nat_flow.destination_ip;
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
        let flow = UdpNatFlow {
            guest_ip: packet.destination_ip(frame),
            guest_port: packet.destination_port(frame),
            host_port: packet.source_port(frame),
        };
        if let Some(nat_flow) = self.udp_flows.get_mut(&flow) {
            nat_flow.last_seen = StdInstant::now();
            packet.set_source_ip(frame, nat_flow.destination_ip);
            packet.set_source_port(frame, nat_flow.destination_port);
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

    fn udp_original_destination(
        &self,
        guest_ip: IpAddress,
        guest_port: u16,
        host_port: u16,
    ) -> Option<UdpDestination> {
        let guest_ip = match guest_ip {
            IpAddress::Ipv4(guest_ip) => guest_ip.octets(),
        };
        let flow = UdpNatFlow {
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
                    NAT_FLOW_CLOSING_TTL
                } else {
                    NAT_FLOW_IDLE_TTL
                }
        });
        self.udp_flows
            .retain(|_, flow| now.duration_since(flow.last_seen) < NAT_FLOW_IDLE_TTL);
    }

    fn udp_host_port_for_destination(
        &mut self,
        guest_ip: [u8; 4],
        guest_port: u16,
        destination_ip: [u8; 4],
        destination_port: u16,
    ) -> Option<u16> {
        if let Some((flow, _)) = self.udp_flows.iter().find(|(flow, nat_flow)| {
            flow.guest_ip == guest_ip
                && flow.guest_port == guest_port
                && nat_flow.destination_ip == destination_ip
                && nat_flow.destination_port == destination_port
        }) {
            return Some(flow.host_port);
        }

        for _ in UDP_NAT_PORT_START..=UDP_NAT_PORT_END {
            let candidate = self.next_udp_host_port;
            self.next_udp_host_port = if self.next_udp_host_port == UDP_NAT_PORT_END {
                UDP_NAT_PORT_START
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
    fn raw_tcp_classifier_keeps_extension_http_methods_interceptable() {
        assert!(bytes_could_be_http_request(b"PROPFIND /dav HTTP/1.1\r\n"));
        assert!(bytes_could_be_http_request(b"CUSTOM-METHOD "));
        assert!(!bytes_could_be_http_request(H2_PREFACE));
        assert!(!bytes_could_be_http_request(b"hello sandbox\n"));
        assert!(!bytes_could_be_http_request(b"PING\r\n"));
    }

    #[test]
    fn h1_rewrite_rejects_duplicate_host_headers() {
        let destination = HttpDestination {
            source_ip: "10.0.2.15".to_string(),
            source_port: 50_000,
            ip: "93.184.216.34".to_string(),
            port: 80,
        };
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nHost: attacker.example\r\n\r\n";

        let error = match rewrite_h1_head(request, &destination, "http", None, None, None) {
            Ok(_) => panic!("duplicate Host headers must be rejected"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn tls_intercept_server_name_falls_back_to_destination_ip_without_sni() {
        let destination = HttpDestination {
            source_ip: "10.0.2.15".to_string(),
            source_port: 50_000,
            ip: "93.184.216.34".to_string(),
            port: 443,
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
    fn transparent_nat_prunes_flow_after_host_fin() {
        let mut nat = TransparentNat::new(Ipv4Address::new(10, 0, 2, 1));
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
        assert_eq!(nat.tcp_host_ports().count(), 0);
    }

    #[test]
    fn transparent_nat_assigns_distinct_udp_ports_for_distinct_destinations() {
        let mut nat = TransparentNat::new(Ipv4Address::new(10, 0, 2, 1));
        let mut first = udp_frame([10, 0, 2, 15], [1, 1, 1, 1], 50_000, 53);
        let mut second = udp_frame([10, 0, 2, 15], [8, 8, 8, 8], 50_000, 53);

        nat.rewrite_guest_frame(&mut first);
        nat.rewrite_guest_frame(&mut second);

        let first_packet = Ipv4UdpPacket::parse(&first).unwrap();
        let second_packet = Ipv4UdpPacket::parse(&second).unwrap();
        let first_host_port = first_packet.destination_port(&first);
        let second_host_port = second_packet.destination_port(&second);
        assert_ne!(first_host_port, second_host_port);
        assert_eq!(
            nat.udp_original_destination(IpAddress::v4(10, 0, 2, 15), 50_000, first_host_port),
            Some(UdpDestination {
                ip: "1.1.1.1".to_string(),
                port: 53,
            }),
        );
        assert_eq!(
            nat.udp_original_destination(IpAddress::v4(10, 0, 2, 15), 50_000, second_host_port),
            Some(UdpDestination {
                ip: "8.8.8.8".to_string(),
                port: 53,
            }),
        );

        let mut response = udp_frame([10, 0, 2, 1], [10, 0, 2, 15], first_host_port, 50_000);
        nat.rewrite_host_frame(&mut response);
        let response_packet = Ipv4UdpPacket::parse(&response).unwrap();
        assert_eq!(response_packet.source_ip(&response), [1, 1, 1, 1]);
        assert_eq!(response_packet.source_port(&response), 53);
    }

    #[test]
    fn transparent_nat_reports_udp_port_exhaustion() {
        let mut nat = TransparentNat::new(Ipv4Address::new(10, 0, 2, 1));
        for host_port in UDP_NAT_PORT_START..=UDP_NAT_PORT_END {
            nat.udp_flows.insert(
                UdpNatFlow {
                    guest_ip: [10, 0, 2, 15],
                    guest_port: host_port,
                    host_port,
                },
                NatFlow {
                    destination_ip: [192, 0, 2, 1],
                    destination_port: 53,
                    last_seen: StdInstant::now(),
                    closing: false,
                },
            );
        }

        assert_eq!(
            nat.udp_host_port_for_destination([10, 0, 2, 16], 50_000, [192, 0, 2, 2], 53),
            None,
        );
    }

    #[test]
    fn dns_unsupported_query_type_returns_nodata_for_known_name() {
        let response = dns_response(&dns_query("public.sandbox.test", 28)).unwrap();

        assert_eq!(&response[2..4], &[0x81, 0x80]);
        assert_eq!(&response[6..8], &[0, 0]);
    }

    #[test]
    fn dns_policy_response_emits_supported_answer_types() {
        let query = dns_query("policy.sandbox.test", 1);
        let response = dns_response_with_decision(
            &query,
            Some(&DnsPolicyResponse {
                code: "NOERROR".to_string(),
                answers: vec![
                    DnsPolicyAnswer {
                        answer_type: "A".to_string(),
                        name: None,
                        address: Some("192.0.2.10".to_string()),
                        target: None,
                        values: Vec::new(),
                        ttl: 60,
                    },
                    DnsPolicyAnswer {
                        answer_type: "AAAA".to_string(),
                        name: None,
                        address: Some("2001:db8::10".to_string()),
                        target: None,
                        values: Vec::new(),
                        ttl: 60,
                    },
                    DnsPolicyAnswer {
                        answer_type: "CNAME".to_string(),
                        name: None,
                        address: None,
                        target: Some("target.sandbox.test".to_string()),
                        values: Vec::new(),
                        ttl: 60,
                    },
                    DnsPolicyAnswer {
                        answer_type: "TXT".to_string(),
                        name: None,
                        address: None,
                        target: None,
                        values: vec!["sandbox".to_string()],
                        ttl: 60,
                    },
                ],
            }),
        )
        .unwrap();

        assert_eq!(&response[6..8], &4u16.to_be_bytes());
        assert!(dns_response_answer_types(&response).contains(&1));
        assert!(dns_response_answer_types(&response).contains(&28));
        assert!(dns_response_answer_types(&response).contains(&5));
        assert!(dns_response_answer_types(&response).contains(&16));
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

    fn dns_response_answer_types(response: &[u8]) -> Vec<u16> {
        let question_count = u16::from_be_bytes([response[4], response[5]]) as usize;
        let answer_count = u16::from_be_bytes([response[6], response[7]]) as usize;
        let mut offset = 12;
        for _ in 0..question_count {
            let (_, question_end) = parse_dns_name(response, offset).unwrap();
            offset = question_end + 4;
        }
        let mut answer_types = Vec::new();
        for _ in 0..answer_count {
            let name_end = skip_dns_name(response, offset).unwrap();
            let answer_type = u16::from_be_bytes([response[name_end], response[name_end + 1]]);
            let data_len =
                u16::from_be_bytes([response[name_end + 8], response[name_end + 9]]) as usize;
            answer_types.push(answer_type);
            offset = name_end + 10 + data_len;
        }
        answer_types
    }

    fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
        loop {
            let len = *packet.get(offset)?;
            offset += 1;
            if len == 0 {
                return Some(offset);
            }
            if len & 0xc0 == 0xc0 {
                packet.get(offset)?;
                return Some(offset + 1);
            }
            if len > 63 || packet.len() < offset + usize::from(len) {
                return None;
            }
            offset += usize::from(len);
        }
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
