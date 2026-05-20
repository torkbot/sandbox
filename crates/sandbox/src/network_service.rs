use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
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
const TLS_READ_BUFFER_BYTES: usize = 16 * 1024;
const MAX_INTERCEPT_HEAD_BYTES: usize = 64 * 1024;
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

#[derive(Debug)]
struct MitmTlsAuthority {
    ca_certificate_pem: String,
    ca_private_key_pem: String,
    client_roots: rustls::RootCertStore,
}

impl MitmTlsAuthority {
    fn new(config: MitmTlsConfig) -> io::Result<Self> {
        let ca_certificate =
            rustls::pki_types::CertificateDer::from_pem_slice(config.ca_certificate_pem.as_bytes())
                .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        let mut client_roots = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            client_roots
                .add(cert)
                .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        }
        client_roots
            .add(ca_certificate)
            .map_err(|error| io::Error::new(ErrorKind::InvalidInput, error))?;
        Ok(Self {
            ca_certificate_pem: config.ca_certificate_pem,
            ca_private_key_pem: config.ca_private_key_pem,
            client_roots,
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

    fn client_connection(
        &self,
        server_name: &str,
        alpn_protocol: Option<&str>,
    ) -> io::Result<rustls::ClientConnection> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(self.client_roots.clone())
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
        let tls_authority = tls_config
            .map(MitmTlsAuthority::new)
            .transpose()?
            .map(Arc::new);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            run_network_service(host, worker_shutdown, tls_authority, outbound_rules, http)
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
    if tls_authority.is_some() {
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
            &http_connections,
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
                outbound_rules.as_deref(),
                http.clone(),
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
    nat: &TransparentTcpNat,
    outbound_rules: Option<&[OutboundRulePlan]>,
    http: Option<Arc<dyn HttpInterceptRuntime>>,
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
        tls_authority,
        http_connections,
    );
}

fn looks_like_tls(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x16))
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
    http: Option<Arc<dyn HttpInterceptRuntime>>,
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
        return rewrite_h2_head(
            guest_head,
            destination,
            scheme,
            tls,
            outbound_rules,
            runtime,
        );
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
    let upstream = resolve_upstream_authority(&authority, default_port_for_scheme(scheme))?;
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

fn rewrite_h2_head(
    guest_head: &[u8],
    destination: &HttpDestination,
    scheme_override: &str,
    tls: Option<HostTlsMetadata>,
    outbound_rules: Option<&[OutboundRulePlan]>,
    runtime: Option<&dyn HttpInterceptRuntime>,
) -> io::Result<Option<RewrittenHead>> {
    let mut cursor = H2_PREFACE.len();
    while guest_head.len() >= cursor + 9 {
        let length = ((guest_head[cursor] as usize) << 16)
            | ((guest_head[cursor + 1] as usize) << 8)
            | (guest_head[cursor + 2] as usize);
        let frame_type = guest_head[cursor + 3];
        let flags = guest_head[cursor + 4];
        let frame_end = cursor + 9 + length;
        if guest_head.len() < frame_end {
            return Ok(None);
        }
        if frame_type != 0x1 {
            cursor = frame_end;
            continue;
        }

        let payload = &guest_head[cursor + 9..frame_end];
        let (header_prefix, header_block, header_padding) =
            split_h2_headers_payload(payload, flags)?;
        let stream_id = h2_stream_id(&guest_head[cursor + 5..cursor + 9]);
        let mut header_block = header_block.to_vec();
        let mut header_sequence_end = frame_end;
        if flags & 0x4 == 0 {
            let continuation = collect_h2_continuations(guest_head, frame_end, stream_id)?;
            let Some(continuation) = continuation else {
                return Ok(None);
            };
            header_block.extend_from_slice(&continuation.header_block);
            header_sequence_end = continuation.end;
        }
        let mut block = rama_core::bytes::BytesMut::from(header_block.as_slice());
        let mut decoder = rama_http::proto::h2::hpack::Decoder::new(4096);
        let mut decoded = Vec::new();
        decoder
            .decode(&mut std::io::Cursor::new(&mut block), |header| {
                decoded.push(header)
            })
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, format!("{error:?}")))?;

        let mut method = "GET".to_string();
        let mut authority = None;
        let mut path = "/".to_string();
        let mut scheme = "http".to_string();
        let mut pairs = Vec::new();
        for header in &decoded {
            match header {
                rama_http::proto::h2::hpack::Header::Method(value) => {
                    method = value.as_str().to_string();
                }
                rama_http::proto::h2::hpack::Header::Authority(value) => {
                    authority = Some(value.to_string());
                }
                rama_http::proto::h2::hpack::Header::Path(value) => {
                    path = value.to_string();
                }
                rama_http::proto::h2::hpack::Header::Scheme(value) => {
                    scheme = value.to_string();
                }
                rama_http::proto::h2::hpack::Header::Field { name, value } => {
                    pairs.push((
                        name.as_str().to_string(),
                        value
                            .to_str()
                            .map_err(|error| io::Error::new(ErrorKind::InvalidData, error))?
                            .to_string(),
                    ));
                }
                _ => {}
            }
        }
        let authority = authority.ok_or_else(|| {
            io::Error::new(ErrorKind::InvalidData, "HTTP/2 request missing :authority")
        })?;
        if scheme == "http" && scheme_override == "https" {
            scheme = "https".to_string();
        }
        let (upstream_server_name, _) =
            split_authority(&authority, default_port_for_scheme(&scheme))?;
        let upstream = resolve_upstream_authority(&authority, default_port_for_scheme(&scheme))?;
        validate_upstream_allowed(&upstream, outbound_rules)?;
        let request = InterceptedHttpRequest {
            protocol: HttpRequestProtocol::Http2,
            method,
            url: format!("{scheme}://{authority}{path}"),
            original_destination: InterceptedDestination {
                ip: destination.ip.clone(),
                port: destination.port,
            },
            upstream_dial: InterceptedDestination {
                ip: upstream.ip.clone(),
                port: upstream.port,
            },
            headers: pairs,
            tls,
        };
        let request = match runtime {
            Some(runtime) => {
                if runtime.rejects_rebound_authority(
                    &scheme,
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
        let mut encoded = rama_core::bytes::BytesMut::new();
        let mut encoder = rama_http::proto::h2::hpack::Encoder::new(4096, 4096);
        let mut hpack_headers = Vec::new();
        hpack_headers.push(rama_http::proto::h2::hpack::Header::Method(
            request.method.parse().map_err(|error| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("invalid HTTP/2 method: {error}"),
                )
            })?,
        ));
        hpack_headers.push(rama_http::proto::h2::hpack::Header::Scheme(
            rama_http::proto::h2::hpack::BytesStr::try_from(
                rama_core::bytes::Bytes::copy_from_slice(scheme.as_bytes()),
            )
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, format!("{error:?}")))?,
        ));
        hpack_headers.push(rama_http::proto::h2::hpack::Header::Authority(
            rama_http::proto::h2::hpack::BytesStr::try_from(
                rama_core::bytes::Bytes::copy_from_slice(authority.as_bytes()),
            )
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, format!("{error:?}")))?,
        ));
        hpack_headers.push(rama_http::proto::h2::hpack::Header::Path(
            rama_http::proto::h2::hpack::BytesStr::try_from(
                rama_core::bytes::Bytes::copy_from_slice(path.as_bytes()),
            )
            .map_err(|error| io::Error::new(ErrorKind::InvalidData, format!("{error:?}")))?,
        ));
        for (name, value) in request.headers {
            hpack_headers.push(rama_http::proto::h2::hpack::Header::Field {
                name: name.parse().map_err(|error| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("invalid header name: {error}"),
                    )
                })?,
                value: value.parse().map_err(|error| {
                    io::Error::new(
                        ErrorKind::InvalidData,
                        format!("invalid header value: {error}"),
                    )
                })?,
            });
        }
        encoder.encode(
            hpack_headers
                .into_iter()
                .map(HpackHeaderExt::with_optional_name),
            &mut encoded,
        );
        let mut rewritten = Vec::new();
        rewritten.extend_from_slice(&guest_head[..cursor]);
        let rewritten_payload_len = header_prefix.len() + encoded.len() + header_padding.len();
        let rewritten_flags = flags | 0x4;
        rewritten.extend_from_slice(&[
            ((rewritten_payload_len >> 16) & 0xff) as u8,
            ((rewritten_payload_len >> 8) & 0xff) as u8,
            (rewritten_payload_len & 0xff) as u8,
            frame_type,
            rewritten_flags,
        ]);
        rewritten.extend_from_slice(&guest_head[cursor + 5..cursor + 9]);
        rewritten.extend_from_slice(header_prefix);
        rewritten.extend_from_slice(&encoded);
        rewritten.extend_from_slice(header_padding);
        rewritten.extend_from_slice(&guest_head[header_sequence_end..]);
        return Ok(Some(RewrittenHead {
            bytes: rewritten,
            upstream_ip: upstream.ip,
            upstream_port: upstream.port,
            upstream_server_name,
        }));
    }
    Ok(None)
}

fn split_h2_headers_payload(payload: &[u8], flags: u8) -> io::Result<(&[u8], &[u8], &[u8])> {
    let mut block_start = 0;
    if flags & 0x8 != 0 {
        if payload.is_empty() {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "HTTP/2 padded HEADERS frame is missing pad length",
            ));
        }
        block_start = 1;
    }
    if flags & 0x20 != 0 {
        if payload.len() < block_start + 5 {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "HTTP/2 priority HEADERS frame is missing priority fields",
            ));
        }
        block_start += 5;
    }
    let padding_len = if flags & 0x8 != 0 {
        payload[0] as usize
    } else {
        0
    };
    if payload.len() < block_start + padding_len {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "HTTP/2 HEADERS frame padding exceeds payload length",
        ));
    }
    let block_end = payload.len() - padding_len;
    Ok((
        &payload[..block_start],
        &payload[block_start..block_end],
        &payload[block_end..],
    ))
}

struct H2ContinuationBlock {
    header_block: Vec<u8>,
    end: usize,
}

fn collect_h2_continuations(
    bytes: &[u8],
    mut cursor: usize,
    stream_id: u32,
) -> io::Result<Option<H2ContinuationBlock>> {
    let mut header_block = Vec::new();
    loop {
        if bytes.len() < cursor + 9 {
            return Ok(None);
        }
        let length = ((bytes[cursor] as usize) << 16)
            | ((bytes[cursor + 1] as usize) << 8)
            | (bytes[cursor + 2] as usize);
        let frame_type = bytes[cursor + 3];
        let flags = bytes[cursor + 4];
        let frame_end = cursor + 9 + length;
        if bytes.len() < frame_end {
            return Ok(None);
        }
        if frame_type != 0x9 || h2_stream_id(&bytes[cursor + 5..cursor + 9]) != stream_id {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "HTTP/2 HEADERS frame was not followed by matching CONTINUATION frames",
            ));
        }
        header_block.extend_from_slice(&bytes[cursor + 9..frame_end]);
        if flags & 0x4 != 0 {
            return Ok(Some(H2ContinuationBlock {
                header_block,
                end: frame_end,
            }));
        }
        cursor = frame_end;
    }
}

fn h2_stream_id(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0] & 0x7f, bytes[1], bytes[2], bytes[3]])
}

trait HpackHeaderExt {
    fn with_optional_name(
        self,
    ) -> rama_http::proto::h2::hpack::Header<Option<rama_http::HeaderName>>;
}

impl HpackHeaderExt for rama_http::proto::h2::hpack::Header {
    fn with_optional_name(
        self,
    ) -> rama_http::proto::h2::hpack::Header<Option<rama_http::HeaderName>> {
        match self {
            Self::Field {
                name: field_name,
                value,
            } => rama_http::proto::h2::hpack::Header::Field {
                name: Some(field_name),
                value,
            },
            Self::Authority(value) => rama_http::proto::h2::hpack::Header::Authority(value),
            Self::Method(value) => rama_http::proto::h2::hpack::Header::Method(value),
            Self::Scheme(value) => rama_http::proto::h2::hpack::Header::Scheme(value),
            Self::Path(value) => rama_http::proto::h2::hpack::Header::Path(value),
            Self::Protocol(value) => rama_http::proto::h2::hpack::Header::Protocol(value),
            Self::Status(value) => rama_http::proto::h2::hpack::Header::Status(value),
        }
    }
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

fn resolve_upstream_authority(authority: &str, default_port: u16) -> io::Result<UpstreamEndpoint> {
    let (host, port) = split_authority(authority, default_port)?;
    let address = (host.as_str(), port)
        .to_socket_addrs()?
        .find(|address| address.is_ipv4())
        .ok_or_else(|| {
            io::Error::new(
                ErrorKind::AddrNotAvailable,
                format!("no IPv4 address resolved for {authority}"),
            )
        })?;
    Ok(UpstreamEndpoint {
        ip: address.ip().to_string(),
        port,
    })
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
        if extension_type == 0 {
            return tls_sni_from_extension(&bytes[offset..offset + extension_len]);
        }
        offset += extension_len;
    }
    None
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
        let upstream =
            match TcpStream::connect((rewrite.upstream_ip.as_str(), rewrite.upstream_port)) {
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
        let InterceptState::ReadingHead { guest_head } = &mut self.state else {
            return;
        };
        while socket.can_recv() {
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
                let Some(authority) = self.tls_authority.as_ref() else {
                    self.close_after_flush = true;
                    self.state = InterceptState::Closing;
                    return;
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
            match rewrite_intercepted_head(
                guest_head,
                &self.destination,
                "http",
                None,
                self.outbound_rules.as_deref(),
                self.runtime.as_deref(),
            ) {
                Ok(Some(rewritten)) => {
                    match TcpStream::connect((
                        rewritten.upstream_ip.as_str(),
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
    fn h2_headers_payload_splits_padded_and_priority_fields() {
        let payload = [
            2, // pad length
            0x80, 0, 0, 1, 7, // priority fields
            0x82, 0x87, // HPACK block
            0, 0, // padding
        ];

        let (prefix, block, padding) = split_h2_headers_payload(&payload, 0x8 | 0x20).unwrap();

        assert_eq!(prefix, &payload[..6]);
        assert_eq!(block, &payload[6..8]);
        assert_eq!(padding, &payload[8..]);
    }

    #[test]
    fn h2_headers_payload_rejects_invalid_padding() {
        let error = split_h2_headers_payload(&[4, 0x82], 0x8).unwrap_err();

        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn h1_rewrite_rejects_duplicate_host_headers() {
        let destination = HttpDestination {
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
    fn h2_rewrite_accepts_headers_split_across_continuations() {
        let mut encoded = rama_core::bytes::BytesMut::new();
        let mut encoder = rama_http::proto::h2::hpack::Encoder::new(4096, 4096);
        encoder.encode(
            [
                rama_http::proto::h2::hpack::Header::Method("GET".parse().unwrap()),
                rama_http::proto::h2::hpack::Header::Scheme(
                    rama_http::proto::h2::hpack::BytesStr::try_from(
                        rama_core::bytes::Bytes::from_static(b"https"),
                    )
                    .unwrap(),
                ),
                rama_http::proto::h2::hpack::Header::Authority(
                    rama_http::proto::h2::hpack::BytesStr::try_from(
                        rama_core::bytes::Bytes::from_static(b"93.184.216.34"),
                    )
                    .unwrap(),
                ),
                rama_http::proto::h2::hpack::Header::Path(
                    rama_http::proto::h2::hpack::BytesStr::try_from(
                        rama_core::bytes::Bytes::from_static(b"/"),
                    )
                    .unwrap(),
                ),
            ]
            .into_iter()
            .map(HpackHeaderExt::with_optional_name),
            &mut encoded,
        );
        let split = encoded.len() / 2;
        let mut request = Vec::new();
        request.extend_from_slice(H2_PREFACE);
        request.extend_from_slice(&h2_frame(0x1, 0, 1, &encoded[..split]));
        request.extend_from_slice(&h2_frame(0x9, 0x4, 1, &encoded[split..]));

        let rewritten = rewrite_h2_head(
            &request,
            &HttpDestination {
                ip: "93.184.216.34".to_string(),
                port: 443,
            },
            "https",
            None,
            Some(&[OutboundRulePlan::AcceptPublicInternet { ports: vec![443] }]),
            None,
        )
        .unwrap()
        .unwrap();

        assert!(rewritten.bytes.starts_with(H2_PREFACE));
        let cursor = H2_PREFACE.len();
        let length = ((rewritten.bytes[cursor] as usize) << 16)
            | ((rewritten.bytes[cursor + 1] as usize) << 8)
            | rewritten.bytes[cursor + 2] as usize;
        assert_eq!(rewritten.bytes[cursor + 3], 0x1);
        assert_eq!(rewritten.bytes[cursor + 4] & 0x4, 0x4);
        assert_eq!(rewritten.bytes.len(), cursor + 9 + length);
    }

    #[test]
    fn tls_intercept_server_name_falls_back_to_destination_ip_without_sni() {
        let destination = HttpDestination {
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

    fn h2_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            ((payload.len() >> 16) & 0xff) as u8,
            ((payload.len() >> 8) & 0xff) as u8,
            (payload.len() & 0xff) as u8,
            frame_type,
            flags,
        ]);
        frame.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }
}
