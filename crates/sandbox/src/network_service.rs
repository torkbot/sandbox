use std::collections::HashMap;
use std::io::{self, Cursor, Read, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};

const HOST_HTTP_PROBE_PORT: u16 = 8080;
const HOST_HTTP_PORT: u16 = 80;
const HOST_HTTPS_PORT: u16 = 443;
const HTTP_LISTENERS_PER_PORT: usize = 4;
const HOST_HTTP_PROBE_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-length: 25\r\nconnection: close\r\n\r\nsandbox explicit network\n";

#[derive(Debug, Clone)]
pub struct HostHttpRequest {
    pub method: String,
    pub url: String,
    pub destination_ip: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct HostHttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub trait HostHttpHandler: Send + Sync + 'static {
    fn handle_http_request(&self, request: HostHttpRequest) -> io::Result<HostHttpResponse>;
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
        http_handler: Option<Arc<dyn HostHttpHandler>>,
        tls_config: Option<MitmTlsConfig>,
    ) -> io::Result<Self> {
        let (host, guest) = UnixStream::pair()?;
        let tls_acceptor = tls_config.map(TlsAcceptor::new).transpose()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || {
            run_network_service(host, worker_shutdown, http_handler, tls_acceptor)
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
    http_handler: Option<Arc<dyn HostHttpHandler>>,
    tls_acceptor: Option<TlsAcceptor>,
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
    let mut http_sockets = HashMap::new();
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PORT);
    add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTP_PROBE_PORT);
    if tls_acceptor.is_some() {
        add_http_listener(&mut sockets, &mut http_sockets, HOST_HTTPS_PORT);
    }
    let mut tls_connections = HashMap::new();

    while !shutdown.load(Ordering::Acquire) {
        let timestamp = Instant::now();
        let _ = iface.poll(timestamp, &mut device, &mut sockets);
        for port in device.nat.host_ports() {
            add_http_listener(&mut sockets, &mut http_sockets, port);
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
                http_handler.as_deref(),
                &device.nat,
                tls_acceptor.as_ref(),
                &mut tls_connections,
            );
        }
        thread::sleep(Duration::from_millis(1));
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
                    tcp::SocketBuffer::new(vec![0; 4096]),
                    tcp::SocketBuffer::new(vec![0; 4096]),
                ))
            })
            .collect()
    });
}

fn poll_http_socket(
    sockets: &mut SocketSet<'_>,
    handle: SocketHandle,
    port: u16,
    handler: Option<&dyn HostHttpHandler>,
    nat: &TransparentTcpNat,
    tls_acceptor: Option<&TlsAcceptor>,
    tls_connections: &mut HashMap<SocketHandle, TlsConnection>,
) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        tls_connections.remove(&handle);
        let _ = socket.listen(port);
        return;
    }

    if socket.can_recv() {
        let mut request = [0; 4096];
        let received = socket.recv_slice(&mut request).unwrap_or(0);
        if received > 0 {
            if port == HOST_HTTPS_PORT {
                poll_tls_http_socket(
                    socket,
                    handle,
                    nat,
                    handler,
                    tls_acceptor,
                    tls_connections,
                    &request[..received],
                );
            } else {
                let response = handler
                    .and_then(|handler| {
                        parse_http_request(socket, nat, &request[..received], false)
                            .and_then(|request| handler.handle_http_request(request).ok())
                    })
                    .map(encode_http_response)
                    .unwrap_or_else(|| HOST_HTTP_PROBE_RESPONSE.to_vec());
                let _ = socket.send_slice(&response);
                socket.close();
            }
        }
    }
}

fn poll_tls_http_socket(
    socket: &mut tcp::Socket<'_>,
    handle: SocketHandle,
    nat: &TransparentTcpNat,
    handler: Option<&dyn HostHttpHandler>,
    tls_acceptor: Option<&TlsAcceptor>,
    tls_connections: &mut HashMap<SocketHandle, TlsConnection>,
    received: &[u8],
) {
    let Some(tls_acceptor) = tls_acceptor else {
        socket.close();
        return;
    };
    let Some(handler) = handler else {
        socket.close();
        return;
    };
    let connection = tls_connections
        .entry(handle)
        .or_insert_with(|| tls_acceptor.connection());
    let mut reader = Cursor::new(received);
    if connection.tls.read_tls(&mut reader).is_err()
        || connection.tls.process_new_packets().is_err()
    {
        socket.close();
        return;
    }
    let mut plaintext = Vec::new();
    let _ = connection.tls.reader().read_to_end(&mut plaintext);
    if !plaintext.is_empty() {
        if let Some(request) = parse_http_request(socket, nat, &plaintext, true) {
            if let Ok(response) = handler.handle_http_request(request) {
                let _ = connection
                    .tls
                    .writer()
                    .write_all(&encode_http_response(response));
            }
        }
    }
    let mut encrypted = Vec::new();
    let _ = connection.tls.write_tls(&mut encrypted);
    if !encrypted.is_empty() {
        let _ = socket.send_slice(&encrypted);
    }
    if !plaintext.is_empty() {
        connection.tls.send_close_notify();
        let mut close_notify = Vec::new();
        let _ = connection.tls.write_tls(&mut close_notify);
        if !close_notify.is_empty() {
            let _ = socket.send_slice(&close_notify);
        }
        socket.close();
    }
}

fn parse_http_request(
    socket: &tcp::Socket<'_>,
    nat: &TransparentTcpNat,
    bytes: &[u8],
    tls: bool,
) -> Option<HostHttpRequest> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((text, ""));
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next()?.to_string();
    let target = request_parts.next()?.to_string();
    let remote = socket.remote_endpoint()?;
    let local = socket.local_endpoint()?;
    let destination_ip = nat.original_destination(remote.addr, remote.port, local.port)?;
    let mut headers = Vec::new();
    let mut host = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name == "host" {
            host = Some(value.clone());
        }
        headers.push((name, value));
    }
    let authority = host.unwrap_or_else(|| destination_ip.clone());
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else {
        format!(
            "{}://{authority}{target}",
            if tls { "https" } else { "http" }
        )
    };

    Some(HostHttpRequest {
        method,
        url,
        destination_ip,
        headers,
        body: body.as_bytes().to_vec(),
    })
}

fn encode_http_response(response: HostHttpResponse) -> Vec<u8> {
    let mut bytes = format!("HTTP/1.1 {} OK\r\n", response.status).into_bytes();
    let has_content_length = response
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("content-length"));
    for (name, value) in response.headers {
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.as_bytes());
        bytes.extend_from_slice(b"\r\n");
    }
    if !has_content_length {
        bytes.extend_from_slice(format!("content-length: {}\r\n", response.body.len()).as_bytes());
    }
    bytes.extend_from_slice(b"connection: close\r\n\r\n");
    bytes.extend_from_slice(&response.body);
    bytes
}

struct LibkrunNetDevice {
    rx: UnixStream,
    tx: UnixStream,
    nat: TransparentTcpNat,
}

impl LibkrunNetDevice {
    fn new(rx: UnixStream, tx: UnixStream, host_ip: Ipv4Address) -> Self {
        Self {
            rx,
            tx,
            nat: TransparentTcpNat::new(host_ip),
        }
    }
}

impl Device for LibkrunNetDevice {
    type RxToken<'a> = LibkrunRxToken;
    type TxToken<'a> = LibkrunTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match read_ethernet_frame(&mut self.rx) {
            Ok(mut frame) => {
                self.nat.rewrite_guest_frame(&mut frame);
                Some((
                    LibkrunRxToken { frame },
                    LibkrunTxToken {
                        stream: &mut self.tx,
                        nat: &mut self.nat,
                    },
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(LibkrunTxToken {
            stream: &mut self.tx,
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
    stream: &'a mut UnixStream,
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
        let _ = write_ethernet_frame(self.stream, &frame);
        result
    }
}

struct TlsAcceptor {
    config: Arc<rustls::ServerConfig>,
}

struct TlsConnection {
    tls: rustls::ServerConnection,
}

impl TlsAcceptor {
    fn new(config: MitmTlsConfig) -> io::Result<Self> {
        let ca_key = rcgen::KeyPair::from_pem(&config.ca_private_key_pem)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let ca = rcgen::Issuer::from_ca_cert_pem(&config.ca_certificate_pem, ca_key)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let leaf_key = rcgen::KeyPair::generate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let leaf =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string(), "localhost".to_string()])
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?
                .signed_by(&leaf_key, &ca)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let cert_chain = vec![CertificateDer::from(leaf.der().to_vec())];
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key_der)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(Self {
            config: Arc::new(config),
        })
    }

    fn connection(&self) -> TlsConnection {
        TlsConnection {
            tls: rustls::ServerConnection::new(self.config.clone())
                .expect("TLS server config should create connections"),
        }
    }
}

#[derive(Debug)]
struct TransparentTcpNat {
    host_ip: [u8; 4],
    flows: HashMap<TcpFlow, [u8; 4]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct TcpFlow {
    guest_ip: [u8; 4],
    guest_port: u16,
    host_port: u16,
}

impl TransparentTcpNat {
    fn new(host_ip: Ipv4Address) -> Self {
        Self {
            host_ip: host_ip.octets(),
            flows: HashMap::new(),
        }
    }

    fn rewrite_guest_frame(&mut self, frame: &mut [u8]) {
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
        self.flows.insert(flow, packet.destination_ip(frame));
        packet.set_destination_ip(frame, self.host_ip);
        packet.recompute_checksums(frame);
    }

    fn rewrite_host_frame(&mut self, frame: &mut [u8]) {
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
        let Some(original_destination) = self.flows.get(&flow).copied() else {
            return;
        };
        packet.set_source_ip(frame, original_destination);
        packet.recompute_checksums(frame);
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
        self.flows.get(&flow).map(|address| {
            Ipv4Address::new(address[0], address[1], address[2], address[3]).to_string()
        })
    }

    fn host_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.flows.keys().map(|flow| flow.host_port)
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

fn read_ethernet_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0; 4];
    reader.read_exact(&mut len)?;
    let frame_len = u32::from_be_bytes(len) as usize;
    let mut frame = vec![0; frame_len];
    reader.read_exact(&mut frame)?;
    Ok(frame)
}

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
}
