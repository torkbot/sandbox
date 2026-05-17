use std::io::{self, Read, Write};
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, IpCidr, Ipv4Address};

const HOST_HTTP_PROBE_PORT: u16 = 8080;
const HOST_HTTP_PROBE_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\ncontent-length: 25\r\nconnection: close\r\n\r\nsandbox explicit network\n";

/// Host-owned endpoint for libkrun's explicit virtio-net unixstream backend.
#[derive(Debug)]
pub struct HostNetwork {
    guest_fd: RawFd,
    shutdown: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HostNetwork {
    pub fn new() -> io::Result<Self> {
        let (host, guest) = UnixStream::pair()?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let worker = thread::spawn(move || run_network_service(host, worker_shutdown));
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

fn run_network_service(stream: UnixStream, shutdown: Arc<AtomicBool>) {
    let _ = stream.set_nonblocking(true);
    let tx = match stream.try_clone() {
        Ok(tx) => tx,
        Err(_) => return,
    };
    let mut device = LibkrunNetDevice::new(stream, tx);
    let mut iface = Interface::new(
        Config::new(EthernetAddress([0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xf0]).into()),
        &mut device,
        Instant::now(),
    );
    iface.update_ip_addrs(|addresses| {
        let _ = addresses.push(IpCidr::new(Ipv4Address::new(10, 0, 2, 1).into(), 24));
    });
    let mut sockets = SocketSet::new(Vec::new());
    let http_probe = sockets.add(tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 4096]),
        tcp::SocketBuffer::new(vec![0; 4096]),
    ));

    while !shutdown.load(Ordering::Acquire) {
        let timestamp = Instant::now();
        let _ = iface.poll(timestamp, &mut device, &mut sockets);
        poll_http_probe(&mut sockets, http_probe);
        thread::sleep(Duration::from_millis(1));
    }
}

fn poll_http_probe(sockets: &mut SocketSet<'_>, handle: smoltcp::iface::SocketHandle) {
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if !socket.is_active() {
        let _ = socket.listen(HOST_HTTP_PROBE_PORT);
        return;
    }

    if socket.can_recv() {
        let mut request = [0; 4096];
        let received = socket.recv_slice(&mut request).unwrap_or(0);
        if received > 0 {
            let _ = socket.send_slice(HOST_HTTP_PROBE_RESPONSE);
            socket.close();
        }
    }
}

struct LibkrunNetDevice {
    rx: UnixStream,
    tx: UnixStream,
}

impl LibkrunNetDevice {
    fn new(rx: UnixStream, tx: UnixStream) -> Self {
        Self { rx, tx }
    }
}

impl Device for LibkrunNetDevice {
    type RxToken<'a> = LibkrunRxToken;
    type TxToken<'a> = LibkrunTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match read_ethernet_frame(&mut self.rx) {
            Ok(frame) => Some((
                LibkrunRxToken { frame },
                LibkrunTxToken {
                    stream: &mut self.tx,
                },
            )),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => None,
            Err(_) => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(LibkrunTxToken {
            stream: &mut self.tx,
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
}

impl phy::TxToken for LibkrunTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0; len];
        let result = f(&mut frame);
        let _ = write_ethernet_frame(self.stream, &frame);
        result
    }
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
