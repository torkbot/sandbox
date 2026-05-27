use std::ffi::CString;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Condvar, Mutex, Once};
use std::thread::{self, JoinHandle};

use base64::Engine;

use crate::MicroVmSpec;
use crate::config::{KernelFormat, RootfsFormat};
use crate::control::INIT_CONTROL_PORT;
use crate::http_flow::HttpInterceptRuntime;
use crate::network::OutboundRulePlan;
use crate::network_service::{HostNetwork, MitmTlsConfig};
use crate::vfs::VirtioVirtualFsBackend;

#[derive(Debug)]
pub struct KrunContext {
    id: u32,
    _networks: Vec<HostNetwork>,
}

#[derive(Default, Clone)]
pub struct HostServices {
    pub http: Option<Arc<dyn HttpInterceptRuntime>>,
}

#[derive(Debug)]
pub struct KrunVm {
    context: Option<KrunContext>,
    control_socket: ControlSocket,
    guest_control_socket: UnixStream,
    worker: Option<JoinHandle<Result<(), KrunError>>>,
    start_status: StartStatusObserver,
}

#[derive(Debug, Clone)]
pub struct StartStatusObserver {
    inner: Arc<(Mutex<Option<Result<(), KrunError>>>, Condvar)>,
}

#[derive(Debug)]
pub struct ControlSocket {
    stream: UnixStream,
    read_buffer: Vec<u8>,
}

const MAX_CONTROL_FRAME_LEN: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrunError {
    operation: &'static str,
    code: i32,
}

impl KrunContext {
    pub fn create(spec: &MicroVmSpec) -> Result<Self, KrunError> {
        Self::create_with_virtual_fs(spec, &[])
    }

    pub fn create_with_virtual_fs(
        spec: &MicroVmSpec,
        virtual_fs: &[VirtualFsDevice],
    ) -> Result<Self, KrunError> {
        Self::create_with_services(spec, virtual_fs, HostServices::default())
    }

    pub fn create_with_services(
        spec: &MicroVmSpec,
        virtual_fs: &[VirtualFsDevice],
        services: HostServices,
    ) -> Result<Self, KrunError> {
        init_krun_logging();
        let raw_id = krun::krun_create_ctx();
        if raw_id < 0 {
            return Err(KrunError {
                operation: "krun_create_ctx",
                code: raw_id,
            });
        }

        let mut context = Self {
            id: raw_id as u32,
            _networks: Vec::new(),
        };
        context.apply_vm_config(spec)?;
        context.apply_console_output()?;
        context.apply_kernel(spec)?;
        context.apply_rootfs(spec)?;
        context.apply_network(spec, &services)?;
        for device in virtual_fs {
            context.add_virtual_fs(device)?;
        }
        context.apply_init(spec, virtual_fs)?;
        Ok(context)
    }

    fn add_virtual_fs(&self, device: &VirtualFsDevice) -> Result<(), KrunError> {
        check_krun(
            "krun_add_virtual_virtiofs",
            krun::krun_add_virtual_virtiofs(
                self.id,
                device.tag.clone(),
                device.backend.clone(),
                Some(1 << 29),
            ),
        )
    }

    fn apply_network(
        &mut self,
        spec: &MicroVmSpec,
        _services: &HostServices,
    ) -> Result<(), KrunError> {
        let Some(network) = &spec.network else {
            return Ok(());
        };

        let tls_config = network.http.as_ref().and_then(|http| {
            Some(MitmTlsConfig {
                ca_certificate_pem: http.ca_certificate_pem.clone()?,
                ca_private_key_pem: http.ca_private_key_pem.clone()?,
            })
        });
        let outbound_rules = network
            .outbound
            .as_ref()
            .map(|outbound| {
                outbound
                    .rules
                    .iter()
                    .map(OutboundRulePlan::parse)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| KrunError::new("NetworkPlan::from_spec", -libc::EINVAL))
            })
            .transpose()?;
        let network = HostNetwork::new(tls_config, outbound_rules, _services.http.clone())
            .map_err(|_| KrunError::new("HostNetwork::new", -libc::EIO))?;
        let guest_fd = network.guest_fd();
        let mac = [0x5a, 0x94, 0xef, 0xe4, 0x0c, 0xef];
        let features = 0;
        let flags = 0;
        check_krun("krun_add_net_unixstream", unsafe {
            krun::krun_add_net_unixstream(
                self.id,
                std::ptr::null(),
                guest_fd,
                mac.as_ptr(),
                features,
                flags,
            )
        })?;
        self._networks.push(network);
        Ok(())
    }

    pub fn add_control_socket_fd(&self, fd: RawFd) -> Result<(), KrunError> {
        check_krun(
            "krun_disable_implicit_vsock",
            krun::krun_disable_implicit_vsock(self.id),
        )?;
        check_krun("krun_add_vsock", krun::krun_add_vsock(self.id, 0))?;
        check_krun(
            "krun_add_vsock_port_fd",
            krun::krun_add_vsock_port_fd(self.id, INIT_CONTROL_PORT, fd),
        )
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    fn apply_vm_config(&self, spec: &MicroVmSpec) -> Result<(), KrunError> {
        check_krun(
            "krun_set_vm_config",
            krun::krun_set_vm_config(self.id, spec.vcpus, spec.memory_mib),
        )
    }

    fn apply_console_output(&self) -> Result<(), KrunError> {
        let Some(path) = std::env::var_os("SANDBOX_CONSOLE_OUTPUT") else {
            return check_krun(
                "krun_disable_implicit_console",
                krun::krun_disable_implicit_console(self.id),
            );
        };
        let path = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| KrunError::new("SANDBOX_CONSOLE_OUTPUT", -libc::EINVAL))?;
        check_krun("krun_set_console_output", unsafe {
            krun::krun_set_console_output(self.id, path.as_ptr())
        })
    }

    fn apply_kernel(&self, spec: &MicroVmSpec) -> Result<(), KrunError> {
        match spec.kernel.format {
            KernelFormat::Auto | KernelFormat::Raw => apply_project_kernel(self.id),
            KernelFormat::Elf
            | KernelFormat::PeGz
            | KernelFormat::ImageGz
            | KernelFormat::ImageZstd => Err(KrunError::new(
                "unsupported project kernel format",
                -libc::EINVAL,
            )),
        }
    }

    fn apply_rootfs(&self, spec: &MicroVmSpec) -> Result<(), KrunError> {
        match spec.rootfs.format {
            RootfsFormat::Directory => {
                let path = cstring_path("krun_set_root", &spec.rootfs.path)?;
                check_krun("krun_set_root", unsafe {
                    krun::krun_set_root(self.id, path.as_ptr())
                })?;
                check_krun(
                    "krun_set_direct_init",
                    krun::krun_set_direct_init(self.id, "/sandbox-init".to_string()),
                )
            }
            RootfsFormat::Erofs => {
                let block_id = CString::new("root").unwrap();
                let path = cstring_path("krun_add_disk3", &spec.rootfs.path)?;
                check_krun("krun_add_disk3", unsafe {
                    krun::krun_add_disk3(
                        self.id,
                        block_id.as_ptr(),
                        path.as_ptr(),
                        0,
                        spec.rootfs.readonly,
                        false,
                        sync_mode(),
                    )
                })?;

                check_krun(
                    "krun_set_direct_block_root",
                    krun::krun_set_direct_block_root(
                        self.id,
                        "/dev/vda".to_string(),
                        "erofs".to_string(),
                        if spec.rootfs.readonly { "ro" } else { "rw" }.to_string(),
                        "/sandbox-init".to_string(),
                    ),
                )
            }
        }
    }

    fn apply_init(
        &self,
        spec: &MicroVmSpec,
        virtual_fs: &[VirtualFsDevice],
    ) -> Result<(), KrunError> {
        // Keep exec metadata populated so libkrun serializes argv/env into
        // krun_env while the kernel command line boots /sandbox-init directly.
        let exec_path = CString::new("/sandbox-init").unwrap();
        let encoded_mounts = encode_virtual_fs_mounts(virtual_fs);
        let mount_arg = CString::new(format!("--virtiofs-mounts={encoded_mounts}")).unwrap();
        let http_network_arg = CString::new("--http-network").unwrap();
        let network_enabled = spec.network.is_some();
        let mount_env = CString::new(format!("SANDBOX_VIRTIOFS_MOUNTS={encoded_mounts}")).unwrap();
        let http_network_env = CString::new("SANDBOX_HTTP_NETWORK=1").unwrap();
        let ca_env = spec
            .network
            .as_ref()
            .and_then(|network| network.http.as_ref())
            .and_then(|http| http.ca_certificate_pem.as_ref())
            .map(|certificate| {
                CString::new(format!(
                    "SANDBOX_HTTP_CA_PEM_B64={}",
                    base64::engine::general_purpose::STANDARD.encode(certificate)
                ))
            })
            .transpose()
            .map_err(|_| KrunError::new("krun_set_exec", -libc::EINVAL))?;
        let mut argv = vec![exec_path.as_ptr(), mount_arg.as_ptr()];
        let mut envp = vec![mount_env.as_ptr()];
        if network_enabled {
            argv.push(http_network_arg.as_ptr());
            envp.push(http_network_env.as_ptr());
        }
        if let Some(ca_env) = ca_env.as_ref() {
            envp.push(ca_env.as_ptr());
        }
        argv.push(std::ptr::null());
        envp.push(std::ptr::null());
        check_krun("krun_set_exec", unsafe {
            krun::krun_set_exec(self.id, exec_path.as_ptr(), argv.as_ptr(), envp.as_ptr())
        })
    }
}

pub struct VirtualFsDevice {
    pub tag: String,
    pub path: String,
    pub readonly: bool,
    pub backend: Arc<dyn VirtioVirtualFsBackend>,
}

fn encode_virtual_fs_mounts(virtual_fs: &[VirtualFsDevice]) -> String {
    let mut value = String::new();
    for device in virtual_fs {
        if !value.is_empty() {
            value.push(';');
        }
        value.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&device.tag));
        value.push(':');
        value.push_str(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&device.path));
        value.push(':');
        value.push_str(if device.readonly { "ro" } else { "rw" });
    }
    value
}

fn init_krun_logging() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        if std::env::var_os("SANDBOX_KRUN_LOG").is_some() {
            let _ = krun::krun_set_log_level(4);
        }
    });
}

#[cfg(sandbox_static_kernel)]
fn apply_project_kernel(ctx_id: u32) -> Result<(), KrunError> {
    let mut guest_addr: usize = 0;
    let mut entry_addr: usize = 0;
    let mut size: usize = 0;
    let host_addr = unsafe {
        krunfw_get_kernel(
            &mut guest_addr as *mut usize,
            &mut entry_addr as *mut usize,
            &mut size as *mut usize,
        )
    };

    check_krun("krun_set_kernel_bundle_raw", unsafe {
        krun::krun_set_kernel_bundle_raw(
            ctx_id,
            host_addr as u64,
            guest_addr as u64,
            entry_addr as u64,
            size,
        )
    })
}

#[cfg(not(sandbox_static_kernel))]
fn apply_project_kernel(_ctx_id: u32) -> Result<(), KrunError> {
    Ok(())
}

#[cfg(sandbox_static_kernel)]
unsafe extern "C" {
    fn krunfw_get_kernel(
        load_addr: *mut usize,
        entry_addr: *mut usize,
        size: *mut usize,
    ) -> *mut u8;
}

impl KrunVm {
    pub fn create(spec: &MicroVmSpec) -> Result<Self, KrunError> {
        Self::create_with_virtual_fs(spec, Vec::new())
    }

    pub fn create_with_virtual_fs(
        spec: &MicroVmSpec,
        virtual_fs: Vec<VirtualFsDevice>,
    ) -> Result<Self, KrunError> {
        Self::create_with_services(spec, virtual_fs, HostServices::default())
    }

    pub fn create_with_services(
        spec: &MicroVmSpec,
        virtual_fs: Vec<VirtualFsDevice>,
        services: HostServices,
    ) -> Result<Self, KrunError> {
        let context = KrunContext::create_with_services(spec, &virtual_fs, services)?;
        let (host_socket, guest_socket) =
            UnixStream::pair().map_err(|_| KrunError::new("UnixStream::pair", -libc::EIO))?;

        context.add_control_socket_fd(guest_socket.as_raw_fd())?;
        Ok(Self {
            context: Some(context),
            control_socket: ControlSocket {
                stream: host_socket,
                read_buffer: Vec::new(),
            },
            guest_control_socket: guest_socket,
            worker: None,
            start_status: StartStatusObserver::new(),
        })
    }

    pub fn start(&mut self) -> Result<(), KrunError> {
        if self.worker.is_some() {
            return Ok(());
        }

        let context = self
            .context
            .take()
            .ok_or_else(|| KrunError::new("krun_start_enter", -libc::EINVAL))?;
        let start_status = self.start_status.clone();
        self.worker = Some(thread::spawn(move || {
            let result = check_krun("krun_start_enter", krun::krun_start_enter(context.id()));
            start_status.set(result.clone());
            result
        }));
        Ok(())
    }

    pub fn start_status(&self) -> Option<Result<(), KrunError>> {
        self.start_status.get()
    }

    pub fn start_status_observer(&self) -> StartStatusObserver {
        self.start_status.clone()
    }

    pub fn context(&self) -> &KrunContext {
        self.context
            .as_ref()
            .expect("KrunContext is not available after VM start")
    }

    pub fn control_socket(&self) -> &ControlSocket {
        &self.control_socket
    }

    pub fn control_socket_mut(&mut self) -> &mut ControlSocket {
        &mut self.control_socket
    }

    pub fn guest_control_socket_raw_fd(&self) -> RawFd {
        self.guest_control_socket.as_raw_fd()
    }
}

impl StartStatusObserver {
    fn new() -> Self {
        Self {
            inner: Arc::new((Mutex::new(None), Condvar::new())),
        }
    }

    fn set(&self, result: Result<(), KrunError>) {
        let (lock, condvar) = &*self.inner;
        *lock.lock().expect("start status lock poisoned") = Some(result);
        condvar.notify_all();
    }

    pub fn get(&self) -> Option<Result<(), KrunError>> {
        let (lock, _) = &*self.inner;
        lock.lock().expect("start status lock poisoned").clone()
    }

    pub fn wait(&self) -> Result<(), KrunError> {
        let (lock, condvar) = &*self.inner;
        let mut status = lock.lock().expect("start status lock poisoned");
        loop {
            if let Some(result) = status.clone() {
                return result;
            }
            status = condvar.wait(status).expect("start status lock poisoned");
        }
    }
}

impl ControlSocket {
    pub fn raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            stream: self.stream.try_clone()?,
            read_buffer: Vec::new(),
        })
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.stream.set_nonblocking(false)?;
        self.stream.write_all(packet)
    }

    pub fn read_packet(&mut self) -> io::Result<Vec<u8>> {
        self.stream.set_nonblocking(false)?;
        let mut len = [0; 4];
        self.stream.read_exact(&mut len)?;
        let frame_len = u32::from_le_bytes(len) as usize;
        let packet_len = control_packet_len(frame_len)?;
        let mut packet = Vec::with_capacity(packet_len);
        packet.extend_from_slice(&len);
        packet.resize(packet_len, 0);
        self.stream.read_exact(&mut packet[4..])?;
        Ok(packet)
    }

    pub fn try_read_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.stream.set_nonblocking(true)?;
        let mut saw_eof = false;
        loop {
            let mut chunk = [0; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    saw_eof = true;
                    break;
                }
                Ok(read) => self.read_buffer.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error),
            }
        }

        if self.read_buffer.len() < 4 {
            if saw_eof {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "guest control socket closed",
                ));
            }
            return Ok(None);
        }
        let len = [
            self.read_buffer[0],
            self.read_buffer[1],
            self.read_buffer[2],
            self.read_buffer[3],
        ];
        let frame_len = u32::from_le_bytes(len) as usize;
        let packet_len = control_packet_len(frame_len)?;
        if self.read_buffer.len() < packet_len {
            if saw_eof {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "guest control socket closed mid-packet",
                ));
            }
            return Ok(None);
        }
        let packet = self.read_buffer.drain(..packet_len).collect();
        Ok(Some(packet))
    }
}

fn control_packet_len(frame_len: usize) -> io::Result<usize> {
    if frame_len > MAX_CONTROL_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "guest control frame length {frame_len} exceeds maximum {MAX_CONTROL_FRAME_LEN}"
            ),
        ));
    }
    frame_len.checked_add(4).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "guest control frame length overflows packet size",
        )
    })
}

impl Drop for KrunContext {
    fn drop(&mut self) {
        let _ = krun::krun_free_ctx(self.id);
    }
}

impl fmt::Display for KrunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed with {}", self.operation, self.code)
    }
}

impl std::error::Error for KrunError {}

fn check_krun(operation: &'static str, code: i32) -> Result<(), KrunError> {
    if code == 0 {
        Ok(())
    } else {
        Err(KrunError { operation, code })
    }
}

impl KrunError {
    fn new(operation: &'static str, code: i32) -> Self {
        Self { operation, code }
    }
}

fn cstring_path(operation: &'static str, path: &Path) -> Result<CString, KrunError> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| KrunError {
        operation,
        code: -libc::EINVAL,
    })
}

fn sync_mode() -> u32 {
    if cfg!(target_os = "macos") { 1 } else { 2 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MicroVmSpecInput;

    #[test]
    fn creates_configures_and_frees_krun_context() {
        if std::env::var_os("SANDBOX_RUN_LIBKRUN_UNIT_TESTS").is_none() {
            return;
        }

        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("runtime-test".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            mounts: Vec::new(),
            network_outbound: None,
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let _ = context.id();
    }

    #[test]
    fn rejects_directory_rootfs() {
        let err = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("directory-root".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "/tmp/sandbox-root".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "directory".to_string(),
            mounts: Vec::new(),
            network_outbound: None,
            network_http: None,
        })
        .unwrap_err();

        assert_eq!(
            err.to_string(),
            "directory rootfs is not supported for sandboxed VM launch; use an EROFS rootfs"
        );
    }

    #[test]
    fn configures_control_port_by_connected_fd() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("control-fd".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            mounts: Vec::new(),
            network_outbound: None,
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let mut fds = [0; 2];
        let socketpair_result =
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(socketpair_result, 0);

        context.add_control_socket_fd(fds[0]).unwrap();

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn vm_creation_owns_host_control_socket() {
        if std::env::var_os("SANDBOX_RUN_LIBKRUN_UNIT_TESTS").is_none() {
            return;
        }

        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("control-socket".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            mounts: Vec::new(),
            network_outbound: None,
            network_http: None,
        })
        .unwrap();

        let vm = KrunVm::create(&spec).unwrap();
        let _ = vm.context().id();
        assert!(vm.control_socket().raw_fd() >= 0);
        assert!(vm.guest_control_socket_raw_fd() >= 0);
    }

    #[test]
    fn control_socket_reads_framed_packets_without_blocking() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };

        assert!(control_socket.try_read_packet().unwrap().is_none());

        let packet = crate::control::ControlFrame::InitReady {
            root_readonly: true,
            init_name: "sandbox-init".to_string(),
        }
        .encode_packet()
        .unwrap();
        guest_socket.write_all(&packet).unwrap();

        assert_eq!(control_socket.try_read_packet().unwrap(), Some(packet));
    }

    #[test]
    fn control_socket_preserves_partial_nonblocking_packets() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };
        let packet = crate::control::ControlFrame::InitReady {
            root_readonly: true,
            init_name: "sandbox-init".to_string(),
        }
        .encode_packet()
        .unwrap();

        guest_socket.write_all(&packet[..2]).unwrap();
        assert!(control_socket.try_read_packet().unwrap().is_none());
        guest_socket.write_all(&packet[2..]).unwrap();

        assert_eq!(control_socket.try_read_packet().unwrap(), Some(packet));
    }

    #[test]
    fn control_socket_reports_closed_peer() {
        let (host_socket, guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };
        drop(guest_socket);

        let error = control_socket.try_read_packet().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("control socket closed"));
    }

    #[test]
    fn control_socket_reports_mid_packet_close() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };
        let packet = crate::control::ControlFrame::InitReady {
            root_readonly: true,
            init_name: "sandbox-init".to_string(),
        }
        .encode_packet()
        .unwrap();

        guest_socket.write_all(&packet[..2]).unwrap();
        drop(guest_socket);

        let error = control_socket.try_read_packet().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert!(error.to_string().contains("control socket closed"));
    }

    #[test]
    fn control_socket_rejects_oversized_nonblocking_packet() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };

        let oversized_len = ((MAX_CONTROL_FRAME_LEN + 1) as u32).to_le_bytes();
        guest_socket.write_all(&oversized_len).unwrap();

        let error = control_socket.try_read_packet().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn control_socket_rejects_oversized_blocking_packet() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };

        let oversized_len = ((MAX_CONTROL_FRAME_LEN + 1) as u32).to_le_bytes();
        guest_socket.write_all(&oversized_len).unwrap();

        let error = control_socket.read_packet().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("exceeds maximum"));
    }

    #[test]
    fn control_socket_writes_after_nonblocking_poll() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
            read_buffer: Vec::new(),
        };
        let packet = crate::control::ControlFrame::GuestExec {
            id: "write-after-poll".to_string(),
            argv: vec!["true".to_string()],
            env: Vec::new(),
        }
        .encode_packet()
        .unwrap();

        assert!(control_socket.try_read_packet().unwrap().is_none());
        control_socket.write_packet(&packet).unwrap();

        let mut received = vec![0; packet.len()];
        guest_socket.read_exact(&mut received).unwrap();
        assert_eq!(received, packet);
    }

    #[test]
    fn virtual_fs_mount_encoding_preserves_delimiters() {
        struct EmptyFs;
        impl crate::vfs::HostVirtualFileSystem for EmptyFs {
            fn lookup(
                &self,
                _parent: crate::vfs::VirtualInode,
                _name: &std::ffi::CStr,
            ) -> io::Result<crate::vfs::VirtioFsEntry> {
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            }

            fn getattr(
                &self,
                _inode: crate::vfs::VirtualInode,
            ) -> io::Result<(crate::vfs::bindings::stat64, std::time::Duration)> {
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            }

            fn readdir(
                &self,
                _inode: crate::vfs::VirtualInode,
            ) -> io::Result<Vec<crate::vfs::VirtioFsDirEntry>> {
                Ok(Vec::new())
            }

            fn read(
                &self,
                _inode: crate::vfs::VirtualInode,
                _offset: u64,
                _size: u32,
            ) -> io::Result<Vec<u8>> {
                Err(io::Error::from_raw_os_error(libc::ENOENT))
            }
        }
        let backend = Arc::new(crate::vfs::VirtualFsAdapter::new(Arc::new(EmptyFs)));
        let encoded = encode_virtual_fs_mounts(&[VirtualFsDevice {
            tag: "virtio=fs;tag".to_string(),
            path: "/mnt/with=equals;semicolon".to_string(),
            readonly: false,
            backend,
        }]);

        assert_eq!(
            encoded,
            "dmlydGlvPWZzO3RhZw:L21udC93aXRoPWVxdWFscztzZW1pY29sb24:rw"
        );
    }

    #[test]
    fn rejects_rootfs_paths_with_nul_bytes() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("bad-root".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "bad\0root".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            mounts: Vec::new(),
            network_outbound: None,
            network_http: None,
        })
        .unwrap();

        let err = KrunContext::create(&spec).unwrap_err();
        assert_eq!(err.to_string(), "krun_add_disk3 failed with -22");
    }
}
