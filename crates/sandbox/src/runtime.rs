use std::ffi::CString;
use std::fmt;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::control::INIT_CONTROL_PORT;
use crate::config::RootfsFormat;
use crate::MicroVmSpec;

#[derive(Debug)]
pub struct KrunContext {
    id: u32,
}

#[derive(Debug)]
pub struct KrunVm {
    context: KrunContext,
    control_socket: ControlSocket,
    guest_control_socket: UnixStream,
}

#[derive(Debug)]
pub struct ControlSocket {
    stream: UnixStream,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrunError {
    operation: &'static str,
    code: i32,
}

impl KrunContext {
    pub fn create(spec: &MicroVmSpec) -> Result<Self, KrunError> {
        let raw_id = krun::krun_create_ctx();
        if raw_id < 0 {
            return Err(KrunError {
                operation: "krun_create_ctx",
                code: raw_id,
            });
        }

        let context = Self { id: raw_id as u32 };
        context.apply_vm_config(spec)?;
        context.apply_rootfs(spec)?;
        Ok(context)
    }

    pub fn add_control_socket_fd(&self, fd: RawFd) -> Result<(), KrunError> {
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

    fn apply_rootfs(&self, spec: &MicroVmSpec) -> Result<(), KrunError> {
        match spec.rootfs.format {
            RootfsFormat::Directory => {
                let path = cstring_path("krun_set_root", &spec.rootfs.path)?;
                check_krun("krun_set_root", unsafe {
                    krun::krun_set_root(self.id, path.as_ptr())
                })
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

                let device = CString::new("/dev/vda").unwrap();
                let fstype = CString::new("erofs").unwrap();
                let options = CString::new(if spec.rootfs.readonly { "ro" } else { "rw" }).unwrap();
                check_krun("krun_set_root_disk_remount", unsafe {
                    krun::krun_set_root_disk_remount(
                        self.id,
                        device.as_ptr(),
                        fstype.as_ptr(),
                        options.as_ptr(),
                    )
                })
            }
        }
    }
}

impl KrunVm {
    pub fn create(spec: &MicroVmSpec) -> Result<Self, KrunError> {
        let context = KrunContext::create(spec)?;
        let (host_socket, guest_socket) =
            UnixStream::pair().map_err(|_| KrunError::new("UnixStream::pair", -libc::EIO))?;

        context.add_control_socket_fd(guest_socket.as_raw_fd())?;
        Ok(Self {
            context,
            control_socket: ControlSocket {
                stream: host_socket,
            },
            guest_control_socket: guest_socket,
        })
    }

    pub fn context(&self) -> &KrunContext {
        &self.context
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

impl ControlSocket {
    pub fn raw_fd(&self) -> RawFd {
        self.stream.as_raw_fd()
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        self.stream.write_all(packet)
    }

    pub fn try_read_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.stream.set_nonblocking(true)?;
        let mut len = [0; 4];
        match self.stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        }

        let frame_len = u32::from_le_bytes(len) as usize;
        let mut packet = Vec::with_capacity(4 + frame_len);
        packet.extend_from_slice(&len);
        packet.resize(4 + frame_len, 0);
        self.stream.read_exact(&mut packet[4..])?;
        Ok(Some(packet))
    }
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
    if cfg!(target_os = "macos") {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MicroVmSpecInput;

    #[test]
    fn creates_configures_and_frees_krun_context() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("runtime-test".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let _ = context.id();
    }

    #[test]
    fn configures_directory_rootfs() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("directory-root".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "/tmp/sandbox-root".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "directory".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let _ = context.id();
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
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let mut fds = [0; 2];
        let socketpair_result = unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_STREAM,
                0,
                fds.as_mut_ptr(),
            )
        };
        assert_eq!(socketpair_result, 0);

        context.add_control_socket_fd(fds[0]).unwrap();

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }

    #[test]
    fn vm_creation_owns_host_control_socket() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("control-socket".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let vm = KrunVm::create(&spec).unwrap();
        assert!(vm.context().id() > 0);
        assert!(vm.control_socket().raw_fd() >= 0);
        assert!(vm.guest_control_socket_raw_fd() >= 0);
    }

    #[test]
    fn control_socket_reads_framed_packets_without_blocking() {
        let (host_socket, mut guest_socket) = UnixStream::pair().unwrap();
        let mut control_socket = ControlSocket {
            stream: host_socket,
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
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let err = KrunContext::create(&spec).unwrap_err();
        assert_eq!(err.to_string(), "krun_add_disk3 failed with -22");
    }
}
