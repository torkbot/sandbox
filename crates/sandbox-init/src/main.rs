use base64::Engine;
#[cfg(target_os = "linux")]
use sandbox_protocol::INIT_CONTROL_PORT;
use sandbox_protocol::{
    ControlFrame, GuestFsDirectoryEntry, GuestFsEntryType, GuestFsError, GuestFsReadRange,
    GuestFsResponseResult, GuestFsStat, GuestPtySize, GuestSpawnStdio,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const GUEST_FS_RESPONSE_PAYLOAD_LIMIT: u64 = 60 * 1024 * 1024;
const GUEST_FS_MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn main() {
    if let Err(error) = run() {
        report_init_failure(&error);
        eprintln!("sandbox-init failed: {error}");
        std::process::exit(1);
    }
}

fn report_init_failure(error: &InitError) {
    let Ok(mut control) = connect_control() else {
        return;
    };
    let Ok(packet) = (ControlFrame::InitFailed {
        message: error.to_string(),
    })
    .encode_packet() else {
        return;
    };
    let _ = control.write_all(&packet);
}

fn run() -> Result<(), InitError> {
    let stage = configured_stage(std::env::args().skip(1))?;
    match stage {
        InitStage::Stage0 => return run_stage0(),
        InitStage::Stage1 => {}
    }

    mount_kernel_filesystems()?;
    let root_readonly = configured_root_readonly()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let hostname_env = std::env::var("SANDBOX_HOSTNAME").ok();
    let http_network_enabled = http_network_enabled(args.iter().map(String::as_str));
    run_setup_tasks(vec![
        setup_task(move || configure_hostname(args.iter().map(String::as_str), hostname_env)),
        setup_task(configure_loopback),
        setup_task(move || configure_http_network(http_network_enabled)),
        setup_task(|| {
            start_orphan_reaper();
            Ok(())
        }),
    ])?;
    let mounts = virtual_fs_mounts(
        std::env::args().skip(1),
        std::env::var("SANDBOX_VIRTIOFS_MOUNTS").ok(),
    )?;
    let mut mounted_virtual_paths = Vec::new();
    mount_configured_block(
        std::env::args().skip(1),
        std::env::var("SANDBOX_BLOCK_MOUNT").ok(),
        &mut mounted_virtual_paths,
        false,
    )?;
    mount_internal_http_ca(&mounts, &mut mounted_virtual_paths)?;
    mount_virtual_filesystems_before_http_ca(&mounts, &mut mounted_virtual_paths)?;
    install_http_ca(root_readonly)?;
    mount_configured_block(
        std::env::args().skip(1),
        std::env::var("SANDBOX_BLOCK_MOUNT").ok(),
        &mut mounted_virtual_paths,
        true,
    )?;
    mount_virtual_filesystems_after_http_ca(&mounts, &mut mounted_virtual_paths)?;
    let packet = init_ready_packet(root_readonly)?;
    let mut control = connect_control()?;
    send_init_ready(&mut control, &packet)?;
    run_control_loop(&mut control)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitStage {
    Stage0,
    Stage1,
}

fn configured_stage(args: impl Iterator<Item = String>) -> Result<InitStage, InitError> {
    let mut stage = None;
    for arg in args {
        let Some(value) = arg.strip_prefix("--stage=") else {
            continue;
        };
        if stage.is_some() {
            return Err(InitError("duplicate --stage argument".to_string()));
        }
        stage = Some(match value {
            "0" => InitStage::Stage0,
            "1" => InitStage::Stage1,
            _ => return Err(InitError(format!("invalid --stage value: {value}"))),
        });
    }
    stage.ok_or_else(|| InitError("--stage is required".to_string()))
}

#[cfg(target_os = "linux")]
fn run_stage0() -> Result<(), InitError> {
    use std::os::unix::process::CommandExt;

    mount_kernel_filesystems()?;
    let root_readonly = configured_root_readonly()?;
    let mount_paths = configured_mount_paths()?;
    mount_real_root(root_readonly, &mount_paths)?;
    move_mount("/proc", "/newroot/proc")?;
    move_mount("/sys", "/newroot/sys")?;
    move_mount("/dev", "/newroot/dev")?;
    mount_fs("tmpfs", "/newroot/dev/shm", "tmpfs", 0)?;
    set_directory_mode("/newroot/dev/shm", 0o1777)?;
    let stage1_path = "/newroot/dev/shm/sandbox-init";
    std::fs::copy("/newroot/proc/self/exe", stage1_path)
        .map_err(|error| InitError(format!("copy stage1 init to {stage1_path}: {error}")))?;
    set_file_mode(stage1_path, 0o755)?;
    move_new_root()?;
    let args = stage1_args();
    let error = std::process::Command::new("/dev/shm/sandbox-init")
        .args(args)
        .exec();
    Err(InitError(format!("exec stage1 init: {error}")))
}

#[cfg(not(target_os = "linux"))]
fn run_stage0() -> Result<(), InitError> {
    Err(InitError("stage 0 is only supported on Linux".to_string()))
}

#[cfg(target_os = "linux")]
fn mount_real_root(readonly: bool, mount_paths: &[String]) -> Result<(), InitError> {
    use std::ffi::CString;

    let target_path = if readonly && !mount_paths.is_empty() {
        "/newroot-lower"
    } else {
        "/newroot"
    };
    std::fs::create_dir_all(target_path)
        .map_err(|error| InitError(format!("create {target_path}: {error}")))?;
    let source = CString::new("/dev/vda").unwrap();
    let target = CString::new(target_path).unwrap();
    let fstype = CString::new("ext4").unwrap();
    let flags = if readonly { libc::MS_RDONLY } else { 0 };
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os("mount root block device"));
    }
    if target_path != "/newroot" {
        prepare_readonly_root_mount_points(mount_paths)?;
    }
    for mount_point in [
        "/newroot/dev",
        "/newroot/proc",
        "/newroot/run",
        "/newroot/sys",
        "/newroot/tmp",
    ] {
        if !std::path::Path::new(mount_point).is_dir() {
            return Err(InitError(format!(
                "rootfs image must contain mount point {mount_point}"
            )));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configured_mount_paths() -> Result<Vec<String>, InitError> {
    let mut paths = virtual_fs_mounts(
        std::env::args().skip(1),
        std::env::var("SANDBOX_VIRTIOFS_MOUNTS").ok(),
    )?
    .into_iter()
    .map(|mount| mount.path)
    .collect::<Vec<_>>();
    if let Some(path) = configured_block_mount(
        std::env::args().skip(1),
        std::env::var("SANDBOX_BLOCK_MOUNT").ok(),
    )? {
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(target_os = "linux")]
fn prepare_readonly_root_mount_points(mount_paths: &[String]) -> Result<(), InitError> {
    mount_fs("tmpfs", "/newroot-overlay", "tmpfs", 0)?;
    std::fs::create_dir_all("/newroot-overlay/upper")
        .map_err(|error| InitError(format!("create read-only root overlay upper: {error}")))?;
    std::fs::create_dir_all("/newroot-overlay/work")
        .map_err(|error| InitError(format!("create read-only root overlay work: {error}")))?;
    std::fs::create_dir_all("/newroot")
        .map_err(|error| InitError(format!("create /newroot: {error}")))?;
    mount_fs_with_data(
        "overlay",
        "/newroot",
        "overlay",
        0,
        "lowerdir=/newroot-lower,upperdir=/newroot-overlay/upper,workdir=/newroot-overlay/work",
    )?;
    for path in mount_paths {
        let target = std::path::Path::new("/newroot").join(path.trim_start_matches('/'));
        if !target.exists() {
            std::fs::create_dir_all(&target).map_err(|error| {
                InitError(format!(
                    "create guest mount point {}: {error}",
                    target.display()
                ))
            })?;
        }
    }
    remount_readonly("/newroot")
}

#[cfg(target_os = "linux")]
fn remount_readonly(target: &str) -> Result<(), InitError> {
    let target = std::ffi::CString::new(target)
        .map_err(|_| InitError("remount target contains nul".to_string()))?;
    let result = unsafe {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os("remount synthetic root read-only"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn move_mount(source: &str, target: &str) -> Result<(), InitError> {
    use std::ffi::CString;

    let source_cstr = CString::new(source)
        .map_err(|_| InitError(format!("move mount source contains nul: {source}")))?;
    let target_cstr = CString::new(target)
        .map_err(|_| InitError(format!("move mount target contains nul: {target}")))?;
    let result = unsafe {
        libc::mount(
            source_cstr.as_ptr(),
            target_cstr.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os(&format!(
            "move mount {source} to {target}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn move_new_root() -> Result<(), InitError> {
    use std::ffi::CString;

    std::env::set_current_dir("/newroot")
        .map_err(|error| InitError(format!("chdir /newroot: {error}")))?;
    let source = CString::new(".").unwrap();
    let target = CString::new("/").unwrap();
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_MOVE,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os("move new root"));
    }
    let root = CString::new(".").unwrap();
    if unsafe { libc::chroot(root.as_ptr()) } < 0 {
        return Err(InitError::last_os("chroot new root"));
    }
    std::env::set_current_dir("/")
        .map_err(|error| InitError(format!("chdir / after chroot: {error}")))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn stage1_args() -> Vec<String> {
    std::env::args()
        .skip(1)
        .map(|arg| {
            if arg.starts_with("--stage=") {
                "--stage=1".to_string()
            } else {
                arg
            }
        })
        .collect()
}

type SetupTask = Box<dyn FnOnce() -> Result<(), InitError> + Send>;

fn setup_task(task: impl FnOnce() -> Result<(), InitError> + Send + 'static) -> SetupTask {
    Box::new(task)
}

fn run_setup_tasks(tasks: Vec<SetupTask>) -> Result<(), InitError> {
    let handles = tasks
        .into_iter()
        .map(std::thread::spawn)
        .collect::<Vec<_>>();
    for handle in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(InitError("init setup task panicked".to_string())),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
static ACTIVE_CHILDREN: OnceLock<Mutex<HashSet<libc::pid_t>>> = OnceLock::new();

#[cfg(target_os = "linux")]
fn active_children() -> &'static Mutex<HashSet<libc::pid_t>> {
    ACTIVE_CHILDREN.get_or_init(|| Mutex::new(HashSet::new()))
}

#[cfg(target_os = "linux")]
fn start_orphan_reaper() {
    let _ = active_children();
    std::thread::spawn(|| {
        loop {
            reap_orphaned_children();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
}

#[cfg(not(target_os = "linux"))]
fn start_orphan_reaper() {}

#[cfg(target_os = "linux")]
fn spawn_active_child(
    command: &mut std::process::Command,
) -> std::io::Result<(std::process::Child, u32)> {
    let mut children = active_children()
        .lock()
        .map_err(|_| std::io::Error::other("active child registry lock poisoned"))?;
    let child = command.spawn()?;
    let child_id = child.id();
    children.insert(child_id as libc::pid_t);
    Ok((child, child_id))
}

#[cfg(not(target_os = "linux"))]
fn spawn_active_child(
    command: &mut std::process::Command,
) -> std::io::Result<(std::process::Child, u32)> {
    let child = command.spawn()?;
    let child_id = child.id();
    Ok((child, child_id))
}

#[cfg(target_os = "linux")]
fn unregister_active_child(pid: u32) {
    if let Ok(mut children) = active_children().lock() {
        children.remove(&(pid as libc::pid_t));
    }
}

#[cfg(not(target_os = "linux"))]
fn unregister_active_child(_pid: u32) {}

#[cfg(target_os = "linux")]
fn reap_orphaned_children() {
    loop {
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        let result = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            return;
        }
        let info = unsafe { info.assume_init() };
        let pid = unsafe { info.si_pid() };
        if pid <= 0 {
            return;
        }
        if active_children()
            .lock()
            .is_ok_and(|children| children.contains(&pid))
        {
            return;
        }
        unsafe {
            libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG);
        }
    }
}

#[cfg(target_os = "linux")]
fn configure_hostname<'a>(
    args: impl Iterator<Item = &'a str>,
    env_hostname: Option<String>,
) -> Result<(), InitError> {
    use std::ffi::CString;

    let hostname = args
        .filter_map(|arg| arg.strip_prefix("--hostname=").map(str::to_string))
        .next()
        .or(env_hostname)
        .unwrap_or_else(|| "sandbox".to_string());
    let hostname_cstr = CString::new(hostname.as_str())
        .map_err(|_| InitError("hostname contains nul".to_string()))?;
    let result = unsafe { libc::sethostname(hostname_cstr.as_ptr(), hostname.len()) };
    if result < 0 {
        return Err(InitError::last_os("set hostname"));
    }
    std::fs::create_dir_all("/run/sandbox")
        .map_err(|error| InitError(format!("create /run/sandbox: {error}")))?;
    std::fs::write("/run/sandbox/hostname", format!("{hostname}\n"))
        .map_err(|error| InitError(format!("write /run/sandbox/hostname: {error}")))?;
    configure_hosts(&hostname)?;
    if !std::path::Path::new("/etc/hostname").exists() {
        write_file_creating_parent(
            "/etc/hostname",
            format!("{hostname}\n"),
            "write /etc/hostname",
        )?;
        return Ok(());
    }
    bind_mount_file("/run/sandbox/hostname", "/etc/hostname")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_hosts(hostname: &str) -> Result<(), InitError> {
    let hosts =
        format!("127.0.0.1 localhost {hostname}\n::1 localhost ip6-localhost ip6-loopback\n");
    std::fs::write("/run/sandbox/hosts", hosts.as_bytes())
        .map_err(|error| InitError(format!("write /run/sandbox/hosts: {error}")))?;
    if !std::path::Path::new("/etc/hosts").exists() {
        write_file_creating_parent("/etc/hosts", hosts, "write /etc/hosts")?;
        return Ok(());
    }
    bind_mount_file("/run/sandbox/hosts", "/etc/hosts")
}

#[cfg(not(target_os = "linux"))]
fn configure_hostname<'a>(
    _args: impl Iterator<Item = &'a str>,
    _env_hostname: Option<String>,
) -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_loopback() -> Result<(), InitError> {
    configure_ipv4_address("lo", "127.0.0.1", "255.0.0.0")?;
    set_interface_up("lo")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn bind_mount_file(source: &str, target: &str) -> Result<(), InitError> {
    use std::ffi::CString;

    let source = CString::new(source)
        .map_err(|_| InitError(format!("bind mount source contains nul: {source}")))?;
    let target = CString::new(target)
        .map_err(|_| InitError(format!("bind mount target contains nul: {target}")))?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os("bind mount hostname"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_loopback() -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_http_network(enabled: bool) -> Result<(), InitError> {
    if !enabled {
        return Ok(());
    }

    configure_ipv4_address("eth0", "10.0.2.2", "255.255.255.0")?;
    set_interface_up("eth0")?;
    add_default_ipv4_route("eth0", "10.0.2.1")?;
    install_resolver_config()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_http_network(_enabled: bool) -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn http_network_enabled<'a>(args: impl Iterator<Item = &'a str>) -> bool {
    args.into_iter().any(|arg| arg == "--http-network")
        || read_flag_from_proc_cmdline("SANDBOX_HTTP_NETWORK")
}

#[cfg(not(target_os = "linux"))]
fn http_network_enabled<'a>(_args: impl Iterator<Item = &'a str>) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn configure_ipv4_address(iface: &str, address: &str, netmask: &str) -> Result<(), InitError> {
    let socket = NetworkControlSocket::open()?;
    let address = ipv4_sockaddr(address)?;
    let netmask = ipv4_sockaddr(netmask)?;
    let mut request = ifreq_with_sockaddr(iface, address)?;
    socket.ioctl(
        libc::SIOCSIFADDR as libc::Ioctl,
        &mut request,
        "set interface IPv4 address",
    )?;
    let mut request = ifreq_with_sockaddr(iface, netmask)?;
    socket.ioctl(
        libc::SIOCSIFNETMASK as libc::Ioctl,
        &mut request,
        "set interface IPv4 netmask",
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_interface_up(iface: &str) -> Result<(), InitError> {
    let socket = NetworkControlSocket::open()?;
    let mut request = ifreq_with_flags(iface, 0)?;
    socket.ioctl(
        libc::SIOCGIFFLAGS as libc::Ioctl,
        &mut request,
        "get interface flags",
    )?;
    let flags = unsafe { request.ifr_ifru.ifru_flags };
    let mut request = ifreq_with_flags(iface, flags | libc::IFF_UP as libc::c_short)?;
    socket.ioctl(
        libc::SIOCSIFFLAGS as libc::Ioctl,
        &mut request,
        "set interface up",
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn add_default_ipv4_route(iface: &str, gateway: &str) -> Result<(), InitError> {
    use std::ffi::CString;

    let socket = NetworkControlSocket::open()?;
    let iface =
        CString::new(iface).map_err(|_| InitError("route interface contains nul".to_string()))?;
    let mut route = libc::rtentry {
        rt_pad1: 0,
        rt_dst: ipv4_sockaddr("0.0.0.0")?,
        rt_gateway: ipv4_sockaddr(gateway)?,
        rt_genmask: ipv4_sockaddr("0.0.0.0")?,
        rt_flags: (libc::RTF_UP | libc::RTF_GATEWAY) as libc::c_ushort,
        rt_pad2: 0,
        rt_pad3: 0,
        rt_tos: 0,
        rt_class: 0,
        rt_pad4: [0; 3],
        rt_metric: 0,
        rt_dev: iface.as_ptr().cast_mut(),
        rt_mtu: 0,
        rt_window: 0,
        rt_irtt: 0,
    };
    socket.ioctl_allow_errno(
        libc::SIOCADDRT as libc::Ioctl,
        &mut route,
        "add default route",
        libc::EEXIST,
    )
}

#[cfg(target_os = "linux")]
struct NetworkControlSocket(libc::c_int);

#[cfg(target_os = "linux")]
impl NetworkControlSocket {
    fn open() -> Result<Self, InitError> {
        let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if fd < 0 {
            return Err(InitError::last_os("socket(AF_INET)"));
        }
        Ok(Self(fd))
    }

    fn ioctl<T>(
        &self,
        request: libc::Ioctl,
        value: &mut T,
        operation: &str,
    ) -> Result<(), InitError> {
        self.ioctl_allow_errno(request, value, operation, 0)
    }

    fn ioctl_allow_errno<T>(
        &self,
        request: libc::Ioctl,
        value: &mut T,
        operation: &str,
        allowed_errno: libc::c_int,
    ) -> Result<(), InitError> {
        let result = unsafe { libc::ioctl(self.0, request, value as *mut T) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if allowed_errno != 0 && error.raw_os_error() == Some(allowed_errno) {
                return Ok(());
            }
            return Err(InitError(format!("{operation}: {error}")));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetworkControlSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

#[cfg(target_os = "linux")]
fn ifreq_with_sockaddr(iface: &str, address: libc::sockaddr) -> Result<libc::ifreq, InitError> {
    let mut request = ifreq_with_name(iface)?;
    request.ifr_ifru.ifru_addr = address;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn ifreq_with_flags(iface: &str, flags: libc::c_short) -> Result<libc::ifreq, InitError> {
    let mut request = ifreq_with_name(iface)?;
    request.ifr_ifru.ifru_flags = flags;
    Ok(request)
}

#[cfg(target_os = "linux")]
fn ifreq_with_name(iface: &str) -> Result<libc::ifreq, InitError> {
    let mut request = unsafe { std::mem::zeroed::<libc::ifreq>() };
    let bytes = iface.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
        return Err(InitError(format!(
            "invalid network interface name: {iface}"
        )));
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        request.ifr_name[index] = byte as libc::c_char;
    }
    Ok(request)
}

#[cfg(target_os = "linux")]
fn ipv4_sockaddr(address: &str) -> Result<libc::sockaddr, InitError> {
    let address = address
        .parse::<std::net::Ipv4Addr>()
        .map_err(|error| InitError(format!("invalid IPv4 address {address}: {error}")))?;
    let sockaddr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(address).to_be(),
        },
        sin_zero: [0; 8],
    };
    Ok(unsafe { std::mem::transmute::<libc::sockaddr_in, libc::sockaddr>(sockaddr) })
}

#[cfg(target_os = "linux")]
fn install_resolver_config() -> Result<(), InitError> {
    use std::ffi::CString;
    use std::path::Path;

    const RESOLV_CONF: &str = "nameserver 10.0.2.1\noptions timeout:1 attempts:1\n";

    std::fs::create_dir_all("/run/sandbox")
        .map_err(|error| InitError(format!("create /run/sandbox: {error}")))?;
    std::fs::write("/run/sandbox/resolv.conf", RESOLV_CONF)
        .map_err(|error| InitError(format!("write sandbox resolver config: {error}")))?;
    if !Path::new("/etc/resolv.conf").exists() {
        write_file_creating_parent("/etc/resolv.conf", RESOLV_CONF, "write /etc/resolv.conf")?;
        return Ok(());
    }

    let source = CString::new("/run/sandbox/resolv.conf").unwrap();
    let target = CString::new("/etc/resolv.conf").unwrap();
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os("bind mount sandbox resolver config"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_kernel_filesystems() -> Result<(), InitError> {
    mount_fs("proc", "/proc", "proc", 0)?;
    mount_fs("sysfs", "/sys", "sysfs", 0)?;
    mount_fs("devtmpfs", "/dev", "devtmpfs", 0)?;
    mount_fs("devpts", "/dev/pts", "devpts", 0)?;
    mount_fs("tmpfs", "/dev/shm", "tmpfs", 0)?;
    set_directory_mode("/dev/shm", 0o1777)?;
    create_standard_fd_links()?;
    mount_fs_if_supported("mqueue", "/dev/mqueue", "mqueue", 0)?;
    mount_fs("cgroup2", "/sys/fs/cgroup", "cgroup2", 0)?;
    mount_fs("tmpfs", "/run", "tmpfs", 0)?;
    mount_fs("tmpfs", "/tmp", "tmpfs", 0)?;
    set_directory_mode("/tmp", 0o1777)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_kernel_filesystems() -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn configured_root_readonly() -> Result<bool, InitError> {
    match std::env::var("SANDBOX_ROOTFS_READONLY") {
        Ok(value) if value == "1" || value.eq_ignore_ascii_case("true") => Ok(true),
        Ok(value) if value == "0" || value.eq_ignore_ascii_case("false") => Ok(false),
        Ok(value) => Err(InitError(format!(
            "invalid SANDBOX_ROOTFS_READONLY value: {value}"
        ))),
        Err(std::env::VarError::NotPresent) => root_mount_readonly(),
        Err(error) => Err(InitError(format!("read SANDBOX_ROOTFS_READONLY: {error}"))),
    }
}

#[cfg(target_os = "linux")]
fn root_mount_readonly() -> Result<bool, InitError> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|error| InitError(format!("read /proc/mounts: {error}")))?;
    for line in mounts.lines() {
        let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
        if fields.get(1) == Some(&"/") {
            let options = fields.get(3).copied().unwrap_or_default();
            return Ok(options.split(',').any(|option| option == "ro"));
        }
    }
    Err(InitError(
        "root mount not found in /proc/mounts".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
fn configured_root_readonly() -> Result<bool, InitError> {
    Ok(true)
}

#[cfg(target_os = "linux")]
fn create_standard_fd_links() -> Result<(), InitError> {
    create_symlink("/proc/self/fd", "/dev/fd")?;
    create_symlink("/proc/self/fd/0", "/dev/stdin")?;
    create_symlink("/proc/self/fd/1", "/dev/stdout")?;
    create_symlink("/proc/self/fd/2", "/dev/stderr")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn create_symlink(target: &str, link: &str) -> Result<(), InitError> {
    match std::os::unix::fs::symlink(target, link) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = std::fs::read_link(link)
                .map_err(|error| InitError(format!("read existing symlink {link}: {error}")))?;
            if existing == std::path::Path::new(target) {
                return Ok(());
            }
            Err(InitError(format!(
                "existing symlink {link} points to {}, expected {target}",
                existing.display()
            )))
        }
        Err(error) => Err(InitError(format!("create symlink {link}: {error}"))),
    }
}

#[cfg(target_os = "linux")]
fn mount_fs_if_supported(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> Result<(), InitError> {
    mount_fs_with_allowed_errors(source, target, fstype, flags, &[libc::ENODEV])
}

#[cfg(target_os = "linux")]
fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
) -> Result<(), InitError> {
    mount_fs_with_allowed_errors(source, target, fstype, flags, &[])
}

#[cfg(target_os = "linux")]
fn mount_fs_with_data(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: &str,
) -> Result<(), InitError> {
    use std::ffi::CString;

    std::fs::create_dir_all(target)
        .map_err(|error| InitError(format!("create mount point {target}: {error}")))?;
    let source = CString::new(source)
        .map_err(|_| InitError(format!("mount source contains nul: {source}")))?;
    let target_cstr = CString::new(target)
        .map_err(|_| InitError(format!("mount target contains nul: {target}")))?;
    let fstype = CString::new(fstype)
        .map_err(|_| InitError(format!("mount fstype contains nul: {fstype}")))?;
    let data = CString::new(data).map_err(|_| InitError("mount data contains nul".to_string()))?;
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target_cstr.as_ptr(),
            fstype.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os(&format!("mount {target}")));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_fs_with_allowed_errors(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    allowed_errors: &[i32],
) -> Result<(), InitError> {
    use std::ffi::CString;
    use std::path::Path;

    std::fs::create_dir_all(Path::new(target))
        .map_err(|error| InitError(format!("create mount point {target}: {error}")))?;

    let source = CString::new(source)
        .map_err(|_| InitError(format!("mount source contains nul: {source}")))?;
    let target_cstr = CString::new(target)
        .map_err(|_| InitError(format!("mount target contains nul: {target}")))?;
    let fstype = CString::new(fstype)
        .map_err(|_| InitError(format!("mount fstype contains nul: {fstype}")))?;

    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target_cstr.as_ptr(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if result < 0 {
        let raw_os_error = std::io::Error::last_os_error().raw_os_error();
        if raw_os_error == Some(libc::EBUSY)
            || raw_os_error.is_some_and(|error| allowed_errors.contains(&error))
        {
            return Ok(());
        }
        return Err(InitError::last_os(&format!("mount {target}")));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_directory_mode(path: &str, mode: u32) -> Result<(), InitError> {
    set_permissions_mode(path, mode)
}

#[cfg(target_os = "linux")]
fn set_file_mode(path: &str, mode: u32) -> Result<(), InitError> {
    set_permissions_mode(path, mode)
}

#[cfg(target_os = "linux")]
fn set_permissions_mode(path: &str, mode: u32) -> Result<(), InitError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| InitError(format!("set mode on {path}: {error}")))
}

#[cfg(target_os = "linux")]
fn mount_internal_http_ca(
    mounts: &[VirtualFsMount],
    mounted_virtual_paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), InitError> {
    let Some(mount) = mounts.iter().find(|mount| is_internal_http_ca_mount(mount)) else {
        return Ok(());
    };
    ensure_mount_point(&mount.path)?;
    mount_virtiofs(&mount.tag, &mount.path, mount.readonly)?;
    mounted_virtual_paths.push(std::path::PathBuf::from(&mount.path));
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_virtual_filesystems_before_http_ca(
    mounts: &[VirtualFsMount],
    mounted_virtual_paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), InitError> {
    for mount in mounts {
        if is_internal_http_ca_mount(mount) || hides_internal_http_ca_mount(&mount.path) {
            continue;
        }
        ensure_mount_point(&mount.path)?;
        mount_virtiofs(&mount.tag, &mount.path, mount.readonly)?;
        mounted_virtual_paths.push(std::path::PathBuf::from(&mount.path));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_virtual_filesystems_after_http_ca(
    mounts: &[VirtualFsMount],
    mounted_virtual_paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), InitError> {
    for mount in mounts {
        if is_internal_http_ca_mount(mount) || !hides_internal_http_ca_mount(&mount.path) {
            continue;
        }
        ensure_mount_point(&mount.path)?;
        mount_virtiofs(&mount.tag, &mount.path, mount.readonly)?;
        mounted_virtual_paths.push(std::path::PathBuf::from(&mount.path));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_internal_http_ca_mount(mount: &VirtualFsMount) -> bool {
    mount.tag == "sandbox-http-ca"
        && normalized_mount_path(&mount.path).as_deref() == Some("/run/sandbox/http-ca")
}

#[cfg(target_os = "linux")]
fn hides_internal_http_ca_mount(path: &str) -> bool {
    normalized_mount_path(path).is_some_and(|path| path == "/run" || path.starts_with("/run/"))
}

fn normalized_mount_path(path: &str) -> Option<String> {
    use std::path::Component;

    let mut components = Vec::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name.to_str()?),
            Component::CurDir => {}
            Component::Prefix(_) | Component::ParentDir => return None,
        }
    }
    Some(format!("/{}", components.join("/")))
}

#[cfg(target_os = "linux")]
fn virtual_fs_mounts(
    args: impl Iterator<Item = String>,
    env_mounts: Option<String>,
) -> Result<Vec<VirtualFsMount>, InitError> {
    let mounts = args
        .filter_map(|arg| arg.strip_prefix("--virtiofs-mounts=").map(str::to_string))
        .next()
        .or(env_mounts)
        .or_else(read_mounts_from_proc_cmdline);
    let Some(mounts) = mounts else {
        return Ok(Vec::new());
    };

    mounts
        .split(';')
        .filter(|mount| !mount.is_empty())
        .map(parse_virtual_fs_mount)
        .collect::<Result<Vec<_>, _>>()
}

#[cfg(target_os = "linux")]
fn mount_configured_block(
    args: impl Iterator<Item = String>,
    env_mount: Option<String>,
    mounted_paths: &mut Vec<std::path::PathBuf>,
    after_http_ca: bool,
) -> Result<(), InitError> {
    let Some(path) = configured_block_mount(args, env_mount)? else {
        return Ok(());
    };
    if block_mount_after_http_ca(&path) != after_http_ca {
        return Ok(());
    }
    ensure_mount_point(&path)?;
    mount_block_device(&path)?;
    mounted_paths.push(std::path::PathBuf::from(path));
    Ok(())
}

#[cfg(target_os = "linux")]
fn configured_block_mount(
    args: impl Iterator<Item = String>,
    env_mount: Option<String>,
) -> Result<Option<String>, InitError> {
    let encoded = args
        .filter_map(|arg| arg.strip_prefix("--block-mount=").map(str::to_string))
        .next()
        .or(env_mount)
        .filter(|value| !value.is_empty());
    encoded.map(|value| decode_mount_field(&value)).transpose()
}

fn block_mount_after_http_ca(path: &str) -> bool {
    normalized_mount_path(path).as_deref() == Some("/run/sandbox/http-ca")
}

#[cfg(target_os = "linux")]
fn mount_block_device(path: &str) -> Result<(), InitError> {
    use std::ffi::CString;

    let source = CString::new("/dev/vdb").unwrap();
    let target = CString::new(path)
        .map_err(|_| InitError(format!("block mount path contains nul: {path}")))?;
    let fstype = CString::new("ext4").unwrap();
    let options = CString::new("rw,data=ordered").unwrap();
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            0,
            options.as_ptr().cast(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os(&format!(
            "mount block device /dev/vdb at {path}"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct VirtualFsMount {
    tag: String,
    path: String,
    readonly: bool,
}

#[cfg(target_os = "linux")]
fn parse_virtual_fs_mount(mount: &str) -> Result<VirtualFsMount, InitError> {
    let parts = mount.split(':').collect::<Vec<_>>();
    let [tag, path, mode] = parts.as_slice() else {
        return Err(InitError(format!(
            "invalid virtual filesystem mount: {mount}"
        )));
    };
    Ok(VirtualFsMount {
        tag: decode_mount_field(tag)?,
        path: decode_mount_field(path)?,
        readonly: *mode != "rw",
    })
}

#[cfg(target_os = "linux")]
fn ensure_mount_point(path: &str) -> Result<(), InitError> {
    use std::path::Path;

    if Path::new(path).is_dir() {
        return Ok(());
    }
    if Path::new(path).exists() {
        return Err(InitError(format!(
            "guest mount point is not a directory: {path}"
        )));
    }

    std::fs::create_dir_all(path)
        .map_err(|error| InitError(format!("create guest mount point {path}: {error}")))?;

    if !Path::new(path).is_dir() {
        return Err(InitError(format!(
            "guest mount point is not a directory: {path}"
        )));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn mount_virtiofs(tag: &str, path: &str, readonly: bool) -> Result<(), InitError> {
    use std::ffi::CString;

    let source = CString::new(tag)
        .map_err(|_| InitError(format!("virtual filesystem tag contains nul: {tag}")))?;
    let target = CString::new(path)
        .map_err(|_| InitError(format!("virtual filesystem path contains nul: {path}")))?;
    let fstype = CString::new("virtiofs").unwrap();
    let options = CString::new(if readonly { "ro" } else { "rw" }).unwrap();

    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            if readonly { libc::MS_RDONLY } else { 0 },
            options.as_ptr().cast(),
        )
    };
    if result < 0 {
        return Err(InitError::last_os(&format!(
            "mount virtiofs {tag} at {path}"
        )));
    }
    Ok(())
}

#[allow(dead_code)]
fn decode_mount_field(value: &str) -> Result<String, InitError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|error| {
            InitError(format!(
                "invalid virtual filesystem mount encoding: {error}"
            ))
        })?;
    String::from_utf8(bytes).map_err(|error| {
        InitError(format!(
            "virtual filesystem mount field is not utf-8: {error}"
        ))
    })
}

#[cfg(not(target_os = "linux"))]
fn virtual_fs_mounts(
    _args: impl Iterator<Item = String>,
    _env_mounts: Option<String>,
) -> Result<Vec<VirtualFsMount>, InitError> {
    Ok(Vec::new())
}

#[cfg(not(target_os = "linux"))]
fn mount_configured_block(
    _args: impl Iterator<Item = String>,
    _env_mount: Option<String>,
    _mounted_paths: &mut Vec<std::path::PathBuf>,
    _after_http_ca: bool,
) -> Result<(), InitError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
struct VirtualFsMount {
    tag: String,
    path: String,
    readonly: bool,
}

#[cfg(not(target_os = "linux"))]
fn mount_internal_http_ca(
    _mounts: &[VirtualFsMount],
    _mounted_virtual_paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), InitError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_virtual_filesystems_before_http_ca(
    _mounts: &[VirtualFsMount],
    _mounted_virtual_paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), InitError> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_virtual_filesystems_after_http_ca(
    _mounts: &[VirtualFsMount],
    _mounted_virtual_paths: &mut Vec<std::path::PathBuf>,
) -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_mounts_from_proc_cmdline() -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    for token in cmdline.split_ascii_whitespace() {
        let token = token.trim_matches('"');
        if let Some(value) = token.strip_prefix("SANDBOX_VIRTIOFS_MOUNTS=") {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_flag_from_proc_cmdline(flag: &str) -> bool {
    let Ok(cmdline) = std::fs::read_to_string("/proc/cmdline") else {
        return false;
    };
    cmdline
        .split_ascii_whitespace()
        .map(|token| token.trim_matches('"'))
        .any(|token| token == flag || token == format!("{flag}=1"))
}

fn init_ready_packet(root_readonly: bool) -> Result<Vec<u8>, InitError> {
    ControlFrame::InitReady {
        root_readonly,
        init_name: "sandbox-init".to_string(),
    }
    .encode_packet()
    .map_err(|error| InitError(error.to_string()))
}

#[cfg(target_os = "linux")]
fn connect_control() -> Result<std::fs::File, InitError> {
    use std::os::fd::FromRawFd;

    const VMADDR_CID_HOST: u32 = 2;

    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(InitError::last_os("socket(AF_VSOCK)"));
    }

    let mut addr = libc::sockaddr_vm {
        svm_family: libc::AF_VSOCK as libc::sa_family_t,
        svm_reserved1: 0,
        svm_port: INIT_CONTROL_PORT,
        svm_cid: VMADDR_CID_HOST,
        svm_zero: [0; 4],
    };

    let connect_result = unsafe {
        libc::connect(
            fd,
            &mut addr as *mut libc::sockaddr_vm as *mut libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if connect_result < 0 {
        let error = InitError::last_os("connect(AF_VSOCK)");
        unsafe {
            libc::close(fd);
        }
        return Err(error);
    }

    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(not(target_os = "linux"))]
fn connect_control() -> Result<std::fs::File, InitError> {
    eprintln!("sandbox-init control connect is only available in the Linux guest");
    Err(InitError(
        "sandbox-init control connect is only available in the Linux guest".to_string(),
    ))
}

fn send_init_ready(control: &mut std::fs::File, packet: &[u8]) -> Result<(), InitError> {
    use std::io::Write;

    control
        .write_all(packet)
        .map_err(|error| InitError(format!("write init.ready: {error}")))
}

fn run_control_loop(control: &mut std::fs::File) -> Result<(), InitError> {
    let write_lock = Arc::new(Mutex::new(()));
    let writer = Arc::new(ControlWriter::new(
        control
            .try_clone()
            .map_err(|error| InitError(format!("clone control stream: {error}")))?,
        write_lock,
    ));
    let execs = Arc::new(ActiveExecs::default());
    let spawns = Arc::new(ActiveSpawns::default());
    let connections = Arc::new(ActiveConnections::default());
    loop {
        let frame = match ControlFrame::decode_packet_from_reader(control) {
            Ok(frame) => frame,
            Err(error) if error.is_eof() => return Ok(()),
            Err(error) => return Err(InitError(format!("read control packet: {error}"))),
        };

        match frame {
            ControlFrame::GuestExec {
                id,
                argv,
                env,
                cwd,
                timeout_ms,
            } => {
                let writer = writer.clone();
                let execs = execs.clone();
                let cancel = execs.insert(id.clone());
                std::thread::spawn(move || {
                    let response = run_guest_exec(id.clone(), argv, env, cwd, timeout_ms, cancel);
                    execs.remove(&id);
                    match response {
                        Ok(frame) => {
                            let _ = send_control_frame(&writer, frame);
                        }
                        Err(error) => {
                            let _ = send_control_frame(
                                &writer,
                                ControlFrame::GuestExecComplete {
                                    id,
                                    exit_code: 127,
                                    stdout: Vec::new(),
                                    stderr: format!("guest.exec failed: {error}\n").into_bytes(),
                                },
                            );
                        }
                    }
                });
            }
            ControlFrame::GuestExecAbort { id } => {
                execs.abort(&id);
            }
            ControlFrame::GuestSpawn {
                id,
                argv,
                env,
                cwd,
                stdin,
                stdout,
                stderr,
                pipes,
                pty,
            } => {
                let writer = writer.clone();
                let spawns_for_thread = spawns.clone();
                let controls = spawns.insert(id.clone());
                std::thread::spawn(move || {
                    match run_guest_spawn(
                        id.clone(),
                        argv,
                        env,
                        cwd,
                        stdin,
                        stdout,
                        stderr,
                        pipes,
                        pty,
                        controls,
                        writer.clone(),
                    ) {
                        Ok(()) => {}
                        Err(error) => {
                            let _ = send_control_frame(
                                &writer,
                                ControlFrame::GuestSpawnStderr {
                                    id: id.clone(),
                                    data: format!("spawn guest command: {error}\n").into_bytes(),
                                },
                            );
                            let _ = send_control_frame(
                                &writer,
                                ControlFrame::GuestSpawnExit {
                                    id: id.clone(),
                                    exit_code: Some(127),
                                    signal: None,
                                },
                            );
                            let _ = send_control_frame(
                                &writer,
                                ControlFrame::GuestSpawnStreamsClosed { id: id.clone() },
                            );
                        }
                    }
                    spawns_for_thread.remove(&id);
                });
            }
            ControlFrame::GuestSpawnStdin { id, data } => {
                spawns.send(&id, SpawnControl::Stdin(data));
            }
            ControlFrame::GuestSpawnStdinClose { id } => {
                spawns.send(&id, SpawnControl::StdinClose);
            }
            ControlFrame::GuestSpawnPipeWrite { id, fd, data } => {
                spawns.send(&id, SpawnControl::PipeInput { fd, data });
            }
            ControlFrame::GuestSpawnPipeClose { id, fd } => {
                spawns.send(&id, SpawnControl::PipeClose { fd });
            }
            ControlFrame::GuestSpawnSignal { id, signal } => {
                spawns.send(&id, SpawnControl::Signal(signal));
            }
            ControlFrame::GuestSpawnResize { id, rows, cols } => {
                spawns.send(&id, SpawnControl::Resize(GuestPtySize { rows, cols }));
            }
            request @ (ControlFrame::GuestFsStat { .. }
            | ControlFrame::GuestFsReadDir { .. }
            | ControlFrame::GuestFsReadFile { .. }
            | ControlFrame::GuestFsWriteFile { .. }
            | ControlFrame::GuestFsMkdir { .. }
            | ControlFrame::GuestFsRemove { .. }
            | ControlFrame::GuestFsRename { .. }) => {
                let writer = writer.clone();
                std::thread::spawn(move || {
                    let _ = send_control_frame(&writer, handle_guest_fs_request(request));
                });
            }
            ControlFrame::GuestConnectionOpen {
                id,
                hostname,
                port,
                secure,
                timeout_ms,
                server_name,
            } => {
                let writer = writer.clone();
                let connections_for_thread = connections.clone();
                let controls = connections.insert(id.clone());
                std::thread::spawn(move || {
                    if let Err(error) = run_guest_connection(
                        id.clone(),
                        hostname,
                        port,
                        secure,
                        timeout_ms,
                        server_name,
                        controls,
                        writer.clone(),
                    ) {
                        let _ = send_control_frame(
                            &writer,
                            ControlFrame::GuestConnectionError {
                                id: id.clone(),
                                message: error.to_string(),
                            },
                        );
                    }
                    connections_for_thread.remove(&id);
                });
            }
            ControlFrame::GuestConnectionWrite { id, data } => {
                connections.send(&id, ConnectionControl::Write(data));
            }
            ControlFrame::GuestConnectionRead { id, max_bytes } => {
                connections.send(&id, ConnectionControl::Read(max_bytes));
            }
            ControlFrame::GuestConnectionClose { id } => {
                connections.send(&id, ConnectionControl::Close);
            }
            ControlFrame::InitReady { .. }
            | ControlFrame::InitFailed { .. }
            | ControlFrame::GuestExecComplete { .. }
            | ControlFrame::GuestFsResponse { .. }
            | ControlFrame::GuestSpawnStarted { .. }
            | ControlFrame::GuestSpawnStdout { .. }
            | ControlFrame::GuestSpawnStderr { .. }
            | ControlFrame::GuestSpawnPipeOutput { .. }
            | ControlFrame::GuestSpawnPipeOutputClosed { .. }
            | ControlFrame::GuestSpawnExit { .. }
            | ControlFrame::GuestSpawnStreamsClosed { .. }
            | ControlFrame::GuestConnectionOpened { .. }
            | ControlFrame::GuestConnectionWriteComplete { .. }
            | ControlFrame::GuestConnectionData { .. }
            | ControlFrame::GuestConnectionEnd { .. }
            | ControlFrame::GuestConnectionError { .. } => {}
        }
    }
}

fn handle_guest_fs_request(request: ControlFrame) -> ControlFrame {
    let (id, result) = match request {
        ControlFrame::GuestFsStat { id, path } => {
            let result = guest_fs_stat(&path).map(GuestFsResponseResult::Stat);
            (id, result)
        }
        ControlFrame::GuestFsReadDir { id, path } => {
            let result = guest_fs_read_dir(&id, &path).map(GuestFsResponseResult::ReadDir);
            (id, result)
        }
        ControlFrame::GuestFsReadFile { id, path, range } => {
            let result = guest_fs_read_file(&path, range).map(GuestFsResponseResult::ReadFile);
            (id, result)
        }
        ControlFrame::GuestFsWriteFile {
            id,
            path,
            contents,
            create_parents,
        } => {
            let result = guest_fs_write_file(&path, &contents, create_parents)
                .map(|()| GuestFsResponseResult::Empty);
            (id, result)
        }
        ControlFrame::GuestFsMkdir {
            id,
            path,
            recursive,
        } => {
            let result = guest_fs_mkdir(&path, recursive).map(|()| GuestFsResponseResult::Empty);
            (id, result)
        }
        ControlFrame::GuestFsRemove {
            id,
            path,
            recursive,
            force,
        } => {
            let result =
                guest_fs_remove(&path, recursive, force).map(|()| GuestFsResponseResult::Empty);
            (id, result)
        }
        ControlFrame::GuestFsRename { id, from, to } => {
            let result = std::fs::rename(&from, &to)
                .map_err(|error| fs_io_error(format!("rename {from} -> {to}"), error))
                .map(|()| GuestFsResponseResult::Empty);
            (id, result)
        }
        _ => unreachable!("non-filesystem control frame passed to filesystem handler"),
    };
    ControlFrame::GuestFsResponse {
        id,
        result: result.unwrap_or_else(|error| GuestFsResponseResult::Error(error)),
    }
}

fn guest_fs_stat(path: &str) -> Result<GuestFsStat, GuestFsError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| fs_io_error(format!("stat {path}"), error))?;
    guest_fs_stat_from_metadata(metadata)
}

fn guest_fs_read_dir(id: &str, path: &str) -> Result<Vec<GuestFsDirectoryEntry>, GuestFsError> {
    let entries =
        std::fs::read_dir(path).map_err(|error| fs_io_error(format!("readDir {path}"), error))?;
    let mut result = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| fs_io_error(format!("readDir {path}"), error))?;
        let name_os = entry.file_name();
        let name_bytes = name_os.as_bytes().to_vec();
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        let metadata = std::fs::symlink_metadata(entry.path())
            .map_err(|error| fs_io_error(format!("readDir {path}/{name}"), error))?;
        result.push(GuestFsDirectoryEntry {
            name,
            name_bytes,
            stat: guest_fs_stat_from_metadata(metadata)?,
        });
    }
    guest_fs_ensure_response_size(
        ControlFrame::GuestFsResponse {
            id: id.to_string(),
            result: GuestFsResponseResult::ReadDir(result.clone()),
        },
        format!("readDir {path} response"),
    )?;
    Ok(result)
}

fn guest_fs_read_file(
    path: &str,
    range: Option<GuestFsReadRange>,
) -> Result<Vec<u8>, GuestFsError> {
    let metadata =
        std::fs::metadata(path).map_err(|error| fs_io_error(format!("readFile {path}"), error))?;
    if !metadata.is_file() {
        return Err(GuestFsError {
            message: format!("readFile {path}: path must reference a regular file"),
            code: Some("EINVAL".to_string()),
        });
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| fs_io_error(format!("readFile {path}"), error))?;
    let read_limit = match range {
        Some(range) => {
            if range.length > GUEST_FS_RESPONSE_PAYLOAD_LIMIT {
                return Err(fs_response_too_large(format!("readFile {path} response")));
            }
            file.seek(SeekFrom::Start(range.offset))
                .map_err(|error| fs_io_error(format!("readFile {path}"), error))?;
            range.length
        }
        None => GUEST_FS_RESPONSE_PAYLOAD_LIMIT + 1,
    };
    let mut contents = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut contents)
        .map_err(|error| fs_io_error(format!("readFile {path}"), error))?;
    if contents.len() as u64 > GUEST_FS_RESPONSE_PAYLOAD_LIMIT {
        return Err(fs_response_too_large(format!("readFile {path} response")));
    }
    Ok(contents)
}

fn guest_fs_write_file(
    path: &str,
    contents: &[u8],
    create_parents: bool,
) -> Result<(), GuestFsError> {
    if create_parents {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|error| fs_io_error(format!("writeFile {path} parent"), error))?;
        }
    }
    std::fs::write(path, contents).map_err(|error| fs_io_error(format!("writeFile {path}"), error))
}

fn guest_fs_mkdir(path: &str, recursive: bool) -> Result<(), GuestFsError> {
    if recursive {
        std::fs::create_dir_all(path).map_err(|error| fs_io_error(format!("mkdir {path}"), error))
    } else {
        std::fs::create_dir(path).map_err(|error| fs_io_error(format!("mkdir {path}"), error))
    }
}

fn guest_fs_remove(path: &str, recursive: bool, force: bool) -> Result<(), GuestFsError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if force && error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(fs_io_error(format!("remove {path}"), error)),
    };
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        if recursive {
            guest_fs_remove_result(path, force, std::fs::remove_dir_all(path))
        } else {
            guest_fs_remove_result(path, force, std::fs::remove_dir(path))
        }
    } else {
        guest_fs_remove_result(path, force, std::fs::remove_file(path))
    }
}

fn guest_fs_remove_result(
    path: &str,
    force: bool,
    result: std::io::Result<()>,
) -> Result<(), GuestFsError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if force && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(fs_io_error(format!("remove {path}"), error)),
    }
}

fn guest_fs_stat_from_metadata(metadata: std::fs::Metadata) -> Result<GuestFsStat, GuestFsError> {
    let file_type = metadata.file_type();
    let entry_type = if file_type.is_file() {
        GuestFsEntryType::File
    } else if file_type.is_dir() {
        GuestFsEntryType::Directory
    } else if file_type.is_symlink() {
        GuestFsEntryType::Symlink
    } else {
        GuestFsEntryType::Other
    };
    let size_bytes = metadata.len();
    if size_bytes > GUEST_FS_MAX_SAFE_INTEGER {
        return Err(GuestFsError {
            message: format!(
                "stat sizeBytes {size_bytes} exceeds JavaScript safe integer limit {GUEST_FS_MAX_SAFE_INTEGER}",
            ),
            code: Some("EFBIG".to_string()),
        });
    }
    Ok(GuestFsStat {
        entry_type,
        size_bytes,
        modified_at_ms: modified_at_ms(&metadata)?,
    })
}

fn modified_at_ms(metadata: &std::fs::Metadata) -> Result<i64, GuestFsError> {
    let modified = metadata
        .modified()
        .map_err(|error| fs_io_error("stat modified time", error))?;
    let millis = match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_millis()).map_err(|_| GuestFsError {
            message: "stat modified time exceeds i128".to_string(),
            code: None,
        })?,
        Err(error) => {
            let duration = error.duration();
            -i128::try_from(duration.as_millis()).map_err(|_| GuestFsError {
                message: "stat modified time exceeds i128".to_string(),
                code: None,
            })?
        }
    };
    i64::try_from(millis).map_err(|_| GuestFsError {
        message: "stat modified time exceeds i64 milliseconds".to_string(),
        code: None,
    })
}

fn fs_io_error(context: impl Into<String>, error: std::io::Error) -> GuestFsError {
    GuestFsError {
        message: format!("{}: {error}", context.into()),
        code: fs_error_code(&error),
    }
}

fn fs_response_too_large(context: impl Into<String>) -> GuestFsError {
    GuestFsError {
        message: format!(
            "{} exceeds {} byte guest filesystem response limit",
            context.into(),
            GUEST_FS_RESPONSE_PAYLOAD_LIMIT,
        ),
        code: Some("EFBIG".to_string()),
    }
}

fn guest_fs_ensure_response_size(
    response: ControlFrame,
    context: impl Into<String>,
) -> Result<(), GuestFsError> {
    let context = context.into();
    let response = response.encode().map_err(|error| GuestFsError {
        message: format!("{context}: {error}"),
        code: None,
    })?;
    if response.len() as u64 > GUEST_FS_RESPONSE_PAYLOAD_LIMIT {
        return Err(fs_response_too_large(context));
    }
    Ok(())
}

fn fs_error_code(error: &std::io::Error) -> Option<String> {
    let errno = error.raw_os_error()?;
    let code = match errno {
        libc::ENOENT => "ENOENT",
        libc::ENOTDIR => "ENOTDIR",
        libc::EISDIR => "EISDIR",
        libc::EEXIST => "EEXIST",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::EROFS => "EROFS",
        libc::EXDEV => "EXDEV",
        libc::EINVAL => "EINVAL",
        libc::EFBIG => "EFBIG",
        _ => return None,
    };
    Some(code.to_string())
}

fn run_guest_spawn(
    id: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    stdin: GuestSpawnStdio,
    stdout: GuestSpawnStdio,
    stderr: GuestSpawnStdio,
    pipes: Vec<i32>,
    pty: Option<GuestPtySize>,
    controls: mpsc::Receiver<SpawnControl>,
    control: Arc<ControlWriter>,
) -> Result<(), InitError> {
    if argv.is_empty() {
        return Err(InitError("guest.spawn argv must not be empty".to_string()));
    }

    prepare_exec_environment(&env)?;

    let pty_mode = match (stdin, stdout, stderr, pty) {
        (GuestSpawnStdio::Pipe, GuestSpawnStdio::Pipe, GuestSpawnStdio::Pipe, None) => None,
        (GuestSpawnStdio::Pty, GuestSpawnStdio::Pty, GuestSpawnStdio::Pty, Some(size)) => {
            Some(size)
        }
        _ => {
            return Err(InitError(
                "guest.spawn stdio must be all pipe with no pty or all pty with pty size"
                    .to_string(),
            ));
        }
    };

    let mut command = std::process::Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.envs(env);
    command.current_dir(cwd);

    let mut pty_master = None;
    if let Some(size) = pty_mode {
        let (master, slave) = open_guest_pty(size)?;
        configure_pty_command(&mut command, &slave);
        command.stdin(std::process::Stdio::from(slave.try_clone().map_err(
            |error| InitError(format!("clone pty slave for stdin: {error}")),
        )?));
        command.stdout(std::process::Stdio::from(slave.try_clone().map_err(
            |error| InitError(format!("clone pty slave for stdout: {error}")),
        )?));
        command.stderr(std::process::Stdio::from(slave));
        pty_master = Some(master);
    } else {
        configure_command_process_group(&mut command);
        command.stdin(std::process::Stdio::piped());
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
    }

    let guest_pipes = open_guest_pipes(&pipes)?;
    configure_guest_pipe_command(&mut command, &guest_pipes);
    let guest_pipe_readers = guest_pipes
        .iter()
        .map(|pipe| {
            pipe.parent.try_clone().map_err(|error| {
                InitError(format!(
                    "clone guest pipe fd {} for output: {error}",
                    pipe.fd
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (mut child, child_id) = spawn_active_child(&mut command)
        .map_err(|error| InitError(format!("{}: {error}", argv[0])))?;
    drop(command);

    let (events, event_receiver) = mpsc::channel();
    let controls_stopped = Arc::new(AtomicBool::new(false));
    let mut pipe_writers = HashMap::new();
    let mut pipe_fds = Vec::with_capacity(guest_pipes.len());
    for (pipe, reader) in guest_pipes.into_iter().zip(guest_pipe_readers) {
        let fd = pipe.fd;
        pipe_writers.insert(fd, pipe.parent);
        pipe_fds.push(fd);
        pump_spawn_output(
            reader,
            events.clone(),
            move |data| SpawnOutputEvent::Pipe { fd, data },
            SpawnOutputEvent::PipeClosed { fd },
        );
    }
    if let Some(master) = pty_master {
        let writer = master
            .try_clone()
            .map_err(|error| InitError(format!("clone pty master for input: {error}")))?;
        pump_spawn_controls(
            child_id,
            controls,
            Some(writer),
            pipe_writers,
            true,
            controls_stopped.clone(),
        );
        pump_spawn_output(
            master,
            events.clone(),
            SpawnOutputEvent::Stdout,
            SpawnOutputEvent::StderrClosed,
        );
        let _ = events.send(SpawnOutputEvent::StdoutClosed);
    } else {
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| InitError("spawned command did not expose stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| InitError("spawned command did not expose stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| InitError("spawned command did not expose stderr".to_string()))?;
        pump_spawn_controls(
            child_id,
            controls,
            Some(stdin),
            pipe_writers,
            false,
            controls_stopped.clone(),
        );
        pump_spawn_output(
            stdout,
            events.clone(),
            SpawnOutputEvent::Stdout,
            SpawnOutputEvent::StdoutClosed,
        );
        pump_spawn_output(
            stderr,
            events.clone(),
            SpawnOutputEvent::Stderr,
            SpawnOutputEvent::StderrClosed,
        );
    }
    send_control_frame(&control, ControlFrame::GuestSpawnStarted { id: id.clone() })?;

    std::thread::spawn(move || {
        let status = child.wait();
        unregister_active_child(child_id);
        controls_stopped.store(true, Ordering::Relaxed);
        let (exit_code, signal) = match status {
            Ok(status) => spawn_exit_status(status),
            Err(_) => (Some(128), None),
        };
        let _ = events.send(SpawnOutputEvent::Exit { exit_code, signal });
    });

    run_spawn_output_coordinator(id, control, event_receiver, pipe_fds);
    Ok(())
}

fn pump_spawn_output<F>(
    mut reader: impl std::io::Read + Send + 'static,
    events: mpsc::Sender<SpawnOutputEvent>,
    data_event: F,
    closed_event: SpawnOutputEvent,
) where
    F: Fn(Vec<u8>) -> SpawnOutputEvent + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = [0; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = events.send(closed_event);
                    return;
                }
                Ok(length) => {
                    let data = buffer[..length].to_vec();
                    if events.send(data_event(data)).is_err() {
                        return;
                    }
                }
                Err(_) => {
                    let _ = events.send(closed_event);
                    return;
                }
            }
        }
    });
}

#[cfg(unix)]
fn pump_spawn_controls<W>(
    child_id: u32,
    controls: mpsc::Receiver<SpawnControl>,
    mut stdin: Option<W>,
    mut pipes: HashMap<i32, std::os::unix::net::UnixStream>,
    resize_input: bool,
    stopped: Arc<AtomicBool>,
) where
    W: Write + Send + 'static,
    W: std::os::fd::AsRawFd,
{
    std::thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            let control = match controls.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(control) => control,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            match control {
                SpawnControl::Stdin(data) => {
                    if let Some(writer) = stdin.as_mut() {
                        let _ = writer.write_all(&data);
                        let _ = writer.flush();
                    }
                }
                SpawnControl::StdinClose => {
                    if resize_input {
                        if let Some(writer) = stdin.as_mut() {
                            let _ = writer.write_all(&[0x04]);
                            let _ = writer.flush();
                        }
                    }
                    stdin = None;
                }
                SpawnControl::PipeInput { fd, data } => {
                    if let Some(writer) = pipes.get_mut(&fd) {
                        let _ = writer.write_all(&data);
                        let _ = writer.flush();
                    }
                }
                SpawnControl::PipeClose { fd } => {
                    if let Some(writer) = pipes.remove(&fd) {
                        let _ = writer.shutdown(std::net::Shutdown::Write);
                    }
                }
                SpawnControl::Signal(signal) => {
                    if let Some(signal) = signal_number(&signal) {
                        signal_child_process_group(child_id, signal);
                    }
                }
                SpawnControl::Resize(size) => {
                    if resize_input {
                        if let Some(writer) = stdin.as_mut() {
                            let _ = resize_spawn_input(writer, size);
                        }
                    }
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn pump_spawn_controls<W>(
    _child_id: u32,
    controls: mpsc::Receiver<SpawnControl>,
    mut stdin: Option<W>,
    mut pipes: HashMap<i32, std::os::unix::net::UnixStream>,
    _resize_input: bool,
    stopped: Arc<AtomicBool>,
) where
    W: Write + Send + 'static,
{
    std::thread::spawn(move || {
        while !stopped.load(Ordering::Relaxed) {
            let control = match controls.recv_timeout(std::time::Duration::from_millis(100)) {
                Ok(control) => control,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            match control {
                SpawnControl::Stdin(data) => {
                    if let Some(writer) = stdin.as_mut() {
                        let _ = writer.write_all(&data);
                        let _ = writer.flush();
                    }
                }
                SpawnControl::StdinClose => {
                    stdin = None;
                }
                SpawnControl::PipeInput { fd, data } => {
                    if let Some(writer) = pipes.get_mut(&fd) {
                        let _ = writer.write_all(&data);
                        let _ = writer.flush();
                    }
                }
                SpawnControl::PipeClose { fd } => {
                    pipes.remove(&fd);
                }
                SpawnControl::Signal(_) | SpawnControl::Resize(_) => {}
            }
        }
    });
}

#[cfg(unix)]
fn signal_number(signal: &str) -> Option<i32> {
    match signal {
        "SIGHUP" => Some(libc::SIGHUP),
        "SIGINT" => Some(libc::SIGINT),
        "SIGQUIT" => Some(libc::SIGQUIT),
        "SIGTERM" => Some(libc::SIGTERM),
        "SIGKILL" => Some(libc::SIGKILL),
        _ => None,
    }
}

#[cfg(not(unix))]
fn signal_number(_signal: &str) -> Option<i32> {
    None
}

#[cfg(unix)]
fn signal_child_process_group(child_pid: u32, signal: i32) {
    let pgid = -(child_pid as libc::pid_t);
    unsafe {
        libc::kill(pgid, signal);
    }
}

#[cfg(not(unix))]
fn signal_child_process_group(_child_pid: u32, _signal: i32) {}

#[cfg(unix)]
fn resize_spawn_input<W: std::os::fd::AsRawFd>(
    input: &W,
    size: GuestPtySize,
) -> std::io::Result<()> {
    set_pty_size(input.as_raw_fd(), size)
}

#[cfg(not(unix))]
fn resize_spawn_input<W>(_input: &W, _size: GuestPtySize) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
struct PreparedGuestPipe {
    fd: i32,
    parent: std::os::unix::net::UnixStream,
    child: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
fn open_guest_pipes(pipes: &[i32]) -> Result<Vec<PreparedGuestPipe>, InitError> {
    use std::os::fd::AsRawFd;

    let requested_fds = pipes.iter().copied().collect::<HashSet<_>>();
    pipes
        .iter()
        .map(|pipe| {
            let (parent, child) = std::os::unix::net::UnixStream::pair()
                .map_err(|error| InitError(format!("open guest pipe fd {pipe}: {error}")))?;
            let child = if requested_fds.contains(&child.as_raw_fd()) {
                duplicate_stream_outside_fds(&child, &requested_fds)
                    .map_err(|error| InitError(format!("prepare guest pipe fd {pipe}: {error}")))?
            } else {
                child
            };
            Ok(PreparedGuestPipe {
                fd: *pipe,
                parent,
                child,
            })
        })
        .collect()
}

#[cfg(unix)]
fn duplicate_stream_outside_fds(
    stream: &std::os::unix::net::UnixStream,
    excluded: &HashSet<i32>,
) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{AsRawFd, FromRawFd};

    let mut minimum = 3;
    loop {
        let fd = unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if !excluded.contains(&fd) {
            return Ok(unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) });
        }
        unsafe {
            libc::close(fd);
        }
        minimum = fd
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("guest pipe descriptor space exhausted"))?;
    }
}

#[cfg(not(unix))]
fn open_guest_pipes(_pipes: &[i32]) -> Result<Vec<PreparedGuestPipe>, InitError> {
    Err(InitError(
        "guest process pipes are only supported on Unix".to_string(),
    ))
}

#[cfg(unix)]
fn configure_guest_pipe_command(command: &mut std::process::Command, pipes: &[PreparedGuestPipe]) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let mappings = pipes
        .iter()
        .map(|pipe| (pipe.child.as_raw_fd(), pipe.fd))
        .collect::<Vec<_>>();
    unsafe {
        command.pre_exec(move || {
            for (source, target) in &mappings {
                if libc::dup2(*source, *target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (source, _) in &mappings {
                libc::close(*source);
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_guest_pipe_command(
    _command: &mut std::process::Command,
    _pipes: &[PreparedGuestPipe],
) {
}

#[cfg(unix)]
fn open_guest_pty(size: GuestPtySize) -> Result<(std::fs::File, std::fs::File), InitError> {
    use std::os::fd::FromRawFd;

    let mut master = 0;
    let mut slave = 0;
    let mut winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };
    if result < 0 {
        return Err(InitError(format!(
            "openpty: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    })
}

#[cfg(not(unix))]
fn open_guest_pty(_size: GuestPtySize) -> Result<(std::fs::File, std::fs::File), InitError> {
    Err(InitError("guest PTY is only supported on Unix".to_string()))
}

#[cfg(unix)]
fn configure_pty_command(command: &mut std::process::Command, slave: &std::fs::File) {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let slave_fd = slave.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(slave_fd, libc::TIOCSCTTY.into(), 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::tcsetpgrp(slave_fd, libc::getpgrp()) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[cfg(not(unix))]
fn configure_pty_command(_command: &mut std::process::Command, _slave: &std::fs::File) {}

#[cfg(unix)]
fn set_pty_size(fd: std::os::fd::RawFd, size: GuestPtySize) -> std::io::Result<()> {
    let winsize = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let result = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &winsize) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn run_spawn_output_coordinator(
    id: String,
    control: Arc<ControlWriter>,
    events: mpsc::Receiver<SpawnOutputEvent>,
    pipe_fds: Vec<i32>,
) {
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut exited = false;
    let mut open_pipes = pipe_fds
        .into_iter()
        .collect::<std::collections::HashSet<_>>();
    loop {
        let event = match events.recv() {
            Ok(event) => event,
            Err(_) => break,
        };

        match event {
            SpawnOutputEvent::Stdout(data) => {
                let _ = send_control_frame(
                    &control,
                    ControlFrame::GuestSpawnStdout {
                        id: id.clone(),
                        data,
                    },
                );
            }
            SpawnOutputEvent::Stderr(data) => {
                let _ = send_control_frame(
                    &control,
                    ControlFrame::GuestSpawnStderr {
                        id: id.clone(),
                        data,
                    },
                );
            }
            SpawnOutputEvent::Pipe { fd, data } => {
                let _ = send_control_frame(
                    &control,
                    ControlFrame::GuestSpawnPipeOutput {
                        id: id.clone(),
                        fd,
                        data,
                    },
                );
            }
            SpawnOutputEvent::StdoutClosed => stdout_open = false,
            SpawnOutputEvent::StderrClosed => stderr_open = false,
            SpawnOutputEvent::PipeClosed { fd } => {
                if open_pipes.remove(&fd) {
                    let _ = send_control_frame(
                        &control,
                        ControlFrame::GuestSpawnPipeOutputClosed { id: id.clone(), fd },
                    );
                }
            }
            SpawnOutputEvent::Exit { exit_code, signal } => {
                exited = true;
                let _ = send_control_frame(
                    &control,
                    ControlFrame::GuestSpawnExit {
                        id: id.clone(),
                        exit_code,
                        signal,
                    },
                );
            }
        }

        if exited && !stdout_open && !stderr_open && open_pipes.is_empty() {
            break;
        }
    }

    let _ = send_control_frame(&control, ControlFrame::GuestSpawnStreamsClosed { id });
}

enum SpawnOutputEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Pipe {
        fd: i32,
        data: Vec<u8>,
    },
    StdoutClosed,
    StderrClosed,
    PipeClosed {
        fd: i32,
    },
    Exit {
        exit_code: Option<i32>,
        signal: Option<String>,
    },
}

enum SpawnControl {
    Stdin(Vec<u8>),
    StdinClose,
    PipeInput { fd: i32, data: Vec<u8> },
    PipeClose { fd: i32 },
    Signal(String),
    Resize(GuestPtySize),
}

enum ConnectionControl {
    Write(Vec<u8>),
    Read(u32),
    Close,
}

const CONNECTION_IO_POLL_INTERVAL: Duration = Duration::from_millis(20);
const RESOLVER_QUEUE_CAPACITY: usize = 64;

struct ResolveRequest {
    hostname: String,
    port: u16,
    cancelled: Arc<AtomicBool>,
    response: mpsc::Sender<Result<Vec<SocketAddr>, String>>,
}

fn resolver_sender() -> &'static mpsc::SyncSender<ResolveRequest> {
    static RESOLVER: OnceLock<mpsc::SyncSender<ResolveRequest>> = OnceLock::new();
    RESOLVER.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<ResolveRequest>(RESOLVER_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("sandbox-guest-resolver".to_string())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    if request.cancelled.load(Ordering::Acquire) {
                        continue;
                    }
                    let result = (request.hostname.as_str(), request.port)
                        .to_socket_addrs()
                        .map(|addresses| addresses.collect::<Vec<_>>())
                        .map_err(|error| error.to_string());
                    if !request.cancelled.load(Ordering::Acquire) {
                        let _ = request.response.send(result);
                    }
                }
            })
            .expect("spawn sandbox guest resolver");
        sender
    })
}

enum GuestConnectionIo {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl GuestConnectionIo {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_read_timeout(timeout),
            Self::Tls(stream) => stream.sock.set_read_timeout(timeout),
        }
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.set_write_timeout(timeout),
            Self::Tls(stream) => stream.sock.set_write_timeout(timeout),
        }
    }

    fn shutdown(&self) {
        let result = match self {
            Self::Plain(stream) => stream.shutdown(Shutdown::Both),
            Self::Tls(stream) => stream.sock.shutdown(Shutdown::Both),
        };
        let _ = result;
    }
}

impl Read for GuestConnectionIo {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for GuestConnectionIo {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn run_guest_connection(
    id: String,
    hostname: String,
    port: u16,
    secure: bool,
    timeout_ms: u64,
    server_name: Option<String>,
    controls: mpsc::Receiver<ConnectionControl>,
    writer: Arc<ControlWriter>,
) -> Result<(), InitError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| InitError("guest connection timeout is too large".to_string()))?;
    let mut pending_controls = VecDeque::new();
    let Some(addresses) = resolve_guest_addresses(
        &hostname,
        port,
        deadline,
        timeout_ms,
        &controls,
        &mut pending_controls,
    )?
    else {
        return Ok(());
    };
    let Some(stream) = connect_guest_tcp(
        &hostname,
        port,
        &addresses,
        deadline,
        timeout_ms,
        &controls,
        &mut pending_controls,
    )?
    else {
        return Ok(());
    };
    let mut connection = if secure {
        let Some(tls) = connect_guest_tls(
            stream,
            server_name.unwrap_or_else(|| hostname.clone()),
            deadline,
            timeout_ms,
            &controls,
            &mut pending_controls,
        )?
        else {
            return Ok(());
        };
        GuestConnectionIo::Tls(Box::new(tls))
    } else {
        GuestConnectionIo::Plain(stream)
    };
    connection
        .set_read_timeout(Some(CONNECTION_IO_POLL_INTERVAL))
        .map_err(|error| InitError(format!("configure guest connection read timeout: {error}")))?;
    connection
        .set_write_timeout(Some(CONNECTION_IO_POLL_INTERVAL))
        .map_err(|error| InitError(format!("configure guest connection write timeout: {error}")))?;
    send_control_frame(
        &writer,
        ControlFrame::GuestConnectionOpened { id: id.clone() },
    )?;

    let mut pending_read = None;
    loop {
        let control = if let Some(control) = pending_controls.pop_front() {
            Some(control)
        } else if pending_read.is_some() {
            match controls.recv_timeout(Duration::from_millis(1)) {
                Ok(control) => Some(control),
                Err(mpsc::RecvTimeoutError::Timeout) => None,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        } else {
            match controls.recv() {
                Ok(control) => Some(control),
                Err(_) => return Ok(()),
            }
        };

        match control {
            Some(ConnectionControl::Write(data)) => {
                if !write_guest_connection(
                    &mut connection,
                    &data,
                    &controls,
                    &mut pending_controls,
                )? {
                    connection.shutdown();
                    return Ok(());
                }
                send_control_frame(
                    &writer,
                    ControlFrame::GuestConnectionWriteComplete { id: id.clone() },
                )?;
            }
            Some(ConnectionControl::Read(max_bytes)) => {
                if pending_read.is_some() {
                    return Err(InitError(
                        "guest connection already has a read in flight".to_string(),
                    ));
                }
                pending_read = Some(max_bytes);
            }
            Some(ConnectionControl::Close) => {
                connection.shutdown();
                return Ok(());
            }
            None => {}
        }

        let Some(max_bytes) = pending_read else {
            continue;
        };
        let mut data = vec![0; max_bytes as usize];
        match connection.read(&mut data) {
            Ok(0) => {
                send_control_frame(&writer, ControlFrame::GuestConnectionEnd { id: id.clone() })?;
                return Ok(());
            }
            Ok(read) => {
                data.truncate(read);
                pending_read = None;
                send_control_frame(
                    &writer,
                    ControlFrame::GuestConnectionData {
                        id: id.clone(),
                        data,
                    },
                )?;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(InitError(format!("read guest connection: {error}")));
            }
        }
    }
}

fn resolve_guest_addresses(
    hostname: &str,
    port: u16,
    deadline: Instant,
    timeout_ms: u64,
    controls: &mpsc::Receiver<ConnectionControl>,
    pending_controls: &mut VecDeque<ConnectionControl>,
) -> Result<Option<Vec<SocketAddr>>, InitError> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let (response, result) = mpsc::channel();
    resolver_sender()
        .try_send(ResolveRequest {
            hostname: hostname.to_string(),
            port,
            cancelled: cancelled.clone(),
            response,
        })
        .map_err(|error| match error {
            mpsc::TrySendError::Full(_) => InitError("guest resolver queue is full".to_string()),
            mpsc::TrySendError::Disconnected(_) => {
                InitError("guest resolver is unavailable".to_string())
            }
        })?;

    loop {
        if drain_connection_controls(controls, pending_controls) {
            cancelled.store(true, Ordering::Release);
            return Ok(None);
        }
        let remaining = connection_remaining(deadline, timeout_ms)?;
        match result.recv_timeout(remaining.min(CONNECTION_IO_POLL_INTERVAL)) {
            Ok(Ok(addresses)) if addresses.is_empty() => {
                return Err(InitError(format!(
                    "resolve {hostname}:{port}: no addresses"
                )));
            }
            Ok(Ok(addresses)) => return Ok(Some(addresses)),
            Ok(Err(error)) => {
                return Err(InitError(format!("resolve {hostname}:{port}: {error}")));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(InitError("guest resolver stopped unexpectedly".to_string()));
            }
        }
    }
}

fn connect_guest_tcp(
    hostname: &str,
    port: u16,
    addresses: &[SocketAddr],
    deadline: Instant,
    timeout_ms: u64,
    controls: &mpsc::Receiver<ConnectionControl>,
    pending_controls: &mut VecDeque<ConnectionControl>,
) -> Result<Option<TcpStream>, InitError> {
    let mut last_error = None;
    for address in addresses {
        let mut connect_failed = false;
        let socket = Socket::new(
            Domain::for_address(*address),
            Type::STREAM,
            Some(Protocol::TCP),
        )
        .map_err(|error| InitError(format!("create guest connection socket: {error}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| InitError(format!("configure guest connection socket: {error}")))?;

        match socket.connect(&(*address).into()) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => loop {
                if drain_connection_controls(controls, pending_controls) {
                    return Ok(None);
                }
                let remaining = connection_remaining(deadline, timeout_ms)?;
                if !poll_socket_writable(&socket, remaining.min(CONNECTION_IO_POLL_INTERVAL))
                    .map_err(|error| InitError(format!("poll guest connection socket: {error}")))?
                {
                    continue;
                }
                match socket.take_error().map_err(|error| {
                    InitError(format!("inspect guest connection socket: {error}"))
                })? {
                    Some(error) => {
                        last_error = Some(error);
                        connect_failed = true;
                        break;
                    }
                    None => break,
                }
            },
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        }

        if connect_failed {
            continue;
        }
        if let Some(error) = socket
            .take_error()
            .map_err(|error| InitError(format!("inspect guest connection socket: {error}")))?
        {
            last_error = Some(error);
            continue;
        }
        socket
            .set_nonblocking(false)
            .map_err(|error| InitError(format!("configure guest connection socket: {error}")))?;
        socket
            .set_tcp_nodelay(true)
            .map_err(|error| InitError(format!("configure guest connection socket: {error}")))?;
        return Ok(Some(socket.into()));
    }

    let details = last_error
        .map(|error| error.to_string())
        .unwrap_or_else(|| "no usable addresses".to_string());
    Err(InitError(format!(
        "connect to {hostname}:{port}: {details}"
    )))
}

fn poll_socket_writable(socket: &Socket, timeout: Duration) -> std::io::Result<bool> {
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLOUT,
        revents: 0,
    };
    let timeout_ms = timeout.as_millis().clamp(1, i32::MAX as u128) as i32;
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(result > 0)
}

fn connection_remaining(deadline: Instant, timeout_ms: u64) -> Result<Duration, InitError> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| InitError(format!("guest connection timed out after {timeout_ms} ms")))
}

fn drain_connection_controls(
    controls: &mpsc::Receiver<ConnectionControl>,
    pending_controls: &mut VecDeque<ConnectionControl>,
) -> bool {
    loop {
        match controls.try_recv() {
            Ok(ConnectionControl::Close) | Err(mpsc::TryRecvError::Disconnected) => return true,
            Ok(control) => pending_controls.push_back(control),
            Err(mpsc::TryRecvError::Empty) => return false,
        }
    }
}

fn write_guest_connection(
    connection: &mut GuestConnectionIo,
    data: &[u8],
    controls: &mpsc::Receiver<ConnectionControl>,
    pending_controls: &mut VecDeque<ConnectionControl>,
) -> Result<bool, InitError> {
    let mut offset = 0;
    while offset < data.len() {
        if drain_connection_controls(controls, pending_controls) {
            return Ok(false);
        }
        match connection.write(&data[offset..]) {
            Ok(0) => {
                return Err(InitError(
                    "write guest connection returned zero bytes".to_string(),
                ));
            }
            Ok(written) => offset += written,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InitError(format!("write guest connection: {error}"))),
        }
    }
    loop {
        if drain_connection_controls(controls, pending_controls) {
            return Ok(false);
        }
        match connection.flush() {
            Ok(()) => return Ok(true),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InitError(format!("flush guest connection: {error}"))),
        }
    }
}

fn connect_guest_tls(
    stream: TcpStream,
    server_name: String,
    deadline: Instant,
    timeout_ms: u64,
    controls: &mpsc::Receiver<ConnectionControl>,
    pending_controls: &mut VecDeque<ConnectionControl>,
) -> Result<Option<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>, InitError> {
    stream
        .set_read_timeout(Some(CONNECTION_IO_POLL_INTERVAL))
        .map_err(|error| InitError(format!("configure TLS handshake read timeout: {error}")))?;
    stream
        .set_write_timeout(Some(CONNECTION_IO_POLL_INTERVAL))
        .map_err(|error| InitError(format!("configure TLS handshake write timeout: {error}")))?;

    let native_roots = rustls_native_certs::load_native_certs();
    if native_roots.certs.is_empty() {
        let details = native_roots
            .errors
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(InitError(if details.is_empty() {
            "guest TLS root store is empty".to_string()
        } else {
            format!("load guest TLS roots: {details}")
        }));
    }
    let mut roots = rustls::RootCertStore::empty();
    for certificate in native_roots.certs {
        roots
            .add(certificate)
            .map_err(|error| InitError(format!("add guest TLS root: {error}")))?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .expect("ring supports the default TLS protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_name = rustls::pki_types::ServerName::try_from(server_name)
        .map_err(|error| InitError(format!("invalid TLS server name: {error}")))?;
    let client = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|error| InitError(format!("create guest TLS connection: {error}")))?;
    let mut tls = rustls::StreamOwned::new(client, stream);
    while tls.conn.is_handshaking() {
        if drain_connection_controls(controls, pending_controls) {
            return Ok(None);
        }
        connection_remaining(deadline, timeout_ms)?;
        match tls.conn.complete_io(&mut tls.sock) {
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut
                    || error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(InitError(format!("guest TLS handshake: {error}"))),
        }
    }
    Ok(Some(tls))
}

#[derive(Default)]
struct ActiveConnections {
    connections: Mutex<HashMap<String, mpsc::Sender<ConnectionControl>>>,
}

impl ActiveConnections {
    fn insert(&self, id: String) -> mpsc::Receiver<ConnectionControl> {
        let (sender, receiver) = mpsc::channel();
        if let Ok(mut connections) = self.connections.lock() {
            connections.insert(id, sender);
        }
        receiver
    }

    fn send(&self, id: &str, control: ConnectionControl) {
        if let Ok(connections) = self.connections.lock() {
            if let Some(sender) = connections.get(id) {
                let _ = sender.send(control);
            }
        }
    }

    fn remove(&self, id: &str) {
        if let Ok(mut connections) = self.connections.lock() {
            connections.remove(id);
        }
    }
}

#[derive(Default)]
struct ActiveSpawns {
    spawns: Mutex<HashMap<String, mpsc::Sender<SpawnControl>>>,
}

impl ActiveSpawns {
    fn insert(&self, id: String) -> mpsc::Receiver<SpawnControl> {
        let (sender, receiver) = mpsc::channel();
        if let Ok(mut spawns) = self.spawns.lock() {
            spawns.insert(id, sender);
        }
        receiver
    }

    fn send(&self, id: &str, control: SpawnControl) {
        if let Ok(spawns) = self.spawns.lock() {
            if let Some(sender) = spawns.get(id) {
                let _ = sender.send(control);
            }
        }
    }

    fn remove(&self, id: &str) {
        if let Ok(mut spawns) = self.spawns.lock() {
            spawns.remove(id);
        }
    }
}

#[derive(Default)]
struct ActiveExecs {
    execs: Mutex<HashMap<String, Arc<ExecCancellation>>>,
}

impl ActiveExecs {
    fn insert(&self, id: String) -> Arc<ExecCancellation> {
        let cancellation = Arc::new(ExecCancellation::default());
        if let Ok(mut execs) = self.execs.lock() {
            execs.insert(id, cancellation.clone());
        }
        cancellation
    }

    fn abort(&self, id: &str) {
        if let Ok(execs) = self.execs.lock() {
            if let Some(cancellation) = execs.get(id) {
                cancellation.abort();
            }
        }
    }

    fn remove(&self, id: &str) {
        if let Ok(mut execs) = self.execs.lock() {
            execs.remove(id);
        }
    }
}

#[derive(Default)]
struct ExecCancellation {
    aborted: AtomicBool,
    child_id: Mutex<Option<u32>>,
}

impl ExecCancellation {
    fn abort(&self) {
        self.aborted.store(true, Ordering::SeqCst);
        if let Some(child_id) = self.child_id.lock().ok().and_then(|child_id| *child_id) {
            terminate_child_process_group(child_id);
        }
    }

    fn set_child(&self, child_id: u32) {
        if let Ok(mut slot) = self.child_id.lock() {
            *slot = Some(child_id);
        }
        if self.is_aborted() {
            terminate_child_process_group(child_id);
        }
    }

    fn clear_child(&self) {
        if let Ok(mut slot) = self.child_id.lock() {
            *slot = None;
        }
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::SeqCst)
    }
}

fn run_guest_exec(
    id: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    cwd: String,
    timeout_ms: Option<u64>,
    cancellation: Arc<ExecCancellation>,
) -> Result<ControlFrame, InitError> {
    if argv.is_empty() {
        return Ok(ControlFrame::GuestExecComplete {
            id,
            exit_code: 127,
            stdout: Vec::new(),
            stderr: b"guest.exec argv must not be empty".to_vec(),
        });
    }

    prepare_exec_environment(&env)?;

    let output = match run_guest_exec_command(&argv, env, cwd, timeout_ms, cancellation) {
        Ok(output) => output,
        Err(ExecCommandError::Spawn(error)) => {
            return Ok(ControlFrame::GuestExecComplete {
                id,
                exit_code: 127,
                stdout: Vec::new(),
                stderr: format!("spawn guest command {}: {error}", argv[0]).into_bytes(),
            });
        }
        Err(ExecCommandError::TimedOut { stdout, stderr }) => {
            return Ok(ControlFrame::GuestExecComplete {
                id,
                exit_code: 124,
                stdout,
                stderr: append_timeout_message(stderr, timeout_ms.unwrap()),
            });
        }
        Err(ExecCommandError::Aborted { stdout, stderr }) => {
            return Ok(ControlFrame::GuestExecComplete {
                id,
                exit_code: 130,
                stdout,
                stderr: append_abort_message(stderr),
            });
        }
        Err(ExecCommandError::Wait(error)) => {
            return Err(InitError(format!(
                "wait for guest command {}: {error}",
                argv[0]
            )));
        }
    };
    let (exit_code, stderr) = exec_status(output.status, output.stderr);

    Ok(ControlFrame::GuestExecComplete {
        id,
        exit_code,
        stdout: output.stdout,
        stderr,
    })
}

struct GuestExecOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

enum ExecCommandError {
    Spawn(std::io::Error),
    Wait(std::io::Error),
    TimedOut { stdout: Vec<u8>, stderr: Vec<u8> },
    Aborted { stdout: Vec<u8>, stderr: Vec<u8> },
}

fn run_guest_exec_command(
    argv: &[String],
    env: Vec<(String, String)>,
    cwd: String,
    timeout_ms: Option<u64>,
    cancellation: Arc<ExecCancellation>,
) -> Result<GuestExecOutput, ExecCommandError> {
    let mut command = std::process::Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    configure_command_process_group(&mut command);

    command.envs(env);
    command.current_dir(cwd);
    let (mut child, child_id) =
        spawn_active_child(&mut command).map_err(ExecCommandError::Spawn)?;
    cancellation.set_child(child_id);
    let stdout = child.stdout.take().expect("stdout was configured as piped");
    let stderr = child.stderr.take().expect("stderr was configured as piped");

    let stdout_reader = read_child_output(stdout);
    let stderr_reader = read_child_output(stderr);

    let deadline = timeout_ms.and_then(exec_deadline);
    let timeout = ExecTimeout::start(child_id, timeout_ms);
    let status = match child.wait() {
        Ok(status) => status,
        Err(error) => {
            unregister_active_child(child_id);
            cancellation.clear_child();
            let _ = timeout.finish();
            return Err(ExecCommandError::Wait(error));
        }
    };

    unregister_active_child(child_id);
    let timed_out = timeout.finish();
    if timed_out {
        cancellation.clear_child();
        let grace_deadline =
            std::time::Instant::now().checked_add(std::time::Duration::from_millis(100));
        let (stdout, stderr) =
            join_output_readers_until(stdout_reader, stderr_reader, grace_deadline)
                .unwrap_or_default();
        return Err(ExecCommandError::TimedOut { stdout, stderr });
    }
    if cancellation.is_aborted() {
        cancellation.clear_child();
        let grace_deadline =
            std::time::Instant::now().checked_add(std::time::Duration::from_millis(100));
        let (stdout, stderr) =
            join_output_readers_until(stdout_reader, stderr_reader, grace_deadline)
                .unwrap_or_default();
        return Err(ExecCommandError::Aborted { stdout, stderr });
    }

    match join_output_readers_until(stdout_reader, stderr_reader, deadline) {
        Some((stdout, stderr)) => {
            cancellation.clear_child();
            Ok(GuestExecOutput {
                status,
                stdout,
                stderr,
            })
        }
        None => {
            terminate_child_process_group(child_id);
            cancellation.clear_child();
            Err(ExecCommandError::TimedOut {
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }
}

enum ExecTimeout {
    Disabled,
    Enabled {
        state: Arc<ExecTimeoutState>,
        worker: std::thread::JoinHandle<()>,
    },
}

impl ExecTimeout {
    fn start(child_id: u32, timeout_ms: Option<u64>) -> Self {
        let Some(timeout_ms) = timeout_ms else {
            return Self::Disabled;
        };
        let state = Arc::new(ExecTimeoutState {
            completed: Mutex::new(false),
            completed_changed: Condvar::new(),
            timed_out: AtomicBool::new(false),
        });
        let worker = {
            let state = state.clone();
            std::thread::spawn(move || {
                state.wait_until_deadline_or_completion(timeout_ms);
                if state.timed_out() {
                    terminate_child_process_group(child_id);
                }
            })
        };
        Self::Enabled { state, worker }
    }

    fn finish(self) -> bool {
        match self {
            Self::Disabled => false,
            Self::Enabled { state, worker } => {
                state.complete();
                let _ = worker.join();
                state.timed_out()
            }
        }
    }
}

struct ExecTimeoutState {
    completed: Mutex<bool>,
    completed_changed: Condvar,
    timed_out: AtomicBool,
}

impl ExecTimeoutState {
    fn wait_until_deadline_or_completion(&self, timeout_ms: u64) {
        let completed = self.completed.lock().unwrap();
        let (completed, result) = self
            .completed_changed
            .wait_timeout_while(
                completed,
                std::time::Duration::from_millis(timeout_ms),
                |completed| !*completed,
            )
            .unwrap();
        if !*completed && result.timed_out() {
            self.timed_out.store(true, Ordering::SeqCst);
        }
    }

    fn complete(&self) {
        if let Ok(mut completed) = self.completed.lock() {
            if !*completed {
                *completed = true;
                self.completed_changed.notify_all();
            }
        }
    }

    fn timed_out(&self) -> bool {
        self.timed_out.load(Ordering::SeqCst)
    }
}

#[cfg(unix)]
fn configure_command_process_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_command_process_group(_command: &mut std::process::Command) {}

#[cfg(unix)]
fn terminate_child_process_group(child_pid: u32) {
    let pgid = -(child_pid as libc::pid_t);
    unsafe {
        libc::kill(pgid, libc::SIGTERM);
    }
    std::thread::sleep(std::time::Duration::from_millis(100));
    unsafe {
        libc::kill(pgid, libc::SIGKILL);
    }
}

#[cfg(not(unix))]
fn terminate_child_process_group(_child_pid: u32) {}

fn read_child_output(
    mut output: impl std::io::Read + Send + 'static,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut data = Vec::new();
        let _ = output.read_to_end(&mut data);
        let _ = sender.send(data);
    });
    receiver
}

fn exec_deadline(timeout_ms: u64) -> Option<std::time::Instant> {
    std::time::Instant::now().checked_add(std::time::Duration::from_millis(timeout_ms))
}

fn join_output_readers_until(
    stdout_reader: std::sync::mpsc::Receiver<Vec<u8>>,
    stderr_reader: std::sync::mpsc::Receiver<Vec<u8>>,
    deadline: Option<std::time::Instant>,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let stdout = join_output_reader_until(stdout_reader, deadline)?;
    let stderr = join_output_reader_until(stderr_reader, deadline)?;
    Some((stdout, stderr))
}

fn join_output_reader_until(
    reader: std::sync::mpsc::Receiver<Vec<u8>>,
    deadline: Option<std::time::Instant>,
) -> Option<Vec<u8>> {
    match deadline {
        Some(deadline) => {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return reader.try_recv().ok();
            }
            reader.recv_timeout(remaining).ok()
        }
        None => Some(reader.recv().unwrap_or_default()),
    }
}

fn append_timeout_message(mut stderr: Vec<u8>, timeout_ms: u64) -> Vec<u8> {
    if !stderr.is_empty() && !stderr.ends_with(b"\n") {
        stderr.push(b'\n');
    }
    stderr.extend_from_slice(format!("sandbox exec timed out after {timeout_ms}ms\n").as_bytes());
    stderr
}

fn append_abort_message(mut stderr: Vec<u8>) -> Vec<u8> {
    if !stderr.is_empty() && !stderr.ends_with(b"\n") {
        stderr.push(b'\n');
    }
    stderr.extend_from_slice(b"sandbox exec aborted\n");
    stderr
}

fn exec_status(status: std::process::ExitStatus, mut stderr: Vec<u8>) -> (i32, Vec<u8>) {
    if let Some(code) = status.code() {
        return (code, stderr);
    }
    let signal = terminating_signal(status);
    if let Some(signal) = signal {
        if !stderr.is_empty() && !stderr.ends_with(b"\n") {
            stderr.push(b'\n');
        }
        stderr.extend_from_slice(format!("killed by signal {signal}\n").as_bytes());
        return (128 + signal, stderr);
    }
    (128, stderr)
}

fn spawn_exit_status(status: std::process::ExitStatus) -> (Option<i32>, Option<String>) {
    if let Some(code) = status.code() {
        return (Some(code), None);
    }
    if let Some(signal) = terminating_signal(status) {
        if let Some(name) = signal_name(signal) {
            return (None, Some(name.to_string()));
        }
        return (Some(128 + signal), None);
    }
    (Some(128), None)
}

#[cfg(unix)]
fn terminating_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn terminating_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

fn signal_name(signal: i32) -> Option<&'static str> {
    match signal {
        libc::SIGHUP => Some("SIGHUP"),
        libc::SIGINT => Some("SIGINT"),
        libc::SIGQUIT => Some("SIGQUIT"),
        libc::SIGTERM => Some("SIGTERM"),
        libc::SIGKILL => Some("SIGKILL"),
        _ => None,
    }
}

fn install_http_ca(root_readonly: bool) -> Result<(), InitError> {
    let certificate_path = std::path::Path::new("/run/sandbox/http-ca/http-ca.pem");
    if !certificate_path.exists() {
        return Ok(());
    }
    if root_readonly {
        return Ok(());
    }

    let certificate = std::fs::read(certificate_path)
        .map_err(|error| InitError(format!("read host HTTP CA certificate: {error}")))?;
    write_http_ca(&certificate)
}

fn prepare_exec_environment(env: &[(String, String)]) -> Result<(), InitError> {
    let _ = env;
    Ok(())
}

fn write_http_ca(certificate: &[u8]) -> Result<(), InitError> {
    std::fs::create_dir_all("/run/sandbox")
        .map_err(|error| InitError(format!("create /run/sandbox: {error}")))?;
    let certificate_path = "/run/sandbox/http-ca.pem";
    std::fs::write(certificate_path, certificate)
        .map_err(|error| InitError(format!("write host HTTP CA certificate: {error}")))?;
    install_http_ca_into_guest_trust(certificate_path)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_http_ca_into_guest_trust(certificate_path: &str) -> Result<(), InitError> {
    let installer = "/usr/lib/sandbox/install-http-ca";
    if !std::path::Path::new(installer).is_file() {
        return Err(InitError(format!(
            "install host HTTP CA certificate: guest rootfs must provide {installer}"
        )));
    }
    let mut command = std::process::Command::new(installer);
    command.arg(certificate_path);
    let output = run_init_command_output(&mut command)
        .map_err(|error| InitError(format!("run {installer}: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(InitError(format!(
        "install host HTTP CA certificate with {installer}: {}",
        String::from_utf8_lossy(&output.stderr)
    )))
}

#[cfg(not(target_os = "linux"))]
fn install_http_ca_into_guest_trust(_certificate_path: &str) -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_init_command_output(
    command: &mut std::process::Command,
) -> std::io::Result<std::process::Output> {
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());
    let (child, child_id) = spawn_active_child(command)?;
    let output = child.wait_with_output();
    unregister_active_child(child_id);
    output
}

fn send_packet(control: &mut std::fs::File, packet: &[u8]) -> Result<(), InitError> {
    control
        .write_all(packet)
        .map_err(|error| InitError(format!("write control packet: {error}")))
}

struct ControlWriter {
    control: Mutex<std::fs::File>,
    write_lock: Arc<Mutex<()>>,
}

impl ControlWriter {
    fn new(control: std::fs::File, write_lock: Arc<Mutex<()>>) -> Self {
        Self {
            control: Mutex::new(control),
            write_lock,
        }
    }

    fn send_packet(&self, packet: &[u8]) -> Result<(), InitError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| InitError("control stream writer lock poisoned".to_string()))?;
        let mut control = self
            .control
            .lock()
            .map_err(|_| InitError("control stream writer lock poisoned".to_string()))?;
        send_packet(&mut control, packet)
    }
}

fn send_control_frame(control: &Arc<ControlWriter>, frame: ControlFrame) -> Result<(), InitError> {
    let packet = frame
        .encode_packet()
        .map_err(|error| InitError(format!("encode control packet: {error}")))?;
    control.send_packet(&packet)
}

fn write_file_creating_parent(
    path: &str,
    contents: impl AsRef<[u8]>,
    operation: &str,
) -> Result<(), InitError> {
    let path = std::path::Path::new(path);
    ensure_parent_directory(path)?;
    std::fs::write(path, contents.as_ref())
        .map_err(|error| InitError(format!("{operation}: {error}")))
}

fn ensure_parent_directory(path: &std::path::Path) -> Result<(), InitError> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)
        .map_err(|error| InitError(format!("create {}: {error}", parent.display())))
}

#[derive(Debug)]
struct InitError(String);

impl InitError {
    #[cfg(target_os = "linux")]
    fn last_os(operation: &str) -> Self {
        Self(format!("{operation}: {}", std::io::Error::last_os_error()))
    }
}

impl std::fmt::Display for InitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for InitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_protocol::ControlFrame;

    #[test]
    fn init_ready_packet_uses_shared_protocol() {
        assert_eq!(
            ControlFrame::decode_packet(&init_ready_packet(true).unwrap()).unwrap(),
            ControlFrame::InitReady {
                root_readonly: true,
                init_name: "sandbox-init".to_string(),
            },
        );
    }

    #[test]
    fn mount_field_decoding_preserves_delimiters() {
        let encoded =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("/mnt/with=equals;semicolon");
        assert_eq!(
            decode_mount_field(&encoded).unwrap(),
            "/mnt/with=equals;semicolon",
        );
    }

    #[test]
    fn block_mount_at_internal_http_ca_is_delayed() {
        assert!(super::block_mount_after_http_ca("/run/sandbox/http-ca"));
        assert!(!super::block_mount_after_http_ca(
            "/run/sandbox/http-ca/state"
        ));
        assert!(!super::block_mount_after_http_ca("/run/sandbox"));
        assert!(!super::block_mount_after_http_ca("/workspace"));
    }

    #[test]
    fn root_file_write_creates_missing_parent_directory() {
        let root = unique_test_dir("root-file-parent");
        let file = root.join("etc/hosts");
        write_file_creating_parent(
            file.to_str().unwrap(),
            "127.0.0.1 localhost\n",
            "write test hosts",
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "127.0.0.1 localhost\n"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("sandbox-init-{name}-{}-{now}", std::process::id()))
    }
}
