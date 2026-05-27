use base64::Engine;
use sandbox_protocol::ControlFrame;
#[cfg(target_os = "linux")]
use sandbox_protocol::INIT_CONTROL_PORT;

fn main() {
    if let Err(error) = run() {
        eprintln!("sandbox-init failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), InitError> {
    let rootfs_overlay_enabled = prepare_rootfs_overlay(
        std::env::args().skip(1),
        std::env::var("SANDBOX_ROOTFS_OVERLAY").ok(),
        std::env::var("SANDBOX_ROOTFS_OVERLAY_VIRTIOFS").ok(),
    )?;
    mount_kernel_filesystems()?;
    configure_http_network(std::env::args().skip(1))?;
    install_http_ca(std::env::var("SANDBOX_HTTP_CA_PEM_B64").ok())?;
    mount_virtual_filesystems(
        std::env::args().skip(1),
        std::env::var("SANDBOX_VIRTIOFS_MOUNTS").ok(),
    )?;
    let packet = init_ready_packet(!rootfs_overlay_enabled)?;
    let mut control = connect_control()?;
    send_init_ready(&mut control, &packet)?;
    run_control_loop(&mut control)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_rootfs_overlay(
    args: impl Iterator<Item = String>,
    mode: Option<String>,
    virtiofs_tag: Option<String>,
) -> Result<bool, InitError> {
    mount_fs("proc", "/proc", "proc", 0)?;
    let mut overlay_virtiofs = virtiofs_tag;
    let enabled = mode.as_deref() == Some("writable")
        || args.into_iter().any(|arg| {
            if let Some(tag) = arg.strip_prefix("--rootfs-overlay-virtiofs=") {
                overlay_virtiofs = Some(tag.to_string());
            }
            arg == "--rootfs-overlay=writable"
        })
        || read_key_value_from_proc_cmdline("SANDBOX_ROOTFS_OVERLAY").as_deref()
            == Some("writable");
    if !enabled {
        return Ok(false);
    }

    raise_console_log_level();
    mount_fs("tmpfs", "/run", "tmpfs", 0)?;
    let (upperdir, workdir) = if let Some(tag) = overlay_virtiofs {
        std::fs::create_dir_all("/run/sandbox-rootfs-overlay")
            .map_err(|error| InitError(format!("create overlay virtiofs mountpoint: {error}")))?;
        mount_virtiofs(&tag, "/run/sandbox-rootfs-overlay", false)?;
        (
            "/run/sandbox-rootfs-overlay/upper".to_string(),
            "/run/sandbox-rootfs-overlay/work".to_string(),
        )
    } else {
        (
            "/run/sandbox-rootfs-upper".to_string(),
            "/run/sandbox-rootfs-work".to_string(),
        )
    };
    std::fs::create_dir_all(&upperdir)
        .map_err(|error| InitError(format!("create overlay upperdir: {error}")))?;
    std::fs::create_dir_all(&workdir)
        .map_err(|error| InitError(format!("create overlay workdir: {error}")))?;
    std::fs::create_dir_all("/run/sandbox-rootfs-root")
        .map_err(|error| InitError(format!("create overlay root: {error}")))?;
    let overlay_upper_diagnostics = diagnose_overlay_upper(&workdir);

    mount_overlay_root(
        "/run/sandbox-rootfs-root",
        &format!("lowerdir=/,upperdir={upperdir},workdir={workdir},userxattr"),
    )
    .map_err(|error| InitError(format!("{error}; {overlay_upper_diagnostics}")))?;

    std::env::set_current_dir("/run/sandbox-rootfs-root")
        .map_err(|error| InitError(format!("chdir overlay root: {error}")))?;
    chroot(".")?;
    std::env::set_current_dir("/")
        .map_err(|error| InitError(format!("chdir / after overlay chroot: {error}")))?;
    Ok(true)
}

#[cfg(target_os = "linux")]
fn raise_console_log_level() {
    let _ = std::fs::write("/proc/sys/kernel/printk", "8 4 1 7\n");
}

#[cfg(target_os = "linux")]
fn diagnose_overlay_upper(workdir: &str) -> String {
    format!(
        "overlay preflight: d_type={}, userxattr={}, rename_whiteout={}",
        diagnose_overlay_dtype(workdir),
        diagnose_overlay_xattr(workdir),
        diagnose_overlay_rename_whiteout(workdir)
    )
}

#[cfg(target_os = "linux")]
fn diagnose_overlay_dtype(workdir: &str) -> String {
    let path = format!("{workdir}/__sandbox_dtype_probe");
    let result = std::fs::create_dir(&path)
        .and_then(|()| {
            let mut found = false;
            for entry in std::fs::read_dir(workdir)? {
                let entry = entry?;
                if entry.file_name() == "__sandbox_dtype_probe" {
                    found = entry.file_type()?.is_dir();
                }
            }
            Ok(found)
        })
        .map_err(|error| error.to_string());
    let _ = std::fs::remove_dir(&path);
    match result {
        Ok(found) => found.to_string(),
        Err(error) => format!("err:{error}"),
    }
}

#[cfg(target_os = "linux")]
fn diagnose_overlay_xattr(workdir: &str) -> String {
    use std::ffi::CString;

    let path = match CString::new(workdir) {
        Ok(path) => path,
        Err(error) => return format!("err:{error}"),
    };
    let name = CString::new("user.overlay.opaque").unwrap();
    let result =
        unsafe { libc::setxattr(path.as_ptr(), name.as_ptr(), b"0".as_ptr().cast(), 1, 0) };
    let status = if result == 0 {
        "ok".to_string()
    } else {
        std::io::Error::last_os_error().to_string()
    };
    let _ = unsafe { libc::removexattr(path.as_ptr(), name.as_ptr()) };
    status
}

#[cfg(target_os = "linux")]
fn diagnose_overlay_rename_whiteout(workdir: &str) -> String {
    use std::ffi::CString;

    let source = format!("{workdir}/__sandbox_rename_whiteout_source");
    let dest = format!("{workdir}/__sandbox_rename_whiteout_dest");
    let _ = std::fs::write(&source, b"x");
    let source_c = match CString::new(source.as_str()) {
        Ok(path) => path,
        Err(error) => return format!("err:{error}"),
    };
    let dest_c = match CString::new(dest.as_str()) {
        Ok(path) => path,
        Err(error) => return format!("err:{error}"),
    };
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source_c.as_ptr(),
            libc::AT_FDCWD,
            dest_c.as_ptr(),
            libc::RENAME_WHITEOUT,
        )
    };
    let status = if result != 0 {
        format!("err:{}", std::io::Error::last_os_error())
    } else {
        let whiteout_xattr = getxattr_size(&source, "user.overlay.whiteout")
            .map_or_else(|error| format!("err:{error}"), |size| format!("ok:{size}"));
        format!("ok xattr={whiteout_xattr}")
    };
    let _ = std::fs::remove_file(&source);
    let _ = std::fs::remove_file(&dest);
    status
}

#[cfg(target_os = "linux")]
fn getxattr_size(path: &str, name: &str) -> Result<isize, std::io::Error> {
    use std::ffi::CString;

    let path = CString::new(path).unwrap();
    let name = CString::new(name).unwrap();
    let result = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

#[cfg(not(target_os = "linux"))]
fn prepare_rootfs_overlay(
    _args: impl Iterator<Item = String>,
    _mode: Option<String>,
    _virtiofs_tag: Option<String>,
) -> Result<bool, InitError> {
    Ok(false)
}

#[cfg(target_os = "linux")]
fn mount_overlay_root(target: &str, options: &str) -> Result<(), InitError> {
    use std::ffi::CString;

    let source = CString::new("overlay").unwrap();
    let target =
        CString::new(target).map_err(|_| InitError("overlay target contains nul".to_string()))?;
    let fstype = CString::new("overlay").unwrap();
    let options =
        CString::new(options).map_err(|_| InitError("overlay options contain nul".to_string()))?;
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
        return Err(InitError::last_os("mount writable root overlay"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn chroot(path: &str) -> Result<(), InitError> {
    use std::ffi::CString;

    let path = CString::new(path).map_err(|_| InitError("chroot path contains nul".to_string()))?;
    let result = unsafe { libc::chroot(path.as_ptr()) };
    if result < 0 {
        return Err(InitError::last_os("chroot overlay root"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn configure_http_network(args: impl Iterator<Item = String>) -> Result<(), InitError> {
    let enabled = args.into_iter().any(|arg| arg == "--http-network")
        || read_flag_from_proc_cmdline("SANDBOX_HTTP_NETWORK");
    if !enabled {
        return Ok(());
    }

    run_setup_command("/sbin/ip", &["link", "set", "eth0", "up"])?;
    run_setup_command("/sbin/ip", &["addr", "add", "10.0.2.2/24", "dev", "eth0"])?;
    run_setup_command("/sbin/ip", &["route", "add", "default", "via", "10.0.2.1"])?;
    install_resolver_config()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn configure_http_network(_args: impl Iterator<Item = String>) -> Result<(), InitError> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_setup_command(program: &str, args: &[&str]) -> Result<(), InitError> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|error| InitError(format!("run setup command {program}: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(InitError(format!(
        "setup command failed: {program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    )))
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
        std::fs::write("/etc/resolv.conf", RESOLV_CONF)
            .map_err(|error| InitError(format!("write /etc/resolv.conf: {error}")))?;
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
fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
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
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::EBUSY) {
            return Ok(());
        }
        return Err(InitError::last_os(&format!("mount {target}")));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_directory_mode(path: &str, mode: u32) -> Result<(), InitError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| InitError(format!("set mode on {path}: {error}")))
}

#[cfg(target_os = "linux")]
fn mount_virtual_filesystems(
    args: impl Iterator<Item = String>,
    env_mounts: Option<String>,
) -> Result<(), InitError> {
    use std::path::Path;

    let mounts = args
        .filter_map(|arg| arg.strip_prefix("--virtiofs-mounts=").map(str::to_string))
        .next()
        .or(env_mounts)
        .or_else(read_mounts_from_proc_cmdline);
    let Some(mounts) = mounts else { return Ok(()) };

    for mount in mounts.split(';').filter(|mount| !mount.is_empty()) {
        let parts = mount.split(':').collect::<Vec<_>>();
        let [tag, path, mode] = parts.as_slice() else {
            return Err(InitError(format!(
                "invalid virtual filesystem mount: {mount}"
            )));
        };
        let tag = decode_mount_field(tag)?;
        let path = decode_mount_field(path)?;
        if !Path::new(&path).is_dir() {
            return Err(InitError(format!(
                "virtual filesystem mount point does not exist: {path}"
            )));
        }

        let readonly = *mode != "rw";
        mount_virtiofs(&tag, &path, readonly)?;
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
fn mount_virtual_filesystems(
    _args: impl Iterator<Item = String>,
    _env_mounts: Option<String>,
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

#[cfg(target_os = "linux")]
fn read_key_value_from_proc_cmdline(key: &str) -> Option<String> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").ok()?;
    for token in cmdline.split_ascii_whitespace() {
        let token = token.trim_matches('"');
        if let Some(value) = token.strip_prefix(&format!("{key}=")) {
            return Some(value.trim_matches('"').to_string());
        }
    }
    None
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
    loop {
        let frame = match ControlFrame::decode_packet_from_reader(control) {
            Ok(frame) => frame,
            Err(error) if error.is_eof() => return Ok(()),
            Err(error) => return Err(InitError(format!("read control packet: {error}"))),
        };

        match frame {
            ControlFrame::GuestExec { id, argv, env } => {
                let response = run_guest_exec(id, argv, env)?;
                let packet = response
                    .encode_packet()
                    .map_err(|error| InitError(format!("encode exec completion: {error}")))?;
                send_packet(control, &packet)?;
            }
            ControlFrame::InitReady { .. } | ControlFrame::GuestExecComplete { .. } => {}
        }
    }
}

fn run_guest_exec(
    id: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
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

    let mut command = std::process::Command::new(&argv[0]);
    command.args(&argv[1..]);
    if std::path::Path::new("/run/sandbox/http-ca.pem").exists() {
        command.env("SSL_CERT_FILE", "/run/sandbox/http-ca.pem");
        command.env("CURL_CA_BUNDLE", "/run/sandbox/http-ca.pem");
    }
    let output = match command.envs(env).output() {
        Ok(output) => output,
        Err(error) => {
            return Ok(ControlFrame::GuestExecComplete {
                id,
                exit_code: 127,
                stdout: Vec::new(),
                stderr: format!("spawn guest command {}: {error}", argv[0]).into_bytes(),
            });
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

#[cfg(unix)]
fn terminating_signal(status: std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn terminating_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

fn install_http_ca(certificate: Option<String>) -> Result<(), InitError> {
    let Some(certificate) = certificate else {
        return Ok(());
    };

    let certificate = base64::engine::general_purpose::STANDARD
        .decode(certificate)
        .map_err(|error| InitError(format!("decode boot HTTP CA certificate: {error}")))?;
    write_http_ca(&certificate)
}

fn prepare_exec_environment(env: &[(String, String)]) -> Result<(), InitError> {
    let Some((_, certificate)) = env.iter().find(|(key, _)| key == "SANDBOX_HTTP_CA_PEM_B64")
    else {
        return Ok(());
    };

    let certificate = base64::engine::general_purpose::STANDARD
        .decode(certificate)
        .map_err(|error| InitError(format!("decode host HTTP CA certificate: {error}")))?;
    write_http_ca(&certificate)?;
    Ok(())
}

fn write_http_ca(certificate: &[u8]) -> Result<(), InitError> {
    std::fs::create_dir_all("/run/sandbox")
        .map_err(|error| InitError(format!("create /run/sandbox: {error}")))?;
    std::fs::write("/run/sandbox/http-ca.pem", certificate)
        .map_err(|error| InitError(format!("write host HTTP CA certificate: {error}")))?;
    Ok(())
}

fn send_packet(control: &mut std::fs::File, packet: &[u8]) -> Result<(), InitError> {
    use std::io::Write;

    control
        .write_all(packet)
        .map_err(|error| InitError(format!("write control packet: {error}")))
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
}
