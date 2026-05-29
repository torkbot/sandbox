use base64::Engine;
use sandbox_protocol::ControlFrame;
#[cfg(target_os = "linux")]
use sandbox_protocol::INIT_CONTROL_PORT;
use std::io::Write;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

fn main() {
    if let Err(error) = run() {
        eprintln!("sandbox-init failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), InitError> {
    mount_kernel_filesystems()?;
    configure_http_network(std::env::args().skip(1))?;
    install_http_ca(std::env::var("SANDBOX_HTTP_CA_PEM_B64").ok())?;
    mount_virtual_filesystems(
        std::env::args().skip(1),
        std::env::var("SANDBOX_VIRTIOFS_MOUNTS").ok(),
    )?;
    let packet = init_ready_packet(true)?;
    let mut control = connect_control()?;
    send_init_ready(&mut control, &packet)?;
    run_control_loop(&mut control)?;
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
                send_locked_packet(&write_lock, control, &packet)?;
            }
            ControlFrame::GuestSpawn { id, argv, env } => {
                let writer = Arc::new(ControlWriter::new(
                    control
                        .try_clone()
                        .map_err(|error| InitError(format!("clone control stream: {error}")))?,
                    write_lock.clone(),
                ));
                match run_guest_spawn(id.clone(), argv, env, writer.clone()) {
                    Ok(()) => {}
                    Err(error) => {
                        send_control_frame(
                            &writer,
                            ControlFrame::GuestSpawnStderr {
                                id: id.clone(),
                                data: format!("spawn guest command: {error}\n").into_bytes(),
                            },
                        )?;
                        send_control_frame(
                            &writer,
                            ControlFrame::GuestSpawnExit {
                                id: id.clone(),
                                exit_code: 127,
                            },
                        )?;
                        send_control_frame(&writer, ControlFrame::GuestSpawnStreamsClosed { id })?;
                    }
                }
            }
            ControlFrame::InitReady { .. }
            | ControlFrame::GuestExecComplete { .. }
            | ControlFrame::GuestSpawnStarted { .. }
            | ControlFrame::GuestSpawnStdout { .. }
            | ControlFrame::GuestSpawnStderr { .. }
            | ControlFrame::GuestSpawnExit { .. }
            | ControlFrame::GuestSpawnStreamsClosed { .. } => {}
        }
    }
}

fn run_guest_spawn(
    id: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    control: Arc<ControlWriter>,
) -> Result<(), InitError> {
    if argv.is_empty() {
        return Err(InitError("guest.spawn argv must not be empty".to_string()));
    }

    prepare_exec_environment(&env)?;

    let mut command = std::process::Command::new(&argv[0]);
    command.args(&argv[1..]);
    if std::path::Path::new("/run/sandbox/http-ca.pem").exists() {
        command.env("SSL_CERT_FILE", "/run/sandbox/http-ca.pem");
        command.env("CURL_CA_BUNDLE", "/run/sandbox/http-ca.pem");
    }

    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .envs(env)
        .spawn()
        .map_err(|error| InitError(format!("{}: {error}", argv[0])))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| InitError("spawned command did not expose stdout".to_string()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| InitError("spawned command did not expose stderr".to_string()))?;
    send_control_frame(&control, ControlFrame::GuestSpawnStarted { id: id.clone() })?;

    let (events, event_receiver) = mpsc::channel();
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
    std::thread::spawn(move || {
        let status = child.wait();
        let exit_code = match status {
            Ok(status) => exec_status(status, Vec::new()).0,
            Err(_) => 128,
        };
        let _ = events.send(SpawnOutputEvent::Exit(exit_code));
    });

    std::thread::spawn(move || {
        run_spawn_output_coordinator(id, control, event_receiver);
    });

    Ok(())
}

fn pump_spawn_output(
    mut reader: impl std::io::Read + Send + 'static,
    events: mpsc::Sender<SpawnOutputEvent>,
    data_event: fn(Vec<u8>) -> SpawnOutputEvent,
    closed_event: SpawnOutputEvent,
) {
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

fn run_spawn_output_coordinator(
    id: String,
    control: Arc<ControlWriter>,
    events: mpsc::Receiver<SpawnOutputEvent>,
) {
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut exit_code = None;
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
            SpawnOutputEvent::StdoutClosed => stdout_open = false,
            SpawnOutputEvent::StderrClosed => stderr_open = false,
            SpawnOutputEvent::Exit(code) => {
                exit_code = Some(code);
                let _ = send_control_frame(
                    &control,
                    ControlFrame::GuestSpawnExit {
                        id: id.clone(),
                        exit_code: code,
                    },
                );
            }
        }

        if exit_code.is_some() && !stdout_open && !stderr_open {
            break;
        }
    }

    let _ = send_control_frame(&control, ControlFrame::GuestSpawnStreamsClosed { id });
}

enum SpawnOutputEvent {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    StdoutClosed,
    StderrClosed,
    Exit(i32),
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
    install_http_ca_into_guest_trust(certificate)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn install_http_ca_into_guest_trust(certificate: &[u8]) -> Result<(), InitError> {
    if std::path::Path::new("/usr/local/share/ca-certificates").is_dir()
        && command_exists("/usr/sbin/update-ca-certificates")
    {
        std::fs::write(
            "/usr/local/share/ca-certificates/sandbox-http-interception-ca.crt",
            certificate,
        )
        .map_err(|error| InitError(format!("write Alpine/Debian CA certificate: {error}")))?;
        run_setup_command("/usr/sbin/update-ca-certificates", &[])?;
        return Ok(());
    }

    if std::path::Path::new("/etc/pki/ca-trust/source/anchors").is_dir()
        && command_exists("/usr/bin/update-ca-trust")
    {
        std::fs::write(
            "/etc/pki/ca-trust/source/anchors/sandbox-http-interception-ca.pem",
            certificate,
        )
        .map_err(|error| InitError(format!("write pki CA certificate: {error}")))?;
        run_setup_command("/usr/bin/update-ca-trust", &["extract"])?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn command_exists(path: &str) -> bool {
    std::path::Path::new(path).is_file()
}

#[cfg(not(target_os = "linux"))]
fn install_http_ca_into_guest_trust(_certificate: &[u8]) -> Result<(), InitError> {
    Ok(())
}

fn send_packet(control: &mut std::fs::File, packet: &[u8]) -> Result<(), InitError> {
    control
        .write_all(packet)
        .map_err(|error| InitError(format!("write control packet: {error}")))
}

fn send_locked_packet(
    lock: &Arc<Mutex<()>>,
    control: &mut std::fs::File,
    packet: &[u8],
) -> Result<(), InitError> {
    let _guard = lock
        .lock()
        .map_err(|_| InitError("control stream writer lock poisoned".to_string()))?;
    send_packet(control, packet)
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
