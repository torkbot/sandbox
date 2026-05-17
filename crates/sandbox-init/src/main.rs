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
    let packet = init_ready_packet()?;
    let mut control = connect_control()?;
    send_init_ready(&mut control, &packet)?;
    run_control_loop(&mut control)?;
    Ok(())
}

fn init_ready_packet() -> Result<Vec<u8>, InitError> {
    ControlFrame::InitReady {
        root_readonly: true,
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
            ControlFrame::GuestExec { id, argv } => {
                let response = run_guest_exec(id, argv)?;
                let packet = response
                    .encode_packet()
                    .map_err(|error| InitError(format!("encode exec completion: {error}")))?;
                send_packet(control, &packet)?;
            }
            ControlFrame::InitReady { .. } | ControlFrame::GuestExecComplete { .. } => {}
        }
    }
}

fn run_guest_exec(id: String, argv: Vec<String>) -> Result<ControlFrame, InitError> {
    if argv.is_empty() {
        return Ok(ControlFrame::GuestExecComplete {
            id,
            exit_code: 127,
            stdout: Vec::new(),
            stderr: b"guest.exec argv must not be empty".to_vec(),
        });
    }

    let output = std::process::Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .map_err(|error| InitError(format!("spawn guest command {}: {error}", argv[0])))?;

    Ok(ControlFrame::GuestExecComplete {
        id,
        exit_code: output.status.code().unwrap_or(128),
        stdout: output.stdout,
        stderr: output.stderr,
    })
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
            ControlFrame::decode_packet(&init_ready_packet().unwrap()).unwrap(),
            ControlFrame::InitReady {
                root_readonly: true,
                init_name: "sandbox-init".to_string(),
            },
        );
    }
}
