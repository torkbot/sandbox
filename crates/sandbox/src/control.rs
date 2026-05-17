//! Guest control channel model.
//!
//! libkrun exposes vsock-to-UNIX-socket mappings. The Node.js package should
//! adapt one of those sockets to TorkBot's `Transport` shape: an async stream
//! of decoded messages plus async `send` and `close`.

use std::fmt;

/// Reserved guest vsock port for the init control plane.
pub const INIT_CONTROL_PORT: u32 = 1024;

/// Minimal envelope for messages exchanged between the host runtime and guest
/// init before higher-level RPC framing is attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEnvelope {
    pub stream_id: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFrame {
    InitReady {
        root_readonly: bool,
        init_name: String,
    },
    GuestExec {
        id: String,
        argv: Vec<String>,
    },
    GuestExecComplete {
        id: String,
        exit_code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrameError {
    message: String,
}

impl ControlFrame {
    pub fn encode(&self) -> Result<Vec<u8>, ControlFrameError> {
        let document = match self {
            Self::InitReady {
                root_readonly,
                init_name,
            } => bson::doc! {
                "type": "init.ready",
                "rootReadonly": *root_readonly,
                "initName": init_name,
            },
            Self::GuestExec { id, argv } => bson::doc! {
                "type": "guest.exec",
                "id": id,
                "argv": argv,
            },
            Self::GuestExecComplete {
                id,
                exit_code,
                stdout,
                stderr,
            } => bson::doc! {
                "type": "guest.exec.complete",
                "id": id,
                "exitCode": *exit_code,
                "stdout": bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: stdout.clone(),
                },
                "stderr": bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: stderr.clone(),
                },
            },
        };

        document
            .to_vec()
            .map_err(|error| ControlFrameError::new(error.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ControlFrameError> {
        let document = bson::Document::from_reader(bytes)
            .map_err(|error| ControlFrameError::new(error.to_string()))?;
        let frame_type = document
            .get_str("type")
            .map_err(|_| ControlFrameError::new("control frame missing type"))?;

        match frame_type {
            "init.ready" => Ok(Self::InitReady {
                root_readonly: document
                    .get_bool("rootReadonly")
                    .map_err(|_| ControlFrameError::new("init.ready missing rootReadonly"))?,
                init_name: document
                    .get_str("initName")
                    .map_err(|_| ControlFrameError::new("init.ready missing initName"))?
                    .to_string(),
            }),
            "guest.exec" => Ok(Self::GuestExec {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.exec missing id"))?
                    .to_string(),
                argv: document
                    .get_array("argv")
                    .map_err(|_| ControlFrameError::new("guest.exec missing argv"))?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_string)
                            .ok_or_else(|| ControlFrameError::new("guest.exec argv must be strings"))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            }),
            "guest.exec.complete" => Ok(Self::GuestExecComplete {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.exec.complete missing id"))?
                    .to_string(),
                exit_code: document
                    .get_i32("exitCode")
                    .map_err(|_| ControlFrameError::new("guest.exec.complete missing exitCode"))?,
                stdout: document
                    .get_binary_generic("stdout")
                    .map_err(|_| ControlFrameError::new("guest.exec.complete missing stdout"))?
                    .to_vec(),
                stderr: document
                    .get_binary_generic("stderr")
                    .map_err(|_| ControlFrameError::new("guest.exec.complete missing stderr"))?
                    .to_vec(),
            }),
            other => Err(ControlFrameError::new(format!(
                "unknown control frame type: {other}"
            ))),
        }
    }
}

impl ControlFrameError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ControlFrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ControlFrameError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_guest_exec_frame() {
        let frame = ControlFrame::GuestExec {
            id: "test".to_string(),
            argv: vec!["/bin/true".to_string()],
        };

        let encoded = frame.encode().unwrap();
        assert_eq!(ControlFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn round_trips_exec_complete_with_binary_output() {
        let frame = ControlFrame::GuestExecComplete {
            id: "test".to_string(),
            exit_code: 0,
            stdout: b"ok\n".to_vec(),
            stderr: Vec::new(),
        };

        let encoded = frame.encode().unwrap();
        assert_eq!(ControlFrame::decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn rejects_unknown_frame_types() {
        let encoded = bson::doc! { "type": "unknown" }.to_vec().unwrap();
        let err = ControlFrame::decode(&encoded).unwrap_err();

        assert_eq!(err.to_string(), "unknown control frame type: unknown");
    }
}
