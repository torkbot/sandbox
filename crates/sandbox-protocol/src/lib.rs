//! Shared host/guest control protocol.
//!
//! This crate intentionally stays independent of libkrun and napi-rs so the
//! guest init and host runtime can share frame definitions without dragging in
//! either side's implementation dependencies.

use std::fmt;
use std::io::{self, Read};

/// Reserved guest vsock port for the init control plane.
pub const INIT_CONTROL_PORT: u32 = 1024;

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
                        value.as_str().map(str::to_string).ok_or_else(|| {
                            ControlFrameError::new("guest.exec argv must be strings")
                        })
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

    pub fn encode_packet(&self) -> Result<Vec<u8>, ControlFrameError> {
        let frame = self.encode()?;
        let frame_len = u32::try_from(frame.len())
            .map_err(|_| ControlFrameError::new("control frame exceeds u32 length"))?;
        let mut packet = Vec::with_capacity(4 + frame.len());
        packet.extend_from_slice(&frame_len.to_le_bytes());
        packet.extend_from_slice(&frame);
        Ok(packet)
    }

    pub fn decode_packet(bytes: &[u8]) -> Result<Self, ControlFrameError> {
        if bytes.len() < 4 {
            return Err(ControlFrameError::new(
                "control packet missing length prefix",
            ));
        }

        let frame_len = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
        let frame = bytes
            .get(4..4 + frame_len)
            .ok_or_else(|| ControlFrameError::new("control packet body is truncated"))?;
        if bytes.len() != 4 + frame_len {
            return Err(ControlFrameError::new("control packet has trailing bytes"));
        }

        Self::decode(frame)
    }

    pub fn decode_packet_from_reader(reader: &mut impl Read) -> Result<Self, ControlFrameError> {
        let mut len = [0; 4];
        match reader.read_exact(&mut len) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(ControlFrameError::eof());
            }
            Err(error) => return Err(ControlFrameError::new(error.to_string())),
        }

        let frame_len = u32::from_le_bytes(len) as usize;
        let mut frame = vec![0; frame_len];
        reader
            .read_exact(&mut frame)
            .map_err(|error| ControlFrameError::new(error.to_string()))?;
        Self::decode(&frame)
    }
}

impl ControlFrameError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn eof() -> Self {
        Self::new("control stream ended")
    }

    pub fn is_eof(&self) -> bool {
        self.message == "control stream ended"
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

    #[test]
    fn packet_encoding_prefixes_frame_length() {
        let frame = ControlFrame::InitReady {
            root_readonly: true,
            init_name: "sandbox-init".to_string(),
        };

        let packet = frame.encode_packet().unwrap();
        let frame_len = u32::from_le_bytes(packet[0..4].try_into().unwrap()) as usize;
        assert_eq!(packet.len(), 4 + frame_len);
        assert_eq!(ControlFrame::decode_packet(&packet).unwrap(), frame);
    }

    #[test]
    fn packet_decoder_rejects_partial_and_extra_bytes() {
        let frame = ControlFrame::GuestExec {
            id: "test".to_string(),
            argv: vec!["/bin/true".to_string()],
        };
        let mut packet = frame.encode_packet().unwrap();

        let truncated = &packet[..packet.len() - 1];
        assert_eq!(
            ControlFrame::decode_packet(truncated)
                .unwrap_err()
                .to_string(),
            "control packet body is truncated",
        );

        packet.push(0);
        assert_eq!(
            ControlFrame::decode_packet(&packet)
                .unwrap_err()
                .to_string(),
            "control packet has trailing bytes",
        );
    }
}
