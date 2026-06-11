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
        env: Vec<(String, String)>,
        timeout_ms: Option<u64>,
    },
    GuestExecAbort {
        id: String,
    },
    GuestSpawn {
        id: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        stdin: GuestSpawnStdio,
        stdout: GuestSpawnStdio,
        stderr: GuestSpawnStdio,
        pty: Option<GuestPtySize>,
    },
    GuestSpawnStdin {
        id: String,
        data: Vec<u8>,
    },
    GuestSpawnStdinClose {
        id: String,
    },
    GuestSpawnSignal {
        id: String,
        signal: String,
    },
    GuestSpawnResize {
        id: String,
        rows: u16,
        cols: u16,
    },
    GuestSpawnStarted {
        id: String,
    },
    GuestSpawnStdout {
        id: String,
        data: Vec<u8>,
    },
    GuestSpawnStderr {
        id: String,
        data: Vec<u8>,
    },
    GuestSpawnExit {
        id: String,
        exit_code: Option<i32>,
        signal: Option<String>,
    },
    GuestSpawnStreamsClosed {
        id: String,
    },
    GuestExecComplete {
        id: String,
        exit_code: i32,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestSpawnStdio {
    Pipe,
    Pty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestPtySize {
    pub rows: u16,
    pub cols: u16,
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
            Self::GuestExec {
                id,
                argv,
                env,
                timeout_ms,
            } => {
                let mut document = bson::doc! {
                    "type": "guest.exec",
                    "id": id,
                    "argv": argv,
                    "env": env.iter().map(|(key, value)| bson::doc! {
                        "key": key,
                        "value": value,
                    }).collect::<Vec<_>>(),
                };
                if let Some(timeout_ms) = timeout_ms {
                    let timeout_ms = i64::try_from(*timeout_ms)
                        .map_err(|_| ControlFrameError::new("guest.exec timeoutMs exceeds i64"))?;
                    document.insert("timeoutMs", timeout_ms);
                }
                document
            }
            Self::GuestExecAbort { id } => bson::doc! {
                "type": "guest.exec.abort",
                "id": id,
            },
            Self::GuestSpawn {
                id,
                argv,
                env,
                stdin,
                stdout,
                stderr,
                pty,
            } => {
                let mut document = bson::doc! {
                    "type": "guest.spawn",
                    "id": id,
                    "argv": argv,
                    "env": env.iter().map(|(key, value)| bson::doc! {
                        "key": key,
                        "value": value,
                    }).collect::<Vec<_>>(),
                    "stdin": stdin.as_str(),
                    "stdout": stdout.as_str(),
                    "stderr": stderr.as_str(),
                };
                if let Some(pty) = pty {
                    document.insert(
                        "pty",
                        bson::doc! {
                            "rows": i32::from(pty.rows),
                            "cols": i32::from(pty.cols),
                        },
                    );
                }
                document
            }
            Self::GuestSpawnStdin { id, data } => bson::doc! {
                "type": "guest.spawn.stdin",
                "id": id,
                "data": bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: data.clone(),
                },
            },
            Self::GuestSpawnStdinClose { id } => bson::doc! {
                "type": "guest.spawn.stdin.close",
                "id": id,
            },
            Self::GuestSpawnSignal { id, signal } => bson::doc! {
                "type": "guest.spawn.signal",
                "id": id,
                "signal": signal,
            },
            Self::GuestSpawnResize { id, rows, cols } => bson::doc! {
                "type": "guest.spawn.resize",
                "id": id,
                "rows": i32::from(*rows),
                "cols": i32::from(*cols),
            },
            Self::GuestSpawnStarted { id } => bson::doc! {
                "type": "guest.spawn.started",
                "id": id,
            },
            Self::GuestSpawnStdout { id, data } => bson::doc! {
                "type": "guest.spawn.stdout",
                "id": id,
                "data": bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: data.clone(),
                },
            },
            Self::GuestSpawnStderr { id, data } => bson::doc! {
                "type": "guest.spawn.stderr",
                "id": id,
                "data": bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: data.clone(),
                },
            },
            Self::GuestSpawnExit {
                id,
                exit_code,
                signal,
            } => {
                let mut document = bson::doc! {
                    "type": "guest.spawn.exit",
                    "id": id,
                };
                if let Some(exit_code) = exit_code {
                    document.insert("exitCode", *exit_code);
                }
                if let Some(signal) = signal {
                    document.insert("signal", signal);
                }
                document
            }
            Self::GuestSpawnStreamsClosed { id } => bson::doc! {
                "type": "guest.spawn.streams.closed",
                "id": id,
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
                env: document
                    .get_array("env")
                    .ok()
                    .map(|values| {
                        values
                            .iter()
                            .map(|value| {
                                let document = value.as_document().ok_or_else(|| {
                                    ControlFrameError::new(
                                        "guest.exec env entries must be documents",
                                    )
                                })?;
                                let key = document
                                    .get_str("key")
                                    .map_err(|_| {
                                        ControlFrameError::new(
                                            "guest.exec env key must be a string",
                                        )
                                    })?
                                    .to_string();
                                let value = document
                                    .get_str("value")
                                    .map_err(|_| {
                                        ControlFrameError::new(
                                            "guest.exec env value must be a string",
                                        )
                                    })?
                                    .to_string();
                                Ok((key, value))
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .transpose()?
                    .unwrap_or_default(),
                timeout_ms: read_optional_u64(&document, "timeoutMs", "guest.exec timeoutMs")?,
            }),
            "guest.exec.abort" => Ok(Self::GuestExecAbort {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.exec.abort missing id"))?
                    .to_string(),
            }),
            "guest.spawn" => Ok(Self::GuestSpawn {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn missing id"))?
                    .to_string(),
                argv: read_string_array(&document, "argv", "guest.spawn argv")?,
                env: read_env_array(&document, "env", "guest.spawn env")?,
                stdin: read_spawn_stdio(&document, "stdin", "guest.spawn stdin")?,
                stdout: read_spawn_stdio(&document, "stdout", "guest.spawn stdout")?,
                stderr: read_spawn_stdio(&document, "stderr", "guest.spawn stderr")?,
                pty: read_optional_pty_size(&document)?,
            }),
            "guest.spawn.stdin" => Ok(Self::GuestSpawnStdin {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stdin missing id"))?
                    .to_string(),
                data: document
                    .get_binary_generic("data")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stdin missing data"))?
                    .to_vec(),
            }),
            "guest.spawn.stdin.close" => Ok(Self::GuestSpawnStdinClose {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stdin.close missing id"))?
                    .to_string(),
            }),
            "guest.spawn.signal" => Ok(Self::GuestSpawnSignal {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.signal missing id"))?
                    .to_string(),
                signal: document
                    .get_str("signal")
                    .map_err(|_| ControlFrameError::new("guest.spawn.signal missing signal"))?
                    .to_string(),
            }),
            "guest.spawn.resize" => Ok(Self::GuestSpawnResize {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.resize missing id"))?
                    .to_string(),
                rows: read_u16(&document, "rows", "guest.spawn.resize rows")?,
                cols: read_u16(&document, "cols", "guest.spawn.resize cols")?,
            }),
            "guest.spawn.started" => Ok(Self::GuestSpawnStarted {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.started missing id"))?
                    .to_string(),
            }),
            "guest.spawn.stdout" => Ok(Self::GuestSpawnStdout {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stdout missing id"))?
                    .to_string(),
                data: document
                    .get_binary_generic("data")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stdout missing data"))?
                    .to_vec(),
            }),
            "guest.spawn.stderr" => Ok(Self::GuestSpawnStderr {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stderr missing id"))?
                    .to_string(),
                data: document
                    .get_binary_generic("data")
                    .map_err(|_| ControlFrameError::new("guest.spawn.stderr missing data"))?
                    .to_vec(),
            }),
            "guest.spawn.exit" => Ok(Self::GuestSpawnExit {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.exit missing id"))?
                    .to_string(),
                exit_code: document.get_i32("exitCode").ok(),
                signal: document.get_str("signal").ok().map(str::to_string),
            }),
            "guest.spawn.streams.closed" => Ok(Self::GuestSpawnStreamsClosed {
                id: document
                    .get_str("id")
                    .map_err(|_| ControlFrameError::new("guest.spawn.streams.closed missing id"))?
                    .to_string(),
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

fn read_string_array(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<Vec<String>, ControlFrameError> {
    document
        .get_array(key)
        .map_err(|_| ControlFrameError::new(format!("{label} missing")))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_string)
                .ok_or_else(|| ControlFrameError::new(format!("{label} must be strings")))
        })
        .collect()
}

fn read_env_array(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<Vec<(String, String)>, ControlFrameError> {
    document
        .get_array(key)
        .ok()
        .map(|values| {
            values
                .iter()
                .map(|value| {
                    let document = value.as_document().ok_or_else(|| {
                        ControlFrameError::new(format!("{label} entries must be documents"))
                    })?;
                    let key = document
                        .get_str("key")
                        .map_err(|_| {
                            ControlFrameError::new(format!("{label} key must be a string"))
                        })?
                        .to_string();
                    let value = document
                        .get_str("value")
                        .map_err(|_| {
                            ControlFrameError::new(format!("{label} value must be a string"))
                        })?
                        .to_string();
                    Ok((key, value))
                })
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .map(|env| env.unwrap_or_default())
}

impl GuestSpawnStdio {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pipe => "pipe",
            Self::Pty => "pty",
        }
    }
}

fn read_spawn_stdio(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<GuestSpawnStdio, ControlFrameError> {
    match document
        .get_str(key)
        .map_err(|_| ControlFrameError::new(format!("{label} missing")))?
    {
        "pipe" => Ok(GuestSpawnStdio::Pipe),
        "pty" => Ok(GuestSpawnStdio::Pty),
        other => Err(ControlFrameError::new(format!(
            "{label} must be pipe or pty, got {other}"
        ))),
    }
}

fn read_optional_pty_size(
    document: &bson::Document,
) -> Result<Option<GuestPtySize>, ControlFrameError> {
    let Some(value) = document.get("pty") else {
        return Ok(None);
    };
    let document = value
        .as_document()
        .ok_or_else(|| ControlFrameError::new("guest.spawn pty must be a document"))?;
    Ok(Some(GuestPtySize {
        rows: read_u16(document, "rows", "guest.spawn pty rows")?,
        cols: read_u16(document, "cols", "guest.spawn pty cols")?,
    }))
}

fn read_u16(document: &bson::Document, key: &str, label: &str) -> Result<u16, ControlFrameError> {
    let value = document
        .get_i32(key)
        .map_err(|_| ControlFrameError::new(format!("{label} missing")))?;
    if value <= 0 {
        return Err(ControlFrameError::new(format!("{label} must be positive")));
    }
    u16::try_from(value).map_err(|_| ControlFrameError::new(format!("{label} must fit in u16")))
}

fn read_optional_u64(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<Option<u64>, ControlFrameError> {
    let Some(value) = document.get(key) else {
        return Ok(None);
    };
    let value = match value {
        bson::Bson::Int32(value) => i64::from(*value),
        bson::Bson::Int64(value) => *value,
        bson::Bson::Double(value) if value.fract() == 0.0 => *value as i64,
        _ => {
            return Err(ControlFrameError::new(format!(
                "{label} must be an integer"
            )));
        }
    };
    if value <= 0 {
        return Err(ControlFrameError::new(format!("{label} must be positive")));
    }
    u64::try_from(value)
        .map(Some)
        .map_err(|_| ControlFrameError::new(format!("{label} must fit in u64")))
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
        let frames = [
            ControlFrame::GuestExec {
                id: "test".to_string(),
                argv: vec!["/bin/true".to_string()],
                env: vec![("FOO".to_string(), "bar".to_string())],
                timeout_ms: Some(5000),
            },
            ControlFrame::GuestExecAbort {
                id: "test".to_string(),
            },
        ];

        for frame in frames {
            let encoded = frame.encode().unwrap();
            assert_eq!(ControlFrame::decode(&encoded).unwrap(), frame);
        }
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
    fn round_trips_guest_spawn_frames() {
        let frames = [
            ControlFrame::GuestSpawn {
                id: "spawn".to_string(),
                argv: vec!["/bin/cat".to_string()],
                env: vec![("FOO".to_string(), "bar".to_string())],
                stdin: GuestSpawnStdio::Pipe,
                stdout: GuestSpawnStdio::Pipe,
                stderr: GuestSpawnStdio::Pipe,
                pty: None,
            },
            ControlFrame::GuestSpawn {
                id: "pty".to_string(),
                argv: vec!["/bin/sh".to_string()],
                env: vec![],
                stdin: GuestSpawnStdio::Pty,
                stdout: GuestSpawnStdio::Pty,
                stderr: GuestSpawnStdio::Pty,
                pty: Some(GuestPtySize { rows: 24, cols: 80 }),
            },
            ControlFrame::GuestSpawnStdin {
                id: "spawn".to_string(),
                data: b"input".to_vec(),
            },
            ControlFrame::GuestSpawnStdinClose {
                id: "spawn".to_string(),
            },
            ControlFrame::GuestSpawnSignal {
                id: "spawn".to_string(),
                signal: "SIGTERM".to_string(),
            },
            ControlFrame::GuestSpawnResize {
                id: "pty".to_string(),
                rows: 40,
                cols: 120,
            },
            ControlFrame::GuestSpawnStarted {
                id: "spawn".to_string(),
            },
            ControlFrame::GuestSpawnStdout {
                id: "spawn".to_string(),
                data: b"out".to_vec(),
            },
            ControlFrame::GuestSpawnStderr {
                id: "spawn".to_string(),
                data: b"err".to_vec(),
            },
            ControlFrame::GuestSpawnExit {
                id: "spawn".to_string(),
                exit_code: Some(7),
                signal: None,
            },
            ControlFrame::GuestSpawnExit {
                id: "spawn".to_string(),
                exit_code: None,
                signal: Some("SIGKILL".to_string()),
            },
            ControlFrame::GuestSpawnStreamsClosed {
                id: "spawn".to_string(),
            },
        ];

        for frame in frames {
            let encoded = frame.encode().unwrap();
            assert_eq!(ControlFrame::decode(&encoded).unwrap(), frame);
        }
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
            env: Vec::new(),
            timeout_ms: None,
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
