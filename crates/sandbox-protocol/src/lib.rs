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
        cwd: String,
        timeout_ms: Option<u64>,
    },
    GuestExecAbort {
        id: String,
    },
    GuestSpawn {
        id: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: String,
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
    GuestFsStat {
        id: String,
        path: String,
    },
    GuestFsReadDir {
        id: String,
        path: String,
    },
    GuestFsReadFile {
        id: String,
        path: String,
        range: Option<GuestFsReadRange>,
    },
    GuestFsWriteFile {
        id: String,
        path: String,
        contents: Vec<u8>,
        create_parents: bool,
    },
    GuestFsMkdir {
        id: String,
        path: String,
        recursive: bool,
    },
    GuestFsRemove {
        id: String,
        path: String,
        recursive: bool,
        force: bool,
    },
    GuestFsRename {
        id: String,
        from: String,
        to: String,
    },
    GuestFsResponse {
        id: String,
        result: GuestFsResponseResult,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestFsReadRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFsStat {
    pub entry_type: GuestFsEntryType,
    pub size_bytes: u64,
    pub modified_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestFsEntryType {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFsDirectoryEntry {
    pub name: String,
    pub name_bytes: Vec<u8>,
    pub stat: GuestFsStat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestFsError {
    pub message: String,
    pub code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestFsResponseResult {
    Stat(GuestFsStat),
    ReadDir(Vec<GuestFsDirectoryEntry>),
    ReadFile(Vec<u8>),
    Empty,
    Error(GuestFsError),
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
                cwd,
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
                document.insert("cwd", cwd);
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
                cwd,
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
                document.insert("cwd", cwd);
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
            Self::GuestFsStat { id, path } => bson::doc! {
                "type": "guest.fs.stat",
                "id": id,
                "path": path,
            },
            Self::GuestFsReadDir { id, path } => bson::doc! {
                "type": "guest.fs.readDir",
                "id": id,
                "path": path,
            },
            Self::GuestFsReadFile { id, path, range } => {
                let mut document = bson::doc! {
                    "type": "guest.fs.readFile",
                    "id": id,
                    "path": path,
                };
                if let Some(range) = range {
                    document.insert(
                        "offset",
                        i64::try_from(range.offset).map_err(|_| {
                            ControlFrameError::new("guest.fs.readFile offset exceeds i64")
                        })?,
                    );
                    document.insert(
                        "length",
                        i64::try_from(range.length).map_err(|_| {
                            ControlFrameError::new("guest.fs.readFile length exceeds i64")
                        })?,
                    );
                }
                document
            }
            Self::GuestFsWriteFile {
                id,
                path,
                contents,
                create_parents,
            } => bson::doc! {
                "type": "guest.fs.writeFile",
                "id": id,
                "path": path,
                "contents": bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: contents.clone(),
                },
                "createParents": *create_parents,
            },
            Self::GuestFsMkdir {
                id,
                path,
                recursive,
            } => bson::doc! {
                "type": "guest.fs.mkdir",
                "id": id,
                "path": path,
                "recursive": *recursive,
            },
            Self::GuestFsRemove {
                id,
                path,
                recursive,
                force,
            } => bson::doc! {
                "type": "guest.fs.remove",
                "id": id,
                "path": path,
                "recursive": *recursive,
                "force": *force,
            },
            Self::GuestFsRename { id, from, to } => bson::doc! {
                "type": "guest.fs.rename",
                "id": id,
                "from": from,
                "to": to,
            },
            Self::GuestFsResponse { id, result } => {
                let mut document = bson::doc! {
                    "type": "guest.fs.response",
                    "id": id,
                };
                encode_guest_fs_response_result(&mut document, result)?;
                document
            }
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
                cwd: document
                    .get_str("cwd")
                    .map_err(|_| ControlFrameError::new("guest.exec missing cwd"))?
                    .to_string(),
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
                cwd: document
                    .get_str("cwd")
                    .map_err(|_| ControlFrameError::new("guest.spawn missing cwd"))?
                    .to_string(),
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
            "guest.fs.stat" => Ok(Self::GuestFsStat {
                id: read_required_string(&document, "id", "guest.fs.stat id")?,
                path: read_required_string(&document, "path", "guest.fs.stat path")?,
            }),
            "guest.fs.readDir" => Ok(Self::GuestFsReadDir {
                id: read_required_string(&document, "id", "guest.fs.readDir id")?,
                path: read_required_string(&document, "path", "guest.fs.readDir path")?,
            }),
            "guest.fs.readFile" => Ok(Self::GuestFsReadFile {
                id: read_required_string(&document, "id", "guest.fs.readFile id")?,
                path: read_required_string(&document, "path", "guest.fs.readFile path")?,
                range: read_optional_guest_fs_read_range(&document)?,
            }),
            "guest.fs.writeFile" => Ok(Self::GuestFsWriteFile {
                id: read_required_string(&document, "id", "guest.fs.writeFile id")?,
                path: read_required_string(&document, "path", "guest.fs.writeFile path")?,
                contents: document
                    .get_binary_generic("contents")
                    .map_err(|_| ControlFrameError::new("guest.fs.writeFile missing contents"))?
                    .to_vec(),
                create_parents: document.get_bool("createParents").map_err(|_| {
                    ControlFrameError::new("guest.fs.writeFile missing createParents")
                })?,
            }),
            "guest.fs.mkdir" => Ok(Self::GuestFsMkdir {
                id: read_required_string(&document, "id", "guest.fs.mkdir id")?,
                path: read_required_string(&document, "path", "guest.fs.mkdir path")?,
                recursive: document
                    .get_bool("recursive")
                    .map_err(|_| ControlFrameError::new("guest.fs.mkdir missing recursive"))?,
            }),
            "guest.fs.remove" => Ok(Self::GuestFsRemove {
                id: read_required_string(&document, "id", "guest.fs.remove id")?,
                path: read_required_string(&document, "path", "guest.fs.remove path")?,
                recursive: document
                    .get_bool("recursive")
                    .map_err(|_| ControlFrameError::new("guest.fs.remove missing recursive"))?,
                force: document
                    .get_bool("force")
                    .map_err(|_| ControlFrameError::new("guest.fs.remove missing force"))?,
            }),
            "guest.fs.rename" => Ok(Self::GuestFsRename {
                id: read_required_string(&document, "id", "guest.fs.rename id")?,
                from: read_required_string(&document, "from", "guest.fs.rename from")?,
                to: read_required_string(&document, "to", "guest.fs.rename to")?,
            }),
            "guest.fs.response" => Ok(Self::GuestFsResponse {
                id: read_required_string(&document, "id", "guest.fs.response id")?,
                result: read_guest_fs_response_result(&document)?,
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

fn encode_guest_fs_response_result(
    document: &mut bson::Document,
    result: &GuestFsResponseResult,
) -> Result<(), ControlFrameError> {
    match result {
        GuestFsResponseResult::Stat(stat) => {
            document.insert("ok", true);
            document.insert("stat", encode_guest_fs_stat(stat)?);
        }
        GuestFsResponseResult::ReadDir(entries) => {
            document.insert("ok", true);
            document.insert(
                "entries",
                entries
                    .iter()
                    .map(encode_guest_fs_directory_entry)
                    .collect::<Result<Vec<_>, _>>()?,
            );
        }
        GuestFsResponseResult::ReadFile(contents) => {
            document.insert("ok", true);
            document.insert(
                "contents",
                bson::Binary {
                    subtype: bson::spec::BinarySubtype::Generic,
                    bytes: contents.clone(),
                },
            );
        }
        GuestFsResponseResult::Empty => {
            document.insert("ok", true);
        }
        GuestFsResponseResult::Error(error) => {
            document.insert("ok", false);
            document.insert("error", error.message.clone());
            if let Some(code) = &error.code {
                document.insert("code", code.clone());
            }
        }
    }
    Ok(())
}

fn encode_guest_fs_directory_entry(
    entry: &GuestFsDirectoryEntry,
) -> Result<bson::Document, ControlFrameError> {
    Ok(bson::doc! {
        "name": entry.name.clone(),
        "nameBytes": bson::Binary {
            subtype: bson::spec::BinarySubtype::Generic,
            bytes: entry.name_bytes.clone(),
        },
        "stat": encode_guest_fs_stat(&entry.stat)?,
    })
}

fn encode_guest_fs_stat(stat: &GuestFsStat) -> Result<bson::Document, ControlFrameError> {
    Ok(bson::doc! {
        "type": stat.entry_type.as_str(),
        "sizeBytes": i64::try_from(stat.size_bytes)
            .map_err(|_| ControlFrameError::new("guest.fs stat sizeBytes exceeds i64"))?,
        "modifiedAtMs": stat.modified_at_ms,
    })
}

impl GuestFsEntryType {
    fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }
}

fn read_required_string(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<String, ControlFrameError> {
    document
        .get_str(key)
        .map(str::to_string)
        .map_err(|_| ControlFrameError::new(format!("{label} missing")))
}

fn read_optional_guest_fs_read_range(
    document: &bson::Document,
) -> Result<Option<GuestFsReadRange>, ControlFrameError> {
    let offset = read_optional_non_negative_u64(document, "offset", "guest.fs.readFile offset")?;
    let length = read_optional_non_negative_u64(document, "length", "guest.fs.readFile length")?;
    match (offset, length) {
        (None, None) => Ok(None),
        (Some(offset), Some(length)) => Ok(Some(GuestFsReadRange { offset, length })),
        _ => Err(ControlFrameError::new(
            "guest.fs.readFile range requires both offset and length",
        )),
    }
}

fn read_guest_fs_response_result(
    document: &bson::Document,
) -> Result<GuestFsResponseResult, ControlFrameError> {
    let ok = document
        .get_bool("ok")
        .map_err(|_| ControlFrameError::new("guest.fs.response missing ok"))?;
    if !ok {
        return Ok(GuestFsResponseResult::Error(GuestFsError {
            message: read_required_string(document, "error", "guest.fs.response error")?,
            code: document.get_str("code").ok().map(str::to_string),
        }));
    }
    if let Ok(stat) = document.get_document("stat") {
        return Ok(GuestFsResponseResult::Stat(read_guest_fs_stat(
            stat,
            "guest.fs.response stat",
        )?));
    }
    if let Ok(entries) = document.get_array("entries") {
        return Ok(GuestFsResponseResult::ReadDir(
            entries
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    let document = value.as_document().ok_or_else(|| {
                        ControlFrameError::new(format!(
                            "guest.fs.response entries[{index}] must be a document"
                        ))
                    })?;
                    Ok(GuestFsDirectoryEntry {
                        name: read_required_string(
                            document,
                            "name",
                            &format!("guest.fs.response entries[{index}] name"),
                        )?,
                        name_bytes: document
                            .get_binary_generic("nameBytes")
                            .map(|bytes| bytes.to_vec())
                            .map_err(|_| {
                                ControlFrameError::new(format!(
                                    "guest.fs.response entries[{index}] missing nameBytes"
                                ))
                            })?,
                        stat: read_guest_fs_stat(
                            document.get_document("stat").map_err(|_| {
                                ControlFrameError::new(format!(
                                    "guest.fs.response entries[{index}] missing stat"
                                ))
                            })?,
                            &format!("guest.fs.response entries[{index}] stat"),
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        ));
    }
    if let Ok(contents) = document.get_binary_generic("contents") {
        return Ok(GuestFsResponseResult::ReadFile(contents.to_vec()));
    }
    Ok(GuestFsResponseResult::Empty)
}

fn read_guest_fs_stat(
    document: &bson::Document,
    label: &str,
) -> Result<GuestFsStat, ControlFrameError> {
    let entry_type = match document
        .get_str("type")
        .map_err(|_| ControlFrameError::new(format!("{label} missing type")))?
    {
        "file" => GuestFsEntryType::File,
        "directory" => GuestFsEntryType::Directory,
        "symlink" => GuestFsEntryType::Symlink,
        "other" => GuestFsEntryType::Other,
        other => {
            return Err(ControlFrameError::new(format!(
                "{label} has invalid type {other}"
            )));
        }
    };
    Ok(GuestFsStat {
        entry_type,
        size_bytes: read_non_negative_u64(document, "sizeBytes", &format!("{label} sizeBytes"))?,
        modified_at_ms: read_i64(document, "modifiedAtMs", &format!("{label} modifiedAtMs"))?,
    })
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

fn read_i64(document: &bson::Document, key: &str, label: &str) -> Result<i64, ControlFrameError> {
    let Some(value) = document.get(key) else {
        return Err(ControlFrameError::new(format!("{label} missing")));
    };
    read_bson_integer(value, label)
}

fn read_non_negative_u64(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<u64, ControlFrameError> {
    let value = read_i64(document, key, label)?;
    if value < 0 {
        return Err(ControlFrameError::new(format!(
            "{label} must be non-negative"
        )));
    }
    u64::try_from(value).map_err(|_| ControlFrameError::new(format!("{label} must fit in u64")))
}

fn read_optional_non_negative_u64(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<Option<u64>, ControlFrameError> {
    let Some(value) = document.get(key) else {
        return Ok(None);
    };
    let value = read_bson_integer(value, label)?;
    if value < 0 {
        return Err(ControlFrameError::new(format!(
            "{label} must be non-negative"
        )));
    }
    u64::try_from(value)
        .map(Some)
        .map_err(|_| ControlFrameError::new(format!("{label} must fit in u64")))
}

fn read_optional_u64(
    document: &bson::Document,
    key: &str,
    label: &str,
) -> Result<Option<u64>, ControlFrameError> {
    let Some(value) = document.get(key) else {
        return Ok(None);
    };
    let value = read_bson_integer(value, label)?;
    if value <= 0 {
        return Err(ControlFrameError::new(format!("{label} must be positive")));
    }
    u64::try_from(value)
        .map(Some)
        .map_err(|_| ControlFrameError::new(format!("{label} must fit in u64")))
}

fn read_bson_integer(value: &bson::Bson, label: &str) -> Result<i64, ControlFrameError> {
    match value {
        bson::Bson::Int32(value) => Ok(i64::from(*value)),
        bson::Bson::Int64(value) => Ok(*value),
        bson::Bson::Double(value) if value.fract() == 0.0 => Ok(*value as i64),
        _ => Err(ControlFrameError::new(format!(
            "{label} must be an integer"
        ))),
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
        let frames = [
            ControlFrame::GuestExec {
                id: "test".to_string(),
                argv: vec!["/bin/true".to_string()],
                env: vec![("FOO".to_string(), "bar".to_string())],
                cwd: "/workspace".to_string(),
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
                cwd: "/workspace".to_string(),
                stdin: GuestSpawnStdio::Pipe,
                stdout: GuestSpawnStdio::Pipe,
                stderr: GuestSpawnStdio::Pipe,
                pty: None,
            },
            ControlFrame::GuestSpawn {
                id: "pty".to_string(),
                argv: vec!["/bin/sh".to_string()],
                env: vec![],
                cwd: "/".to_string(),
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
    fn round_trips_guest_fs_frames() {
        let stat = GuestFsStat {
            entry_type: GuestFsEntryType::File,
            size_bytes: 5,
            modified_at_ms: 1234,
        };
        let frames = [
            ControlFrame::GuestFsStat {
                id: "fs".to_string(),
                path: "/tmp/file".to_string(),
            },
            ControlFrame::GuestFsReadDir {
                id: "fs".to_string(),
                path: "/tmp".to_string(),
            },
            ControlFrame::GuestFsReadFile {
                id: "fs".to_string(),
                path: "/tmp/file".to_string(),
                range: Some(GuestFsReadRange {
                    offset: 1,
                    length: 3,
                }),
            },
            ControlFrame::GuestFsWriteFile {
                id: "fs".to_string(),
                path: "/tmp/file".to_string(),
                contents: b"hello".to_vec(),
                create_parents: true,
            },
            ControlFrame::GuestFsMkdir {
                id: "fs".to_string(),
                path: "/tmp/dir".to_string(),
                recursive: true,
            },
            ControlFrame::GuestFsRemove {
                id: "fs".to_string(),
                path: "/tmp/dir".to_string(),
                recursive: true,
                force: true,
            },
            ControlFrame::GuestFsRename {
                id: "fs".to_string(),
                from: "/tmp/a".to_string(),
                to: "/tmp/b".to_string(),
            },
            ControlFrame::GuestFsResponse {
                id: "fs".to_string(),
                result: GuestFsResponseResult::Stat(stat.clone()),
            },
            ControlFrame::GuestFsResponse {
                id: "fs".to_string(),
                result: GuestFsResponseResult::ReadDir(vec![GuestFsDirectoryEntry {
                    name: "file".to_string(),
                    name_bytes: b"file".to_vec(),
                    stat: stat.clone(),
                }]),
            },
            ControlFrame::GuestFsResponse {
                id: "fs".to_string(),
                result: GuestFsResponseResult::ReadFile(b"hello".to_vec()),
            },
            ControlFrame::GuestFsResponse {
                id: "fs".to_string(),
                result: GuestFsResponseResult::Empty,
            },
            ControlFrame::GuestFsResponse {
                id: "fs".to_string(),
                result: GuestFsResponseResult::Error(GuestFsError {
                    message: "missing".to_string(),
                    code: Some("ENOENT".to_string()),
                }),
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
            cwd: "/".to_string(),
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
