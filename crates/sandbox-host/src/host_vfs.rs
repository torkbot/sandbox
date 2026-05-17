use std::collections::HashMap;
use std::ffi::CStr;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use bson::{Bson, Document, doc};
use sandbox::network_service::{HostHttpHandler, HostHttpRequest, HostHttpResponse};
use sandbox::vfs::{
    VirtioFsDirEntry, VirtioFsEntry, VirtioVirtualFsBackend, VirtualFsAdapter, VirtualInode,
    bindings, virtual_directory_entry, virtual_file_entry,
};

pub struct HostIoBridge {
    stdout: Mutex<io::Stdout>,
    next_id: AtomicU64,
    pending: Mutex<HashMap<String, mpsc::Sender<Document>>>,
}

impl HostIoBridge {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            stdout: Mutex::new(io::stdout()),
            next_id: AtomicU64::new(1),
            pending: Mutex::new(HashMap::new()),
        })
    }

    pub fn write_raw_packet(&self, packet: &[u8]) -> io::Result<()> {
        let mut stdout = self.stdout.lock().expect("stdout lock poisoned");
        stdout.write_all(packet)?;
        stdout.flush()
    }

    pub fn request(&self, mut document: Document) -> io::Result<Document> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed).to_string();
        document.insert("id", id.clone());
        let packet = encode_document_packet(&document)?;
        let (tx, rx) = mpsc::channel();
        self.pending
            .lock()
            .expect("pending vfs lock poisoned")
            .insert(id.clone(), tx);

        if let Err(error) = self.write_raw_packet(&packet) {
            self.pending
                .lock()
                .expect("pending vfs lock poisoned")
                .remove(&id);
            return Err(error);
        }

        let response = rx.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "host vfs response channel closed",
            )
        })?;
        if response.get_bool("ok").unwrap_or(false) {
            Ok(response)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                response
                    .get_str("error")
                    .unwrap_or("host virtual filesystem request failed")
                    .to_string(),
            ))
        }
    }

    pub fn route_response(&self, document: Document) -> bool {
        let response_type = document.get_str("type").ok();
        if response_type != Some("host.vfs.response") && response_type != Some("host.http.response")
        {
            return false;
        }
        let Ok(id) = document.get_str("id") else {
            return true;
        };
        if let Some(tx) = self
            .pending
            .lock()
            .expect("pending vfs lock poisoned")
            .remove(id)
        {
            let _ = tx.send(document);
        }
        true
    }
}

impl HostHttpHandler for HostIoBridge {
    fn handle_http_request(&self, request: HostHttpRequest) -> io::Result<HostHttpResponse> {
        let response = self.request(doc! {
            "type": "host.http.request",
            "method": request.method,
            "url": request.url,
            "destinationIp": request.destination_ip,
            "headers": request.headers.into_iter().map(|(name, value)| doc! {
                "name": name,
                "value": value,
            }).collect::<Vec<_>>(),
            "body": Bson::Binary(bson::Binary {
                subtype: bson::spec::BinarySubtype::Generic,
                bytes: request.body,
            }),
        })?;
        let status = response.get_i32("status").map_err(to_io_error)?;
        let headers = response
            .get_array("headers")
            .map_err(to_io_error)?
            .iter()
            .map(|value| {
                let document = value.as_document().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "HTTP header must be a document")
                })?;
                Ok((
                    document.get_str("name").map_err(to_io_error)?.to_string(),
                    document.get_str("value").map_err(to_io_error)?.to_string(),
                ))
            })
            .collect::<io::Result<Vec<_>>>()?;
        let body = response
            .get_binary_generic("body")
            .cloned()
            .map_err(to_io_error)?;

        Ok(HostHttpResponse {
            status: u16::try_from(status)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?,
            headers,
            body,
        })
    }
}

#[derive(Clone)]
pub struct NodeVirtualFs {
    mount_path: String,
    bridge: Arc<HostIoBridge>,
    state: Arc<Mutex<NodeVirtualFsState>>,
}

#[derive(Default)]
struct NodeVirtualFsState {
    next_inode: u64,
    paths_by_inode: HashMap<u64, String>,
    inodes_by_path: HashMap<String, u64>,
}

impl NodeVirtualFs {
    pub fn new(mount_path: String, bridge: Arc<HostIoBridge>) -> Arc<dyn VirtioVirtualFsBackend> {
        let mut state = NodeVirtualFsState {
            next_inode: 2,
            ..Default::default()
        };
        state.paths_by_inode.insert(1, "/".to_string());
        state.inodes_by_path.insert("/".to_string(), 1);

        Arc::new(VirtualFsAdapter::new(Arc::new(Self {
            mount_path,
            bridge,
            state: Arc::new(Mutex::new(state)),
        })))
    }

    fn inode_for_path(&self, path: &str) -> u64 {
        let mut state = self.state.lock().expect("vfs inode state lock poisoned");
        if let Some(inode) = state.inodes_by_path.get(path) {
            return *inode;
        }

        let inode = state.next_inode;
        state.next_inode += 1;
        state.inodes_by_path.insert(path.to_string(), inode);
        state.paths_by_inode.insert(inode, path.to_string());
        inode
    }

    fn path_for_inode(&self, inode: VirtualInode) -> io::Result<String> {
        self.state
            .lock()
            .expect("vfs inode state lock poisoned")
            .paths_by_inode
            .get(&u64::from(inode))
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "unknown virtual inode"))
    }
}

impl sandbox::vfs::HostVirtualFileSystem for NodeVirtualFs {
    fn lookup(&self, parent: VirtualInode, name: &CStr) -> io::Result<VirtioFsEntry> {
        let parent = self.path_for_inode(parent)?;
        let name = name.to_str().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "virtual path is not utf-8")
        })?;
        let path = join_guest_path(&parent, name);
        let stat = self.stat_path(&path)?;
        Ok(entry_from_stat(self.inode_for_path(&path), &stat))
    }

    fn getattr(&self, inode: VirtualInode) -> io::Result<(bindings::stat64, Duration)> {
        let path = self.path_for_inode(inode)?;
        let stat = self.stat_path(&path)?;
        Ok((
            entry_from_stat(u64::from(inode), &stat).attr,
            Duration::from_secs(1),
        ))
    }

    fn readdir(&self, inode: VirtualInode) -> io::Result<Vec<VirtioFsDirEntry>> {
        let path = self.path_for_inode(inode)?;
        let response = self.bridge.request(doc! {
            "type": "host.vfs.list",
            "mountPath": &self.mount_path,
            "path": &path,
        })?;
        let entries = response.get_array("entries").map_err(to_io_error)?;
        entries
            .iter()
            .map(|entry| {
                let document = entry.as_document().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "vfs entry must be a document")
                })?;
                let name = document.get_str("name").map_err(to_io_error)?;
                let ty = document.get_str("type").map_err(to_io_error)?;
                let child_path = join_guest_path(&path, name);
                Ok(VirtioFsDirEntry {
                    inode: self.inode_for_path(&child_path),
                    type_: dirent_type(ty)?,
                    name: name.as_bytes().to_vec(),
                })
            })
            .collect()
    }

    fn read(&self, inode: VirtualInode, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let path = self.path_for_inode(inode)?;
        let response = self.bridge.request(doc! {
            "type": "host.vfs.read",
            "mountPath": &self.mount_path,
            "path": &path,
            "offset": offset as i64,
            "size": size as i64,
        })?;
        response
            .get_binary_generic("contents")
            .cloned()
            .map_err(to_io_error)
    }
}

impl NodeVirtualFs {
    fn stat_path(&self, path: &str) -> io::Result<Document> {
        let response = self.bridge.request(doc! {
            "type": "host.vfs.stat",
            "mountPath": &self.mount_path,
            "path": path,
        })?;
        response.get_document("stat").cloned().map_err(to_io_error)
    }
}

fn entry_from_stat(inode: u64, stat: &Document) -> VirtioFsEntry {
    match stat.get_str("type").unwrap_or("file") {
        "directory" => virtual_directory_entry(inode),
        _ => virtual_file_entry(inode, stat_size(stat)),
    }
}

fn stat_size(stat: &Document) -> u64 {
    match stat.get("sizeBytes") {
        Some(Bson::Int32(value)) => (*value).max(0) as u64,
        Some(Bson::Int64(value)) => (*value).max(0) as u64,
        _ => 0,
    }
}

fn dirent_type(ty: &str) -> io::Result<u32> {
    match ty {
        "directory" => Ok(libc::DT_DIR as u32),
        "file" => Ok(libc::DT_REG as u32),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported virtual filesystem entry type: {other}"),
        )),
    }
}

fn join_guest_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn encode_document_packet(document: &Document) -> io::Result<Vec<u8>> {
    let frame = document
        .to_vec()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    let frame_len = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "host frame too large"))?;
    let mut packet = Vec::with_capacity(4 + frame.len());
    packet.extend_from_slice(&frame_len.to_le_bytes());
    packet.extend_from_slice(&frame);
    Ok(packet)
}

fn to_io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
