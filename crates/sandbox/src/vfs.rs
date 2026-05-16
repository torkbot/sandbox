//! Host virtual filesystem primitives backed by libkrun's virtio-fs contract.

use std::ffi::CStr;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use krun_devices::virtio::bindings;
pub use krun_devices::virtio::fs::{
    Context as VirtioFsContext, DirEntry as VirtioFsDirEntry, Entry as VirtioFsEntry,
    FileSystem as VirtioFileSystem, FsOptions as VirtioFsOptions,
};

/// Inode used by host-provided virtual mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualInode(u64);

impl From<u64> for VirtualInode {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<VirtualInode> for u64 {
    fn from(value: VirtualInode) -> Self {
        value.0
    }
}

/// File handle used by host-provided virtual mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VirtualHandle(u64);

impl From<u64> for VirtualHandle {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<VirtualHandle> for u64 {
    fn from(value: VirtualHandle) -> Self {
        value.0
    }
}

/// A narrow, read-oriented host filesystem that can be lifted into libkrun's
/// virtio-fs `FileSystem` trait without inventing a second guest filesystem API.
pub trait HostVirtualFileSystem: Send + Sync + 'static {
    fn lookup(&self, parent: VirtualInode, name: &CStr) -> io::Result<VirtioFsEntry>;

    fn getattr(
        &self,
        inode: VirtualInode,
    ) -> io::Result<(bindings::stat64, Duration)>;
}

/// Adapter from Sandbox's host VFS contract into libkrun's virtio-fs contract.
#[derive(Clone)]
pub struct VirtualFsAdapter {
    inner: Arc<dyn HostVirtualFileSystem>,
}

impl VirtualFsAdapter {
    pub fn new(inner: Arc<dyn HostVirtualFileSystem>) -> Self {
        Self { inner }
    }
}

impl VirtioFileSystem for VirtualFsAdapter {
    type Inode = VirtualInode;
    type Handle = VirtualHandle;

    fn init(&self, capable: VirtioFsOptions) -> io::Result<VirtioFsOptions> {
        Ok(capable & VirtioFsOptions::DO_READDIRPLUS)
    }

    fn lookup(
        &self,
        _ctx: VirtioFsContext,
        parent: Self::Inode,
        name: &CStr,
    ) -> io::Result<VirtioFsEntry> {
        self.inner.lookup(parent, name)
    }

    fn getattr(
        &self,
        _ctx: VirtioFsContext,
        inode: Self::Inode,
        _handle: Option<Self::Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.inner.getattr(inode)
    }
}

pub fn virtual_file_entry(inode: u64, size: u64) -> VirtioFsEntry {
    virtio_entry(inode, libc::S_IFREG as u32 | 0o444, size)
}

pub fn virtual_directory_entry(inode: u64) -> VirtioFsEntry {
    virtio_entry(inode, libc::S_IFDIR as u32 | 0o555, 0)
}

fn virtio_entry(inode: u64, mode: u32, size: u64) -> VirtioFsEntry {
    VirtioFsEntry {
        inode,
        generation: 0,
        attr: stat(inode, mode, size),
        attr_flags: 0,
        attr_timeout: Duration::from_secs(1),
        entry_timeout: Duration::from_secs(1),
    }
}

fn stat(inode: u64, mode: u32, size: u64) -> bindings::stat64 {
    let mut stat = unsafe { std::mem::zeroed::<bindings::stat64>() };
    stat.st_ino = inode;
    stat.st_mode = mode as _;
    stat.st_nlink = 1;
    stat.st_size = size as _;
    stat
}
