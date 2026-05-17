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

    fn getattr(&self, inode: VirtualInode) -> io::Result<(bindings::stat64, Duration)>;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[derive(Default)]
    struct FixtureFs;

    impl HostVirtualFileSystem for FixtureFs {
        fn lookup(&self, parent: VirtualInode, name: &CStr) -> io::Result<VirtioFsEntry> {
            assert_eq!(u64::from(parent), 1);
            assert_eq!(name.to_str().unwrap(), "status.json");
            Ok(virtual_file_entry(2, 19))
        }

        fn getattr(&self, inode: VirtualInode) -> io::Result<(bindings::stat64, Duration)> {
            assert_eq!(u64::from(inode), 2);
            Ok((virtual_file_entry(2, 19).attr, Duration::from_secs(1)))
        }
    }

    #[test]
    fn virtual_file_entry_uses_regular_read_only_metadata() {
        let entry = virtual_file_entry(42, 99);
        let mode = entry.attr.st_mode as libc::mode_t;

        assert_eq!(entry.inode, 42);
        assert_eq!(entry.attr.st_ino, 42);
        assert_eq!(entry.attr.st_size, 99);
        assert_eq!(mode & libc::S_IFMT, libc::S_IFREG);
        assert_eq!(mode & 0o777, 0o444);
    }

    #[test]
    fn virtual_directory_entry_uses_directory_read_only_metadata() {
        let entry = virtual_directory_entry(7);
        let mode = entry.attr.st_mode as libc::mode_t;

        assert_eq!(entry.inode, 7);
        assert_eq!(entry.attr.st_ino, 7);
        assert_eq!(mode & libc::S_IFMT, libc::S_IFDIR);
        assert_eq!(mode & 0o777, 0o555);
    }

    #[test]
    fn adapter_delegates_lookup_and_getattr_to_host_filesystem() {
        let adapter = VirtualFsAdapter::new(Arc::new(FixtureFs));
        let ctx = VirtioFsContext {
            uid: 1_000,
            gid: 1_000,
            pid: 123,
        };
        let name = CString::new("status.json").unwrap();

        let entry = adapter
            .lookup(ctx, VirtualInode::from(1), name.as_c_str())
            .unwrap();
        assert_eq!(entry.inode, 2);

        let (attr, timeout) = adapter.getattr(ctx, VirtualInode::from(2), None).unwrap();
        assert_eq!(attr.st_size, 19);
        assert_eq!(timeout, Duration::from_secs(1));
    }
}
