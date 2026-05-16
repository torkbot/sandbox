use std::ffi::CString;
use std::fmt;
use std::path::Path;

use crate::config::RootfsFormat;
use crate::MicroVmSpec;

#[derive(Debug)]
pub struct KrunContext {
    id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrunError {
    operation: &'static str,
    code: i32,
}

impl KrunContext {
    pub fn create(spec: &MicroVmSpec) -> Result<Self, KrunError> {
        let raw_id = krun::krun_create_ctx();
        if raw_id < 0 {
            return Err(KrunError {
                operation: "krun_create_ctx",
                code: raw_id,
            });
        }

        let context = Self { id: raw_id as u32 };
        context.apply_vm_config(spec)?;
        context.apply_rootfs(spec)?;
        Ok(context)
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    fn apply_vm_config(&self, spec: &MicroVmSpec) -> Result<(), KrunError> {
        check_krun(
            "krun_set_vm_config",
            krun::krun_set_vm_config(self.id, spec.vcpus, spec.memory_mib),
        )
    }

    fn apply_rootfs(&self, spec: &MicroVmSpec) -> Result<(), KrunError> {
        match spec.rootfs.format {
            RootfsFormat::Directory => {
                let path = cstring_path("krun_set_root", &spec.rootfs.path)?;
                check_krun("krun_set_root", unsafe {
                    krun::krun_set_root(self.id, path.as_ptr())
                })
            }
            RootfsFormat::Erofs => {
                let block_id = CString::new("root").unwrap();
                let path = cstring_path("krun_add_disk3", &spec.rootfs.path)?;
                check_krun("krun_add_disk3", unsafe {
                    krun::krun_add_disk3(
                        self.id,
                        block_id.as_ptr(),
                        path.as_ptr(),
                        0,
                        spec.rootfs.readonly,
                        false,
                        sync_mode(),
                    )
                })?;

                let device = CString::new("/dev/vda").unwrap();
                let fstype = CString::new("erofs").unwrap();
                let options = CString::new(if spec.rootfs.readonly { "ro" } else { "rw" }).unwrap();
                check_krun("krun_set_root_disk_remount", unsafe {
                    krun::krun_set_root_disk_remount(
                        self.id,
                        device.as_ptr(),
                        fstype.as_ptr(),
                        options.as_ptr(),
                    )
                })
            }
        }
    }
}

impl Drop for KrunContext {
    fn drop(&mut self) {
        let _ = krun::krun_free_ctx(self.id);
    }
}

impl fmt::Display for KrunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed with {}", self.operation, self.code)
    }
}

impl std::error::Error for KrunError {}

fn check_krun(operation: &'static str, code: i32) -> Result<(), KrunError> {
    if code == 0 {
        Ok(())
    } else {
        Err(KrunError { operation, code })
    }
}

fn cstring_path(operation: &'static str, path: &Path) -> Result<CString, KrunError> {
    CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| KrunError {
        operation,
        code: -libc::EINVAL,
    })
}

fn sync_mode() -> u32 {
    if cfg!(target_os = "macos") {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MicroVmSpecInput;

    #[test]
    fn creates_configures_and_frees_krun_context() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("runtime-test".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let _ = context.id();
    }

    #[test]
    fn configures_directory_rootfs() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("directory-root".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "/tmp/sandbox-root".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "directory".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let context = KrunContext::create(&spec).unwrap();
        let _ = context.id();
    }

    #[test]
    fn rejects_rootfs_paths_with_nul_bytes() {
        let spec = MicroVmSpec::build(MicroVmSpecInput {
            name: Some("bad-root".to_string()),
            vcpus: Some(1),
            memory_mib: Some(128),
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "bad\0root".to_string(),
            rootfs_readonly: Some(true),
            rootfs_format: "erofs".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        })
        .unwrap();

        let err = KrunContext::create(&spec).unwrap_err();
        assert_eq!(err.to_string(), "krun_add_disk3 failed with -22");
    }
}
