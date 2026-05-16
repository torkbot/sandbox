use std::fmt;

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
}
