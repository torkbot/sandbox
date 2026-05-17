use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmSpec {
    pub name: Option<String>,
    pub vcpus: u8,
    pub memory_mib: u32,
    pub kernel: KernelSpec,
    pub init: InitSpec,
    pub rootfs: RootfsSpec,
    pub rootfs_overlay: Option<RootfsOverlaySpec>,
    pub mounts: Vec<MountSpec>,
    pub network: Option<NetworkSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelSpec {
    pub format: KernelFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelFormat {
    Auto,
    Raw,
    Elf,
    PeGz,
    ImageGz,
    ImageZstd,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitSpec {
    pub crate_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsSpec {
    pub path: PathBuf,
    pub readonly: bool,
    pub format: RootfsFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsFormat {
    Directory,
    Erofs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsOverlaySpec {
    Writable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSpec {
    VirtualFs { path: String, writable: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSpec {
    pub http: Option<HttpSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSpec {
    pub protected_ranges: Vec<String>,
    pub ca_certificate_pem: Option<String>,
    pub ca_private_key_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecError {
    message: String,
}

impl SpecError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SpecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SpecError {}

impl MicroVmSpec {
    pub fn build(input: MicroVmSpecInput) -> Result<Self, SpecError> {
        let vcpus = input.vcpus.unwrap_or(1);
        if vcpus == 0 {
            return Err(SpecError::new("cpu.vcpus must be greater than zero"));
        }

        let vcpus = u8::try_from(vcpus).map_err(|_| SpecError::new("cpu.vcpus must fit in u8"))?;

        let memory_mib = input.memory_mib.unwrap_or(512);
        if memory_mib == 0 {
            return Err(SpecError::new("memory.mib must be greater than zero"));
        }

        if input.rootfs_path.is_empty() {
            return Err(SpecError::new("rootfs.path must not be empty"));
        }

        let kernel = KernelSpec {
            format: KernelFormat::parse(input.kernel_format.as_deref().unwrap_or("auto"))?,
        };

        if input.init_crate != "sandbox-init" {
            return Err(SpecError::new(format!(
                "unsupported init crate: {}",
                input.init_crate
            )));
        }
        let init = InitSpec {
            crate_name: input.init_crate,
        };

        let rootfs = RootfsSpec {
            path: PathBuf::from(input.rootfs_path),
            readonly: input.rootfs_readonly.unwrap_or(true),
            format: RootfsFormat::parse(&input.rootfs_format)?,
        };

        let rootfs_overlay = input
            .rootfs_overlay_mode
            .map(|mode| RootfsOverlaySpec::parse(&mode))
            .transpose()?;

        let mounts = input
            .mounts
            .into_iter()
            .map(MountSpec::parse)
            .collect::<Result<Vec<_>, _>>()?;
        crate::mounts::MountTable::plan(&mounts)
            .map_err(|error| SpecError::new(error.to_string()))?;

        let network = input.network_http.map(|http| NetworkSpec {
            http: Some(HttpSpec {
                protected_ranges: http.protected_ranges,
                ca_certificate_pem: http.ca_certificate_pem,
                ca_private_key_pem: http.ca_private_key_pem,
            }),
        });
        crate::network::NetworkPlan::from_http(
            network.as_ref().and_then(|network| network.http.as_ref()),
        )
        .map_err(|error| SpecError::new(error.to_string()))?;

        Ok(Self {
            name: input.name,
            vcpus,
            memory_mib,
            kernel,
            init,
            rootfs,
            rootfs_overlay,
            mounts,
            network,
        })
    }
}

impl KernelFormat {
    fn parse(value: &str) -> Result<Self, SpecError> {
        match value {
            "auto" => Ok(Self::Auto),
            "raw" => Ok(Self::Raw),
            "elf" => Ok(Self::Elf),
            "pe-gz" => Ok(Self::PeGz),
            "image-gz" => Ok(Self::ImageGz),
            "image-zstd" => Ok(Self::ImageZstd),
            other => Err(SpecError::new(format!(
                "unsupported kernel.format: {other}"
            ))),
        }
    }
}

impl RootfsFormat {
    fn parse(value: &str) -> Result<Self, SpecError> {
        match value {
            "directory" => Ok(Self::Directory),
            "erofs" => Ok(Self::Erofs),
            other => Err(SpecError::new(format!(
                "unsupported rootfs.format: {other}"
            ))),
        }
    }
}

impl RootfsOverlaySpec {
    fn parse(value: &str) -> Result<Self, SpecError> {
        match value {
            "writable" => Ok(Self::Writable),
            other => Err(SpecError::new(format!(
                "unsupported rootfsOverlay.mode: {other}"
            ))),
        }
    }
}

impl MountSpec {
    fn parse(input: MountSpecInput) -> Result<Self, SpecError> {
        if !input.path.starts_with('/') {
            return Err(SpecError::new("mount.path must be absolute"));
        }
        if input.path.contains('=') || input.path.contains(';') {
            return Err(SpecError::new("mount.path must not contain '=' or ';'"));
        }

        match input.kind.as_str() {
            "virtual-fs" => Ok(Self::VirtualFs {
                path: input.path,
                writable: input.writable.unwrap_or(false),
            }),
            other => Err(SpecError::new(format!("unsupported mount.kind: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmSpecInput {
    pub name: Option<String>,
    pub vcpus: Option<u32>,
    pub memory_mib: Option<u32>,
    pub kernel_format: Option<String>,
    pub init_crate: String,
    pub rootfs_path: String,
    pub rootfs_readonly: Option<bool>,
    pub rootfs_format: String,
    pub rootfs_overlay_mode: Option<String>,
    pub mounts: Vec<MountSpecInput>,
    pub network_http: Option<HttpSpecInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpecInput {
    pub kind: String,
    pub path: String,
    pub writable: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSpecInput {
    pub protected_ranges: Vec<String>,
    pub ca_certificate_pem: Option<String>,
    pub ca_private_key_pem: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_input() -> MicroVmSpecInput {
        MicroVmSpecInput {
            name: Some("test".to_string()),
            vcpus: None,
            memory_mib: None,
            kernel_format: None,
            init_crate: "sandbox-init".to_string(),
            rootfs_path: "rootfs.erofs".to_string(),
            rootfs_readonly: None,
            rootfs_format: "erofs".to_string(),
            rootfs_overlay_mode: None,
            mounts: Vec::new(),
            network_http: None,
        }
    }

    #[test]
    fn defaults_cpu_memory_and_readonly_rootfs() {
        let spec = MicroVmSpec::build(valid_input()).unwrap();

        assert_eq!(spec.vcpus, 1);
        assert_eq!(spec.memory_mib, 512);
        assert_eq!(spec.kernel.format, KernelFormat::Auto);
        assert_eq!(spec.init.crate_name, "sandbox-init");
        assert_eq!(spec.rootfs.readonly, true);
        assert_eq!(spec.rootfs.format, RootfsFormat::Erofs);
    }

    #[test]
    fn keeps_requested_mount_and_network_shape() {
        let mut input = valid_input();
        input.rootfs_overlay_mode = Some("writable".to_string());
        input.mounts = vec![MountSpecInput {
            kind: "virtual-fs".to_string(),
            path: "/sandbox".to_string(),
            writable: Some(true),
        }];
        input.network_http = Some(HttpSpecInput {
            protected_ranges: vec!["127.0.0.0/8".to_string()],
            ca_certificate_pem: Some(
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----".to_string(),
            ),
            ca_private_key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----".to_string(),
            ),
        });

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(spec.rootfs_overlay, Some(RootfsOverlaySpec::Writable));
        assert_eq!(
            spec.mounts,
            vec![MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
                writable: true,
            }],
        );
        assert_eq!(
            spec.network.unwrap().http.unwrap().protected_ranges,
            vec!["127.0.0.0/8"],
        );
    }

    #[test]
    fn rejects_zero_vcpus() {
        let mut input = valid_input();
        input.vcpus = Some(0);

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(err.to_string(), "cpu.vcpus must be greater than zero");
    }

    #[test]
    fn rejects_unknown_init_crate() {
        let mut input = valid_input();
        input.init_crate = "other-init".to_string();

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(err.to_string(), "unsupported init crate: other-init");
    }

    #[test]
    fn rejects_relative_mount_paths() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "virtual-fs".to_string(),
            path: "sandbox".to_string(),
            writable: None,
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(err.to_string(), "mount.path must be absolute");
    }
}
