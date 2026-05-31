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
    pub storage: Option<RootfsStorageSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsStorageSpec {
    CowBlockStore {
        block_size: u64,
        max_dirty_bytes: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsFormat {
    Qcow2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSpec {
    VirtualFs { path: String, writable: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSpec {
    pub outbound: Option<OutboundSpec>,
    pub http: Option<HttpSpec>,
    pub policy: Option<NetworkPolicySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPolicySpec {
    pub connection_hook: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSpec {
    pub policy: OutboundPolicy,
    pub rules: Vec<OutboundRuleSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundPolicy {
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundRuleSpec {
    AcceptTcp { cidr: String, ports: Vec<u16> },
    AcceptUdp { cidr: String, ports: Vec<u16> },
    AcceptPublicInternet { ports: Vec<u16> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpSpec {
    pub protected_ranges: Vec<String>,
    pub ca_certificate_pem: Option<String>,
    pub ca_private_key_pem: Option<String>,
    pub request_header_hooks: Vec<HttpRequestHeaderHookSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestHeaderHookSpec {
    pub id: String,
    pub origin: String,
}

impl HttpSpec {
    fn from_input(input: HttpSpecInput) -> Result<Self, rcgen::Error> {
        let (ca_certificate_pem, ca_private_key_pem) =
            match (input.ca_certificate_pem, input.ca_private_key_pem) {
                (Some(certificate), Some(private_key)) => (Some(certificate), Some(private_key)),
                _ => {
                    let (certificate, private_key) = generate_http_ca()?;
                    (Some(certificate), Some(private_key))
                }
            };

        Ok(Self {
            protected_ranges: input.protected_ranges,
            ca_certificate_pem,
            ca_private_key_pem,
            request_header_hooks: input.request_header_hooks,
        })
    }
}

fn generate_http_ca() -> Result<(String, String), rcgen::Error> {
    let key = rcgen::KeyPair::generate()?;
    let mut params =
        rcgen::CertificateParams::new(vec!["Sandbox HTTP Interception CA".to_string()])?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Sandbox HTTP Interception CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let certificate = params.self_signed(&key)?;
    Ok((certificate.pem(), key.serialize_pem()))
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
            storage: input
                .rootfs_storage
                .map(RootfsStorageSpec::parse)
                .transpose()?,
        };
        let mounts = input
            .mounts
            .into_iter()
            .map(MountSpec::parse)
            .collect::<Result<Vec<_>, _>>()?;
        crate::mounts::MountTable::plan(&mounts)
            .map_err(|error| SpecError::new(error.to_string()))?;

        let network = if input.network_outbound.is_some()
            || input.network_http.is_some()
            || input.network_policy.is_some()
        {
            Some(NetworkSpec {
                outbound: input.network_outbound,
                http: input
                    .network_http
                    .map(HttpSpec::from_input)
                    .transpose()
                    .map_err(|error| SpecError::new(error.to_string()))?,
                policy: input.network_policy,
            })
        } else {
            None
        };
        crate::network::NetworkPlan::from_spec(network.as_ref())
            .map_err(|error| SpecError::new(error.to_string()))?;

        Ok(Self {
            name: input.name,
            vcpus,
            memory_mib,
            kernel,
            init,
            rootfs,
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
            "qcow2" => Ok(Self::Qcow2),
            other => Err(SpecError::new(format!(
                "unsupported rootfs.format: {other}"
            ))),
        }
    }
}

impl MountSpec {
    fn parse(input: MountSpecInput) -> Result<Self, SpecError> {
        if !input.path.starts_with('/') {
            return Err(SpecError::new("mount.path must be absolute"));
        }
        if input.path == "/" {
            return Err(SpecError::new("mount.path must not be root"));
        }
        if input
            .path
            .split('/')
            .any(|component| component == "." || component == "..")
        {
            return Err(SpecError::new(
                "mount.path must not contain '.' or '..' components",
            ));
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
    pub rootfs_storage: Option<RootfsStorageSpecInput>,
    pub mounts: Vec<MountSpecInput>,
    pub network_outbound: Option<OutboundSpec>,
    pub network_http: Option<HttpSpecInput>,
    pub network_policy: Option<NetworkPolicySpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsStorageSpecInput {
    pub kind: String,
    pub block_size: u64,
    pub max_dirty_bytes: u64,
}

impl RootfsStorageSpec {
    fn parse(input: RootfsStorageSpecInput) -> Result<Self, SpecError> {
        match input.kind.as_str() {
            "cow-block-store" => {
                if input.block_size == 0 || input.block_size % 512 != 0 {
                    return Err(SpecError::new(
                        "rootfs.storage.blockSize must be a positive multiple of 512",
                    ));
                }
                if input.max_dirty_bytes < input.block_size {
                    return Err(SpecError::new(
                        "rootfs.storage.maxDirtyBytes must be at least rootfs.storage.blockSize",
                    ));
                }
                Ok(Self::CowBlockStore {
                    block_size: input.block_size,
                    max_dirty_bytes: input.max_dirty_bytes,
                })
            }
            other => Err(SpecError::new(format!(
                "unsupported rootfs.storage.kind: {other}"
            ))),
        }
    }
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
    pub request_header_hooks: Vec<HttpRequestHeaderHookSpec>,
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
            rootfs_path: "rootfs.qcow2".to_string(),
            rootfs_readonly: None,
            rootfs_format: "qcow2".to_string(),
            rootfs_storage: None,
            mounts: Vec::new(),
            network_outbound: None,
            network_http: None,
            network_policy: None,
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
        assert_eq!(spec.rootfs.format, RootfsFormat::Qcow2);
    }

    #[test]
    fn parses_cow_rootfs_storage_limits() {
        let mut input = valid_input();
        input.rootfs_storage = Some(RootfsStorageSpecInput {
            kind: "cow-block-store".to_string(),
            block_size: 4096,
            max_dirty_bytes: 65536,
        });

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(
            spec.rootfs.storage,
            Some(RootfsStorageSpec::CowBlockStore {
                block_size: 4096,
                max_dirty_bytes: 65536,
            }),
        );
    }

    #[test]
    fn rejects_cow_rootfs_storage_limit_below_block_size() {
        let mut input = valid_input();
        input.rootfs_storage = Some(RootfsStorageSpecInput {
            kind: "cow-block-store".to_string(),
            block_size: 4096,
            max_dirty_bytes: 1024,
        });

        let error = MicroVmSpec::build(input).unwrap_err();

        assert_eq!(
            error.to_string(),
            "rootfs.storage.maxDirtyBytes must be at least rootfs.storage.blockSize",
        );
    }

    #[test]
    fn keeps_requested_mount_and_network_shape() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "virtual-fs".to_string(),
            path: "/sandbox".to_string(),
            writable: Some(true),
        }];
        input.network_outbound = Some(OutboundSpec {
            policy: OutboundPolicy::Deny,
            rules: vec![
                OutboundRuleSpec::AcceptTcp {
                    cidr: "127.0.0.1/32".to_string(),
                    ports: vec![80],
                },
                OutboundRuleSpec::AcceptPublicInternet { ports: vec![443] },
            ],
        });
        input.network_http = Some(HttpSpecInput {
            protected_ranges: vec!["127.0.0.0/8".to_string()],
            ca_certificate_pem: Some(
                "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----".to_string(),
            ),
            ca_private_key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----".to_string(),
            ),
            request_header_hooks: vec![HttpRequestHeaderHookSpec {
                id: "github".to_string(),
                origin: "https://api.github.com".to_string(),
            }],
        });

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(
            spec.mounts,
            vec![MountSpec::VirtualFs {
                path: "/sandbox".to_string(),
                writable: true,
            }],
        );
        let network = spec.network.unwrap();
        assert_eq!(
            network.outbound.unwrap().rules,
            vec![
                OutboundRuleSpec::AcceptTcp {
                    cidr: "127.0.0.1/32".to_string(),
                    ports: vec![80],
                },
                OutboundRuleSpec::AcceptPublicInternet { ports: vec![443] },
            ],
        );
        let http = network.http.unwrap();
        assert_eq!(http.protected_ranges, vec!["127.0.0.0/8"]);
        assert_eq!(http.request_header_hooks[0].id, "github");
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
