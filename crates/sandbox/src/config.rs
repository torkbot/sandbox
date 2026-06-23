use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmSpec {
    pub name: Option<String>,
    pub hostname: String,
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
    EphemeralCow {
        block_size: u64,
        max_dirty_bytes: u64,
    },
    PersistentQcow2Overlay {
        path: PathBuf,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootfsFormat {
    Qcow2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSpec {
    VirtualFs {
        path: String,
        writable: bool,
    },
    HostDirectory {
        path: String,
        source: PathBuf,
        access: HostDirectoryAccess,
        mask: Option<HostDirectoryMask>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostDirectoryAccess {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDirectoryMask {
    pub paths: Vec<String>,
    pub storage: Option<HostDirectoryMaskStorage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDirectoryMaskStorage {
    pub source: PathBuf,
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
        validate_hostname(&input.hostname)?;

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
            hostname: input.hostname,
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
            "host-directory" => {
                let source = input
                    .source
                    .ok_or_else(|| SpecError::new("host-directory mount source is required"))?;
                if source.is_empty() {
                    return Err(SpecError::new(
                        "host-directory mount source must not be empty",
                    ));
                }
                let source = PathBuf::from(source);
                if !source.is_absolute() {
                    return Err(SpecError::new(
                        "host-directory mount source must be absolute",
                    ));
                }
                let access = HostDirectoryAccess::parse(input.access.as_deref())?;
                let mask = HostDirectoryMask::parse(input.mask, access, &source)?;
                Ok(Self::HostDirectory {
                    path: input.path,
                    source,
                    access,
                    mask,
                })
            }
            other => Err(SpecError::new(format!("unsupported mount.kind: {other}"))),
        }
    }
}

impl HostDirectoryAccess {
    fn parse(value: Option<&str>) -> Result<Self, SpecError> {
        match value {
            Some("ro") => Ok(Self::ReadOnly),
            Some("rw") => Ok(Self::ReadWrite),
            Some(other) => Err(SpecError::new(format!(
                "unsupported host-directory mount access: {other}"
            ))),
            None => Err(SpecError::new("host-directory mount access is required")),
        }
    }
}

impl HostDirectoryMask {
    fn parse(
        input: Option<HostDirectoryMaskInput>,
        access: HostDirectoryAccess,
        source: &Path,
    ) -> Result<Option<Self>, SpecError> {
        let Some(input) = input else {
            return Ok(None);
        };
        if input.paths.is_empty() {
            return Err(SpecError::new(
                "host-directory mask paths must not be empty",
            ));
        }
        let mut paths = Vec::with_capacity(input.paths.len());
        for path in input.paths {
            validate_host_directory_mask_path(&path)?;
            if paths.contains(&path) {
                return Err(SpecError::new(format!(
                    "duplicate host-directory mask path: {path}"
                )));
            }
            for existing in &paths {
                if host_directory_mask_path_is_nested(existing, &path, source) {
                    return Err(SpecError::new(format!(
                        "nested host-directory mask path: {path}"
                    )));
                }
            }
            paths.push(path);
        }

        let storage = match (access, input.storage) {
            (HostDirectoryAccess::ReadOnly, Some(_)) => {
                return Err(SpecError::new(
                    "read-only host-directory masks must not declare storage",
                ));
            }
            (HostDirectoryAccess::ReadOnly, None) => None,
            (HostDirectoryAccess::ReadWrite, Some(storage)) => {
                Some(HostDirectoryMaskStorage::parse(storage)?)
            }
            (HostDirectoryAccess::ReadWrite, None) => {
                return Err(SpecError::new(
                    "writable host-directory masks require storage",
                ));
            }
        };

        if let Some(storage) = &storage {
            validate_host_directory_mask_storage_isolated(source, &storage.source, &paths)?;
        }

        Ok(Some(Self { paths, storage }))
    }
}

impl HostDirectoryMaskStorage {
    fn parse(input: HostDirectoryMaskStorageInput) -> Result<Self, SpecError> {
        let source = input
            .source
            .ok_or_else(|| SpecError::new("host-directory mask storage source is required"))?;
        if source.is_empty() {
            return Err(SpecError::new(
                "host-directory mask storage source must not be empty",
            ));
        }
        let source = PathBuf::from(source);
        if !source.is_absolute() {
            return Err(SpecError::new(
                "host-directory mask storage source must be absolute",
            ));
        }
        match input.access.as_deref() {
            Some("rw") => Ok(Self { source }),
            Some(_) | None => Err(SpecError::new(
                "host-directory mask storage access must be rw",
            )),
        }
    }
}

fn validate_host_directory_mask_path(path: &str) -> Result<(), SpecError> {
    if !path.starts_with('/') {
        return Err(SpecError::new("host-directory mask path must be absolute"));
    }
    if path == "/" {
        return Err(SpecError::new("host-directory mask path must not be root"));
    }
    if path
        .split('/')
        .skip(1)
        .any(|component| component.is_empty())
    {
        return Err(SpecError::new(
            "host-directory mask path must not contain empty components",
        ));
    }
    if path
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err(SpecError::new(
            "host-directory mask path must not contain '.' or '..' components",
        ));
    }
    Ok(())
}

fn host_directory_mask_path_is_nested(left: &str, right: &str, source: &Path) -> bool {
    let case_insensitive = host_path_is_case_insensitive(source);
    let left = left
        .split('/')
        .skip(1)
        .map(|component| normalize_mask_component(component, case_insensitive))
        .collect::<Vec<_>>();
    let right = right
        .split('/')
        .skip(1)
        .map(|component| normalize_mask_component(component, case_insensitive))
        .collect::<Vec<_>>();
    let shortest_len = left.len().min(right.len());
    left.len() != right.len()
        && left
            .iter()
            .take(shortest_len)
            .zip(right.iter())
            .all(|(left, right)| left == right)
}

fn normalize_mask_component(component: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        component.to_ascii_lowercase()
    } else {
        component.to_string()
    }
}

fn validate_host_directory_mask_storage_isolated(
    source: &Path,
    storage: &Path,
    masks: &[String],
) -> Result<(), SpecError> {
    let source = realpath_or_resolve(source);
    let storage = realpath_or_resolve(storage);
    if path_inside_or_equal(&source, &storage) {
        return Err(SpecError::new(
            "host-directory mask storage source must not be inside the bind source",
        ));
    }
    for mask in masks {
        let upper_path = realpath_or_resolve(&storage.join(mask.trim_start_matches('/')));
        if path_inside_or_equal(&source, &upper_path) {
            return Err(SpecError::new(
                "host-directory mask storage entries must not resolve inside the bind source",
            ));
        }
    }
    reject_mask_storage_hard_links(&source, &storage, masks)
}

fn realpath_or_resolve(path: &Path) -> PathBuf {
    match fs::canonicalize(path) {
        Ok(path) => path,
        Err(_) => {
            let Some(parent) = path.parent() else {
                return path.to_path_buf();
            };
            if parent == path {
                return path.to_path_buf();
            }
            let Some(name) = path.file_name() else {
                return path.to_path_buf();
            };
            realpath_or_resolve(parent).join(name)
        }
    }
}

fn path_inside_or_equal(parent: &Path, child: &Path) -> bool {
    child == parent || child.starts_with(parent)
}

fn reject_mask_storage_hard_links(
    source: &Path,
    storage: &Path,
    masks: &[String],
) -> Result<(), SpecError> {
    let mut upper_inodes = HashSet::new();
    for mask in masks {
        collect_linked_regular_file_inodes(
            &realpath_or_resolve(&storage.join(mask.trim_start_matches('/'))),
            &mut upper_inodes,
        );
    }
    if upper_inodes.is_empty() {
        return Ok(());
    }
    if tree_contains_regular_file_inode(source, &upper_inodes) {
        return Err(SpecError::new(
            "host-directory mask storage entries must not hard-link to the bind source",
        ));
    }
    Ok(())
}

fn collect_linked_regular_file_inodes(path: &Path, inodes: &mut HashSet<(u64, u64)>) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.is_file() {
        if metadata.nlink() > 1 {
            inodes.insert((metadata.dev(), metadata.ino()));
        }
        return;
    }
    if !metadata.is_dir() {
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        collect_linked_regular_file_inodes(&entry.path(), inodes);
    }
}

fn tree_contains_regular_file_inode(path: &Path, inodes: &HashSet<(u64, u64)>) -> bool {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return false;
    };
    if metadata.is_file() {
        return inodes.contains(&(metadata.dev(), metadata.ino()));
    }
    if !metadata.is_dir() {
        return false;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return false;
    };
    entries
        .flatten()
        .any(|entry| tree_contains_regular_file_inode(&entry.path(), inodes))
}

#[cfg(target_os = "macos")]
fn host_path_is_case_insensitive(path: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = realpath_or_resolve(path);
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    let value = unsafe { libc::pathconf(path.as_ptr(), libc::_PC_CASE_SENSITIVE) };
    value == 0
}

#[cfg(not(target_os = "macos"))]
fn host_path_is_case_insensitive(_path: &Path) -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MicroVmSpecInput {
    pub name: Option<String>,
    pub hostname: String,
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

fn validate_hostname(hostname: &str) -> Result<(), SpecError> {
    if hostname.is_empty() {
        return Err(SpecError::new("hostname must not be empty"));
    }
    if hostname.len() > 64 {
        return Err(SpecError::new("hostname must be at most 64 characters"));
    }
    if !hostname
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        return Err(SpecError::new("hostname must be a valid hostname"));
    }
    for label in hostname.split('.') {
        if label.is_empty() {
            return Err(SpecError::new("hostname must be a valid hostname"));
        }
        if label.len() > 63 {
            return Err(SpecError::new(
                "hostname labels must be at most 63 characters",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(SpecError::new("hostname must be a valid hostname"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootfsStorageSpecInput {
    pub kind: String,
    pub block_size: Option<u64>,
    pub max_dirty_bytes: Option<u64>,
    pub path: Option<String>,
}

impl RootfsStorageSpec {
    fn parse(input: RootfsStorageSpecInput) -> Result<Self, SpecError> {
        Ok(match input.kind.as_str() {
            "cow-block-store" => {
                let (block_size, max_dirty_bytes) = parse_rootfs_block_storage_limits(&input)?;
                Self::CowBlockStore {
                    block_size,
                    max_dirty_bytes,
                }
            }
            "ephemeral-cow" => {
                let (block_size, max_dirty_bytes) = parse_rootfs_block_storage_limits(&input)?;
                Self::EphemeralCow {
                    block_size,
                    max_dirty_bytes,
                }
            }
            "persistent-qcow2-overlay" => {
                let path = input
                    .path
                    .ok_or_else(|| SpecError::new("rootfs.storage.path is required"))?;
                if path.is_empty() {
                    return Err(SpecError::new("rootfs.storage.path must not be empty"));
                }
                if path.contains('\0') {
                    return Err(SpecError::new(
                        "rootfs.storage.path must not contain NUL bytes",
                    ));
                }
                let path = PathBuf::from(path);
                if !path.is_absolute() {
                    return Err(SpecError::new("rootfs.storage.path must be absolute"));
                }
                Self::PersistentQcow2Overlay { path }
            }
            other => {
                return Err(SpecError::new(format!(
                    "unsupported rootfs.storage.kind: {other}"
                )));
            }
        })
    }
}

fn parse_rootfs_block_storage_limits(
    input: &RootfsStorageSpecInput,
) -> Result<(u64, u64), SpecError> {
    let block_size = input
        .block_size
        .ok_or_else(|| SpecError::new("rootfs.storage.blockSize is required"))?;
    let max_dirty_bytes = input
        .max_dirty_bytes
        .ok_or_else(|| SpecError::new("rootfs.storage.maxDirtyBytes is required"))?;
    if block_size == 0 || block_size % 512 != 0 {
        return Err(SpecError::new(
            "rootfs.storage.blockSize must be a positive multiple of 512",
        ));
    }
    if max_dirty_bytes < block_size {
        return Err(SpecError::new(
            "rootfs.storage.maxDirtyBytes must be at least rootfs.storage.blockSize",
        ));
    }
    Ok((block_size, max_dirty_bytes))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountSpecInput {
    pub kind: String,
    pub path: String,
    pub writable: Option<bool>,
    pub source: Option<String>,
    pub access: Option<String>,
    pub mask: Option<HostDirectoryMaskInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDirectoryMaskInput {
    pub paths: Vec<String>,
    pub storage: Option<HostDirectoryMaskStorageInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDirectoryMaskStorageInput {
    pub source: Option<String>,
    pub access: Option<String>,
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "sandbox-config-{name}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn valid_input() -> MicroVmSpecInput {
        MicroVmSpecInput {
            name: Some("test".to_string()),
            hostname: "sandbox".to_string(),
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
            block_size: Some(4096),
            max_dirty_bytes: Some(65536),
            path: None,
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
    fn parses_ephemeral_rootfs_storage_limits() {
        let mut input = valid_input();
        input.rootfs_storage = Some(RootfsStorageSpecInput {
            kind: "ephemeral-cow".to_string(),
            block_size: Some(65536),
            max_dirty_bytes: Some(131072),
            path: None,
        });

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(
            spec.rootfs.storage,
            Some(RootfsStorageSpec::EphemeralCow {
                block_size: 65536,
                max_dirty_bytes: 131072,
            }),
        );
    }

    #[test]
    fn parses_persistent_qcow2_overlay_path() {
        let mut input = valid_input();
        input.rootfs_storage = Some(RootfsStorageSpecInput {
            kind: "persistent-qcow2-overlay".to_string(),
            block_size: None,
            max_dirty_bytes: None,
            path: Some("/tmp/rootfs.qcow2".to_string()),
        });

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(
            spec.rootfs.storage,
            Some(RootfsStorageSpec::PersistentQcow2Overlay {
                path: PathBuf::from("/tmp/rootfs.qcow2"),
            }),
        );
    }

    #[test]
    fn rejects_cow_rootfs_storage_limit_below_block_size() {
        let mut input = valid_input();
        input.rootfs_storage = Some(RootfsStorageSpecInput {
            kind: "cow-block-store".to_string(),
            block_size: Some(4096),
            max_dirty_bytes: Some(1024),
            path: None,
        });

        let error = MicroVmSpec::build(input).unwrap_err();

        assert_eq!(
            error.to_string(),
            "rootfs.storage.maxDirtyBytes must be at least rootfs.storage.blockSize",
        );
    }

    #[test]
    fn rejects_relative_persistent_qcow2_overlay_path() {
        let mut input = valid_input();
        input.rootfs_storage = Some(RootfsStorageSpecInput {
            kind: "persistent-qcow2-overlay".to_string(),
            block_size: None,
            max_dirty_bytes: None,
            path: Some("rootfs.qcow2".to_string()),
        });

        let error = MicroVmSpec::build(input).unwrap_err();

        assert_eq!(error.to_string(), "rootfs.storage.path must be absolute");
    }

    #[test]
    fn keeps_requested_mount_and_network_shape() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "virtual-fs".to_string(),
            path: "/sandbox".to_string(),
            writable: Some(true),
            source: None,
            access: None,
            mask: None,
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
    fn keeps_requested_host_directory_mount_shape() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some("/host/workspace".to_string()),
            access: Some("rw".to_string()),
            mask: None,
        }];

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(
            spec.mounts,
            vec![MountSpec::HostDirectory {
                path: "/workspace".to_string(),
                source: PathBuf::from("/host/workspace"),
                access: HostDirectoryAccess::ReadWrite,
                mask: None,
            }],
        );
    }

    #[test]
    fn keeps_requested_host_directory_mask_shape() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some("/host/workspace".to_string()),
            access: Some("rw".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec![
                    "/node_modules".to_string(),
                    "/packages/a/node_modules".to_string(),
                ],
                storage: Some(HostDirectoryMaskStorageInput {
                    source: Some("/host/mask-storage".to_string()),
                    access: Some("rw".to_string()),
                }),
            }),
        }];

        let spec = MicroVmSpec::build(input).unwrap();

        assert_eq!(
            spec.mounts,
            vec![MountSpec::HostDirectory {
                path: "/workspace".to_string(),
                source: PathBuf::from("/host/workspace"),
                access: HostDirectoryAccess::ReadWrite,
                mask: Some(HostDirectoryMask {
                    paths: vec![
                        "/node_modules".to_string(),
                        "/packages/a/node_modules".to_string(),
                    ],
                    storage: Some(HostDirectoryMaskStorage {
                        source: PathBuf::from("/host/mask-storage"),
                    }),
                }),
            }],
        );
    }

    #[test]
    fn rejects_host_directory_mask_paths_with_empty_components() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some("/host/workspace".to_string()),
            access: Some("ro".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec!["/node_modules/".to_string()],
                storage: None,
            }),
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "host-directory mask path must not contain empty components",
        );
    }

    #[test]
    fn rejects_nested_host_directory_mask_paths() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some("/host/workspace".to_string()),
            access: Some("ro".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec![
                    "/node_modules".to_string(),
                    "/node_modules/.bin".to_string(),
                ],
                storage: None,
            }),
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "nested host-directory mask path: /node_modules/.bin",
        );
    }

    #[test]
    fn preserves_case_sensitive_host_directory_mask_paths() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some("/host/workspace".to_string()),
            access: Some("rw".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec!["/Foo/bar".to_string(), "/foo".to_string()],
                storage: None,
            }),
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "writable host-directory masks require storage",
        );
    }

    #[test]
    fn rejects_host_directory_mask_storage_inside_source() {
        let source = TempTree::new("source");
        let storage = source.path.join(".sandbox-mask");
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some(source.path.to_string_lossy().into_owned()),
            access: Some("rw".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec!["/node_modules".to_string()],
                storage: Some(HostDirectoryMaskStorageInput {
                    source: Some(storage.to_string_lossy().into_owned()),
                    access: Some("rw".to_string()),
                }),
            }),
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "host-directory mask storage source must not be inside the bind source",
        );
    }

    #[test]
    fn rejects_host_directory_mask_storage_entries_that_reenter_source() {
        let root = TempTree::new("root");
        let source = root.path.join("workspace");
        fs::create_dir(&source).unwrap();
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some(source.to_string_lossy().into_owned()),
            access: Some("rw".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec!["/workspace".to_string()],
                storage: Some(HostDirectoryMaskStorageInput {
                    source: Some(root.path.to_string_lossy().into_owned()),
                    access: Some("rw".to_string()),
                }),
            }),
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "host-directory mask storage entries must not resolve inside the bind source",
        );
    }

    #[test]
    fn rejects_host_directory_mask_storage_hard_links_to_source() {
        let source = TempTree::new("source");
        let storage = TempTree::new("storage");
        fs::write(source.path.join("lower.txt"), "lower").unwrap();
        fs::create_dir(storage.path.join("node_modules")).unwrap();
        fs::hard_link(
            source.path.join("lower.txt"),
            storage.path.join("node_modules").join("linked.txt"),
        )
        .unwrap();
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some(source.path.to_string_lossy().into_owned()),
            access: Some("rw".to_string()),
            mask: Some(HostDirectoryMaskInput {
                paths: vec!["/node_modules".to_string()],
                storage: Some(HostDirectoryMaskStorageInput {
                    source: Some(storage.path.to_string_lossy().into_owned()),
                    access: Some("rw".to_string()),
                }),
            }),
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(
            err.to_string(),
            "host-directory mask storage entries must not hard-link to the bind source",
        );
    }

    #[test]
    fn rejects_host_directory_mounts_without_access() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "host-directory".to_string(),
            path: "/workspace".to_string(),
            writable: None,
            source: Some("/host/workspace".to_string()),
            access: None,
            mask: None,
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(err.to_string(), "host-directory mount access is required",);
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
    fn rejects_hostname_above_linux_uts_limit() {
        let mut input = valid_input();
        input.hostname = "a".repeat(65);

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(err.to_string(), "hostname must be at most 64 characters");
    }

    #[test]
    fn rejects_relative_mount_paths() {
        let mut input = valid_input();
        input.mounts = vec![MountSpecInput {
            kind: "virtual-fs".to_string(),
            path: "sandbox".to_string(),
            writable: None,
            source: None,
            access: None,
            mask: None,
        }];

        let err = MicroVmSpec::build(input).unwrap_err();
        assert_eq!(err.to_string(), "mount.path must be absolute");
    }
}
