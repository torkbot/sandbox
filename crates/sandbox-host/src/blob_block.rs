use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use bson::Document;
use futures_util::stream::{self, StreamExt, TryStreamExt};
use object_store::aws::AmazonS3Builder;
use object_store::azure::MicrosoftAzureBuilder;
use object_store::client::SpawnedReqwestConnector;
use object_store::gcp::GoogleCloudStorageBuilder;
use object_store::local::LocalFileSystem;
use object_store::path::Path;
use object_store::prefix::PrefixStore;
use object_store::{ObjectStore, ObjectStoreExt, PutMode, UpdateVersion};
use sandbox::block_storage::{CowBlockStore, format_empty_ext4};
use sandbox::runtime::BlockDeviceService;
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;
use tokio::sync::{Semaphore, oneshot, watch};
use tokio::task::JoinHandle;

const BLOCK_SIZE: u64 = 4 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct BlobBlockConfig {
    pub pack_bytes: usize,
    pub background_upload_bytes: u64,
    pub max_dirty_bytes: u64,
    pub max_cached_bytes: u64,
    pub object_concurrency: usize,
    pub lease_duration: Duration,
    pub lease_renew_interval: Duration,
    pub lease_request_timeout: Duration,
    pub lease_close_timeout: Duration,
    pub block_close_timeout: Duration,
}

impl BlobBlockConfig {
    fn validate(&self) -> Result<(), BlobBlockFailure> {
        if self.pack_bytes < BLOCK_SIZE as usize
            || self.pack_bytes > u32::MAX as usize
            || !self.pack_bytes.is_multiple_of(BLOCK_SIZE as usize)
            || self.background_upload_bytes < BLOCK_SIZE
            || self.max_dirty_bytes < BLOCK_SIZE
            || self.background_upload_bytes > self.max_dirty_bytes
            || self.max_cached_bytes < BLOCK_SIZE
            || self.object_concurrency == 0
            || self.lease_duration.is_zero()
            || self.lease_renew_interval.is_zero()
            || self.lease_renew_interval + self.lease_request_timeout >= self.lease_duration
            || self.lease_close_timeout.is_zero()
            || self.block_close_timeout.is_zero()
        {
            return Err(BlobBlockFailure::new(
                "storage-error",
                "invalid blob block host configuration",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct BlobBlockFailure {
    pub code: &'static str,
    pub message: String,
    pub retry_after_ms: Option<u64>,
}

impl BlobBlockFailure {
    fn new(code: &'static str, error: impl fmt::Display) -> Self {
        Self {
            code,
            message: error.to_string(),
            retry_after_ms: None,
        }
    }

    fn locked(volume: &str, retry_after_ms: Option<u64>) -> Self {
        Self {
            code: "volume-locked",
            message: format!("block volume {volume} is already leased"),
            retry_after_ms,
        }
    }

    fn lease_provider_error(error: impl fmt::Display, lease_duration: Duration) -> Self {
        Self {
            code: "lease-provider-error",
            message: format!("blob block lease state is uncertain: {error}"),
            retry_after_ms: Some(lease_duration.as_millis() as u64),
        }
    }

    fn lease_store_failure(error: object_store::Error, lease_duration: Duration) -> Self {
        let (code, message) = match &error {
            object_store::Error::Precondition { .. } => (
                "lease-lost",
                format!("blob block lease ownership was lost: {error}"),
            ),
            object_store::Error::PermissionDenied { .. }
            | object_store::Error::Unauthenticated { .. } => (
                "lease-authentication-failed",
                format!("blob block lease authentication failed: {error}"),
            ),
            _ => (
                "lease-provider-error",
                format!("blob block lease state is uncertain: {error}"),
            ),
        };
        Self {
            code,
            message,
            retry_after_ms: Some(lease_duration.as_millis() as u64),
        }
    }
}

fn provider_failure(error: object_store::Error) -> BlobBlockFailure {
    let code = match &error {
        object_store::Error::PermissionDenied { .. }
        | object_store::Error::Unauthenticated { .. } => "authentication-failed",
        _ => "provider-error",
    };
    BlobBlockFailure::new(code, error)
}

impl fmt::Display for BlobBlockFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for BlobBlockFailure {}

pub struct BlobBlockVolume {
    runtime: Arc<Runtime>,
    provider: Arc<dyn ObjectStore>,
    volume_root: Path,
    metadata_path: Path,
    metadata: VolumeMetadata,
    provisioned: bool,
    store: Option<Arc<PackedObjectBlockStore>>,
    _lease: VolumeLease,
    size: u64,
    closed: bool,
    config: BlobBlockConfig,
}

impl BlobBlockVolume {
    pub fn acquire(config: &BlobBlockConfig, document: Document) -> Result<Self, BlobBlockFailure> {
        config.validate()?;
        let request: AcquireRequest = bson::deserialize_from_document(document)
            .map_err(|error| BlobBlockFailure::new("invalid-request", error))?;
        request
            .validate()
            .map_err(|error| BlobBlockFailure::new("invalid-request", error))?;
        let size_bytes = request.size_bytes();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()
                .map_err(|error| BlobBlockFailure::new("storage-error", error))?,
        );
        let provider = ProviderStore::build(&request.provider, &runtime)
            .map_err(|error| BlobBlockFailure::new("provider-error", error))?;
        let volume_root = Path::from(format!("volumes/{}", request.volume));
        let lease = match provider.local_root.as_ref() {
            Some(root) => VolumeLease::Local {
                _lease: LocalLease::acquire(root, request.provider.prefix(), &request.volume)?,
            },
            None => VolumeLease::Object {
                _lease: runtime.block_on(ObjectLease::acquire(
                    runtime.clone(),
                    provider.store.clone(),
                    volume_root.clone().join("lease.json"),
                    request.volume.clone(),
                    config.clone(),
                ))?,
            },
        };

        let metadata_path = volume_root.clone().join("metadata.json");
        let metadata = lease.metadata(&runtime, &provider.store, &metadata_path)?;
        lease.revalidate()?;
        let (metadata, provisioned) = match metadata {
            Some(metadata) => {
                metadata.validate(size_bytes)?;
                (metadata, true)
            }
            None => (VolumeMetadata::new(size_bytes), false),
        };
        Ok(Self {
            runtime,
            provider: provider.store,
            volume_root,
            metadata_path,
            metadata,
            provisioned,
            store: None,
            _lease: lease,
            size: size_bytes,
            closed: false,
            config: config.clone(),
        })
    }

    pub fn service(&mut self) -> Result<BlockDeviceService, BlobBlockFailure> {
        if self.store.is_none() {
            let active_metadata = if self.provisioned && self._lease.requires_isolated_generation()
            {
                let next = self.metadata.next_generation();
                self.runtime
                    .block_on(clone_manifest_generation(
                        self.provider.clone(),
                        self.volume_root
                            .clone()
                            .join("data")
                            .join(self.metadata.generation.as_str()),
                        self.volume_root
                            .clone()
                            .join("data")
                            .join(next.generation.as_str()),
                    ))
                    .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
                self._lease.revalidate()?;
                next
            } else {
                self.metadata.clone()
            };
            let generation_root = self
                .volume_root
                .clone()
                .join("data")
                .join(active_metadata.generation.as_str());
            let manifest = self
                .runtime
                .block_on(read_manifest(
                    &self.provider,
                    &generation_root.clone().join("manifest.json"),
                ))
                .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
            let manifest = match manifest {
                Some(manifest) => manifest,
                None if self.provisioned => {
                    return Err(BlobBlockFailure::new(
                        "storage-error",
                        "missing blob block manifest for provisioned volume",
                    ));
                }
                None => BlockManifest::default(),
            };
            manifest
                .validate(self.size, self.config.pack_bytes)
                .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
            let store = Arc::new(PackedObjectBlockStore::new(
                self.runtime.clone(),
                self.provider.clone(),
                generation_root,
                self.volume_root.clone().join("objects"),
                manifest,
                self.size,
                self.config.clone(),
            ));
            if !self.provisioned {
                if let Err(error) =
                    format_empty_ext4(store.clone(), self.size, active_metadata.fs_uuid)
                {
                    return Err(BlobBlockFailure::new("storage-error", error));
                }
            }
            if !self.provisioned || active_metadata.generation != self.metadata.generation {
                if let Err(error) = self._lease.commit_metadata(
                    &self.runtime,
                    &self.provider,
                    &self.metadata_path,
                    &active_metadata,
                ) {
                    return Err(error);
                }
                self.metadata = active_metadata;
                self.provisioned = true;
            }
            if let Err(error) = self._lease.revalidate() {
                return Err(error);
            }
            self.store = Some(store);
        }
        Ok(BlockDeviceService {
            storage: self
                .store
                .as_ref()
                .expect("block store initialized")
                .clone(),
            size: self.size,
        })
    }

    pub fn take_failure_receiver(&mut self) -> Option<mpsc::Receiver<BlobBlockFailure>> {
        self._lease.take_failure_receiver()
    }

    pub fn failed(&self) -> bool {
        self._lease.failed()
    }

    pub fn close(&mut self) -> Result<(), BlobBlockFailure> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if let Some(store) = self.store.as_ref()
            && let Err(error) = store.close()
        {
            self._lease.close(false)?;
            return Err(BlobBlockFailure::new("storage-error", error));
        }
        self._lease.close(true)
    }
}

impl Drop for BlobBlockVolume {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AcquireRequest {
    #[serde(rename = "type")]
    frame_type: String,
    provider: Provider,
    volume: String,
    size_bytes: String,
}

impl AcquireRequest {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.frame_type != "host.block.acquire" {
            return Err(format!("expected host.block.acquire, got {}", self.frame_type).into());
        }
        validate_volume(&self.volume)?;
        self.provider.validate()?;
        let size = self.size_bytes.parse::<u64>()?;
        if size < 8 * 1024 * 1024 || !size.is_multiple_of(4096) {
            return Err("sizeBytes must be a 4096-byte multiple of at least 8 MiB".into());
        }
        Ok(())
    }

    fn size_bytes(&self) -> u64 {
        self.size_bytes
            .parse()
            .expect("validated block size must parse")
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum Provider {
    Local {
        path: String,
        prefix: Option<String>,
    },
    S3 {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        prefix: Option<String>,
        auth: S3Auth,
    },
    Gcs {
        bucket: String,
        prefix: Option<String>,
        auth: GcsAuth,
    },
    Azure {
        account: String,
        container: String,
        endpoint: Option<String>,
        prefix: Option<String>,
        auth: AzureAuth,
    },
}

impl Provider {
    fn prefix(&self) -> Option<&str> {
        match self {
            Self::Local { prefix, .. }
            | Self::S3 { prefix, .. }
            | Self::Gcs { prefix, .. }
            | Self::Azure { prefix, .. } => prefix.as_deref(),
        }
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(prefix) = self.prefix() {
            validate_prefix(prefix)?;
        }
        match self {
            Self::Local { path, .. } => {
                if !FsPath::new(path).is_absolute() {
                    return Err("local provider path must be absolute".into());
                }
                require_string(path, "local provider path")
            }
            Self::S3 {
                bucket,
                region,
                endpoint,
                auth,
                ..
            } => {
                require_string(bucket, "S3 bucket")?;
                require_string(region, "S3 region")?;
                validate_endpoint(endpoint.as_deref())?;
                auth.validate()
            }
            Self::Gcs { bucket, auth, .. } => {
                require_string(bucket, "GCS bucket")?;
                auth.validate()
            }
            Self::Azure {
                account,
                container,
                endpoint,
                auth,
                ..
            } => {
                require_string(account, "Azure account")?;
                require_string(container, "Azure container")?;
                validate_endpoint(endpoint.as_deref())?;
                auth.validate()
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum S3Auth {
    Environment,
    AccessKey {
        #[serde(rename = "accessKeyId")]
        access_key_id: String,
        #[serde(rename = "secretAccessKey")]
        secret_access_key: String,
        #[serde(rename = "sessionToken")]
        session_token: Option<String>,
    },
}

impl S3Auth {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Environment => Ok(()),
            Self::AccessKey {
                access_key_id,
                secret_access_key,
                session_token,
            } => {
                require_string(access_key_id, "S3 access key id")?;
                require_string(secret_access_key, "S3 secret access key")?;
                if let Some(token) = session_token {
                    require_string(token, "S3 session token")?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum GcsAuth {
    Environment,
    ServiceAccount { key: String },
    BearerToken { token: String },
}

impl GcsAuth {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Environment => Ok(()),
            Self::ServiceAccount { key } => require_string(key, "GCS service account key"),
            Self::BearerToken { token } => require_string(token, "GCS bearer token"),
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum AzureAuth {
    Environment,
    AccessKey {
        #[serde(rename = "accessKey")]
        access_key: String,
    },
    BearerToken {
        token: String,
    },
    ClientSecret {
        #[serde(rename = "clientId")]
        client_id: String,
        #[serde(rename = "clientSecret")]
        client_secret: String,
        #[serde(rename = "tenantId")]
        tenant_id: String,
    },
}

impl AzureAuth {
    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Environment => Ok(()),
            Self::AccessKey { access_key } => require_string(access_key, "Azure access key"),
            Self::BearerToken { token } => require_string(token, "Azure bearer token"),
            Self::ClientSecret {
                client_id,
                client_secret,
                tenant_id,
            } => {
                require_string(client_id, "Azure client id")?;
                require_string(client_secret, "Azure client secret")?;
                require_string(tenant_id, "Azure tenant id")
            }
        }
    }
}

struct ProviderStore {
    store: Arc<dyn ObjectStore>,
    local_root: Option<PathBuf>,
}

impl ProviderStore {
    fn build(provider: &Provider, runtime: &Runtime) -> Result<Self, Box<dyn std::error::Error>> {
        let (store, local_root): (Arc<dyn ObjectStore>, Option<PathBuf>) = match provider {
            Provider::Local { path, .. } => (
                Arc::new(LocalFileSystem::new_with_prefix(path)?),
                Some(PathBuf::from(path)),
            ),
            Provider::S3 {
                bucket,
                region,
                endpoint,
                auth,
                ..
            } => {
                let mut builder = match auth {
                    S3Auth::Environment => AmazonS3Builder::from_env(),
                    S3Auth::AccessKey {
                        access_key_id,
                        secret_access_key,
                        session_token,
                    } => {
                        let builder = AmazonS3Builder::new()
                            .with_access_key_id(access_key_id)
                            .with_secret_access_key(secret_access_key);
                        match session_token {
                            Some(token) => builder.with_token(token),
                            None => builder,
                        }
                    }
                }
                .with_bucket_name(bucket)
                .with_region(region)
                .with_http_connector(SpawnedReqwestConnector::new(runtime.handle().clone()));
                if let Some(endpoint) = endpoint {
                    builder = builder
                        .with_endpoint(endpoint)
                        .with_allow_http(endpoint.starts_with("http://"));
                }
                (Arc::new(builder.build()?), None)
            }
            Provider::Gcs { bucket, auth, .. } => {
                let builder = match auth {
                    GcsAuth::Environment => GoogleCloudStorageBuilder::from_env(),
                    GcsAuth::ServiceAccount { key } => {
                        GoogleCloudStorageBuilder::new().with_service_account_key(key)
                    }
                    GcsAuth::BearerToken { token } => {
                        GoogleCloudStorageBuilder::new().with_bearer_token(token)
                    }
                }
                .with_bucket_name(bucket)
                .with_http_connector(SpawnedReqwestConnector::new(runtime.handle().clone()));
                (Arc::new(builder.build()?), None)
            }
            Provider::Azure {
                account,
                container,
                endpoint,
                auth,
                ..
            } => {
                let mut builder = match auth {
                    AzureAuth::Environment => MicrosoftAzureBuilder::from_env(),
                    AzureAuth::AccessKey { access_key } => {
                        MicrosoftAzureBuilder::new().with_access_key(access_key)
                    }
                    AzureAuth::BearerToken { token } => {
                        MicrosoftAzureBuilder::new().with_bearer_token_authorization(token)
                    }
                    AzureAuth::ClientSecret {
                        client_id,
                        client_secret,
                        tenant_id,
                    } => MicrosoftAzureBuilder::new().with_client_secret_authorization(
                        client_id,
                        client_secret,
                        tenant_id,
                    ),
                }
                .with_account(account)
                .with_container_name(container)
                .with_http_connector(SpawnedReqwestConnector::new(runtime.handle().clone()));
                if let Some(endpoint) = endpoint {
                    builder = builder
                        .with_endpoint(endpoint.clone())
                        .with_allow_http(endpoint.starts_with("http://"));
                }
                (Arc::new(builder.build()?), None)
            }
        };
        let store = match provider.prefix() {
            Some(prefix) => Arc::new(PrefixStore::new(store, prefix)) as Arc<dyn ObjectStore>,
            None => store,
        };
        Ok(Self { store, local_root })
    }
}

enum VolumeLease {
    Local { _lease: LocalLease },
    Object { _lease: ObjectLease },
}

impl VolumeLease {
    fn requires_isolated_generation(&self) -> bool {
        matches!(self, Self::Object { .. })
    }

    fn revalidate(&self) -> Result<(), BlobBlockFailure> {
        match self {
            Self::Local { .. } => Ok(()),
            Self::Object { _lease } => _lease.state.failure().map_or(Ok(()), Err),
        }
    }

    fn metadata(
        &self,
        runtime: &Arc<Runtime>,
        store: &Arc<dyn ObjectStore>,
        path: &Path,
    ) -> Result<Option<VolumeMetadata>, BlobBlockFailure> {
        match self {
            Self::Local { .. } => runtime
                .block_on(read_json(store, path))
                .map_err(|error| BlobBlockFailure::new("storage-error", error)),
            Self::Object { _lease } => runtime.block_on(_lease.state.metadata()),
        }
    }

    fn commit_metadata(
        &self,
        runtime: &Arc<Runtime>,
        store: &Arc<dyn ObjectStore>,
        path: &Path,
        metadata: &VolumeMetadata,
    ) -> Result<(), BlobBlockFailure> {
        match self {
            Self::Local { .. } => runtime
                .block_on(put_json_create(store, path, metadata))
                .map_err(|error| BlobBlockFailure::new("storage-error", error)),
            Self::Object { _lease } => {
                runtime.block_on(_lease.state.commit_metadata(metadata.clone()))
            }
        }
    }

    fn take_failure_receiver(&mut self) -> Option<mpsc::Receiver<BlobBlockFailure>> {
        match self {
            Self::Local { .. } => None,
            Self::Object { _lease } => _lease.failure_rx.take(),
        }
    }

    fn failed(&self) -> bool {
        match self {
            Self::Local { .. } => false,
            Self::Object { _lease } => _lease.state.failure().is_some(),
        }
    }

    fn close(&mut self, release: bool) -> Result<(), BlobBlockFailure> {
        match self {
            Self::Local { .. } => Ok(()),
            Self::Object { _lease } => _lease.close(release),
        }
    }
}

struct LocalLease {
    file: File,
}

impl LocalLease {
    fn acquire(
        root: &FsPath,
        prefix: Option<&str>,
        volume: &str,
    ) -> Result<Self, BlobBlockFailure> {
        let mut path = root.to_path_buf();
        if let Some(prefix) = prefix {
            path.push(prefix);
        }
        path.push("volumes");
        path.push(volume);
        fs::create_dir_all(&path)
            .map_err(|error| BlobBlockFailure::new("provider-error", error))?;
        path.push("lease.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| BlobBlockFailure::new("provider-error", error))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(BlobBlockFailure::locked(volume, None));
            }
            return Err(BlobBlockFailure::new("provider-error", error));
        }
        Ok(Self { file })
    }
}

impl Drop for LocalLease {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

struct ObjectLease {
    runtime: Arc<Runtime>,
    state: Arc<ObjectLeaseState>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
    failure_rx: Option<mpsc::Receiver<BlobBlockFailure>>,
    closed: bool,
}

struct ObjectLeaseState {
    store: Arc<dyn ObjectStore>,
    path: Path,
    owner: String,
    record: tokio::sync::Mutex<ObjectLeaseRecord>,
    failure: Mutex<Option<BlobBlockFailure>>,
    config: BlobBlockConfig,
}

struct ObjectLeaseRecord {
    version: UpdateVersion,
    metadata: Option<VolumeMetadata>,
}

#[derive(Serialize, Deserialize)]
struct LeaseDocument {
    owner: String,
    released: bool,
    metadata: Option<VolumeMetadata>,
}

impl ObjectLease {
    async fn acquire(
        runtime: Arc<Runtime>,
        store: Arc<dyn ObjectStore>,
        path: Path,
        volume: String,
        config: BlobBlockConfig,
    ) -> Result<Self, BlobBlockFailure> {
        let owner = bson::oid::ObjectId::new().to_hex();
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: owner.clone(),
            released: false,
            metadata: None,
        })
        .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
        let get_store = store.clone();
        let get_path = path.clone();
        let existing = tokio::spawn(async move { get_store.get(&get_path).await });
        let created = store
            .put_opts(&path, payload.into(), PutMode::Create.into())
            .await;
        let (version, metadata) = match created {
            Ok(result) => {
                existing.abort();
                (UpdateVersion::from(result), None)
            }
            Err(object_store::Error::AlreadyExists { .. }) => {
                let result = existing
                    .await
                    .map_err(|error| BlobBlockFailure::new("storage-error", error))?
                    .map_err(provider_failure)?;
                let meta = result.meta.clone();
                let bytes = result.bytes().await.map_err(provider_failure)?;
                let existing: LeaseDocument = serde_json::from_slice(&bytes)
                    .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
                if !existing.released {
                    let server_now = object_store_now_millis(&store, &path)
                        .await
                        .map_err(provider_failure)?;
                    if !lease_is_expired(
                        meta.last_modified.timestamp_millis(),
                        server_now,
                        config.lease_duration,
                    ) {
                        return Err(BlobBlockFailure::locked(
                            &volume,
                            Some(lease_retry_after_ms(
                                meta.last_modified.timestamp_millis(),
                                server_now,
                                config.lease_duration,
                            )),
                        ));
                    }
                }
                let prior = UpdateVersion {
                    e_tag: meta.e_tag,
                    version: meta.version,
                };
                let metadata = existing.metadata;
                let payload = serde_json::to_vec(&LeaseDocument {
                    owner: owner.clone(),
                    released: false,
                    metadata: metadata.clone(),
                })
                .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
                let result = store
                    .put_opts(&path, payload.into(), PutMode::Update(prior).into())
                    .await;
                match result {
                    Ok(result) => (UpdateVersion::from(result), metadata),
                    Err(object_store::Error::Precondition { .. }) => {
                        return Err(BlobBlockFailure::locked(&volume, None));
                    }
                    Err(error) => return Err(provider_failure(error)),
                }
            }
            Err(error) => {
                existing.abort();
                return Err(provider_failure(error));
            }
        };
        let state = Arc::new(ObjectLeaseState {
            store,
            path,
            owner,
            record: tokio::sync::Mutex::new(ObjectLeaseRecord { version, metadata }),
            failure: Mutex::new(None),
            config: config.clone(),
        });
        let (stop, mut stopped) = watch::channel(false);
        let (failure_tx, failure_rx) = mpsc::sync_channel(1);
        let renewal_state = state.clone();
        let task = runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(config.lease_renew_interval) => {
                        let failure = match tokio::time::timeout(config.lease_request_timeout, renewal_state.renew()).await {
                            Ok(Ok(())) => continue,
                            Ok(Err(error)) => error,
                            Err(_) => BlobBlockFailure::lease_provider_error("renewal request timed out", config.lease_duration),
                        };
                        *renewal_state.failure.lock().expect("lease failure lock poisoned") = Some(failure.clone());
                        let _ = failure_tx.send(failure);
                        return;
                        }
                    changed = stopped.changed() => {
                        if changed.is_err() || *stopped.borrow() {
                            return;
                        }
                    }
                }
            }
        });
        Ok(Self {
            runtime,
            state,
            stop,
            task: Some(task),
            failure_rx: Some(failure_rx),
            closed: false,
        })
    }

    fn close(&mut self, release: bool) -> Result<(), BlobBlockFailure> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = self.stop.send(true);
        if let Some(mut task) = self.task.take() {
            self.runtime.block_on(async {
                if tokio::time::timeout(self.state.config.lease_close_timeout, &mut task)
                    .await
                    .is_err()
                {
                    task.abort();
                    let _ = task.await;
                }
            });
        }
        if let Some(failure) = self.state.failure() {
            return Err(failure);
        }
        if !release {
            return Ok(());
        }
        self.runtime
            .block_on(async {
                tokio::time::timeout(self.state.config.lease_close_timeout, self.state.release())
                    .await
            })
            .map_err(|_| {
                BlobBlockFailure::lease_provider_error(
                    "release request timed out",
                    self.state.config.lease_duration,
                )
            })?
    }
}

async fn object_store_now_millis(
    store: &Arc<dyn ObjectStore>,
    lease_path: &Path,
) -> Result<i64, object_store::Error> {
    let probe_path = Path::from(format!("{lease_path}.clock"));
    store.put(&probe_path, Vec::<u8>::new().into()).await?;
    Ok(store
        .head(&probe_path)
        .await?
        .last_modified
        .timestamp_millis())
}

fn lease_is_expired(last_modified_ms: i64, server_now_ms: i64, lease_duration: Duration) -> bool {
    server_now_ms.saturating_sub(last_modified_ms) >= lease_duration.as_millis() as i64
}

fn lease_retry_after_ms(
    last_modified_ms: i64,
    server_now_ms: i64,
    lease_duration: Duration,
) -> u64 {
    let age_ms = server_now_ms.saturating_sub(last_modified_ms).max(0) as u64;
    (lease_duration.as_millis() as u64).saturating_sub(age_ms)
}

impl ObjectLeaseState {
    fn failure(&self) -> Option<BlobBlockFailure> {
        self.failure
            .lock()
            .expect("lease failure lock poisoned")
            .clone()
    }

    async fn metadata(&self) -> Result<Option<VolumeMetadata>, BlobBlockFailure> {
        Ok(self.record.lock().await.metadata.clone())
    }

    async fn renew(&self) -> Result<(), BlobBlockFailure> {
        let mut record = self.record.lock().await;
        let metadata = record.metadata.clone();
        self.update_document(&mut record, false, metadata).await
    }

    async fn update_document(
        &self,
        record: &mut ObjectLeaseRecord,
        released: bool,
        metadata: Option<VolumeMetadata>,
    ) -> Result<(), BlobBlockFailure> {
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: self.owner.clone(),
            released,
            metadata,
        })
        .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
        let result = self
            .store
            .put_opts(
                &self.path,
                payload.into(),
                PutMode::Update(record.version.clone()).into(),
            )
            .await
            .map_err(|error| {
                BlobBlockFailure::lease_store_failure(error, self.config.lease_duration)
            })?;
        record.version = UpdateVersion::from(result);
        Ok(())
    }

    async fn commit_metadata(&self, metadata: VolumeMetadata) -> Result<(), BlobBlockFailure> {
        let mut record = self.record.lock().await;
        self.update_document(&mut record, false, Some(metadata.clone()))
            .await?;
        record.metadata = Some(metadata);
        Ok(())
    }

    async fn release(&self) -> Result<(), BlobBlockFailure> {
        let mut record = self.record.lock().await;
        let metadata = record.metadata.clone();
        self.update_document(&mut record, true, metadata).await
    }
}

impl Drop for ObjectLease {
    fn drop(&mut self) {
        let _ = self.close(true);
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlockLocation {
    object: String,
    offset: u32,
    len: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct BlockManifest {
    #[serde(default = "manifest_version")]
    version: u32,
    #[serde(default)]
    blocks: HashMap<u64, BlockLocation>,
}

impl Default for BlockManifest {
    fn default() -> Self {
        Self {
            version: manifest_version(),
            blocks: HashMap::new(),
        }
    }
}

fn manifest_version() -> u32 {
    1
}

impl BlockManifest {
    fn validate(&self, size: u64, pack_bytes: usize) -> io::Result<()> {
        if self.version != manifest_version() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported blob block manifest version: {}", self.version),
            ));
        }
        let block_count = size.div_ceil(BLOCK_SIZE);
        for (index, location) in &self.blocks {
            let end = u64::from(location.offset)
                .checked_add(u64::from(location.len))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "block range overflow")
                })?;
            if *index >= block_count
                || location.len == 0
                || u64::from(location.len) > BLOCK_SIZE
                || end > pack_bytes as u64
                || location.object.len() != 24
                || !location.object.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid blob block manifest entry",
                ));
            }
        }
        Ok(())
    }
}

struct BlockCache {
    blocks: HashMap<u64, Vec<u8>>,
    order: VecDeque<u64>,
    bytes: u64,
    max_bytes: u64,
}

impl BlockCache {
    fn new(max_bytes: u64) -> Self {
        Self {
            blocks: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_bytes,
        }
    }

    fn insert(&mut self, index: u64, data: Vec<u8>) {
        if let Some(previous) = self.blocks.insert(index, data.clone()) {
            self.bytes = self.bytes.saturating_sub(previous.len() as u64);
            self.order.retain(|cached| *cached != index);
        }
        self.bytes += data.len() as u64;
        self.order.push_back(index);
        while self.bytes > self.max_bytes {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(removed) = self.blocks.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(removed.len() as u64);
            }
        }
    }

    fn remove(&mut self, index: u64) {
        if let Some(removed) = self.blocks.remove(&index) {
            self.bytes = self.bytes.saturating_sub(removed.len() as u64);
        }
    }
}

struct PackedObjectBlockStore {
    runtime: Arc<Runtime>,
    provider: Arc<dyn ObjectStore>,
    generation_root: Path,
    object_root: Path,
    manifest: Mutex<BlockManifest>,
    staging: Mutex<StagingState>,
    cache: Mutex<BlockCache>,
    flushing: Mutex<()>,
    upload_permits: Arc<Semaphore>,
    size: u64,
    config: BlobBlockConfig,
}

#[derive(Clone)]
struct DirtyBlock {
    sequence: u64,
    data: Option<Vec<u8>>,
}

#[derive(Default)]
struct StagingState {
    next_sequence: u64,
    dirty: HashMap<u64, DirtyBlock>,
    scheduled: HashMap<u64, u64>,
    pending: Vec<PendingUpload>,
}

struct PendingUpload {
    receiver: oneshot::Receiver<io::Result<Vec<(u64, u64, BlockLocation)>>>,
    bytes: u64,
}

impl PackedObjectBlockStore {
    fn new(
        runtime: Arc<Runtime>,
        provider: Arc<dyn ObjectStore>,
        generation_root: Path,
        object_root: Path,
        manifest: BlockManifest,
        size: u64,
        config: BlobBlockConfig,
    ) -> Self {
        Self {
            runtime,
            provider,
            generation_root,
            object_root,
            manifest: Mutex::new(manifest),
            staging: Mutex::new(StagingState::default()),
            cache: Mutex::new(BlockCache::new(config.max_cached_bytes)),
            flushing: Mutex::new(()),
            upload_permits: Arc::new(Semaphore::new(config.object_concurrency)),
            size,
            config,
        }
    }

    fn wait_for<T, F>(&self, future: F) -> io::Result<T>
    where
        T: Send + 'static,
        F: Future<Output = io::Result<T>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.runtime.spawn(async move {
            let _ = sender.send(future.await);
        });
        receiver
            .recv()
            .map_err(|_| io::Error::other("blob block storage runtime stopped"))?
    }

    fn close(&self) -> io::Result<()> {
        self.flush_dirty(Some(self.config.block_close_timeout))
    }

    fn schedule_uploads(&self, force: bool) {
        let mut staging = self
            .staging
            .lock()
            .expect("blob block staging lock poisoned");
        let blocks = staging
            .dirty
            .iter()
            .filter_map(|(index, block)| {
                block.data.as_ref().and_then(|data| {
                    (staging.scheduled.get(index) != Some(&block.sequence))
                        .then(|| (*index, block.sequence, data.clone()))
                })
            })
            .collect::<Vec<_>>();
        let bytes = blocks
            .iter()
            .map(|(_, _, data)| data.len() as u64)
            .sum::<u64>();
        if blocks.is_empty() || (!force && bytes < self.config.background_upload_bytes) {
            return;
        }
        for (index, sequence, _) in &blocks {
            staging.scheduled.insert(*index, *sequence);
        }
        let provider = self.provider.clone();
        let object_root = self.object_root.clone();
        let config = self.config.clone();
        let upload_permits = self.upload_permits.clone();
        let (sender, receiver) = oneshot::channel();
        self.runtime.spawn(async move {
            let _ = sender
                .send(upload_blocks(provider, object_root, upload_permits, config, blocks).await);
        });
        staging.pending.push(PendingUpload { receiver, bytes });
    }

    fn flush_dirty(&self, timeout: Option<Duration>) -> io::Result<()> {
        let _flushing = self
            .flushing
            .lock()
            .expect("blob block flush lock poisoned");
        self.schedule_uploads(true);
        let (dirty, pending) = {
            let mut staging = self
                .staging
                .lock()
                .expect("blob block staging lock poisoned");
            (staging.dirty.clone(), std::mem::take(&mut staging.pending))
        };
        if dirty.is_empty() {
            return Ok(());
        }
        let provider = self.provider.clone();
        let generation_root = self.generation_root.clone();
        let mut manifest = self
            .manifest
            .lock()
            .expect("blob block manifest lock poisoned")
            .clone();
        let flushed = dirty.clone();
        let result = self.wait_for(async move {
            let operation = async {
                let mut uploaded = HashSet::new();
                for pending in pending {
                    for (index, sequence, location) in pending
                        .receiver
                        .await
                        .map_err(|_| io::Error::other("blob block background upload stopped"))??
                    {
                        if dirty
                            .get(&index)
                            .is_some_and(|block| block.sequence == sequence)
                        {
                            manifest.blocks.insert(index, location);
                            uploaded.insert(index);
                        }
                    }
                }
                for (index, block) in &dirty {
                    match &block.data {
                        Some(_) if !uploaded.contains(index) => {
                            return Err(io::Error::other(
                                "blob block sync is missing an uploaded block",
                            ));
                        }
                        None => {
                            manifest.blocks.remove(index);
                        }
                        Some(_) => {}
                    }
                }
                provider
                    .put(
                        &generation_root.clone().join("manifest.json"),
                        serde_json::to_vec(&manifest)
                            .map_err(io::Error::other)?
                            .into(),
                    )
                    .await
                    .map_err(io::Error::other)?;
                Ok(manifest)
            };
            match timeout {
                Some(timeout) => tokio::time::timeout(timeout, operation)
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "blob block flush timed out")
                    })?,
                None => operation.await,
            }
        });
        manifest = match result {
            Ok(manifest) => manifest,
            Err(error) => {
                self.staging
                    .lock()
                    .expect("blob block staging lock poisoned")
                    .scheduled
                    .clear();
                return Err(error);
            }
        };
        *self
            .manifest
            .lock()
            .expect("blob block manifest lock poisoned") = manifest;
        let mut cache = self.cache.lock().expect("blob block cache lock poisoned");
        for (index, block) in &flushed {
            match &block.data {
                Some(data) => cache.insert(*index, data.clone()),
                None => cache.remove(*index),
            }
        }
        drop(cache);
        let mut staging = self
            .staging
            .lock()
            .expect("blob block staging lock poisoned");
        staging.dirty.retain(|index, block| {
            flushed
                .get(index)
                .is_none_or(|flushed| flushed.sequence != block.sequence)
        });
        staging.scheduled.clear();
        Ok(())
    }
}

async fn upload_blocks(
    provider: Arc<dyn ObjectStore>,
    object_root: Path,
    upload_permits: Arc<Semaphore>,
    config: BlobBlockConfig,
    mut blocks: Vec<(u64, u64, Vec<u8>)>,
) -> io::Result<Vec<(u64, u64, BlockLocation)>> {
    blocks.sort_unstable_by_key(|(index, _, _)| *index);
    let mut packs = Vec::<(String, Vec<u8>, Vec<(u64, u64, BlockLocation)>)>::new();
    for chunk in blocks.chunks(config.pack_bytes / BLOCK_SIZE as usize) {
        let object = bson::oid::ObjectId::new().to_hex();
        let mut bytes = Vec::with_capacity(config.pack_bytes);
        let mut locations = Vec::with_capacity(chunk.len());
        for (index, sequence, data) in chunk {
            let offset = bytes.len() as u32;
            bytes.extend_from_slice(data);
            locations.push((
                *index,
                *sequence,
                BlockLocation {
                    object: object.clone(),
                    offset,
                    len: data.len() as u32,
                },
            ));
        }
        packs.push((object, bytes, locations));
    }
    stream::iter(packs.into_iter().map(|(object, bytes, locations)| {
        let provider = provider.clone();
        let path = object_root.clone().join(object.as_str());
        let upload_permits = upload_permits.clone();
        async move {
            let _permit = upload_permits
                .acquire_owned()
                .await
                .map_err(|_| io::Error::other("blob block upload scheduler stopped"))?;
            provider
                .put_opts(&path, bytes.into(), PutMode::Create.into())
                .await
                .map_err(io::Error::other)?;
            Ok::<_, io::Error>(locations)
        }
    }))
    .buffer_unordered(config.object_concurrency)
    .try_collect::<Vec<_>>()
    .await
    .map(|packs| packs.into_iter().flatten().collect())
}

impl fmt::Debug for PackedObjectBlockStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackedObjectBlockStore")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl CowBlockStore for PackedObjectBlockStore {
    fn block_size(&self) -> u64 {
        BLOCK_SIZE
    }

    fn list_blocks(&self) -> io::Result<HashSet<u64>> {
        let mut blocks = self
            .manifest
            .lock()
            .expect("blob block manifest lock poisoned")
            .blocks
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        for (index, block) in self
            .staging
            .lock()
            .expect("blob block staging lock poisoned")
            .dirty
            .iter()
        {
            if block.data.is_some() {
                blocks.insert(*index);
            } else {
                blocks.remove(index);
            }
        }
        Ok(blocks)
    }

    fn read_blocks(&self, start: u64, count: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
        let end = start
            .checked_add(count)
            .ok_or_else(|| io::Error::other("blob block read range overflow"))?;
        if end > self.size.div_ceil(BLOCK_SIZE) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "blob block read exceeds volume size",
            ));
        }
        let mut blocks = HashMap::new();
        let mut reads = HashMap::<String, Vec<(u64, BlockLocation)>>::new();
        {
            let staging = self
                .staging
                .lock()
                .expect("blob block staging lock poisoned");
            let cached = self.cache.lock().expect("blob block cache lock poisoned");
            let manifest = self
                .manifest
                .lock()
                .expect("blob block manifest lock poisoned");
            for index in start..end {
                if let Some(block) = staging.dirty.get(&index) {
                    if let Some(data) = &block.data {
                        blocks.insert(index, data.clone());
                    }
                } else if let Some(data) = cached.blocks.get(&index) {
                    blocks.insert(index, data.clone());
                } else if let Some(location) = manifest.blocks.get(&index) {
                    reads
                        .entry(location.object.clone())
                        .or_default()
                        .push((index, location.clone()));
                }
            }
        }
        if !reads.is_empty() {
            let provider = self.provider.clone();
            let object_root = self.object_root.clone();
            let object_concurrency = self.config.object_concurrency;
            let fetched = self.wait_for(async move {
                stream::iter(reads.into_iter().map(|(object, entries)| {
                    let provider = provider.clone();
                    let path = object_root.clone().join(object.as_str());
                    async move {
                        let ranges = entries
                            .iter()
                            .map(|(_, location)| {
                                u64::from(location.offset)
                                    ..u64::from(location.offset) + u64::from(location.len)
                            })
                            .collect::<Vec<_>>();
                        let bytes = provider
                            .get_ranges(&path, &ranges)
                            .await
                            .map_err(io::Error::other)?;
                        Ok::<_, io::Error>(
                            entries
                                .into_iter()
                                .zip(bytes)
                                .map(|((index, location), bytes)| (index, location, bytes.to_vec()))
                                .collect::<Vec<_>>(),
                        )
                    }
                }))
                .buffer_unordered(object_concurrency)
                .try_collect::<Vec<_>>()
                .await
            })?;
            let staging = self
                .staging
                .lock()
                .expect("blob block staging lock poisoned");
            let mut cache = self.cache.lock().expect("blob block cache lock poisoned");
            let manifest = self
                .manifest
                .lock()
                .expect("blob block manifest lock poisoned");
            for entries in fetched {
                for (index, location, data) in entries {
                    if let Some(block) = staging.dirty.get(&index) {
                        match &block.data {
                            Some(data) => {
                                blocks.insert(index, data.clone());
                            }
                            None => {
                                blocks.remove(&index);
                            }
                        }
                    } else if let Some(data) = cache.blocks.get(&index) {
                        blocks.insert(index, data.clone());
                    } else if manifest.blocks.get(&index) == Some(&location) {
                        cache.insert(index, data.clone());
                        blocks.insert(index, data);
                    }
                }
            }
        }
        let mut blocks = blocks.into_iter().collect::<Vec<_>>();
        blocks.sort_unstable_by_key(|(index, _)| *index);
        Ok(blocks)
    }

    fn write_blocks(&self, chunks: Vec<(u64, Vec<u8>)>) -> io::Result<()> {
        let block_count = self.size.div_ceil(BLOCK_SIZE);
        if chunks.iter().any(|(index, data)| {
            *index >= block_count || data.is_empty() || data.len() > BLOCK_SIZE as usize
        }) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid blob block write",
            ));
        }
        let flushing = self
            .flushing
            .lock()
            .expect("blob block flush lock poisoned");
        let mut staging = self
            .staging
            .lock()
            .expect("blob block staging lock poisoned");
        for (index, data) in chunks {
            staging.next_sequence = staging
                .next_sequence
                .checked_add(1)
                .ok_or_else(|| io::Error::other("blob block write sequence overflow"))?;
            let block = DirtyBlock {
                sequence: staging.next_sequence,
                data: (!data.iter().all(|byte| *byte == 0)).then_some(data),
            };
            staging.dirty.insert(index, block);
        }
        drop(staging);
        self.schedule_uploads(false);
        let should_flush = {
            let staging = self
                .staging
                .lock()
                .expect("blob block staging lock poisoned");
            let dirty_bytes = (staging.dirty.len() as u64).saturating_mul(BLOCK_SIZE);
            let pending_bytes = staging
                .pending
                .iter()
                .fold(0_u64, |bytes, pending| bytes.saturating_add(pending.bytes));
            dirty_bytes >= self.config.max_dirty_bytes
                || pending_bytes >= self.config.max_dirty_bytes
        };
        drop(flushing);
        if should_flush {
            self.flush_dirty(None)
        } else {
            Ok(())
        }
    }

    fn flush(&self) -> io::Result<()> {
        self.flush_dirty(None)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VolumeMetadata {
    version: u32,
    size_bytes: u64,
    fs_uuid: [u8; 16],
    generation: String,
}

impl VolumeMetadata {
    fn new(size_bytes: u64) -> Self {
        let first = bson::oid::ObjectId::new().bytes();
        let second = bson::oid::ObjectId::new().bytes();
        let mut fs_uuid = [0; 16];
        fs_uuid[..12].copy_from_slice(&first);
        fs_uuid[12..].copy_from_slice(&second[..4]);
        Self {
            version: 1,
            size_bytes,
            fs_uuid,
            generation: bson::oid::ObjectId::new().to_hex(),
        }
    }

    fn next_generation(&self) -> Self {
        Self {
            version: self.version,
            size_bytes: self.size_bytes,
            fs_uuid: self.fs_uuid,
            generation: bson::oid::ObjectId::new().to_hex(),
        }
    }

    fn validate(&self, requested_size: u64) -> Result<(), BlobBlockFailure> {
        if self.version != 1 {
            return Err(BlobBlockFailure::new(
                "storage-error",
                format!("unsupported blob block volume version: {}", self.version),
            ));
        }
        if self.size_bytes != requested_size {
            return Err(BlobBlockFailure::new(
                "volume-mismatch",
                format!(
                    "blob block volume size mismatch: stored {}, requested {}",
                    self.size_bytes, requested_size
                ),
            ));
        }
        if self.generation.len() != 24
            || !self.generation.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(BlobBlockFailure::new(
                "storage-error",
                "invalid blob block volume generation",
            ));
        }
        Ok(())
    }
}

async fn read_json<T: for<'de> Deserialize<'de>>(
    store: &Arc<dyn ObjectStore>,
    path: &Path,
) -> Result<Option<T>, Box<dyn std::error::Error>> {
    match store.get(path).await {
        Ok(result) => Ok(Some(serde_json::from_slice(&result.bytes().await?)?)),
        Err(object_store::Error::NotFound { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn read_manifest(
    store: &Arc<dyn ObjectStore>,
    path: &Path,
) -> Result<Option<BlockManifest>, Box<dyn std::error::Error>> {
    read_json(store, path).await
}

async fn clone_manifest_generation(
    store: Arc<dyn ObjectStore>,
    source_path: Path,
    target_path: Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let source = source_path.join("manifest.json");
    let target = target_path.join("manifest.json");
    let manifest = read_manifest(&store, &source)
        .await?
        .ok_or_else(|| format!("missing blob block manifest at {source}"))?;
    put_json_create(&store, &target, &manifest).await?;
    Ok(())
}

async fn put_json_create<T: Serialize>(
    store: &Arc<dyn ObjectStore>,
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    store
        .put_opts(
            path,
            serde_json::to_vec(value)?.into(),
            PutMode::Create.into(),
        )
        .await?;
    Ok(())
}

fn validate_volume(volume: &str) -> Result<(), Box<dyn std::error::Error>> {
    if volume.is_empty()
        || volume.len() > 128
        || !volume
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || !volume
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !volume
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err("volume must be 1-128 letters, digits, '.', '_', or '-'".into());
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<(), Box<dyn std::error::Error>> {
    if prefix.is_empty()
        || prefix.contains('\0')
        || prefix.starts_with('/')
        || prefix.ends_with('/')
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("provider prefix must be a non-empty relative object path".into());
    }
    Ok(())
}

fn validate_endpoint(endpoint: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(endpoint) = endpoint
        && !endpoint.starts_with("https://")
        && !endpoint.starts_with("http://")
    {
        return Err("provider endpoint must be an HTTP(S) URL".into());
    }
    Ok(())
}

fn require_string(value: &str, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    if value.is_empty() || value.contains('\0') {
        return Err(format!("{field} must be a non-empty string without NUL bytes").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use bson::doc;

    use std::sync::Arc;

    use object_store::memory::InMemory;
    use object_store::path::Path as ObjectPath;
    use object_store::throttle::{ThrottleConfig, ThrottledStore};
    use object_store::{Error as ObjectStoreError, ObjectStore, ObjectStoreExt};
    use object_store::{PutMode, UpdateVersion};
    use sandbox::block_storage::CowBlockStore;
    use tokio::runtime::Runtime;

    use super::{
        BlobBlockConfig, BlobBlockFailure, BlobBlockVolume, BlockManifest, LeaseDocument,
        ObjectLease, PackedObjectBlockStore, VolumeLease, VolumeMetadata,
        clone_manifest_generation, lease_is_expired, lease_retry_after_ms, provider_failure,
    };

    const TEST_SIZE: u64 = 64 * 1024 * 1024;

    fn config() -> BlobBlockConfig {
        crate::blob_block_config()
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "sandbox-blob-block-{}",
                bson::oid::ObjectId::new().to_hex()
            ));
            fs::create_dir(&path).expect("create blob block test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn local_volume_is_sparse_exclusive_and_reopenable() {
        let directory = TestDirectory::new();
        let request = |size: u64| {
            doc! {
                "type": "host.block.acquire",
                "provider": {
                    "kind": "local",
                    "path": directory.0.to_string_lossy().to_string(),
                },
                "volume": "workspace",
                "sizeBytes": size.to_string(),
            }
        };

        let config = config();
        let mut first =
            BlobBlockVolume::acquire(&config, request(TEST_SIZE)).expect("acquire new volume");
        let acquired_bytes = allocated_bytes(&directory.0);
        assert!(
            acquired_bytes < 4096,
            "acquisition materialized {acquired_bytes} bytes before attachment"
        );
        let competing = BlobBlockVolume::acquire(&config, request(TEST_SIZE))
            .err()
            .expect("competing acquire must fail");
        assert_eq!(
            competing.to_string(),
            "block volume workspace is already leased"
        );

        first.service().expect("provision attached volume");
        let generation = first.metadata.generation.clone();
        let provisioned_bytes = allocated_bytes(&directory.0);
        assert!(
            provisioned_bytes < TEST_SIZE / 2,
            "sparse filesystem used {provisioned_bytes} bytes for a {TEST_SIZE}-byte volume"
        );

        drop(first);
        let reopened =
            BlobBlockVolume::acquire(&config, request(TEST_SIZE)).expect("reopen volume");
        drop(reopened);
        fs::remove_file(
            directory
                .0
                .join("volumes/workspace/data")
                .join(generation)
                .join("manifest.json"),
        )
        .expect("remove provisioned manifest");
        let mut damaged =
            BlobBlockVolume::acquire(&config, request(TEST_SIZE)).expect("acquire damaged volume");
        let error = damaged
            .service()
            .err()
            .expect("provisioned volume without a manifest must fail");
        assert!(error.to_string().contains("missing blob block manifest"));
        drop(damaged);
        let mismatch = BlobBlockVolume::acquire(&config, request(TEST_SIZE * 2))
            .err()
            .expect("size mismatch must fail");
        assert_eq!(
            mismatch.to_string(),
            format!(
                "blob block volume size mismatch: stored {TEST_SIZE}, requested {}",
                TEST_SIZE * 2
            )
        );
    }

    #[test]
    fn object_lease_fails_closed_after_an_ambiguous_write_version() {
        let runtime = Arc::new(Runtime::new().expect("create object lease test runtime"));
        let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/lease.json");
        let acquire = || {
            runtime.block_on(ObjectLease::acquire(
                runtime.clone(),
                store.clone(),
                path.clone(),
                "workspace".to_string(),
                config(),
            ))
        };

        let first = acquire().expect("acquire object lease");
        let competing = acquire().err().expect("competing object lease must fail");
        assert_eq!(
            competing.to_string(),
            "block volume workspace is already leased"
        );
        runtime.block_on(async {
            let current = store.get(&path).await.expect("read current lease");
            let version = UpdateVersion {
                e_tag: current.meta.e_tag.clone(),
                version: current.meta.version.clone(),
            };
            let payload = current.bytes().await.expect("read lease bytes");
            store
                .put_opts(&path, payload.into(), PutMode::Update(version).into())
                .await
                .expect("simulate renewal with a lost response");
        });
        drop(first);

        let blocked = acquire()
            .err()
            .expect("ambiguous release must fall back to lease expiry");
        assert_eq!(blocked.code, "volume-locked");
        assert!(blocked.retry_after_ms.is_some_and(|delay| delay > 0));
    }

    #[test]
    fn new_object_lease_uses_only_the_conditional_create() {
        let runtime = Arc::new(Runtime::new().expect("create object lease test runtime"));
        let throttled = Arc::new(ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig {
                wait_get_per_call: Duration::from_millis(500),
                ..ThrottleConfig::default()
            },
        ));
        let store = throttled.clone() as Arc<dyn ObjectStore>;
        let started_at = Instant::now();
        let lease = runtime
            .block_on(ObjectLease::acquire(
                runtime.clone(),
                store,
                ObjectPath::from("volumes/workspace/lease.json"),
                "workspace".to_string(),
                config(),
            ))
            .expect("acquire new object lease");

        assert!(started_at.elapsed() < Duration::from_millis(100));
        drop(lease);
    }

    #[test]
    fn lost_object_lease_cannot_publish_volume_metadata() {
        let runtime = Arc::new(Runtime::new().expect("create object lease test runtime"));
        let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/lease.json");
        let first = runtime
            .block_on(ObjectLease::acquire(
                runtime.clone(),
                store.clone(),
                path.clone(),
                "workspace".to_string(),
                config(),
            ))
            .expect("acquire object lease");

        runtime.block_on(async {
            let current = store.get(&path).await.expect("read current lease");
            let version = UpdateVersion {
                e_tag: current.meta.e_tag,
                version: current.meta.version,
            };
            store
                .put_opts(
                    &path,
                    serde_json::to_vec(&LeaseDocument {
                        owner: "replacement".to_string(),
                        released: false,
                        metadata: None,
                    })
                    .expect("serialize replacement lease")
                    .into(),
                    PutMode::Update(version).into(),
                )
                .await
                .expect("replace lease owner");

            let failure = first
                .state
                .commit_metadata(VolumeMetadata::new(TEST_SIZE))
                .await
                .expect_err("lost lease must not publish metadata");
            assert_eq!(failure.code, "lease-lost");
            assert_eq!(failure.retry_after_ms, Some(30_000));
            let current = store.get(&path).await.expect("read replacement lease");
            let document: LeaseDocument =
                serde_json::from_slice(&current.bytes().await.expect("read lease bytes"))
                    .expect("deserialize lease");
            assert!(document.metadata.is_none());
        });
        drop(first);
    }

    #[test]
    fn lease_revalidation_does_not_wait_for_object_storage() {
        let runtime = Arc::new(Runtime::new().expect("create object lease test runtime"));
        let throttled = Arc::new(ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig::default(),
        ));
        let store = throttled.clone() as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/lease.json");
        let mut lease = runtime
            .block_on(ObjectLease::acquire(
                runtime.clone(),
                store,
                path,
                "workspace".to_string(),
                config(),
            ))
            .expect("acquire object lease");
        lease.stop.send(true).expect("stop renewal task");
        runtime
            .block_on(lease.task.take().expect("renewal task"))
            .expect("join renewal task");
        throttled.config_mut(|config| {
            config.wait_put_per_call = Duration::from_millis(500);
        });

        let lease = VolumeLease::Object { _lease: lease };
        let started_at = Instant::now();
        lease.revalidate().expect("revalidate held lease");

        assert!(started_at.elapsed() < Duration::from_millis(100));
        throttled.config_mut(|config| {
            config.wait_put_per_call = Duration::ZERO;
        });
        drop(lease);
    }

    #[test]
    fn object_lease_close_aborts_a_stuck_renewal() {
        let runtime = Arc::new(Runtime::new().expect("create object lease test runtime"));
        let throttled = Arc::new(ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig::default(),
        ));
        let store = throttled.clone() as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/lease.json");
        let mut lease = runtime
            .block_on(ObjectLease::acquire(
                runtime.clone(),
                store,
                path,
                "workspace".to_string(),
                config(),
            ))
            .expect("acquire object lease");
        lease.stop.send(true).expect("stop normal renewal task");
        runtime
            .block_on(lease.task.take().expect("normal renewal task"))
            .expect("join normal renewal task");

        throttled.config_mut(|config| {
            config.wait_put_per_call = Duration::from_secs(30);
        });
        let state = lease.state.clone();
        lease.task = Some(runtime.spawn(async move {
            let _ = state.renew().await;
        }));
        runtime.block_on(async { tokio::time::sleep(Duration::from_millis(50)).await });

        let started_at = Instant::now();
        drop(lease);
        assert!(started_at.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn block_store_close_times_out_when_object_storage_is_stuck() {
        let runtime = Arc::new(Runtime::new().expect("create block store test runtime"));
        let throttled = Arc::new(ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig::default(),
        ));
        let mut config = config();
        config.block_close_timeout = Duration::from_millis(100);
        let generation_root = ObjectPath::from("volumes/workspace/data/current");
        let store = PackedObjectBlockStore::new(
            runtime.clone(),
            throttled.clone(),
            generation_root.clone(),
            ObjectPath::from("volumes/workspace/objects"),
            BlockManifest::default(),
            TEST_SIZE,
            config,
        );
        store
            .write_blocks(vec![(7, vec![42; 4096])])
            .expect("buffer block");
        throttled.config_mut(|config| {
            config.wait_put_per_call = Duration::from_secs(30);
        });

        let started_at = Instant::now();
        let error = store.close().expect_err("stuck close must time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started_at.elapsed() < Duration::from_secs(1));
        let object_store = throttled as Arc<dyn ObjectStore>;
        assert!(
            runtime
                .block_on(super::read_manifest(
                    &object_store,
                    &generation_root.join("manifest.json"),
                ))
                .expect("read manifest after failed close")
                .is_none()
        );
    }

    #[test]
    fn background_upload_does_not_publish_a_superseded_block() {
        let runtime = Arc::new(Runtime::new().expect("create block store test runtime"));
        let throttled = Arc::new(ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig {
                wait_put_per_call: Duration::from_millis(200),
                ..ThrottleConfig::default()
            },
        ));
        let object_store = throttled as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/data/current");
        let mut block_config = config();
        block_config.background_upload_bytes = super::BLOCK_SIZE;
        let store = PackedObjectBlockStore::new(
            runtime.clone(),
            object_store.clone(),
            path.clone(),
            ObjectPath::from("volumes/workspace/objects"),
            BlockManifest::default(),
            TEST_SIZE,
            block_config.clone(),
        );

        let write_started = Instant::now();
        store
            .write_blocks(vec![(7, vec![42; 4096])])
            .expect("stage background upload");
        assert!(write_started.elapsed() < Duration::from_millis(100));
        store
            .write_blocks(vec![(7, vec![43; 4096])])
            .expect("supersede background upload");
        store.flush().expect("flush latest block");

        let manifest = runtime
            .block_on(super::read_manifest(
                &object_store,
                &path.clone().join("manifest.json"),
            ))
            .expect("read manifest")
            .expect("committed manifest");
        let reopened = PackedObjectBlockStore::new(
            runtime,
            object_store,
            path,
            ObjectPath::from("volumes/workspace/objects"),
            manifest,
            TEST_SIZE,
            block_config,
        );
        assert_eq!(
            reopened.read_blocks(7, 1).expect("read latest block"),
            vec![(7, vec![43; 4096])]
        );
    }

    #[test]
    fn completed_write_cannot_be_overwritten_by_a_stale_read_cache() {
        let runtime = Arc::new(Runtime::new().expect("create block store test runtime"));
        let throttled = Arc::new(ThrottledStore::new(
            InMemory::new(),
            ThrottleConfig::default(),
        ));
        let object_store = throttled.clone() as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/data/current");
        let object_root = ObjectPath::from("volumes/workspace/objects");
        let seed = PackedObjectBlockStore::new(
            runtime.clone(),
            object_store.clone(),
            path.clone(),
            object_root.clone(),
            BlockManifest::default(),
            TEST_SIZE,
            config(),
        );
        seed.write_blocks(vec![(7, vec![41; 4096])])
            .expect("write original block");
        seed.flush().expect("flush original block");
        let manifest = runtime
            .block_on(super::read_manifest(
                &object_store,
                &path.clone().join("manifest.json"),
            ))
            .expect("read manifest")
            .expect("committed manifest");
        let store = Arc::new(PackedObjectBlockStore::new(
            runtime,
            object_store,
            path,
            object_root,
            manifest,
            TEST_SIZE,
            config(),
        ));
        throttled.config_mut(|config| {
            config.wait_get_per_call = Duration::from_millis(250);
        });
        let reader = {
            let store = store.clone();
            std::thread::spawn(move || store.read_blocks(7, 1).expect("read overlapping block"))
        };
        std::thread::sleep(Duration::from_millis(50));
        store
            .write_blocks(vec![(7, vec![42; 4096])])
            .expect("write replacement block");
        store.flush().expect("flush replacement block");
        reader.join().expect("join overlapping read");
        throttled.config_mut(|config| {
            config.wait_get_per_call = Duration::ZERO;
        });

        assert_eq!(
            store.read_blocks(7, 1).expect("read completed write"),
            vec![(7, vec![42; 4096])]
        );
    }

    #[test]
    fn repeated_overwrites_apply_upload_backpressure() {
        let runtime = Arc::new(Runtime::new().expect("create block store test runtime"));
        let object_store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/data/current");
        let mut block_config = config();
        block_config.background_upload_bytes = super::BLOCK_SIZE;
        block_config.max_dirty_bytes = 4 * super::BLOCK_SIZE;
        let store = PackedObjectBlockStore::new(
            runtime.clone(),
            object_store.clone(),
            path.clone(),
            ObjectPath::from("volumes/workspace/objects"),
            BlockManifest::default(),
            TEST_SIZE,
            block_config,
        );

        for value in 1..=4 {
            store
                .write_blocks(vec![(7, vec![value; 4096])])
                .expect("overwrite block");
        }

        assert!(
            runtime
                .block_on(super::read_manifest(
                    &object_store,
                    &path.join("manifest.json"),
                ))
                .expect("read manifest after backpressure")
                .is_some()
        );
        assert_eq!(
            store.read_blocks(7, 1).expect("read latest overwrite"),
            vec![(7, vec![4; 4096])]
        );
    }

    #[test]
    fn block_store_buffers_writes_until_flush() {
        let runtime = Arc::new(Runtime::new().expect("create block store test runtime"));
        let object_store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let path = ObjectPath::from("volumes/workspace/data/current");
        let manifest_path = path.clone().join("manifest.json");
        let store = PackedObjectBlockStore::new(
            runtime.clone(),
            object_store.clone(),
            path.clone(),
            ObjectPath::from("volumes/workspace/objects"),
            BlockManifest::default(),
            TEST_SIZE,
            config(),
        );
        store
            .write_blocks(vec![(7, vec![42; 4096])])
            .expect("buffer block");

        assert!(
            runtime
                .block_on(super::read_manifest(&object_store, &manifest_path))
                .expect("read manifest")
                .is_none()
        );
        assert_eq!(
            store.read_blocks(7, 1).expect("read buffered block"),
            vec![(7, vec![42; 4096])]
        );

        store.flush().expect("flush block");
        let manifest = runtime
            .block_on(super::read_manifest(&object_store, &manifest_path))
            .expect("read flushed manifest")
            .expect("flushed manifest");
        assert!(manifest.blocks.contains_key(&7));

        store
            .write_blocks(vec![(7, vec![0; 4096])])
            .expect("buffer block deletion");
        assert!(
            store
                .read_blocks(7, 1)
                .expect("read deleted block")
                .is_empty()
        );
        assert!(
            !store
                .list_blocks()
                .expect("list buffered blocks")
                .contains(&7)
        );
        assert!(
            runtime
                .block_on(super::read_manifest(&object_store, &manifest_path))
                .expect("read manifest before deletion flush")
                .expect("durable manifest")
                .blocks
                .contains_key(&7)
        );
        store.flush().expect("flush block deletion");
        assert!(
            !runtime
                .block_on(super::read_manifest(&object_store, &manifest_path))
                .expect("read manifest after deletion flush")
                .expect("durable manifest")
                .blocks
                .contains_key(&7)
        );

        store
            .write_blocks(vec![(8, vec![24; 4096])])
            .expect("buffer block before close");
        store.close().expect("close block store");
        let manifest = runtime
            .block_on(super::read_manifest(&object_store, &manifest_path))
            .expect("read close-flushed manifest")
            .expect("close-flushed manifest");
        let reopened = PackedObjectBlockStore::new(
            runtime,
            object_store,
            path,
            ObjectPath::from("volumes/workspace/objects"),
            manifest,
            TEST_SIZE,
            config(),
        );
        assert_eq!(
            reopened.read_blocks(8, 1).expect("read reopened block"),
            vec![(8, vec![24; 4096])]
        );
    }

    #[test]
    fn lease_expiry_uses_provider_timestamps() {
        let duration = Duration::from_secs(30);
        assert!(!lease_is_expired(1_000, 30_999, duration));
        assert!(lease_is_expired(1_000, 31_000, duration));
        assert!(!lease_is_expired(31_000, 1_000, duration));
        assert_eq!(lease_retry_after_ms(1_000, 6_000, duration), 25_000);
        assert_eq!(lease_retry_after_ms(1_000, 31_000, duration), 0);
    }

    #[test]
    fn provider_authentication_failures_are_distinct() {
        let error = || ObjectStoreError::Unauthenticated {
            path: "volumes/workspace/lease.json".to_string(),
            source: Box::new(std::io::Error::other("bad credentials")),
        };
        let failure = provider_failure(error());
        assert_eq!(failure.code, "authentication-failed");
        assert_eq!(failure.retry_after_ms, None);
        let failure = BlobBlockFailure::lease_store_failure(error(), Duration::from_secs(30));
        assert_eq!(failure.code, "lease-authentication-failed");
        assert_eq!(failure.retry_after_ms, Some(30_000));
    }

    #[test]
    fn provisioning_attempts_use_distinct_unpublished_generations() {
        let first = VolumeMetadata::new(TEST_SIZE);
        let second = VolumeMetadata::new(TEST_SIZE);

        assert_ne!(first.generation, second.generation);
        first.validate(TEST_SIZE).expect("validate first metadata");
        second
            .validate(TEST_SIZE)
            .expect("validate second metadata");
    }

    #[test]
    fn handed_off_generations_do_not_fence_each_other() {
        let runtime = Arc::new(Runtime::new().expect("create generation test runtime"));
        let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let object_root = ObjectPath::from("volumes/workspace/objects");
        let source_path = ObjectPath::from("volumes/workspace/data/source");
        let source = PackedObjectBlockStore::new(
            runtime.clone(),
            store.clone(),
            source_path.clone(),
            object_root.clone(),
            BlockManifest::default(),
            TEST_SIZE,
            config(),
        );
        source
            .write_blocks(vec![(1, vec![1; 4096])])
            .expect("write source block");
        source.flush().expect("flush source generation");

        let active_path = ObjectPath::from("volumes/workspace/data/active");
        let stale_path = ObjectPath::from("volumes/workspace/data/stale");
        runtime
            .block_on(clone_manifest_generation(
                store.clone(),
                source_path.clone(),
                active_path.clone(),
            ))
            .expect("clone active manifest");
        runtime
            .block_on(clone_manifest_generation(
                store.clone(),
                source_path,
                stale_path.clone(),
            ))
            .expect("clone stale manifest");
        let manifest = |path: &ObjectPath| {
            runtime
                .block_on(super::read_manifest(
                    &store,
                    &path.clone().join("manifest.json"),
                ))
                .expect("read generation manifest")
                .expect("generation manifest")
        };
        let active_manifest = manifest(&active_path);
        let stale_manifest = manifest(&stale_path);
        let active = PackedObjectBlockStore::new(
            runtime.clone(),
            store.clone(),
            active_path.clone(),
            object_root.clone(),
            active_manifest,
            TEST_SIZE,
            config(),
        );
        let stale = PackedObjectBlockStore::new(
            runtime,
            store,
            stale_path.clone(),
            object_root,
            stale_manifest,
            TEST_SIZE,
            config(),
        );
        stale
            .write_blocks(vec![(2, vec![2; 4096])])
            .and_then(|_| stale.flush())
            .expect("write stale generation");
        active
            .write_blocks(vec![(2, vec![3; 4096])])
            .and_then(|_| active.flush())
            .expect("write active generation");
        assert_eq!(stale.read_blocks(2, 1).unwrap()[0].1, vec![2; 4096]);
        assert_eq!(active.read_blocks(2, 1).unwrap()[0].1, vec![3; 4096]);
    }

    fn allocated_bytes(path: &Path) -> u64 {
        fs::read_dir(path)
            .expect("read blob block test directory")
            .map(|entry| entry.expect("read blob block directory entry").path())
            .map(|path| {
                let metadata = fs::metadata(&path).expect("read blob block object metadata");
                if metadata.is_dir() {
                    allocated_bytes(&path)
                } else {
                    metadata.len()
                }
            })
            .sum()
    }
}
