use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use bson::Document;
use sandbox::block_storage::{CowBlockStore, format_empty_ext4};
use sandbox::runtime::BlockDeviceService;
use serde::{Deserialize, Serialize};
use slatedb::admin::{AdminBuilder, CloneSourceSpec};
use slatedb::config::WriteOptions;
use slatedb::object_store::aws::AmazonS3Builder;
use slatedb::object_store::azure::MicrosoftAzureBuilder;
use slatedb::object_store::gcp::GoogleCloudStorageBuilder;
use slatedb::object_store::local::LocalFileSystem;
use slatedb::object_store::path::Path;
use slatedb::object_store::prefix::PrefixStore;
use slatedb::object_store::{ObjectStore, ObjectStoreExt, PutMode, UpdateVersion};
use slatedb::{Db, WriteBatch};
use tokio::runtime::Runtime;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const BLOCK_SIZE: u64 = 64 * 1024;
pub(crate) const LEASE_DURATION: Duration = Duration::from_secs(30);
pub(crate) const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(10);
pub(crate) const LEASE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LEASE_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
const BLOCK_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

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

    fn lease_provider_error(error: impl fmt::Display) -> Self {
        Self {
            code: "lease-provider-error",
            message: format!("blob block lease state is uncertain: {error}"),
            retry_after_ms: Some(LEASE_DURATION.as_millis() as u64),
        }
    }

    fn lease_store_failure(error: slatedb::object_store::Error) -> Self {
        let (code, message) = match &error {
            slatedb::object_store::Error::Precondition { .. } => (
                "lease-lost",
                format!("blob block lease ownership was lost: {error}"),
            ),
            slatedb::object_store::Error::PermissionDenied { .. }
            | slatedb::object_store::Error::Unauthenticated { .. } => (
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
            retry_after_ms: Some(LEASE_DURATION.as_millis() as u64),
        }
    }
}

fn provider_failure(error: slatedb::object_store::Error) -> BlobBlockFailure {
    let code = match &error {
        slatedb::object_store::Error::PermissionDenied { .. }
        | slatedb::object_store::Error::Unauthenticated { .. } => "authentication-failed",
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
    store: Option<Arc<SlateDbBlockStore>>,
    _lease: VolumeLease,
    size: u64,
    closed: bool,
}

impl BlobBlockVolume {
    pub fn acquire(document: Document) -> Result<Self, BlobBlockFailure> {
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
        let provider = ProviderStore::build(&request.provider)
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
        })
    }

    pub fn service(&mut self) -> Result<BlockDeviceService, BlobBlockFailure> {
        if self.store.is_none() {
            let active_metadata = if self.provisioned && self._lease.requires_isolated_generation()
            {
                let next = self.metadata.next_generation();
                self.runtime
                    .block_on(clone_db_generation(
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
            let db = self
                .runtime
                .block_on(Db::open(
                    self.volume_root
                        .clone()
                        .join("data")
                        .join(active_metadata.generation.as_str()),
                    self.provider.clone(),
                ))
                .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
            let store = Arc::new(SlateDbBlockStore::new(
                self.runtime.clone(),
                db.clone(),
                self.size,
            ));
            if !self.provisioned {
                if let Err(error) =
                    format_empty_ext4(store.clone(), self.size, active_metadata.fs_uuid)
                {
                    let _ = self.runtime.block_on(db.close());
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
                    let _ = self.runtime.block_on(db.close());
                    return Err(error);
                }
                self.metadata = active_metadata;
                self.provisioned = true;
            }
            if let Err(error) = self._lease.revalidate() {
                let _ = self.runtime.block_on(db.close());
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
    fn build(provider: &Provider) -> Result<Self, Box<dyn std::error::Error>> {
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
                .with_region(region);
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
                .with_bucket_name(bucket);
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
                .with_container_name(container);
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
    ) -> Result<Self, BlobBlockFailure> {
        let owner = bson::oid::ObjectId::new().to_hex();
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: owner.clone(),
            released: false,
            metadata: None,
        })
        .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
        let created = store
            .put_opts(&path, payload.into(), PutMode::Create.into())
            .await;
        let (version, metadata) = match created {
            Ok(result) => (UpdateVersion::from(result), None),
            Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                let result = store.get(&path).await.map_err(provider_failure)?;
                let meta = result.meta.clone();
                let bytes = result.bytes().await.map_err(provider_failure)?;
                let existing: LeaseDocument = serde_json::from_slice(&bytes)
                    .map_err(|error| BlobBlockFailure::new("storage-error", error))?;
                if !existing.released {
                    let server_now = object_store_now_millis(&store, &path)
                        .await
                        .map_err(provider_failure)?;
                    if !lease_is_expired(meta.last_modified.timestamp_millis(), server_now) {
                        return Err(BlobBlockFailure::locked(
                            &volume,
                            Some(lease_retry_after_ms(
                                meta.last_modified.timestamp_millis(),
                                server_now,
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
                    Err(slatedb::object_store::Error::Precondition { .. }) => {
                        return Err(BlobBlockFailure::locked(&volume, None));
                    }
                    Err(error) => return Err(provider_failure(error)),
                }
            }
            Err(error) => return Err(provider_failure(error)),
        };
        let state = Arc::new(ObjectLeaseState {
            store,
            path,
            owner,
            record: tokio::sync::Mutex::new(ObjectLeaseRecord { version, metadata }),
            failure: Mutex::new(None),
        });
        let (stop, mut stopped) = watch::channel(false);
        let (failure_tx, failure_rx) = mpsc::sync_channel(1);
        let renewal_state = state.clone();
        let task = runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(LEASE_RENEW_INTERVAL) => {
                        let failure = match tokio::time::timeout(LEASE_REQUEST_TIMEOUT, renewal_state.renew()).await {
                            Ok(Ok(())) => continue,
                            Ok(Err(error)) => error,
                            Err(_) => BlobBlockFailure::lease_provider_error("renewal request timed out"),
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
                if tokio::time::timeout(LEASE_CLOSE_TIMEOUT, &mut task)
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
                tokio::time::timeout(LEASE_CLOSE_TIMEOUT, self.state.release()).await
            })
            .map_err(|_| BlobBlockFailure::lease_provider_error("release request timed out"))?
    }
}

async fn object_store_now_millis(
    store: &Arc<dyn ObjectStore>,
    lease_path: &Path,
) -> Result<i64, slatedb::object_store::Error> {
    let probe_path = Path::from(format!("{lease_path}.clock"));
    store.put(&probe_path, Vec::<u8>::new().into()).await?;
    Ok(store
        .head(&probe_path)
        .await?
        .last_modified
        .timestamp_millis())
}

fn lease_is_expired(last_modified_ms: i64, server_now_ms: i64) -> bool {
    server_now_ms.saturating_sub(last_modified_ms) >= LEASE_DURATION.as_millis() as i64
}

fn lease_retry_after_ms(last_modified_ms: i64, server_now_ms: i64) -> u64 {
    let age_ms = server_now_ms.saturating_sub(last_modified_ms).max(0) as u64;
    (LEASE_DURATION.as_millis() as u64).saturating_sub(age_ms)
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
            .map_err(BlobBlockFailure::lease_store_failure)?;
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

struct SlateDbBlockStore {
    runtime: Arc<Runtime>,
    db: Db,
    size: u64,
}

impl SlateDbBlockStore {
    fn new(runtime: Arc<Runtime>, db: Db, size: u64) -> Self {
        Self { runtime, db, size }
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
        let db = self.db.clone();
        self.runtime.block_on(async move {
            tokio::time::timeout(BLOCK_CLOSE_TIMEOUT, db.close())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "blob block close timed out"))?
                .map_err(io::Error::other)
        })
    }
}

impl fmt::Debug for SlateDbBlockStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SlateDbBlockStore")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl CowBlockStore for SlateDbBlockStore {
    fn block_size(&self) -> u64 {
        BLOCK_SIZE
    }

    fn list_blocks(&self) -> io::Result<HashSet<u64>> {
        let db = self.db.clone();
        self.wait_for(async move {
            let mut blocks = HashSet::new();
            let mut iter = db.scan_prefix(b"b", ..).await.map_err(io::Error::other)?;
            while let Some(entry) = iter.next().await.map_err(io::Error::other)? {
                if entry.key.len() != 9 || entry.key[0] != b'b' {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid blob block key",
                    ));
                }
                blocks.insert(u64::from_be_bytes(
                    entry.key[1..].try_into().expect("block key length checked"),
                ));
            }
            Ok(blocks)
        })
    }

    fn read_blocks(&self, start: u64, count: u64) -> io::Result<Vec<(u64, Vec<u8>)>> {
        let end = start
            .checked_add(count)
            .ok_or_else(|| io::Error::other("blob block read range overflow"))?;
        let db = self.db.clone();
        self.wait_for(async move {
            let mut chunks = Vec::new();
            let mut iter = db
                .scan(block_key(start).to_vec()..block_key(end).to_vec())
                .await
                .map_err(io::Error::other)?;
            while let Some(entry) = iter.next().await.map_err(io::Error::other)? {
                if entry.key.len() != 9 || entry.key[0] != b'b' {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid blob block key",
                    ));
                }
                let index = u64::from_be_bytes(
                    entry.key[1..].try_into().expect("block key length checked"),
                );
                chunks.push((index, entry.value.to_vec()));
            }
            Ok(chunks)
        })
    }

    fn write_blocks(&self, chunks: Vec<(u64, Vec<u8>)>) -> io::Result<()> {
        let mut batch = WriteBatch::new();
        for (index, data) in chunks {
            if data.len() > BLOCK_SIZE as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "blob block exceeds block size",
                ));
            }
            let key = block_key(index);
            if data.iter().all(|byte| *byte == 0) {
                batch.delete(key);
            } else {
                batch.put(key, data);
            }
        }
        let db = self.db.clone();
        self.wait_for(async move {
            db.write_with_options(
                batch,
                &WriteOptions {
                    await_durable: false,
                    ..WriteOptions::default()
                },
            )
            .await
            .map_err(io::Error::other)?;
            Ok(())
        })
    }

    fn flush(&self) -> io::Result<()> {
        let db = self.db.clone();
        self.wait_for(async move { db.flush().await.map_err(io::Error::other) })
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
        Err(slatedb::object_store::Error::NotFound { .. }) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn clone_db_generation(
    store: Arc<dyn ObjectStore>,
    source_path: Path,
    target_path: Path,
) -> Result<(), Box<dyn std::error::Error>> {
    AdminBuilder::new(target_path, store)
        .build()
        .create_clone_builder_from_source(CloneSourceSpec::new(source_path))
        .build()
        .await?;
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

fn block_key(index: u64) -> [u8; 9] {
    let mut key = [0; 9];
    key[0] = b'b';
    key[1..].copy_from_slice(&index.to_be_bytes());
    key
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

    use slatedb::Db;
    use slatedb::object_store::memory::InMemory;
    use slatedb::object_store::path::Path as ObjectPath;
    use slatedb::object_store::throttle::{ThrottleConfig, ThrottledStore};
    use slatedb::object_store::{Error as ObjectStoreError, ObjectStore, ObjectStoreExt};
    use slatedb::object_store::{PutMode, UpdateVersion};
    use tokio::runtime::Runtime;

    use super::{
        BlobBlockFailure, BlobBlockVolume, LeaseDocument, ObjectLease, SlateDbBlockStore,
        VolumeLease, VolumeMetadata, clone_db_generation, lease_is_expired, lease_retry_after_ms,
        provider_failure,
    };

    const TEST_SIZE: u64 = 64 * 1024 * 1024;

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

        let mut first = BlobBlockVolume::acquire(request(TEST_SIZE)).expect("acquire new volume");
        let acquired_bytes = allocated_bytes(&directory.0);
        assert!(
            acquired_bytes < 4096,
            "acquisition materialized {acquired_bytes} bytes before attachment"
        );
        let competing = BlobBlockVolume::acquire(request(TEST_SIZE))
            .err()
            .expect("competing acquire must fail");
        assert_eq!(
            competing.to_string(),
            "block volume workspace is already leased"
        );

        first.service().expect("provision attached volume");
        let provisioned_bytes = allocated_bytes(&directory.0);
        assert!(
            provisioned_bytes < TEST_SIZE / 2,
            "sparse filesystem used {provisioned_bytes} bytes for a {TEST_SIZE}-byte volume"
        );

        drop(first);
        let reopened = BlobBlockVolume::acquire(request(TEST_SIZE)).expect("reopen volume");
        drop(reopened);
        let mismatch = BlobBlockVolume::acquire(request(TEST_SIZE * 2))
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
        let db = runtime
            .block_on(Db::open(
                ObjectPath::from("volumes/workspace/data/current"),
                throttled.clone(),
            ))
            .expect("open block store database");
        let store = SlateDbBlockStore::new(runtime, db, TEST_SIZE);
        throttled.config_mut(|config| {
            config.wait_put_per_call = Duration::from_secs(30);
        });

        let started_at = Instant::now();
        let error = store.close().expect_err("stuck close must time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(started_at.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn lease_expiry_uses_provider_timestamps() {
        assert!(!lease_is_expired(1_000, 30_999));
        assert!(lease_is_expired(1_000, 31_000));
        assert!(!lease_is_expired(31_000, 1_000));
        assert_eq!(lease_retry_after_ms(1_000, 6_000), 25_000);
        assert_eq!(lease_retry_after_ms(1_000, 31_000), 0);
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
        let failure = BlobBlockFailure::lease_store_failure(error());
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
        let runtime = Runtime::new().expect("create SlateDB generation test runtime");
        runtime.block_on(async {
            let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
            let source_path = ObjectPath::from("volumes/workspace/data/source");
            let source = Db::open(source_path.clone(), store.clone())
                .await
                .expect("open source generation");
            source
                .put(b"before", b"first")
                .await
                .expect("write source value");
            source.close().await.expect("close source generation");

            let active_path = ObjectPath::from("volumes/workspace/data/active");
            clone_db_generation(store.clone(), source_path.clone(), active_path.clone())
                .await
                .expect("clone active generation");
            let active = Db::open(active_path, store.clone())
                .await
                .expect("open active generation");

            let stale_path = ObjectPath::from("volumes/workspace/data/stale");
            clone_db_generation(store.clone(), source_path, stale_path.clone())
                .await
                .expect("clone stale generation");
            let stale = Db::open(stale_path, store)
                .await
                .expect("open stale generation");
            stale
                .put(b"after", b"stale")
                .await
                .expect("stale generation remains isolated");
            active
                .put(b"after", b"replacement")
                .await
                .expect("active generation remains writable");
            active.close().await.expect("close active generation");
            stale.close().await.expect("close stale generation");
        });
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
