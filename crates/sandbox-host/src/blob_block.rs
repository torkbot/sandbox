use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
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
const LEASE_DURATION: Duration = Duration::from_secs(30);
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(10);
const LEASE_RENEW_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const LEASE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const LEASE_RENEW_DEADLINE: Duration = Duration::from_secs(25);
const LEASE_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct BlobBlockVolume {
    store: Arc<SlateDbBlockStore>,
    _lease: VolumeLease,
    size: u64,
}

impl BlobBlockVolume {
    pub fn acquire(document: Document) -> Result<Self, Box<dyn std::error::Error>> {
        let request: AcquireRequest = bson::deserialize_from_document(document)?;
        request.validate()?;
        let size_bytes = request.size_bytes();
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(4)
                .enable_all()
                .build()?,
        );
        let provider = ProviderStore::build(&request.provider)?;
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
        let db = if let Some(current) = metadata {
            current.validate(size_bytes)?;
            if lease.requires_isolated_generation() {
                let next = current.next_generation();
                let source_path = volume_root
                    .clone()
                    .join("data")
                    .join(current.generation.as_str());
                let next_path = volume_root
                    .clone()
                    .join("data")
                    .join(next.generation.as_str());
                runtime.block_on(clone_db_generation(
                    provider.store.clone(),
                    source_path,
                    next_path.clone(),
                ))?;
                lease.revalidate()?;
                let db = runtime.block_on(Db::open(next_path, provider.store.clone()))?;
                lease.revalidate()?;
                if let Err(error) =
                    lease.commit_metadata(&runtime, &provider.store, &metadata_path, &next)
                {
                    let _ = runtime.block_on(db.close());
                    return Err(error);
                }
                if let Err(error) = lease.revalidate() {
                    let _ = runtime.block_on(db.close());
                    return Err(error);
                }
                db
            } else {
                runtime.block_on(Db::open(
                    volume_root
                        .clone()
                        .join("data")
                        .join(current.generation.as_str()),
                    provider.store.clone(),
                ))?
            }
        } else {
            let metadata = VolumeMetadata::new(size_bytes);
            // ponytail: interrupted provisioning or handoff can leave an unreachable generation;
            // add provider garbage collection when volume deletion is introduced.
            let db = runtime.block_on(Db::open(
                volume_root.join("data").join(metadata.generation.as_str()),
                provider.store.clone(),
            ))?;
            let store = Arc::new(SlateDbBlockStore::new(
                runtime.clone(),
                db.clone(),
                size_bytes,
            ));
            format_empty_ext4(store, size_bytes, metadata.fs_uuid)?;
            if let Err(error) =
                lease.commit_metadata(&runtime, &provider.store, &metadata_path, &metadata)
            {
                let _ = runtime.block_on(db.close());
                return Err(error);
            }
            db
        };
        let store = Arc::new(SlateDbBlockStore::new(runtime, db, size_bytes));
        Ok(Self {
            store,
            _lease: lease,
            size: size_bytes,
        })
    }

    pub fn service(&self) -> BlockDeviceService {
        BlockDeviceService {
            storage: self.store.clone(),
            size: self.size,
        }
    }
}

impl Drop for BlobBlockVolume {
    fn drop(&mut self) {
        let _ = self.store.close();
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

    fn revalidate(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Local { .. } => Ok(()),
            Self::Object { _lease } => {
                _lease
                    .runtime
                    .block_on(_lease.state.renew())
                    .map_err(|error| {
                        format!("block volume lease lost during acquisition: {error}").into()
                    })
            }
        }
    }

    fn metadata(
        &self,
        runtime: &Arc<Runtime>,
        store: &Arc<dyn ObjectStore>,
        path: &Path,
    ) -> Result<Option<VolumeMetadata>, Box<dyn std::error::Error>> {
        match self {
            Self::Local { .. } => runtime.block_on(read_json(store, path)),
            Self::Object { _lease } => runtime.block_on(_lease.state.metadata()),
        }
    }

    fn commit_metadata(
        &self,
        runtime: &Arc<Runtime>,
        store: &Arc<dyn ObjectStore>,
        path: &Path,
        metadata: &VolumeMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match self {
            Self::Local { .. } => runtime.block_on(put_json_create(store, path, metadata)),
            Self::Object { _lease } => runtime
                .block_on(_lease.state.commit_metadata(metadata.clone()))
                .map_err(|error| {
                    format!("block volume lease lost while publishing metadata: {error}").into()
                }),
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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let mut path = root.to_path_buf();
        if let Some(prefix) = prefix {
            path.push(prefix);
        }
        path.push("volumes");
        path.push(volume);
        fs::create_dir_all(&path)?;
        path.push("lease.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if matches!(error.raw_os_error(), Some(code) if code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(format!("block volume {volume} is already leased").into());
            }
            return Err(error.into());
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
}

struct ObjectLeaseState {
    store: Arc<dyn ObjectStore>,
    path: Path,
    owner: String,
    record: tokio::sync::Mutex<ObjectLeaseRecord>,
    ownership_lost: AtomicBool,
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
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let owner = bson::oid::ObjectId::new().to_hex();
        let (version, metadata) = match store.get(&path).await {
            Err(slatedb::object_store::Error::NotFound { .. }) => {
                let payload = serde_json::to_vec(&LeaseDocument {
                    owner: owner.clone(),
                    released: false,
                    metadata: None,
                })?;
                match store
                    .put_opts(&path, payload.into(), PutMode::Create.into())
                    .await
                {
                    Ok(result) => (UpdateVersion::from(result), None),
                    Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                        return Err(format!("block volume {volume} is already leased").into());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(result) => {
                let meta = result.meta.clone();
                let existing: LeaseDocument = serde_json::from_slice(&result.bytes().await?)?;
                if !existing.released {
                    let server_now = object_store_now_millis(&store, &path).await?;
                    if !lease_is_expired(meta.last_modified.timestamp_millis(), server_now) {
                        return Err(format!("block volume {volume} is already leased").into());
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
                })?;
                match store
                    .put_opts(&path, payload.into(), PutMode::Update(prior).into())
                    .await
                {
                    Ok(result) => (UpdateVersion::from(result), metadata),
                    Err(slatedb::object_store::Error::Precondition { .. }) => {
                        return Err(format!("block volume {volume} is already leased").into());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        };
        let state = Arc::new(ObjectLeaseState {
            store,
            path,
            owner,
            record: tokio::sync::Mutex::new(ObjectLeaseRecord { version, metadata }),
            ownership_lost: AtomicBool::new(false),
        });
        let (stop, mut stopped) = watch::channel(false);
        let renewal_state = state.clone();
        let task = runtime.spawn(async move {
            let mut last_renewed = tokio::time::Instant::now();
            let mut next_renewal = LEASE_RENEW_INTERVAL;
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(next_renewal) => {
                        match tokio::time::timeout(LEASE_REQUEST_TIMEOUT, renewal_state.renew()).await {
                            Ok(Ok(())) => {
                                last_renewed = tokio::time::Instant::now();
                                next_renewal = LEASE_RENEW_INTERVAL;
                            }
                            result => {
                                let error = match result {
                                    Ok(Err(error)) => error.to_string(),
                                    Err(_) => "request timed out".to_string(),
                                    Ok(Ok(())) => unreachable!(),
                                };
                                if renewal_state.ownership_lost.load(Ordering::Relaxed) {
                                    eprintln!("sandbox-host: blob block lease ownership was lost: {error}");
                                    std::process::exit(1);
                                }
                                if last_renewed.elapsed() >= LEASE_RENEW_DEADLINE {
                                    eprintln!("sandbox-host: blob block lease could not be renewed before its safety deadline: {error}");
                                    std::process::exit(1);
                                }
                                eprintln!("sandbox-host: blob block lease renewal failed; retrying: {error}");
                                next_renewal = LEASE_RENEW_RETRY_INTERVAL;
                            }
                        }
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
        })
    }
}

async fn object_store_now_millis(
    store: &Arc<dyn ObjectStore>,
    lease_path: &Path,
) -> Result<i64, Box<dyn std::error::Error>> {
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

impl ObjectLeaseState {
    async fn metadata(&self) -> Result<Option<VolumeMetadata>, Box<dyn std::error::Error>> {
        Ok(self.record.lock().await.metadata.clone())
    }

    async fn renew(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut record = self.record.lock().await;
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: self.owner.clone(),
            released: false,
            metadata: record.metadata.clone(),
        })?;
        let result = match self
            .store
            .put_opts(
                &self.path,
                payload.clone().into(),
                PutMode::Update(record.version.clone()).into(),
            )
            .await
        {
            Ok(result) => result,
            Err(slatedb::object_store::Error::Precondition { .. }) => {
                let current = self.store.get(&self.path).await?;
                let current_meta = current.meta.clone();
                let document: LeaseDocument = serde_json::from_slice(&current.bytes().await?)?;
                if document.released || document.owner != self.owner {
                    self.ownership_lost.store(true, Ordering::Relaxed);
                    return Err("blob block lease ownership was lost".into());
                }
                record.version = UpdateVersion {
                    e_tag: current_meta.e_tag,
                    version: current_meta.version,
                };
                self.store
                    .put_opts(
                        &self.path,
                        payload.into(),
                        PutMode::Update(record.version.clone()).into(),
                    )
                    .await?
            }
            Err(error) => return Err(error.into()),
        };
        record.version = UpdateVersion::from(result);
        Ok(())
    }

    async fn commit_metadata(
        &self,
        metadata: VolumeMetadata,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut record = self.record.lock().await;
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: self.owner.clone(),
            released: false,
            metadata: Some(metadata.clone()),
        })?;
        let result = self
            .store
            .put_opts(
                &self.path,
                payload.into(),
                PutMode::Update(record.version.clone()).into(),
            )
            .await?;
        record.version = UpdateVersion::from(result);
        record.metadata = Some(metadata);
        Ok(())
    }

    async fn release(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut record = self.record.lock().await;
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: self.owner.clone(),
            released: true,
            metadata: record.metadata.clone(),
        })?;
        let result = self
            .store
            .put_opts(
                &self.path,
                payload.into(),
                PutMode::Update(record.version.clone()).into(),
            )
            .await?;
        record.version = UpdateVersion::from(result);
        Ok(())
    }
}

impl Drop for ObjectLease {
    fn drop(&mut self) {
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
        let _ = self.runtime.block_on(async {
            tokio::time::timeout(LEASE_CLOSE_TIMEOUT, self.state.release()).await
        });
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
        self.wait_for(async move { db.close().await.map_err(io::Error::other) })
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

    fn validate(&self, requested_size: u64) -> Result<(), Box<dyn std::error::Error>> {
        if self.version != 1 {
            return Err(format!("unsupported blob block volume version: {}", self.version).into());
        }
        if self.size_bytes != requested_size {
            return Err(format!(
                "blob block volume size mismatch: stored {}, requested {}",
                self.size_bytes, requested_size
            )
            .into());
        }
        if self.generation.len() != 24
            || !self.generation.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid blob block volume generation".into());
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
    use slatedb::object_store::{ObjectStore, ObjectStoreExt};
    use slatedb::object_store::{PutMode, UpdateVersion};
    use tokio::runtime::Runtime;

    use super::{
        BlobBlockVolume, LeaseDocument, ObjectLease, VolumeMetadata, clone_db_generation,
        lease_is_expired,
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

        let first = BlobBlockVolume::acquire(request(TEST_SIZE)).expect("acquire new volume");
        let allocated = allocated_bytes(&directory.0);
        assert!(
            allocated < TEST_SIZE / 2,
            "sparse filesystem used {allocated} bytes for a {TEST_SIZE}-byte volume"
        );
        let competing = BlobBlockVolume::acquire(request(TEST_SIZE))
            .err()
            .expect("competing acquire must fail");
        assert_eq!(
            competing.to_string(),
            "block volume workspace is already leased"
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
    fn object_lease_uses_conditional_writes_for_exclusion_and_release() {
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
        drop(first);

        let reacquired = acquire().expect("reacquire released object lease");
        drop(reacquired);
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

            first
                .state
                .commit_metadata(VolumeMetadata::new(TEST_SIZE))
                .await
                .expect_err("lost lease must not publish metadata");
            let current = store.get(&path).await.expect("read replacement lease");
            let document: LeaseDocument =
                serde_json::from_slice(&current.bytes().await.expect("read lease bytes"))
                    .expect("deserialize lease");
            assert!(document.metadata.is_none());
        });
        drop(first);
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
    fn lease_expiry_uses_provider_timestamps() {
        assert!(!lease_is_expired(1_000, 30_999));
        assert!(lease_is_expired(1_000, 31_000));
        assert!(!lease_is_expired(31_000, 1_000));
    }

    #[test]
    fn provisioning_attempts_use_isolated_generations() {
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
