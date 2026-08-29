use std::collections::HashSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io;
use std::os::fd::AsRawFd;
use std::path::{Path as FsPath, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bson::Document;
use futures_util::TryStreamExt;
use sandbox::block_storage::{CowBlockStore, format_empty_ext4};
use sandbox::runtime::BlockDeviceService;
use serde::{Deserialize, Serialize};
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

        let ready_path = volume_root.clone().join("metadata.json");
        let provisioning_path = volume_root.clone().join("provisioning.json");
        let db_path = volume_root.join("data");
        let ready = runtime.block_on(read_json::<VolumeMetadata>(&provider.store, &ready_path))?;
        let db = if let Some(ready) = ready {
            ready.validate(size_bytes)?;
            runtime.block_on(Db::open(db_path, provider.store.clone()))?
        } else {
            let provisioning = runtime
                .block_on(read_json::<ProvisioningMetadata>(
                    &provider.store,
                    &provisioning_path,
                ))?
                .unwrap_or_else(ProvisioningMetadata::new);
            runtime.block_on(put_json_create_if_absent(
                &provider.store,
                &provisioning_path,
                &provisioning,
            ))?;
            runtime.block_on(clear_prefix(&provider.store, &db_path))?;
            let db = runtime.block_on(Db::open(db_path, provider.store.clone()))?;
            let store = Arc::new(SlateDbBlockStore::new(
                runtime.clone(),
                db.clone(),
                size_bytes,
            ));
            format_empty_ext4(store, size_bytes, provisioning.fs_uuid)?;
            runtime.block_on(put_json_create(
                &provider.store,
                &ready_path,
                &VolumeMetadata {
                    version: 1,
                    size_bytes,
                    fs_uuid: provisioning.fs_uuid,
                },
            ))?;
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
    version: tokio::sync::Mutex<UpdateVersion>,
}

#[derive(Serialize, Deserialize)]
struct LeaseDocument {
    owner: String,
    released: bool,
}

impl ObjectLease {
    async fn acquire(
        runtime: Arc<Runtime>,
        store: Arc<dyn ObjectStore>,
        path: Path,
        volume: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let owner = bson::oid::ObjectId::new().to_hex();
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: owner.clone(),
            released: false,
        })?;
        let version = match store.get(&path).await {
            Err(slatedb::object_store::Error::NotFound { .. }) => {
                match store
                    .put_opts(&path, payload.clone().into(), PutMode::Create.into())
                    .await
                {
                    Ok(result) => UpdateVersion::from(result),
                    Err(slatedb::object_store::Error::AlreadyExists { .. }) => {
                        return Err(format!("block volume {volume} is already leased").into());
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            Ok(result) => {
                let meta = result.meta.clone();
                let existing: LeaseDocument = serde_json::from_slice(&result.bytes().await?)?;
                let age_ms = now_millis().saturating_sub(meta.last_modified.timestamp_millis());
                if !existing.released && age_ms < LEASE_DURATION.as_millis() as i64 {
                    return Err(format!("block volume {volume} is already leased").into());
                }
                let prior = UpdateVersion {
                    e_tag: meta.e_tag,
                    version: meta.version,
                };
                match store
                    .put_opts(&path, payload.clone().into(), PutMode::Update(prior).into())
                    .await
                {
                    Ok(result) => UpdateVersion::from(result),
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
            version: tokio::sync::Mutex::new(version),
        });
        let (stop, mut stopped) = watch::channel(false);
        let renewal_state = state.clone();
        let task = runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(LEASE_RENEW_INTERVAL) => {
                        if let Err(error) = renewal_state.renew().await {
                            eprintln!("sandbox-host: blob block lease renewal failed: {error}");
                            std::process::exit(1);
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

impl ObjectLeaseState {
    async fn renew(&self) -> Result<(), Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: self.owner.clone(),
            released: false,
        })?;
        let mut version = self.version.lock().await;
        let result = self
            .store
            .put_opts(
                &self.path,
                payload.into(),
                PutMode::Update(version.clone()).into(),
            )
            .await?;
        *version = UpdateVersion::from(result);
        Ok(())
    }

    async fn release(&self) -> Result<(), Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(&LeaseDocument {
            owner: self.owner.clone(),
            released: true,
        })?;
        let version = self.version.lock().await.clone();
        self.store
            .put_opts(&self.path, payload.into(), PutMode::Update(version).into())
            .await?;
        Ok(())
    }
}

impl Drop for ObjectLease {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        if let Some(task) = self.task.take() {
            let _ = self.runtime.block_on(task);
        }
        let _ = self.runtime.block_on(self.state.release());
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

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VolumeMetadata {
    version: u32,
    size_bytes: u64,
    fs_uuid: [u8; 16],
}

impl VolumeMetadata {
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
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProvisioningMetadata {
    fs_uuid: [u8; 16],
}

impl ProvisioningMetadata {
    fn new() -> Self {
        let first = bson::oid::ObjectId::new().bytes();
        let second = bson::oid::ObjectId::new().bytes();
        let mut fs_uuid = [0; 16];
        fs_uuid[..12].copy_from_slice(&first);
        fs_uuid[12..].copy_from_slice(&second[..4]);
        Self { fs_uuid }
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

async fn put_json_create_if_absent<T: Serialize>(
    store: &Arc<dyn ObjectStore>,
    path: &Path,
    value: &T,
) -> Result<(), Box<dyn std::error::Error>> {
    match put_json_create(store, path, value).await {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<slatedb::object_store::Error>()
                .is_some_and(|error| {
                    matches!(error, slatedb::object_store::Error::AlreadyExists { .. })
                }) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

async fn clear_prefix(
    store: &Arc<dyn ObjectStore>,
    prefix: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut objects = store.list(Some(prefix));
    while let Some(object) = objects.try_next().await? {
        store.delete(&object.location).await?;
    }
    Ok(())
}

fn block_key(index: u64) -> [u8; 9] {
    let mut key = [0; 9];
    key[0] = b'b';
    key[1..].copy_from_slice(&index.to_be_bytes());
    key
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(i64::MAX as u128) as i64
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

    use bson::doc;

    use std::sync::Arc;

    use slatedb::object_store::ObjectStore;
    use slatedb::object_store::memory::InMemory;
    use slatedb::object_store::path::Path as ObjectPath;
    use tokio::runtime::Runtime;

    use super::{BlobBlockVolume, ObjectLease};

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
