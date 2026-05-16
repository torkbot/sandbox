use napi::bindgen_prelude::*;
use napi_derive::napi;
use sandbox::config::{HttpSpecInput, MicroVmSpecInput, MountSpecInput};

#[napi]
pub struct NativeSandboxVm {}

#[napi]
impl NativeSandboxVm {
    #[napi]
    pub async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[napi(object)]
pub struct NativeCpuOptions {
    pub vcpus: Option<u32>,
}

#[napi(object)]
pub struct NativeMemoryOptions {
    pub mib: Option<u32>,
}

#[napi(object)]
pub struct NativeRootfsOptions {
    pub path: String,
    pub readonly: Option<bool>,
    pub format: String,
}

#[napi(object)]
pub struct NativeRootfsOverlayOptions {
    pub mode: String,
}

#[napi(object)]
pub struct NativeMountOptions {
    pub kind: String,
    pub path: String,
    pub name: Option<String>,
}

#[napi(object)]
pub struct NativeHttpOptions {
    pub protected_ranges: Option<Vec<String>>,
}

#[napi(object)]
pub struct NativeNetworkOptions {
    pub http: Option<NativeHttpOptions>,
}

#[napi(object)]
pub struct NativeSpawnSandboxOptions {
    pub name: Option<String>,
    pub cpu: Option<NativeCpuOptions>,
    pub memory: Option<NativeMemoryOptions>,
    pub rootfs: NativeRootfsOptions,
    pub rootfs_overlay: Option<NativeRootfsOverlayOptions>,
    pub mounts: Option<Vec<NativeMountOptions>>,
    pub network: Option<NativeNetworkOptions>,
}

#[napi]
pub async fn spawn_sandbox(options: NativeSpawnSandboxOptions) -> Result<NativeSandboxVm> {
    let spec = sandbox::MicroVmSpec::build(options.into_spec_input()).map_err(|error| {
        Error::new(
            Status::InvalidArg,
            format!("invalid spawnSandbox options: {error}"),
        )
    })?;
    let _ = spec.name.as_deref();

    Err(Error::new(
        Status::GenericFailure,
        "spawnSandbox native runtime is not implemented yet",
    ))
}

impl NativeSpawnSandboxOptions {
    fn into_spec_input(self) -> MicroVmSpecInput {
        MicroVmSpecInput {
            name: self.name,
            vcpus: self.cpu.and_then(|cpu| cpu.vcpus),
            memory_mib: self.memory.and_then(|memory| memory.mib),
            rootfs_path: self.rootfs.path,
            rootfs_readonly: self.rootfs.readonly,
            rootfs_format: self.rootfs.format,
            rootfs_overlay_mode: self.rootfs_overlay.map(|overlay| overlay.mode),
            mounts: self
                .mounts
                .unwrap_or_default()
                .into_iter()
                .map(|mount| MountSpecInput {
                    kind: mount.kind,
                    path: mount.path,
                    name: mount.name,
                })
                .collect(),
            network_http: self.network.and_then(|network| {
                network.http.map(|http| HttpSpecInput {
                    protected_ranges: http.protected_ranges.unwrap_or_default(),
                })
            }),
        }
    }
}
