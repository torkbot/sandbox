use napi::bindgen_prelude::*;
use napi_derive::napi;

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
pub struct NativeSpawnSandboxOptions {
    pub name: Option<String>,
}

#[napi]
pub async fn spawn_sandbox(_options: NativeSpawnSandboxOptions) -> Result<NativeSandboxVm> {
    Err(Error::new(
        Status::GenericFailure,
        "spawnSandbox native runtime is not implemented yet",
    ))
}

#[napi(object)]
pub struct NativeArtifactInspectionOptions {
    pub expected_static: bool,
}

#[napi(object)]
pub struct NativeArtifactInspection {
    pub static_linkage_ok: bool,
}

#[napi]
pub async fn inspect_sandbox_artifact(
    _options: NativeArtifactInspectionOptions,
) -> Result<NativeArtifactInspection> {
    Err(Error::new(
        Status::GenericFailure,
        "inspectSandboxArtifact native runtime is not implemented yet",
    ))
}
