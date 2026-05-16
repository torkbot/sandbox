use napi::bindgen_prelude::*;
use napi_derive::napi;
use serde::Deserialize;

#[napi]
pub struct NativeSandboxVm {}

#[napi]
impl NativeSandboxVm {
    #[napi]
    pub async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeSpawnSandboxOptions {
    name: Option<String>,
}

#[napi]
pub async fn spawn_sandbox(options_json: String) -> Result<NativeSandboxVm> {
    let options: NativeSpawnSandboxOptions = parse_json(&options_json, "spawnSandbox options")?;
    let _ = options.name.as_deref();
    Err(Error::new(
        Status::GenericFailure,
        "spawnSandbox native runtime is not implemented yet",
    ))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeArtifactInspectionOptions {
    expected_static: bool,
}

#[napi(object)]
pub struct NativeArtifactInspection {
    pub static_linkage_ok: bool,
}

#[napi]
pub async fn inspect_sandbox_artifact(
    options_json: String,
) -> Result<NativeArtifactInspection> {
    let options: NativeArtifactInspectionOptions =
        parse_json(&options_json, "inspectSandboxArtifact options")?;
    let _ = options.expected_static;
    Err(Error::new(
        Status::GenericFailure,
        "inspectSandboxArtifact native runtime is not implemented yet",
    ))
}

fn parse_json<T: for<'de> Deserialize<'de>>(json: &str, label: &str) -> Result<T> {
    serde_json::from_str(json).map_err(|error| {
        Error::new(
            Status::InvalidArg,
            format!("invalid {label}: {error}"),
        )
    })
}
