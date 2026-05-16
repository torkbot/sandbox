use napi::bindgen_prelude::*;
use napi_derive::napi;
use std::collections::HashSet;
use std::process::Command;

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
    let _ = options.name.as_deref();
    Err(Error::new(
        Status::GenericFailure,
        "spawnSandbox native runtime is not implemented yet",
    ))
}

#[napi(object)]
pub struct NativeArtifactInspectionOptions {
    pub expected_static: bool,
    pub forbidden_dynamic_libraries: Vec<String>,
    pub macos_entitlements: Option<Vec<String>>,
    pub artifact_path: String,
}

#[napi(object)]
pub struct NativeArtifactInspection {
    pub static_linkage_ok: bool,
    pub dynamic_libraries: Vec<String>,
    pub codesign_valid: bool,
    pub entitlement_names: Vec<String>,
}

#[napi]
pub async fn inspect_sandbox_artifact(
    options: NativeArtifactInspectionOptions,
) -> Result<NativeArtifactInspection> {
    let dynamic_libraries = read_dynamic_libraries(&options.artifact_path)?;
    let static_linkage_ok = if options.expected_static {
        !dynamic_libraries.iter().any(|library| {
            options
                .forbidden_dynamic_libraries
                .iter()
                .any(|forbidden| library.contains(forbidden))
        })
    } else {
        true
    };

    let (codesign_valid, entitlement_names) = read_codesign_entitlements(&options.artifact_path)?;

    let required_entitlements = options.macos_entitlements.unwrap_or_default();
    let present: HashSet<&str> = entitlement_names.iter().map(String::as_str).collect();
    let codesign_valid = codesign_valid
        && required_entitlements
            .iter()
            .all(|entitlement| present.contains(entitlement.as_str()));

    Ok(NativeArtifactInspection {
        static_linkage_ok,
        dynamic_libraries,
        codesign_valid,
        entitlement_names,
    })
}

fn read_dynamic_libraries(artifact_path: &str) -> Result<Vec<String>> {
    if cfg!(target_os = "macos") {
        let output = Command::new("otool")
            .arg("-L")
            .arg(artifact_path)
            .output()
            .map_err(|error| {
                Error::new(
                    Status::GenericFailure,
                    format!("failed to run otool: {error}"),
                )
            })?;

        if !output.status.success() {
            return Err(Error::new(
                Status::GenericFailure,
                format!(
                    "otool failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .skip(1)
            .filter_map(|line| line.trim().split_whitespace().next())
            .map(str::to_owned)
            .collect())
    } else {
        Ok(Vec::new())
    }
}

fn read_codesign_entitlements(artifact_path: &str) -> Result<(bool, Vec<String>)> {
    if !cfg!(target_os = "macos") {
        return Ok((true, Vec::new()));
    }

    let output = Command::new("codesign")
        .args(["-d", "--entitlements", ":-", artifact_path])
        .output()
        .map_err(|error| {
            Error::new(
                Status::GenericFailure,
                format!("failed to run codesign: {error}"),
            )
        })?;

    if !output.status.success() {
        return Ok((false, Vec::new()));
    }

    let entitlements = String::from_utf8_lossy(&output.stdout);
    Ok((
        true,
        entitlements
            .lines()
            .filter_map(extract_entitlement_key)
            .collect(),
    ))
}

fn extract_entitlement_key(line: &str) -> Option<String> {
    let line = line.trim();
    let key = line.strip_prefix("<key>")?.strip_suffix("</key>")?;
    Some(key.to_owned())
}
