use napi::bindgen_prelude::*;
use napi_derive::napi;
use sandbox::config::{HttpSpecInput, MicroVmSpecInput, MountSpecInput};

#[napi]
pub struct NativeSandboxVm {
    vm: Option<sandbox::runtime::KrunVm>,
}

#[napi]
impl NativeSandboxVm {
    #[napi]
    pub fn close(&mut self) -> Result<()> {
        self.vm.take();
        Ok(())
    }

    #[napi(getter)]
    pub fn has_control_socket(&self) -> bool {
        self.vm
            .as_ref()
            .map(|vm| vm.control_socket().raw_fd() >= 0)
            .unwrap_or(false)
    }

    #[napi]
    pub fn write_control_packet(&mut self, packet: Uint8Array) -> Result<()> {
        let vm = self
            .vm
            .as_mut()
            .ok_or_else(|| Error::new(Status::InvalidArg, "sandbox VM is closed"))?;
        vm.control_socket_mut()
            .write_packet(packet.as_ref())
            .map_err(|error| {
                Error::new(
                    Status::GenericFailure,
                    format!("failed to write control packet: {error}"),
                )
            })
    }

    #[napi]
    pub fn try_read_control_packet(&mut self) -> Result<Option<Uint8Array>> {
        let vm = self
            .vm
            .as_mut()
            .ok_or_else(|| Error::new(Status::InvalidArg, "sandbox VM is closed"))?;
        if let Some(Err(error)) = vm.start_status() {
            return Err(Error::new(
                Status::GenericFailure,
                format!("libkrun VM exited before control packet was available: {error}"),
            ));
        }
        vm.control_socket_mut()
            .try_read_packet()
            .map(|packet| packet.map(Uint8Array::from))
            .map_err(|error| {
                Error::new(
                    Status::GenericFailure,
                    format!("failed to read control packet: {error}"),
                )
            })
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
pub struct NativeKernelOptions {
    pub format: Option<String>,
}

#[napi(object)]
pub struct NativeInitOptions {
    pub crate_name: String,
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
    pub ca_certificate_pem: Option<String>,
    pub ca_private_key_pem: Option<String>,
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
    pub kernel: NativeKernelOptions,
    pub init: NativeInitOptions,
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
    let mut vm = sandbox::runtime::KrunVm::create(&spec).map_err(|error| {
        Error::new(
            Status::GenericFailure,
            format!("failed to initialize libkrun context: {error}"),
        )
    })?;
    vm.start().map_err(|error| {
        Error::new(
            Status::GenericFailure,
            format!("failed to start libkrun VM: {error}"),
        )
    })?;

    Ok(NativeSandboxVm { vm: Some(vm) })
}

impl NativeSpawnSandboxOptions {
    fn into_spec_input(self) -> MicroVmSpecInput {
        MicroVmSpecInput {
            name: self.name,
            vcpus: self.cpu.and_then(|cpu| cpu.vcpus),
            memory_mib: self.memory.and_then(|memory| memory.mib),
            kernel_format: self.kernel.format,
            init_crate: self.init.crate_name,
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
                    ca_certificate_pem: http.ca_certificate_pem,
                    ca_private_key_pem: http.ca_private_key_pem,
                })
            }),
        }
    }
}
