# libkrun Fork Notes

Sandbox pins `torkbot/libkrun` as the `deps/libkrun` submodule. The current
integration branch is based on `containers/libkrun` commit
`c652b56ca6fe28a038bf4be5beb39fa54b4247c0`, whose crates identify themselves as
`2.0.0-dev`. Because upstream 2.0 is still under active development, update the
pin deliberately and verify the complete Sandbox integration before advancing
it.

## Integration policy

- Link libkrun into the Rust host crate. Sandbox does not maintain a Rust
  binding to libkrun's C API.
- Keep the fork limited to capabilities the Sandbox runtime exercises.
- Follow upstream's explicit device configuration model. Do not restore removed
  implicit console, vsock, root-disk, or data-disk compatibility APIs.
- Keep the final Sandbox host artifact statically linked apart from unavoidable
  platform system libraries.

## Sandbox capabilities

The fork carries the following integration seams on top of upstream 2.0:

- process-resident kernel and initrd bundles, avoiding a runtime `libkrunfw`
  dependency;
- an explicit direct block root backed by the Sandbox storage abstraction;
- file-descriptor-backed vsock ports for the host/guest control channel;
- explicit console output to a caller-owned file descriptor;
- in-process virtual virtio-fs backends;
- a virtio-fs mask layer that hides selected lower paths and can route
  guest-created masked entries into writable host storage;
- macOS host-directory identity mapping and private guest metadata, configured
  through a required Sandbox-only Rust passthrough mode; and
- direct Rust init configuration.

The mask layer belongs in the virtio-fs backend, below the guest syscall
boundary, so lookup, readdir, create, unlink, rename, and file-open behavior are
enforced consistently for every guest process. Sandbox passes mask and virtual
filesystem configuration through Rust-only helpers. Do not add corresponding C
APIs unless another consumer demonstrates that need.

Prefer file descriptors when Sandbox owns the host service lifecycle. Socket
paths remain appropriate for separately managed processes, but otherwise add
filesystem coordination that the runtime does not need.

## Packaging

On macOS, the `sandbox-host` executable that opens Hypervisor.framework must be
signed with the HVF entitlement. Signing the Node native module alone is not
sufficient.
