# Sandbox Architecture

## Goal

Provide a Node.js library that starts libkrun microVMs and lets the host program control networking, filesystems, and guest lifecycle through programmable policy hooks.

The library is not a generic VM manager. It is a constrained runtime for running untrusted workloads with explicit host-mediated capabilities.

## Upstream Grounding

Current libkrun has the key extension points this project should build around, but Sandbox should not bind to the C API or treat `include/libkrun.h` as the integration surface. The host crate should integrate with libkrun as Rust code and keep the final deliverable statically linked. If upstream's crate boundaries or build outputs do not support that cleanly, carry small patches in `torkbot/libkrun`.

- `krun_set_kernel(...)` can point libkrun at an explicit kernel and initramfs, which is the path away from a dynamic `libkrunfw` dependency.
- `krun_add_vsock_port(...)`, `krun_add_vsock_port2(...)`, and `krun_add_vsock(...)` support guest-host IPC and Transparent Socket Impersonation control.
- `krun_add_net_unixstream(...)`, `krun_add_net_unixgram(...)`, and `krun_add_net_tap(...)` support conventional virtio-net backends.
- `krun_add_virtiofs3(...)` supports path-backed virtio-fs mounts with read-only control.
- generic vhost-user device support exists, but the currently exposed device set covers console, RNG, RTC, input, vsock, sound, and CAN. A host virtual filesystem backend may still need a small libkrun fork patch for virtio-fs vhost-user support.

libkrun's own security model is important: the VMM and guest are treated as the same host security context unless the host isolates the VMM with OS facilities. Sandbox must enforce host policy in its own services and still run the VMM with least privilege.

## Public Node.js Shape

The Node API should expose a small object model:

```ts
export interface MicroVm {
  readonly control: Transport;
  close(): Promise<void>;
}
```

`Transport` should match TorkBot's existing shape:

```ts
export interface Transport<TIncoming = unknown, TOutgoing = unknown> {
  readonly incoming: AsyncIterable<TIncoming>;
  send(message: TOutgoing): Promise<void>;
  close(): Promise<void>;
}
```

The transport is backed by libkrun vsock mapped to a host-owned fd. This is the only supported control mode for now, so it should be implicit in `spawnSandbox` rather than exposed as a choice in the public API.

The Node/Rust boundary should use `napi-rs`. Keep the TypeScript API as the ergonomic public surface and use `napi-rs` for the efficient hand-over into the Rust host runtime, libkrun integration, and long-lived native resources.

## Guest Init

The guest init is a first-class binary in this repo. It should:

1. Establish the host control channel.
2. Install host-provided CA material into the guest trust store.
3. Configure networking for the chosen mode.
4. Mount required virtual filesystems.
5. Report readiness to the host.
6. Drop privileges and supervise the untrusted workload.

This is where project-specific behavior belongs. The Node-facing API should not rely on shelling into the guest after boot to repair missing setup.

The target is direct Rust init injection: libkrun should load the `sandbox-init` binary we build in this repository without relying on the legacy C `init.krun` stage. The current two-stage boot path, where libkrun's init mounts the root and then execs `/sandbox-init`, is only a compatibility bridge while our fork catches up. `containers/libkrun#670` is the closest upstream direction: it ports libkrun's init to Rust and moves mount, network, config, and workload supervision into crate code. We should pull the useful shape into `torkbot/libkrun` where it helps, but keep Sandbox's project-specific control protocol and setup logic in `crates/sandbox-init`.

## Root Filesystem

Build the guest root filesystem before VM instantiation. The runtime API should receive a prebuilt rootfs artifact, not dynamically build one from a Docker image during `spawnSandbox`.

The build-time tooling can use a simple Docker image create/export/extract flow to shape the rootfs. That flow belongs in packaging or fixture-generation tools, not in the hot runtime path.

The target shape is an immutable read-only root volume, likely EROFS, produced from that extracted rootfs. Writable guest state should come from explicit SQLite-backed mounts rather than by making the root filesystem writable. That keeps the base environment content-addressable and makes all mutable state visible to the host-side filesystem layer.

Rootfs shaping is a separate build-time mode. Normal VM instantiation should boot an immutable root by default, but authoring tools may opt into a writable root overlay. In that mode the host can run incremental guest commands, capture rootfs deltas, and produce a new EROFS artifact programmatically. The low-level snapshot API should return artifact bytes and a digest, not force a host filesystem write. The output becomes the next prebuilt rootfs input; it should not turn normal runtime VMs into mutable-root machines.

## Networking

Sandbox needs two networking layers:

- A packet/socket layer that connects the guest to the host.
- An HTTP interception layer that terminates TLS, runs Node.js policy and header transforms, then forwards traffic.

The first implementation should prefer virtio-net connected to a userspace backend that we control, because HTTP interception and protected-range policy are clearer when traffic passes through a host process. libkrun's TSI path remains useful for host control sockets or later transparent socket work, but TSI makes the VMM itself the network proxy and should be treated carefully.

Candidate directions:

- `smoltcp`: small Rust TCP/IP stack and the best fit for a natively compiled in-process service if it can cover the subset we need.
- Rust-native virtio/vhost-user networking crates: worth evaluating if they let us build the guest-facing network service without sidecars.
- `libslirp`: mature userspace NAT model, but only attractive if it can be statically linked cleanly and wrapped without fighting the Rust/napi-rs boundary.
- gVisor netstack and `gvproxy`: useful references for behavior and architecture, but poor direct dependencies for Sandbox because they are Go-oriented and sidecar-shaped.
- `passt`: useful reference for host networking behavior, but not a good runtime dependency if it requires an external process.

The likely path is: start with conventional virtio-net connected to a Rust host networking service compiled into Sandbox. Avoid a required external network helper process. Any networking component we choose should fit the static artifact strategy or be treated as reference material only.

HTTP interception requires explicit guest trust injection. The guest init should mount or receive the generated CA certificate and update the guest trust store before starting the workload. Host policy must cover:

- destination allow/deny rules,
- protected host and private network ranges,
- loopback and link-local handling,
- DNS policy,
- CONNECT and TLS interception behavior,
- request/response header modification hooks in Node.js.

## Filesystems

Sandbox needs three filesystem modes:

- Static or read-only host directory mounts through libkrun virtio-fs, and eventually immutable root volumes such as EROFS.
- Writable SQLite-backed mounts persisted through connected database handles.
- Fully virtual filesystems implemented by host Node.js code, including procfs-like control trees.

Path-backed virtio-fs is adequate for immutable roots and simple mounts, but it does not provide a programmable per-operation host API. The programmable filesystem should be a vhost-user backend owned by this project, with Node.js callbacks behind a Rust service boundary. That keeps guest filesystem traffic on a virtio device instead of inventing a guest agent protocol for normal file operations.

Writable mounts should be represented as structured database state rather than opaque disk images. Sandbox must receive a connected, ready database handle instead of an SQLite file path, and that handle may be backed by `:memory:`. The public type should align with the database handle TorkBot already uses: prepare statements, execute SQL, and run transactions. Multiple guest mounts may share the same database handle, so each `sqliteFsMount` has an explicit mount `name` used to partition filesystem state inside the database. A practical MVP can materialize a writable upperdir and sync deltas through the handle, but the target architecture is a direct host filesystem service backed by tables for nodes, versions, content blobs, and operations.

## libkrun Fork

`torkbot/libkrun` is checked out at `deps/libkrun` for local inspection. It is currently a fresh fork with only `main` from `origin`. Convert it to a git submodule when this repo needs to track a specific libkrun commit as part of the build.

Expected fork patches:

- expose any missing vhost-user device type needed for virtio-fs,
- add file-descriptor variants for libkrun surfaces that currently force UNIX socket paths when the caller already owns a connected or listening socket,
- make custom kernel/initramfs/static-kernel workflows smooth for this package,
- make direct Rust init injection the normal path, without a C stage-0 init binary,
- support linking libkrun into Sandbox statically instead of loading libkrun as a dynamic C library,
- keep changes small and upstreamable.

Prefer fd-oriented APIs for host services owned by Sandbox. Socket paths are useful when integrating with a separately managed process, but they force unnecessary filesystem coordination when the Node/Rust host runtime already created the socket and controls its lifetime.

More generally, avoid host filesystem coordination unless the filesystem path is intrinsic to the artifact being consumed. Prefer file descriptors over socket paths, connected database handles over database paths, and bytes or async iterables over output paths.

## Static Kernel

The package should not depend on `libkrunfw` at runtime. The host crate should configure a project-built kernel directly through the libkrun Rust integration. The build needs to produce reproducible artifacts and statically link the kernel bundle into the native module.

`torkbot/libkrunfw` is still useful as build-time kernel infrastructure because it already defines the Linux version, kernel config, and patch series libkrun expects. Sandbox tracks that fork at `deps/libkrunfw` on `torkbot/sandbox` and uses it to build patched kernel artifacts. The dynamic `libkrunfw` output remains an intermediate or compatibility artifact, not something the runtime should load.

The first build entrypoint is `npm run build:kernel`, which assumes a local Docker environment and runs the libkrunfw Makefile in a Linux builder container. See [kernel-build.md](kernel-build.md). The generated `kernel.c` bundle can be compiled into the Sandbox Rust crate with `SANDBOX_KERNEL_BUNDLE_C`, then handed to the `torkbot/libkrun` fork through a raw kernel-bundle setter. `spawnSandbox` must not build or discover a kernel dynamically.

## Static Linking And macOS Signing

The desired output is a statically linked Sandbox host binary or native Node module, including the libkrun pieces we depend on. Dynamic dependencies should be treated as build failures unless they are unavoidable platform system libraries.

macOS needs a separate signing track. HVF requires the correct Hypervisor entitlement on the host executable process, not on the Node native addon alone. Sandbox signs the addon as a build artifact so it can be loaded, but TorkBot or any other host executable that actually launches VMs must be signed with the Hypervisor entitlement before launch. This is part of the runtime contract, not a release-only afterthought.

## Phased Implementation

1. Create a minimal Node API and Rust host crate with a libkrun context wrapper.
2. Build `sandbox-init` as a static guest binary and boot it with an explicit kernel/initramfs. If needed, use libkrun's legacy init only as a temporary bridge.
3. Add a vsock control channel and adapt it to the TypeScript `Transport` interface.
4. Add build-time Docker image export/extract rootfs tooling, then consume a prebuilt immutable read-only root volume at VM instantiation.
5. Add rootfs overlay shaping mode that can run incremental guest operations and publish a new EROFS artifact.
6. Add CA injection and a host HTTP proxy with Node.js policy callbacks.
7. Prototype SQLite-backed mounts with materialized deltas persisted through the supplied database handle.
8. Add a vhost-user filesystem backend for virtual and SQLite-backed mounts.
9. Move any required libkrun changes into `torkbot/libkrun` and keep them upstream-shaped.
