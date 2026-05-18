# Sandbox Architecture

## Goal

Provide a Node.js library that starts libkrun microVMs and lets the host program control networking, filesystems, and guest lifecycle through programmable policy hooks.

The library is not a generic VM manager. It is a constrained runtime for running untrusted workloads with explicit host-mediated capabilities.

## Boundary Invariants

Sandbox should make whole classes of bugs unrepresentable at the boundary where they enter the system:

- Public configuration is validated recursively before any helper process, native runtime, or libkrun context is created. Invalid rootfs compositions, unsupported backing types, and impossible mount specs must fail before launch.
- Guest-visible filesystem metadata is concrete where the kernel needs concrete values. Regular files and symlinks need known sizes; unknown-size streaming semantics require a separate explicit contract.
- Unsupported filesystem operation flags fail closed before crossing into JavaScript callbacks. If a POSIX variant such as exchange rename is needed later, it should be implemented as a named capability with matching inode-cache semantics and tests.
- Nonblocking I/O owns pending bytes explicitly. `WouldBlock` is a scheduling event, not permission to drop proxy prefaces, guest request bytes, or encrypted TLS response bytes.
- Long-lived per-flow host state has an owner and a reclamation path. NAT flows, dynamic listeners, proxy connections, callback waiters, and child processes should not outlive the VM lifecycle that created them.
- Host callback responses are lifecycle-aware. API/control writes fail strictly after close, while late service callback responses from in-flight filesystem or policy work are ignored once the VM is already closing.
- Network reachability is decided by `network.outbound` before JavaScript HTTP policy. HTTP policy can deny or rewrite egress headers, but it cannot grant reachability outside the default-deny firewall rules.

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

The target shape is an immutable read-only root volume, likely EROFS, produced from that extracted rootfs. Runtime writable root behavior should be a filesystem composition, not a second unrelated VM option.

The first writable-root primitive is explicit Linux overlayfs:

```ts
rootfs: linuxOverlayFs({
  lower: prebuiltRootfs("dist/rootfs/base.erofs", { format: "erofs" }),
  upper: scratchFs(),
})
```

`linuxOverlayFs(...)` means real Linux overlayfs semantics. It should not silently switch to a host-side userspace merge implementation for different inputs. Unsupported lower/upper combinations should be rejected until they are intentionally implemented.

Snapshotting a modified rootfs back into EROFS is deferred. The near-term contract is only that `linuxOverlayFs(...)` makes `/` writable through an isolated scratch upper while leaving the prebuilt lower unchanged.

## Networking

Sandbox needs two networking layers:

- A packet/socket layer that connects the guest to the host.
- An HTTP interception layer that terminates TLS, runs Node.js policy and header transforms, then forwards traffic.

The first implementation should prefer virtio-net connected to a userspace backend that we control, because HTTP interception and outbound policy are clearer when traffic passes through a host process. libkrun's TSI path remains useful for host control sockets or later transparent socket work, but TSI makes the VMM itself the network proxy and should be treated carefully.

Candidate directions:

- `smoltcp`: small Rust TCP/IP stack and the best fit for a natively compiled in-process service if it can cover the subset we need.
- Rust-native virtio/vhost-user networking crates: worth evaluating if they let us build the guest-facing network service without sidecars.
- `libslirp`: mature userspace NAT model, but only attractive if it can be statically linked cleanly and wrapped without fighting the Rust/napi-rs boundary.
- gVisor netstack and `gvproxy`: useful references for behavior and architecture, but poor direct dependencies for Sandbox because they are Go-oriented and sidecar-shaped.
- `passt`: useful reference for host networking behavior, but not a good runtime dependency if it requires an external process.

The likely path is: start with conventional virtio-net connected to a Rust host networking service compiled into Sandbox. Avoid a required external network helper process. Any networking component we choose should fit the static artifact strategy or be treated as reference material only.

Outbound networking is default-deny. The public API should look like a small firewall ruleset, not a bag of proxy options:

```ts
network: {
  outbound: {
    policy: "deny",
    rules: [
      acceptTcp({ cidr: "127.0.0.1/32", ports: [origin.port] }),
      acceptPublicInternet({ ports: [443] }),
    ],
  },
  http: {
    async policy(request) {
      return { action: "allow", headers: request.headers };
    },
  },
}
```

`network.outbound` decides reachability. `network.http.policy` can deny requests and rewrite egress headers, but it cannot grant network reachability that the outbound rules did not already provide. The host must enforce outbound rules before invoking JavaScript policy, and it must re-check them for DNS results, CONNECT targets, TLS SNI routing, redirects, and the final upstream dial target.

The HTTP interception CA is Sandbox infrastructure, not public API. Guest init should receive Sandbox-generated CA material and update the guest trust store before starting the workload. Callers should only provide the HTTP policy callback. If a future caller needs bring-your-own CA, that should be designed as a separate explicit capability rather than leaking certificate plumbing into the first API.

Host policy must cover:

- default-deny outbound reachability with explicit accept rules for protocol, CIDR or public-internet scope, and ports,
- loopback and link-local handling,
- DNS policy and post-resolution enforcement,
- CONNECT and TLS interception behavior,
- egress request header modification in Node.js with request bodies and responses passed through.

## Filesystems

Sandbox needs small filesystem primitives:

- `prebuiltRootfs(...)`: a supplied root artifact such as a directory or EROFS image.
- `scratchFs()`: an isolated writable filesystem owned by one VM instance.
- `linuxOverlayFs({ lower, upper })`: a real Linux overlayfs composition over generic filesystem values, rejecting combinations that cannot be mounted with Linux overlayfs.
- `mount(path, fs)`: a guest-visible mount boundary.
- `virtualFs(...)` / `virtualFsMount(...)`: host Node.js callbacks implementing a guest-visible filesystem.

Terminology matters:

- **mounts** are guest-visible kernel mounts. They should appear as mount boundaries in the guest.
- **bindings** are host-side attachment points into a filesystem abstraction. They are not guest-visible mount boundaries by definition.
- **attachment points** are the locations inside a host-side filesystem abstraction where bindings attach.

Do not hide bindings behind `mount(...)`. Sandbox exposes `binding(...)` as the separate host-side primitive. Internal optimizations are allowed for specific filesystem combinations, but they must preserve the named primitive's semantics.

Path-backed virtio-fs is adequate for simple guest-visible mounts, but it does not provide a programmable per-operation host API. The programmable filesystem should be a vhost-user backend owned by this project, with Node.js callbacks behind a Rust service boundary. That keeps guest filesystem traffic on a virtio device instead of inventing a guest agent protocol for normal file operations.

Durable filesystem implementations should be layered on top of the generic user-space filesystem hooks, not built into Sandbox as first-class mount types. Sandbox's responsibility is to provide correct guest filesystem operations and a stable JavaScript mount handle; storage engines belong above that boundary.

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

The desired output is a statically linked Sandbox VM-host binary, including the libkrun pieces we depend on. Dynamic dependencies should be treated as build failures unless they are unavoidable platform system libraries.

macOS needs a separate signing track. HVF requires the correct Hypervisor entitlement on the executable process that opens Hypervisor.framework. That process must be a Sandbox-owned helper executable, not `node`. The Node package remains the ergonomic TypeScript API, but macOS VM launch is delegated to the signed `sandbox-host` binary over a local control transport. Signing the napi addon or a dylib is not sufficient for HVF because the entitlement is process-scoped.

The napi-rs addon can still provide efficient local primitives, validation, and non-HVF fast paths, but it must not be the only VM launch path on macOS unless the embedding executable is known to be signed with the HVF entitlement. The addon may be ad-hoc signed as a loadable native module, but it should not carry the HVF entitlement.

The first helper protocol is deliberately small. Node starts `sandbox-host --stdio`, sends one length-prefixed BSON `host.spawn` document containing the validated VM spec, then both sides reuse the existing length-prefixed guest control frames for `init.ready` and `guest.exec`. Filesystem callbacks, HTTP policy, and other host services need explicit protocol additions before their required e2e scenarios can pass.

## Phased Implementation

1. Create a minimal Node API and Rust host crate with a libkrun context wrapper.
2. Build `sandbox-init` as a static guest binary and boot it with an explicit kernel/initramfs. If needed, use libkrun's legacy init only as a temporary bridge.
3. Add a vsock control channel and adapt it to the TypeScript `Transport` interface.
4. Add build-time Docker image export/extract rootfs tooling, then consume a prebuilt immutable read-only root volume at VM instantiation.
5. Add `linuxOverlayFs({ lower: prebuiltRootfs(...), upper: scratchFs() })` so `/` can be writable while the prebuilt lower remains immutable.
6. Add CA injection and a host HTTP proxy with Node.js policy callbacks.
7. Add a vhost-user filesystem backend for virtual and writable host-implemented guest mounts.
8. Move any required libkrun changes into `torkbot/libkrun` and keep them upstream-shaped.
