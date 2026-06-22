# libkrun Fork Notes

Inspection target: `deps/libkrun`

Remote:

- `origin`: `https://github.com/torkbot/libkrun.git`

Branch state:

- local `torkbot/sandbox` tracks `origin/torkbot/sandbox`

Relevant current capabilities:

- explicit kernel/initramfs configuration lets this project avoid a runtime `libkrunfw` dependency.
- vsock port mapping is the right host/guest control-channel anchor.
- virtio-net supports UNIX stream, UNIX datagram, and tap-style integration points.
- virtio-fs supports path-backed host directory mounts. Sandbox extends that
  passthrough backend with an in-process mask layer for hiding selected lower
  host paths and optionally routing guest-created masked entries into a writable
  host storage directory.
- generic vhost-user device support is present for external device backends.

Integration policy:

- Do not bind Sandbox to libkrun's C API.
- Treat libkrun as Rust code that Sandbox links into its host crate.
- Patch the fork if needed to make static linking and internal Rust integration clean.
- Keep the final Sandbox host artifact statically linked apart from unavoidable platform system libraries.

Sandbox fork additions:

- `mask_fs` wraps the libkrun passthrough virtio-fs backend inside the virtio-fs
  worker, below the guest syscall boundary and below the JavaScript API layer.
- Mask enforcement belongs in the virtio-fs backend because it must affect
  lookup, readdir, create, unlink, rename, and file open behavior consistently
  for all guest processes.
- Sandbox calls a Rust-only helper to pass mask configuration into libkrun. Do
  not expose this project-specific configuration through libkrun's C API unless
  another consumer needs it.

Important gap:

- The currently exposed vhost-user device set covers console, RNG, RTC, input, vsock, sound, and CAN. A fully programmable host filesystem backend may need a small fork patch for virtio-fs vhost-user support.
- Some libkrun surfaces require UNIX socket paths even when Sandbox already owns
  the relevant socket. Prefer adding fd-taking variants where fd ownership gives
  cleaner lifecycle control and avoids creating filesystem-visible socket paths
  only to satisfy libkrun.
- macOS packaging must handle HVF entitlement code signing for the `sandbox-host` executable that opens Hypervisor.framework. Signing the Node native module alone is not sufficient.
- Sandbox should avoid path-only APIs when a lower-level primitive is available: fd for sockets, connected handles for databases, and bytes or async iterables for generated artifacts.
