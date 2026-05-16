# libkrun Fork Notes

Inspection target: `deps/libkrun`

Remote:

- `origin`: `https://github.com/torkbot/libkrun.git`

Branch state:

- local `main` tracks `origin/main`
- no `torkbot/sandbox` branch exists yet

Relevant current capabilities:

- explicit kernel/initramfs configuration lets this project avoid a runtime `libkrunfw` dependency.
- vsock port mapping is the right host/guest control-channel anchor.
- virtio-net supports UNIX stream, UNIX datagram, and tap-style integration points.
- virtio-fs supports path-backed host directory mounts.
- generic vhost-user device support is present for external device backends.

Integration policy:

- Do not bind Sandbox to libkrun's C API.
- Treat libkrun as Rust code that Sandbox links into its host crate.
- Patch the fork if needed to make static linking and internal Rust integration clean.
- Keep the final Sandbox host artifact statically linked apart from unavoidable platform system libraries.

Important gap:

- The currently exposed vhost-user device set covers console, RNG, RTC, input, vsock, sound, and CAN. A fully programmable host filesystem backend may need a small fork patch for virtio-fs vhost-user support.
- Some libkrun surfaces require UNIX socket paths even when Sandbox already owns the relevant socket. Prefer adding fd-taking variants where fd ownership gives cleaner lifecycle control and avoids creating filesystem-visible socket paths only to satisfy libkrun.
- macOS packaging must handle HVF entitlement code signing for the final executable or native module that opens Hypervisor.framework.
- Sandbox should avoid path-only APIs when a lower-level primitive is available: fd for sockets, connected handles for databases, and bytes or async iterables for generated artifacts.

Near-term branch plan:

1. Create `torkbot/sandbox` in `deps/libkrun` only when the first patch is known.
2. Keep the first patch narrowly focused on the missing extension point.
3. Prefer upstream-compatible public API changes over project-only hooks.
4. When adding fd variants, mirror the existing path-taking API and document fd ownership/duplication rules explicitly.
5. Verify static-link output and macOS codesigning requirements as soon as the first booting host binary exists.
