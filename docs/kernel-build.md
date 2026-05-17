# Kernel Build

Sandbox should not load `libkrunfw` at runtime. The `torkbot/libkrunfw` fork is a build-time input for producing the patched Linux kernel artifacts that Sandbox will later embed or package with the native module.

## Submodule

`deps/libkrunfw` tracks `https://github.com/torkbot/libkrunfw.git` on the `torkbot/sandbox` branch.

The upstream Makefile currently:

- downloads Linux `6.12.87`,
- applies patches from `patches/`,
- uses the matching `config-libkrunfw_<arch>` file,
- builds the kernel,
- produces `kernel.c` with `bin2cbundle.py`,
- optionally builds a dynamic `libkrunfw` library.

Sandbox uses this as kernel-build infrastructure only. The dynamic library output is not a runtime dependency.

## Local Build

The first build entrypoint assumes Docker is available locally:

```sh
npm run build:kernel
```

By default this runs `deps/libkrunfw` inside `debian:bookworm`, installs the Linux kernel build dependencies, runs `make`, and copies the kernel artifacts to:

```text
dist/kernel/libkrunfw/<arch>/
```

Environment knobs:

- `SANDBOX_KERNEL_ARCH`: guest architecture passed to the libkrunfw Makefile. Defaults to `arm64` on Apple Silicon and `x86_64` on x64 hosts.
- `SANDBOX_KERNEL_BUILDER_IMAGE`: Docker image to use. Defaults to `debian:bookworm`.
- `SANDBOX_KERNEL_OUT_DIR`: host output directory. Defaults to `dist/kernel/libkrunfw/<arch>`.

The build is intentionally not part of `spawnSandbox`. Runtime VM creation should receive a prebuilt kernel/rootfs artifact set.

## Next Integration Step

The current script preserves the artifacts libkrunfw already knows how to make. The next host-runtime slice should choose the exact artifact format consumed by the Rust crate:

- directly map/use the built kernel image, or
- compile the generated `kernel.c` bundle into the native module, or
- patch libkrun/libkrunfw for an fd/blob-backed kernel handoff.

The choice should keep the runtime contract path-minimal: paths are acceptable for build inputs and package artifacts, but VM instantiation should not require building or discovering kernels dynamically.
