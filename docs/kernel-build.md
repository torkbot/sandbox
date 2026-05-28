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

## Init And Rootfs Fixtures

The project also has build-time fixture helpers:

```sh
npm run build:init
npm run build:rootfs
npm run build:rootfs:erofs
```

`build:init` cross-builds `crates/sandbox-init` as a static Linux guest binary. `build:rootfs` exports an Alpine rootfs with agent-oriented command-line utilities and copies that init binary into it as `/sandbox-init`. The default image includes basics such as `bash`, `coreutils`, `curl`, `file`, `findutils`, `git`, `jq`, `less`, `openssh-client`, `ripgrep`, archive tools, PDF tools through `poppler-utils`, image metadata/conversion tools through `exiftool` and ImageMagick, and media inspection/conversion through `ffmpeg`. `build:rootfs:erofs` packs that directory into `dist/rootfs/alpine-3.23.erofs` with deterministic `mkfs.erofs` settings, `lz4hc` compression, a 1 MiB compression cluster, and packed tail fragments. These are development and CI fixtures, not runtime APIs.

## Static Link Handoff

The lowest-level runtime handoff is the generated `kernel.c` bundle, not the `libkrunfw` dynamic library. To compile the Sandbox Rust crate with that bundle linked into the VM host:

```sh
npm run build:host
```

The build script expects the kernel bundle from `build:kernel` and passes it to Cargo as `SANDBOX_KERNEL_BUNDLE_C`. Cargo compiles the C kernel bundle into the crate and enables the `sandbox_static_kernel` cfg. At runtime, `sandbox-host` calls the raw kernel-bundle setter in the `torkbot/libkrun` fork with host address, guest load address, entry address, and size. Sandbox configures the guest kernel command line to boot `/sandbox-init` directly.

This avoids a runtime dependency on `libkrunfw` and avoids resolving a kernel path during VM creation. Paths remain build inputs and package artifacts only; VM instantiation should not require building or discovering kernels dynamically.
