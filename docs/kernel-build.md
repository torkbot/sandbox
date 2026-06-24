# Kernel Build

Sandbox should not load `libkrunfw` at runtime. The `torkbot/libkrunfw` fork is a build-time input for producing the patched Linux kernel artifacts that Sandbox will later embed or package with the native module.

## Submodule

`deps/libkrunfw` tracks `https://github.com/torkbot/libkrunfw.git` on the `torkbot/sandbox` branch.

The upstream Makefile currently:

- downloads Linux `6.12.91`,
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

By default this runs `deps/libkrunfw` inside `debian:12`, installs the Linux kernel build dependencies, runs `make`, and copies the kernel artifacts to:

```text
dist/kernel/libkrunfw/<arch>/
```

`build:kernel` also writes `kernel-metadata.json` beside `kernel.c`. The metadata records the selected architecture, libkrunfw commit, kernel version, and a fingerprint of the kernel config, patches, and build wrapper. Before `build:host` embeds `kernel.c`, it verifies this metadata against the current checkout and fails closed if the kernel artifact is stale.

Environment knobs:

- `SANDBOX_KERNEL_ARCH`: guest architecture passed to the libkrunfw Makefile. Defaults to `arm64` on Apple Silicon and `x86_64` on x64 hosts.
- `SANDBOX_KERNEL_BUILDER_IMAGE`: Docker image to use. Defaults to `debian:12`.
- `SANDBOX_KERNEL_JOBS`: kernel build parallelism. Defaults to `4` to avoid overcommitting memory in local Docker builders.
- `SANDBOX_KERNEL_OUT_DIR`: host output directory. Defaults to `dist/kernel/libkrunfw/<arch>`.

The build is intentionally not part of `spawnSandbox`. Runtime VM creation should receive a prebuilt kernel/rootfs artifact set.

## Init And Rootfs Fixtures

The project also has build-time fixture helpers:

```sh
npm run build:init
npm run build:initrd
npm run build:rootfs
npm run build:rootfs:qcow2
```

`build:init` cross-builds `crates/sandbox-init` as a static Linux guest binary. `build:initrd` packs that binary into a small initramfs as `/init`; the host binary embeds this initramfs and boots it as stage 0. Stage 0 mounts the selected rootfs, moves kernel filesystems into it, copies the same init binary into guest tmpfs, and execs stage 1 from inside the selected image. `build:rootfs` exports an Alpine rootfs with agent-oriented command-line utilities and the mount points stage 0 requires: `/dev`, `/proc`, `/run`, `/sys`, and `/tmp`. The default image includes basics such as `bash`, `coreutils`, `curl`, `file`, `findutils`, `git`, `gh`, `jq`, `less`, `openssh-client`, `ripgrep`, Node.js 24 with `npm`, Python with `pip`, archive tools, PDF tools through `poppler-utils`, image metadata/conversion tools through `exiftool` and ImageMagick, and media inspection/conversion through `ffmpeg`. `build:rootfs:qcow2` packs that directory into a compressed `dist/rootfs/alpine-3.23.qcow2` image whose guest filesystem is ext4 with an 8 GiB virtual size by default and writes `dist/rootfs/alpine-3.23-agent.environment-facts.json` beside it. Set `SANDBOX_ROOTFS_VIRTUAL_SIZE` to a size such as `6gb`, `8gb`, or `8192mb` to change the build-time virtual filesystem size. These artifacts are development and CI fixtures today and are shaped like the external image packages Sandbox users will select through `rootfs.image(...)`.

## Static Link Handoff

The lowest-level runtime handoff is the generated `kernel.c` bundle, not the `libkrunfw` dynamic library. To compile the Sandbox Rust crate with that bundle linked into the VM host:

```sh
npm run build:host
```

The build script expects the kernel bundle and matching metadata from `build:kernel`, validates both, and passes the bundle to Cargo as `SANDBOX_KERNEL_BUNDLE_C`. It also expects the initramfs from `build:initrd` and passes it as `SANDBOX_INITRD_IMAGE`. Cargo compiles the C kernel bundle into the crate, embeds the initramfs bytes, and enables the `sandbox_static_kernel` and `sandbox_static_initrd` cfgs. At runtime, `sandbox-host` calls the raw kernel-bundle and initrd-bundle setters in the `torkbot/libkrun` fork. The kernel boots initramfs `/init` as stage 0; stage 1 then runs from tmpfs inside the caller-selected rootfs.

This avoids a runtime dependency on `libkrunfw` and avoids resolving a kernel path during VM creation. Paths remain build inputs and package artifacts only; VM instantiation should not require building or discovering kernels dynamically.
