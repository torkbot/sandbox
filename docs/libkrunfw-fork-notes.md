# libkrunfw Fork Notes

Inspection target: `deps/libkrunfw`

Remote:

- `origin`: `https://github.com/torkbot/libkrunfw.git`

Branch state:

- `torkbot/sandbox` exists and tracks `origin/torkbot/sandbox`.

Role in Sandbox:

- Build-time source for the patched Linux kernel config and patch series.
- Not a runtime dynamic dependency.
- Not the public API for selecting kernels at `spawnSandbox` time.

Current upstream build shape:

- `Makefile` downloads Linux `6.12.87`.
- `patches/` is applied in sorted order.
- `config-libkrunfw_<arch>` selects the guest kernel config.
- `bin2cbundle.py` can turn the built kernel into `kernel.c`.
- The Makefile then links a dynamic `libkrunfw` library, which Sandbox should treat as a compatibility output rather than a runtime dependency.

Sandbox build entrypoint:

- `npm run build:kernel`
- Assumes local Docker is available.
- Runs the libkrunfw Makefile in a Linux container.
- Copies `kernel.c` and the built kernel image into `dist/kernel/libkrunfw/<arch>/`.

Near-term branch plan:

1. Keep the fork branch aligned with upstream until Sandbox needs a patch.
2. Prefer adding build/export hooks that expose kernel artifacts directly instead of requiring consumers to load a dynamic library.
3. Keep runtime integration in the Sandbox Rust crate: package or embed prebuilt kernel artifacts and pass low-level primitives to libkrun.
4. If libkrun only supports path-oriented kernel setup where fd/blob setup is cleaner, stage the small API patch in `torkbot/libkrun`.
