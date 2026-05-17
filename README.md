# Sandbox

Sandbox is a TypeScript-first Node.js library for spawning libkrun-backed microVMs.

The target shape is:

- boot a guest from a prebuilt read-only rootfs artifact, likely EROFS,
- mount host-implemented virtual filesystems,
- intercept guest HTTP traffic through host TypeScript policy,
- communicate with guest init over a bidirectional transport,
- ship as a statically linked host artifact.

```ts
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  virtualFsMount,
} from "@torkbot/sandbox";

await using vm = await spawnSandbox({
  kernel: projectKernel(),
  init: projectInit(),
  rootfs: prebuiltRootfs("dist/rootfs/sandbox.erofs", { format: "erofs" }),

  mounts: [
    virtualFsMount("/sandbox/proc", {
      async stat(path) {
        if (path === "/") {
          return {
            type: "directory",
            sizeBytes: null,
            mediaType: null,
            modifiedAtMs: null,
          };
        }

        if (path === "/status.json") {
          return {
            type: "file",
            sizeBytes: null,
            mediaType: "application/json",
            modifiedAtMs: null,
          };
        }

        throw new Error(`missing path ${path}`);
      },

      async list(path) {
        if (path !== "/") throw new Error(`missing directory ${path}`);
        return [{ name: "status.json", type: "file" }];
      },

      async read(input) {
        if (input.path !== "/status.json") {
          throw new Error(`unknown virtual file: ${input.path}`);
        }

        return Buffer.from(JSON.stringify({ ready: true }));
      },
    }),
  ],

  network: {
    http: {
      async policy(request) {
        if (request.url.includes("/blocked")) {
          return { action: "deny", reason: "blocked by host policy" };
        }

        return {
          action: "allow",
          headers: {
            ...request.headers,
            "x-sandbox": "1",
          },
        };
      },
    },
  },
});
```

Incremental guest operations are explicit:

```ts
const result = await vm.control.exec({
  id: "tests",
  argv: ["node", "--test", "test/**/*.test.ts"],
});

if (result.exitCode !== 0) {
  throw new Error(result.stderr);
}
```

Mounted filesystems are also available from JavaScript through the same `stat` / `list` / `read` shape:

```ts
const sandboxProc = vm.mounts.virtualFs("/sandbox/proc");
const statusBytes = await sandboxProc.read({
  path: "/status.json",
  signal: AbortSignal.timeout(1_000),
});

console.log(JSON.parse(Buffer.from(statusBytes).toString("utf8")));
```

Root filesystems are immutable by default. For build-time image shaping, a VM can opt into a writable root overlay and publish the result as a new EROFS artifact:

```ts
await using vm = await spawnSandbox({
  kernel: projectKernel(),
  init: projectInit(),
  rootfs: prebuiltRootfs("dist/rootfs/base.erofs", { format: "erofs" }),
  rootfsOverlay: {
    mode: "writable",
  },
});

await vm.control.exec({
  id: "install-toolchain",
  argv: ["/bin/sh", "-lc", "apk add --no-cache git nodejs"],
});

const shaped = await vm.rootfs.snapshot({
  format: "erofs",
});
```

The guest contract is intentionally narrow:

- `/` is read-only.
- `/sandbox/proc` is implemented by the host.
- HTTP policy and header rewriting happen in TypeScript on the host.

## Design Targets

- no dynamic `libkrun` or `libkrunfw` dependency in the final host artifact,
- `napi-rs` for the Node/Rust native boundary,
- custom guest init owned by this repo,
- implicit fd-backed host control sockets owned by Sandbox,
- avoid host filesystem coordination unless it is intrinsic to the artifact; prefer file descriptors, database handles, bytes, and async iterables over paths,
- build-time rootfs shaping, with prebuilt rootfs artifacts supplied at VM instantiation,
- programmable virtual filesystems backed by TypeScript callbacks,
- transparent HTTP interception with TypeScript policy hooks,
- Rust-native or statically linkable networking components; sidecar network daemons are references, not default runtime dependencies,
- macOS HVF entitlement signing verified as part of the integration test flow.

## Repository Layout

- `src/`: TypeScript API consumed by Node.js callers.
- `crates/sandbox-host`: signed VM-host helper used for macOS HVF launch.
- `crates/sandbox`: Rust host implementation that owns the libkrun boundary and host services.
- `crates/sandbox-init`: custom guest init used to configure the guest before supervising untrusted code.
- `tests/e2e`: TypeScript e2e scenarios run directly by Node.js 24+ type stripping.

See [docs/architecture.md](docs/architecture.md) for the initial design.

Kernel artifacts are built separately from runtime VM creation. See [docs/kernel-build.md](docs/kernel-build.md) for the Docker-based `deps/libkrunfw` build entrypoint.
See [docs/testing-strategy.md](docs/testing-strategy.md) for the integration and e2e verification plan.
