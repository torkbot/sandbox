# Sandbox

Sandbox is a TypeScript-first Node.js library for running work inside
libkrun-backed microVMs with host-controlled filesystems and network policy.

```ts
import {
  defineSandbox,
  fs,
  rootfs,
} from "@torkbot/sandbox";

const workspaceFs = fs.memory({
  files: {
    "/hello.txt": "hello from the host filesystem\n",
  },
});

const sandbox = defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
  resources: {
    cpus: 2,
    memoryMiB: 2048,
  },
});

await using lane = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspaceFs),
  },
  cwd: "/workspace",
});

const result = await lane.exec("cat", ["hello.txt"]);

if (result.exitCode !== 0) {
  throw new Error(result.stderr);
}
```

## Quick Start

Create reusable machine configuration once, then boot one or more instances with
the mounts each instance needs:

```ts
import {
  defineSandbox,
  fs,
  rootfs,
} from "@torkbot/sandbox";

const workspaceFs = fs.memory();

const sandbox = defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
});

await using lane = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspaceFs),
  },
  cwd: "/workspace",
});

const result = await lane.exec("sh", ["-lc", "printf 'ok\\n'"], {
  env: { CI: "1" },
});

if (result.exitCode !== 0) {
  throw new Error(result.stderr);
}
```

The public API is split into three layers:

- `defineSandbox(...)` describes reusable machine configuration.
- `sandbox.boot(...)` creates a runtime instance with per-instance mounts.
- `lane.exec(...)` runs buffered work inside the booted instance.

Expensive artifact preparation is intentionally outside `boot()`.
`rootfs.builtIn("alpine:3.23")` selects a built-in rootfs artifact that must
already be installed with Sandbox. It does not pull an image or build a rootfs
at runtime.

## Durable, Policy-Controlled Instances

Sandbox composes durable rootfs mutation with explicit network policy. In this
example, dirty COW blocks are synchronized to blob storage, public HTTP(S)
egress is allowed, and only GitHub API requests receive an installation token:

```ts
import {
  defineSandbox,
  network,
  rootfs,
  type SandboxBlockStore,
} from "@torkbot/sandbox";

const writableRootfs: SandboxBlockStore = new BlobSynchronizedCowBlockStore({
  bucket: "sandbox-rootfs-overlays",
  keyPrefix: "lanes/github-worker",
});

const githubTokens = new GitHubInstallationTokenService({
  installationId: 123456,
});

const sandbox = defineSandbox({
  rootfs: rootfs.cow({
    base: rootfs.builtIn("alpine:3.23"),
    writable: writableRootfs,
  }),
  resources: {
    cpus: 4,
    memoryMiB: 4096,
  },
  network: network.policy(async (conn) => {
    if (conn.matchDns("10.0.2.1")?.accept()) return;

    const github = conn.transport === "tcp"
      ? conn.matchHttp("api.github.com")
      : undefined;
    if (github) {
      github.accept(async (request) => {
        if (request.destination.hostname !== "api.github.com") return;
        request.headers.set(
          "authorization",
          `Bearer ${await githubTokens.tokenForRequest(request)}`,
        );
      });
      return;
    }
  }),
});

await using lane = await sandbox.boot({ cwd: "/workspace" });

await lane.exec("sh", [
  "-lc",
  "apk add --no-cache git curl && curl -fsSL https://api.github.com/user",
]);
```

## API Overview

### Configuration

```ts
type SandboxDefinition = {
  rootfs: Rootfs;
  resources?: {
    cpus?: number;
    memoryMiB?: number;
  };
  network?: NetworkPolicy;
};
```

`rootfs` selects the guest root filesystem. The first public rootfs source is
the read-only built-in catalog:

```ts
rootfs.builtIn("alpine:3.23");
```

`resources` controls the VM shape used by every instance booted from the
definition. Omitted values use Sandbox defaults.

```ts
defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
  resources: {
    cpus: 4,
    memoryMiB: 4096,
  },
});
```

Use `rootfs.cow(...)` when rootfs mutations should persist. The sandbox library
owns the COW block-device contract; user-space owns the block store's
durability, migration, and checkpoint policy. Built-in rootfs packages include
one compressed QCOW2 image with an ext4 guest filesystem. `rootfs.builtIn(...)`
mounts that image read-only in the guest; `rootfs.cow(...)` mounts the same base
read-write through the host COW block store.

```ts
defineSandbox({
  rootfs: rootfs.cow({
    base: rootfs.builtIn("alpine:3.23"),
    writable: laneBlockStore,
  }),
});
```

The block store interface is intentionally storage-agnostic:

```ts
interface SandboxBlockStore {
  readonly blockSize: number;
  list(context: SandboxBlockStoreContext): Promise<readonly bigint[]>;
  read(
    range: SandboxBlockRange,
    context: SandboxBlockStoreContext,
  ): Promise<readonly SandboxBlockChunk[]>;
  write(
    chunks: readonly SandboxBlockChunk[],
    context: SandboxBlockStoreContext,
  ): Promise<void>;
  flush?(context: SandboxBlockStoreContext): Promise<void>;
}
```

The `context.base` value identifies the exact built-in base image for this boot.
The sandbox library passes it through to every block-store operation; user-space
storage can use it to namespace blocks, reject mismatched snapshots, or migrate
state. `list()` returns the block IDs currently present in the COW store. The
Rust block backend reads that manifest once at boot, so clean base-image blocks
are served without asking JavaScript. Dirty blocks are read lazily and writes are
batched back through `write(...)` on flush.

A writable COW block store must be attached to at most one running sandbox
instance at a time. Concurrent sandboxes sharing the same writable store are
undefined behavior; create one store per lane or enforce exclusivity in the
storage driver.

`network` is optional. When omitted, egress is denied. A network policy receives
connection requests and grants only the traffic it explicitly allows:

```ts
const policy = network.policy(async (conn) => {
  if (conn.transport === "tcp" && conn.dst.isPublicInternet() && conn.dst.port === 443) {
    conn.accept();
  }
});
```

`conn.accept()` grants the observed connection or flow at the transport layer.
It does not classify the application protocol, does not enter HTTP middleware,
and does not MITM TLS. `conn.acceptHttp(...)` is TCP-only and explicitly opts
the flow into Sandbox's HTTP-family enforcement path. If the accepted flow is
not actually HTTP or HTTPS, it fails closed.

```ts
const policy = network.policy(async (conn) => {
  const api = conn.transport === "tcp"
    ? conn.matchHttp("api.example.com")
    : undefined;
  if (!api) return;

  api.accept(async (request) => {
    request.headers.set(
      "authorization",
      `Bearer ${await credentialBroker.authorizationFor(request)}`,
    );
  });
});
```

Every TCP and UDP policy request carries source and destination IP-layer
endpoints:

```ts
conn.src.ip;
conn.src.port;
conn.dst.ip;
conn.dst.port;
```

Endpoint helpers classify logical address ranges without relying on hostnames:
`isLoopback()`, `isPrivate()`, `isLinkLocal()`, `isMulticast()`,
`isBroadcast()`, `isDocumentation()`, `isReserved()`, and
`isPublicInternet()`. `transport` is the TCP/UDP discriminator. Sandbox does
not expose a best-effort `conn.protocol` classifier.

HTTP middleware receives trusted destination metadata separately from the
request URL. `request.destination.hostname` is populated only when Sandbox can
pin the destination IP to trusted connection metadata, such as its own DNS
answer cache. IP-addressed requests still work under `acceptHttp(...)`, but they
do not advertise a hostname. Do not use the HTTP `Host` header as authority for
policy decisions.

For common policy checks, protocol match helpers acquire a typed capability
before accepting traffic:

```ts
network.policy(async (conn) => {
  if (conn.matchDns("10.0.2.1")?.accept()) return;

  if (conn.transport !== "tcp") return;
  const http = conn.matchHttp((candidate) =>
    candidate.hostname === "api.github.com"
  );
  if (!http) return;

  if (!(await policyManager.allow(http))) return;

  http.accept((request) => policyManager.handle(request));
});
```

Deny remains the default. If the policy callback does not create a grant, the
connection is blocked. The grants returned by `accept()` and `acceptHttp()` are
reserved as future extension points for instance-local state, such as
remembering a grant for a time window.

The runtime uses this policy shape to keep the JavaScript boundary explicit.
Native rules can be added under the same model later without changing the
caller-facing API.

### Boot Options

Mounts are per-instance because different sandbox instances often need
different filesystems over the same reusable machine configuration:

```ts
await using lane = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspaceFs),
    "/tmp": fs.virtual(privateFs),
    "/mnt": fs.virtual(sharedFs),
  },
  cwd: "/workspace",
});
```

Sandbox does not special-case `/workspace`. Mount paths are just guest-visible
paths backed by user-supplied filesystems. The target path must already exist
in the selected rootfs; the built-in Alpine rootfs includes `/workspace`,
`/tmp`, and `/mnt`.

### Filesystems

`fs.memory(...)` creates a real in-memory POSIX filesystem that can be mounted:

```ts
const workspaceFs = fs.memory({
  files: {
    "/README.md": "# Example\n",
  },
});
```

`fs.virtual(...)` adapts any compatible user-space JavaScript filesystem to
Sandbox mounts:

```ts
const workspace = fs.virtual(workspaceFs);
```

### Processes

`exec` is the simple buffered process API:

```ts
const result = await lane.exec("npm", ["test"], {
  cwd: "/workspace",
  env: { CI: "1" },
});
```

`exec` is intentionally small: it buffers stdout and stderr and returns when the
process exits. Streaming stdin/stdout/stderr belongs in the future
`lane.spawn(...)` API.

## Internal Architecture

Sandbox hides the kernel, init, transport, and host helper behind a small
TypeScript API:

- The runtime boots a libkrun-backed guest from a prebuilt rootfs artifact:
  a compressed QCOW2 image that contains an ext4 guest filesystem.
- Kernel and init artifacts are implementation details owned by Sandbox.
- A signed `sandbox-host` helper owns the Node/Rust/libkrun boundary.
- Guest control traffic uses an implicit fd-backed transport between the host
  and Sandbox init.
- Host-implemented virtual filesystems are mounted into the guest.
- Rootfs mutation persistence is modeled as block-level copy-on-write rootfs,
  not as a guest-visible POSIX filesystem.
- Network egress is default-deny. Native code should enforce fast-path policy
  decisions and delegate to JavaScript only when a policy callback is required.
- HTTP request middleware is caller-provided JavaScript, but Sandbox owns the
  interception machinery and certificate plumbing.
- When HTTP interception is enabled, the host generates the CA material and
  passes only the public CA certificate to Sandbox init. Init does not generate
  or manage certificates; the host exposes the supplied CA through an internal
  read-only virtiofs mount, then init installs it using the selected rootfs'
  native trust-store mechanism. Built-in rootfs launches use an ephemeral
  writable COW view for HTTP interception so init can update the guest trust
  store deterministically. If a rootfs does not provide a supported native
  trust-store installer, init fails closed.

The intended boundary is that Sandbox knows how to launch, isolate, mount,
intercept, and enforce. User-space owns artifact selection, filesystem
durability, network policy state, confirmation flows, and credential brokering.

## Design Targets

- no dynamic `libkrun` or `libkrunfw` dependency in the final host artifact,
- a signed `sandbox-host` process for the Node/Rust host boundary,
- custom guest init owned by this repo,
- implicit fd-backed host control sockets owned by Sandbox,
- avoid host filesystem coordination unless it is intrinsic to the artifact; prefer file descriptors, database handles, bytes, and async iterables over paths,
- build-time rootfs shaping, with built-in rootfs artifacts selected by typed logical names at VM instantiation,
- immutable rootfs by default, with copy-on-write rootfs supplied by a user-space block store when requested,
- generic guest-visible mounts backed by the same user-space filesystem abstraction,
- programmable virtual filesystems backed by TypeScript callbacks,
- transparent HTTP interception with TypeScript request-header hooks,
- default-deny outbound networking with JavaScript policy callbacks only where native rules cannot decide,
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

## Publishing

The npm package is published as `@torkbot/sandbox`. It does not use post-install scripts. The root package contains the TypeScript API and declares platform artifacts as optional dependencies:

- `@torkbot/sandbox-darwin-arm64`
- `@torkbot/sandbox-linux-x64-gnu`

Each platform package contains the `sandbox-host` helper and built-in rootfs artifacts for that target. Runtime artifact resolution only loads the installed optional dependency for the current platform. Local development uses the same layout by materializing the current platform package under `node_modules`.

### macOS signing setup

For now, the macOS `sandbox-host` artifact is not Developer ID signed or notarized. This is an explicit, possibly temporary workaround for publishing before this project has an Apple Developer account.

macOS users must sign the installed helper locally before launching a VM:

```sh
npx @torkbot/sandbox setup-macos
```

This performs an ad-hoc local `codesign` with the `com.apple.security.hypervisor` entitlement required by Hypervisor.framework. It does not contact Apple and does not require an Apple Developer account. If a macOS user tries to launch a VM before running setup, Sandbox throws a runtime error that points back to this command.

The release workflow verifies the tag, builds platform packages on their native runners, publishes the platform packages first, and then publishes the root package. That keeps the installable root package from pointing at missing optional artifacts while staying as close as npm allows to a single coordinated release operation.

Local release packaging sanity check:

```sh
npm run release:pack
```

After rebuilding local native artifacts, refresh the local optional package layout with:

```sh
npm run artifacts:link-current
```
