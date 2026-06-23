# Sandbox

Sandbox is a TypeScript-first Node.js library for running AI-agent work inside
isolated Linux VMs. It gives agent builders a small API for booting strongly
isolated VMs, mounting host-controlled filesystems, preserving machine state
across boots, and enforcing explicit network egress policy.

Use Sandbox when your agent needs to run tools, install packages, clone repos,
execute untrusted code, or call external APIs without handing the work broad
filesystem or network access on the host machine.

Sandbox is designed for:

- agent runtimes that need disposable or durable Linux workspaces,
- coding agents that need real shells, compilers, package managers, and repo
  checkouts,
- browser or data agents that need tightly-scoped outbound network access,
- hosted agent platforms that need per-task isolation with policy and audit
  points in TypeScript,
- systems that need to broker credentials from the host without putting long
  lived secrets inside the VM.

## Example

This example creates a durable agent lane, mounts a host-controlled workspace,
allows DNS through Cloudflare, allows only GitHub API HTTP traffic, and injects
a short-lived GitHub token from the host before the request leaves the sandbox.

```ts
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  type SandboxBlockStore,
} from "@torkbot/sandbox";

const workspace = fs.memory({
  files: {
    "/task.txt": "Summarize the current GitHub user\n",
  },
});

const writableRootfs: SandboxBlockStore = new BlobBackedBlockStore({
  bucket: "agent-machines",
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
    // Let commands resolve names, but answer DNS via an explicit resolver.
    if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

    // Only GitHub API HTTP(S) traffic gets HTTP middleware.
    const github = conn.matchHttp("api.github.com");
    if (!github) return;

    // Keep the credential decision in host-controlled TypeScript.
    if (!(await githubTokens.canServe(github))) return;

    github.accept(async (request) => {
      request.headers.set(
        "authorization",
        `Bearer ${await githubTokens.tokenForRequest(request)}`,
      );
    });
  }),
});

await using lane = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspace),
  },
  cwd: "/workspace",
});

const result = await lane.exec("sh", [
  "-lc",
  "cat task.txt && curl -fsSL https://api.github.com/user",
]);

if (result.exitCode !== 0) {
  throw new Error(result.stderr);
}
```

The agent process gets a normal Linux VM. The host keeps control over
the workspace contents, machine persistence, network decisions, and credential
injection.

## Quick Paths

### Run one isolated command

Use a built-in read-only VM image and a memory-backed workspace:

```ts
const workspace = fs.memory({
  files: { "/hello.txt": "hello from the host\n" },
});

const sandbox = defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
});

await using lane = await sandbox.boot({
  mounts: { "/workspace": fs.virtual(workspace) },
  cwd: "/workspace",
});

const result = await lane.exec("cat", ["hello.txt"]);
```

### Give an agent a durable machine

Use `rootfs.cow(...)` when package installs, language toolchains, caches, and
other machine changes should survive across boots. Sandbox handles turning those
changes into storage operations; your application owns where the changed bytes
are stored.

```ts
const source = rootfs.compose({
  base: rootfs.builtIn("alpine:3.23"),
  overlay: blockStore,
});

const sandbox = defineSandbox({
  rootfs: rootfs.cow({ source }),
});
```

Attach one writable storage backend to at most one running sandbox instance at a
time. Create one backend per lane, or enforce exclusivity in your storage
layer.

Use `rootfs.persistent(...)` when durable VM state should live in one local file
on disk instead of in a JavaScript storage backend:

```ts
const sandbox = defineSandbox({
  rootfs: rootfs.persistent({
    base: rootfs.builtIn("alpine:3.23"),
    path: "/absolute/project/.sandbox/rootfs.qcow2",
  }),
});
```

Sandbox creates the state file on first boot and reuses it on later boots. The
built-in VM image stays read-only and can be shared by many VMs; only the
selected state file is single-writer while a VM is running. Sandbox records
which built-in image the file belongs to and rejects mismatched reuse. The
`.qcow2` extension identifies the VM disk-image format; for callers, the file is
just the durable state for that lane.

### Mount host-controlled data

Mounts are per boot. They are paths inside the VM backed by TypeScript
filesystem implementations, not host path passthrough.

```ts
await using lane = await sandbox.boot({
  hostname: "agent-42",
  mounts: {
    "/workspace": fs.virtual(workspaceFs),
    "/mnt/shared": fs.virtual(sharedFs),
  },
  cwd: "/workspace",
});
```

Sandbox configures the kernel hostname during boot. Omit `hostname` to use the
built-in default `sandbox`.

Sandbox init creates missing mount target directories immediately before
attaching each virtual filesystem, matching container runtime behavior when the
target parent is on init-owned tmpfs or comes from an earlier virtual mount. On
durable machine paths that cannot be created without changing saved machine
state, boot fails with the startup error surfaced in the host exception.

### Read and write the running guest

Use `vm.fs` when the host needs to inspect or mutate the full composed guest
filesystem after boot, including the rootfs and every mounted filesystem:

```ts
await using vm = await sandbox.boot();

await vm.fs.writeFile("/tmp/task/input.txt", "hello world", {
  createParents: true,
});

const chunk = await vm.fs.readFile("/tmp/task/input.txt", {
  range: { offset: 6, length: 5 },
});

const entries = await vm.fs.readDir("/tmp/task");
const published = new TextDecoder().decode(chunk);

await vm.fs.rename("/tmp/task/input.txt", "/tmp/task/published.txt");
```

`readDir(...)` returns entry names, exact entry-name bytes, and metadata
together, so callers do not need one `stat(...)` call per entry. `writeFile(...)`
creates a missing file and replaces an existing file; `createParents` only
controls whether missing parent directories are created first.

### Control network egress

Networking is default-deny. Policy callbacks grant only the flows they accept:

```ts
const sandbox = defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
  network: network.policy((conn) => {
    if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

    conn.matchHttp("api.example.com")?.accept((request) => {
      request.headers.set("authorization", `Bearer ${apiToken}`);
    });
  }),
});
```

Use `conn.accept()` for raw transport, and protocol match helpers when you want
Sandbox to handle protocol-specific semantics. `conn.matchHttp(...)` does not
trust the HTTP `Host` header; it uses trusted destination metadata and then
routes accepted traffic through HTTP-family enforcement.

### Broker credentials from the host

Credential injection belongs in HTTP middleware, not in the VM filesystem or
environment:

```ts
const github = conn.matchHttp("api.github.com");
if (!github) return;

if (!(await policyManager.allow(github))) return;

github.accept(async (request) => {
  request.headers.set(
    "authorization",
    `Bearer ${await policyManager.tokenFor(request)}`,
  );
});
```

This lets the VM run ordinary tools such as `curl`, `git`, package managers,
or language CLIs while the host decides which outbound requests receive
credentials.

## API Reference

### `defineSandbox(options)`

Creates reusable machine configuration.

```ts
const sandbox = defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
  resources: {
    cpus: 4,
    memoryMiB: 4096,
  },
  network: network.policy((conn) => {
    conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] });
  }),
});
```

`defineSandbox(...)` does not start a VM. It describes rootfs, resource, and
network policy defaults that can be reused across many boots.

Use `environmentFacts()` on a definition to recover facts known from
configuration without starting a VM:

```ts
const facts = sandbox.environmentFacts();
```

Use `environmentFacts()` on a booted instance when the caller needs observations
from the running VM as well:

```ts
await using vm = await sandbox.boot();

const facts = await vm.environmentFacts();
```

Facts are affirmative typed triples with required provenance. The exported
`SandboxEnvironmentFact` union narrows `topic`, `relation`, and `value`; every
member has this outer shape:

```ts
type SandboxEnvironmentFact = {
  source: "config" | "guest";
  topic: string;
  relation: string;
  value: string;
};
```

The current built-in Alpine rootfs reports facts such as
`rootfs-image is alpine:3.23`, `distro is alpine`, `distro-version is 3.23`,
`package-manager is apk`, `shell is /bin/sh`, rootfs write semantics, and
policy-controlled network egress when `network.policy(...)` is configured.
Read-only built-in definitions also report concrete `command exists ...`
entries for `bash`, `curl`, `git`, `gh`, `jq`, `node`, `npm`, `python3`,
`pip3`, and `rg`; writable rootfs definitions leave command availability to
the booted instance's runtime-observed facts. Built-in image facts are sourced
from the rootfs build definition. The booted instance additionally reports
runtime-observed distro, distro version, package-manager, shell, command
availability, and root mount mode facts.

### `rootfs`

In this API, `rootfs` means the Linux machine state the VM starts from:
system packages, language runtimes, caches, and files outside your explicit
workspace mounts. Most application code should choose whether that machine is
read-only, temporary, saved through application storage, or saved in one local
file.

```ts
rootfs.builtIn("alpine:3.23");
```

Selects a built-in VM image that the guest can read but not modify. Built-in
images are prepared at build or install time; Sandbox does not pull container
images or build root filesystems during `boot()`.

```ts
rootfs.ephemeral({
  base: rootfs.builtIn("alpine:3.23"),
  maxDirtyBytes: 64 * 1024 * 1024,
});
```

Gives the VM writable machine state for one boot. Sandbox keeps changes in
memory and discards them when the sandbox instance exits. Use this when a
command needs to install packages, write caches, or mutate the Linux machine,
but those changes must not persist across boots.

```ts
rootfs.cow({
  base: rootfs.builtIn("alpine:3.23"),
  writable: blockStore,
  maxDirtyBytes: 64 * 1024 * 1024,
});
```

Gives the VM a writable machine whose changes are saved through your
`SandboxBlockStore`. Use this when durable machine state belongs in your own
storage service, such as object storage, a database-backed block store, or a
per-agent lane store.

```ts
rootfs.persistent({
  base: rootfs.builtIn("alpine:3.23"),
  path: "/absolute/project/.sandbox/rootfs.qcow2",
});
```

Gives the VM a writable machine whose changes are saved in one local host file.
The `path` is required and must be absolute. If the file does not exist, Sandbox
creates it on first boot; the parent directory must already exist. If the file
already exists, Sandbox reuses it. The file is a QCOW2 overlay: a sparse VM disk
image that stores changes on top of the read-only built-in image. The built-in
image itself is opened read-only and is not locked, so many VMs can share the
same base image. Sandbox records which built-in image the state file belongs to
and rejects reuse with a different base.

The state file is host-owned VM state. Keep it outside guest-writable
host-directory mounts, or hide its containing directory with a host-directory
`mask.paths` entry such as `"/.sandbox"`. Sandbox does not attempt to prove this
for arbitrary host paths, symlinks, or mount layouts. The state file is locked
for the VM lifetime on filesystems that honor advisory file locks;
concurrent boots must use distinct state files unless the caller supplies
stronger storage coordination.

For offline image export, describe the same saved machine state without booting
a VM:

```ts
const source = rootfs.compose({
  base: rootfs.builtIn("alpine:3.23"),
  overlay: blockStore,
});

const image = await rootfs.flatten({
  format: "qcow2",
  source,
  dest: imageStore,
  clusterSize: 65536,
});

for await (const chunk of rootfs.bytes(image)) {
  await upload(chunk);
}
```

Here, `overlay` means the saved changes layered on top of the read-only built-in
image.

`rootfs.ephemeral(...)`, `rootfs.cow(...)`, and `rootfs.persistent(...)` all
present a writable Linux machine without modifying the built-in image.
`rootfs.cow(...)` normalizes through the same composed source used by
`rootfs.flatten(...)`, so boot and image export share one contract: a read-only
base plus saved changes. Unchanged data is served from the built-in image.
Changed data is read lazily and flushed through your `SandboxBlockStore`.
`maxDirtyBytes` limits how much changed data Sandbox buffers before forcing a
write to the storage backend during a run. For
`rootfs.ephemeral(...)`, the same value is the native in-memory change budget;
VM writes beyond that budget fail instead of growing host memory without
bound. When omitted, Sandbox uses a 64 MiB default.
`rootfs.persistent(...)` stores the saved changes directly in the local state
file instead of a `SandboxBlockStore`; the file is sparse and grows as the VM
writes.

`rootfs.flatten(...)` writes a standalone bootable disk image into `dest`, using
`dest` as random-access image-byte storage. `rootfs.bytes(...)` streams raw image
container bytes for a built-in image or a flattened image; it does not stream the
filesystem contents inside the image. The current export format is QCOW2, a
sparse disk-image container understood by common tooling.

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

The `context.base` value identifies the exact built-in base image for the boot,
so storage layers can namespace blocks, reject mismatched snapshots, or migrate
state.

`write()` receives block bytes owned by the block store. The sandbox runtime
will not mutate those `Uint8Array` values after passing them to `write()`, so a
store may retain them for delayed persistence. A store that returns bytes from
`read()` should treat the returned arrays as immutable after the promise
resolves.

### `sandbox.boot(options)`

Boots a sandbox instance.

```ts
await using lane = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspaceFs),
  },
  cwd: "/workspace",
});
```

Boot options are per instance. The same sandbox definition can be booted with
different mounts and working directories.

### Filesystems

```ts
const workspaceFs = fs.memory({
  files: {
    "/README.md": "# Task\n",
  },
});
```

`fs.memory(...)` creates an in-memory POSIX filesystem.

```ts
const mount = fs.virtual(workspaceFs);
```

`fs.virtual(...)` adapts a compatible JavaScript filesystem for guest mounts.
Sandbox virtual mounts are host-implemented filesystems, not direct host
directory mounts.

```ts
const source = fs.bind({
  source: "/Users/alice/project",
  access: "ro",
});
```

`fs.bind(...)` mounts an absolute host directory through native virtio-fs. The
`access` field is required and must be `"ro"` or `"rw"`.

```ts
const source = fs.bind({
  source: "/Users/alice/project",
  access: "ro",
  mask: {
    paths: ["/node_modules", "/.git"],
  },
});
```

`mask` hides selected host paths from the guest. Mask paths are absolute inside
the bound host directory. In a read-only bind mount, masked paths are simply
absent from the guest.

```ts
const maskStorage = fs.bind({
  source: "/tmp/sandbox-mask-storage/project",
  access: "rw",
});

const source = fs.bind({
  source: "/Users/alice/project",
  access: "rw",
  mask: {
    paths: ["/node_modules"],
    storage: maskStorage,
  },
});
```

Writable bind mounts require `mask.storage`, and that storage must also be a
writable `fs.bind(...)` source. If the guest creates a masked path, Sandbox
stores that guest-owned entry under the storage directory using the same
mask-relative path, while the original host entry remains hidden and unchanged.

### Guest filesystem

Every booted sandbox exposes `vm.fs`, a small host API over the running guest's
composed filesystem. Paths are absolute guest paths. Except for `/`, paths must
not end in a trailing slash; this keeps symlink entries from being accidentally
resolved as their directory targets by Linux path traversal.
Safe inspection operations may target `/`, but mutation paths for `writeFile`,
`mkdir`, `remove`, and `rename` must not be the guest root.

```ts
const stat = await vm.fs.stat("/workspace/package.json");
const entries = await vm.fs.readDir("/workspace/src");
const bytes = await vm.fs.readFile("/workspace/log.txt", {
  range: { offset: 1024, length: 4096 },
});

await vm.fs.writeFile("/workspace/out/result.json", contents, {
  createParents: true,
});
await vm.fs.mkdir("/workspace/cache/deep", { recursive: true });
await vm.fs.remove("/workspace/cache", { recursive: true });
await vm.fs.remove("/workspace/maybe-gone", { force: true });
await vm.fs.rename("/workspace/out/result.tmp", "/workspace/out/result.json");
```

`stat(...)` reports the directory entry itself, including symlinks, rather than
following symlink targets. `readFile(...)` reads the whole file unless a byte
`range` with required `offset` and `length` is supplied. `writeFile(...)`
creates or truncates the target file; the caller does not need to know whether
the file already exists.

`readDir(...)` includes each entry's `name`, exact `nameBytes`, and `stat` in one
round trip. `name` is the normal UTF-8 filename for ordinary entries;
`nameBytes` preserves the raw guest directory-entry bytes.

For `remove(...)`, `recursive` permits deleting non-empty directories. `force`
only suppresses a missing target; permission, read-only filesystem, type, and
non-empty-directory errors are still returned.

`rename(...)` is a single guest rename operation. It does not create missing
parent directories, because doing so would turn a rename into multiple
filesystem mutations and weaken the atomicity callers expect. The target parent
must already exist; cross-filesystem renames may fail with the guest filesystem's
native error.

### Processes

```ts
const result = await lane.exec("npm", ["test"], {
  cwd: "/workspace",
  env: { CI: "1" },
  timeoutMs: 120_000,
  signal: abortController.signal,
});
```

`exec(...)` is the buffered process API. It returns after the command exits with
`exitCode`, `stdout`, and `stderr`. When `timeoutMs` expires, Sandbox terminates
the guest process group and returns exit code `124`. When `signal` aborts,
Sandbox terminates that guest process group, rejects the `exec(...)` promise with
an `AbortError`, and keeps the sandbox usable for subsequent commands.

Use `spawn(...)` for non-interactive long-lived processes with streaming
stdin, stdout, and stderr. It returns a process handle immediately; `ready`
tracks guest-side startup.

```ts
import { Writable } from "node:stream";

const child = lane.spawn("npm", ["test"], { cwd: "/workspace" });

child.stdout.pipeTo(Writable.toWeb(process.stdout));
child.stderr.pipeTo(Writable.toWeb(process.stderr));

const { exitCode } = await child.exit;
```

Use `pty(...)` when the guest process should see a real terminal, such as an
interactive shell, REPL, pager, or terminal UI:

```ts
import { Readable, Writable } from "node:stream";

const shell = lane.pty("/bin/sh", ["-i"], {
  cwd: "/workspace",
  env: { TERM: "xterm-256color" },
  size: { rows: 40, cols: 120 },
});

Readable.toWeb(process.stdin).pipeTo(shell.input);
shell.output.pipeTo(Writable.toWeb(process.stdout));
```

### Network Policy

```ts
const policy = network.policy(async (conn) => {
  if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

  const api = conn.matchHttp("api.example.com");
  if (!api) return;

  if (!(await policyManager.allow(api))) return;

  api.accept((request) => policyManager.handleHttp(request));
});
```

Policy callbacks are default-deny. If the callback does not create a grant, the
connection is blocked.

Every policy event exposes IP-layer endpoints:

```ts
conn.src.ip;
conn.src.port;
conn.dst.ip;
conn.dst.port;
```

Endpoint helpers classify address ranges without relying on DNS, TLS, or HTTP:

```ts
conn.dst.isLoopback();
conn.dst.isPrivate();
conn.dst.isLinkLocal();
conn.dst.isMulticast();
conn.dst.isBroadcast();
conn.dst.isDocumentation();
conn.dst.isReserved();
conn.dst.isPublicInternet();
```

Transport and protocol helpers:

```ts
conn.accept();                  // accept raw TCP or UDP transport
conn.matchDns();                // DNS over UDP or TCP
conn.matchTcp("203.0.113.10:5432");
conn.matchUdp("203.0.113.10:8125");
conn.matchHttp("api.example.com");
```

`conn.matchDns()` normalizes DNS over UDP and TCP. The guest is configured to
use Sandbox's internal resolver; policy code decides whether to accept that DNS
flow and can choose explicit upstream resolvers in `accept(...)`. Accepted DNS
answers are cached as trusted, guest-scoped hostname metadata for later
connection policy decisions. Sandbox may retain this attribution metadata for a
bounded window after a short DNS TTL so delayed connections can still be tied
back to the accepted DNS answer that produced their destination IP.

```ts
const dns = conn.matchDns();
if (dns) {
  dns.accept({ resolvers: ["1.1.1.1", "8.8.8.8"] });
}
```

`conn.matchHttp(...)` acquires an HTTP capability from trusted destination
metadata, including hostnames observed from accepted DNS answers. It does not
inspect or trust the HTTP `Host` header. IP-addressed HTTP requests can still be
accepted through lower-level policy, but they do not advertise a trusted
hostname. Calling `accept()` without middleware authorizes the matched flow
without rewriting bytes; pass middleware only when Sandbox should inspect and
mutate HTTP request headers.

```ts
const http = conn.matchHttp((candidate) =>
  candidate.hostname.endsWith(".example.com")
);

if (http) {
  http.accept((request) => {
    request.headers.set("x-agent-policy", "allowed");
  });
}
```

`http.accept(...)` enters Sandbox's HTTP-family enforcement path. If the matched
flow is not actually HTTP or HTTPS, it fails closed.

## Architecture Reference

Sandbox hides the kernel, init, transport, and host helper behind a TypeScript
API:

- The runtime boots a libkrun-backed microVM from a prebuilt Linux image.
- The built-in image contains the guest filesystem and common agent tooling.
- A signed `sandbox-host` helper owns the Node/Rust/libkrun boundary.
- Guest control traffic uses an fd-backed transport between the host and the
  custom Sandbox init process.
- Host-implemented virtual filesystems are mounted into the guest.
- Durable machine changes are saved below the guest filesystem layer, so callers
  can persist package installs and caches without exposing host state as a
  guest-writable POSIX filesystem.
- Network egress is default-deny and policy-controlled.
- HTTP request middleware is caller-provided JavaScript, while Sandbox owns
  interception, forwarding, and certificate plumbing.

When HTTP interception is enabled, the host generates CA material and passes
only the public CA certificate to Sandbox init. Init installs that CA using the
selected rootfs' native trust-store mechanism only when the rootfs is writable.
Read-only built-in rootfs launches keep the CA available under `/run` and do not
mutate the trust store, so HTTP interception does not change rootfs write
behavior. If a writable rootfs does not provide a supported trust-store
installer, init fails closed.

The intended boundary is:

- Sandbox owns launch, isolation, mounts, network interception, and enforcement.
- User-space owns artifact selection, filesystem durability, network policy
  state, confirmation flows, audit logs, and credential brokering.

See [docs/architecture.md](docs/architecture.md) for the design background,
[docs/kernel-build.md](docs/kernel-build.md) for kernel artifact builds, and
[docs/testing-strategy.md](docs/testing-strategy.md) for the integration and
e2e testing plan.

## Platform Notes

The npm package is published as `@torkbot/sandbox`. It does not use
post-install scripts. The root package contains the TypeScript API and declares
platform artifacts as optional dependencies:

- `@torkbot/sandbox-darwin-arm64`
- `@torkbot/sandbox-linux-x64-gnu`

Each platform package contains the `sandbox-host` helper and built-in rootfs
artifacts for that target. Runtime artifact resolution only loads the installed
optional dependency for the current platform. Local development uses the same
layout by materializing the current platform package under `node_modules`.

### macOS signing setup

For now, the macOS `sandbox-host` artifact is not Developer ID signed or
notarized. macOS users must sign the installed helper locally before launching a
VM:

```sh
npx @torkbot/sandbox setup-macos
```

This performs an ad-hoc local `codesign` with the
`com.apple.security.hypervisor` entitlement required by Hypervisor.framework. It
does not contact Apple and does not require an Apple Developer account. If a
macOS user tries to launch a VM before running setup, Sandbox throws a runtime
error that points back to this command.

## Development

Local release packaging sanity check:

```sh
npm run release:pack
```

After rebuilding local native artifacts, refresh the local optional package
layout with:

```sh
npm run artifacts:link-current
```

Repository layout:

- `src/`: TypeScript API consumed by Node.js callers.
- `crates/sandbox`: Rust host implementation for libkrun, block storage,
  network, HTTP, and VFS services.
- `crates/sandbox-host`: signed VM-host helper used for macOS HVF launch.
- `crates/sandbox-init`: custom guest init used to configure the guest before
  supervising untrusted code.
- `tests/e2e`: TypeScript e2e scenarios run directly by Node.js 24+ type
  stripping.
