# Sandbox

Run real agent work in isolated Linux VMs while your TypeScript host keeps
control of files, durable machine state, network egress, and credentials.

```ts
import {
  defineSandbox,
  fs,
  network,
  rootfs,
} from "@torkbot/sandbox";
import { image as alpine323Agent } from "@torkbot/sandbox-image-alpine-3.23-agent";

const workspace = fs.memory({
  files: {
    "/task.txt": "Summarize the current GitHub user\n",
  },
});

const machineState = new AgentMachineStore({
  bucket: "agent-machines",
  keyPrefix: "lanes/github-worker",
});

const githubTokens = new GitHubInstallationTokenService({
  installationId: 123456,
});

const sandbox = defineSandbox({
  rootfs: rootfs.cow({
    base: alpine323Agent,
    writable: machineState,
  }),
  resources: {
    cpus: 4,
    memoryMiB: 4096,
  },
  network: network.policy(async (conn) => {
    if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

    const github = conn.matchHttp("api.github.com");
    if (!github || !(await githubTokens.canServe(github))) return;

    github.accept(async (request) => {
      request.headers.set(
        "authorization",
        `Bearer ${await githubTokens.tokenForRequest(request)}`,
      );
    });
  }),
});

await using vm = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspace),
  },
  cwd: "/workspace",
});

const result = await vm.exec("sh", [
  "-lc",
  "cat task.txt && curl -fsSL https://api.github.com/user",
]);
```

The VM gets ordinary Linux tools. The host keeps the workspace, saved machine
state, network policy, and GitHub token outside the guest.

## Install

Install the core library and the image package you want to run:

```sh
npm install @torkbot/sandbox @torkbot/sandbox-image-alpine-3.23-agent
```

Base images are separate npm packages that define the Linux environment your
agent starts from. The core package owns the VM runtime, TypeScript API, and
policy hooks. Image packages own their contents and release cadence. Pin image
package versions the same way you pin any other npm dependency.

## Scenario Examples

The examples below build up from a single isolated command to durable agent
machines, host-controlled data, guest inspection, network policy, and credential
brokering.
Each example links to the API section that implements it.

### 1. Run One Command In A Clean VM

Use a pinned Linux image and a memory-backed workspace when the task should
leave no machine state behind.

Uses: [`defineSandbox`](#definesandboxoptions),
[`sandbox.boot`](#sandboxbootoptions), [`fs.memory`](#fsmemoryoptions),
[`fs.virtual`](#fsvirtualfilesystem), [`vm.exec`](#vmexeccommand-args-options).

```ts
const workspace = fs.memory({
  files: {
    "/prompt.txt": "Print the Node.js version\n",
  },
});

const sandbox = defineSandbox({
  rootfs: alpine323Agent,
});

await using vm = await sandbox.boot({
  mounts: {
    "/workspace": fs.virtual(workspace),
  },
  cwd: "/workspace",
});

const result = await vm.exec("sh", [
  "-lc",
  "cat prompt.txt && node --version",
]);

if (result.exitCode !== 0) {
  throw new Error(result.stderr);
}
```

The workload sees a normal Linux VM. The workspace is host-owned memory, mounted
into the guest only for this boot.

### 2. Give Each Agent A Durable Machine

Give an agent a saved machine when package installs, language toolchains,
cloned repos, and caches should survive across boots.

Uses: [`rootfs.cow`](#rootfscowoptions),
[`rootfs.persistent`](#rootfspersistentoptions).

```ts
const machineState = new AgentMachineStore({
  bucket: "agent-machines",
  keyPrefix: "lanes/github-worker",
});

const sandbox = defineSandbox({
  rootfs: rootfs.cow({
    base: alpine323Agent,
    writable: machineState,
  }),
});
```

`rootfs.cow(...)` lets you plug in your own storage backend for saved machine
changes. Sandbox handles the VM details; your application decides where the
agent's machine state lives.

This is powerful because Sandbox saves only the deltas the agent creates. Your
store can put those deltas anywhere with a block-storage-like API: object
storage, a database, a local cache, a tenant-scoped service, or a content
addressed backend. Agents get durable machines without the host copying or
owning a full VM image per agent.

For one local durable machine, save changes in a local file:

```ts
const sandbox = defineSandbox({
  rootfs: rootfs.persistent({
    base: alpine323Agent,
    path: "/absolute/project/.sandbox/machine-state",
  }),
});
```

Use `rootfs.ephemeral(...)` when the VM can change its machine for one boot but
all changes should be discarded:

```ts
const sandbox = defineSandbox({
  rootfs: rootfs.ephemeral({
    base: alpine323Agent,
    maxDirtyBytes: 64 * 1024 * 1024,
  }),
});
```

### 3. Mount Host-Controlled Workspaces

Use virtual filesystems when your application owns the workspace data and wants
to serve it through JavaScript callbacks.

Uses: [`fs.virtual`](#fsvirtualfilesystem), [`fs.bind`](#fsbindoptions),
[`sandbox.boot`](#sandboxbootoptions).

```ts
const taskFiles = fs.memory({
  files: {
    "/README.md": "# Task\n",
    "/src/input.json": JSON.stringify({ repo: "torkbot/sandbox" }),
  },
});

await using vm = await sandbox.boot({
  hostname: "agent-42",
  mounts: {
    "/workspace": fs.virtual(taskFiles),
  },
  cwd: "/workspace",
});
```

Use `fs.bind(...)` when the VM should see an existing host directory. The host
path and access mode are explicit:

```ts
await using vm = await sandbox.boot({
  mounts: {
    "/workspace": fs.bind({
      source: "/Users/alice/project",
      access: "ro",
      mask: {
        paths: ["/.git", "/node_modules"],
      },
    }),
  },
  cwd: "/workspace",
});
```

Writable bind mounts require writable mask storage for masked paths:

```ts
const maskStorage = fs.bind({
  source: "/tmp/sandbox-mask-storage/project",
  access: "rw",
});

const workspace = fs.bind({
  source: "/Users/alice/project",
  access: "rw",
  mask: {
    paths: ["/node_modules"],
    storage: maskStorage,
  },
});
```

### 4. Inspect And Mutate The Running Guest

Use `vm.fs` when the host needs to inspect outputs, create inputs, or publish
files after boot. This API sees the running machine filesystem, including
mounted workspaces.

Uses: [`vm.fs`](#vmfs).

```ts
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

`readDir(...)` returns entry names, raw entry-name bytes, and metadata together,
so callers do not need one `stat(...)` call per entry.

### 5. Run Long-Lived And Interactive Tools

Use `exec(...)` for buffered commands, `spawn(...)` for streaming processes, and
`pty(...)` for shells, REPLs, pagers, and terminal UIs.

Uses: [`vm.exec`](#vmexeccommand-args-options),
[`vm.spawn`](#vmspawncommand-args-options), [`vm.pty`](#vmptycommand-args-options).

```ts
const result = await vm.exec("npm", ["test"], {
  cwd: "/workspace",
  env: { CI: "1" },
  timeoutMs: 120_000,
  signal: abortController.signal,
});
```

```ts
import { Writable } from "node:stream";

const child = vm.spawn("npm", ["test"], {
  cwd: "/workspace",
});

child.stdout.pipeTo(Writable.toWeb(process.stdout));
child.stderr.pipeTo(Writable.toWeb(process.stderr));

const { exitCode } = await child.exit;
```

```ts
import { Readable, Writable } from "node:stream";

const shell = vm.pty("/bin/sh", ["-i"], {
  cwd: "/workspace",
  env: { TERM: "xterm-256color" },
  size: { rows: 40, cols: 120 },
});

Readable.toWeb(process.stdin).pipeTo(shell.input);
shell.output.pipeTo(Writable.toWeb(process.stdout));
```

### 6. Enforce Default-Deny Network Egress

Networking is blocked unless the policy callback creates a grant.

Uses: [`network.policy`](#networkpolicyonconnectionrequest),
[`conn.matchDns`](#connmatchdns), [`conn.matchHttp`](#connmatchhttpmatcher),
[`conn.accept`](#connaccept).

```ts
const sandbox = defineSandbox({
  rootfs: alpine323Agent,
  network: network.policy((conn) => {
    if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

    conn.matchHttp("api.example.com")?.accept();
  }),
});
```

Use raw transport grants for protocol-independent reachability:

```ts
const sandbox = defineSandbox({
  rootfs: alpine323Agent,
  network: network.policy((conn) => {
    if (conn.dst.isLoopback()) {
      conn.accept();
      return;
    }

    if (conn.matchTcp("203.0.113.10:5432")?.accept()) return;
  }),
});
```

HTTP matching is based on trusted destination metadata, not on the guest-sent
HTTP `Host` header.

### 7. Broker Credentials From The Host

Keep credentials in the host process. Let the VM run ordinary tools, but attach
authorization only to the upstream request after Sandbox has matched the flow.

Uses: [`HttpConnectionMatch.accept`](#httpconnectionmatchacceptmiddleware),
[`SandboxHttpRequest`](#sandboxhttprequest).

```ts
const githubTokens = new GitHubInstallationTokenService({
  installationId: 123456,
});

const sandbox = defineSandbox({
  rootfs: rootfs.cow({
    base: alpine323Agent,
    writable: writableRootfs,
  }),
  network: network.policy(async (conn) => {
    if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

    const github = conn.matchHttp("api.github.com");
    if (!github) return;

    if (!(await githubTokens.canServe(github))) return;

    github.accept(async (request) => {
      request.headers.set(
        "authorization",
        `Bearer ${await githubTokens.tokenForRequest(request)}`,
      );
    });
  }),
});
```

The guest never receives the token through environment variables, mounted files,
or rewritten guest-visible request bytes.

### 8. Snapshot A Configured Machine

Use `rootfs.compose(...)`, `rootfs.flatten(...)`, and `rootfs.bytes(...)` when
saved machine state should become a portable image you can upload, archive, or
reuse later.

Uses: [`rootfs.compose`](#rootfscomposeoptions),
[`rootfs.flatten`](#rootfsflattenoptions), [`rootfs.bytes`](#rootfsbytesimage-options).

```ts
const source = rootfs.compose({
  base: alpine323Agent,
  overlay: machineState,
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

Most applications can keep using `rootfs.cow(...)` or `rootfs.persistent(...)`.
This export path is for systems that need to turn a configured machine into a
portable image.

## Public API

This section documents the public API in the same order as the scenario
examples above.

### `defineSandbox(options)`

Used in: [Run one command](#1-run-one-command-in-a-clean-vm),
[durable machines](#2-give-each-agent-a-durable-machine),
[network policy](#6-enforce-default-deny-network-egress).

```ts
const sandbox = defineSandbox({
  rootfs: alpine323Agent,
  resources: {
    cpus: 4,
    memoryMiB: 4096,
  },
  network: network.policy((conn) => {
    conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] });
  }),
});
```

`defineSandbox(...)` validates reusable VM configuration. It does not start a
VM. `rootfs` is required. `resources` and `network` are optional.

Use `environmentFacts()` on a definition to recover facts known from
configuration without launching a VM:

```ts
const facts = sandbox.environmentFacts();
```

### `sandbox.boot(options)`

Used in: [Run one command](#1-run-one-command-in-a-clean-vm),
[mount host-controlled workspaces](#3-mount-host-controlled-workspaces).

```ts
await using vm = await sandbox.boot({
  hostname: "agent-42",
  mounts: {
    "/workspace": fs.virtual(workspaceFs),
  },
  cwd: "/workspace",
});
```

Boot options are per instance. The same sandbox definition can be booted with
different mounts, hostnames, and working directories.

`mounts` is a record keyed by absolute guest paths. `cwd`, when supplied, is the
default working directory for later process calls. `hostname` configures the
guest hostname for that boot. Omit it to use `sandbox`.

### `rootfs.image(input)`

Used in: [Install](#install), [machine state options](#2-give-each-agent-a-durable-machine).

```ts
rootfs.image({
  name: "alpine:3.23-agent",
  path: "/absolute/path/to/alpine-3.23-agent.qcow2",
  format: "qcow2",
  architecture: process.arch,
  digest: "sha256:<64 lowercase hex characters>",
  sizeBytes: 167772160n,
  facts: [
    {
      source: "config",
      topic: "rootfs-image",
      relation: "is",
      value: "alpine:3.23-agent",
    },
  ],
});
```

Describes the read-only Linux environment a VM starts from. All fields are
required. Sandbox does not accept moving aliases such as `latest`, `stable`,
`current`, or `lts`, and it does not pull or build images during `boot()`.

Most applications should import an image package rather than construct this
descriptor by hand:

```ts
import { image as alpine323Agent } from "@torkbot/sandbox-image-alpine-3.23-agent";
```

### `rootfs.ephemeral(options)`

Used in: [Durable machines](#2-give-each-agent-a-durable-machine).

```ts
rootfs.ephemeral({
  base: alpine323Agent,
  maxDirtyBytes: 64 * 1024 * 1024,
});
```

Gives the VM writable machine state for one boot. Changes are held in memory
and discarded when the VM exits. `base` is required. `maxDirtyBytes` is optional
and defaults to 64 MiB.

### `rootfs.cow(options)`

Used in: [Durable machines](#2-give-each-agent-a-durable-machine),
[snapshot a configured machine](#8-snapshot-a-configured-machine).

```ts
rootfs.cow({
  base: alpine323Agent,
  writable: blockStore,
  maxDirtyBytes: 64 * 1024 * 1024,
});
```

Creates a VM whose machine changes are saved through caller-owned storage. The
starting image remains read-only. You can also pass a pre-composed source:

```ts
const source = rootfs.compose({
  base: alpine323Agent,
  overlay: blockStore,
});

rootfs.cow({ source });
```

Attach one writable state store to at most one running VM at a time, or enforce
single-writer coordination in your storage layer.

### `rootfs.persistent(options)`

Used in: [Durable machines](#2-give-each-agent-a-durable-machine).

```ts
rootfs.persistent({
  base: alpine323Agent,
  path: "/absolute/project/.sandbox/machine-state",
});
```

Creates or reuses one local file for durable machine state. `path` is required
and must be absolute. The starting image stays read-only and can be shared by
many VMs; the selected state file is locked for the VM lifetime on filesystems
that honor advisory locks.

Keep the state file outside guest-writable host-directory mounts, or hide the
containing directory with a host-directory mask such as `"/.sandbox"`.

### `rootfs.compose(options)`

Used in: [Snapshot a configured machine](#8-snapshot-a-configured-machine).

```ts
const source = rootfs.compose({
  base: alpine323Agent,
  overlay: blockStore,
});
```

Pairs a starting image with saved machine changes. `rootfs.cow(...)` and
`rootfs.flatten(...)` both understand this composed source.

### `rootfs.flatten(options)`

Used in: [Snapshot a configured machine](#8-snapshot-a-configured-machine).

```ts
const image = await rootfs.flatten({
  format: "qcow2",
  source,
  dest: imageStore,
  clusterSize: 65536,
});
```

Writes a standalone machine image into `dest`. `source` is either a rootfs image
or a composed rootfs source. `dest` is a writable `SandboxBlockStore`. The
current output format is `qcow2`.

### `rootfs.bytes(image, options)`

Used in: [Snapshot a configured machine](#8-snapshot-a-configured-machine).

```ts
for await (const chunk of rootfs.bytes(image, { chunkSize: 1024 * 1024 })) {
  await upload(chunk);
}
```

Streams image bytes for a rootfs image descriptor or a flattened image. It does
not stream the filesystem contents inside the image.

### `SandboxBlockStore`

Used in: [Durable machines](#2-give-each-agent-a-durable-machine),
[snapshot a configured machine](#8-snapshot-a-configured-machine).

`SandboxBlockStore` is the advanced extension point behind caller-owned machine
state. Sandbox stores only the changes made by the VM. Implement this interface
when you want those deltas in object storage, a database, a cache, or another
service instead of a local file.

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

The `context.base` value identifies the starting image or generated image being
read or written. Storage layers can use it to namespace deltas, reject
mismatched snapshots, or migrate state.

`write()` receives block bytes owned by the block store. Sandbox will not
mutate those `Uint8Array` values after passing them to `write()`, so stores may
retain them for delayed persistence.

### `fs.memory(options)`

Used in: [Run one command](#1-run-one-command-in-a-clean-vm),
[mount host-controlled workspaces](#3-mount-host-controlled-workspaces).

```ts
const workspace = fs.memory({
  files: {
    "/README.md": "# Task\n",
  },
});
```

Creates an in-memory POSIX filesystem.

### `fs.virtual(fileSystem)`

Used in: [Run one command](#1-run-one-command-in-a-clean-vm),
[mount host-controlled workspaces](#3-mount-host-controlled-workspaces).

```ts
const mount = fs.virtual(workspace);
```

Adapts a compatible JavaScript filesystem for guest mounting. Virtual mounts
are host-implemented filesystems, not host path passthrough.

### `fs.bind(options)`

Used in: [Mount host-controlled workspaces](#3-mount-host-controlled-workspaces).

```ts
fs.bind({
  source: "/Users/alice/project",
  access: "ro",
  mask: {
    paths: ["/.git", "/node_modules"],
  },
});
```

Mounts an absolute host directory through native virtio-fs. `source` and
`access` are required. `access` must be `"ro"` or `"rw"`.

`mask.paths` are absolute paths inside the bound directory. In read-only bind
mounts, masked paths are absent. In writable bind mounts, masked paths require
`mask.storage`, and guest-created entries under those paths are stored in the
mask storage directory instead of the original host directory.

### `vm.exec(command, args, options)`

Used in: [Run one command](#1-run-one-command-in-a-clean-vm),
[long-lived and interactive tools](#5-run-long-lived-and-interactive-tools).

```ts
const result = await vm.exec("npm", ["test"], {
  cwd: "/workspace",
  env: { CI: "1" },
  timeoutMs: 120_000,
  signal: abortController.signal,
});
```

Runs a buffered process and returns `{ exitCode, stdout, stderr }`. When
`timeoutMs` expires, Sandbox terminates the guest process group and returns exit
code `124`. When `signal` aborts, Sandbox terminates that process group,
rejects the promise with an `AbortError`, and keeps the VM usable.

### `vm.spawn(command, args, options)`

Used in: [Long-lived and interactive tools](#5-run-long-lived-and-interactive-tools).

```ts
const child = vm.spawn("npm", ["test"], {
  cwd: "/workspace",
});
```

Returns a streaming process handle with `stdin`, `stdout`, `stderr`, `ready`,
`exit`, and `kill(...)`.

### `vm.pty(command, args, options)`

Used in: [Long-lived and interactive tools](#5-run-long-lived-and-interactive-tools).

```ts
const shell = vm.pty("/bin/sh", ["-i"], {
  cwd: "/workspace",
  env: { TERM: "xterm-256color" },
  size: { rows: 40, cols: 120 },
});
```

Runs a process attached to a real guest terminal. Use this for shells, REPLs,
pagers, and terminal UIs. The handle exposes `input`, `output`, `ready`, `exit`,
`resize(...)`, and `kill(...)`.

### `vm.fs`

Used in: [Inspect and mutate the running guest](#4-inspect-and-mutate-the-running-guest).

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

Paths are absolute guest paths. `stat(...)` reports the directory entry itself,
including symlinks. `readFile(...)` reads the whole file unless a range with
required `offset` and `length` is supplied. `writeFile(...)` creates or
truncates the target file. `rename(...)` is a single guest rename operation and
does not create missing parent directories.

### `network.policy(onConnectionRequest)`

Used in: [Default-deny network egress](#6-enforce-default-deny-network-egress),
[credential brokering](#7-broker-credentials-from-the-host).

```ts
const policy = network.policy(async (conn) => {
  if (conn.matchDns()?.accept({ resolvers: ["1.1.1.1"] })) return;

  const api = conn.matchHttp("api.example.com");
  if (!api) return;

  api.accept((request) => {
    request.headers.set("x-agent-policy", "allowed");
  });
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

conn.dst.isLoopback();
conn.dst.isPrivate();
conn.dst.isLinkLocal();
conn.dst.isMulticast();
conn.dst.isBroadcast();
conn.dst.isDocumentation();
conn.dst.isReserved();
conn.dst.isPublicInternet();
```

### `conn.accept()`

Used in: [Default-deny network egress](#6-enforce-default-deny-network-egress).

Accepts the observed raw TCP or UDP flow without protocol-specific handling.

### `conn.matchDns()`

Used in: [Default-deny network egress](#6-enforce-default-deny-network-egress),
[credential brokering](#7-broker-credentials-from-the-host).

```ts
const dns = conn.matchDns();
if (dns) {
  dns.accept({ resolvers: ["1.1.1.1", "8.8.8.8"] });
}
```

Normalizes DNS over UDP and TCP. Accepted DNS answers become trusted,
guest-scoped hostname metadata for later connection policy decisions.

### `conn.matchTcp(matcher)` And `conn.matchUdp(matcher)`

Used in: [Default-deny network egress](#6-enforce-default-deny-network-egress).

```ts
conn.matchTcp("203.0.113.10:5432")?.accept();
conn.matchUdp({ ip: "203.0.113.10", port: 8125 })?.accept();
```

Matches raw transport destinations by endpoint string, endpoint object, or
predicate callback.

### `conn.matchHttp(matcher)`

Used in: [Default-deny network egress](#6-enforce-default-deny-network-egress),
[credential brokering](#7-broker-credentials-from-the-host).

```ts
const http = conn.matchHttp((candidate) =>
  candidate.hostname.endsWith(".example.com")
);
```

Returns an HTTP capability when trusted destination metadata matches. This does
not trust the HTTP `Host` header. IP-addressed HTTP requests can be allowed by
lower-level policy, but they do not advertise a trusted hostname.

### `HttpConnectionMatch.accept(middleware)`

Used in: [Credential brokering](#7-broker-credentials-from-the-host).

```ts
http.accept((request) => {
  request.headers.set("authorization", `Bearer ${token}`);
});
```

Enters Sandbox's HTTP-family enforcement path. If the matched flow is not
actually HTTP or HTTPS, it fails closed. Omit `middleware` to authorize the
matched HTTP-family flow without mutating request headers.

### `SandboxHttpRequest`

Used in: [Credential brokering](#7-broker-credentials-from-the-host).

Middleware receives request metadata reconstructed by Sandbox:

```ts
request.protocol;        // "http/1.1" or "h2"
request.url;             // URL
request.method;          // exact guest method
request.headers;         // mutable upstream request headers
request.destination;     // source IP/port, original IP/port, hostname
request.tls?.sni;
request.tls?.alpn;
```

Header mutations apply only to the upstream host-side request. Sandbox does not
write injected credentials back into guest-visible request bytes.

### Environment Facts

Used in: [Install](#install), [`defineSandbox`](#definesandboxoptions).

```ts
const configFacts = sandbox.environmentFacts();

await using vm = await sandbox.boot();
const observedFacts = await vm.environmentFacts();
```

Facts are affirmative typed triples with required provenance:

```ts
type SandboxEnvironmentFact = {
  source: "config" | "guest";
  topic: string;
  relation: string;
  value: string;
};
```

Image descriptors provide config-sourced facts such as
`rootfs-image is alpine:3.23-agent`, `distro is alpine`,
`distro-version is 3.23`, `package-manager is apk`, `shell is /bin/sh`, and
`command exists ...` entries for commands the image package advertises.
Sandbox adds rootfs write-mode and network-egress facts from the sandbox
definition. Booted instances add guest-observed facts.

## Images And Packaging

Core Sandbox releases and image releases are independent.

The `@torkbot/sandbox` package contains:

- TypeScript API,
- `sandbox-host` platform artifact as an optional dependency,
- custom kernel and initrd owned by the core library.

Image packages contain:

- one pinned Linux machine image per supported CPU architecture,
- image facts,
- an exported `image` descriptor created with `rootfs.image(...)`.

Image package versions use the npm prerelease section for image content:

```text
0.1.0-image.20260623T142355Z.sha9c4f2a1b3c4d
```

The `0.1.0` prefix is the JavaScript export compatibility profile. The
timestamp sorts releases in maintainer-facing lists. The short `sha...` suffix
correlates with the full release digest recorded in GitHub release metadata.

Applications import and pin image packages explicitly.

## Implementation And Security Model

Sandbox's security boundary is a Linux microVM plus a small set of
host-mediated services. The host application decides what to attach and what to
grant.

### Runtime Architecture

- `@torkbot/sandbox` starts a signed `sandbox-host` helper process.
- `sandbox-host` owns the Rust/libkrun integration and opens the VM.
- The core package embeds the kernel and initrd.
- The initrd starts `sandbox-init` as stage 0.
- Stage 0 mounts the selected machine image and execs the same binary as stage 1.
- Stage 1 configures the guest, mounts requested filesystems, sets up control,
  reports readiness, and supervises workloads.

The Node process stays the ergonomic TypeScript API. VM launch and native
resources live in the helper process, which is important for macOS Hypervisor
entitlements and for bounding VM lifetime.

### Filesystem Boundary

Machine images are read-only by default. Writable machine state is explicit:

- `rootfs.ephemeral(...)` stores changes in memory for one boot,
- `rootfs.cow(...)` stores agent-made deltas in caller-owned storage,
- `rootfs.persistent(...)` stores agent-made deltas in one local state file.

Host workspaces are separate mounts. `fs.virtual(...)` is host-implemented.
`fs.bind(...)` is host-directory passthrough with explicit `"ro"` or `"rw"`
access. Keep durable machine state outside guest-writable host mounts.

### Network Boundary

Network egress is default-deny. A policy callback must grant each observed
flow. HTTP middleware does not grant reachability by itself; reachability comes
from the accepted connection capability.

For HTTP and HTTPS, Sandbox binds request handling to trusted connection
metadata such as original destination, accepted DNS answers, TLS SNI, and the
matched authority. The HTTP `Host` header is not trusted for policy decisions.

### Credential Boundary

Credentials should stay in host-controlled TypeScript. HTTP middleware can add
headers to the upstream request after Sandbox has matched and accepted the
flow. Injected credentials are not written into the guest filesystem,
environment, or guest-visible request bytes.

### CA And HTTPS Interception

When HTTP interception needs a guest-trusted CA, the host generates CA material
and gives init only the public CA certificate. Init installs it through the
selected image's native trust-store mechanism only when the machine is writable.
If no supported installer exists, init fails closed.

### Platform Packaging

The root package has no post-install scripts. It resolves the current platform
helper through optional dependencies:

- `@torkbot/sandbox-darwin-arm64`
- `@torkbot/sandbox-linux-x64-gnu`

### macOS Signing Setup

For now, the macOS `sandbox-host` artifact may need local signing before launch:

```sh
npx @torkbot/sandbox setup-macos
```

This performs an ad-hoc local `codesign` with the
`com.apple.security.hypervisor` entitlement required by Hypervisor.framework.
It does not contact Apple and does not require an Apple Developer account.

## Development

```sh
npm run typecheck
npm run test:unit
npm run test:artifact
```

Local release packaging sanity check:

```sh
npm run release:pack
```

After rebuilding local native artifacts, refresh the local optional package
layout:

```sh
npm run artifacts:link-current
```

Repository layout:

- `src/`: TypeScript API consumed by Node.js callers.
- `crates/sandbox`: Rust host implementation for libkrun, block storage,
  network, HTTP, and VFS services.
- `crates/sandbox-host`: VM-host helper used for native launch.
- `crates/sandbox-init`: custom guest init.
- `images/`: source definitions for separately released rootfs image packages.
- `tests/e2e`: TypeScript e2e scenarios run directly by Node.js 24+ type
  stripping.

Design background:

- [docs/architecture.md](docs/architecture.md)
- [docs/kernel-build.md](docs/kernel-build.md)
- [docs/testing-strategy.md](docs/testing-strategy.md)
