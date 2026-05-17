# E2E Coverage Matrix

This matrix is the implementation backlog for confidence-building e2e tests. It is MECE by subsystem: each row belongs to one primary capability, and together the rows cover the production-ready Sandbox primitive currently in scope.

Statuses:

- `passing`: required e2e exists and passes.
- `skipped`: e2e exists but is intentionally skipped until the implementation slice lands.
- `todo`: e2e should be authored.
- `blocked`: e2e depends on an upstream/fork/platform decision.

## VM Lifecycle And Control

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `vm.boot.ready` | Boot a VM from Node.js and receive readiness | Spawn a VM, wait for `init.ready`, assert root/init metadata | `boot-smoke.test.ts` | passing |
| `vm.control.exec-basic` | Execute a guest command over host control | Run `/bin/uname -a`, assert exit code/stdout | `boot-smoke.test.ts` | passing |
| `vm.control.env` | Pass explicit environment to a guest command | Run shell command that prints a host-supplied env var | not authored | todo |
| `vm.control.stderr-exit` | Preserve stderr and non-zero exit status | Run command that writes stderr and exits non-zero | not authored | todo |
| `vm.control.large-output` | Preserve larger stdout/stderr payloads | Run command emitting multi-64KB stdout and stderr | not authored | todo |
| `vm.control.concurrent-exec` | Support multiple in-flight exec commands | Start several execs and verify matching completion IDs | not authored | todo |
| `vm.close.releases` | Close terminates VM resources and rejects later operations | Close VM, then assert `exec` and mount operations fail deterministically | not authored | todo |

## Guest Init And Runtime Setup

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `init.identity` | Repo-owned init is the setup boundary | Assert `init.ready.guest.init.name === "sandbox-init"` | `boot-smoke.test.ts` | passing |
| `init.ca` | CA material is installed before workload commands run | Assert `$SSL_CERT_FILE` points to `/run/sandbox/http-ca.pem` and contents match host CA | `http-policy.test.ts` | passing |
| `init.network` | Guest network is configured before readiness | Assert `eth0`, `10.0.2.2/24`, default route via `10.0.2.1` | `network.test.ts` | passing |
| `init.mounts-before-ready` | Configured mounts are ready before commands run | Boot with virtual mount, immediately read from guest after `init.ready` | `filesystem.test.ts` | passing |
| `init.direct-rust` | Boot without libkrun's legacy stage-1 init | Assert final direct-init boot path and no stage-1 dependency | not authored | blocked |

## Filesystems

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `fs.root.immutable` | Root filesystem is read-only in normal mode | Attempt root write and assert failure | `filesystem.test.ts` | passing |
| `fs.virtual.read` | Host JS callbacks back stat/list/read | Guest reads host-generated file; JS reads same mount handle | `filesystem.test.ts` | passing |
| `fs.virtual.writable` | Host JS callbacks back create/write/truncate | Guest creates, overwrites, truncates; JS verifies final state | `filesystem.test.ts` | passing |
| `fs.virtual.range-read` | Guest partial reads map to host range reads | Guest reads slices from a larger virtual file; host records requested offsets | not authored | todo |
| `fs.virtual.errors` | Missing path/callback failures surface deterministically | Guest reads missing file and write-protected file; assert errno/exit behavior | not authored | todo |
| `fs.virtual.metadata` | File type, size, and writable bits are reflected accurately | Guest `stat`s directory/file and compares mode/size | not authored | todo |
| `fs.rootfs.overlay-snapshot` | Writable overlay can publish a new EROFS artifact | Run guest mutation, `vm.rootfs.snapshot({ format: "erofs" })`, boot snapshot | `rootfs-shaping.test.ts` | skipped |

## HTTP And TLS Interception

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `http.policy.allow-rewrite` | One JS policy round trip can allow and rewrite headers | HTTP request reaches origin with rewritten header | `http-policy.test.ts` | passing |
| `http.policy.deny` | JS policy deny returns deterministic guest-visible error | HTTP/HTTPS denied request returns 451 | `http-policy.test.ts` | passing |
| `http.policy.metadata` | Policy sees method, URL, destination IP, headers | Assert captured request metadata for HTTP and HTTPS | `http-policy.test.ts` | passing |
| `tls.ca-trust` | Guest trusts injected CA for intercepted HTTPS | HTTPS request succeeds without `-k` | `http-policy.test.ts` | passing |
| `tls.sni-leaf` | MITM leaf cert is generated for requested SNI hostname | `example.test` via `--connect-to` succeeds to policy | `http-policy.test.ts` | passing |
| `tls.sni-host-mismatch` | SNI and Host mismatch are visible in one policy call | URL SNI `example.test`, Host `other.test`, assert both | `http-policy.test.ts` | passing |
| `tls.pinning` | Pinned clients fail closed before policy | `curl --pinnedpubkey` fails and policy count remains zero | `http-policy.test.ts` | passing |
| `http.large-bodies` | HTTP request/response bodies exceed one TCP read/write | POST 32KB, receive 384KB | `http-policy.test.ts` | passing |
| `https.large-bodies` | HTTPS request/response bodies exceed one TLS record | POST large body over TLS and receive large response | `http-policy.test.ts` | passing |
| `http.concurrent` | Concurrent HTTP requests keep policy/response accounting | Eight concurrent HTTP curls, eight policy calls | `http-policy.test.ts` | passing |
| `https.concurrent` | Concurrent HTTPS requests keep policy/response accounting | Eight concurrent HTTPS curls, eight policy calls | `http-policy.test.ts` | passing |
| `http.keepalive` | Multiple requests on one connection are handled intentionally | Use one HTTP client connection for two requests; assert supported behavior or deterministic close | not authored | todo |
| `http.upstream-refused` | Refused upstream connection is deterministic | Policy allows request to an unroutable/refused origin; guest gets stable failure | not authored | todo |
| `http.upstream-timeout` | Slow upstream timeout is deterministic | Origin accepts but delays response past timeout; guest gets stable failure | not authored | todo |
| `http.upstream-reset` | Mid-body reset is deterministic | Origin closes mid-response; guest sees stable failure | not authored | todo |
| `tls.no-sni` | TLS clients without SNI get deterministic certificate/policy behavior | Connect by IP literal and assert documented metadata/cert behavior | not authored | todo |
| `tls.cert-cache` | Dynamic cert issuance is bounded and reused | Make repeated SNI requests and assert resolver/cache behavior via host evidence | not authored | todo |
| `http2.alpn` | HTTP/2 strategy is explicit | Attempt HTTP/2-capable client; assert downgrade, deny, or supported HTTP/2 behavior | not authored | todo |

## Network Policy

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `net.explicit-virtio` | Guest traffic exits through explicit virtio-net backend | Assert interface/route and blocked probe response | `network.test.ts` | passing |
| `net.default-protected` | Default private/link-local ranges are blocked before JS policy | Curl RFC1918/link-local addresses; assert 403 and zero policy calls | `http-policy.test.ts` | passing |
| `net.caller-protected` | Caller CIDRs extend default deny set | Configure `protectedRanges`, request that CIDR, assert 403 and zero policy calls | `http-policy.test.ts` | passing |
| `net.public-policy` | Public/non-protected destination reaches policy | Request `203.0.113.10` via transparent interception and assert policy called | `network.test.ts` and `http-policy.test.ts` | passing |
| `net.dns-observable` | DNS-dependent traffic is observable and cannot bypass policy | Guest requests hostname without `--connect-to`; assert DNS behavior and policy evidence | not authored | todo |
| `net.dns-protected` | DNS resolution to protected IP remains blocked | Host-controlled hostname resolves to private/link-local IP; assert pre-policy block | not authored | todo |
| `net.ipv6` | IPv6 behavior is explicit | Attempt IPv6 HTTP destination; assert unsupported deterministic failure or implemented policy | not authored | todo |
| `net.udp` | UDP/non-HTTP behavior is explicit | Guest UDP probe cannot silently bypass policy | not authored | todo |

## Build, Packaging, And Platform Contracts

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `artifact.no-libkrun-dylib` | Host artifact has no dynamic `libkrun` dependency | Inspect dynamic libraries | `linkage-and-signing.test.ts` | passing |
| `artifact.no-libkrunfw-dylib` | Host artifact has no dynamic `libkrunfw` dependency | Inspect dynamic libraries | `linkage-and-signing.test.ts` | passing |
| `artifact.macos-hvf-signing` | macOS helper owns HVF entitlement | Inspect helper codesign entitlements | `linkage-and-signing.test.ts` | passing on macOS |
| `artifact.node-unsigned-ok` | Node itself is not required to be signed for HVF | Assert VM boot goes through helper, not Node process | partially covered by architecture; not authored | todo |
| `artifact.kernel-explicit` | Project kernel/init artifacts are explicit inputs | Boot uses `projectKernel()` and `projectInit()` paths only | partially covered by smoke tests | todo |
| `artifact.linux-host-ci` | Linux host runs VM/control/network e2e | CI job runs core e2e on Linux host with KVM | GitHub Actions exists but matrix row not proven here | todo |
| `artifact.reproducible-rootfs` | Rootfs fixture is reproducible/content-addressed | Build rootfs fixture twice and compare digest | not authored | todo |
| `artifact.reproducible-kernel` | Kernel fixture is reproducible/content-addressed | Build kernel fixture and compare expected digest/metadata | not authored | todo |

## libkrun Fork Contracts

| ID | Capability | E2E scenario | Current coverage | Status |
| --- | --- | --- | --- | --- |
| `libkrun.static-rust` | Sandbox integrates libkrun as Rust/static dependency, not C API binding | Build/linkage contract rejects C-header/dylib path | partially covered by linkage | todo |
| `libkrun.fd-network` | Sandbox-owned sockets do not require filesystem socket paths | Boot networking/control using owned fds and assert no socket-path setup | partially covered by runtime unit tests | todo |
| `libkrun.virtiofs-traits` | VFS uses libkrun virtual filesystem traits/types | Writable VFS e2e passes through libkrun backend hooks | `filesystem.test.ts` | passing |
| `libkrun.direct-init` | Direct Rust init injection replaces stage-1 bridge | Boot without legacy init stage and assert readiness | not authored | blocked |

## Current Required Suite

The current `npm run test:e2e` suite requires the rows marked `passing` above plus the existing skipped rootfs shaping placeholder. The matrix is intentionally broader than the current required suite so new slices can be promoted by changing `todo` rows into executable `.test.ts` cases without redefining project scope.
