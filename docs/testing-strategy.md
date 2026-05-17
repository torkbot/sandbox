# Testing Strategy

## Goal

Sandbox needs integration-style tests that objectively prove the runtime properties we care about: a statically linked host artifact can boot a libkrun microVM, configure a guest with our init, enforce host-side policy, intercept HTTP, mount immutable and writable filesystems, and provide a reliable host/guest control channel.

The test suite should produce artifacts that are easy to inspect after failure: host logs, guest console logs, control-channel transcripts, proxy traces, filesystem snapshots, and platform-link/signing reports.

## Test Tiers

### Tier 0: Build And Static Artifact Checks

Runs on every developer machine.

Evidence:

- `cargo check --workspace` passes.
- the host binary or native module links without `libkrun` or `libkrunfw` dynamic dependencies.
- the guest init binary is statically linked.
- packaged kernel/initramfs/rootfs artifacts are content-addressed and reproducible from the same build-time inputs.
- `deps/libkrunfw` can build the patched Linux kernel artifacts through the Docker-based build entrypoint.

Platform checks:

- Linux: use `ldd`, `readelf`, or `objdump` to reject unexpected dynamic dependencies.
- macOS: use `otool -L` to reject unexpected dynamic dependencies and `codesign -dv --entitlements :-` to verify HVF entitlements on the final executable.

### Tier 1: Host-Only Service Simulation

Runs without a hypervisor.

Evidence:

- HTTP policy hooks receive normalized request metadata and can allow, deny, and rewrite headers.
- protected network ranges are blocked before forwarding.
- virtual filesystem callbacks are deterministic and return expected metadata, directory entries, and file contents.
- mounted filesystems are inspectable from JavaScript with the same `stat` / `list` / `read` shape exposed to the host runtime.
- the `Transport` adapter preserves message order, close behavior, and backpressure.

These tests should use fake packet/filesystem/control clients so policy semantics are stable even when libkrun is not available.

### Tier 2: Single-VM Smoke Test

Runs only when the host supports KVM or HVF and the signing/build prerequisites are present.

Fixture:

- prebuilt rootfs fixture produced before the VM test starts.
- guest init from `crates/sandbox-init`.
- host control socket connected over vsock.

Evidence:

- guest boots and sends `init.ready` over the control transport.
- host sends a command and receives an acknowledged response.
- guest sees the expected kernel command line and mounted root.
- guest shutdown is clean and host observes the exit status.
- no required C `init.krun` stage remains once the libkrun fork supports direct Rust init injection.

### Tier 3: Filesystem E2E

Runs with a real VM.

Fixture:

- immutable read-only root, initially from extracted Docker rootfs and eventually from EROFS.
- virtual procfs-like mount implemented by host callbacks.

Evidence:

- guest cannot write to the root mount.
- guest can read host-generated virtual files and directories.
- writable virtual filesystem behavior is covered through generic host filesystem hooks once that mode lands.
- virtual files show host-generated contents and directory metadata.
- JavaScript can inspect mounted virtual filesystems through stable mount handles without entering the guest.

### Tier 3b: Rootfs Shaping E2E

Runs with a real VM in an explicit writable-overlay mode.

Evidence:

- immutable root mode remains the default.
- writable-overlay mode allows incremental guest operations to modify root contents.
- `vm.rootfs.snapshot({ format: "erofs" })` produces EROFS artifact bytes.
- the snapshot report includes a stable digest.
- a subsequent VM can boot from the produced artifact as a read-only root.

### Tier 4: Network And HTTP Policy E2E

Runs with a real VM and host proxy.

Fixture:

- guest CA trust injected by init.
- guest HTTP client and HTTPS client.
- host test origin server.
- blocked host/private-range endpoints.

Evidence:

- HTTPS request succeeds only through the host interception layer.
- Node.js policy sees method, URL, destination IP, headers, and TLS metadata.
- allowed requests reach the test origin with expected header rewrites.
- denied requests fail with a deterministic guest-visible error.
- requests to protected host, loopback, link-local, and configured private ranges are blocked.
- DNS policy is observable in the proxy trace.

### Tier 5: libkrun Fork Contract Tests

Runs against `deps/libkrun` or the pinned submodule.

Evidence:

- static Rust integration builds without binding to the C API.
- the Node module uses the `napi-rs` boundary for native hand-off rather than shelling out or passing large data through ad hoc subprocess protocols.
- networking does not require a sidecar daemon; any required network component is native to the static artifact or explicitly fails the contract test.
- fd-taking variants work for sockets owned by the Sandbox host runtime.
- path-taking variants still work where they are intentionally used for external processes.
- any vhost-user filesystem patch is covered by a booting VM test.

### Tier 6: macOS HVF Packaging Test

Runs on macOS only.

Evidence:

- the `sandbox-host` executable that opens Hypervisor.framework is signed.
- the signature contains the HVF entitlement.
- a smoke VM boots through the signed helper artifact.
- unsigned Node is not treated as an acceptable HVF host process.

## Test Harness Shape

Use a TypeScript e2e runner as the orchestration layer because the public library is Node-facing and policy hooks are TypeScript. Run it directly on Node.js 24+ using the built-in type-stripping support, matching the neighboring TorkBot repositories. The runner should call the signed `sandbox-host` binary for VM launch on macOS, and may use native bindings for host-only primitives or platforms where the embedding process is allowed to own the hypervisor. It should collect structured evidence into `test-results/e2e/<run-id>/`.

Each e2e test should emit:

- `manifest.json`: host platform, git commit, artifact hashes, selected test fixture, and capability checks.
- `host.log`: host runtime logs.
- `guest-console.log`: guest console output.
- `control.jsonl`: host/guest control-channel transcript.
- `proxy.jsonl`: HTTP proxy observations and decisions.
- `fs.json`: filesystem assertions and database state summaries.
- `linkage.json`: static-link and signing verification.

## Capability Detection

The runner should skip, not fail, tests whose host prerequisites are absent. It must still fail if a prerequisite is present but the runtime cannot use it.

Detected capabilities:

- Docker or compatible CLI for build-time rootfs fixture generation.
- Docker or compatible CLI for build-time kernel fixture generation.
- Linux KVM access.
- macOS HVF access.
- macOS codesign availability and entitlement verification.
- EROFS image generation through the Docker-based `build:rootfs:erofs` fixture.

## Success Criteria By Project Goal

- Spawn microVMs from Node.js: Node e2e creates a VM, receives readiness, sends commands, and shuts down cleanly.
- Custom init: the Rust guest init from this repository performs setup, reports readiness, and supervises a test workload. Any libkrun-provided init stage is a temporary bridge and should be removed from the passing target suite once direct Rust init injection lands.
- Static linking: linkage report shows no dynamic `libkrun` or `libkrunfw` dependency.
- Immutable root: root hash remains stable and guest root writes fail.
- Rootfs shaping: explicit writable-overlay mode can capture deltas and publish a new EROFS rootfs artifact.
- Virtual filesystem: guest reads host-generated files and metadata through a mounted virtual tree.
- HTTP interception: TLS traffic is intercepted with guest-trusted CA, policy hooks run in Node.js, headers are modified, and forwarding is transparent.
- Network policy: protected host and private ranges are blocked with deterministic evidence.
- Host/guest transport: bidirectional messages preserve ordering, errors, and close semantics.
- macOS support: HVF entitlement signing is verified on `sandbox-host` and VM boot goes through that signed helper, not through a signed copy of Node.

## First Implementation Slice

1. Add the e2e runner with capability detection and result-directory creation.
2. Add host-only tests for `Transport`, HTTP policy, and virtual filesystem behavior.
3. Add build-time Docker export/extract rootfs fixture generation.
4. Add the first boot smoke test with guest `init.ready`.
5. Add static-link and macOS entitlement checks as soon as a host artifact exists.

## Initial Scenario Files

The first executable scenario files live under `tests/e2e/scenarios/` as `.test.ts` files. They intentionally describe the desired Node.js developer experience before the implementation exists:

- `boot-smoke.test.ts`: boots a VM, waits for `init.ready`, sends a control command, and checks command output.
- `filesystem.test.ts`: boots with an immutable root and host-backed virtual filesystem using the same `stat` / `list` / `read` shape as TorkBot plugin filesystems.
- `rootfs-shaping.test.ts`: opts into writable root overlay mode, runs incremental guest commands, and snapshots the result as an EROFS artifact.
- `http-policy.test.ts`: injects CA trust, intercepts HTTPS, runs Node policy hooks, rewrites headers, and blocks protected destinations.
- `linkage-and-signing.test.ts`: verifies static linkage, absence of dynamic libkrun/libkrunfw dependencies, and macOS HVF entitlement signing.

These tests are expected to fail until the runtime exists. A failing test is useful when the failure points at the next missing runtime boundary; a passing placeholder is not.
