# E2E Roadmap

This is the roadmap for the Sandbox e2e suite. The goal is not to maintain a spreadsheet of capabilities; the goal is to grow a small set of scenario files whose test names read like the contract we need from a production sandboxing primitive.

Roadmap rule: if a behavior is listed here, it should exist as an executable e2e test. Tests for behavior we have not implemented yet should fail clearly and should never disappear into prose.

## `boot-smoke.test.ts`

This file owns VM lifecycle and the host/guest control channel. It should prove that Node can create a VM, observe readiness, execute guest work, and shut the VM down without leaking ambiguous state.

Passing:

- `Node can boot a sandbox VM and exchange control messages`
  - Covers VM creation, `init.ready`, root/init metadata, and a basic guest command.
- `guest init death is surfaced through the VM API`
  - Kills the guest init and asserts in-flight and later control operations fail deterministically.
- `guest exec receives explicit environment variables`
  - Runs a shell command that prints a host-supplied env var.
- `guest exec preserves stderr and non-zero exit status`
  - Runs a command that writes to stderr and exits with a chosen non-zero code.
- `guest exec preserves large stdout and stderr payloads`
  - Emits multi-64KB stdout/stderr and asserts exact byte counts/content.
- `guest exec supports multiple in-flight commands`
  - Starts several execs concurrently and verifies completions match request IDs.
- `closing a VM terminates resources and rejects later operations`
  - Closes the VM, then asserts later `exec` operations fail deterministically.
- `guest command lockup can be cleaned up by closing the VM`
  - Starts a non-returning guest command, closes the VM, and asserts cleanup completes without leaking the host API.
- `host process exit is surfaced through the VM API`
  - Terminates `sandbox-host` underneath an active VM and asserts the next host operation rejects with an idiomatic closed/crashed error.
- `guest OOM is surfaced through the VM API`
  - Trigger an intentional guest OOM and assert the host observes VM failure deterministically.

Failing:

- No remaining known failures in this scenario file.

## `filesystem.test.ts`

This file owns filesystem behavior. The tests are split by boundary: guest-visible mount behavior, host-side JavaScript tools over mounted filesystems, mount ordering, and cleanup/error behavior. Durable storage engines are intentionally out of scope here; they should be built above the generic virtual filesystem hooks.

Passing:

- `virtual filesystem mounts are backed by host JavaScript callbacks`
  - Covers the read-only callback ABI: `stat`, `list`, `read`, guest reads, and raw JS mount handles.
- `writable virtual filesystem mounts persist guest mutations through host callbacks`
  - Covers guest-originated create, write, overwrite, truncate, and JS inspection through `vm.mounts.get()`.
- `host filesystem tools read complete files and line ranges through JavaScript`
  - Covers the coding-agent `read` primitive from the host side, including 1-indexed line windows.
- `host filesystem tools write complete files through JavaScript`
  - Covers the coding-agent `write` primitive as complete-file replacement/creation through the host API.
- `host filesystem tools patch files using exact text replacements`
  - Covers the coding-agent patch/edit primitive with exact, unique text replacement.
- `host filesystem tools run bash against the composed virtual filesystem`
  - Covers the coding-agent `bash` primitive over the same mounted filesystem abstraction without host filesystem access.
- `closing a VM while a host filesystem callback is locked up cleans up the sandbox`
  - Starts guest work that reaches a never-resolving host callback, closes the VM, and asserts close completes and in-flight work rejects.
- `virtual filesystem range reads pass correct offsets to host callbacks`
  - Guest reads slices from a larger virtual file and the host records requested ranges.
- `virtual filesystem metadata is reflected in guest stat output`
  - Assert file type, directory type, size, and writable bits from inside the guest.
- `virtual filesystem errors surface deterministically to the guest`
  - Missing file, read-only write, and host callback failure should produce stable guest behavior.
- `virtual filesystem handles larger file reads without truncation`
  - Read a file larger than the current small fixture and assert exact content.
- `guest-visible mounts are applied in declaration order so specific mounts can shadow parents`
  - Covers ordered mount application and the expected parent/child mount shadowing semantics.

Failing:

- No remaining known failures in this scenario file.

## `filesystem-posix-hardening.test.ts`

This file owns production filesystem semantics needed by coding-agent workloads. These tests are real VM tests through the public TypeScript API and should stay focused on user-visible POSIX behavior rather than internal backend structure.

Passing:

- `writable virtual filesystem supports nested directories and atomic rename`
  - Create nested directories, write a temporary file, atomically rename it into place, and assert the host filesystem view matches.
- `writable virtual filesystem supports unlink and empty directory removal`
  - Remove a file and then its empty parent directory from the guest, then assert host-side state is gone.
- `writable virtual filesystem supports symlink metadata without host path escape`
  - Create relative and absolute symlinks in a mounted virtual filesystem and assert readlink/relative resolution behavior is stable.
- `writable virtual filesystem preserves POSIX rename edge semantics`
  - Rename over an existing file atomically and reject replacing a non-empty directory.

Failing:

- No remaining known failures in this scenario file.

## `guest-hardening.test.ts`

This file owns hostile guest behavior. These tests should prove that untrusted code can exhaust or pressure guest resources without wedging the host API, escaping its VM, or carrying state into later sandbox instances.

Passing:

- `guest memory exhaustion is contained and the host can launch a fresh VM`
  - Drive guest memory to OOM and assert the VM/API failure is deterministic and a later VM still boots.
- `guest CPU exhaustion can be stopped without wedging the host API`
  - Saturate the guest vCPU with hot loops and assert `close()` still completes.
- `guest fork pressure can be stopped without wedging the host API`
  - Spawn guest processes aggressively and assert `close()` still completes.
- `guest disk exhaustion is bounded to the sandbox upper filesystem`
  - Fill the writable overlay and assert the guest hits a sandbox quota without leaking state to the next VM.
- `guest kernel object pressure can be stopped without wedging the host API`
  - Drive kernel object/file-descriptor pressure inside the guest and assert `close()` still completes.

Failing:

- No remaining known failures in this scenario file.

## `rootfs-shaping.test.ts`

This file owns root filesystem composition. Runtime VMs should stay immutable by default unless the root is explicitly composed with `linuxOverlayFs(...)`.

Passing:

- `linuxOverlayFs composes a prebuilt lower filesystem with a scratch upper filesystem`
  - Assert `/` is writable when the rootfs is an explicit Linux overlayfs composition.
- `immutable root remains the default when overlay mode is absent`
  - Assert root writes fail in normal runtime mode.
- `linuxOverlayFs does not mutate its prebuilt lower filesystem`
  - Mutate the overlay root, then boot the lower root alone and assert the mutation is absent.
- `scratchFs upper state is isolated between VM instances`
  - Mutate one scratch upper, then boot another `scratchFs()` upper and assert the mutation is absent.
- `mount creates a guest-visible mount boundary`
  - Assert `mount(path, fs)` is visible in the guest as a real mount boundary.
- `binding creates a host-side attachment point without a guest-visible mount boundary`
  - Assert host tools can use a binding while the guest cannot see it as a path or mount.
- `virtualFsMount remains an alias for guest-visible mounts`
  - Preserve compatibility while keeping mount terminology explicit.

Failing:

- No remaining known failures in this scenario file.

## `http-policy.test.ts`

This file owns L7 interception: HTTP parsing, TLS MITM, JavaScript policy, header rewriting, body handling, and failure behavior.

Passing:

- `plain HTTP traffic is intercepted, policy checked, rewritten, and forwarded`
  - Covers allow, deny, header rewrite, outbound policy handling, and policy metadata.
- `HTTPS traffic is intercepted, policy checked, and outbound-denied destinations are blocked`
  - Covers guest CA trust, TLS MITM, deny decisions, and outbound-denied destinations.
- `outbound default-deny blocks destinations before JavaScript policy`
  - Covers default-deny outbound enforcement before policy.
- `transparent HTTPS generates a trusted leaf cert for the requested SNI hostname`
  - Covers dynamic per-SNI leaf certificate issuance.
- `transparent HTTPS exposes SNI and Host mismatch to one policy call`
  - Covers SNI/Host mismatch visibility without a second JS round trip.
- `certificate pinning rejects MITM and fails closed before HTTP policy`
  - Covers pinned clients failing before policy is invoked.
- `HTTP interception forwards request and response bodies larger than a single TCP read`
  - Covers large HTTP upload/download and host framing.
- `HTTP interception handles concurrent guest requests without dropping policy calls`
  - Covers concurrent HTTP request accounting.
- `HTTP keep-alive behavior is explicit and deterministic`
  - Uses one client connection for two pipelined requests and asserts the documented close-after-one-response behavior.
- `upstream connection refused returns a deterministic guest-visible failure`
  - Allows policy to a refused origin and asserts the guest sees a stable `502`.
- `upstream timeout returns a deterministic guest-visible failure`
  - Origin accepts but delays response past the host upstream timeout; guest sees a stable `502`.
- `upstream reset mid-body is passed through as a truncated response`
  - Origin closes mid-response after headers are sent; the guest observes the upstream status and client-level truncation.
- `TLS without SNI has deterministic certificate and policy metadata`
  - Connects by IP literal and asserts missing-SNI metadata reaches one policy call deterministically.
- `dynamic MITM certificates are reused or bounded intentionally`
  - Repeated SNI requests provide guest-observed certificate evidence for cache behavior.
- `HTTP/2 ALPN behavior is explicit`
  - Attempts an HTTP/2-capable client and asserts deterministic HTTP/1.1 ALPN downgrade.

Failing:

No remaining known failures in this scenario file.

## `http-production-hardening.test.ts`

This file owns production HTTP behavior that matters for long-running agent workloads and failure cleanup.

Passing:

- `HTTP interception streams response bodies without waiting for upstream completion`
  - A slow upstream response should deliver first bytes to the guest before the origin finishes the whole response.
- `closing a VM while HTTP policy is locked up cleans up the sandbox`
  - A never-resolving JavaScript policy callback should not prevent VM close from completing and rejecting in-flight guest work.
- `plain HTTP egress header rewrite does not expose or modify request bodies`
  - JavaScript policy sees request metadata and headers only; Rust forwards the original body and the upstream response unchanged.
- `HTTPS egress header rewrite does not expose or modify request bodies`
  - The same egress-only header contract holds under TLS MITM with SNI metadata.
- `redirects to outbound-denied destinations are blocked before JavaScript policy`
  - A public origin redirecting to metadata/private infrastructure cannot bypass the outbound policy.
- `HTTPS interception buffers fragmented TLS plaintext before policy`
  - TLS headers and bodies split across records are buffered until a complete HTTP request is available.
- `HTTPS interception handles forwarded TLS ports without remapping to 443`
  - TLS is detected per flow so a pre-listened non-443 HTTPS destination still goes through MITM interception.

Failing:

- No remaining known failures in this scenario file.

## `network.test.ts`

This file owns L3/L4 behavior that is not specific to HTTP semantics.

Passing:

- `HTTP networking transparently intercepts guest TCP over explicit virtio-net`
  - Covers guest interface, route, and transparent TCP interception through the in-process backend.
- `outbound default deny blocks destinations before JavaScript policy`
  - Configure no matching accept rule and assert a pre-policy block.
- `public destinations reach JavaScript policy`
  - Request a destination allowed by `acceptTcp(...)` and assert policy evidence.
- `outbound-only policy creates the guest network device`
  - `network.outbound` without `network.http` still creates the guest interface and route.
- `DNS-dependent traffic is observable and cannot bypass policy`
  - Guest requests a hostname without `--connect-to`; assert DNS behavior and policy evidence.
- `DNS resolution to a denied IP is blocked before policy`
  - Host-controlled hostname resolves to a destination without an accept rule and is blocked.
- `public internet allow rules do not allow IPv6 loopback resolution`
  - `acceptPublicInternet(...)` never treats IPv6 loopback/link-local resolution as public reachability.
- `IPv6 behavior is explicit`
  - Attempt IPv6 HTTP destination and assert deterministic unsupported or implemented behavior.

Arbitrary UDP forwarding is not currently a production runtime surface. DNS UDP remains covered through resolver-driven scenarios; a future general UDP forwarding feature should add listener-backed e2e evidence with a deterministic host observable.

Failing:

- No remaining known failures in this scenario file.

## Artifact Tests: `tests/artifact/linkage-and-signing.test.ts`

This suite owns cheap packaging and platform contracts for the executable that actually opens the hypervisor. It is intentionally outside `npm run test:e2e` because it does not exercise guest runtime behavior.

Passing:

- `VM host artifact has no libkrun/libkrunfw dynamic dependency and is signed on macOS`
  - Covers dynamic dependency rejection and macOS HVF entitlement checks on `sandbox-host`.
- `unsigned Node is acceptable because VM launch goes through sandbox-host`
  - Assert the hypervisor-owning process is the helper, not the Node process.
- `project kernel and init artifacts are selected explicitly`
  - Assert runtime uses `projectKernel()` and `projectInit()` artifacts without dynamic discovery.
- `Linux host CI runs the core VM/control/network contract`
  - The CI job should prove the same required e2e subset on a Linux host with KVM.

Failing:

- No remaining known failures in this scenario file.

## Artifact Tests: `tests/artifact/libkrun-contract.test.ts`

This suite owns cheap static contracts against the libkrun integration and fork shape.

Passing:

- `Sandbox integrates libkrun through Rust/static build outputs, not the C header surface`
  - Reject accidental C API binding or dynamic library paths.
- `Sandbox-owned sockets can be supplied without filesystem socket paths`
  - Prove fd-oriented network/control surfaces where the fork supports them.
- `virtual filesystem operations use libkrun virtual filesystem traits`
  - Keep writable VFS tied to the libkrun trait/backend path.

Failing:

- No remaining known failures in this scenario file.

## Reproducibility Tests: `tests/reproducibility/build-artifacts.test.ts`

This suite owns expensive build reproducibility checks. It is intentionally outside default e2e and CI because it rebuilds Docker rootfs artifacts and the Linux kernel.

Passing:

- `rootfs fixture builds reproducibly`
  - Build the rootfs fixture twice and compare digest/metadata.
- `kernel fixture builds reproducibly`
  - Build the kernel fixture twice and compare digest/metadata.

Failing:

- No remaining known failures in this scenario file.

## `libkrun-contract.test.ts`

This runtime e2e file owns fork-specific contracts that require booting a VM.

Passing:

- `direct Rust init injection boots without libkrun stage-1 init`
  - Boot `sandbox-init` directly without relying on libkrun stage-1 init.

Failing:

- No remaining known failures in this scenario file.

## Required Suite Today

`npm run test:e2e` should include runtime VM behavior tests. `npm run test:artifact` should include cheap packaging/linkage contracts. `npm run test:reproducibility` should include expensive build reproducibility checks and should be run intentionally, not as part of the default PR loop. Host capability detection may decline to run the suite on machines that cannot launch VMs, but roadmap behavior should never be hidden behind implementation placeholders.

New hardening slices should add or refine real tests with idiomatic test names, then make those tests pass without adding compatibility layers or speculative options.
