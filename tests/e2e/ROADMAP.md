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
  - Covers allow, deny, header rewrite, protected range handling, and policy metadata.
- `HTTPS traffic is intercepted, policy checked, rewritten, and protected ranges are blocked`
  - Covers CA trust, TLS MITM, allow, deny, rewrite, and protected ranges.
- `protected host and private network destinations are blocked before JavaScript policy`
  - Covers default RFC1918, carrier-grade NAT, and link-local pre-policy blocks.
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
- `HTTPS interception forwards request and response bodies larger than a single TLS record`
  - Covers large HTTPS upload/download.
- `HTTPS interception handles concurrent guest requests without dropping TLS policy calls`
  - Covers concurrent HTTPS request accounting.
- `HTTP keep-alive behavior is explicit and deterministic`
  - Uses one client connection for two pipelined requests and asserts the documented close-after-one-response behavior.
- `upstream connection refused returns a deterministic guest-visible failure`
  - Allows policy to a refused origin and asserts the guest sees a stable `502`.
- `upstream timeout returns a deterministic guest-visible failure`
  - Origin accepts but delays response past the host upstream timeout; guest sees a stable `502`.
- `upstream reset mid-body returns a deterministic guest-visible failure`
  - Origin closes mid-response and the guest observes a stable `502`.
- `TLS without SNI has deterministic certificate and policy metadata`
  - Connects by IP literal and asserts missing-SNI metadata reaches one policy call deterministically.
- `dynamic MITM certificates are reused or bounded intentionally`
  - Repeated SNI requests provide guest-observed certificate evidence for cache behavior.
- `HTTP/2 ALPN behavior is explicit`
  - Attempts an HTTP/2-capable client and asserts deterministic HTTP/1.1 ALPN downgrade.

Failing:

No remaining known failures in this scenario file.

## `network.test.ts`

This file owns L3/L4 behavior that is not specific to HTTP semantics.

Passing:

- `HTTP networking transparently intercepts guest TCP over explicit virtio-net`
  - Covers guest interface, route, and transparent TCP interception through the in-process backend.
- `caller protected ranges extend the default network deny set`
  - Configure a custom CIDR and assert pre-policy block.
- `public destinations reach JavaScript policy`
  - Request a non-protected destination and assert policy evidence.
- `DNS-dependent traffic is observable and cannot bypass policy`
  - Guest requests a hostname without `--connect-to`; assert DNS behavior and policy evidence.
- `DNS resolution to a protected IP is still blocked before policy`
  - Host-controlled hostname resolves to private/link-local IP and is blocked.
- `IPv6 behavior is explicit`
  - Attempt IPv6 HTTP destination and assert deterministic unsupported or implemented behavior.
- `UDP and non-HTTP traffic cannot silently bypass policy`
  - Probe UDP/non-HTTP traffic and assert the documented behavior.

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
