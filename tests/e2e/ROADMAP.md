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

## `http-request-headers.test.ts`

This file owns the new L7 contract: HTTP request-header hooks are default-allow, mutate only the host-to-upstream request, and cannot use URL authority alone to release credentials.

Passing:

- None yet. These tests define the Rust/Rama data-plane contract and must fail until that implementation exists.

Failing:

- `HTTP request-header hook injects host credentials only on the upstream leg`
  - A guest request reaches a local origin, a host hook sets `authorization`, and the origin sees the header while the guest only supplied its own non-secret marker.
- `HTTP credential hooks do not authorize DNS-rebound private destinations`
  - A request whose URL authority matches `https://api.github.com/*` but whose connection is rebound to link-local/private address space must be denied before credential injection.

## `network.test.ts`

This file owns L3/L4 behavior that is not specific to HTTP semantics.

Passing:

- `outbound policy creates the guest network device and default route`
  - Covers guest interface and route setup when L4 outbound policy is configured.
- `outbound default deny returns a deterministic HTTP denial`
  - Configure no matching accept rule and assert the guest sees a deterministic `403`.

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

- `boots sandbox-init as PID 1`
  - Boot `sandbox-init` as the first guest userspace process.

Failing:

- No remaining known failures in this scenario file.

## Required Suite Today

`npm run test:e2e` should include runtime VM behavior tests. `npm run test:artifact` should include cheap packaging/linkage contracts. `npm run test:reproducibility` should include expensive build reproducibility checks and should be run intentionally, not as part of the default PR loop. Host capability detection may decline to run the suite on machines that cannot launch VMs, but roadmap behavior should never be hidden behind implementation placeholders.

New hardening slices should add or refine real tests with idiomatic test names, then make those tests pass without adding compatibility layers or speculative options.
