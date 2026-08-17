---
status: accepted
---

# Preserve guest identity with private macOS virtio-fs metadata

macOS host-directory binds must not expose unrelated host UID and GID numbers inside a Sandbox guest. Sandbox will map the sandbox host process identity to the configured guest process identity and will preserve guest-owned Linux metadata in one private xattr when an inode can no longer be represented faithfully by native host metadata.

## Identity mapping

The public `fs.bind({ source, access })` API remains unchanged while Sandbox only runs guest workloads as root. At VM startup, Sandbox snapshots the sandbox host process's effective UID and GID. Every host-directory bind in that VM independently maps those values to guest UID `0` and GID `0`.

Other host UIDs and GIDs do not pass through. Each unmapped component appears as Linux overflow/nobody ID `65534`, so a host owner of `502:80` under a `502:20` process mapping appears as guest `0:65534`.

The mapping is fixed for the VM lifetime and recomputed only on the next boot. A future configured non-root guest identity will replace guest `0:0`; this ADR does not add that public capability.

Adopted numeric IDs are stable filesystem metadata, not viewer-relative identities. Concurrently mounting one host directory into multiple VMs, especially with different guest identities, is discouraged but not detected or prevented.

## Native and adopted inodes

A native inode has no `user.torkbot.sandbox.metadata` xattr. Its guest UID, GID, and mode are derived from mapped host `stat` values.

An adopted inode has a complete `user.torkbot.sandbox.metadata` xattr. The record is the adoption marker and the exclusive authority for guest UID, GID, mode, and Linux file capabilities:

```text
uid:gid:mode:capability
```

All four fields are structurally required. UID and GID are canonical decimal numbers, mode is canonical octal including the physical inode kind, and capability is either `-` or the lowercase hexadecimal bytes of a valid Linux V2 or V3 `security.capability` value. Capability length, revision, and flags are validated according to the Linux format rather than accepted as arbitrary hex:

```text
0:0:0100644:-
```

The virtual inode kind must match the physical host inode kind. Guest `mknod` requests for FIFOs, Unix sockets, character devices, block devices, and overlayfs whiteouts fail with `EOPNOTSUPP` before creating a backing entry. Ordinary files, directories, and physical symlinks remain supported.

The record is private host bookkeeping. The guest cannot list, read, write, or remove it directly. Sandbox does not inspect, migrate, delete, or otherwise interpret the legacy `user.containers.override_stat` attribute.

Only an explicit host attribute-not-found result means an inode is native. Malformed present metadata fails with `EINVAL`. A too-small xattr read buffer is resized and retried; permission, I/O, and other read failures propagate rather than falling back to host `stat`.

## Adoption lifecycle

Guest-created entries are adopted before creation is reported successful. An existing native inode becomes adopted when virtio-fs must persist a change to guest-visible UID, GID, mode, or capabilities. This includes successful guest `chmod`, `chown`, and `security.capability` operations, plus content changes that must clear setuid, setgid, or file capabilities. Ordinary reads, generic xattr operations, and content writes that do not change authority metadata do not cause adoption.

Adoption is monotonic for the lifetime of the inode. Returning every field to values that happen to match the host does not remove the record. Removing `security.capability` leaves the complete record in place.

The xattr belongs to the inode rather than a pathname. Hard links share adoption and metadata changes, renames preserve them, and removing one hard link does not affect the others. A host copy that preserves the private xattr creates an adopted destination; a copy that drops xattrs creates a native destination.

If the host removes the complete record, Sandbox cannot distinguish the formerly adopted inode from a native inode. If the host replaces the inode, the replacement is also native. These are accepted host-side integrity boundaries; Sandbox will not add a second marker, sidecar, journal, or path registry to detect them.

## Host backing permissions

New guest-created regular files use physical host mode `0600`, and new guest-created directories use physical host mode `0700`. The requested Linux mode exists exclusively in the private record. A guest-created file may therefore be executable inside the guest while remaining non-executable on the host.

Adopting an existing host inode does not rewrite its physical mode, and later guest `chmod` changes only the private record. Guest `chown` never changes physical macOS ownership. Once adopted, later host ownership and mode changes do not alter guest `stat`, but physical host permissions remain a hard ceiling on the sandbox host process's ability to access the backing inode. The resulting host access error propagates to the guest; virtio-fs does not repair host permissions.

## Guest xattrs and privilege removal

Guest `user.*` xattrs use the established virtiofsd carrier convention: prepend the complete guest name with `user.virtiofs.` on the host. For example, guest `user.comment` is stored as host `user.virtiofs.user.comment`. Only attributes under that host prefix are decoded into guest names; all other raw host xattrs, carrier names, and the private metadata record remain hidden from guest listing and direct access. Host `user.virtiofs.*` is therefore reserved guest-owned state.

macOS limits an xattr name to 127 bytes. The 14-byte carrier prefix leaves 113 bytes for the complete guest name, including its namespace. Longer guest names fail with `ERANGE`. Sandbox does not add a hashed, indexed, or aggregate fallback representation for longer names.

Guest `security.capability` is synthesized from the private metadata record instead of using a second carrier xattr. Every `trusted.*` operation fails with `EOPNOTSUPP`, and trusted names never appear in guest listings. Although the guest kernel checks capabilities for direct trusted-xattr operations, the FUSE `listxattr` protocol does not convey the caller's capability set, so the backend cannot faithfully reproduce the namespace's capability-dependent visibility. Every other `security.*` and every `system.*` operation, including POSIX and NFS-style ACLs, also fails with `EOPNOTSUPP`; storing bytes would falsely imply security or filesystem semantics that Sandbox does not enforce.

The negotiated FUSE `HANDLE_KILLPRIV_V2` contract governs privilege removal. A guest ownership change replaces the complete metadata record once, applying the new UID or GID while unconditionally removing file capabilities and clearing the required setuid/setgid bits. Failure leaves both ownership and privilege metadata unchanged.

For writes and truncation that carry a killpriv request, virtio-fs first replaces the metadata record with capabilities and the required setuid/setgid bits removed, then mutates the contents. Failure to remove privilege metadata prevents the content mutation. If the later content operation fails, the conservative privilege removal remains.

## Backing-volume and creation failures

Writable binds require backing-volume xattr support. `fs.bind(...)` remains a pure descriptor constructor; `sandbox.boot(...)` checks the macOS volume capability without creating a probe file and rejects before starting the guest when the volume clearly reports that xattrs are unavailable. The error identifies the affected source path. Every distinct writable backing root is checked independently, including writable mask storage when it resides on another volume. Individual xattr operations remain authoritative and propagate their real errors.

Read-only binds may start on volumes without xattr support in native-only mode. Ownership and mode derive from mapped host `stat`, xattr reads fail with `EOPNOTSUPP`, and metadata mutations fail with `EROFS`. When a read-only volume supports xattrs, valid adopted metadata and carrier xattrs remain visible and malformed private metadata still fails with `EINVAL`.

macOS cannot atomically create a directory entry and attach its metadata record. Sandbox creates the requested final path, attaches the complete record before reporting guest success, and removes the entry if metadata attachment fails. Cleanup failure is logged and creation still fails. A sandbox-host crash between physical creation and xattr attachment can leave a native entry; this is accepted rather than introducing temporary-name recovery, scanning, journaling, or sidecar state.

## Implementation boundaries

This behavior stays behind the existing `fs.bind(...)` interface. The TypeScript mount descriptor and the Node-to-host spawn document do not gain identity or xattr fields. `sandbox-host`, which owns the effective host identity and VM launch, snapshots that identity once per VM and constructs one required internal mapping containing host UID, host GID, guest UID, and guest GID. For the current root-only guest this is `<effective host UID>:<effective host GID>` to `0:0`. The same mapping is attached to every host-directory device in the VM; it is not inferred separately from each mount.

The Sandbox runtime passes host-directory configuration through one Rust-only libkrun helper for both masked and unmasked binds. The libkrun device configuration represents ordinary passthrough and Sandbox metadata passthrough as distinct modes. The Sandbox mode requires the complete identity mapping; it is not an `Option`, has no default mapping, and never falls back to the legacy macOS passthrough behavior. Existing libkrun C callers therefore do not acquire Sandbox semantics implicitly, and this project-specific configuration does not add a C API.

Within the macOS virtio-fs backend, one metadata module owns the private record schema, native-versus-adopted classification, identity translation, carrier-xattr namespace, and complete-record replacement operations. FUSE request handlers ask that module for guest metadata operations instead of parsing or composing private xattrs themselves. This keeps the on-host representation and its error rules out of the device builder and Sandbox public API.

Writable-volume preflight remains in `sandbox-host`, before libkrun starts the VM, because it must report a caller-facing bind source rather than a later inode operation. The macOS backend still treats each xattr syscall as authoritative. Preflight is an early diagnostic, not a cached promise that later metadata writes will succeed.

The combined record is the atomicity boundary. A metadata transition reads at most one prior record and publishes at most one replacement record. Current single-worker request dispatch supplies the required operation serialization; the metadata module must not invent a second lock or expose partial-field setters.

## Consequences

- Guest ownership is stable and no unrelated macOS account numbers leak into the VM.
- Host tools see physical transport permissions rather than adopted guest permissions.
- Guest-created and adopted inodes require xattr-preserving host backup and copy workflows if their Linux metadata must survive.
- Concurrent multi-VM use has stable numeric metadata but is intentionally unsupported by guidance rather than enforcement.
- POSIX requires concurrent file-attribute operations such as `chmod` and `chown` to have results consistent with some serial ordering. The current in-process virtio-fs device already provides that ordering: it has one request queue and one worker, and the worker handles each request synchronously before taking the next request. The metadata backend therefore must not add a separate per-inode lock while that dispatch invariant holds. The combined-record read-modify-write path must document its reliance on serialized dispatch. Any future change that permits requests to overlap must introduce same-inode serialization before enabling that parallelism.

## Acceptance examples

The implementation starts with end-to-end expectations at the public `fs.bind(...)` interface:

- With sandbox-host identity `502:20`, a native host inode owned by `502:80` appears in the guest as `0:65534`; an inode owned by `501:20` appears as `65534:0`. Neither unrelated host ID passes through.
- Guest `chmod` or `chown` of a native inode creates one complete private record. The requested guest metadata survives VM restart, while the host owner and backing mode remain unchanged.
- After adoption, host owner or mode changes do not change guest `stat`. Removing the complete private record makes the inode native again; replacing the inode also creates native state.
- A malformed present private record makes metadata operations fail with `EINVAL`; Sandbox never falls back to host metadata.
- Guest `user.comment` round-trips through host `user.virtiofs.user.comment`. Raw host attributes and carrier names are not listed in the guest, and a guest xattr name longer than 113 bytes fails with `ERANGE`.
- Guest file capabilities survive restart, are removed with the negotiated Linux killpriv behavior, and never occupy a second host xattr.
- Unsupported special-file creation fails with `EOPNOTSUPP` and leaves no host directory entry.
- A writable bind or writable mask-storage root on a volume that reports no xattr support rejects `sandbox.boot(...)` before the guest starts. A read-only bind on that volume starts in native-only mode.
- Concurrent guest `chmod` and `chown` operations produce a state consistent with a serial ordering; neither completed operation is silently lost.

## Documentation requirements

The implementation is not complete until the behavior is documented at each audience boundary:

- The `fs.bind` README and public API documentation must explain effective-user mapping, unmapped `65534` IDs, native versus adopted inodes, host backing permissions, the 113-byte guest xattr-name limit, and the lack of a new identity option while workloads are root-only.
- User guidance must warn against mounting one writable host directory into multiple VMs, describe xattr-preserving backup and copy requirements, and list unsupported special files, ACLs, and security labels.
- `docs/architecture.md` must record the metadata schema, adoption transitions, namespace mapping, privilege-removal order, backing-volume checks, strict read-error behavior, and accepted host-removal and creation crash windows.
- Code comments must be placed at the non-obvious invariant boundaries: the record as adoption marker, attribute-not-found as the only per-inode native signal, owner-only backing modes, privilege removal before content mutation, cleanup after metadata attachment failure, and combined-record updates relying on the single synchronous virtio-fs worker. Comments should explain why the ordering or split exists rather than restating the operations.
- End-to-end tests must express the public guest/host behavior, while focused backend tests cover parsing, error propagation, concurrency, cleanup, and xattr namespace rules.
