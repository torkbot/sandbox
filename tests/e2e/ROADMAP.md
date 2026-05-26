# E2E Roadmap

The e2e suite should read like the contract of the public API, not a record of
internal launch primitives. Scenario names should stay close to the README path:
configure a reusable sandbox, boot an instance, run work, and close it.

## `sandbox-api.test.ts`

Passing:

- `new public API boots a built-in rootfs and runs a process`
  - Covers `createSandboxConfig`, `rootfs.builtIn(...)`, `config.boot()`, and `sandbox.process.exec(...)`.
- `boot options provide instance-specific virtual mounts`
  - Covers per-instance `mounts` and `fs.virtual(...)` without separate binding concepts.
- `overlay supplies writable copy-on-write rootfs storage`
  - Covers a user-space virtual filesystem as the rootfs copy-on-write store.

Next:

- Add a deterministic local HTTP origin test for `network.buildPolicy(...)` once
  the guest image and DNS path can exercise the interception layer without
  depending on public internet behavior.
- Add a streaming process test when `sandbox.process.spawn(...)` lands.
- Reintroduce hostile guest and POSIX-hardening coverage using only the public
  API above.

## Artifact Tests

`tests/artifact/linkage-and-signing.test.ts` owns static packaging and platform
contracts for `sandbox-host`. It intentionally does not expose kernel or init as
public TypeScript configuration.
