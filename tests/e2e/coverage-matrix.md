# E2E Coverage Matrix

These scenarios are mutually exclusive by runtime capability and collectively cover the near-field Sandbox goals.

## VM Lifecycle And Control

- boot/readiness: init reports root/init metadata and accepts commands.
- command semantics: stdout, stderr, exit code, env, large output, concurrent commands, and close behavior are deterministic.
- shutdown: closing the VM terminates guest resources and rejects later host operations.

## Guest Init And Runtime Setup

- init identity: the repo-owned init is the guest setup boundary.
- trust setup: CA material is installed before workload commands run.
- network setup: guest interface, address, route, and resolver state are usable without host repair commands.
- mount setup: configured host filesystems are mounted before readiness.

## Filesystems

- immutable root: root writes fail in normal runtime mode.
- read-only virtual filesystem: host callbacks provide stat/list/read and stable JS mount handles.
- writable virtual filesystem: guest create/write/truncate operations round-trip through host callbacks and are visible through JS handles.
- filesystem errors: missing paths, read-only writes, and callback failures surface deterministically to the guest.
- rootfs shaping: explicit overlay mode can snapshot artifact bytes and boot the result.

## HTTP And TLS Interception

- policy path: method, URL, destination IP, headers, TLS metadata, allow/deny, and header rewrites are delivered in one JavaScript round trip.
- TLS trust: generated leaf certs are trusted for SNI hostnames; pinned clients fail closed before policy.
- message bodies: HTTP and HTTPS request/response bodies larger than a single read/write are forwarded correctly.
- concurrency: simultaneous HTTP and HTTPS requests do not drop policy calls or response bytes.
- upstream failures: connection errors and malformed upstream responses are deterministic guest-visible failures.

## Network Policy

- default protected ranges: private, carrier-grade NAT, and link-local destinations are blocked before JavaScript policy.
- caller protected ranges: supplied CIDRs extend the default deny set.
- public destinations: non-protected destinations can reach policy and, when allowed, the configured origin.
- DNS/proxy behavior: DNS-dependent traffic is observable and policyable without bypassing interception.

## Build, Packaging, And Platform Contracts

- static linkage: no dynamic `libkrun` or `libkrunfw` dependency.
- kernel/init artifacts: project-built artifacts are selected explicitly and not discovered dynamically at runtime.
- macOS signing: the helper executable, not Node, owns HVF entitlements.
- Linux host: CI proves the same VM/control/network contract on a Linux host.

## libkrun Fork Contracts

- fd-oriented APIs: Sandbox-owned sockets can be supplied without filesystem socket paths where needed.
- virtiofs hooks: readable and writable virtual filesystem operations are backed by libkrun virtual filesystem traits/types.
- direct init: the final boot path does not require a libkrun-provided stage-1 init.
