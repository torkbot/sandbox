import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
} from "../../../src/index.ts";
import { collectAsync } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("Sandbox integrates libkrun through Rust/static build outputs, not the C header surface", async () => {
  const sandboxCargo = await readFile(new URL("../../../crates/sandbox/Cargo.toml", import.meta.url), "utf8");
  const nodeBinding = await readFile(new URL("../../../crates/sandbox-node/src/lib.rs", import.meta.url), "utf8");

  assert.match(sandboxCargo, /krun = \{ package = "libkrun", path = "\.\.\/\.\.\/deps\/libkrun\/src\/libkrun"/);
  assert.match(sandboxCargo, /krun-devices = \{ path = "\.\.\/\.\.\/deps\/libkrun\/src\/devices"/);
  assert.doesNotMatch(nodeBinding, /libkrun\.h|krun[_-]sys/i);
});

test("Sandbox-owned sockets can be supplied without filesystem socket paths", async () => {
  const runtime = await readFile(new URL("../../../crates/sandbox/src/runtime.rs", import.meta.url), "utf8");

  assert.match(runtime, /UnixStream::pair\(\)/);
  assert.match(runtime, /add_control_socket_fd/);
  assert.match(runtime, /krun_add_vsock_port_fd/);
  assert.doesNotMatch(runtime, /krun_add_vsock_port\([^_]/);
});

test("virtual filesystem operations use libkrun virtual filesystem traits", async () => {
  const vfs = await readFile(new URL("../../../crates/sandbox/src/vfs.rs", import.meta.url), "utf8");
  const hostVfs = await readFile(new URL("../../../crates/sandbox-host/src/host_vfs.rs", import.meta.url), "utf8");

  assert.match(vfs, /VirtualFsBackend as VirtioVirtualFsBackend/);
  assert.match(vfs, /impl VirtioVirtualFsBackend for VirtualFsAdapter/);
  assert.match(hostVfs, /Arc<dyn VirtioVirtualFsBackend>/);
  assert.match(hostVfs, /impl sandbox::vfs::HostVirtualFileSystem for NodeVirtualFs/);
});

test("direct Rust init injection boots without libkrun stage-1 init", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "direct-rust-init",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "direct-rust-init",
    script: "cat /proc/1/comm; printf '\\n'; tr '\\0' ' ' < /proc/1/cmdline",
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^sandbox-init\n/);
});
