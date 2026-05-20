import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("Sandbox integrates libkrun through Rust/static build outputs, not the C header surface", async () => {
  const sandboxCargo = await readFile(new URL("../../crates/sandbox/Cargo.toml", import.meta.url), "utf8");
  const hostCargo = await readFile(new URL("../../crates/sandbox-host/Cargo.toml", import.meta.url), "utf8");

  assert.match(sandboxCargo, /krun = \{ package = "libkrun", path = "\.\.\/\.\.\/deps\/libkrun\/src\/libkrun"/);
  assert.match(sandboxCargo, /krun-devices = \{ path = "\.\.\/\.\.\/deps\/libkrun\/src\/devices"/);
  assert.doesNotMatch(hostCargo, /napi|libkrun\.h|krun[_-]sys/i);
});

test("Sandbox-owned sockets can be supplied without filesystem socket paths", async () => {
  const runtime = await readFile(new URL("../../crates/sandbox/src/runtime.rs", import.meta.url), "utf8");

  assert.match(runtime, /UnixStream::pair\(\)/);
  assert.match(runtime, /add_control_socket_fd/);
  assert.match(runtime, /krun_add_vsock_port_fd/);
  assert.doesNotMatch(runtime, /krun_add_vsock_port\([^_]/);
});

test("virtual filesystem operations use libkrun virtual filesystem traits", async () => {
  const vfs = await readFile(new URL("../../crates/sandbox/src/vfs.rs", import.meta.url), "utf8");
  const hostVfs = await readFile(new URL("../../crates/sandbox-host/src/host_vfs.rs", import.meta.url), "utf8");

  assert.match(vfs, /VirtualFsBackend as VirtioVirtualFsBackend/);
  assert.match(vfs, /impl VirtioVirtualFsBackend for VirtualFsAdapter/);
  assert.match(hostVfs, /Arc<dyn VirtioVirtualFsBackend>/);
  assert.match(hostVfs, /impl sandbox::vfs::HostVirtualFileSystem for NodeVirtualFs/);
});
