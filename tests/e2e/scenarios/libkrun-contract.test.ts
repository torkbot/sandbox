import test from "node:test";
import assert from "node:assert/strict";

test("Sandbox integrates libkrun through Rust/static build outputs, not the C header surface", () => {
  assert.fail("the build must reject accidental C API binding or dynamic libkrun/libkrunfw paths");
});

test("Sandbox-owned sockets can be supplied without filesystem socket paths", () => {
  assert.fail("fd-oriented network and control surfaces must be proven where the libkrun fork supports them");
});

test("virtual filesystem operations use libkrun virtual filesystem traits", () => {
  assert.fail("writable VFS e2e behavior must be tied to the libkrun virtual filesystem trait/backend path");
});

test("direct Rust init injection boots without libkrun stage-1 init", () => {
  assert.fail("sandbox-init must boot directly without relying on libkrun stage-1 init");
});
