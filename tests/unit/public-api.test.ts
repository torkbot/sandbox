import test from "node:test";
import assert from "node:assert/strict";
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  type SandboxFileSystem,
  type SandboxWritableFileSystem,
  type SandboxWritableFileSystemSource,
} from "../../src/index.ts";

test("rootfs.builtIn creates a typed built-in rootfs reference", () => {
  assert.deepEqual(rootfs.builtIn("alpine:3.20"), {
    kind: "built-in-rootfs",
    name: "alpine:3.20",
  });
});

test("fs.virtual wraps user-space filesystems for mounts and overlays", () => {
  const fileSystem = writableFileSystem();

  assert.deepEqual(fs.virtual(fileSystem), {
    kind: "virtual-fs",
    fileSystem,
  });
});

test("defineSandbox rejects read-only overlay filesystems", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.20"),
      overlay: fs.virtual(readOnlyFileSystem()) as SandboxWritableFileSystemSource,
    }),
    /invalid sandbox definition: overlay filesystem must be writable/,
  );
});

test("network.policy creates an opaque connection policy", () => {
  const policy = network.policy(async (conn) => {
    if (conn.host === "registry.npmjs.org") {
      conn.allowHttp();
    }
  });

  assert.equal(policy.kind, "network-policy");
});

function readOnlyFileSystem(): SandboxFileSystem {
  return {
    async stat() {
      throw new Error("not reached");
    },
    async list() {
      throw new Error("not reached");
    },
    async read() {
      throw new Error("not reached");
    },
  };
}

function writableFileSystem(): SandboxWritableFileSystem {
  return {
    ...readOnlyFileSystem(),
    async createFile() {
      throw new Error("not reached");
    },
    async write() {
      throw new Error("not reached");
    },
    async truncate() {
      throw new Error("not reached");
    },
  };
}
