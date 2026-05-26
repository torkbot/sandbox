import test from "node:test";
import assert from "node:assert/strict";
import {
  createSandboxConfig,
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

test("createSandboxConfig rejects read-only overlay filesystems", () => {
  assert.throws(
    () => createSandboxConfig({
      rootfs: rootfs.builtIn("alpine:3.20"),
      overlay: fs.virtual(readOnlyFileSystem()) as SandboxWritableFileSystemSource,
    }),
    /invalid sandbox config: overlay filesystem must be writable/,
  );
});

test("network.buildPolicy creates a deny-by-default connection policy", async () => {
  const calls: string[] = [];
  const policy = network.buildPolicy({
    async onConnectionRequest(conn) {
      calls.push(`${conn.host}:${conn.port}`);
      if (conn.host === "registry.npmjs.org") {
        conn.allowHttp();
      }
    },
  });

  const grants: string[] = [];
  await policy.onConnectionRequest({
    transport: "tcp",
    host: "registry.npmjs.org",
    port: 443,
    allow() {
      grants.push("raw");
      return {};
    },
    allowHttp() {
      grants.push("http");
      return {};
    },
  });

  assert.deepEqual(calls, ["registry.npmjs.org:443"]);
  assert.deepEqual(grants, ["http"]);
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
