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

test("fs.memory supports POSIX hard links and extended attributes", async () => {
  const fileSystem = fs.memory({
    files: {
      "/source.txt": "source",
    },
  });

  await fileSystem.link("/source.txt", "/linked.txt");
  await fileSystem.write({
    path: "/linked.txt",
    offset: 0,
    contents: new TextEncoder().encode("linked"),
  });

  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/source.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "linked",
  );

  await fileSystem.setxattr("/linked.txt", "trusted.overlay.whiteout", new Uint8Array([1, 2, 3]));
  assert.deepEqual(await fileSystem.listxattr("/source.txt"), ["trusted.overlay.whiteout"]);
  assert.deepEqual(
    await fileSystem.getxattr("/source.txt", "trusted.overlay.whiteout"),
    new Uint8Array([1, 2, 3]),
  );
});

test("fs.memory creates user overlay whiteouts for rename whiteout", async () => {
  const fileSystem = fs.memory({
    files: {
      "/source.txt": "source",
    },
  });

  await fileSystem.rename("/source.txt", "/renamed.txt", 4);

  assert.deepEqual(await fileSystem.listxattr("/source.txt"), ["user.overlay.whiteout"]);
  assert.deepEqual(await fileSystem.getxattr("/source.txt", "user.overlay.whiteout"), new Uint8Array());
});

test("defineSandbox accepts resource limits", () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.20"),
    resources: {
      cpus: 2,
      memoryMiB: 1024,
    },
  });

  assert.equal(typeof sandbox.boot, "function");
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
