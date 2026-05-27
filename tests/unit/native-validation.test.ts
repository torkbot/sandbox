import test from "node:test";
import assert from "node:assert/strict";
import {
  defineSandbox,
  fs,
  rootfs,
  type SandboxFileSystem,
  type SandboxWritableFileSystem,
  type SandboxWritableFileSystemSource,
} from "../../src/index.ts";

test("defineSandbox rejects non-built-in rootfs objects", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: { kind: "prebuilt-rootfs", path: "rootfs.erofs", format: "erofs" } as never,
    }),
    /invalid sandbox definition: rootfs must be selected with rootfs\.builtIn\(\.\.\.\)/,
  );
});

test("defineSandbox rejects unsupported built-in rootfs names", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: { kind: "built-in-rootfs", name: "debian:13" } as never,
    }),
    /unsupported built-in rootfs: debian:13/,
  );
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

test("defineSandbox rejects invalid resource limits", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.20"),
      resources: { cpus: 0 },
    }),
    /invalid sandbox definition: resources\.cpus must be a positive integer/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.20"),
      resources: { cpus: 256 },
    }),
    /invalid sandbox definition: resources\.cpus must be less than or equal to 255/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.20"),
      resources: { memoryMiB: 0 },
    }),
    /invalid sandbox definition: resources\.memoryMiB must be a positive integer/,
  );
});

test("boot rejects relative mount paths before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.20"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        workspace: fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must be absolute/,
  );
});

test("boot rejects root and dot-component mount paths before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.20"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not be root/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/tmp/../proc": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not contain '\.' or '\.\.' components/,
  );
});

test("boot rejects mount paths with NUL bytes before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.20"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/bad\0path": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not contain NUL bytes/,
  );
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
