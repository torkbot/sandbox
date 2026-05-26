import test from "node:test";
import assert from "node:assert/strict";
import {
  createSandboxConfig,
  fs,
  rootfs,
  type SandboxFileSystem,
  type SandboxWritableFileSystem,
  type SandboxWritableFileSystemSource,
} from "../../src/index.ts";

test("createSandboxConfig rejects non-built-in rootfs objects", () => {
  assert.throws(
    () => createSandboxConfig({
      rootfs: { kind: "prebuilt-rootfs", path: "rootfs.erofs", format: "erofs" } as never,
    }),
    /invalid sandbox config: rootfs must be selected with rootfs\.builtIn\(\.\.\.\)/,
  );
});

test("createSandboxConfig rejects unsupported built-in rootfs names", () => {
  assert.throws(
    () => createSandboxConfig({
      rootfs: { kind: "built-in-rootfs", name: "debian:13" } as never,
    }),
    /unsupported built-in rootfs: debian:13/,
  );
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

test("boot rejects relative mount paths before runtime launch", async () => {
  const config = createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
  });

  await assert.rejects(
    config.boot({
      mounts: {
        workspace: fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must be absolute/,
  );
});

test("boot rejects root and dot-component mount paths before runtime launch", async () => {
  const config = createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
  });

  await assert.rejects(
    config.boot({
      mounts: {
        "/": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not be root/,
  );

  await assert.rejects(
    config.boot({
      mounts: {
        "/tmp/../proc": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not contain '\.' or '\.\.' components/,
  );
});

test("boot rejects mount paths with NUL bytes before runtime launch", async () => {
  const config = createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
  });

  await assert.rejects(
    config.boot({
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
