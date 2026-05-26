import test from "node:test";
import assert from "node:assert/strict";
import {
  createSandboxConfig,
  fs,
  rootfs,
  type SandboxFileStat,
  type SandboxPosixFileSystem,
} from "../../../src/index.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("new public API boots a built-in rootfs and runs a process", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
  }).boot();

  const result = await sandbox.process.exec("/bin/sh", ["-lc", "printf '%s' ready"]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "ready");
  assert.equal(result.stderr, "");
});

test("boot options provide instance-specific virtual mounts", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const laneFs = memoryWritableFileSystem({
    "/note.txt": new TextEncoder().encode("lane-private"),
  });
  await using sandbox = await createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
  }).boot({
    mounts: {
      "/mnt": fs.virtual(laneFs),
    },
  });

  const result = await sandbox.process.exec("/bin/cat", ["/mnt/note.txt"]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "lane-private");
});

test("boot cwd becomes the default process working directory", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
  }).boot({
    cwd: "/tmp",
  });

  const result = await sandbox.process.exec("/bin/pwd");

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.trim(), "/tmp");
});

test("overlay supplies writable copy-on-write rootfs storage", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const overlay = memoryWritableFileSystem();
  await using sandbox = await createSandboxConfig({
    rootfs: rootfs.builtIn("alpine:3.20"),
    overlay: fs.virtual(overlay),
  }).boot();

  const result = await sandbox.process.exec("/bin/sh", [
    "-lc",
    "printf '%s' installed > /usr/local/bin/example && cat /usr/local/bin/example",
  ]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "installed");
});

function memoryWritableFileSystem(files: Record<string, Uint8Array> = {}): SandboxPosixFileSystem {
  const entries = new Map<string, Uint8Array>(Object.entries(files));

  return {
    async stat(path) {
      if (path === "/") {
        return directoryStat(true);
      }
      const file = entries.get(path);
      if (file === undefined) {
        throw new Error(`not found: ${path}`);
      }
      return fileStat(file.byteLength, true);
    },
    async list(path) {
      if (path !== "/") {
        throw new Error(`not a directory: ${path}`);
      }
      return Array.from(entries.keys(), (entry) => ({
        name: entry.slice(1),
        type: "file" as const,
      }));
    },
    async read(input) {
      const file = entries.get(input.path);
      if (file === undefined) {
        throw new Error(`not found: ${input.path}`);
      }
      const offset = input.range?.offset ?? 0;
      const end = input.range === undefined ? file.byteLength : offset + input.range.length;
      return file.slice(offset, end);
    },
    async createFile(path) {
      entries.set(path, new Uint8Array());
      return fileStat(0, true);
    },
    async write(input) {
      const previous = entries.get(input.path) ?? new Uint8Array();
      const nextLength = Math.max(previous.byteLength, input.offset + input.contents.byteLength);
      const next = new Uint8Array(nextLength);
      next.set(previous);
      next.set(input.contents, input.offset);
      entries.set(input.path, next);
      return input.contents.byteLength;
    },
    async truncate(path, size) {
      const previous = entries.get(path) ?? new Uint8Array();
      const next = new Uint8Array(size);
      next.set(previous.slice(0, size));
      entries.set(path, next);
      return fileStat(size, true);
    },
    async mkdir() {
      return directoryStat(true);
    },
    async unlink(path: string) {
      entries.delete(path);
    },
    async rmdir() {
    },
    async rename(from: string, to: string) {
      const file = entries.get(from);
      if (file === undefined) {
        throw new Error(`not found: ${from}`);
      }
      entries.delete(from);
      entries.set(to, file);
    },
    async symlink() {
      throw new Error("symlink not implemented by test filesystem");
    },
    async readlink() {
      throw new Error("readlink not implemented by test filesystem");
    },
  };
}

function fileStat(sizeBytes: number, writable: boolean): SandboxFileStat {
  return {
    type: "file",
    sizeBytes,
    mediaType: null,
    modifiedAtMs: null,
    writable,
  };
}

function directoryStat(writable: boolean): SandboxFileStat {
  return {
    type: "directory",
    sizeBytes: null,
    mediaType: null,
    modifiedAtMs: null,
    writable,
  };
}
