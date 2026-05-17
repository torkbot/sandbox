import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  type SandboxDirectoryEntry,
  type SandboxFileStat,
  type SandboxWritableFileSystem,
  spawnSandbox,
  virtualFsMount,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("virtual filesystem mounts are backed by host JavaScript callbacks", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "virtual-filesystem",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return {
              type: "directory",
              sizeBytes: null,
              mediaType: null,
              modifiedAtMs: null,
            };
          }

          if (path === "/status.json") {
            return {
              type: "file",
              sizeBytes: 19,
              mediaType: "application/json",
              modifiedAtMs: null,
            };
          }

          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }

          return [{ name: "status.json", type: "file" }];
        },
        async read(input) {
          assert.equal(input.path, "/status.json");
          return Buffer.from('{"status":"ready"}\n');
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const checks = await execGuestShell(vm, {
    id: "virtual-filesystem-checks",
    script: `
      set -u
      root_status=0
      test ! -w / || root_status=$?
      contents="$(cat /sandbox/status.json)"
      echo "root_status=$root_status"
      echo "contents=$contents"
      test "$root_status" = "0"
      test "$contents" = '{"status":"ready"}'
    `,
  });

  assert.equal(
    checks.exitCode,
    0,
    `guest filesystem checks failed\nstdout:\n${checks.stdout}\nstderr:\n${checks.stderr}`,
  );

  assert.equal((await vm.mounts.get("/sandbox").stat("/status.json")).type, "file");
  assert.deepEqual(await vm.mounts.get("/sandbox").list("/"), [
    { name: "status.json", type: "file" },
  ]);

  const virtualRead = await vm.mounts.virtualFs("/sandbox").read({
    path: "/status.json",
    signal: AbortSignal.timeout(1_000),
  });
  assert.equal(Buffer.from(virtualRead).toString("utf8"), '{"status":"ready"}\n');

  await writeEvidence("fs.json", {
    virtualRead: Buffer.from(virtualRead).toString("utf8"),
  });
});

test("writable virtual filesystem mounts persist guest mutations through host callbacks", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createMemoryWritableFileSystem();
  const vm = await spawnSandbox({
    name: "writable-virtual-filesystem",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/workspace", fileSystem),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const checks = await execGuestShell(vm, {
    id: "writable-virtual-filesystem-checks",
    script: `
      set -eu
      printf 'hello world' > /workspace/notes.txt
      test "$(cat /workspace/notes.txt)" = "hello world"
      printf 'SANDBOX' | dd of=/workspace/notes.txt bs=1 seek=6 conv=notrunc status=none
      test "$(cat /workspace/notes.txt)" = "hello SANDBOX"
      truncate -s 5 /workspace/notes.txt
      test "$(cat /workspace/notes.txt)" = "hello"
    `,
  });

  assert.equal(
    checks.exitCode,
    0,
    `guest writable filesystem checks failed\nstdout:\n${checks.stdout}\nstderr:\n${checks.stderr}`,
  );

  assert.deepEqual(await vm.mounts.get("/workspace").list("/"), [
    { name: "notes.txt", type: "file" },
  ]);
  assert.equal((await vm.mounts.get("/workspace").stat("/notes.txt")).sizeBytes, 5);
  const contents = await vm.mounts.get("/workspace").read({
    path: "/notes.txt",
    signal: AbortSignal.timeout(1_000),
  });
  assert.equal(Buffer.from(contents).toString("utf8"), "hello");
});

function createMemoryWritableFileSystem(): SandboxWritableFileSystem {
  const files = new Map<string, Uint8Array>();

  return {
    async stat(path) {
      if (path === "/") {
        return directoryStat(true);
      }
      const contents = files.get(path);
      if (contents === undefined) {
        throw new Error(`missing path ${path}`);
      }
      return fileStat(contents.byteLength, true);
    },
    async list(path) {
      if (path !== "/") {
        throw new Error(`missing directory ${path}`);
      }
      return [...files.keys()]
        .filter((filePath) => filePath.slice(1).indexOf("/") === -1)
        .sort()
        .map((filePath): SandboxDirectoryEntry => ({
          name: filePath.slice(1),
          type: "file",
        }));
    },
    async read(input) {
      const contents = files.get(input.path);
      if (contents === undefined) {
        throw new Error(`missing file ${input.path}`);
      }
      const offset = input.range?.offset ?? 0;
      const length = input.range?.length ?? contents.byteLength - offset;
      return contents.slice(offset, offset + length);
    },
    async createFile(path) {
      files.set(path, new Uint8Array());
      return fileStat(0, true);
    },
    async write(input) {
      const current = files.get(input.path);
      if (current === undefined) {
        throw new Error(`missing file ${input.path}`);
      }
      const nextLength = Math.max(current.byteLength, input.offset + input.contents.byteLength);
      const next = new Uint8Array(nextLength);
      next.set(current);
      next.set(input.contents, input.offset);
      files.set(input.path, next);
      return input.contents.byteLength;
    },
    async truncate(path, size) {
      const current = files.get(path);
      if (current === undefined) {
        throw new Error(`missing file ${path}`);
      }
      const next = new Uint8Array(size);
      next.set(current.slice(0, size));
      files.set(path, next);
      return fileStat(size, true);
    },
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

function fileStat(sizeBytes: number, writable: boolean): SandboxFileStat {
  return {
    type: "file",
    sizeBytes,
    mediaType: "application/octet-stream",
    modifiedAtMs: null,
    writable,
  };
}
