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
import { execGuestShell, withTimeout } from "../support/guest-control.ts";
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

test("host filesystem tools read complete files and line ranges through JavaScript", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createMemoryWritableFileSystem();
  await fileSystem.createFile("/notes.txt");
  await fileSystem.write({
    path: "/notes.txt",
    offset: 0,
    contents: Buffer.from("one\ntwo\nthree\nfour\n"),
  });

  const vm = await spawnSandbox({
    name: "host-filesystem-read-tools",
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

  const all = await vm.mounts.host("/workspace").read({
    path: "notes.txt",
    signal: AbortSignal.timeout(1_000),
  });
  assert.equal(all.content, "one\ntwo\nthree\nfour\n");
  assert.equal(all.totalLines, 5);
  assert.equal(all.truncated, false);

  const range = await vm.mounts.host("/workspace").read({
    path: "/notes.txt",
    offset: 2,
    limit: 2,
    signal: AbortSignal.timeout(1_000),
  });
  assert.equal(range.content, "two\nthree");
  assert.equal(range.totalLines, 5);
  assert.equal(range.truncated, true);
});

test("host filesystem tools write complete files through JavaScript", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createMemoryWritableFileSystem();
  const vm = await spawnSandbox({
    name: "host-filesystem-write-tools",
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

  await vm.mounts.host("/workspace").write({
    path: "agent.txt",
    content: "created by host tools\n",
    signal: AbortSignal.timeout(1_000),
  });

  const result = await execGuestShell(vm, {
    id: "host-filesystem-write-tools",
    script: "cat /workspace/agent.txt",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "created by host tools\n");
});

test("host filesystem tools patch files using exact text replacements", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createMemoryWritableFileSystem();
  await fileSystem.createFile("/agent.ts");
  await fileSystem.write({
    path: "/agent.ts",
    offset: 0,
    contents: Buffer.from("const answer = 'old';\n"),
  });

  const vm = await spawnSandbox({
    name: "host-filesystem-patch-tools",
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

  await vm.mounts.host("/workspace").patch({
    path: "/agent.ts",
    edits: [
      {
        oldText: "'old'",
        newText: "'new'",
      },
    ],
    signal: AbortSignal.timeout(1_000),
  });

  const result = await execGuestShell(vm, {
    id: "host-filesystem-patch-tools",
    script: "cat /workspace/agent.ts",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "const answer = 'new';\n");
});

test("host filesystem tools run bash against the composed virtual filesystem", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createMemoryWritableFileSystem();
  await fileSystem.createFile("/input.txt");
  await fileSystem.write({
    path: "/input.txt",
    offset: 0,
    contents: Buffer.from("alpha\nbeta\n"),
  });

  const vm = await spawnSandbox({
    name: "host-filesystem-bash-tools",
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

  const result = await vm.mounts.host("/workspace").bash({
    command: "grep beta input.txt > output.txt && cat output.txt",
    timeoutMs: 1_000,
    signal: AbortSignal.timeout(2_000),
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "beta\n");
  assert.equal(result.stderr, "");
  const written = await vm.mounts.host("/workspace").read({
    path: "/output.txt",
    signal: AbortSignal.timeout(1_000),
  });
  assert.equal(written.content, "beta\n");
});

test("guest-visible mounts are applied in declaration order so specific mounts can shadow parents", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const parentFs = createDirectoryOnlyFileSystem(["project"]);
  const childFs = createMemoryWritableFileSystem();
  await childFs.createFile("/file.txt");
  await childFs.write({
    path: "/file.txt",
    offset: 0,
    contents: Buffer.from("child mount wins"),
  });

  const vm = await spawnSandbox({
    name: "ordered-virtual-filesystem-mounts",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/workspace", parentFs),
      virtualFsMount("/workspace/project", childFs),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "ordered-virtual-filesystem-mounts",
    script: "cat /workspace/project/file.txt",
  });

  assert.equal(
    result.exitCode,
    0,
    `ordered mount check failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.stdout, "child mount wins");
});

test("closing a VM while a host filesystem callback is locked up cleans up the sandbox", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let unblockRead: (() => void) | undefined;
  let readStartedResolve: (() => void) | undefined;
  const readStarted = new Promise<void>((resolve) => {
    readStartedResolve = resolve;
  });

  const vm = await spawnSandbox({
    name: "locked-host-filesystem",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return directoryStat(false);
          }
          if (path === "/stuck.txt") {
            return fileStat(5, false);
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }
          return [{ name: "stuck.txt", type: "file" }];
        },
        async read() {
          readStartedResolve?.();
          await new Promise<void>((resolve) => {
            unblockRead = resolve;
          });
          return Buffer.from("stuck");
        },
      }),
    ],
  });

  t.after(async () => {
    unblockRead?.();
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const read = execGuestShell(vm, {
    id: "locked-vfs-read",
    script: "cat /sandbox/stuck.txt",
  });
  const readRejects = assert.rejects(
    withTimeout(read, 5_000, "locked filesystem guest command"),
    /closed|exited|sandbox VM|sandbox-host/i,
  );
  await withTimeout(readStarted, 2_000, "host filesystem read callback");

  await withTimeout(vm.close(), 3_000, "close locked filesystem VM");
  await readRejects;
});

test("virtual filesystem range reads pass correct offsets to host callbacks", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const contents = Buffer.from("abcdefghijklmnopqrstuvwxyz".repeat(512));
  const reads: Array<{ offset: number | null; length: number | null }> = [];
  const vm = await spawnSandbox({
    name: "virtual-filesystem-range-reads",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return directoryStat(false);
          }
          if (path === "/alphabet.txt") {
            return fileStat(contents.byteLength, false);
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }
          return [{ name: "alphabet.txt", type: "file" }];
        },
        async read(input) {
          reads.push({
            offset: input.range?.offset ?? null,
            length: input.range?.length ?? null,
          });
          const offset = input.range?.offset ?? 0;
          const length = input.range?.length ?? contents.byteLength - offset;
          return contents.subarray(offset, offset + length);
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "virtual-filesystem-range-reads",
    script: "dd if=/sandbox/alphabet.txt bs=1 skip=5000 count=13 status=none",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, contents.subarray(5000, 5013).toString("utf8"));
  assert.ok(
    reads.some((read) =>
      read.offset !== null
      && read.length !== null
      && read.offset <= 5000
      && read.offset + read.length >= 5013
    ),
    `expected a host range read covering offset 5000 length 13, got ${JSON.stringify(reads)}`,
  );
});

test("virtual filesystem metadata is reflected in guest stat output", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "virtual-filesystem-metadata",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return directoryStat(false);
          }
          if (path === "/data.bin") {
            return fileStat(1234, false);
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }
          return [{ name: "data.bin", type: "file" }];
        },
        async read() {
          return Buffer.alloc(1234, "m");
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "virtual-filesystem-metadata",
    script: `
      set -eu
      test -d /sandbox
      test -f /sandbox/data.bin
      test "$(wc -c < /sandbox/data.bin)" = "1234"
      stat /sandbox/data.bin | grep 'regular file'
      stat /sandbox/data.bin | grep 'Size: 1234'
      stat /sandbox/data.bin | grep 'Access: (0444'
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest metadata checks failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
});

test("virtual filesystem errors surface deterministically to the guest", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "virtual-filesystem-errors",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return directoryStat(false);
          }
          if (path === "/readonly.txt" || path === "/throws.txt") {
            return fileStat(4, false);
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }
          return [
            { name: "readonly.txt", type: "file" },
            { name: "throws.txt", type: "file" },
          ];
        },
        async read(input) {
          if (input.path === "/throws.txt") {
            throw new Error("host read failed intentionally");
          }
          return Buffer.from("data");
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "virtual-filesystem-errors",
    script: `
      set +e
      cat /sandbox/missing.txt >/tmp/missing.out 2>/tmp/missing.err
      missing_status=$?
      printf nope > /sandbox/readonly.txt 2>/tmp/write.err
      write_status=$?
      cat /sandbox/throws.txt >/tmp/throws.out 2>/tmp/throws.err
      throws_status=$?
      echo "missing=$missing_status"
      echo "write=$write_status"
      echo "throws=$throws_status"
      test "$missing_status" != "0"
      test "$write_status" != "0"
      test "$throws_status" != "0"
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest error checks failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.match(result.stdout, /missing=[1-9][0-9]*/);
  assert.match(result.stdout, /write=[1-9][0-9]*/);
  assert.match(result.stdout, /throws=[1-9][0-9]*/);
});

test("virtual filesystem rejects guest-mounted regular files with unknown size", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let readCount = 0;
  const vm = await spawnSandbox({
    name: "virtual-filesystem-unknown-size",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return directoryStat(false);
          }
          if (path === "/dynamic.txt") {
            return {
              type: "file",
              sizeBytes: null,
              mediaType: "text/plain",
              modifiedAtMs: null,
              writable: false,
            };
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }
          return [{ name: "dynamic.txt", type: "file" }];
        },
        async read() {
          readCount += 1;
          return Buffer.from("dynamic content");
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "virtual-filesystem-unknown-size",
    script: `
      set +e
      cat /sandbox/dynamic.txt >/dev/null 2>&1
      status=$?
      echo "status=$status"
      test "$status" != "0"
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `unknown-size file should fail closed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(readCount, 0);
});

test("virtual filesystem handles larger file reads without truncation", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const contents = Buffer.alloc(512 * 1024, "L");
  const vm = await spawnSandbox({
    name: "virtual-filesystem-large-read",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return directoryStat(false);
          }
          if (path === "/sandbox.bin") {
            return fileStat(contents.byteLength, false);
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }
          return [{ name: "large.bin", type: "file" }];
        },
        async read(input) {
          const offset = input.range?.offset ?? 0;
          const length = input.range?.length ?? contents.byteLength - offset;
          return contents.subarray(offset, offset + length);
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "virtual-filesystem-large-read",
    script: "wc -c < /sandbox/sandbox.bin",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(Number(result.stdout.trim()), contents.byteLength);
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

function createDirectoryOnlyFileSystem(
  rootEntries: readonly string[],
): SandboxWritableFileSystem {
  return {
    async stat(path) {
      if (path === "/" || rootEntries.includes(path.slice(1))) {
        return directoryStat(true);
      }
      throw new Error(`missing path ${path}`);
    },
    async list(path) {
      if (path !== "/") {
        throw new Error(`missing directory ${path}`);
      }
      return rootEntries.map((name): SandboxDirectoryEntry => ({
        name,
        type: "directory",
      }));
    },
    async read(input) {
      throw new Error(`not a file ${input.path}`);
    },
    async createFile(path) {
      throw new Error(`cannot create file ${path}`);
    },
    async write(input) {
      throw new Error(`cannot write file ${input.path}`);
    },
    async truncate(path) {
      throw new Error(`cannot truncate file ${path}`);
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
