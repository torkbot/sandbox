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
import { collectAsync } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("writable virtual filesystem supports nested directories and atomic rename", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createPosixMemoryFileSystem();
  const vm = await spawnSandbox({
    name: "vfs-posix-rename",
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

  const result = await execGuestShell(vm, {
    id: "vfs-posix-rename",
    script: `
      set -eu
      mkdir -p /workspace/src/lib
      printf 'export const value = 1;\\n' > /workspace/src/lib/value.tmp
      mv /workspace/src/lib/value.tmp /workspace/src/lib/value.ts
      test ! -e /workspace/src/lib/value.tmp
      test "$(cat /workspace/src/lib/value.ts)" = "export const value = 1;"
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest nested directory/rename operations failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.deepEqual(await fileSystem.list("/src/lib"), [
    { name: "value.ts", type: "file" },
  ]);
});

test("writable virtual filesystem supports unlink and empty directory removal", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createPosixMemoryFileSystem();
  await fileSystem.mkdir("/tmp");
  await fileSystem.createFile("/tmp/remove-me.txt");
  await fileSystem.write({
    path: "/tmp/remove-me.txt",
    offset: 0,
    contents: Buffer.from("remove me"),
  });

  const vm = await spawnSandbox({
    name: "vfs-posix-unlink",
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

  const result = await execGuestShell(vm, {
    id: "vfs-posix-unlink",
    script: `
      set -eu
      rm /workspace/tmp/remove-me.txt
      rmdir /workspace/tmp
      test ! -e /workspace/tmp
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest unlink/rmdir operations failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  await assert.rejects(fileSystem.stat("/tmp"), /missing path/);
});

test("writable virtual filesystem supports symlink metadata without host path escape", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createPosixMemoryFileSystem();
  await fileSystem.mkdir("/src");
  await fileSystem.createFile("/src/target.txt");
  await fileSystem.write({
    path: "/src/target.txt",
    offset: 0,
    contents: Buffer.from("target"),
  });

  const vm = await spawnSandbox({
    name: "vfs-posix-symlink",
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

  const result = await execGuestShell(vm, {
    id: "vfs-posix-symlink",
    script: `
      set -eu
      ln -s target.txt /workspace/src/link.txt
      test "$(readlink /workspace/src/link.txt)" = "target.txt"
      test "$(cat /workspace/src/link.txt)" = "target"
      ln -s /etc/passwd /workspace/src/host-escape
      test "$(readlink /workspace/src/host-escape)" = "/etc/passwd"
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest symlink operations failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(await fileSystem.readlink("/src/link.txt"), "target.txt");
  assert.equal(await fileSystem.readlink("/src/host-escape"), "/etc/passwd");
});

test("writable virtual filesystem preserves POSIX rename edge semantics", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const fileSystem = createPosixMemoryFileSystem();
  await fileSystem.mkdir("/src");
  await fileSystem.mkdir("/tree");
  await fileSystem.mkdir("/non-empty");
  await fileSystem.createFile("/non-empty/child.txt");
  await fileSystem.write({
    path: "/non-empty/child.txt",
    offset: 0,
    contents: Buffer.from("child"),
  });
  await fileSystem.createFile("/src/current.txt");
  await fileSystem.write({
    path: "/src/current.txt",
    offset: 0,
    contents: Buffer.from("old"),
  });
  await fileSystem.createFile("/src/next.txt");
  await fileSystem.write({
    path: "/src/next.txt",
    offset: 0,
    contents: Buffer.from("new"),
  });
  await fileSystem.createFile("/tree/child.txt");
  await fileSystem.write({
    path: "/tree/child.txt",
    offset: 0,
    contents: Buffer.from("cached child"),
  });

  const vm = await spawnSandbox({
    name: "vfs-posix-rename-edges",
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

  const result = await execGuestShell(vm, {
    id: "vfs-posix-rename-edges",
    script: `
      set -eu
      mv /workspace/src/next.txt /workspace/src/current.txt
      test "$(cat /workspace/src/current.txt)" = "new"
      test ! -e /workspace/src/next.txt
      mkdir /workspace/empty
      if mv -T /workspace/empty /workspace/non-empty 2>/run/rename-non-empty.err; then
        exit 10
      fi
      test -d /workspace/empty
      test "$(cat /workspace/non-empty/child.txt)" = "child"
      ls /workspace/tree/child.txt >/dev/null
      mv /workspace/tree /workspace/renamed-tree
      test "$(cat /workspace/renamed-tree/child.txt)" = "cached child"
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest rename edge operations failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.deepEqual(await fileSystem.list("/src"), [
    { name: "current.txt", type: "file" },
  ]);
  assert.deepEqual(
    new TextDecoder().decode(await fileSystem.read({
      path: "/src/current.txt",
      signal: new AbortController().signal,
    })),
    "new",
  );
});

type PosixMemoryFileSystem = SandboxWritableFileSystem & {
  mkdir(path: string): Promise<SandboxFileStat>;
  unlink(path: string): Promise<void>;
  rmdir(path: string): Promise<void>;
  rename(from: string, to: string): Promise<void>;
  symlink(target: string, path: string): Promise<SandboxFileStat>;
  readlink(path: string): Promise<string>;
};

type Entry =
  | { readonly type: "directory" }
  | { readonly type: "file"; readonly contents: Uint8Array }
  | { readonly type: "symlink"; readonly target: string };

function createPosixMemoryFileSystem(): PosixMemoryFileSystem {
  const entries = new Map<string, Entry>([["/", { type: "directory" }]]);
  const read = async (input: {
    readonly path: string;
    readonly range?: {
      readonly offset: number;
      readonly length: number;
    };
  }): Promise<Uint8Array> => {
    const normalized = normalizePath(input.path);
    const entry = entries.get(normalized);
    if (entry?.type === "symlink") {
      return await read({
        ...input,
        path: resolveSymlinkParent(normalized, entry.target),
      });
    }
    if (entry?.type !== "file") {
      throw new Error(`missing file ${input.path}`);
    }
    const offset = input.range?.offset ?? 0;
    const length = input.range?.length ?? entry.contents.byteLength - offset;
    return entry.contents.slice(offset, offset + length);
  };

  return {
    async stat(path) {
      const entry = entries.get(normalizePath(path));
      if (entry === undefined) {
        throw new Error(`missing path ${path}`);
      }
      if (entry.type === "directory") {
        return directoryStat(true);
      }
      if (entry.type === "symlink") {
        return symlinkStat(entry.target.length);
      }
      return fileStat(entry.contents.byteLength, true);
    },
    async list(path) {
      const normalized = normalizePath(path);
      const entry = entries.get(normalized);
      if (entry?.type !== "directory") {
        throw new Error(`missing directory ${path}`);
      }

      const prefix = normalized === "/" ? "/" : `${normalized}/`;
      const children: SandboxDirectoryEntry[] = [];
      for (const [entryPath, child] of entries) {
        if (entryPath === normalized || !entryPath.startsWith(prefix)) {
          continue;
        }
        const name = entryPath.slice(prefix.length);
        if (name.includes("/")) {
          continue;
        }
        children.push({
          name,
          type: child.type === "directory" ? "directory" : "file",
        });
      }
      return children.sort((left, right) => left.name.localeCompare(right.name));
    },
    read,
    async createFile(path) {
      const normalized = normalizePath(path);
      assertParentDirectory(entries, normalized);
      entries.set(normalized, { type: "file", contents: new Uint8Array() });
      return fileStat(0, true);
    },
    async write(input) {
      const normalized = normalizePath(input.path);
      const entry = entries.get(normalized);
      if (entry?.type !== "file") {
        throw new Error(`missing file ${input.path}`);
      }
      const nextLength = Math.max(entry.contents.byteLength, input.offset + input.contents.byteLength);
      const next = new Uint8Array(nextLength);
      next.set(entry.contents);
      next.set(input.contents, input.offset);
      entries.set(normalized, { type: "file", contents: next });
      return input.contents.byteLength;
    },
    async truncate(path, size) {
      const normalized = normalizePath(path);
      const entry = entries.get(normalized);
      if (entry?.type !== "file") {
        throw new Error(`missing file ${path}`);
      }
      const next = new Uint8Array(size);
      next.set(entry.contents.slice(0, size));
      entries.set(normalized, { type: "file", contents: next });
      return fileStat(size, true);
    },
    async mkdir(path) {
      const normalized = normalizePath(path);
      assertParentDirectory(entries, normalized);
      entries.set(normalized, { type: "directory" });
      return directoryStat(true);
    },
    async unlink(path) {
      const normalized = normalizePath(path);
      const entry = entries.get(normalized);
      if (entry === undefined || entry.type === "directory") {
        throw new Error(`missing file ${path}`);
      }
      entries.delete(normalized);
    },
    async rmdir(path) {
      const normalized = normalizePath(path);
      if (entries.get(normalized)?.type !== "directory") {
        throw new Error(`missing directory ${path}`);
      }
      const prefix = `${normalized}/`;
      if ([...entries.keys()].some((entryPath) => entryPath.startsWith(prefix))) {
        throw new Error(`directory not empty ${path}`);
      }
      entries.delete(normalized);
    },
    async rename(from, to) {
      const normalizedFrom = normalizePath(from);
      const normalizedTo = normalizePath(to);
      const entry = entries.get(normalizedFrom);
      if (entry === undefined) {
        throw new Error(`missing path ${from}`);
      }
      assertParentDirectory(entries, normalizedTo);
      const target = entries.get(normalizedTo);
      if (target?.type === "directory") {
        const prefix = `${normalizedTo}/`;
        if ([...entries.keys()].some((entryPath) => entryPath.startsWith(prefix))) {
          throw new Error(`directory not empty ${to}`);
        }
      }
      entries.delete(normalizedFrom);
      entries.set(normalizedTo, entry);
      if (entry.type === "directory") {
        const fromPrefix = `${normalizedFrom}/`;
        const moved = [...entries.entries()]
          .filter(([entryPath]) => entryPath.startsWith(fromPrefix))
          .map(([entryPath, child]) => [
            `${normalizedTo}/${entryPath.slice(fromPrefix.length)}`,
            child,
            entryPath,
          ] as const);
        for (const [nextPath, child, previousPath] of moved) {
          entries.delete(previousPath);
          entries.set(nextPath, child);
        }
      }
    },
    async symlink(target, path) {
      const normalized = normalizePath(path);
      assertParentDirectory(entries, normalized);
      entries.set(normalized, { type: "symlink", target });
      return symlinkStat(target.length);
    },
    async readlink(path) {
      const entry = entries.get(normalizePath(path));
      if (entry?.type !== "symlink") {
        throw new Error(`not a symlink ${path}`);
      }
      return entry.target;
    },
  };
}

function normalizePath(path: string): string {
  if (path === "" || path === "/") {
    return "/";
  }
  return `/${path.split("/").filter(Boolean).join("/")}`;
}

function assertParentDirectory(entries: Map<string, Entry>, path: string): void {
  const parent = path.slice(0, path.lastIndexOf("/")) || "/";
  if (entries.get(parent)?.type !== "directory") {
    throw new Error(`missing parent directory ${parent}`);
  }
}

function resolveSymlinkParent(path: string, target: string): string {
  if (target.startsWith("/")) {
    throw new Error(`absolute symlink target cannot escape virtual filesystem: ${target}`);
  }
  const parent = path.slice(0, path.lastIndexOf("/")) || "/";
  return normalizePath(`${parent}/${target}`);
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

function symlinkStat(sizeBytes: number): SandboxFileStat {
  return {
    type: "symlink",
    sizeBytes,
    mediaType: null,
    modifiedAtMs: null,
    writable: true,
  };
}
