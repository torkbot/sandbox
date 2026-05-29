import test from "node:test";
import assert from "node:assert/strict";
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  type SandboxFileSystem,
  type SandboxBlockStore,
  type SandboxWritableFileSystem,
} from "../../src/index.ts";

test("rootfs.builtIn creates a typed built-in rootfs reference", () => {
  assert.deepEqual(rootfs.builtIn("alpine:3.23"), {
    kind: "built-in-rootfs",
    name: "alpine:3.23",
  });
});

test("fs.virtual wraps user-space filesystems for mounts", () => {
  const fileSystem = writableFileSystem();

  assert.deepEqual(fs.virtual(fileSystem), {
    kind: "virtual-fs",
    fileSystem,
  });
});

test("rootfs.cow couples a built-in base with writable block storage", () => {
  const blockStore = memoryBlockStore();

  assert.deepEqual(rootfs.cow({
    base: rootfs.builtIn("alpine:3.23"),
    writable: blockStore,
  }), {
    kind: "cow-rootfs",
    base: {
      kind: "built-in-rootfs",
      name: "alpine:3.23",
    },
    writable: blockStore,
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

  await fileSystem.setxattr("/linked.txt", "trusted.example", new Uint8Array([1, 2, 3]));
  assert.deepEqual(await fileSystem.listxattr("/source.txt"), ["trusted.example"]);
  assert.deepEqual(
    await fileSystem.getxattr("/source.txt", "trusted.example"),
    new Uint8Array([1, 2, 3]),
  );
});

test("fs.memory rejects unsupported rename flags before mutating entries", async () => {
  const fileSystem = fs.memory({
    files: {
      "/source.txt": "source",
      "/target.txt": "target",
    },
  });

  await assert.rejects(fileSystem.rename("/source.txt", "/target.txt", 2), /unsupported rename flags: 2/);
  await assert.rejects(fileSystem.rename("/source.txt", "/target.txt", 4), /unsupported rename flags: 4/);

  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/source.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "source",
  );
  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/target.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "target",
  );
});

test("fs.memory reports symlink target size and refuses replacement", async () => {
  const fileSystem = fs.memory({
    files: {
      "/existing.txt": "existing",
    },
  });

  const stat = await fileSystem.symlink("target.txt", "/link.txt");

  assert.equal(stat.type, "symlink");
  assert.equal(stat.sizeBytes, new TextEncoder().encode("target.txt").byteLength);
  assert.equal((await fileSystem.stat("/link.txt")).sizeBytes, stat.sizeBytes);
  await assert.rejects(
    fileSystem.symlink("target.txt", "/existing.txt"),
    /path exists: \/existing\.txt/,
  );
});

test("fs.memory refuses missing parent directories for POSIX mutations", async () => {
  const fileSystem = fs.memory({
    files: {
      "/source.txt": "source",
    },
  });

  await assert.rejects(fileSystem.createFile("/missing/file.txt"), /not found: \/missing/);
  await assert.rejects(fileSystem.mkdir("/missing/dir"), /not found: \/missing/);
  await assert.rejects(fileSystem.rename("/source.txt", "/missing/source.txt"), /not found: \/missing/);
  await assert.rejects(fileSystem.link("/source.txt", "/missing/source.txt"), /not found: \/missing/);
  await assert.rejects(fileSystem.symlink("source.txt", "/missing/link.txt"), /not found: \/missing/);
});

test("fs.memory rejects invalid rename replacements", async () => {
  const fileSystem = fs.memory({
    files: {
      "/file.txt": "file",
      "/target.txt": "target",
      "/dir/child.txt": "child",
      "/empty/.keep": "",
    },
  });
  await fileSystem.mkdir("/empty-dir");

  await assert.rejects(fileSystem.rename("/file.txt", "/dir"), /is a directory: \/dir/);
  await assert.rejects(fileSystem.rename("/dir", "/target.txt"), /not a directory: \/target\.txt/);
  await assert.rejects(fileSystem.rename("/empty-dir", "/dir"), /directory not empty: \/dir/);
});

test("fs.memory treats same-node renames as no-ops", async () => {
  const fileSystem = fs.memory({
    files: {
      "/dir/child.txt": "child",
      "/file.txt": "file",
    },
  });
  await fileSystem.link("/file.txt", "/linked.txt");

  await fileSystem.rename("/dir", "/dir");
  await fileSystem.rename("/file.txt", "/linked.txt");

  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/dir/child.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "child",
  );
  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/file.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "file",
  );
  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/linked.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "file",
  );
});

test("fs.memory rejects directory renames into their own subtree", async () => {
  const fileSystem = fs.memory({
    files: {
      "/a/b/file.txt": "file",
    },
  });

  await assert.rejects(fileSystem.rename("/a", "/a/b/c"), /invalid rename target: \/a\/b\/c/);

  assert.equal(
    new TextDecoder().decode(await fileSystem.read({
      path: "/a/b/file.txt",
      signal: AbortSignal.timeout(1_000),
    })),
    "file",
  );
});

test("defineSandbox accepts resource limits", () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    resources: {
      cpus: 2,
      memoryMiB: 1024,
    },
  });

  assert.equal(typeof sandbox.boot, "function");
});

test("defineSandbox accepts COW rootfs", () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.cow({
      base: rootfs.builtIn("alpine:3.23"),
      writable: memoryBlockStore(),
    }),
  });

  assert.equal(typeof sandbox.boot, "function");
});

test("defineSandbox rejects invalid COW rootfs block store", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.cow({
        base: rootfs.builtIn("alpine:3.23"),
        writable: {
          ...memoryBlockStore(),
          blockSize: 1_000,
        },
      }),
    }),
    /invalid sandbox definition: rootfs COW block size must be a multiple of 512 bytes/,
  );
});

test("network.policy creates an opaque connection policy", () => {
  const policy = network.policy(async (conn) => {
    conn.accept();
    conn.matchDns("1.1.1.1")?.accept();
    conn.matchDns("1.1.1.1")?.accept({ resolvers: ["8.8.8.8", { ip: "8.8.4.4", port: 53 }] });
    conn.matchDns((dns) => dns.dst.port === 53)?.accept();
    conn.matchHttp("api.example.com")?.accept();
    conn.matchHttp((http) => http.hostname === "api.example.com")?.accept();

    if (conn.transport === "tcp") {
      conn.acceptHttp();
      conn.matchTcp("203.0.113.10:5432")?.accept();
      conn.matchTcp((tcp) => tcp.dst.port === 5432)?.accept();
      // @ts-expect-error UDP matching is UDP-only.
      conn.matchUdp("203.0.113.10:8125");
    }
    if (conn.transport === "udp") {
      conn.matchUdp("203.0.113.10:8125")?.accept();
      conn.matchUdp((udp) => udp.dst.port === 8125)?.accept();
      // @ts-expect-error HTTP enforcement is TCP-only.
      conn.acceptHttp();
      // @ts-expect-error TCP matching is TCP-only.
      conn.matchTcp("203.0.113.10:5432");
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

function memoryBlockStore(): SandboxBlockStore {
  const blocks = new Map<bigint, Uint8Array>();
  return {
    blockSize: 4096,
    async list() {
      return Array.from(blocks.keys());
    },
    async read(range) {
      const chunks = [];
      for (let offset = 0; offset < range.count; offset += 1) {
        const start = range.start + BigInt(offset);
        const data = blocks.get(start);
        if (data !== undefined) {
          chunks.push({ start, data });
        }
      }
      return chunks;
    },
    async write(chunks) {
      for (const chunk of chunks) {
        blocks.set(chunk.start, chunk.data);
      }
    },
  };
}
