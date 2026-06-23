import test from "node:test";
import assert from "node:assert/strict";
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  type SandboxFileSystem,
  type SandboxBlockStore,
  type SandboxEnvironmentFact,
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

test("fs.bind creates an explicit host directory mount source", () => {
  assert.deepEqual(fs.bind({
    source: "/tmp/sandbox-workspace",
    access: "ro",
  }), {
    kind: "host-directory",
    source: "/tmp/sandbox-workspace",
    access: "ro",
  });
});

test("fs.bind groups masked host paths under the bind source", () => {
  const storage = fs.bind({
    source: "/tmp/sandbox-mask-storage",
    access: "rw",
  });

  assert.deepEqual(fs.bind({
    source: "/tmp/sandbox-workspace",
    access: "ro",
    mask: {
      paths: ["/node_modules", "/.git"],
    },
  }), {
    kind: "host-directory",
    source: "/tmp/sandbox-workspace",
    access: "ro",
    mask: {
      paths: ["/node_modules", "/.git"],
    },
  });

  assert.deepEqual(fs.bind({
    source: "/tmp/sandbox-workspace",
    access: "rw",
    mask: {
      paths: ["/node_modules"],
      storage,
    },
  }), {
    kind: "host-directory",
    source: "/tmp/sandbox-workspace",
    access: "rw",
    mask: {
      paths: ["/node_modules"],
      storage,
    },
  });
});

test("rootfs.cow couples a built-in base with writable block storage", () => {
  const blockStore = memoryBlockStore();
  const composed = rootfs.compose({
    base: rootfs.builtIn("alpine:3.23"),
    overlay: blockStore,
  });

  assert.deepEqual(composed, {
    kind: "composed-rootfs",
    base: {
      kind: "built-in-rootfs",
      name: "alpine:3.23",
    },
    overlay: blockStore,
  });

  assert.deepEqual(rootfs.cow({
    base: rootfs.builtIn("alpine:3.23"),
    writable: blockStore,
  }), {
    kind: "cow-rootfs",
    source: composed,
  });
});

test("rootfs.cow accepts a composed rootfs source", () => {
  const blockStore = memoryBlockStore();
  const source = rootfs.compose({
    base: rootfs.builtIn("alpine:3.23"),
    overlay: blockStore,
  });

  assert.deepEqual(rootfs.cow({ source }), {
    kind: "cow-rootfs",
    source,
  });
});

test("rootfs.ephemeral makes writable rootfs persistence explicit", () => {
  assert.deepEqual(rootfs.ephemeral({
    base: rootfs.builtIn("alpine:3.23"),
    maxDirtyBytes: 64 * 1024,
  }), {
    kind: "ephemeral-rootfs",
    base: rootfs.builtIn("alpine:3.23"),
    maxDirtyBytes: 64 * 1024,
  });
});

test("rootfs.persistent creates a file-backed persistent built-in rootfs reference", () => {
  assert.deepEqual(rootfs.persistent({
    base: rootfs.builtIn("alpine:3.23"),
    path: "/tmp/sandbox-rootfs.qcow2",
  }), {
    kind: "persistent-rootfs",
    base: rootfs.builtIn("alpine:3.23"),
    path: "/tmp/sandbox-rootfs.qcow2",
  });
});

test("defineSandbox exposes config-derived environment facts", () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.ephemeral({
      base: rootfs.builtIn("alpine:3.23"),
    }),
    network: network.policy((conn) => {
      conn.accept();
    }),
  });

  const facts = sandbox.environmentFacts();
  const first = facts[0];

  assert.notEqual(first, undefined);

  if (first === undefined) {
    throw new Error("expected at least one environment fact");
  }

  const typedFirst: SandboxEnvironmentFact = first;

  assert.equal(typedFirst.source, "config");
  assert.deepEqual(facts, [
    {
      source: "config",
      topic: "rootfs-image",
      relation: "is",
      value: "alpine:3.23",
    },
    {
      source: "config",
      topic: "distro",
      relation: "is",
      value: "alpine",
    },
    {
      source: "config",
      topic: "distro-version",
      relation: "is",
      value: "3.23",
    },
    {
      source: "config",
      topic: "package-manager",
      relation: "is",
      value: "apk",
    },
    {
      source: "config",
      topic: "shell",
      relation: "is",
      value: "/bin/sh",
    },
    {
      source: "config",
      topic: "rootfs",
      relation: "write-mode",
      value: "writable-ephemeral",
    },
    {
      source: "config",
      topic: "network-egress",
      relation: "requires",
      value: "policy-grant",
    },
  ]);
});

test("environment facts distinguish rootfs and network semantics", () => {
  const readonlyFacts = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).environmentFacts();
  const cowFacts = defineSandbox({
    rootfs: rootfs.cow({
      base: rootfs.builtIn("alpine:3.23"),
      writable: memoryBlockStore(),
    }),
  }).environmentFacts();
  const persistentFacts = defineSandbox({
    rootfs: rootfs.persistent({
      base: rootfs.builtIn("alpine:3.23"),
      path: "/tmp/sandbox-rootfs.qcow2",
    }),
  }).environmentFacts();

  assertIncludesFact(readonlyFacts, {
    source: "config",
    topic: "rootfs",
    relation: "write-mode",
    value: "read-only",
  });
  assertIncludesFact(readonlyFacts, {
    source: "config",
    topic: "network-egress",
    relation: "is",
    value: "not-configured",
  });
  assertIncludesFact(readonlyFacts, {
    source: "config",
    topic: "command",
    relation: "exists",
    value: "git",
  });
  assertIncludesFact(cowFacts, {
    source: "config",
    topic: "rootfs",
    relation: "write-mode",
    value: "writable-persistent-cow",
  });
  assertIncludesFact(persistentFacts, {
    source: "config",
    topic: "rootfs",
    relation: "write-mode",
    value: "writable-persistent-file",
  });
  assertDoesNotIncludeFact(cowFacts, {
    source: "config",
    topic: "command",
    relation: "exists",
    value: "git",
  });
  assertDoesNotIncludeFact(persistentFacts, {
    source: "config",
    topic: "command",
    relation: "exists",
    value: "git",
  });
});

test("rootfs.cow can be called without binding rootfs as this", () => {
  const blockStore = memoryBlockStore();
  const { cow } = rootfs;

  assert.deepEqual(cow({
    base: rootfs.builtIn("alpine:3.23"),
    writable: blockStore,
  }), {
    kind: "cow-rootfs",
    source: {
      kind: "composed-rootfs",
      base: rootfs.builtIn("alpine:3.23"),
      overlay: blockStore,
    },
  });
});

test("rootfs.flatten requires an explicit destination block store", async () => {
  const blockStore = memoryBlockStore();
  const source = rootfs.compose({
    base: rootfs.builtIn("alpine:3.23"),
    overlay: blockStore,
  });

  await assert.rejects(
    rootfs.flatten({
      format: "qcow2",
      source,
      dest: {
        ...memoryBlockStore(),
        blockSize: 123,
      },
    }),
    /invalid rootfs image destination: blockSize must be a positive multiple of 512/,
  );
});

test("rootfs.bytes validates byte stream options", async () => {
  await assert.rejects(
    async () => {
      for await (const _chunk of rootfs.bytes(rootfs.builtIn("alpine:3.23"), {
        chunkSize: 0,
      })) {
        break;
      }
    },
    /invalid rootfs bytes options: chunkSize must be a positive safe integer/,
  );
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

test("boot rejects invalid hostnames before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({ hostname: "" }),
    /invalid sandbox boot options: hostname must not be empty/,
  );
  await assert.rejects(
    sandbox.boot({ hostname: "a".repeat(65) }),
    /invalid sandbox boot options: hostname must be at most 64 characters/,
  );
  await assert.rejects(
    sandbox.boot({ hostname: "-agent" }),
    /invalid sandbox boot options: hostname must be a valid hostname/,
  );
  await assert.rejects(
    sandbox.boot({ hostname: "agent..example" }),
    /invalid sandbox boot options: hostname must be a valid hostname/,
  );
  await assert.rejects(
    sandbox.boot({ hostname: "agent.-bad" }),
    /invalid sandbox boot options: hostname must be a valid hostname/,
  );
});

test("defineSandbox accepts COW rootfs", () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.cow({
      base: rootfs.builtIn("alpine:3.23"),
      writable: memoryBlockStore(),
      maxDirtyBytes: 64 * 1024,
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

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.cow({
        base: rootfs.builtIn("alpine:3.23"),
        writable: memoryBlockStore(),
        maxDirtyBytes: 1024,
      }),
    }),
    /invalid sandbox definition: rootfs COW maxDirtyBytes must be at least the COW block size/,
  );
});

test("network.policy creates an opaque connection policy", () => {
  const policy = network.policy(async (conn) => {
    conn.accept();
    conn.matchDns()?.accept();
    conn.matchDns()?.accept({ resolvers: ["8.8.8.8", { ip: "8.8.4.4", port: 53 }] });
    // @ts-expect-error DNS matching is argumentless.
    conn.matchDns("1.1.1.1");
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

function assertIncludesFact(
  facts: readonly SandboxEnvironmentFact[],
  expected: SandboxEnvironmentFact,
): void {
  assert.ok(
    facts.some((fact) => {
      return fact.source === expected.source
        && fact.topic === expected.topic
        && fact.relation === expected.relation
        && fact.value === expected.value;
    }),
    `expected environment fact ${JSON.stringify(expected)} in ${JSON.stringify(facts)}`,
  );
}

function assertDoesNotIncludeFact(
  facts: readonly SandboxEnvironmentFact[],
  expected: SandboxEnvironmentFact,
): void {
  assert.equal(
    facts.some((fact) => {
      return fact.source === expected.source
        && fact.topic === expected.topic
        && fact.relation === expected.relation
        && fact.value === expected.value;
    }),
    false,
    `unexpected environment fact ${JSON.stringify(expected)} in ${JSON.stringify(facts)}`,
  );
}

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
