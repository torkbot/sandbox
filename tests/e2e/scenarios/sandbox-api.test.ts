import assert from "node:assert/strict";
import test from "node:test";
import {
  defineSandbox,
  fs,
  rootfs,
  type SandboxBlockStore,
} from "../../../src/index.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("new public API boots a built-in rootfs and runs a process", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", ["-lc", "printf '%s' ready"]);

  assert.equal(
    result.exitCode,
    0,
    `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.stdout, "ready");
  assert.equal(result.stderr, "");
});

test("built-in agent rootfs includes common agent runtimes and CLIs", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "gh --version | head -n1",
      "node --version",
      "npm --version",
      "python3 --version",
      "python3 -m pip --version",
    ].join(" && "),
  ]);

  assert.equal(
    result.exitCode,
    0,
    `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.match(result.stdout, /^gh version /m);
  assert.match(result.stdout, /^v24\./m);
  assert.match(result.stdout, /^11\./m);
  assert.match(result.stdout, /^Python 3\./m);
  assert.match(result.stdout, /^pip /m);
});

test("boot options provide instance-specific virtual mounts", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const laneFs = fs.memory({
    files: {
      "/note.txt": "lane-private",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    mounts: {
      "/mnt": fs.virtual(laneFs),
    },
  });

  const result = await sandbox.exec("/bin/cat", ["/mnt/note.txt"]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "lane-private");
});

test("boot cwd becomes the default process working directory", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    cwd: "/tmp",
  });

  const result = await sandbox.exec("/bin/pwd");

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.trim(), "/tmp");
});

test("COW rootfs round-trips rootfs mutations across instances", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const blockStore = memoryBlockStore();
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.cow({
      base: rootfs.builtIn("alpine:3.23"),
      writable: blockStore,
    }),
  });

  const first = await sandboxDefinition.boot();
  try {
    const write = await first.exec("/bin/sh", [
      "-lc",
      "printf '%s' persisted > /root/lane-state.txt && sync",
    ]);
    assert.equal(write.exitCode, 0, write.stderr);
  } finally {
    await first.close();
  }

  await using second = await sandboxDefinition.boot();
  const read = await second.exec("/bin/cat", ["/root/lane-state.txt"]);

  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "persisted");
  assert.deepEqual(blockStore.observedBaseIdentities().length, 1);
  assert.match(blockStore.observedBaseIdentities()[0] ?? "", /built-in:alpine:3\.23:qcow2:/);
});

test("COW rootfs close sync ignores the instance cwd", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const blockStore = memoryBlockStore();
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.cow({
      base: rootfs.builtIn("alpine:3.23"),
      writable: blockStore,
    }),
  });

  const first = await sandboxDefinition.boot({ cwd: "/tmp/close-cwd" });
  try {
    const prepare = await first.exec("/bin/mkdir", ["-p", "/tmp/close-cwd"], {
      cwd: "/",
    });
    assert.equal(prepare.exitCode, 0, prepare.stderr);
    const write = await first.exec("/bin/sh", [
      "-lc",
      "printf '%s' cwd-independent > /root/close-sync.txt",
    ]);
    assert.equal(write.exitCode, 0, write.stderr);
    const removeCwd = await first.exec("/bin/rm", ["-rf", "/tmp/close-cwd"], {
      cwd: "/",
    });
    assert.equal(removeCwd.exitCode, 0, removeCwd.stderr);
  } finally {
    await first.close();
  }

  await using second = await sandboxDefinition.boot();
  const read = await second.exec("/bin/cat", ["/root/close-sync.txt"]);

  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "cwd-independent");
});

function memoryBlockStore(): SandboxBlockStore & { observedBaseIdentities(): readonly string[] } {
  const blocks = new Map<bigint, Uint8Array>();
  const baseIdentities = new Set<string>();
  return {
    blockSize: 65536,
    async list(context) {
      baseIdentities.add(context.base);
      return Array.from(blocks.keys());
    },
    async read(range, context) {
      baseIdentities.add(context.base);
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
    async write(chunks, context) {
      baseIdentities.add(context.base);
      for (const chunk of chunks) {
        blocks.set(chunk.start, chunk.data);
      }
    },
    async flush(context) {
      baseIdentities.add(context.base);
    },
    observedBaseIdentities() {
      return Array.from(baseIdentities);
    },
  };
}
