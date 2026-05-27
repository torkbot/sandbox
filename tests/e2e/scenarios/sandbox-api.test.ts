import test from "node:test";
import assert from "node:assert/strict";
import {
  defineSandbox,
  fs,
  rootfs,
  storage,
  type SandboxBlockStore,
} from "../../../src/index.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("new public API boots a built-in rootfs and runs a process", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.20"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", ["-lc", "printf '%s' ready"]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "ready");
  assert.equal(result.stderr, "");
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
    rootfs: rootfs.builtIn("alpine:3.20"),
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
    rootfs: rootfs.builtIn("alpine:3.20"),
  }).boot({
    cwd: "/tmp",
  });

  const result = await sandbox.exec("/bin/pwd");

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.trim(), "/tmp");
});

test("COW block root storage round-trips rootfs mutations across instances", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const blockStore = memoryBlockStore();
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.20"),
    storage: storage.cow(blockStore),
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
});

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
