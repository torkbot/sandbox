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

test("missing writable mount directories are created before mounting virtual filesystems", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const missingFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    mounts: {
      "/tmp/missing-mount": fs.virtual(missingFs),
    },
  });

  const result = await sandbox.exec("/bin/cat", ["/tmp/missing-mount/note.txt"]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "mounted\n");
});

test("top-level read-only rootfs mount directories fail with actionable init output", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const missingFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  await assert.rejects(
    defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.23"),
    }).boot({
      mounts: {
        "/missing-mount": fs.virtual(missingFs),
      },
    }),
    /virtual filesystem mount point parent is on durable rootfs: \/missing-mount/,
  );
});

test("missing COW rootfs mount directories do not persist synthetic rootfs paths", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const blockStore = memoryBlockStore();
  const missingFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.cow({
      base: rootfs.builtIn("alpine:3.23"),
      writable: blockStore,
    }),
  });

  await assert.rejects(
    sandboxDefinition.boot({
      mounts: {
        "/opt/cache": fs.virtual(missingFs),
      },
    }),
    /virtual filesystem mount point parent is on durable rootfs: \/opt\/cache/,
  );

  await using sandbox = await sandboxDefinition.boot();
  const result = await sandbox.exec("/bin/sh", ["-lc", "test ! -e /opt/cache"]);

  assert.equal(result.exitCode, 0, result.stderr);
});

test("ordered nested virtual mounts can use parent mount directories", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const workspace = fs.memory({
    files: {
      "/cache/.keep": "",
      "/note.txt": "workspace\n",
    },
  });
  const cache = fs.memory({
    files: {
      "/note.txt": "cache\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    mounts: {
      "/workspace": fs.virtual(workspace),
      "/workspace/cache": fs.virtual(cache),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "cat /workspace/note.txt /workspace/cache/note.txt",
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "workspace\ncache\n");
});

test("invalid rootfs mount targets fail with actionable init output", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const mountedFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  await assert.rejects(
    defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.23"),
    }).boot({
      mounts: {
        "/etc/passwd": fs.virtual(mountedFs),
      },
    }),
    /virtual filesystem mount point is not a directory: \/etc\/passwd/,
  );
});

test("virtual memory mounts can be used as the boot cwd", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const workspace = fs.memory({
    files: {
      "/hello.txt": "hi\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    cwd: "/workspace",
    mounts: {
      "/workspace": fs.virtual(workspace),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "printf 'cwd=%s\\n' \"$PWD\" && cat hello.txt && exit 7",
  ]);

  assert.equal(result.exitCode, 7, result.stderr);
  assert.equal(result.stdout, "cwd=/workspace\nhi\n");
  assert.equal(result.stderr, "");
});

test("virtual memory mounts support guest directory reads from root cwd", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const mount = fs.memory({
    files: {
      "/hello.txt": "hi\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    cwd: "/",
    mounts: {
      "/mnt": fs.virtual(mount),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "echo before && ls -1 /mnt && cat /mnt/hello.txt && exit 7",
  ]);

  assert.equal(result.exitCode, 7, result.stderr);
  assert.equal(result.stdout, "before\nhello.txt\nhi\n");
  assert.equal(result.stderr, "");
});

test("virtual memory mount paths may contain init delimiters", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    cwd: "/",
    mounts: {
      "/tmp/a=b": fs.virtual(fs.memory({
        files: {
          "/note.txt": "equals\n",
        },
      })),
      "/tmp/a;b": fs.virtual(fs.memory({
        files: {
          "/note.txt": "semicolon\n",
        },
      })),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "cat '/tmp/a=b/note.txt' '/tmp/a;b/note.txt'",
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "equals\nsemicolon\n");
  assert.equal(result.stderr, "");
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

function memoryBlockStore(): SandboxBlockStore & {
  observedBaseIdentities(): readonly string[];
  observedBlocks(): readonly bigint[];
} {
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
    observedBlocks() {
      return Array.from(blocks.keys());
    },
  };
}
