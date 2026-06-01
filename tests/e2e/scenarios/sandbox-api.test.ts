import assert from "node:assert/strict";
import test from "node:test";
import {
  defineSandbox,
  fs,
  rootfs,
  type SandboxBlockStore,
} from "../../../src/index.ts";
import { requireHostArtifact, requireVmLaunchSupport } from "../support/capabilities.ts";

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

test("boot configures the default guest hostname", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", ["-lc", "hostname && cat /etc/hostname"]);

  assert.equal(
    result.exitCode,
    0,
    `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.stdout, "sandbox\nsandbox\n");
  assert.equal(result.stderr, "");
});

test("boot accepts an instance-specific guest hostname", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot({
    hostname: "agent-42",
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "hostname",
      "cat /etc/hostname",
      "python3 - <<'PY'",
      "import socket",
      "print(socket.gethostbyname(socket.gethostname()))",
      "PY",
    ].join("\n"),
  ]);

  assert.equal(
    result.exitCode,
    0,
    `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.stdout, "agent-42\nagent-42\n127.0.0.1\n");
  assert.equal(result.stderr, "");
});

test("guest init provides baseline Linux facilities", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", ["-lc", [
    "ip addr show lo | grep -q '127.0.0.1/8'",
    "python3 - <<'PY'",
    "import socket",
    "listener = socket.socket()",
    "listener.bind(('127.0.0.1', 0))",
    "listener.listen(1)",
    "client = socket.create_connection(('127.0.0.1', listener.getsockname()[1]), timeout=3)",
    "accepted, _ = listener.accept()",
    "client.sendall(b'ok')",
    "print(accepted.recv(2).decode())",
    "accepted.close()",
    "client.close()",
    "listener.close()",
    "PY",
    "grep -q 'devpts /dev/pts devpts' /proc/mounts",
    "python3 - <<'PY'",
    "import os, pty",
    "master, slave = pty.openpty()",
    "os.close(master)",
    "os.close(slave)",
    "PY",
    "grep -q 'tmpfs /dev/shm tmpfs' /proc/mounts",
    "printf shm >/dev/shm/sandbox-init-probe",
    "test \"$(cat /dev/shm/sandbox-init-probe)\" = shm",
    "if grep -qw mqueue /proc/filesystems; then grep -q 'mqueue /dev/mqueue mqueue' /proc/mounts; fi",
    "grep -q 'cgroup2 /sys/fs/cgroup cgroup2' /proc/mounts",
    "python3 - <<'PY'",
    "import os, subprocess, time",
    "subprocess.run(['/bin/sh', '-c', 'sleep 0.1 &'], check=True)",
    "time.sleep(0.5)",
    "zombies = []",
    "for name in os.listdir('/proc'):",
    "    if not name.isdigit():",
    "        continue",
    "    try:",
    "        stat = open(f'/proc/{name}/stat').read()",
    "    except FileNotFoundError:",
    "        continue",
    "    suffix = stat.rsplit(')', 1)[1].strip().split()",
    "    state, ppid = suffix[0], suffix[1]",
    "    if state == 'Z' and ppid == '1':",
    "        zombies.append(name)",
    "assert not zombies, zombies",
    "PY",
  ].join("\n")]);

  assert.equal(
    result.exitCode,
    0,
    `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.match(result.stdout, /^ok\n/);
  assert.equal(result.stderr, "");
});

test("buffered exec timeout terminates guest process", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", ["-lc", "sleep 5"], {
    timeoutMs: 250,
  });

  assert.equal(result.exitCode, 124);
  assert.match(result.stderr, /sandbox exec timed out after 250ms/);

  const followup = await sandbox.exec("/bin/sh", ["-lc", "printf ok"]);
  assert.equal(followup.stdout, "ok");
});

test("buffered exec abort terminates guest process and leaves control usable", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const abort = new AbortController();
  const exec = sandbox.exec("/bin/sh", ["-lc", "sleep 5"], {
    signal: abort.signal,
  });

  abort.abort();
  await assert.rejects(exec, { name: "AbortError" });

  const followup = await sandbox.exec("/bin/sh", ["-lc", "printf ok"]);
  assert.equal(followup.stdout, "ok");
});

test("buffered exec abort terminates descendants holding output pipes open", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const marker = "/tmp/abort-descendant-survived";
  const abort = new AbortController();
  const exec = sandbox.exec("/bin/sh", [
    "-lc",
    `rm -f ${marker}; sh -c 'sleep 2; touch ${marker}' &`,
  ], {
    signal: abort.signal,
  });

  await new Promise((resolve) => setTimeout(resolve, 100));
  abort.abort();
  await assert.rejects(exec, { name: "AbortError" });

  await sandbox.exec("/bin/sleep", ["3"]);
  const followup = await sandbox.exec("/bin/sh", ["-lc", `test ! -e ${marker}`]);
  assert.equal(followup.exitCode, 0, followup.stderr);
});

test("buffered exec calls overlap without blocking the control plane", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const slow = sandbox.exec("/bin/sh", ["-lc", "sleep 1; printf slow"]);
  const fast = sandbox.exec("/bin/sh", ["-lc", "printf fast"]);

  assert.equal((await fast).stdout, "fast");
  assert.equal((await slow).stdout, "slow");
});

test("buffered exec timeout returns when descendant keeps output pipes open", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const started = Date.now();
  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "command -v setsid >/dev/null; setsid sh -c 'sleep 5' & sleep 5",
  ], {
    timeoutMs: 250,
  });
  const elapsedMs = Date.now() - started;

  assert.equal(result.exitCode, 124);
  assert.match(result.stderr, /sandbox exec timed out after 250ms/);
  assert.ok(elapsedMs < 2_000, `timeout returned after ${elapsedMs}ms`);
});

test("buffered exec closes stdin for commands that read input", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/cat");

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
});

test("buffered exec timeout includes output drain time", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const started = Date.now();
  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "sleep 5 & exit 0",
  ], {
    timeoutMs: 250,
  });
  const elapsedMs = Date.now() - started;

  assert.equal(result.exitCode, 124);
  assert.match(result.stderr, /sandbox exec timed out after 250ms/);
  assert.ok(elapsedMs < 2_000, `timeout returned after ${elapsedMs}ms`);
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
      "test -x /usr/lib/sandbox/install-http-ca",
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
      maxDirtyBytes: 128 * 1024,
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

test("built-in rootfs exposes enough guest disk space for agent workloads", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  }).boot();

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "df -Pk / | awk 'NR == 2 { print $2 }'",
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.ok(Number(result.stdout.trim()) >= 6 * 1024 * 1024, result.stdout);
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

test("COW rootfs can be flattened to a QCOW2 image stream", async (t) => {
  if (!requireHostArtifact(t)) {
    return;
  }

  const overlay = memoryBlockStore();
  const dest = memoryBlockStore();
  const source = rootfs.compose({
    base: rootfs.builtIn("alpine:3.23"),
    overlay,
  });

  const image = await rootfs.flatten({
    format: "qcow2",
    source,
    dest,
    clusterSize: 65536,
  });
  const chunks = [];
  for await (const chunk of rootfs.bytes(image, {
    chunkSize: 4,
    signal: AbortSignal.timeout(5_000),
  })) {
    chunks.push(chunk);
    break;
  }

  assert.equal(image.format, "qcow2");
  assert.ok(image.sizeBytes > 0n);
  assert.deepEqual(chunks[0], new Uint8Array([0x51, 0x46, 0x49, 0xfb]));
  assert.equal(dest.observedBaseIdentities().length, 1);
  assert.match(dest.observedBaseIdentities()[0] ?? "", /^rootfs-image:qcow2:/);
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
