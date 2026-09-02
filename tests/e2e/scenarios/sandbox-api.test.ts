import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, open, readFile, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  SandboxBlobStorageError,
  storage,
  type SandboxBlockStore,
  type SandboxEnvironmentFact,
  type RootfsImageConfig,
} from "../../../src/index.ts";
import { requireHostArtifact, requireVmLaunchSupport } from "../support/capabilities.ts";
import { testRootfsImageOrSkip } from "../support/rootfs.ts";

async function testRootfsForVmTest(t: TestContext): Promise<RootfsImageConfig | undefined> {
  if (!requireVmLaunchSupport(t)) {
    return undefined;
  }

  return await testRootfsImageOrSkip(t);
}

async function testRootfsForMacOsVmTest(t: TestContext): Promise<RootfsImageConfig | undefined> {
  if (process.platform !== "darwin") {
    t.skip("macOS-specific virtio-fs semantics");
    return undefined;
  }

  return await testRootfsForVmTest(t);
}

function readHostXattr(
  path: string,
  name: string,
  symlinkMode: "follow" | "no-follow",
): string {
  const args = symlinkMode === "no-follow"
    ? ["-s", "-p", name, path]
    : ["-p", name, path];
  return execFileSync("/usr/bin/xattr", args, { encoding: "utf8" }).trim();
}

async function testRootfsForHostArtifactTest(t: TestContext): Promise<RootfsImageConfig | undefined> {
  if (!requireHostArtifact(t)) {
    return undefined;
  }

  return await testRootfsImageOrSkip(t);
}

test("new public API boots an external rootfs image and runs a process", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const result = await sandbox.exec("/bin/sh", ["-lc", [
    "set -e",
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
    "test \"$(readlink /dev/fd)\" = /proc/self/fd",
    "test \"$(readlink /dev/stdin)\" = /proc/self/fd/0",
    "test \"$(readlink /dev/stdout)\" = /proc/self/fd/1",
    "test \"$(readlink /dev/stderr)\" = /proc/self/fd/2",
    "test \"$(bash -c 'cat < <(printf fd-ready)')\" = fd-ready",
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const slow = sandbox.exec("/bin/sh", ["-lc", "sleep 1; printf slow"]);
  const fast = sandbox.exec("/bin/sh", ["-lc", "printf fast"]);

  assert.equal((await fast).stdout, "fast");
  assert.equal((await slow).stdout, "slow");
});

test("buffered exec timeout returns when descendant keeps output pipes open", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const result = await sandbox.exec("/bin/cat");

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "");
  assert.equal(result.stderr, "");
});

test("spawn returns stream handles immediately and pipes guest stdio", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  assert.throws(
    () => sandbox.spawn("/bin/true", [], { pipes: [2] }),
    /pipes\[0\] must be an integer between 3 and 2147483647/,
  );
  assert.throws(
    () => sandbox.spawn("/bin/true", [], { pipes: [3, 3] }),
    /duplicate pipe fd: 3/,
  );

  const child = sandbox.spawn("/bin/sh", [
    "-lc",
    "cat; printf stderr-ready >&2",
  ]);
  const stdout = readStreamText(child.stdout);
  const stderr = readStreamText(child.stderr);
  const writer = child.stdin.getWriter();
  await writer.write(new TextEncoder().encode("stdin-ready"));
  await writer.close();

  await child.ready;
  assert.equal(await stdout, "stdin-ready");
  assert.equal(await stderr, "stderr-ready");
  assert.deepEqual(await child.exit, { exitCode: 0, signal: null });
});

test("spawn exposes caller-selected full-duplex guest file descriptors", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const child = sandbox.spawn("/bin/sh", [
    "-lc",
    "request=$(cat <&3); printf 'reply:%s' \"$request\" >&3",
  ], {
    pipes: [3],
  });
  const pipe = child.pipes.get(3);
  assert.ok(pipe);

  const output = readStreamText(pipe.output);
  const writer = pipe.input.getWriter();
  await writer.write(new TextEncoder().encode("request"));
  await writer.close();

  await child.ready;
  assert.equal(await output, "reply:request");
  assert.deepEqual(await child.exit, { exitCode: 0, signal: null });
});

test("spawn kill terminates a long-lived guest process", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const child = sandbox.spawn("/bin/sleep", ["30"]);
  await child.ready;
  child.kill("SIGKILL");

  assert.deepEqual(await child.exit, { exitCode: null, signal: "SIGKILL" });
});

test("spawn and pty honor already-aborted signals before launching", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const controller = new AbortController();
  controller.abort();

  assert.throws(
    () => sandbox.spawn("/bin/sh", ["-lc", "touch /tmp/spawn-started"], { signal: controller.signal }),
    { name: "AbortError" },
  );
  assert.throws(
    () =>
      sandbox.pty("/bin/sh", ["-lc", "touch /tmp/pty-started"], {
        signal: controller.signal,
        size: { rows: 24, cols: 80 },
      }),
    { name: "AbortError" },
  );

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "test ! -e /tmp/spawn-started && test ! -e /tmp/pty-started",
  ]);
  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
});

test("pty runs an interactive terminal process with a required size", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const term = sandbox.pty("/bin/sh", [
    "-lc",
    "IFS= read -r line; stty size; printf 'line=%s done' \"$line\"",
  ], {
    env: { TERM: "xterm-256color" },
    size: { rows: 24, cols: 80 },
  });
  const output = readStreamText(term.output, { timeoutMs: 5_000 });
  const writer = term.input.getWriter();
  await term.ready;
  term.resize({ rows: 33, cols: 101 });
  await writer.write(new TextEncoder().encode("pty-ready\n"));
  await writer.close();

  const text = await output;
  assert.match(text, /33 101/);
  assert.match(text, /line=pty-ready/);
  assert.match(text, /done/);
  assert.deepEqual(await term.exit, { exitCode: 0, signal: null });
});

test("buffered exec timeout includes output drain time", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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

test("agent rootfs image includes common agent runtimes and CLIs", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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

test("environment facts can be recovered from a running VM", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.ephemeral({
      base: testRootfs,
    }),
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot();

  const facts = await sandbox.environmentFacts();

  assertIncludesFact(facts, {
    source: "config",
    topic: "rootfs",
    relation: "write-mode",
    value: "writable-ephemeral",
  });
  assertIncludesFact(facts, {
    source: "config",
    topic: "network-egress",
    relation: "requires",
    value: "policy-grant",
  });
  assertIncludesFact(facts, {
    source: "guest",
    topic: "distro",
    relation: "is",
    value: "alpine",
  });
  assertIncludesGuestDistroVersion(facts);
  assertIncludesFact(facts, {
    source: "guest",
    topic: "package-manager",
    relation: "is",
    value: "apk",
  });
  assertIncludesFact(facts, {
    source: "guest",
    topic: "shell",
    relation: "is",
    value: "/bin/sh",
  });
  assertIncludesFact(facts, {
    source: "guest",
    topic: "command",
    relation: "exists",
    value: "git",
  });
  assertIncludesFact(facts, {
    source: "guest",
    topic: "rootfs",
    relation: "mount-mode",
    value: "read-write",
  });
});

test("environment facts parse os-release as data", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: rootfs.ephemeral({
      base: testRootfs,
    }),
  }).boot();

  const write = await sandbox.exec("/bin/sh", [
    "-lc",
    "printf '%s\\n' 'ID=$(touch /tmp/os-release-executed)' 'VERSION_ID=3.23' >/etc/os-release",
  ]);
  assert.equal(
    write.exitCode,
    0,
    `stdout:\n${write.stdout}\nstderr:\n${write.stderr}`,
  );

  await assert.rejects(
    sandbox.environmentFacts(),
    /unsupported guest distro environment fact/,
  );

  const check = await sandbox.exec("/bin/sh", [
    "-lc",
    "test ! -e /tmp/os-release-executed",
  ]);
  assert.equal(
    check.exitCode,
    0,
    `stdout:\n${check.stdout}\nstderr:\n${check.stderr}`,
  );
});

test("boot options provide instance-specific virtual mounts", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const laneFs = fs.memory({
    files: {
      "/note.txt": "lane-private",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/mnt": fs.virtual(laneFs),
    },
  });

  const result = await sandbox.exec("/bin/cat", ["/mnt/note.txt"]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "lane-private");
});

test("declarative blob storage persists an agent overlay and mounted workspace", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const objectStore = await mkdtemp(join(tmpdir(), "sandbox-declarative-blob-"));
  t.after(async () => {
    await rm(objectStore, { recursive: true, force: true });
  });
  const provider = { kind: "local" as const, path: objectStore };
  const sandbox = defineSandbox({
    rootfs: rootfs.cow({
      base: testRootfs,
      writable: storage.blob.overlay({ provider, volume: "agent-overlay" }),
    }),
  });
  const workspace = storage.blob.block({
    provider,
    volume: "agent-workspace",
    sizeBytes: 64n * 1024n * 1024n,
  });

  const first = await sandbox.boot({ mounts: { "/workspace": workspace } });
  try {
    const write = await first.exec("/bin/sh", [
      "-lc",
      "printf '%s' machine > /agent-state && printf '%s' workspace > /workspace/state && sync",
    ]);
    assert.equal(write.exitCode, 0, write.stderr);
    await assert.rejects(sandbox.boot({ mounts: { "/workspace": workspace } }), (error) => {
      assert.ok(error instanceof SandboxBlobStorageError);
      assert.equal(error.code, "volume-locked");
      assert.match(error.message, /agent-overlay is already leased/);
      return true;
    });
  } finally {
    await first.close();
  }

  await using second = await sandbox.boot({ mounts: { "/workspace": workspace } });
  const read = await second.exec("/bin/sh", ["-lc", "cat /agent-state /workspace/state"]);
  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "machineworkspace");
});

test("clean blob overlay close does not keep a short-lived process alive", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const objectStore = await mkdtemp(join(tmpdir(), "sandbox-blob-close-process-"));
  t.after(async () => {
    await rm(objectStore, { recursive: true, force: true });
  });
  const moduleUrl = new URL("../../../src/index.ts", import.meta.url).href;
  const serializedRootfs = JSON.stringify(testRootfs, (_key, value) => (
    typeof value === "bigint" ? value.toString() : value
  ));
  execFileSync(process.execPath, ["--input-type=module", "--eval", `
    const { defineSandbox, rootfs, storage } = await import(${JSON.stringify(moduleUrl)});
    const serializedRootfs = ${serializedRootfs};
    const base = { ...serializedRootfs, sizeBytes: BigInt(serializedRootfs.sizeBytes) };
    const vm = await defineSandbox({
      rootfs: rootfs.cow({
        base,
        writable: storage.blob.overlay({
          provider: { kind: "local", path: ${JSON.stringify(objectStore)} },
          volume: "agent-overlay",
        }),
      }),
    }).boot();
    await vm.close();
  `], { timeout: 10_000 });
});

test("blob overlays reject a different rootfs base before boot", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const objectStore = await mkdtemp(join(tmpdir(), "sandbox-blob-overlay-base-"));
  t.after(async () => {
    await rm(objectStore, { recursive: true, force: true });
  });
  const overlay = storage.blob.overlay({
    provider: { kind: "local", path: objectStore },
    volume: "agent-overlay",
  });
  await assert.rejects(
    defineSandbox({
      rootfs: rootfs.cow({
        base: { ...testRootfs, path: join(objectStore, "missing.qcow2") },
        writable: overlay,
      }),
    }).boot(),
  );
  const first = await defineSandbox({
    rootfs: rootfs.cow({ base: testRootfs, writable: overlay }),
  }).boot();
  await first.close();

  const differentBase = {
    ...testRootfs,
    digest: `sha256:${"0".repeat(64)}` as `sha256:${string}`,
  };
  await assert.rejects(
    defineSandbox({
      rootfs: rootfs.cow({ base: differentBase, writable: overlay }),
    }).boot(),
    (error) => {
      assert.ok(error instanceof SandboxBlobStorageError);
      assert.equal(error.code, "volume-mismatch");
      assert.match(error.message, /blob rootfs overlay base identity mismatch/);
      return true;
    },
  );
});

test("blob volumes reject being reused across overlay and disk roles", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const objectStore = await mkdtemp(join(tmpdir(), "sandbox-blob-volume-role-"));
  t.after(async () => {
    await rm(objectStore, { recursive: true, force: true });
  });
  const provider = { kind: "local" as const, path: objectStore };
  const disk = storage.blob.block({
    provider,
    volume: "workspace-first",
    sizeBytes: 64n * 1024n * 1024n,
  });
  const firstDisk = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: { "/workspace": disk },
  });
  await firstDisk.close();
  const diskThenOverlay = storage.blob.overlay({ provider, volume: "workspace-first" });
  await assert.rejects(
    defineSandbox({
      rootfs: rootfs.cow({ base: testRootfs, writable: diskThenOverlay }),
    }).boot(),
    /blob volume role mismatch: stored guest-block-device, requested rootfs-cow-overlay/,
  );

  const overlay = storage.blob.overlay({ provider, volume: "overlay-first" });
  const firstOverlay = await defineSandbox({
    rootfs: rootfs.cow({ base: testRootfs, writable: overlay }),
  }).boot();
  await firstOverlay.close();
  const overlayThenDisk = storage.blob.block({
    provider,
    volume: "overlay-first",
    sizeBytes: 64n * 1024n * 1024n,
  });
  await assert.rejects(
    defineSandbox({ rootfs: testRootfs }).boot({
      mounts: { "/workspace": overlayThenDisk },
    }),
    /blob volume role mismatch: stored rootfs-cow-overlay, requested guest-block-device/,
  );
});

test("failed declarative blob mount boot releases its lease", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const objectStore = await mkdtemp(join(tmpdir(), "sandbox-blob-mount-error-"));
  t.after(async () => {
    await rm(objectStore, { recursive: true, force: true });
  });
  const disk = storage.blob.block({
    provider: { kind: "local" as const, path: objectStore },
    volume: "agent-state",
    sizeBytes: 64n * 1024n * 1024n,
  });
  await assert.rejects(
    defineSandbox({ rootfs: testRootfs }).boot({
      mounts: { "/etc/hostname": disk },
    }),
    /guest mount point is not a directory: \/etc\/hostname/,
  );

  await using retry = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: { "/workspace": disk },
  });
  const result = await retry.exec("/bin/sh", ["-lc", "test -d /workspace"]);
  assert.equal(result.exitCode, 0, result.stderr);
});

test("blob store opening failures preserve their public error code", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const objectStore = await mkdtemp(join(tmpdir(), "sandbox-blob-open-error-"));
  t.after(async () => {
    await rm(objectStore, { recursive: true, force: true });
  });
  const disk = storage.blob.block({
    provider: { kind: "local" as const, path: objectStore },
    volume: "agent-state",
    sizeBytes: 64n * 1024n * 1024n,
  });
  const first = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: { "/workspace": disk },
  });
  await first.close();

  const metadata = JSON.parse(
    await readFile(join(objectStore, "volumes", "agent-state", "metadata.json"), "utf8"),
  ) as { generation: string };
  await unlink(
    join(objectStore, "volumes", "agent-state", "data", metadata.generation, "manifest.json"),
  );

  await assert.rejects(
    defineSandbox({ rootfs: testRootfs }).boot({
      mounts: { "/workspace": disk },
    }),
    (error) => {
      assert.ok(error instanceof SandboxBlobStorageError);
      assert.equal(error.code, "storage-error");
      assert.match(error.message, /missing blob block manifest for provisioned volume/);
      return true;
    },
  );
});

test("timed out declarative blob boot terminates a stuck host", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const server = createServer(() => {});
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  const address = server.address();
  assert.ok(address !== null && typeof address !== "string");
  const priorTimeout = process.env.SANDBOX_LAUNCH_TIMEOUT_MS;
  process.env.SANDBOX_LAUNCH_TIMEOUT_MS = "100";
  const startedAt = performance.now();
  try {
    await assert.rejects(
      defineSandbox({ rootfs: testRootfs }).boot({
        mounts: {
          "/workspace": storage.blob.block({
            provider: {
              kind: "s3",
              bucket: "agent-disks",
              region: "us-east-1",
              endpoint: `http://127.0.0.1:${address.port}`,
              auth: {
                kind: "access-key",
                accessKeyId: "test",
                secretAccessKey: "test",
              },
            },
            volume: "stuck-acquisition",
            sizeBytes: 64n * 1024n * 1024n,
          }),
        },
      }),
      /sandbox-host did not produce a launch acknowledgement within 100ms/,
    );
  } finally {
    if (priorTimeout === undefined) {
      delete process.env.SANDBOX_LAUNCH_TIMEOUT_MS;
    } else {
      process.env.SANDBOX_LAUNCH_TIMEOUT_MS = priorTimeout;
    }
  }
  assert.ok(performance.now() - startedAt < 4_000);
});

test("running sandbox exposes a remote-friendly guest filesystem API", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  await sandbox.fs.writeFile("/tmp/vmfs/input.txt", "hello world", {
    createParents: true,
  });
  assert.equal(
    new TextDecoder().decode(await sandbox.fs.readFile("/tmp/vmfs/input.txt")),
    "hello world",
  );
  assert.equal(
    new TextDecoder().decode(await sandbox.fs.readFile("/tmp/vmfs/input.txt", {
      range: { offset: 6, length: 5 },
    })),
    "world",
  );
  await assert.rejects(
    () => sandbox.fs.writeFile("/tmp/vmfs/invalid.txt", "invalid", {
      createParents: "true" as unknown as boolean,
    }),
    /invalid sandbox fs writeFile createParents: value must be a boolean/,
  );
  await assert.rejects(
    () => sandbox.fs.mkdir("/tmp/vmfs/invalid", {
      recursive: "true" as unknown as boolean,
    }),
    /invalid sandbox fs mkdir recursive: value must be a boolean/,
  );
  await assert.rejects(
    () => sandbox.fs.remove("/tmp/vmfs/invalid", {
      force: "true" as unknown as boolean,
    }),
    /invalid sandbox fs remove force: value must be a boolean/,
  );
  await assert.rejects(
    () => sandbox.fs.remove("/tmp/vmfs/input.txt/", { force: true }),
    /invalid sandbox fs remove path: path must not end with a trailing slash/,
  );
  await assert.rejects(
    () => sandbox.fs.remove("/", { recursive: true }),
    /invalid sandbox fs remove path: path must not be root/,
  );
  const validationFollowup = await sandbox.exec("/bin/sh", ["-lc", "printf ok"]);
  assert.equal(validationFollowup.stdout, "ok");

  await sandbox.exec("/bin/sh", ["-lc", "mkfifo /tmp/vmfs/pipe"]);
  await assert.rejects(
    () => sandbox.fs.readFile("/tmp/vmfs/pipe"),
    (error) =>
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "EINVAL",
  );
  const fifoFollowup = await sandbox.exec("/bin/sh", ["-lc", "printf ok"]);
  assert.equal(fifoFollowup.stdout, "ok");

  await sandbox.exec("/bin/sh", ["-lc", "dd if=/dev/zero of=/tmp/vmfs/large.bin bs=1M count=61 status=none"]);
  await assert.rejects(
    () => sandbox.fs.readFile("/tmp/vmfs/large.bin"),
    (error) =>
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "EFBIG",
  );
  assert.equal((await sandbox.fs.readFile("/tmp/vmfs/large.bin", {
    range: { offset: 1024, length: 16 },
  })).byteLength, 16);

  await sandbox.exec("/bin/sh", ["-lc", "truncate -s 9007199254740992 /tmp/vmfs/huge-sparse.bin"]);
  await assert.rejects(
    () => sandbox.fs.stat("/tmp/vmfs/huge-sparse.bin"),
    (error) =>
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      error.code === "EFBIG",
  );
  const hugeStatFollowup = await sandbox.exec("/bin/sh", ["-lc", "printf ok"]);
  assert.equal(hugeStatFollowup.stdout, "ok");

  await sandbox.fs.writeFile("/tmp/vmfs/list/a.txt", new TextEncoder().encode("alpha"), {
    createParents: true,
  });
  await sandbox.fs.writeFile("/tmp/vmfs/list/b.txt", "beta");
  await sandbox.fs.mkdir("/tmp/vmfs/list/subdir");

  const entries = [...await sandbox.fs.readDir("/tmp/vmfs/list")]
    .sort((left, right) => left.name.localeCompare(right.name));
  assert.deepEqual(
    entries.map((entry) => ({
      name: entry.name,
      type: entry.stat.type,
    })),
    [
      { name: "a.txt", type: "file" },
      { name: "b.txt", type: "file" },
      { name: "subdir", type: "directory" },
    ],
  );
  assert.equal(entries[0]?.stat.sizeBytes, 5);
  assert.equal(entries[1]?.stat.sizeBytes, 4);
  assert.equal(typeof entries[2]?.stat.sizeBytes, "number");
  assert.equal(typeof entries[0]?.stat.modifiedAtMs, "number");
  assert.deepEqual([...(entries[0]?.nameBytes ?? [])], [...new TextEncoder().encode("a.txt")]);

  const stat = await sandbox.fs.stat("/tmp/vmfs/list/a.txt");
  assert.equal(stat.type, "file");
  assert.equal(stat.sizeBytes, 5);
  assert.equal(typeof stat.modifiedAtMs, "number");

  await sandbox.fs.mkdir("/tmp/vmfs/nonutf8");
  await sandbox.exec("/bin/sh", [
    "-lc",
    "printf x > \"$(printf '/tmp/vmfs/nonutf8/name_\\377')\"",
  ]);
  const nonUtf8Entries = await sandbox.fs.readDir("/tmp/vmfs/nonutf8");
  assert.equal(nonUtf8Entries.length, 1);
  const nonUtf8Entry = nonUtf8Entries[0];
  assert.ok(nonUtf8Entry);
  assert.equal(nonUtf8Entry.stat.type, "file");
  assert.equal(nonUtf8Entry.stat.sizeBytes, 1);
  assert.deepEqual([...nonUtf8Entry.nameBytes], [...new TextEncoder().encode("name_"), 0xff]);

  await sandbox.fs.mkdir("/tmp/vmfs/tree/deep", { recursive: true });
  await sandbox.fs.writeFile("/tmp/vmfs/tree/deep/file.txt", "tree");
  await assert.rejects(
    () => sandbox.fs.remove("/tmp/vmfs/tree"),
    (error) => typeof error === "object"
      && error !== null
      && "code" in error
      && error.code === "ENOTEMPTY",
  );
  await sandbox.fs.remove("/tmp/vmfs/tree", { recursive: true });
  await assert.rejects(
    () => sandbox.fs.remove("/tmp/vmfs/tree"),
    (error) => typeof error === "object"
      && error !== null
      && "code" in error
      && error.code === "ENOENT",
  );
  await sandbox.fs.remove("/tmp/vmfs/tree", { force: true });

  await sandbox.fs.writeFile("/tmp/vmfs/publish.tmp", "published");
  await sandbox.fs.rename("/tmp/vmfs/publish.tmp", "/tmp/vmfs/publish.txt");
  assert.equal(
    new TextDecoder().decode(await sandbox.fs.readFile("/tmp/vmfs/publish.txt")),
    "published",
  );
  await assert.rejects(
    () => sandbox.fs.rename("/tmp/vmfs/publish.txt", "/tmp/vmfs/missing-parent/publish.txt"),
    (error) => typeof error === "object"
      && error !== null
      && "code" in error
      && error.code === "ENOENT",
  );
});

test("host directory bind mounts use native virtio-fs access modes", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const readOnlySource = await mkdtemp(join(tmpdir(), "sandbox-bind-ro-"));
  const readWriteSource = await mkdtemp(join(tmpdir(), "sandbox-bind-rw-"));
  t.after(async () => {
    await rm(readOnlySource, { recursive: true, force: true });
    await rm(readWriteSource, { recursive: true, force: true });
  });
  await writeFile(join(readOnlySource, "note.txt"), "from-host\n");
  await writeFile(join(readWriteSource, "before.txt"), "before\n");

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/tmp/bind-ro": fs.bind({ source: readOnlySource, access: "ro" }),
      "/tmp/bind-rw": fs.bind({ source: readWriteSource, access: "rw" }),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "cat /tmp/bind-ro/note.txt",
      "if sh -c 'printf blocked > /tmp/bind-ro/blocked.txt' 2>/tmp/ro.err; then exit 13; fi",
      "cat /tmp/bind-rw/before.txt",
      "printf from-guest > /tmp/bind-rw/after.txt",
    ].join("\n"),
  ]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "from-host\nbefore\n");
  assert.equal(result.stderr, "");
  assert.equal(await readFile(join(readWriteSource, "after.txt"), "utf8"), "from-guest");
});

test("macOS host directory binds map the sandbox-host identity to guest root", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-identity-"));
  const hostIdentity = await lstat(source);
  const guestCreatedPath = join(source, "guest.txt");
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await writeFile(join(source, "host.txt"), "host\n");

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/tmp/identity": fs.bind({ source, access: "rw" }),
    },
  });

  await writeFile(join(source, "live-host.txt"), "live host\n");

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "stat -c '%u:%g' /tmp/identity/host.txt /tmp/identity/live-host.txt",
      "printf guest > /tmp/identity/guest.txt",
      "stat -c '%u:%g' /tmp/identity/guest.txt",
    ].join("\n"),
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "0:0\n0:0\n0:0\n");
  const guestCreated = await lstat(guestCreatedPath);
  assert.equal(guestCreated.uid, hostIdentity.uid);
  assert.equal(guestCreated.gid, hostIdentity.gid);
  assert.equal(guestCreated.mode & 0o7777, 0o600);
});

test("macOS host directory binds use guest identity metadata for permission checks", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-permissions-"));
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await chmod(source, 0o755);
  await writeFile(join(source, "native.txt"), "native\n");
  await writeFile(join(source, "adopted.txt"), "adopted\n");
  await chmod(join(source, "native.txt"), 0o600);
  await chmod(join(source, "adopted.txt"), 0o600);

  await using sandbox = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: {
      "/tmp/permissions": fs.bind({ source, access: "rw" }),
    },
  });

  const denied = await sandbox.exec("/usr/bin/python3", [
    "-c",
    [
      "import os",
      "path = '/tmp/permissions/native.txt'",
      "assert (os.stat(path).st_uid, os.stat(path).st_gid) == (0, 0)",
      "os.setgroups([])",
      "os.setgid(456)",
      "os.setuid(123)",
      "try:",
      "    open(path).read()",
      "except PermissionError:",
      "    pass",
      "else:",
      "    raise AssertionError('unmapped guest identity read owner-only native file')",
    ].join("\n"),
  ]);
  assert.equal(denied.exitCode, 0, denied.stderr);

  const adopt = await sandbox.exec("/bin/sh", [
    "-lc",
    "chown 123:456 /tmp/permissions/adopted.txt && chmod 600 /tmp/permissions/adopted.txt",
  ]);
  assert.equal(adopt.exitCode, 0, adopt.stderr);

  const allowed = await sandbox.exec("/usr/bin/python3", [
    "-c",
    [
      "import os",
      "path = '/tmp/permissions/adopted.txt'",
      "st = os.stat(path)",
      "assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (123, 456, 0o600)",
      "os.setgroups([])",
      "os.setgid(456)",
      "os.setuid(123)",
      "assert open(path).read() == 'adopted\\n'",
    ].join("\n"),
  ]);
  assert.equal(allowed.exitCode, 0, allowed.stderr);
});

test("macOS host directory binds persist guest metadata without changing host metadata", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-metadata-"));
  const hostPath = join(source, "metadata.txt");
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await writeFile(hostPath, "metadata\n");
  const hostRacePath = join(source, "race.txt");
  await writeFile(hostRacePath, "race\n");
  const hostLinkPath = join(source, "metadata-link");
  await symlink("metadata.txt", hostLinkPath);
  await chmod(hostPath, 0o640);
  const hostBefore = await lstat(hostPath);
  const hostLinkBefore = await lstat(hostLinkPath);

  const definition = defineSandbox({ rootfs: testRootfs });
  {
    await using sandbox = await definition.boot({
      mounts: {
        "/tmp/metadata": fs.bind({ source, access: "rw" }),
      },
    });
    const result = await sandbox.exec("/bin/sh", [
      "-lc",
      [
        "set -e",
        "chmod 751 /tmp/metadata/metadata.txt",
        "chown 123:456 /tmp/metadata/metadata.txt",
        "chown -h 234:567 /tmp/metadata/metadata-link",
        "ln -s metadata.txt /tmp/metadata/created-link",
        "for i in $(seq 1 25); do",
        "  chmod 640 /tmp/metadata/race.txt",
        "  chown 0:0 /tmp/metadata/race.txt",
        "  chmod 751 /tmp/metadata/race.txt & chmod_pid=$!",
        "  chown 123:456 /tmp/metadata/race.txt & chown_pid=$!",
        "  wait $chmod_pid $chown_pid",
        "  test \"$(stat -c '%u:%g:%a' /tmp/metadata/race.txt)\" = 123:456:751",
        "done",
        "stat -c '%u:%g:%a' /tmp/metadata/metadata.txt",
        "stat -c '%u:%g:%a' /tmp/metadata/metadata-link",
        "stat -c '%u:%g:%a' /tmp/metadata/created-link",
      ].join("\n"),
    ]);

    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout, "123:456:751\n234:567:755\n0:0:777\n");
  }

  const hostAfter = await lstat(hostPath);
  assert.equal(hostAfter.uid, hostBefore.uid);
  assert.equal(hostAfter.gid, hostBefore.gid);
  assert.equal(hostAfter.mode & 0o7777, 0o640);
  const hostLinkAfter = await lstat(hostLinkPath);
  assert.equal(hostLinkAfter.uid, hostLinkBefore.uid);
  assert.equal(hostLinkAfter.gid, hostLinkBefore.gid);
  assert.equal(
    readHostXattr(hostPath, "user.torkbot.sandbox.metadata", "follow"),
    "123:456:0100751:-",
  );
  assert.equal(
    readHostXattr(hostLinkPath, "user.torkbot.sandbox.metadata", "no-follow"),
    "234:567:0120755:-",
  );
  assert.equal(
    readHostXattr(
      join(source, "created-link"),
      "user.torkbot.sandbox.metadata",
      "no-follow",
    ),
    "0:0:0120777:-",
  );
  assert.equal(
    readHostXattr(hostRacePath, "user.torkbot.sandbox.metadata", "follow"),
    "123:456:0100751:-",
  );

  {
    await using sandbox = await definition.boot({
      mounts: {
        "/tmp/metadata": fs.bind({ source, access: "ro" }),
      },
    });
    const result = await sandbox.exec("/bin/stat", [
      "-c",
      "%u:%g:%a",
      "/tmp/metadata/metadata.txt",
      "/tmp/metadata/metadata-link",
      "/tmp/metadata/created-link",
    ]);

    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout, "123:456:751\n234:567:755\n0:0:777\n");
  }

  execFileSync("/usr/bin/xattr", ["-d", "user.torkbot.sandbox.metadata", hostPath]);
  {
    await using sandbox = await definition.boot({
      mounts: {
        "/tmp/metadata": fs.bind({ source, access: "ro" }),
      },
    });
    const result = await sandbox.exec("/bin/stat", [
      "-c",
      "%u:%g:%a",
      "/tmp/metadata/metadata.txt",
    ]);

    assert.equal(result.exitCode, 0, result.stderr);
    assert.equal(result.stdout, "0:0:640\n");
  }
});

test("macOS host directory binds isolate guest xattrs behind Sandbox carriers", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-xattrs-"));
  const hostPath = join(source, "xattrs.txt");
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await writeFile(hostPath, "xattrs\n");

  const definition = defineSandbox({ rootfs: testRootfs });
  {
    await using sandbox = await definition.boot({
      mounts: {
        "/tmp/xattrs": fs.bind({ source, access: "rw" }),
      },
    });
    const result = await sandbox.exec("/usr/bin/python3", [
      "-c",
      [
        "import errno, os, struct",
        "path = b'/tmp/xattrs/xattrs.txt'",
        "os.setxattr(path, b'user.comment', b'hello')",
        "assert os.getxattr(path, b'user.comment') == b'hello'",
        "assert 'user.comment' in os.listxattr(path)",
        "assert 'user.torkbot.sandbox.metadata' not in os.listxattr(path)",
        "for name in (b'trusted.note', b'security.selinux', b'system.posix_acl_access'):",
        "    try:",
        "        os.setxattr(path, name, b'value')",
        "    except OSError as error:",
        "        assert error.errno == errno.EOPNOTSUPP, (name, error)",
        "    else:",
        "        raise AssertionError(name)",
        "long_name = b'user.' + (b'x' * 109)",
        "try:",
        "    os.setxattr(path, long_name, b'value')",
        "except OSError as error:",
        "    assert error.errno == errno.ERANGE, error",
        "else:",
        "    raise AssertionError('long xattr name accepted')",
        "capability = struct.pack('<IIIII', 0x02000000, 0, 0, 0, 0)",
        "os.chmod(path, 0o6755)",
        "os.setxattr(path, b'security.capability', capability)",
        "assert os.getxattr(path, b'security.capability') == capability",
        "os.chown(path, 123, 456)",
        "try:",
        "    os.getxattr(path, b'security.capability')",
        "except OSError as error:",
        "    assert error.errno == errno.ENODATA, error",
        "else:",
        "    raise AssertionError('capability survived chown')",
        "mode = os.stat(path).st_mode",
        "assert mode & 0o6000 == 0, oct(mode)",
        "os.chmod(path, 0o6755)",
        "os.setxattr(path, b'security.capability', capability)",
      ].join("\n"),
    ]);

    assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }

  assert.equal(
    readHostXattr(hostPath, "user.virtiofs.user.comment", "follow"),
    "hello",
  );
  assert.equal(
    readHostXattr(hostPath, "user.torkbot.sandbox.metadata", "follow"),
    "123:456:0106755:0000000200000000000000000000000000000000",
  );

  {
    await using sandbox = await definition.boot({
      mounts: {
        "/tmp/xattrs": fs.bind({ source, access: "rw" }),
      },
    });
    const result = await sandbox.exec("/usr/bin/python3", [
      "-c",
      [
        "import errno, os, struct",
        "path = b'/tmp/xattrs/xattrs.txt'",
        "capability = struct.pack('<IIIII', 0x02000000, 0, 0, 0, 0)",
        "assert os.getxattr(path, b'security.capability') == capability",
        "assert os.stat(path).st_mode & 0o6000 == 0o6000",
        "with open(path, 'ab') as file:",
        "    file.write(b'changed')",
        "try:",
        "    os.getxattr(path, b'security.capability')",
        "except OSError as error:",
        "    assert error.errno == errno.ENODATA, error",
        "else:",
        "    raise AssertionError('capability survived content write')",
      ].join("\n"),
    ]);

    assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  }
  assert.equal(
    readHostXattr(hostPath, "user.torkbot.sandbox.metadata", "follow"),
    "123:456:0106755:-",
  );
});

test("macOS host directory binds reject guest special files without host artifacts", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-special-"));
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/tmp/special": fs.bind({ source, access: "rw" }),
    },
  });
  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "if mkfifo /tmp/special/pipe 2>/tmp/mkfifo.err; then exit 10; fi; test ! -e /tmp/special/pipe",
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  await assert.rejects(lstat(join(source, "pipe")), { code: "ENOENT" });
});

test("macOS host directory binds reject malformed adopted metadata", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-malformed-"));
  const hostPath = join(source, "malformed.txt");
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await writeFile(hostPath, "malformed\n");
  execFileSync("/usr/bin/xattr", [
    "-w",
    "user.torkbot.sandbox.metadata",
    "not-a-complete-record",
    hostPath,
  ]);

  await using sandbox = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: {
      "/tmp/malformed": fs.bind({ source, access: "ro" }),
    },
  });
  const result = await sandbox.exec("/bin/stat", ["/tmp/malformed/malformed.txt"]);

  assert.notEqual(result.exitCode, 0);
  assert.match(result.stderr, /Invalid argument/);
});

test("macOS host directory binds ignore the legacy override-stat xattr", async (t) => {
  const testRootfs = await testRootfsForMacOsVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-bind-legacy-xattr-"));
  const hostPath = join(source, "legacy.txt");
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await writeFile(hostPath, "legacy\n");
  await chmod(hostPath, 0o640);
  execFileSync("/usr/bin/xattr", [
    "-w",
    "user.containers.override_stat",
    "123:456:0100751",
    hostPath,
  ]);

  await using sandbox = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: {
      "/tmp/legacy": fs.bind({ source, access: "ro" }),
    },
  });
  const result = await sandbox.exec("/usr/bin/python3", [
    "-c",
    [
      "import os",
      "path = '/tmp/legacy/legacy.txt'",
      "st = os.stat(path)",
      "assert (st.st_uid, st.st_gid, st.st_mode & 0o777) == (0, 0, 0o640)",
      "assert 'user.containers.override_stat' not in os.listxattr(path)",
    ].join("\n"),
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(
    readHostXattr(hostPath, "user.containers.override_stat", "follow"),
    "123:456:0100751",
  );
});

test("read-only host directory masks hide lower host entries", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-mask-ro-"));
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await mkdir(join(source, "node_modules"));
  await mkdir(join(source, ".git"));
  await writeFile(join(source, "node_modules", "lower.txt"), "lower\n");
  await writeFile(join(source, ".git", "config"), "lower-git\n");
  await writeFile(join(source, "visible.txt"), "visible\n");

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/tmp/workspace": fs.bind({
        source,
        access: "ro",
        mask: {
          paths: ["/node_modules", "/.git"],
          storage: undefined,
        } as never,
      }),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "set -e",
      "cat /tmp/workspace/visible.txt",
      "test ! -e /tmp/workspace/node_modules",
      "test ! -e /tmp/workspace/.git",
      ...(process.platform === "darwin" ? ["test ! -e /tmp/workspace/.GIT"] : []),
      "if ls -a /tmp/workspace | grep -E '^(node_modules|\\.git)$'; then exit 10; fi",
      "if sh -c 'printf blocked > /tmp/workspace/node_modules' 2>/tmp/mask-ro.err; then exit 11; fi",
    ].join("\n"),
  ]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "visible\n");
  assert.equal(result.stderr, "");
});

test("writable host directory masks store guest-created entries in host mask storage", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-mask-rw-source-"));
  const storage = await mkdtemp(join(tmpdir(), "sandbox-mask-rw-storage-"));
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
    await rm(storage, { recursive: true, force: true });
  });
  await mkdir(join(source, "node_modules"));
  await mkdir(join(source, ".cache"));
  await mkdir(join(source, "packages", "a", "node_modules"), { recursive: true });
  await writeFile(join(source, "node_modules", "lower.txt"), "lower-root\n");
  await writeFile(join(source, ".cache", "lower.txt"), "lower-cache\n");
  await writeFile(join(source, "packages", "a", "node_modules", "lower.txt"), "lower-package\n");
  await writeFile(join(source, "visible.txt"), "visible\n");
  await writeFile(join(storage, "preexisting"), "upper-preexisting\n");
  await writeFile(join(source, "preexisting"), "lower-preexisting\n");

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/tmp/workspace": fs.bind({
        source,
        access: "rw",
        mask: {
          paths: ["/node_modules", "/.cache", "/packages/a/node_modules", "/preexisting"],
          storage: fs.bind({
            source: storage,
            access: "rw",
          }),
        },
      }),
    },
  });

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "set -e",
      "cat /tmp/workspace/visible.txt",
      "test ! -e /tmp/workspace/node_modules",
      "test ! -e /tmp/workspace/.cache",
      "test ! -e /tmp/workspace/packages/a/node_modules",
      ...(process.platform === "darwin"
        ? ["if ls -a /tmp/workspace/Packages/A | grep -E '^node_modules$'; then exit 13; fi"]
        : []),
      "if ls -a /tmp/workspace | grep -E '^(node_modules|\\.cache)$'; then exit 10; fi",
      "if ! ls -a /tmp/workspace | grep -q -E '^preexisting$'; then exit 12; fi",
      "cat /tmp/workspace/preexisting",
      ...(process.platform === "darwin"
        ? ["test \"$(stat -c '%u:%g' /tmp/workspace/preexisting)\" = 0:0"]
        : []),
      "printf file-entry > /tmp/workspace/node_modules",
      "test -f /tmp/workspace/node_modules",
      "cat /tmp/workspace/node_modules",
      "rm /tmp/workspace/node_modules",
      "test ! -e /tmp/workspace/node_modules",
      "if sh -c 'printf no-parent > /tmp/workspace/.cache/value.txt' 2>/tmp/mask-parent.err; then exit 11; fi",
      "mkdir /tmp/workspace/node_modules",
      "printf child > /tmp/workspace/node_modules/child.txt",
      "mkdir /tmp/workspace/.cache",
      "printf cached > /tmp/workspace/.cache/value.txt",
      "mkdir /tmp/workspace/packages/a/node_modules",
      "printf package > /tmp/workspace/packages/a/node_modules/pkg.txt",
      "cat /tmp/workspace/node_modules/child.txt",
      "cat /tmp/workspace/.cache/value.txt",
      "cat /tmp/workspace/packages/a/node_modules/pkg.txt",
    ].join("\n"),
  ]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "visible\nupper-preexisting\nfile-entrychildcachedpackage");
  assert.equal(result.stderr, "");
  assert.equal(await readFile(join(source, "node_modules", "lower.txt"), "utf8"), "lower-root\n");
  assert.equal(await readFile(join(source, ".cache", "lower.txt"), "utf8"), "lower-cache\n");
  assert.equal(await readFile(join(source, "packages", "a", "node_modules", "lower.txt"), "utf8"), "lower-package\n");
  assert.equal(await readFile(join(source, "preexisting"), "utf8"), "lower-preexisting\n");
  assert.equal((await lstat(join(storage, "node_modules"))).isDirectory(), true);
  assert.equal(await readFile(join(storage, "node_modules", "child.txt"), "utf8"), "child");
  assert.equal(await readFile(join(storage, ".cache", "value.txt"), "utf8"), "cached");
  assert.equal(await readFile(join(storage, "packages", "a", "node_modules", "pkg.txt"), "utf8"), "package");
  assert.equal(await readFile(join(storage, "preexisting"), "utf8"), "upper-preexisting\n");
  if (process.platform === "darwin") {
    assert.equal(
      readHostXattr(
        join(storage, "node_modules", "child.txt"),
        "user.torkbot.sandbox.metadata",
        "follow",
      ),
      "0:0:0100644:-",
    );
  }
});

test("writable host directory masks persist storage beneath another masked source path", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const source = await mkdtemp(join(tmpdir(), "sandbox-mask-nested-source-"));
  const storage = join(source, ".kc", "mounts", "workspace");
  t.after(async () => {
    await rm(source, { recursive: true, force: true });
  });
  await mkdir(storage, { recursive: true });
  await mkdir(join(source, "node_modules"));
  await writeFile(join(source, ".kc", "machine-state"), "host-private\n");
  await writeFile(join(source, "node_modules", "lower.txt"), "host-native\n");
  await writeFile(join(source, "visible.txt"), "visible\n");

  const sandboxDefinition = defineSandbox({
    rootfs: testRootfs,
  });
  const boot = () => sandboxDefinition.boot({
    mounts: {
      "/tmp/workspace": fs.bind({
        source,
        access: "rw",
        mask: {
          paths: ["/.kc", "/node_modules"],
          storage: fs.bind({
            source: storage,
            access: "rw",
          }),
        },
      }),
    },
  });

  {
    await using sandbox = await boot();
    const result = await sandbox.exec("/bin/sh", [
      "-lc",
      [
        "set -e",
        "test ! -e /tmp/workspace/.kc",
        "test ! -e /tmp/workspace/node_modules",
        "cat /tmp/workspace/visible.txt",
        "mkdir /tmp/workspace/node_modules",
        "printf guest-native > /tmp/workspace/node_modules/native.txt",
        "ln /tmp/workspace/node_modules/native.txt /tmp/workspace/node_modules/native-link.txt",
        "test ! -e /tmp/workspace/.kc",
      ].join("\n"),
    ]);

    assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    assert.equal(result.stdout, "visible\n");
    assert.equal(result.stderr, "");
  }

  assert.equal(await readFile(join(source, ".kc", "machine-state"), "utf8"), "host-private\n");
  assert.equal(await readFile(join(source, "node_modules", "lower.txt"), "utf8"), "host-native\n");
  assert.equal(await readFile(join(storage, "node_modules", "native.txt"), "utf8"), "guest-native");

  {
    await using sandbox = await boot();
    const result = await sandbox.exec("/bin/sh", [
      "-lc",
      [
        "set -e",
        "test ! -e /tmp/workspace/.kc",
        "cat /tmp/workspace/node_modules/native.txt",
        "cat /tmp/workspace/node_modules/native-link.txt",
      ].join("\n"),
    ]);

    assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
    assert.equal(result.stdout, "guest-nativeguest-native");
    assert.equal(result.stderr, "");
  }
});

test("missing writable mount directories are created before mounting virtual filesystems", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const missingFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    mounts: {
      "/tmp/missing-mount": fs.virtual(missingFs),
    },
  });

  const result = await sandbox.exec("/bin/cat", ["/tmp/missing-mount/note.txt"]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "mounted\n");
});

test("top-level read-only rootfs mount directories are synthetic", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const missingFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  await using mounted = await defineSandbox({ rootfs: testRootfs }).boot({
    mounts: { "/missing-mount": fs.virtual(missingFs) },
  });
  const read = await mounted.exec("/bin/cat", ["/missing-mount/note.txt"]);
  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "mounted\n");

  await mounted.close();
  await using rootfsOnly = await defineSandbox({ rootfs: testRootfs }).boot();
  const absent = await rootfsOnly.exec("/bin/sh", ["-lc", "test ! -e /missing-mount"]);
  assert.equal(absent.exitCode, 0, absent.stderr);
});

test("read-only rootfs mount directories follow guest-absolute symlinks", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const overlay = memoryBlockStore();
  await using builder = await defineSandbox({
    rootfs: rootfs.cow({ base: testRootfs, writable: overlay }),
  }).boot();
  const prepare = await builder.exec("/bin/sh", [
    "-lc",
    "mkdir -p /srv/data && ln -s /srv/data /data && sync",
  ]);
  assert.equal(prepare.exitCode, 0, prepare.stderr);
  await builder.close();

  const image = await rootfs.flatten({
    format: "qcow2",
    source: rootfs.compose({ base: testRootfs, overlay }),
    dest: memoryBlockStore(),
  });
  const imageDir = await mkdtemp(join(tmpdir(), "sandbox-symlink-rootfs-"));
  t.after(async () => {
    await rm(imageDir, { recursive: true, force: true });
  });
  const imagePath = join(imageDir, "rootfs.qcow2");
  const imageFile = await open(imagePath, "w");
  const imageHash = createHash("sha256");
  try {
    for await (const chunk of rootfs.bytes(image)) {
      imageHash.update(chunk);
      await imageFile.write(chunk);
    }
  } finally {
    await imageFile.close();
  }
  const customRootfs: RootfsImageConfig = {
    ...testRootfs,
    path: imagePath,
    digest: `sha256:${imageHash.digest("hex")}`,
    sizeBytes: image.sizeBytes,
  };
  const mountedFs = fs.memory({ files: { "/note.txt": "mounted\n" } });
  await using sandbox = await defineSandbox({ rootfs: customRootfs }).boot({
    mounts: { "/data/cache": fs.virtual(mountedFs) },
  });

  const read = await sandbox.exec("/bin/cat", ["/data/cache/note.txt"]);
  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "mounted\n");
});

test("missing COW rootfs mount directories become machine state", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
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
      base: testRootfs,
      writable: blockStore,
      maxDirtyBytes: 128 * 1024,
    }),
  });

  const mounted = await sandboxDefinition.boot({
    mounts: { "/opt/cache": fs.virtual(missingFs) },
  });
  const read = await mounted.exec("/bin/cat", ["/opt/cache/note.txt"]);
  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "mounted\n");
  await mounted.close();

  await using sandbox = await sandboxDefinition.boot();
  const result = await sandbox.exec("/bin/sh", ["-lc", "test -d /opt/cache"]);

  assert.equal(result.exitCode, 0, result.stderr);
});

test("ordered nested virtual mounts create child directories under parent mounts", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const workspace = fs.memory({
    files: {
      "/note.txt": "workspace\n",
    },
  });
  const cache = fs.memory({
    files: {
      "/note.txt": "cache\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const mountedFs = fs.memory({
    files: {
      "/note.txt": "mounted\n",
    },
  });
  await assert.rejects(
    defineSandbox({
      rootfs: testRootfs,
    }).boot({
      mounts: {
        "/etc/passwd": fs.virtual(mountedFs),
      },
    }),
    /guest mount point is not a directory: \/etc\/passwd/,
  );
});

test("virtual memory mounts can be used as the boot cwd", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const workspace = fs.memory({
    files: {
      "/hello.txt": "hi\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const mount = fs.memory({
    files: {
      "/hello.txt": "hi\n",
    },
  });
  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot({
    cwd: "/tmp",
  });

  const result = await sandbox.exec("/bin/pwd", []);

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.trim(), "/tmp");
});

test("agent rootfs image exposes enough guest disk space for agent workloads", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
  }).boot();

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    "df -Pk / | awk 'NR == 2 { print $2 }'",
  ]);

  assert.equal(result.exitCode, 0, result.stderr);
  assert.ok(Number(result.stdout.trim()) >= 6 * 1024 * 1024, result.stdout);
});

test("HTTP interception does not make read-only rootfs writable", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot();

  const result = await sandbox.exec("/bin/sh", [
    "-lc",
    [
      "set -eu",
      "root_options=$(awk '$2 == \"/\" { print $4; exit }' /proc/mounts)",
      "case \",$root_options,\" in *,ro,*) ;; *) echo \"root mount is writable: $root_options\"; exit 1 ;; esac",
      "if touch /root/no-cow-probe 2>/tmp/no-cow-touch.err; then",
      "  echo 'rootfs write unexpectedly succeeded'",
      "  exit 1",
      "fi",
      "grep -qi 'read-only' /tmp/no-cow-touch.err",
      "printf ok",
    ].join("\n"),
  ]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "ok");
});

test("ephemeral rootfs allows rootfs mutations only for the running instance", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.ephemeral({
      base: testRootfs,
      maxDirtyBytes: 128 * 1024,
    }),
  });

  await using first = await sandboxDefinition.boot();
  const write = await first.exec("/bin/sh", [
    "-lc",
    [
      "set -eu",
      "root_options=$(awk '$2 == \"/\" { print $4; exit }' /proc/mounts)",
      "case \",$root_options,\" in *,rw,*) ;; *) echo \"root mount is not writable: $root_options\"; exit 1 ;; esac",
      "printf '%s' transient > /root/ephemeral-state.txt",
      "test \"$(cat /root/ephemeral-state.txt)\" = transient",
    ].join("\n"),
  ]);
  assert.equal(write.exitCode, 0, `stdout:\n${write.stdout}\nstderr:\n${write.stderr}`);

  await first.close();

  await using second = await sandboxDefinition.boot();
  const read = await second.exec("/bin/sh", [
    "-lc",
    "test ! -e /root/ephemeral-state.txt",
  ]);
  assert.equal(read.exitCode, 0, `stdout:\n${read.stdout}\nstderr:\n${read.stderr}`);
});

test("COW rootfs round-trips rootfs mutations across instances", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const blockStore = memoryBlockStore();
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.cow({
      base: testRootfs,
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
  assert.match(blockStore.observedBaseIdentities()[0] ?? "", /^rootfs-image:alpine:3\.23-agent:qcow2:/);
});

test("persistent rootfs creates and reuses a QCOW2 overlay file", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const dir = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-"));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const overlayPath = join(dir, "rootfs.qcow2");
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: overlayPath,
    }),
  });

  await assert.rejects(lstat(overlayPath), { code: "ENOENT" });

  const first = await sandboxDefinition.boot();
  try {
    const write = await first.exec("/bin/sh", [
      "-lc",
      "printf '%s' persisted > /root/persistent-state.txt && sync",
    ]);
    assert.equal(write.exitCode, 0, write.stderr);
  } finally {
    await first.close();
  }

  assert.equal((await lstat(overlayPath)).isFile(), true);
  await assertQcow2Magic(overlayPath);
  await assert.rejects(lstat(`${overlayPath}.metadata.json`), { code: "ENOENT" });

  await using second = await sandboxDefinition.boot();
  const read = await second.exec("/bin/cat", ["/root/persistent-state.txt"]);

  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "persisted");
});

test("persistent rootfs rejects reuse when base metadata does not match", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const dir = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-metadata-"));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const overlayPath = join(dir, "rootfs.qcow2");
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: overlayPath,
    }),
  });

  const first = await sandboxDefinition.boot();
  await first.close();

  await corruptQcow2BackingFilename(overlayPath);

  await assert.rejects(
    sandboxDefinition.boot(),
    /rootfs overlay base identity mismatch/,
  );
});

test("persistent rootfs validates the base image digest before reuse", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const dir = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-digest-"));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  await assert.rejects(
    defineSandbox({
      rootfs: rootfs.persistent({
        base: {
          ...testRootfs,
          digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        },
        path: join(dir, "rootfs.qcow2"),
      }),
    }).boot(),
    /rootfs image digest mismatch/,
  );
});

test("persistent rootfs can live under a masked read-write host directory mount", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const workspace = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-masked-workspace-"));
  const maskStorage = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-masked-storage-"));
  t.after(async () => {
    await rm(workspace, { recursive: true, force: true });
    await rm(maskStorage, { recursive: true, force: true });
  });
  await mkdir(join(workspace, ".sandbox"));
  await writeFile(join(workspace, "visible.txt"), "workspace-visible\n");
  const overlayPath = join(workspace, ".sandbox", "rootfs.qcow2");
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: overlayPath,
    }),
  });
  const boot = {
    mounts: {
      "/tmp/workspace": fs.bind({
        source: workspace,
        access: "rw",
        mask: {
          paths: ["/.sandbox"],
          storage: fs.bind({ source: maskStorage, access: "rw" }),
        },
      }),
    },
  };

  const first = await sandboxDefinition.boot(boot);
  try {
    const write = await first.exec("/bin/sh", [
      "-lc",
      [
        "set -e",
        "cat /tmp/workspace/visible.txt",
        "test ! -e /tmp/workspace/.sandbox",
        "printf '%s' masked > /root/masked-persistent-state.txt",
        "sync",
      ].join("\n"),
    ]);
    assert.equal(write.exitCode, 0, `stdout:\n${write.stdout}\nstderr:\n${write.stderr}`);
    assert.equal(write.stdout, "workspace-visible\n");
  } finally {
    await first.close();
  }

  assert.equal((await lstat(overlayPath)).isFile(), true);
  assert.equal(await readFile(join(workspace, "visible.txt"), "utf8"), "workspace-visible\n");

  await using second = await sandboxDefinition.boot(boot);
  const read = await second.exec("/bin/cat", ["/root/masked-persistent-state.txt"]);

  assert.equal(read.exitCode, 0, read.stderr);
  assert.equal(read.stdout, "masked");
});

test("persistent rootfs locks only the selected overlay file", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const dir = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-lock-"));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const firstOverlay = join(dir, "first.qcow2");
  const secondOverlay = join(dir, "second.qcow2");
  const firstDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: firstOverlay,
    }),
  });
  const secondDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: secondOverlay,
    }),
  });

  const first = await firstDefinition.boot();
  try {
    const write = await first.exec("/bin/sh", [
      "-lc",
      "printf '%s' first > /root/first-overlay.txt && sync",
    ]);
    assert.equal(write.exitCode, 0, write.stderr);

    await assert.rejects(
      firstDefinition.boot(),
      /rootfs overlay is already in use|lock|busy|EBUSY/i,
    );

    const second = await secondDefinition.boot();
    try {
      const probe = await second.exec("/bin/sh", [
        "-lc",
        "test ! -e /root/first-overlay.txt && printf '%s' second > /root/second-overlay.txt && sync",
      ]);
      assert.equal(probe.exitCode, 0, `stdout:\n${probe.stdout}\nstderr:\n${probe.stderr}`);
    } finally {
      await second.close();
    }
  } finally {
    await first.close();
  }

  assert.equal((await lstat(firstOverlay)).isFile(), true);
  assert.equal((await lstat(secondOverlay)).isFile(), true);
  await assert.rejects(lstat(`${firstOverlay}.lock`), { code: "ENOENT" });
  await assert.rejects(lstat(`${secondOverlay}.lock`), { code: "ENOENT" });
});

test("persistent rootfs locks canonical overlay targets", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const dir = await mkdtemp(join(tmpdir(), "sandbox-persistent-rootfs-alias-"));
  t.after(async () => {
    await rm(dir, { recursive: true, force: true });
  });
  const realDir = join(dir, "real");
  const aliasDir = join(dir, "alias");
  await mkdir(realDir);
  await symlink(realDir, aliasDir);
  const realOverlay = join(realDir, "rootfs.qcow2");
  const aliasOverlay = join(aliasDir, "rootfs.qcow2");
  const realDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: realOverlay,
    }),
  });
  const aliasDefinition = defineSandbox({
    rootfs: rootfs.persistent({
      base: testRootfs,
      path: aliasOverlay,
    }),
  });

  const first = await realDefinition.boot();
  try {
    await assert.rejects(
      aliasDefinition.boot(),
      /rootfs overlay is already in use|lock|busy|EBUSY/i,
    );
  } finally {
    await first.close();
  }
});

test("COW rootfs can be flattened to a QCOW2 image stream", async (t) => {
  const testRootfs = await testRootfsForHostArtifactTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const overlay = memoryBlockStore();
  const dest = memoryBlockStore();
  const source = rootfs.compose({
    base: testRootfs,
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
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) {
    return;
  }

  const blockStore = memoryBlockStore();
  const sandboxDefinition = defineSandbox({
    rootfs: rootfs.cow({
      base: testRootfs,
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

async function assertQcow2Magic(path: string): Promise<void> {
  const file = await open(path, "r");
  try {
    const magic = new Uint8Array(4);
    const { bytesRead } = await file.read(magic, 0, magic.byteLength, 0);
    assert.equal(bytesRead, magic.byteLength);
    assert.deepEqual(magic, new Uint8Array([0x51, 0x46, 0x49, 0xfb]));
  } finally {
    await file.close();
  }
}

async function corruptQcow2BackingFilename(path: string): Promise<void> {
  const file = await open(path, "r+");
  try {
    const header = Buffer.alloc(20);
    const { bytesRead } = await file.read(header, 0, header.byteLength, 0);
    assert.equal(bytesRead, header.byteLength);
    assert.deepEqual(header.subarray(0, 4), Buffer.from([0x51, 0x46, 0x49, 0xfb]));
    const backingOffset = Number(header.readBigUInt64BE(8));
    const backingSize = header.readUInt32BE(16);
    assert.ok(backingOffset > 0);
    assert.ok(backingSize > 0);
    await file.write(Buffer.alloc(backingSize, "x"), 0, backingSize, backingOffset);
  } finally {
    await file.close();
  }
}

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

function assertIncludesGuestDistroVersion(
  facts: readonly SandboxEnvironmentFact[],
): void {
  const fact = facts.find((candidate) => {
    return candidate.source === "guest"
      && candidate.topic === "distro-version"
      && candidate.relation === "is";
  });

  assert.notEqual(
    fact,
    undefined,
    `expected guest distro-version fact in ${JSON.stringify(facts)}`,
  );

  if (fact === undefined) {
    throw new Error("expected guest distro-version fact");
  }

  assert.match(fact.value, /^3\.23(?:\.[0-9]+)?$/);
}

async function readStreamText(
  stream: ReadableStream<Uint8Array>,
  options: { readonly timeoutMs?: number } = {},
): Promise<string> {
  const timeout = options.timeoutMs === undefined
    ? undefined
    : new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error(`timed out reading stream after ${options.timeoutMs}ms`)), options.timeoutMs);
      });
  if (timeout !== undefined) {
    return await Promise.race([readStreamTextUntilClosed(stream), timeout]);
  }
  return await readStreamTextUntilClosed(stream);
}

async function readStreamTextUntilClosed(stream: ReadableStream<Uint8Array>): Promise<string> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const size = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(data);
}
