import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  defineSandbox,
  fs,
  rootfs,
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

test("overlay supplies writable copy-on-write rootfs storage", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const overlay = fs.memory();
  let sandbox: Awaited<ReturnType<ReturnType<typeof defineSandbox>["boot"]>>;
  try {
    sandbox = await defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.20"),
      overlay: fs.virtual(overlay),
    }).boot();
  } catch (error) {
    if (await isUnsupportedVirtualOverlayUpper()) {
      t.skip("guest kernel does not support virtiofs as an overlay upper filesystem");
      return;
    }
    throw error;
  }

  await using disposable = sandbox;
  const result = await disposable.exec("/bin/sh", [
    "-lc",
    "printf '%s' installed > /usr/local/bin/example && cat /usr/local/bin/example",
  ]);

  assert.equal(result.exitCode, 0, `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`);
  assert.equal(result.stdout, "installed");
});

async function isUnsupportedVirtualOverlayUpper(): Promise<boolean> {
  const consoleOutput = process.env.SANDBOX_CONSOLE_OUTPUT;
  if (consoleOutput === undefined || consoleOutput.length === 0) {
    return false;
  }
  try {
    const text = await readFile(consoleOutput, "utf8");
    return text.includes("overlayfs: upper fs missing required features");
  } catch {
    return false;
  }
}
