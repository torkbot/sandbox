import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, readlink, readdir, rm } from "node:fs/promises";
import { join, relative } from "node:path";

const repoRoot = new URL("../..", import.meta.url);

test("rootfs fixture produces a QCOW2 image", async () => {
  const resultsDir = join(repoRoot.pathname, "test-results");
  await mkdir(resultsDir, { recursive: true });
  const workDir = await mkdtemp(join(resultsDir, "rootfs-qcow2-"));
  try {
    const rootfsDir = join(workDir, "rootfs");
    const qcow2 = join(workDir, "rootfs.qcow2");

    await runNpmScript("build:rootfs", {
      SANDBOX_ROOTFS_OUT_DIR: rootfsDir,
    });
    await runNpmScript("build:rootfs:qcow2", {
      SANDBOX_ROOTFS_SOURCE_DIR: rootfsDir,
      SANDBOX_ROOTFS_QCOW2_OUT: qcow2,
    });

    assert.deepEqual((await readFile(qcow2)).subarray(0, 4), Buffer.from("QFI\xfb", "binary"));
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

test("kernel fixture builds reproducibly", async () => {
  const workDir = await mkdtemp(join(repoRoot.pathname, "test-results/kernel-repro-"));
  try {
    const firstDir = join(workDir, "kernel-a");
    const secondDir = join(workDir, "kernel-b");

    await runNpmScript("build:kernel", {
      SANDBOX_KERNEL_OUT_DIR: firstDir,
    });
    await runNpmScript("build:kernel", {
      SANDBOX_KERNEL_OUT_DIR: secondDir,
    });

    assert.equal(await digestTree(firstDir), await digestTree(secondDir));
  } finally {
    await rm(workDir, { recursive: true, force: true });
  }
});

async function runNpmScript(
  script: string,
  env: Record<string, string>,
): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn("npm", ["run", script], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...env,
      },
      stdio: "pipe",
    });
    let output = "";
    child.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise();
        return;
      }
      reject(new Error(`npm run ${script} exited with ${code}\n${output}`));
    });
  });
}

async function digestTree(root: string): Promise<string> {
  const hash = createHash("sha256");
  for (const path of await listPaths(root)) {
    const info = await lstat(path);
    hash.update(relative(root, path));
    hash.update("\0");
    hash.update(info.isSymbolicLink() ? "symlink" : "file");
    hash.update("\0");
    hash.update(String(info.mode & 0o777));
    hash.update("\0");
    hash.update(info.isSymbolicLink() ? await readlink(path) : await readFile(path));
    hash.update("\0");
  }
  return hash.digest("hex");
}

async function listPaths(root: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const paths: string[] = [];
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      paths.push(...await listPaths(path));
    } else if (entry.isFile() || entry.isSymbolicLink()) {
      paths.push(path);
    }
  }
  return paths.sort();
}

async function digestFile(path: string): Promise<string> {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}
