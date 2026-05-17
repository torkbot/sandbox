import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { lstat, mkdtemp, readFile, readlink, readdir, rm } from "node:fs/promises";
import { join, relative } from "node:path";

const repoRoot = new URL("../..", import.meta.url);

test("rootfs fixture builds reproducibly", async () => {
  const workDir = await mkdtemp(join(repoRoot.pathname, "test-results/rootfs-repro-"));
  try {
    const firstDir = join(workDir, "rootfs-a");
    const secondDir = join(workDir, "rootfs-b");
    const firstErofs = join(workDir, "rootfs-a.erofs");
    const secondErofs = join(workDir, "rootfs-b.erofs");

    await runNpmScript("build:rootfs", {
      SANDBOX_ROOTFS_OUT_DIR: firstDir,
    });
    await runNpmScript("build:rootfs", {
      SANDBOX_ROOTFS_OUT_DIR: secondDir,
    });
    await runNpmScript("build:rootfs:erofs", {
      SANDBOX_ROOTFS_SOURCE_DIR: firstDir,
      SANDBOX_ROOTFS_EROFS_OUT: firstErofs,
    });
    await runNpmScript("build:rootfs:erofs", {
      SANDBOX_ROOTFS_SOURCE_DIR: secondDir,
      SANDBOX_ROOTFS_EROFS_OUT: secondErofs,
    });

    assert.equal(await digestTree(firstDir), await digestTree(secondDir));
    assert.equal(await digestFile(firstErofs), await digestFile(secondErofs));
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
