import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { platform } from "node:os";
import { existsSync } from "node:fs";
import { lstat, mkdtemp, readFile, readlink, readdir, rm } from "node:fs/promises";
import { basename, join, relative } from "node:path";
import { hostBinaryPath } from "../../../src/host-process.ts";
import { projectInit, projectKernel } from "../../../src/index.ts";
import { inspectNativeArtifact } from "../support/artifact.ts";
import { writeEvidence } from "../support/evidence.ts";
import { requireHostArtifact } from "../support/capabilities.ts";

const repoRoot = new URL("../../..", import.meta.url);

test("VM host artifact has no libkrun/libkrunfw dynamic dependency and is signed on macOS", async (t) => {
  if (!requireHostArtifact(t)) {
    return;
  }

  const artifact = await inspectNativeArtifact({
    forbiddenDynamicLibraries: ["libkrun", "libkrunfw"],
    macosEntitlements: platform() === "darwin"
      ? ["com.apple.security.hypervisor"]
      : [],
  });

  assert.equal(artifact.staticLinkage.ok, true);
  assert.equal(artifact.dynamicLibraries.some((lib) => /libkrun|libkrunfw/.test(lib)), false);

  if (platform() === "darwin") {
    assert.equal(artifact.codesign.valid, true);
    assert.equal(artifact.codesign.hostExecutableHasRequiredEntitlements, true);
  }

  await writeEvidence("linkage.json", artifact);
});

test("unsigned Node is acceptable because VM launch goes through sandbox-host", (t) => {
  if (!requireHostArtifact(t)) {
    return;
  }

  const hostPath = hostBinaryPath();
  assert.equal(basename(hostPath), "sandbox-host");
  assert.notEqual(hostPath, process.execPath);
  assert.equal(existsSync(hostPath), true);
});

test("project kernel and init artifacts are selected explicitly", () => {
  assert.deepEqual(projectKernel(), {
    kind: "project-kernel",
  });
  assert.deepEqual(projectKernel({ format: "image-zstd" }), {
    kind: "project-kernel",
    format: "image-zstd",
  });
  assert.deepEqual(projectInit(), {
    kind: "project-init",
    crate: "sandbox-init",
  });
});

test("Linux host CI runs the core VM/control/network contract", async () => {
  const workflow = await readFile(new URL("../../../.github/workflows/ci.yml", import.meta.url), "utf8");

  assert.match(workflow, /ubuntu-24\.04/);
  assert.match(workflow, /submodules:\s*recursive/);
  assert.match(workflow, /npm run test:e2e/);
});

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
