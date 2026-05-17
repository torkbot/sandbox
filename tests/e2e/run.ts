import { spawn } from "node:child_process";
import { copyFile, mkdir, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { execFile } from "node:child_process";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const runId = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const resultDir = join(repoRoot, "test-results", "e2e", runId);
const execFileAsync = promisify(execFile);

await mkdir(resultDir, { recursive: true });

const manifest = {
  runId,
  platform: platform(),
  status: "running",
  scenarios: [
    "boot-smoke",
    "filesystem",
    "http-policy",
    "linkage-and-signing",
    "rootfs-shaping",
  ],
};

await writeFile(join(resultDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
const nodePath = await e2eNodePath(resultDir);

const child = spawn(
  nodePath,
  [
    "--test",
    "tests/e2e/scenarios/*.test.ts",
  ],
  {
    cwd: repoRoot,
    env: {
      ...process.env,
      SANDBOX_E2E_RESULT_DIR: resultDir,
      SANDBOX_E2E_RUN_ID: runId,
    },
    stdio: "inherit",
  },
);

const exitCode = await new Promise<number>((resolve) => {
  child.on("exit", (code, signal) => {
    if (signal) {
      resolve(1);
      return;
    }

    resolve(code ?? 1);
  });
});

manifest.status = exitCode === 0 ? "passed" : "failed";
await writeFile(join(resultDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
process.exitCode = exitCode;

async function e2eNodePath(outputDir: string): Promise<string> {
  if (platform() !== "darwin" || process.env.SANDBOX_E2E_HVF_NODE === "1") {
    return process.execPath;
  }

  const signedNodePath = join(outputDir, "node-hvf");
  await copyFile(process.execPath, signedNodePath);
  await execFileAsync("codesign", [
    "--force",
    "--sign",
    "-",
    "--entitlements",
    join(repoRoot, "entitlements", "macos-hvf.plist"),
    signedNodePath,
  ]);
  process.env.SANDBOX_E2E_HVF_NODE = "1";
  return signedNodePath;
}
