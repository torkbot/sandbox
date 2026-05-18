import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const runId = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const resultDir = join(repoRoot, "test-results", "e2e", runId);

await mkdir(resultDir, { recursive: true });

const manifest = {
  runId,
  platform: platform(),
  status: "running",
  scenarios: [
    "boot-smoke",
    "filesystem",
    "filesystem-posix-hardening",
    "guest-hardening",
    "http-policy",
    "http-production-hardening",
    "libkrun-contract",
    "network",
    "rootfs-shaping",
  ],
};

await writeFile(join(resultDir, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);

const child = spawn(
  process.execPath,
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
