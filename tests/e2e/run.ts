import { spawn } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const runId = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const resultDir = join(repoRoot, "test-results", "e2e", runId);
const consoleOutputPath = process.env.SANDBOX_CONSOLE_OUTPUT ?? join(resultDir, "console.log");

await mkdir(resultDir, { recursive: true });

const manifest = {
  runId,
  platform: platform(),
  status: "running",
  scenarios: [
    "sandbox-api",
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
      SANDBOX_CONSOLE_OUTPUT: consoleOutputPath,
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
if (exitCode !== 0) {
  try {
    const consoleOutput = await readFile(consoleOutputPath, "utf8");
    if (consoleOutput.trim().length > 0) {
      console.error("Guest console output:");
      console.error(consoleOutput.trimEnd());
    }
  } catch {
    // The console output is best-effort diagnostic context for failing e2e runs.
  }
}
process.exitCode = exitCode;
