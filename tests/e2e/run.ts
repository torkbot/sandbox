import { spawn } from "node:child_process";
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { mkdir, readdir, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));
const runId = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const resultDir = join(repoRoot, "test-results", "e2e", runId);
const configuredConsoleOutputPath = process.env.SANDBOX_CONSOLE_OUTPUT;
const consoleOutputPath = configuredConsoleOutputPath ?? join(resultDir, "guest-console");

await mkdir(resultDir, { recursive: true });
if (configuredConsoleOutputPath === undefined) {
  await mkdir(consoleOutputPath, { recursive: true });
}

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
    const consoleOutput = await readConsoleOutput(consoleOutputPath);
    if (consoleOutput.trim().length > 0) {
      console.error("Guest console output:");
      console.error(consoleOutput.trimEnd());
    }
  } catch {
    // The console output is best-effort diagnostic context for failing e2e runs.
  }
}
process.exitCode = exitCode;

async function readConsoleOutput(path: string): Promise<string> {
  const maxBytes = 8_000;
  const stat = statSync(path);
  if (stat.isFile()) {
    return readConsoleTail(path, maxBytes);
  }

  const entries = await readdir(path, { recursive: true, withFileTypes: true });
  let output = "";
  let remainingBytes = maxBytes;
  for (const entry of entries) {
    if (!entry.isFile() || entry.name !== "console.log") continue;
    if (output.length > 0) {
      output += "\n";
      remainingBytes -= 1;
    }
    const tail = readConsoleTail(join(entry.parentPath, entry.name), remainingBytes);
    output += tail;
    remainingBytes -= Buffer.byteLength(tail);
    if (remainingBytes <= 0) break;
  }
  return output;
}

function readConsoleTail(path: string, maxBytes: number): string {
  let fd: number | undefined;
  try {
    if (maxBytes <= 0) return "";
    const stat = statSync(path);
    const offset = Math.max(0, stat.size - maxBytes);
    const size = stat.size - offset;
    if (size <= 0) return "";
    const buffer = Buffer.alloc(size);
    fd = openSync(path, "r");
    readSync(fd, buffer, 0, size, offset);
    return buffer.toString("utf8").trimEnd();
  } catch {
    return "";
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
}
