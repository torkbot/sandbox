import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const args = process.argv.slice(2);
const targetSha = requiredArg("--target-sha");
const workflow = optionalArg("--workflow") ?? "CI";
const outDir = optionalArg("--out-dir") ?? "dist/release-artifacts";
const timeoutMs = Number.parseInt(optionalArg("--timeout-ms") ?? "900000", 10);
const pollIntervalMs = Number.parseInt(optionalArg("--poll-interval-ms") ?? "15000", 10);

type WorkflowRun = {
  readonly databaseId: number;
  readonly headBranch: string;
  readonly headSha: string;
  readonly conclusion: string | null;
  readonly status: string;
  readonly url: string;
};

const selectedRun = await waitForSuccessfulRun();

await mkdir(resolve(repoRoot, outDir), { recursive: true });
await execute("gh", [
  "run",
  "download",
  String(selectedRun.databaseId),
  "--dir",
  outDir,
  "--pattern",
  "release-platform-*",
]);

console.log(`downloaded release artifacts from ${selectedRun.url}`);

async function waitForSuccessfulRun(): Promise<WorkflowRun> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() <= deadline) {
    const runs = await listRuns();
    const completed = runs.find((run) => run.status === "completed");
    if (completed?.conclusion === "success") {
      return completed;
    }
    if (completed !== undefined) {
      throw new Error(`main ${workflow} run failed for ${targetSha}: ${JSON.stringify(completed)}`);
    }

    console.log(`waiting for successful main ${workflow} run for ${targetSha}`);
    await sleep(pollIntervalMs);
  }

  throw new Error(`timed out waiting for successful main ${workflow} run for ${targetSha}`);
}

async function listRuns(): Promise<WorkflowRun[]> {
  const runJson = await execute("gh", [
    "run",
    "list",
    "--workflow",
    workflow,
    "--branch",
    "main",
    "--commit",
    targetSha,
    "--event",
    "push",
    "--limit",
    "5",
    "--json",
    "databaseId,headBranch,headSha,conclusion,status,url",
  ]);
  const runs = JSON.parse(runJson) as WorkflowRun[];
  return runs.filter((run) => run.headBranch === "main" && run.headSha === targetSha);
}

async function sleep(milliseconds: number): Promise<void> {
  await new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function requiredArg(name: string): string {
  const value = optionalArg(name);
  if (value === undefined) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

function optionalArg(name: string): string | undefined {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined) {
    return undefined;
  }
  if (value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing value for argument: ${name}`);
  }
  return value;
}

async function execute(command: string, args: readonly string[]): Promise<string> {
  return await new Promise<string>((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise(Buffer.concat(stdout).toString("utf8"));
      } else {
        reject(new Error(`${command} ${args.join(" ")} exited with ${code}: ${Buffer.concat(stderr).toString("utf8")}`));
      }
    });
  });
}
