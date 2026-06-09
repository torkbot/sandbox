import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const args = process.argv.slice(2);
const targetSha = requiredArg("--target-sha");
const workflow = optionalArg("--workflow") ?? "CI";
const completionWorkflow = optionalArg("--completion-workflow") ?? "Complete macOS Notarization";
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

type Artifact = {
  readonly name: string;
};

type ArtifactRun = {
  readonly databaseId: number;
  readonly url: string;
};

await mkdir(resolve(repoRoot, outDir), { recursive: true });
const artifactRuns = await waitForReleaseArtifactRuns();
await downloadArtifact(artifactRuns.linux, "release-platform-linux-x64-gnu");
await downloadArtifact(artifactRuns.darwin, "release-platform-darwin-arm64");

console.log(`downloaded linux release artifact from ${artifactRuns.linux.url}`);
console.log(`downloaded darwin release artifact from ${artifactRuns.darwin.url}`);

async function waitForReleaseArtifactRuns(): Promise<{
  readonly linux: ArtifactRun;
  readonly darwin: ArtifactRun;
}> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() <= deadline) {
    const runs = await listRuns();
    const linux = await findRunWithArtifact(runs.ciRuns, "release-platform-linux-x64-gnu");
    const darwin =
      await findRunWithArtifact(runs.ciRuns, "release-platform-darwin-arm64") ??
      await findRunWithArtifact(runs.completionRuns, `release-platform-darwin-arm64-${targetSha}`);
    if (linux !== undefined && darwin !== undefined) {
      return { linux, darwin };
    }

    console.log(`waiting for successful release artifact run for ${targetSha}`);
    await sleep(pollIntervalMs);
  }

  throw new Error(`timed out waiting for successful release artifact run for ${targetSha}: ${JSON.stringify(await listRuns())}`);
}

async function listRuns(): Promise<{
  readonly ciRuns: readonly WorkflowRun[];
  readonly completionRuns: readonly WorkflowRun[];
}> {
  const [ciRuns, completionRuns] = await Promise.all([
    listWorkflowRuns(workflow, "push", targetSha),
    listWorkflowRuns(completionWorkflow, "workflow_dispatch"),
  ]);
  return {
    ciRuns: ciRuns.filter((run) => run.headBranch === "main" && run.headSha === targetSha),
    completionRuns: completionRuns.filter((run) => run.headBranch === "main"),
  };
}

async function listWorkflowRuns(workflowName: string, event: string, commit?: string): Promise<WorkflowRun[]> {
  const runArgs = [
    "run",
    "list",
    "--workflow",
    workflowName,
    "--branch",
    "main",
    "--event",
    event,
    "--limit",
    "20",
    "--json",
    "databaseId,headBranch,headSha,conclusion,status,url",
  ];
  if (commit !== undefined) {
    runArgs.push("--commit", commit);
  }
  const runJson = await execute("gh", runArgs);
  return JSON.parse(runJson) as WorkflowRun[];
}

async function findRunWithArtifact(runs: readonly WorkflowRun[], artifactName: string): Promise<ArtifactRun | undefined> {
  for (const run of runs) {
    if (run.status !== "completed") {
      continue;
    }
    if (run.conclusion !== "success" && run.conclusion !== "cancelled") {
      continue;
    }
    const artifacts = await listArtifacts(run.databaseId);
    if (artifacts.some((artifact) => artifact.name === artifactName)) {
      return {
        databaseId: run.databaseId,
        url: run.url,
      };
    }
  }
  return undefined;
}

async function listArtifacts(runId: number): Promise<readonly Artifact[]> {
  const artifactJson = await execute("gh", [
    "api",
    `repos/${requiredEnv("GITHUB_REPOSITORY")}/actions/runs/${runId}/artifacts`,
    "--jq",
    ".artifacts",
  ]);
  return JSON.parse(artifactJson) as Artifact[];
}

async function downloadArtifact(run: ArtifactRun, artifactName: string): Promise<void> {
  await execute("gh", [
    "run",
    "download",
    String(run.databaseId),
    "--name",
    artifactName,
    "--dir",
    resolve(repoRoot, outDir, artifactName),
  ]);
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

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) {
    throw new Error(`missing required environment variable: ${name}`);
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
