import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { resolve } from "node:path";

import { defineSandbox } from "../src/index.ts";
import { ensureLocalSandboxHost } from "./support/local-host-artifact.ts";
import { defaultLocalImageId, loadLocalImageArtifact, type LocalImageArtifact } from "./support/local-image-artifact.ts";

type IterationTiming = {
  readonly iteration: number;
  readonly warmup: boolean;
  readonly bootMs: number;
  readonly execMs: number;
  readonly closeMs: number;
  readonly totalMs: number;
  readonly exitCode: number;
};

type LatencyStats = {
  readonly count: number;
  readonly minMs: number;
  readonly p50Ms: number;
  readonly p90Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly maxMs: number;
  readonly meanMs: number;
  readonly stddevMs: number;
};

type BenchmarkConfig = {
  readonly iterations: number;
  readonly warmups: number;
  readonly command: string;
  readonly commandArgs: readonly string[];
  readonly image: string;
  readonly output: string;
};

const repoRoot = resolve(import.meta.dirname, "..");
const runId = new Date()
  .toISOString()
  .replaceAll(":", "-")
  .replaceAll(".", "-");
const config = parseArgs(process.argv.slice(2));

const artifacts = await assertVmLaunchSupport();
const benchmarkImage = await loadBenchmarkRootfs(config.image);
const testRootfs = benchmarkImage.image;
await mkdir(resolve(repoRoot, config.output), { recursive: true });

const timings: IterationTiming[] = [];
const totalRuns = config.warmups + config.iterations;
console.log(
  `Running ${config.iterations} measured lifecycle iterations` +
    (config.warmups > 0 ? ` after ${config.warmups} warmup iterations` : "") +
    ` with command: ${[config.command, ...config.commandArgs].join(" ")}`,
);

for (let index = 0; index < totalRuns; index += 1) {
  const warmup = index < config.warmups;
  const iteration = warmup ? index + 1 : index - config.warmups + 1;
  const timing = await runLifecycleIteration(iteration, warmup, config);
  timings.push(timing);
  const label = warmup ? `warmup ${iteration}` : `iteration ${iteration}`;
  console.log(
    `${label}: boot=${formatMs(timing.bootMs)} exec=${formatMs(timing.execMs)} ` +
      `close=${formatMs(timing.closeMs)} total=${formatMs(timing.totalMs)}`,
  );
}

const measured = timings.filter((timing) => !timing.warmup);
const report = {
  runId,
  platform: platform(),
  arch: process.arch,
  command: config.command,
  commandArgs: config.commandArgs,
  rootfs: testRootfs.name,
  git: gitMetadata(),
  node: {
    execPath: process.execPath,
    version: process.version,
  },
  artifacts: {
    ...artifacts,
    rootfs: benchmarkImage.rootfs,
    rootfsFactsPath: benchmarkImage.factsPath,
  },
  iterations: config.iterations,
  warmups: config.warmups,
  stats: {
    boot: summarize(measured.map((timing) => timing.bootMs)),
    exec: summarize(measured.map((timing) => timing.execMs)),
    close: summarize(measured.map((timing) => timing.closeMs)),
    total: summarize(measured.map((timing) => timing.totalMs)),
  },
  timings,
};

const outputPath = resolve(repoRoot, config.output, "summary.json");
await writeFile(outputPath, `${JSON.stringify(report, null, 2)}\n`);
console.log(`Wrote benchmark summary to ${outputPath}`);
console.log(
  `Total p50=${formatMs(report.stats.total.p50Ms)} p95=${formatMs(report.stats.total.p95Ms)} mean=${formatMs(report.stats.total.meanMs)}`,
);

async function runLifecycleIteration(
  iteration: number,
  warmup: boolean,
  input: BenchmarkConfig,
): Promise<IterationTiming> {
  const totalStart = nowMs();
  const bootStart = totalStart;
  const sandboxDefinition = defineSandbox({
    rootfs: testRootfs,
  });

  const sandbox = await sandboxDefinition.boot();
  let closed = false;
  try {
    const bootMs = nowMs() - bootStart;

    const execStart = nowMs();
    const result = await sandbox.exec(input.command, input.commandArgs);
    const execMs = nowMs() - execStart;
    if (result.exitCode !== 0) {
      throw new Error(
        `guest command exited with ${result.exitCode}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
      );
    }

    const closeStart = nowMs();
    await sandbox.close();
    closed = true;
    const closeMs = nowMs() - closeStart;

    return {
      iteration,
      warmup,
      bootMs,
      execMs,
      closeMs,
      totalMs: nowMs() - totalStart,
      exitCode: result.exitCode,
    };
  } finally {
    if (!closed) {
      await sandbox.close();
    }
  }
}

async function loadBenchmarkRootfs(imageId: string): Promise<LocalImageArtifact> {
  return await loadLocalImageArtifact({
    repoRoot,
    imageId,
    consumer: "benchmark",
  });
}

async function assertVmLaunchSupport(): Promise<{
  readonly hostBinary: ArtifactMetadata;
}> {
  if (process.platform === "linux" && !existsSync("/dev/kvm")) {
    throw new Error("Linux KVM is not available on this host");
  }
  if (process.platform !== "darwin" && process.platform !== "linux") {
    throw new Error(`unsupported VM launch host platform: ${process.platform}`);
  }
  const hostBinary = await ensureLocalSandboxHost({
    repoRoot,
    consumer: "benchmark",
  });
  return {
    hostBinary: await artifactMetadata(hostBinary),
  };
}

type ArtifactMetadata = {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
};

async function artifactMetadata(path: string): Promise<ArtifactMetadata> {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    const data = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    bytes += data.byteLength;
    hash.update(data);
  }
  return {
    path,
    sha256: hash.digest("hex"),
    bytes,
  };
}

function gitMetadata(): {
  readonly commit: string | null;
  readonly dirty: boolean | null;
} {
  try {
    const commit = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    const dirty =
      execFileSync("git", ["status", "--porcelain"], {
        cwd: repoRoot,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }).trim().length > 0;
    return { commit, dirty };
  } catch {
    return { commit: null, dirty: null };
  }
}

function parseArgs(args: readonly string[]): BenchmarkConfig {
  let iterations = 10;
  let warmups = 1;
  let command = "/bin/true";
  let commandArgs: readonly string[] = [];
  let image = defaultLocalImageId;
  let output = `test-results/benchmarks/e2e-lifecycle/${runId}`;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === undefined) {
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      printUsage();
      process.exit(0);
    }
    if (arg === "--iterations" || arg === "-n") {
      iterations = parsePositiveInteger(readValue(args, index), arg);
      index += 1;
      continue;
    }
    if (arg === "--warmups") {
      warmups = parseNonNegativeInteger(readValue(args, index), arg);
      index += 1;
      continue;
    }
    if (arg === "--command" || arg === "-c") {
      command = "/bin/sh";
      commandArgs = ["-lc", readValue(args, index)];
      index += 1;
      continue;
    }
    if (arg === "--exec") {
      command = readValue(args, index);
      commandArgs = [];
      index += 1;
      continue;
    }
    if (arg === "--output") {
      output = readValue(args, index);
      index += 1;
      continue;
    }
    if (arg === "--image") {
      image = readValue(args, index);
      index += 1;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return { iterations, warmups, command, commandArgs, image, output };
}

function readValue(args: readonly string[], index: number): string {
  const value = args[index + 1];
  if (value === undefined || value.startsWith("-")) {
    throw new Error(`missing value for ${args[index]}`);
  }
  return value;
}

function parsePositiveInteger(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new Error(`${label} must be a positive integer`);
  }
  return parsed;
}

function parseNonNegativeInteger(value: string, label: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return parsed;
}

function summarize(values: readonly number[]): LatencyStats {
  if (values.length === 0) {
    throw new Error("cannot summarize an empty sample");
  }

  const sorted = [...values].sort((left, right) => left - right);
  const meanMs = sorted.reduce((sum, value) => sum + value, 0) / sorted.length;
  const variance =
    sorted.reduce((sum, value) => sum + (value - meanMs) ** 2, 0) /
    sorted.length;
  const first = sorted[0];
  const last = sorted[sorted.length - 1];
  if (first === undefined || last === undefined) {
    throw new Error("cannot summarize an empty sample");
  }

  return {
    count: sorted.length,
    minMs: first,
    p50Ms: percentile(sorted, 0.5),
    p90Ms: percentile(sorted, 0.9),
    p95Ms: percentile(sorted, 0.95),
    p99Ms: percentile(sorted, 0.99),
    maxMs: last,
    meanMs,
    stddevMs: Math.sqrt(variance),
  };
}

function percentile(
  sortedValues: readonly number[],
  percentileValue: number,
): number {
  if (sortedValues.length === 1) {
    const only = sortedValues[0];
    if (only === undefined) {
      throw new Error("cannot compute percentile for an empty sample");
    }
    return only;
  }

  const position = (sortedValues.length - 1) * percentileValue;
  const lowerIndex = Math.floor(position);
  const upperIndex = Math.ceil(position);
  const lower = sortedValues[lowerIndex];
  const upper = sortedValues[upperIndex];
  if (lower === undefined || upper === undefined) {
    throw new Error("percentile index out of range");
  }
  if (lowerIndex === upperIndex) {
    return lower;
  }
  return lower + (upper - lower) * (position - lowerIndex);
}

function nowMs(): number {
  return Number(process.hrtime.bigint()) / 1_000_000;
}

function formatMs(value: number): string {
  return `${value.toFixed(1)}ms`;
}

function printUsage(): void {
  console.log(`usage: node ./scripts/benchmark-e2e-lifecycle.ts [options]

Boot a sandbox microVM, wait for init.ready, run one guest command, close
the VM, and report latency statistics for repeated lifecycle iterations.

Options:
  -n, --iterations <count>  measured iterations to run (default: 10)
      --warmups <count>     warmup iterations excluded from stats (default: 1)
      --exec <path>          guest executable to run directly (default: /bin/true)
  -c, --command <script>    guest shell command to run through /bin/sh -lc
      --image <id>           built local image artifact to use (default: ${defaultLocalImageId})
      --output <dir>        output directory for summary.json

Image prerequisite:
  npm run images:build-local -- --image ${defaultLocalImageId}
`);
}
