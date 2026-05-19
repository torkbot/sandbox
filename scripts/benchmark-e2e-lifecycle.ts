import { access, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { platform } from "node:os";
import { resolve } from "node:path";

import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  type SandboxControlEvent,
} from "../src/index.ts";
import { hostBinaryPath } from "../src/host-process.ts";

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
  readonly rootfs: string;
  readonly output: string;
};

const repoRoot = resolve(import.meta.dirname, "..");
const runId = new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
const config = parseArgs(process.argv.slice(2));

await assertVmLaunchSupport(config.rootfs);
await mkdir(resolve(repoRoot, config.output), { recursive: true });

const timings: IterationTiming[] = [];
const totalRuns = config.warmups + config.iterations;
console.log(
  `Running ${config.iterations} measured lifecycle iterations` +
    (config.warmups > 0 ? ` after ${config.warmups} warmup iterations` : "") +
    ` with command: ${config.command}`,
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
  rootfs: config.rootfs,
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
console.log(`Total p50=${formatMs(report.stats.total.p50Ms)} p95=${formatMs(report.stats.total.p95Ms)} mean=${formatMs(report.stats.total.meanMs)}`);

async function runLifecycleIteration(
  iteration: number,
  warmup: boolean,
  input: BenchmarkConfig,
): Promise<IterationTiming> {
  const totalStart = nowMs();
  const bootStart = totalStart;
  const vm = await spawnSandbox({
    name: warmup ? `lifecycle-warmup-${iteration}` : `lifecycle-benchmark-${iteration}`,
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs(input.rootfs, {
      format: "erofs",
    }),
  });

  let closed = false;
  try {
    await collectAsync(vm.control.incoming, isInitReady, 10_000);
    const bootMs = nowMs() - bootStart;

    const execStart = nowMs();
    const result = await vm.control.exec({
      id: warmup ? `warmup-${iteration}` : `benchmark-${iteration}`,
      argv: ["/bin/sh", "-lc", input.command],
    });
    const execMs = nowMs() - execStart;
    if (result.exitCode !== 0) {
      throw new Error(
        `guest command exited with ${result.exitCode}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
      );
    }

    const closeStart = nowMs();
    await vm.close();
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
      await vm.close();
    }
  }
}

function isInitReady(event: SandboxControlEvent): event is Extract<SandboxControlEvent, { type: "init.ready" }> {
  return event.type === "init.ready";
}

async function collectAsync<T>(
  iterable: AsyncIterable<T>,
  predicate: (item: T) => boolean,
  timeoutMs: number,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      (async () => {
        for await (const item of iterable) {
          if (predicate(item)) {
            return item;
          }
        }
        throw new Error("Async iterable ended before the expected event was observed");
      })(),
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          reject(new Error(`Timed out after ${timeoutMs}ms waiting for expected event`));
        }, timeoutMs);
        timeout.unref();
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

async function assertVmLaunchSupport(rootfs: string): Promise<void> {
  hostBinaryPath();
  if (process.platform === "linux" && !existsSync("/dev/kvm")) {
    throw new Error("Linux KVM is not available on this host");
  }
  if (process.platform !== "darwin" && process.platform !== "linux") {
    throw new Error(`unsupported VM launch host platform: ${process.platform}`);
  }
  await access(resolve(repoRoot, rootfs));
}

function parseArgs(args: readonly string[]): BenchmarkConfig {
  let iterations = 10;
  let warmups = 1;
  let command = "true";
  let rootfs = "dist/rootfs/alpine-3.20.erofs";
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
      command = readValue(args, index);
      index += 1;
      continue;
    }
    if (arg === "--rootfs") {
      rootfs = readValue(args, index);
      index += 1;
      continue;
    }
    if (arg === "--output") {
      output = readValue(args, index);
      index += 1;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return { iterations, warmups, command, rootfs, output };
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
  const variance = sorted.reduce((sum, value) => sum + (value - meanMs) ** 2, 0) / sorted.length;
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

function percentile(sortedValues: readonly number[], percentileValue: number): number {
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

Boot a sandbox microVM, wait for init.ready, run one guest shell command, close
the VM, and report latency statistics for repeated lifecycle iterations.

Options:
  -n, --iterations <count>  measured iterations to run (default: 10)
      --warmups <count>     warmup iterations excluded from stats (default: 1)
  -c, --command <script>    guest shell command to run (default: true)
      --rootfs <path>       EROFS rootfs path (default: dist/rootfs/alpine-3.20.erofs)
      --output <dir>        output directory for summary.json
`);
}
