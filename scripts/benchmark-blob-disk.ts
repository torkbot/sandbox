import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { platform } from "node:os";
import { resolve } from "node:path";
import { performance } from "node:perf_hooks";

import {
  block,
  defineSandbox,
  network,
  rootfs,
  type SandboxBlobBlockProvider,
} from "../src/index.ts";
import { ensureLocalSandboxHost } from "./support/local-host-artifact.ts";
import { loadLocalImageArtifact } from "./support/local-image-artifact.ts";

type Suite = "acquisition" | "micro" | "workload" | "all";

type Config = {
  readonly provider: SandboxBlobBlockProvider;
  readonly providerLabel: string;
  readonly volume: string;
  readonly sizeMiB: number;
  readonly fileSizeMiB: number;
  readonly runtimeSeconds: number;
  readonly trials: number;
  readonly suite: Suite;
  readonly npmPackage?: string;
  readonly output: string;
  readonly plan: boolean;
};

type FioCase = {
  readonly name: string;
  readonly filename: string;
  readonly args: readonly string[];
};

type Target = {
  readonly name: "control" | "blob";
  readonly path: string;
};

const repoRoot = resolve(import.meta.dirname, "..");
const config = parseArgs(process.argv.slice(2));
const fioCases = defineFioCases(config);

if (config.plan) {
  process.stdout.write(`${JSON.stringify({ config: publicConfig(config), fioCases }, null, 2)}\n`);
  process.exit(0);
}

const hostPath = await ensureLocalSandboxHost({ repoRoot, consumer: "blob disk benchmark" });
const builtHostPath = resolve(repoRoot, "target/release/sandbox-host");
if (sha256(hostPath) !== sha256(builtHostPath)) {
  throw new Error(
    "blob disk benchmark host is stale; run npm run build:host, then npm run artifacts:link-current",
  );
}
await mkdir(config.output, { recursive: true });
if (config.provider.kind === "local") {
  await mkdir(config.provider.path, { recursive: true });
}
if (config.suite === "acquisition") {
  await runAcquisitionBenchmark();
  process.exit(0);
}
const image = await loadLocalImageArtifact({ repoRoot, consumer: "blob disk benchmark" });

const acquireStarted = performance.now();
const disk = await block.blob.acquire({
  provider: config.provider,
  volume: config.volume,
  sizeBytes: BigInt(config.sizeMiB) * 1024n * 1024n,
});
const acquireMs = performance.now() - acquireStarted;

const bootStarted = performance.now();
const sandbox = await defineSandbox({
  rootfs: rootfs.ephemeral({
    base: image.image,
    maxDirtyBytes: (config.fileSizeMiB + 128) * 1024 * 1024,
  }),
  network: network.policy((connection) => {
    connection.accept();
  }),
  resources: { cpus: 2, memoryMiB: 2048 },
}).boot({ mounts: { "/workspace": disk }, cwd: "/workspace" });
const bootMs = performance.now() - bootStarted;

const fio = [];
const npm = [];
let closeMs = 0;
let failure: ReturnType<typeof serializeError> | undefined;
try {
  if (config.suite === "micro" || config.suite === "all") {
    await runChecked("install fio", "/sbin/apk", ["add", "--no-cache", "fio"]);
    for (const target of targets()) {
      await runChecked(`prepare ${target.name} target`, "/bin/mkdir", ["-p", target.path]);
      for (const test of fioCases) {
        for (let trial = 1; trial <= config.trials; trial += 1) {
          const result = await runFio(target, test, trial);
          fio.push(result);
          await writeFile(
            resolve(config.output, `${target.name}-${test.name}-${trial}.json`),
            `${JSON.stringify(result.raw, null, 2)}\n`,
          );
          process.stderr.write(
            `${target.name}/${test.name} trial ${trial}: ${formatRate(result.read)} read, `
              + `${formatRate(result.write)} write, sync-p95=${formatNs(result.syncP95Ns)}\n`,
          );
        }
      }
    }
  }
  if (config.suite === "workload" || config.suite === "all") {
    await warmNpmCache(config.npmPackage!);
    for (let trial = 1; trial <= config.trials; trial += 1) {
      for (const target of targets()) {
        npm.push(await runNpmWorkload(target, config.npmPackage!, trial));
      }
    }
  }
} catch (error) {
  failure = serializeError(error);
} finally {
  const closeStarted = performance.now();
  try {
    await sandbox.close();
  } catch (error) {
    failure ??= serializeError(error);
  }
  closeMs = performance.now() - closeStarted;
}

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  git: gitMetadata(hostPath),
  host: { platform: platform(), arch: process.arch, node: process.version },
  config: publicConfig(config),
  timings: { acquireMs, bootMs, closeMs },
  fio: fio.map(({ raw: _raw, ...result }) => result),
  fioComparisons: summarizeFio(fio),
  npm,
  npmComparison: summarizeNpm(npm),
  failure,
};
await writeFile(resolve(config.output, "summary.json"), `${JSON.stringify(report, null, 2)}\n`);
process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
if (failure !== undefined) {
  process.exitCode = 1;
}

async function runFio(target: Target, test: FioCase, trial: number) {
  const name = `${target.name}-${test.name}-${trial}`;
  const result = await runChecked(name, "/usr/bin/fio", [
    `--name=${name}`,
    `--filename=${target.path}/${test.filename}`,
    `--size=${config.fileSizeMiB}m`,
    `--runtime=${config.runtimeSeconds}`,
    "--time_based=1",
    "--group_reporting=1",
    "--output-format=json",
    ...test.args,
  ]);
  const raw = JSON.parse(result.stdout) as FioOutput;
  const job = raw.jobs[0];
  if (job === undefined) {
    throw new Error(`${test.name} returned no fio jobs`);
  }
  return {
    target: target.name,
    name: test.name,
    trial,
    elapsedMs: result.elapsedMs,
    read: fioDirection(job.read),
    write: fioDirection(job.write),
    syncP95Ns: percentile(job.sync?.lat_ns?.percentile, "95.000000"),
    raw,
  };
}

async function runNpmWorkload(target: Target, packageSpec: string, trial: number) {
  const directory = `${target.path}/npm-workload`;
  const command = [
    "set -eu",
    `rm -rf ${shellArg(directory)}`,
    `mkdir -p ${shellArg(directory)}`,
    `cd ${shellArg(directory)}`,
    "npm init --yes >/dev/null",
    `npm install --prefer-offline --ignore-scripts --no-audit --no-fund ${shellArg(packageSpec)}`,
    "find node_modules -type f | wc -l",
    "du -sk node_modules",
  ].join("\n");
  const result = await runChecked("npm workload", "/bin/sh", ["-lc", command]);
  const lines = result.stdout.trim().split("\n");
  return {
    target: target.name,
    trial,
    package: packageSpec,
    elapsedMs: result.elapsedMs,
    files: Number(lines.at(-2)),
    kib: Number(lines.at(-1)?.split(/\s+/)[0]),
  };
}

async function warmNpmCache(packageSpec: string) {
  const directory = "/var/tmp/sandbox-blob-disk-npm-warmup";
  const command = [
    "set -eu",
    `rm -rf ${shellArg(directory)}`,
    `mkdir -p ${shellArg(directory)}`,
    `cd ${shellArg(directory)}`,
    "npm init --yes >/dev/null",
    `npm install --ignore-scripts --no-audit --no-fund ${shellArg(packageSpec)} >/dev/null`,
    `rm -rf ${shellArg(directory)}`,
  ].join("\n");
  await runChecked("warm npm cache", "/bin/sh", ["-lc", command]);
}

async function runChecked(label: string, command: string, args: readonly string[]) {
  const started = performance.now();
  const result = await sandbox.exec(command, args);
  const elapsedMs = performance.now() - started;
  if (result.exitCode !== 0) {
    throw new Error(
      `${label} exited with ${result.exitCode}\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
    );
  }
  return { ...result, elapsedMs };
}

function defineFioCases(input: Config): readonly FioCase[] {
  if (input.suite === "acquisition" || input.suite === "workload") {
    return [];
  }
  return [
    {
      name: "seq-write-q1",
      filename: "sequential.bin",
      args: ["--rw=write", "--bs=1m", "--ioengine=libaio", "--direct=1", "--iodepth=1"],
    },
    {
      name: "seq-write-q32",
      filename: "sequential.bin",
      args: ["--rw=write", "--bs=1m", "--ioengine=libaio", "--direct=1", "--iodepth=32"],
    },
    {
      name: "rand-write-q1",
      filename: "random.bin",
      args: ["--rw=randwrite", "--bs=4k", "--ioengine=libaio", "--direct=1", "--iodepth=1"],
    },
    {
      name: "rand-write-q32",
      filename: "random.bin",
      args: ["--rw=randwrite", "--bs=4k", "--ioengine=libaio", "--direct=1", "--iodepth=32"],
    },
    {
      name: "rand-write-fdatasync",
      filename: "random.bin",
      args: ["--rw=randwrite", "--bs=4k", "--ioengine=sync", "--direct=0", "--fdatasync=1"],
    },
    {
      name: "rand-read-warm-q32",
      filename: "random.bin",
      args: ["--rw=randread", "--bs=4k", "--ioengine=libaio", "--direct=1", "--iodepth=32"],
    },
  ];
}

function targets(): readonly Target[] {
  return [
    { name: "control", path: "/var/tmp/sandbox-blob-disk-benchmark" },
    { name: "blob", path: "/workspace" },
  ];
}

function parseArgs(args: readonly string[]): Config {
  const values = new Map<string, string>();
  let plan = false;
  for (const arg of args) {
    if (arg === "--plan") {
      plan = true;
      continue;
    }
    const match = /^--([^=]+)=(.+)$/.exec(arg);
    if (match === null) {
      throw new Error(`invalid argument: ${arg}; expected --name=value`);
    }
    values.set(match[1]!, match[2]!);
  }
  const providerKind = required(values, "provider");
  const volume = required(values, "volume");
  const suite = (values.get("suite") ?? "micro") as Suite;
  if (suite !== "acquisition" && suite !== "micro" && suite !== "workload" && suite !== "all") {
    throw new Error("--suite must be acquisition, micro, workload, or all");
  }
  const npmPackage = values.get("npm-package");
  if ((suite === "workload" || suite === "all") && npmPackage === undefined) {
    throw new Error("--npm-package is required for workload benchmarks");
  }
  const output = resolve(repoRoot, values.get("output") ?? `dist/benchmarks/blob-disk/${runId()}`);
  const common = {
    volume,
    sizeMiB: positiveInteger(values.get("size-mib") ?? "256", "size-mib"),
    fileSizeMiB: positiveInteger(values.get("file-size-mib") ?? "64", "file-size-mib"),
    runtimeSeconds: positiveInteger(values.get("runtime-seconds") ?? "10", "runtime-seconds"),
    trials: positiveInteger(values.get("trials") ?? "3", "trials"),
    suite,
    npmPackage,
    output,
    plan,
  };
  if (providerKind === "local") {
    const path = resolve(required(values, "local-path"));
    return {
      ...common,
      providerLabel: `local:${path}`,
      provider: { kind: "local", path, prefix: values.get("prefix") },
    };
  }
  if (providerKind === "s3") {
    const endpoint = required(values, "endpoint");
    const bucket = required(values, "bucket");
    const prefix = required(values, "prefix");
    return {
      ...common,
      providerLabel: `s3:${new URL(endpoint).host}/${bucket}/${prefix}`,
      provider: {
        kind: "s3",
        endpoint,
        bucket,
        prefix,
        region: values.get("region") ?? "auto",
        auth: { kind: "environment" },
      },
    };
  }
  throw new Error("--provider must be local or s3");
}

async function runAcquisitionBenchmark() {
  const observations: Array<Awaited<ReturnType<typeof acquireAndClose>>> = [];
  for (let trial = 1; trial <= config.trials; trial += 1) {
    const volume = `${config.volume}-a-${trial}-${randomUUID().slice(0, 8)}`;
    if (volume.length > 128) {
      throw new Error("--volume is too long for acquisition trial suffixes");
    }
    observations.push(await acquireAndClose(volume, trial, "new"));
    observations.push(await acquireAndClose(volume, trial, "reacquire"));
  }
  const values = (kind: "new" | "reacquire", field: "acquireMs" | "closeMs") => observations
    .filter((observation) => observation.kind === kind)
    .map((observation) => observation[field]);
  const report = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    git: gitMetadata(hostPath),
    host: { platform: platform(), arch: process.arch, node: process.version },
    config: publicConfig(config),
    acquisition: {
      observations,
      summary: {
        new: {
          acquireMs: distribution(values("new", "acquireMs")),
          closeMs: distribution(values("new", "closeMs")),
        },
        reacquire: {
          acquireMs: distribution(values("reacquire", "acquireMs")),
          closeMs: distribution(values("reacquire", "closeMs")),
        },
      },
    },
  };
  await writeFile(resolve(config.output, "summary.json"), `${JSON.stringify(report, null, 2)}\n`);
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

async function acquireAndClose(volume: string, trial: number, kind: "new" | "reacquire") {
  const acquireStarted = performance.now();
  const device = await block.blob.acquire({
    provider: config.provider,
    volume,
    sizeBytes: BigInt(config.sizeMiB) * 1024n * 1024n,
  });
  const acquireMs = performance.now() - acquireStarted;
  const lifecycle = device.getLifecycle?.();
  if (lifecycle === undefined) {
    throw new Error("acquired blob block device did not expose lifecycle");
  }
  const closeStarted = performance.now();
  await lifecycle.close();
  return { kind, trial, acquireMs, closeMs: performance.now() - closeStarted };
}

function publicConfig(input: Config) {
  return {
    provider: input.providerLabel,
    volume: input.volume,
    sizeMiB: input.sizeMiB,
    fileSizeMiB: input.fileSizeMiB,
    runtimeSeconds: input.runtimeSeconds,
    trials: input.trials,
    suite: input.suite,
    npmPackage: input.npmPackage,
    output: input.output,
  };
}

function fioDirection(value: FioDirection | undefined) {
  return {
    bytesPerSecond: value?.bw_bytes ?? 0,
    iops: value?.iops ?? 0,
    p50Ns: percentile(value?.clat_ns?.percentile, "50.000000"),
    p95Ns: percentile(value?.clat_ns?.percentile, "95.000000"),
    p99Ns: percentile(value?.clat_ns?.percentile, "99.000000"),
  };
}

function percentile(values: Readonly<Record<string, number>> | undefined, key: string): number | undefined {
  return values?.[key];
}

function formatRate(value: ReturnType<typeof fioDirection>): string {
  return `${value.iops.toFixed(1)} IOPS/${(value.bytesPerSecond / 1024 / 1024).toFixed(1)} MiB/s`;
}

function formatNs(value: number | undefined): string {
  return value === undefined ? "n/a" : `${(value / 1_000_000).toFixed(1)} ms`;
}

function summarizeFio(results: ReadonlyArray<{
  readonly target: Target["name"];
  readonly name: string;
  readonly read: ReturnType<typeof fioDirection>;
  readonly write: ReturnType<typeof fioDirection>;
}>) {
  return [...new Set(results.map((result) => result.name))].map((name) => {
    const values = (target: Target["name"], field: "iops" | "bytesPerSecond") => results
      .filter((result) => result.name === name && result.target === target)
      .map((result) => Math.max(result.read[field], result.write[field]));
    const controlIops = median(values("control", "iops"));
    const blobIops = median(values("blob", "iops"));
    const controlBytesPerSecond = median(values("control", "bytesPerSecond"));
    const blobBytesPerSecond = median(values("blob", "bytesPerSecond"));
    return {
      name,
      control: { iops: controlIops, bytesPerSecond: controlBytesPerSecond },
      blob: { iops: blobIops, bytesPerSecond: blobBytesPerSecond },
      percentOfControl: controlIops === 0 ? undefined : blobIops / controlIops * 100,
    };
  });
}

function summarizeNpm(results: ReadonlyArray<{
  readonly target: Target["name"];
  readonly elapsedMs: number;
}>) {
  if (results.length === 0) {
    return undefined;
  }
  const elapsed = (target: Target["name"]) => median(
    results.filter((result) => result.target === target).map((result) => result.elapsedMs),
  );
  const controlMs = elapsed("control");
  const blobMs = elapsed("blob");
  return { controlMs, blobMs, percentOfControl: blobMs / controlMs * 100 };
}

function median(values: readonly number[]): number {
  if (values.length === 0) {
    throw new Error("cannot calculate a median without observations");
  }
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 0
    ? (ordered[middle - 1]! + ordered[middle]!) / 2
    : ordered[middle]!;
}

function distribution(values: readonly number[]) {
  const ordered = [...values].sort((left, right) => left - right);
  return {
    min: ordered[0]!,
    median: median(ordered),
    p95: ordered[Math.ceil(ordered.length * 0.95) - 1]!,
    max: ordered.at(-1)!,
  };
}

function positiveInteger(value: string, name: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`--${name} must be a positive integer`);
  }
  return parsed;
}

function required(values: ReadonlyMap<string, string>, name: string): string {
  const value = values.get(name);
  if (value === undefined || value.length === 0) {
    throw new Error(`--${name} is required`);
  }
  return value;
}

function shellArg(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function runId(): string {
  return new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-");
}

function gitMetadata(hostPath: string) {
  return {
    commit: execFileSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8" }).trim(),
    dirty: execFileSync("git", ["status", "--porcelain"], { cwd: repoRoot, encoding: "utf8" }).trim().length > 0,
    benchmarkSha256: sha256(import.meta.filename),
    hostSha256: sha256(hostPath),
  };
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function serializeError(error: unknown) {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      ...("code" in error ? { code: error.code } : {}),
    };
  }
  return { name: "Error", message: String(error) };
}

type FioDirection = {
  readonly bw_bytes?: number;
  readonly iops?: number;
  readonly clat_ns?: { readonly percentile?: Readonly<Record<string, number>> };
};

type FioOutput = {
  readonly jobs: ReadonlyArray<{
    readonly read?: FioDirection;
    readonly write?: FioDirection;
    readonly sync?: { readonly lat_ns?: { readonly percentile?: Readonly<Record<string, number>> } };
  }>;
};
