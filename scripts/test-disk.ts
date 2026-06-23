#!/usr/bin/env node

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { stderr, stdout } from "node:process";
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  type NetworkConnectionRequest,
  type SandboxBlockStore,
} from "../src/index.ts";
import type { RootfsEnvironmentFactsManifest } from "../src/environment-facts.ts";

type DiskTestOptions = {
  readonly size: string;
  readonly runtimeSeconds: number;
  readonly target: "rootfs" | "vfs" | "both";
  readonly skipInstall: boolean;
};

const options = parseArgs(process.argv.slice(2));
const blockStore = memoryBlockStore();
const networkStats = createNetworkStats();
const workspace = fs.memory({});
const testRootfs = await loadDiskTestRootfs();

const sandbox = defineSandbox({
  rootfs: rootfs.cow({
    base: testRootfs,
    writable: blockStore,
  }),
  network: network.policy((connection) => {
    networkStats.observe(connection);
    connection.accept();
  }),
  resources: {
    cpus: 2,
    memoryMiB: 2048,
  },
});

stderr.write("Booting memory-backed COW rootfs for disk test.\n");
const vm = await sandbox.boot({
  mounts: {
    "/mnt": fs.virtual(workspace),
  },
  cwd: "/root",
});

let exitCode = 1;
try {
  await runChecked("df-before", "/bin/df", ["-h", "/", "/mnt"]);
  if (!options.skipInstall) {
    await runChecked("install-fio", "/sbin/apk", ["add", "--no-cache", "fio"]);
  }

  if (options.target === "rootfs" || options.target === "both") {
    await runFio("cow-rootfs", "/root", options);
  }
  if (options.target === "vfs" || options.target === "both") {
    await runFio("memory-vfs", "/mnt", options);
  }

  await runChecked("df-after", "/bin/df", ["-h", "/", "/mnt"]);
  exitCode = 0;
} finally {
  try {
    await vm.close();
  } finally {
    dumpStats(blockStore.stats(), networkStats.snapshot());
  }
}

process.exitCode = exitCode;

async function loadDiskTestRootfs() {
  const repoRoot = resolve(import.meta.dirname, "..");
  const path = resolve(process.env.SANDBOX_TEST_ROOTFS_IMAGE ?? resolve(repoRoot, "dist/rootfs/alpine-3.23.qcow2"));
  const factsPath = resolve(process.env.SANDBOX_TEST_ROOTFS_FACTS ?? resolve(repoRoot, "dist/rootfs/alpine-3.23-agent.environment-facts.json"));
  const [imageStat, manifest] = await Promise.all([
    stat(path),
    readRootfsFactsManifest(factsPath),
  ]);
  if (!imageStat.isFile()) {
    throw new Error(`rootfs image path is not a file: ${path}`);
  }
  return rootfs.image({
    name: manifest.rootfs,
    path,
    format: "qcow2",
    architecture: process.arch,
    digest: `sha256:${await sha256File(path)}`,
    sizeBytes: BigInt(imageStat.size),
    facts: manifest.facts,
  });
}

async function readRootfsFactsManifest(path: string): Promise<RootfsEnvironmentFactsManifest> {
  const manifest = JSON.parse(await readFile(path, "utf8")) as RootfsEnvironmentFactsManifest;
  if (manifest.schemaVersion !== 1) {
    throw new Error(`unsupported rootfs facts manifest schema version: ${manifest.schemaVersion}`);
  }
  return manifest;
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolveDigest, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => {
      hash.update(chunk);
    });
    stream.on("error", reject);
    stream.on("end", () => {
      resolveDigest(hash.digest("hex"));
    });
  });
}

async function runFio(name: string, directory: string, options: DiskTestOptions): Promise<void> {
  await runChecked(name, "/usr/bin/fio", [
    `--name=${name}`,
    `--directory=${directory}`,
    "--filename=fio-verify.bin",
    `--size=${options.size}`,
    "--bs=4k",
    "--rw=randrw",
    "--rwmixread=50",
    "--ioengine=sync",
    "--direct=0",
    "--verify=crc32c",
    "--verify_fatal=1",
    "--do_verify=1",
    `--runtime=${options.runtimeSeconds}`,
    "--time_based",
    "--group_reporting",
    "--unlink=1",
  ]);
}

async function runChecked(label: string, command: string, args: readonly string[]): Promise<void> {
  stderr.write(`\n==> ${label}: ${[command, ...args].join(" ")}\n`);
  const child = await vm.spawn(command, args, {
    cwd: "/root",
    env: {
      TERM: "dumb",
    },
  });
  const stdoutPump = pump(child.stdout, stdout);
  const stderrPump = pump(child.stderr, stderr);
  const { exitCode } = await child.exit;
  await Promise.all([stdoutPump, stderrPump]);
  if (exitCode !== 0) {
    throw new Error(`${label} failed with exit code ${exitCode}`);
  }
}

async function pump(source: AsyncIterable<Uint8Array>, destination: NodeJS.WritableStream): Promise<void> {
  for await (const chunk of source) {
    destination.write(chunk);
  }
}

type CowBlockStats = {
  readonly blockSize: number;
  readonly storedBlocks: number;
  readonly storedBytes: number;
  readonly listCalls: number;
  readonly readCalls: number;
  readonly readRanges: number;
  readonly readChunksReturned: number;
  readonly readBytesReturned: number;
  readonly writeCalls: number;
  readonly writeChunks: number;
  readonly writeBytes: number;
  readonly flushCalls: number;
};

type NetworkStatsSnapshot = {
  readonly policyCalls: number;
  readonly byDestination: ReadonlyMap<string, number>;
};

function memoryBlockStore(): SandboxBlockStore & { stats(): CowBlockStats } {
  const blocks = new Map<bigint, Uint8Array>();
  let listCalls = 0;
  let readCalls = 0;
  let readRanges = 0;
  let readChunksReturned = 0;
  let readBytesReturned = 0;
  let writeCalls = 0;
  let writeChunks = 0;
  let writeBytes = 0;
  let flushCalls = 0;
  return {
    blockSize: 4096,
    async list() {
      listCalls += 1;
      return Array.from(blocks.keys());
    },
    async read(range) {
      readCalls += 1;
      readRanges += range.count;
      const chunks = [];
      for (let offset = 0; offset < range.count; offset += 1) {
        const start = range.start + BigInt(offset);
        const data = blocks.get(start);
        if (data !== undefined) {
          chunks.push({ start, data });
          readChunksReturned += 1;
          readBytesReturned += data.byteLength;
        }
      }
      return chunks;
    },
    async write(chunks) {
      writeCalls += 1;
      for (const chunk of chunks) {
        const data = chunk.data.slice();
        blocks.set(chunk.start, data);
        writeChunks += 1;
        writeBytes += data.byteLength;
      }
    },
    async flush() {
      flushCalls += 1;
    },
    stats() {
      let storedBytes = 0;
      for (const block of blocks.values()) {
        storedBytes += block.byteLength;
      }
      return {
        blockSize: 4096,
        storedBlocks: blocks.size,
        storedBytes,
        listCalls,
        readCalls,
        readRanges,
        readChunksReturned,
        readBytesReturned,
        writeCalls,
        writeChunks,
        writeBytes,
        flushCalls,
      };
    },
  };
}

function createNetworkStats(): {
  observe(connection: NetworkConnectionRequest): void;
  snapshot(): NetworkStatsSnapshot;
} {
  let policyCalls = 0;
  const byDestination = new Map<string, number>();
  return {
    observe(connection) {
      policyCalls += 1;
      const destination = [
        connection.transport,
        connection.dst.ip,
        connection.dst.port,
      ].join(":");
      byDestination.set(destination, (byDestination.get(destination) ?? 0) + 1);
    },
    snapshot() {
      return {
        policyCalls,
        byDestination: new Map(byDestination),
      };
    },
  };
}

function dumpStats(cow: CowBlockStats, net: NetworkStatsSnapshot): void {
  stderr.write("\nDisk test stats:\n");
  stderr.write("  COW rootfs:\n");
  stderr.write(`    block size: ${cow.blockSize} bytes\n`);
  stderr.write(`    stored blocks: ${cow.storedBlocks} (${formatBytes(cow.storedBytes)})\n`);
  stderr.write(`    list calls: ${cow.listCalls}\n`);
  stderr.write(`    read calls: ${cow.readCalls}, requested blocks: ${cow.readRanges}, returned blocks: ${cow.readChunksReturned} (${formatBytes(cow.readBytesReturned)})\n`);
  stderr.write(`    write calls: ${cow.writeCalls}, written blocks: ${cow.writeChunks} (${formatBytes(cow.writeBytes)})\n`);
  stderr.write(`    flush calls: ${cow.flushCalls}\n`);
  stderr.write("  Network:\n");
  stderr.write(`    observed HTTP/S policy calls: ${net.policyCalls}\n`);
  if (net.byDestination.size === 0) {
    stderr.write("    destinations: none observed\n");
  } else {
    stderr.write("    destinations:\n");
    for (const [destination, count] of net.byDestination) {
      stderr.write(`      ${destination}: ${count}\n`);
    }
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  if (bytes < 1024 * 1024) {
    return `${(bytes / 1024).toFixed(1)} KiB`;
  }
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  }
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GiB`;
}

function parseArgs(args: readonly string[]): DiskTestOptions {
  let size = "64m";
  let runtimeSeconds = 30;
  let target: DiskTestOptions["target"] = "rootfs";
  let skipInstall = false;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    switch (arg) {
      case "--size":
        size = requireValue(args, ++index, arg);
        break;
      case "--runtime":
        runtimeSeconds = Number.parseInt(requireValue(args, ++index, arg), 10);
        if (!Number.isFinite(runtimeSeconds) || runtimeSeconds <= 0) {
          throw new Error("--runtime must be a positive integer number of seconds");
        }
        break;
      case "--target": {
        const value = requireValue(args, ++index, arg);
        if (value !== "rootfs" && value !== "vfs" && value !== "both") {
          throw new Error("--target must be rootfs, vfs, or both");
        }
        target = value;
        break;
      }
      case "--skip-install":
        skipInstall = true;
        break;
      default:
        throw new Error(`unknown argument: ${arg}`);
    }
  }

  return {
    size,
    runtimeSeconds,
    target,
    skipInstall,
  };
}

function requireValue(args: readonly string[], index: number, flag: string): string {
  const value = args[index];
  if (value === undefined || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}
