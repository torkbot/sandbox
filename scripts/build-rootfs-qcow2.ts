import { copyFile, mkdir, stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { spawn } from "node:child_process";
import {
  rootfsEnvironmentFactsManifestFile,
} from "../src/environment-facts.ts";

const repoRoot = resolve(import.meta.dirname, "..");
const sourceDir = resolve(repoRoot, process.env.SANDBOX_ROOTFS_SOURCE_DIR ?? "dist/rootfs/alpine-3.23");
const outPath = resolve(repoRoot, process.env.SANDBOX_ROOTFS_QCOW2_OUT ?? "dist/rootfs/alpine-3.23.qcow2");
const rootfsEnvironmentFactsArtifactName = "alpine-3.23-agent.environment-facts.json";
const rootfsEnvironmentFactsOut = resolve(
  repoRoot,
  process.env.SANDBOX_ROOTFS_ENVIRONMENT_FACTS_OUT ?? `dist/rootfs/${rootfsEnvironmentFactsArtifactName}`,
);
const clusterSize = decimalEnv("SANDBOX_QCOW2_CLUSTER_SIZE", "32768");
const virtualSizeKiB = sizeEnvKiB("SANDBOX_ROOTFS_VIRTUAL_SIZE", "8gb");
const filesystemUuid = "00000000-0000-0000-0000-000000000000";

await assertDirectory(sourceDir);
const outDir = dirname(outPath);
await mkdir(outDir, { recursive: true });

await run("docker", [
  "run",
  "--rm",
  "--volume",
  `${sourceDir}:/rootfs:ro`,
  "--volume",
  `${outDir}:/out`,
  process.env.SANDBOX_QCOW2_BUILDER_IMAGE ?? "debian:12",
  "sh",
  "-lc",
  [
    "apt-get update",
    "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends e2fsprogs qemu-utils ca-certificates",
    "mkdir -p /work/rootfs",
    "tar -C /rootfs -cf - . | tar -C /work/rootfs -xf -",
    "chown -R 0:0 /work/rootfs",
    "size_kb=$(du -sk /work/rootfs | cut -f1)",
    `image_kb=${virtualSizeKiB}`,
    "if [ \"${size_kb}\" -gt \"${image_kb}\" ]; then echo \"rootfs contents exceed virtual image size\" >&2; exit 1; fi",
    "truncate -s \"${image_kb}K\" /work/rootfs.ext4",
    "export E2FSPROGS_FAKE_TIME=0",
    [
      "mke2fs",
      "-q",
      "-t ext4",
      "-O ^has_journal",
      `-U ${shellArg(filesystemUuid)}`,
      `-E root_owner=0:0,hash_seed=${shellArg(filesystemUuid)}`,
      "-d /work/rootfs",
      "/work/rootfs.ext4",
    ].join(" "),
    [
      "qemu-img",
      "convert",
      "-f raw",
      "-O qcow2",
      "-c",
      `-o compat=1.1,cluster_size=${shellArg(clusterSize)},lazy_refcounts=off`,
      "/work/rootfs.ext4",
      `/out/${shellArg(basename(outPath))}`,
    ].join(" "),
  ].join(" && "),
]);

console.log(`rootfs QCOW2 image written to ${outPath}`);
await mkdir(dirname(rootfsEnvironmentFactsOut), { recursive: true });
await copyFile(
  resolve(sourceDir, rootfsEnvironmentFactsManifestFile),
  rootfsEnvironmentFactsOut,
);
console.log(`rootfs environment facts written to ${rootfsEnvironmentFactsOut}`);

async function assertDirectory(path: string): Promise<void> {
  try {
    const info = await stat(path);
    if (!info.isDirectory()) {
      throw new Error(`required rootfs source is not a directory: ${path}`);
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("required rootfs source")) {
      throw error;
    }

    throw new Error(`required rootfs source does not exist: ${path}`);
  }
}

function shellArg(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function decimalEnv(name: string, fallback: string): string {
  const value = process.env[name] ?? fallback;
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error(`${name} must be a positive decimal integer`);
  }
  return value;
}

function sizeEnvKiB(name: string, fallback: string): string {
  const value = process.env[name] ?? fallback;
  const match = /^([1-9][0-9]*)(kb|mb|gb)$/i.exec(value);
  if (match === null) {
    throw new Error(`${name} must be a size like 8388608kb, 8192mb, or 8gb`);
  }

  const amount = BigInt(match[1] ?? "0");
  const unit = (match[2] ?? "").toLowerCase();
  const kib = unit === "kb"
    ? amount
    : unit === "mb"
      ? amount * 1024n
      : amount * 1024n * 1024n;
  if (kib > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error(`${name} must fit in JavaScript's safe integer range`);
  }
  return kib.toString();
}

async function run(command: string, args: readonly string[]): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise();
      } else {
        reject(new Error(`${command} exited with ${code}`));
      }
    });
  });
}
