import { mkdir, stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const sourceDir = resolve(repoRoot, process.env.SANDBOX_ROOTFS_SOURCE_DIR ?? "dist/rootfs/alpine-3.23");
const outPath = resolve(repoRoot, process.env.SANDBOX_ROOTFS_QCOW2_OUT ?? "dist/rootfs/alpine-3.23.qcow2");
const clusterSize = process.env.SANDBOX_QCOW2_CLUSTER_SIZE ?? "65536";
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
  process.env.SANDBOX_QCOW2_BUILDER_IMAGE ?? "debian:bookworm",
  "sh",
  "-lc",
  [
    "apt-get update",
    "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends e2fsprogs qemu-utils ca-certificates",
    "mkdir -p /work/rootfs",
    "tar -C /rootfs -cf - . | tar -C /work/rootfs -xf -",
    "chown -R 0:0 /work/rootfs",
    "size_kb=$(du -sk /work/rootfs | cut -f1)",
    "image_kb=$((size_kb + 131072))",
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
