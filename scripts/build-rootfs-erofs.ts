import { mkdir, stat } from "node:fs/promises";
import { basename, dirname, resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const sourceDir = resolve(repoRoot, process.env.SANDBOX_ROOTFS_SOURCE_DIR ?? "dist/rootfs/alpine-3.23");
const outPath = resolve(repoRoot, process.env.SANDBOX_ROOTFS_EROFS_OUT ?? "dist/rootfs/alpine-3.23.erofs");
const compression = process.env.SANDBOX_EROFS_COMPRESSION ?? "lz4hc,level=12";
const clusterSize = process.env.SANDBOX_EROFS_CLUSTER_SIZE ?? "1048576";
const extendedOptions = process.env.SANDBOX_EROFS_EXTENDED_OPTIONS ?? "fragments";

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
  process.env.SANDBOX_EROFS_BUILDER_IMAGE ?? "alpine:3.23",
  "sh",
  "-lc",
  [
    "apk add --no-cache erofs-utils ca-certificates",
    [
      "mkfs.erofs",
      "--quiet",
      "-x-1",
      `-z${shellArg(compression)}`,
      `-C${shellArg(clusterSize)}`,
      `-E${shellArg(extendedOptions)}`,
      "-T0",
      "-U 00000000-0000-0000-0000-000000000000",
      "--all-root",
      `/out/${shellArg(basename(outPath))}`,
      "/rootfs",
    ].join(" "),
  ].join(" && "),
]);

console.log(`rootfs EROFS image written to ${outPath}`);

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
