import { mkdir, copyFile, rm, stat, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { spawn } from "node:child_process";
import {
  expectedKernelArtifactMetadata,
  kernelMetadataFile,
} from "./kernel-artifact-metadata.ts";

const repoRoot = resolve(import.meta.dirname, "..");
const libkrunfwRoot = resolve(repoRoot, "deps/libkrunfw");

const arch = process.env.SANDBOX_KERNEL_ARCH ?? guestArch();
const image = process.env.SANDBOX_KERNEL_BUILDER_IMAGE ?? "debian:bookworm";
const outDir = resolve(repoRoot, process.env.SANDBOX_KERNEL_OUT_DIR ?? `dist/kernel/libkrunfw/${arch}`);
const jobs = process.env.SANDBOX_KERNEL_JOBS ?? "4";

if (!/^[1-9]\d*$/.test(jobs)) {
  throw new Error(`SANDBOX_KERNEL_JOBS must be a positive integer: ${jobs}`);
}

await assertExists(resolve(libkrunfwRoot, "Makefile"));
const metadata = await expectedKernelArtifactMetadata({ repoRoot, arch });
const kernelTarball = `${metadata.kernelVersion}.tar.xz`;
const kernelRemote = `https://cdn.kernel.org/pub/linux/kernel/v6.x/${kernelTarball}`;

await rm(resolve(libkrunfwRoot, metadata.kernelBundle), { force: true });
await rm(resolve(libkrunfwRoot, metadata.kernelVersion), { recursive: true, force: true });

await run("docker", [
  "run",
  "--rm",
  "--volume",
  `${repoRoot}:/work`,
  "--workdir",
  "/work/deps/libkrunfw",
  image,
  "bash",
  "-lc",
  [
    "apt-get update",
    "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential bc bison ca-certificates cpio curl flex libelf-dev libssl-dev python3 python3-pyelftools xz-utils",
    "mkdir -p tarballs",
    `[ -s tarballs/${shellArg(kernelTarball)} ] || curl --fail --location --retry 3 --connect-timeout 30 --speed-time 60 --speed-limit 1024 ${shellArg(kernelRemote)} -o tarballs/${shellArg(kernelTarball)}`,
    `make -j${shellArg(jobs)} ARCH=${shellArg(arch)}`,
  ].join(" && "),
]);

await mkdir(outDir, { recursive: true });

const outputs = [
  [metadata.kernelBundle, metadata.kernelBundle],
  [metadata.kernelBinary, metadata.kernelBinary],
] as const;

for (const [source, destination] of outputs) {
  const sourcePath = resolve(libkrunfwRoot, source);
  await assertExists(sourcePath);
  const destinationPath = resolve(outDir, destination);
  await mkdir(dirname(destinationPath), { recursive: true });
  await copyFile(sourcePath, destinationPath);
}
await writeFile(
  resolve(outDir, kernelMetadataFile),
  `${JSON.stringify(metadata, null, 2)}\n`,
);

console.log(`kernel artifacts written to ${outDir}`);

function guestArch(): string {
  switch (process.arch) {
    case "arm64":
      return "arm64";
    case "x64":
      return "x86_64";
    default:
      throw new Error(`unsupported host architecture for kernel build: ${process.arch}`);
  }
}

async function assertExists(path: string): Promise<void> {
  try {
    await stat(path);
  } catch {
    throw new Error(`required path does not exist: ${path}`);
  }
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

function shellArg(value: string): string {
  return `'${value.replaceAll("'", "'\"'\"'")}'`;
}
