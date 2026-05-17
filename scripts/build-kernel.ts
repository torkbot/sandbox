import { mkdir, copyFile, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const libkrunfwRoot = resolve(repoRoot, "deps/libkrunfw");

const arch = process.env.SANDBOX_KERNEL_ARCH ?? guestArch();
const image = process.env.SANDBOX_KERNEL_BUILDER_IMAGE ?? "debian:bookworm";
const outDir = resolve(repoRoot, process.env.SANDBOX_KERNEL_OUT_DIR ?? `dist/kernel/libkrunfw/${arch}`);

await assertExists(resolve(libkrunfwRoot, "Makefile"));

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
    `make -j$(nproc) ARCH=${shellArg(arch)}`,
  ].join(" && "),
]);

await mkdir(outDir, { recursive: true });

const kernelBinary = kernelBinaryForArch(arch);
const outputs = [
  ["kernel.c", "kernel.c"],
  [kernelBinary, kernelBinary],
] as const;

for (const [source, destination] of outputs) {
  const sourcePath = resolve(libkrunfwRoot, source);
  await assertExists(sourcePath);
  const destinationPath = resolve(outDir, destination);
  await mkdir(dirname(destinationPath), { recursive: true });
  await copyFile(sourcePath, destinationPath);
}

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

function kernelBinaryForArch(value: string): string {
  switch (value) {
    case "arm64":
    case "aarch64":
      return "linux-6.12.87/arch/arm64/boot/Image";
    case "x86_64":
      return "linux-6.12.87/vmlinux";
    case "riscv":
    case "riscv64":
      return "linux-6.12.87/arch/riscv/boot/Image";
    default:
      throw new Error(`unsupported guest architecture for kernel build: ${value}`);
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
