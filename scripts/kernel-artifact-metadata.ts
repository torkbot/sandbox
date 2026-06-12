import { createHash } from "node:crypto";
import { readdir, readFile, stat } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { spawn } from "node:child_process";

export const kernelMetadataFile = "kernel-metadata.json";

export interface KernelArtifactMetadata {
  schemaVersion: 1;
  arch: string;
  guestArch: string;
  kernelVersion: string;
  libkrunfwHead: string;
  sourceFingerprint: string;
  kernelBundle: string;
  kernelBinary: string;
}

interface ExpectedKernelMetadataInput {
  repoRoot: string;
  arch: string;
}

export async function expectedKernelArtifactMetadata(
  input: ExpectedKernelMetadataInput,
): Promise<KernelArtifactMetadata> {
  const libkrunfwRoot = resolve(input.repoRoot, "deps/libkrunfw");
  const makefile = await readFile(resolve(libkrunfwRoot, "Makefile"), "utf8");
  const kernelVersion = requiredMakefileValue(makefile, "KERNEL_VERSION");
  const guestArch = guestArchFor(input.arch);
  const kernelBinary = kernelBinaryFor(input.arch, kernelVersion);
  const sourceFiles = [
    "Makefile",
    "bin2cbundle.py",
    `config-libkrunfw_${guestArch}`,
    ...await filesUnder(resolve(libkrunfwRoot, "patches")),
  ];
  const libkrunfwHead = await git(["rev-parse", "HEAD"], libkrunfwRoot);
  const sourceFingerprint = sha256Text([
    `arch=${input.arch}\n`,
    `guestArch=${guestArch}\n`,
    `kernelVersion=${kernelVersion}\n`,
    `libkrunfwHead=${libkrunfwHead}\n`,
    ...await Promise.all(sourceFiles.map(async (file) => {
      const path = resolve(libkrunfwRoot, file);
      return `${file}\0${await sha256File(path)}\n`;
    })),
    `scripts/build-kernel.ts\0${await sha256File(resolve(input.repoRoot, "scripts/build-kernel.ts"))}\n`,
    `scripts/kernel-artifact-metadata.ts\0${await sha256File(resolve(input.repoRoot, "scripts/kernel-artifact-metadata.ts"))}\n`,
  ].join(""));

  return {
    schemaVersion: 1,
    arch: input.arch,
    guestArch,
    kernelVersion,
    libkrunfwHead,
    sourceFingerprint,
    kernelBundle: "kernel.c",
    kernelBinary,
  };
}

export async function readKernelArtifactMetadata(path: string): Promise<KernelArtifactMetadata> {
  const parsed = JSON.parse(await readFile(path, "utf8")) as Partial<KernelArtifactMetadata>;
  assertMetadataField(parsed.schemaVersion === 1, "schemaVersion");
  assertMetadataField(typeof parsed.arch === "string" && parsed.arch.length > 0, "arch");
  assertMetadataField(typeof parsed.guestArch === "string" && parsed.guestArch.length > 0, "guestArch");
  assertMetadataField(typeof parsed.kernelVersion === "string" && parsed.kernelVersion.length > 0, "kernelVersion");
  assertMetadataField(typeof parsed.libkrunfwHead === "string" && parsed.libkrunfwHead.length > 0, "libkrunfwHead");
  assertMetadataField(typeof parsed.sourceFingerprint === "string" && parsed.sourceFingerprint.length > 0, "sourceFingerprint");
  assertMetadataField(typeof parsed.kernelBundle === "string" && parsed.kernelBundle.length > 0, "kernelBundle");
  assertMetadataField(typeof parsed.kernelBinary === "string" && parsed.kernelBinary.length > 0, "kernelBinary");
  return parsed as KernelArtifactMetadata;
}

export function metadataPathForKernelBundle(kernelBundle: string): string {
  return resolve(dirname(kernelBundle), kernelMetadataFile);
}

export function assertKernelArtifactMetadataMatches(
  actual: KernelArtifactMetadata,
  expected: KernelArtifactMetadata,
): void {
  const mismatches = ([
    "schemaVersion",
    "arch",
    "guestArch",
    "kernelVersion",
    "libkrunfwHead",
    "sourceFingerprint",
    "kernelBundle",
    "kernelBinary",
  ] as const).filter((key) => actual[key] !== expected[key]);

  if (mismatches.length > 0) {
    throw new Error(
      `stale kernel artifact metadata at ${kernelMetadataFile}: ${mismatches.join(", ")} differ; run npm run build:kernel`,
    );
  }
}

export function guestArchFor(value: string): string {
  switch (value) {
    case "arm64":
      return "aarch64";
    case "x86_64":
    case "riscv64":
      return value;
    case "riscv":
      return "riscv64";
    default:
      throw new Error(`unsupported guest architecture for kernel build: ${value}`);
  }
}

export function kernelBinaryFor(value: string, kernelSourceDir: string): string {
  switch (value) {
    case "arm64":
    case "aarch64":
      return `${kernelSourceDir}/arch/arm64/boot/Image`;
    case "x86_64":
      return `${kernelSourceDir}/vmlinux`;
    case "riscv":
    case "riscv64":
      return `${kernelSourceDir}/arch/riscv/boot/Image`;
    default:
      throw new Error(`unsupported guest architecture for kernel build: ${value}`);
  }
}

function requiredMakefileValue(makefile: string, name: string): string {
  const match = new RegExp(`^${name}\\s*=\\s*(\\S+)\\s*$`, "m").exec(makefile);
  const value = match?.[1];
  if (!value) {
    throw new Error(`deps/libkrunfw/Makefile does not define ${name}`);
  }
  return value;
}

async function filesUnder(root: string): Promise<string[]> {
  return await filesUnderBase(root, root);
}

async function filesUnderBase(root: string, base: string): Promise<string[]> {
  const entries = await readdir(root, { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      return await filesUnderBase(path, base);
    }
    if (!entry.isFile()) {
      return [];
    }
    return [relative(resolve(base, ".."), path)];
  }));
  return files.flat().sort();
}

async function sha256File(path: string): Promise<string> {
  await stat(path);
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}

function sha256Text(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

async function git(args: readonly string[], cwd: string): Promise<string> {
  return await new Promise<string>((resolvePromise, reject) => {
    const child = spawn("git", args, {
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise(Buffer.concat(stdout).toString("utf8").trim());
      } else {
        reject(new Error(`git ${args.join(" ")} failed: ${Buffer.concat(stderr).toString("utf8").trim()}`));
      }
    });
  });
}

function assertMetadataField(condition: boolean, field: string): asserts condition {
  if (!condition) {
    throw new Error(`invalid kernel artifact metadata: missing or invalid ${field}`);
  }
}
