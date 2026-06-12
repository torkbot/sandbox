import { access } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import {
  assertKernelArtifactMetadataMatches,
  expectedKernelArtifactMetadata,
  metadataPathForKernelBundle,
  readKernelArtifactMetadata,
} from "./kernel-artifact-metadata.ts";

const repoRoot = resolve(import.meta.dirname, "..");
const kernelBundle = resolve(
  repoRoot,
  process.env.SANDBOX_KERNEL_BUNDLE_C ?? `dist/kernel/libkrunfw/${kernelArch()}/kernel.c`,
);

await assertExists(kernelBundle);
assertKernelArtifactMetadataMatches(
  await readKernelArtifactMetadata(metadataPathForKernelBundle(kernelBundle)),
  await expectedKernelArtifactMetadata({ repoRoot, arch: kernelArch() }),
);

await run("cargo", ["build", "-p", "sandbox-host", "--release"], {
  SANDBOX_KERNEL_BUNDLE_C: kernelBundle,
});

if (process.env.SANDBOX_SKIP_HOST_SIGNING !== "1") {
  await run("node", ["./scripts/sign-host.ts"]);
}

function kernelArch(): string {
  switch (process.arch) {
    case "arm64":
      return "arm64";
    case "x64":
      return "x86_64";
    default:
      throw new Error(`unsupported host architecture for host build: ${process.arch}`);
  }
}

async function assertExists(path: string): Promise<void> {
  try {
    await access(path);
  } catch {
    throw new Error(`required host build input does not exist: ${path}`);
  }
}

async function run(
  command: string,
  args: readonly string[],
  env: Record<string, string> = {},
): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...env,
      },
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
