import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { sha256File } from "./image-release-version.ts";
import {
  defaultLocalImageId,
  localImageArtifactPaths,
  localNodeArchitecture,
} from "./support/local-image-artifact.ts";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const args = process.argv.slice(2);
const imageId = optionalArg(args, "--image") ?? defaultLocalImageId;
const architecture = parseArchitecture(optionalArg(args, "--architecture") ?? localNodeArchitecture());
const paths = localImageArtifactPaths({
  repoRoot,
  imageId,
  architecture,
});

await mkdir(resolve(paths.rootDir, ".."), { recursive: true });
await run("node", [
  "./scripts/build-image-rootfs.ts",
  "--image",
  imageId,
  "--architecture",
  architecture,
  "--out-dir",
  paths.rootDir,
]);
await run("node", ["./scripts/build-rootfs-qcow2.ts"], {
  SANDBOX_ROOTFS_SOURCE_DIR: paths.rootDir,
  SANDBOX_ROOTFS_QCOW2_OUT: paths.rootfsPath,
  SANDBOX_ROOTFS_ENVIRONMENT_FACTS_OUT: paths.factsPath,
});
const digest = await sha256File(paths.rootfsPath);
await writeFile(paths.digestPath, `${digest}\n`);
console.log(`local image artifact written to ${paths.rootfsPath}`);

function optionalArg(values: readonly string[], name: string): string | undefined {
  const index = values.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = values[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

function parseArchitecture(value: string): "arm64" | "x64" {
  if (value === "arm64" || value === "x64") {
    return value;
  }
  throw new Error(`unsupported image artifact architecture: ${value}`);
}

async function run(command: string, commandArgs: readonly string[], env: NodeJS.ProcessEnv = {}): Promise<void> {
  console.log(`$ ${[command, ...commandArgs].join(" ")}`);
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, [...commandArgs], {
      cwd: repoRoot,
      env: {
        ...process.env,
        ...env,
      },
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`${command} ${commandArgs.join(" ")} failed with exit code ${code ?? "unknown"}`));
        return;
      }
      resolvePromise();
    });
  });
}
