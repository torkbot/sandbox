import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const args = process.argv.slice(2);
const runnerArch = requiredArg("--runner-arch");
const outputPath = process.env.GITHUB_OUTPUT;

const kernelKeyHash = sha256Text([
  `runner-arch=${runnerArch}\n`,
  await git(["submodule", "status", "--recursive", "deps/libkrunfw"]),
  await gitTrackedFileHashes([
    "scripts/build-kernel.ts",
    "scripts/kernel-artifact-metadata.ts",
  ]),
].join(""));

const initKeyHash = sha256Text([
  `runner-arch=${runnerArch}\n`,
  await gitTrackedFileHashes([
    "Cargo.lock",
    "Cargo.toml",
    "crates/sandbox-init",
    "crates/sandbox-protocol",
    "scripts/build-init.ts",
  ]),
].join(""));

const rootfsKeyHash = sha256Text([
  `runner-arch=${runnerArch}\n`,
  `init-key-hash=${initKeyHash}\n`,
  await gitTrackedFileHashes([
    "scripts/build-rootfs.ts",
    "scripts/build-rootfs-qcow2.ts",
    "src/environment-facts.ts",
  ]),
].join(""));

const outputs = {
  "kernel-key": `sandbox-kernel-${runnerArch}-${kernelKeyHash}`,
  "init-key": `sandbox-init-${runnerArch}-${initKeyHash}`,
  "rootfs-key": `sandbox-rootfs-${runnerArch}-${rootfsKeyHash}`,
};

const outputText = Object.entries(outputs)
  .map(([key, value]) => `${key}=${value}`)
  .join("\n") + "\n";

if (outputPath === undefined || outputPath.length === 0) {
  process.stdout.write(outputText);
} else {
  await writeFile(outputPath, outputText, { flag: "a" });
}

function requiredArg(name: string): string {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

async function gitTrackedFileHashes(paths: readonly string[]): Promise<string> {
  const files = (await git(["ls-files", "-z", ...paths]))
    .split("\0")
    .filter((file) => file.length > 0);

  const lines = await Promise.all(
    files.map(async (file) => {
      const hash = createHash("sha256")
        .update(await readFile(resolve(repoRoot, file)))
        .digest("hex");
      return `${hash}  ${file}\n`;
    }),
  );
  return lines.join("");
}

async function git(args: readonly string[]): Promise<string> {
  return await new Promise<string>((resolvePromise, reject) => {
    const child = spawn("git", args, {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise(Buffer.concat(stdout).toString("utf8"));
      } else {
        reject(new Error(`git ${args.join(" ")} exited with ${code}: ${Buffer.concat(stderr).toString("utf8")}`));
      }
    });
  });
}

function sha256Text(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
