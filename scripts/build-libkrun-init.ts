import { mkdir, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { spawn } from "node:child_process";

const repoRoot = resolve(import.meta.dirname, "..");
const arch = process.env.SANDBOX_INIT_ARCH ?? guestArch();
const image = process.env.SANDBOX_LIBKRUN_INIT_BUILDER_IMAGE ?? "debian:bookworm";
const outPath = resolve(repoRoot, process.env.SANDBOX_LIBKRUN_INIT_OUT ?? `dist/init/libkrun/${arch}/init.krun`);

await mkdir(dirname(outPath), { recursive: true });

await run("docker", [
  "run",
  "--rm",
  "--volume",
  `${repoRoot}:/work`,
  "--workdir",
  "/work",
  image,
  "bash",
  "-lc",
  [
    "apt-get update",
    "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends build-essential",
    `cc -O2 -static -Wall -o ${shellArg(containerPath(outPath))} deps/libkrun/init/init.c deps/libkrun/init/dhcp.c`,
  ].join(" && "),
]);

await assertExists(outPath);
console.log(`libkrun stage-0 init written to ${outPath}`);

function guestArch(): string {
  switch (process.arch) {
    case "arm64":
      return "aarch64";
    case "x64":
      return "x86_64";
    default:
      throw new Error(`unsupported host architecture for libkrun init build: ${process.arch}`);
  }
}

function containerPath(path: string): string {
  return `/work/${path.slice(repoRoot.length + 1)}`;
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
