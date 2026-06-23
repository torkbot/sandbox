import { copyFile, mkdir, stat } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { spawn } from "node:child_process";
import { getgid, getuid } from "node:process";

const repoRoot = resolve(import.meta.dirname, "..");
const target = process.env.SANDBOX_INIT_TARGET ?? guestTarget();
const image = process.env.SANDBOX_INIT_BUILDER_IMAGE ?? "rust:1-bookworm";
const outDir = resolve(repoRoot, process.env.SANDBOX_INIT_OUT_DIR ?? `dist/init/${target}`);
const owner = `${getuid?.() ?? 0}:${getgid?.() ?? 0}`;

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
    "export PATH=/usr/local/cargo/bin:$PATH",
    "rustup target add " + shellArg(target),
    "apt-get update",
    "DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends musl-tools",
    `cargo build -p sandbox-init --release --target ${shellArg(target)}`,
    `chown -R ${shellArg(owner)} /work/target`,
  ].join(" && "),
]);

const binaryName = target.includes("windows") ? "sandbox-init.exe" : "sandbox-init";
const sourcePath = resolve(repoRoot, "target", target, "release", binaryName);
await assertExists(sourcePath);

const destinationPath = resolve(outDir, binaryName);
await mkdir(dirname(destinationPath), { recursive: true });
await copyFile(sourcePath, destinationPath);

console.log(`init artifact written to ${destinationPath}`);

function guestTarget(): string {
  switch (process.arch) {
    case "arm64":
      return "aarch64-unknown-linux-musl";
    case "x64":
      return "x86_64-unknown-linux-musl";
    default:
      throw new Error(`unsupported host architecture for init build: ${process.arch}`);
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
