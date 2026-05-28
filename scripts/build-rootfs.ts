import { chmod, copyFile, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { getgid, getuid } from "node:process";

const repoRoot = resolve(import.meta.dirname, "..");
const image = process.env.SANDBOX_ROOTFS_IMAGE ?? "alpine:3.20";
const outDir = resolve(repoRoot, process.env.SANDBOX_ROOTFS_OUT_DIR ?? "dist/rootfs/alpine-3.20");
const initPath = resolve(
  repoRoot,
  process.env.SANDBOX_INIT_BINARY_PATH ?? `dist/init/${guestTarget()}/sandbox-init`,
);

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });

await run("docker", [
  "run",
  "--rm",
  "--volume",
  `${outDir}:/out`,
  image,
  "sh",
  "-lc",
  `apk add --no-cache curl && cd / && tar --exclude=out --exclude=proc --exclude=sys --exclude=dev --exclude=tmp -cf - . | tar -C /out -xf - && chown -R ${getuid?.() ?? 0}:${getgid?.() ?? 0} /out`,
]);

await assertExists(initPath);
await copyFile(initPath, resolve(outDir, "sandbox-init"));
await rm(resolve(outDir, ".dockerenv"), { force: true });
await writeFile(resolve(outDir, "etc/hostname"), "sandbox\n");
await writeFile(
  resolve(outDir, "etc/hosts"),
  "127.0.0.1 localhost sandbox\n::1 localhost ip6-localhost ip6-loopback\n",
);
await mkdir(resolve(outDir, "dev"), { recursive: true });
await mkdir(resolve(outDir, "proc"), { recursive: true });
await mkdir(resolve(outDir, "sandbox"), { recursive: true });
await mkdir(resolve(outDir, "sys"), { recursive: true });
await mkdir(resolve(outDir, "tmp"), { recursive: true, mode: 0o1777 });
await chmod(resolve(outDir, "tmp"), 0o1777);
await mkdir(resolve(outDir, "workspace"), { recursive: true });

console.log(`rootfs directory written to ${outDir}`);

function guestTarget(): string {
  switch (process.arch) {
    case "arm64":
      return "aarch64-unknown-linux-musl";
    case "x64":
      return "x86_64-unknown-linux-musl";
    default:
      throw new Error(`unsupported host architecture for rootfs build: ${process.arch}`);
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
