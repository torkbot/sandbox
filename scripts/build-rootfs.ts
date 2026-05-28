import { chmod, copyFile, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { getgid, getuid } from "node:process";

const repoRoot = resolve(import.meta.dirname, "..");
const image = process.env.SANDBOX_ROOTFS_IMAGE ?? "alpine:3.23";
const outDir = resolve(repoRoot, process.env.SANDBOX_ROOTFS_OUT_DIR ?? "dist/rootfs/alpine-3.23");
const initPath = resolve(
  repoRoot,
  process.env.SANDBOX_INIT_BINARY_PATH ?? `dist/init/${guestTarget()}/sandbox-init`,
);
const agentPackages = [
  "bash",
  "ca-certificates",
  "coreutils",
  "curl",
  "exiftool",
  "ffmpeg",
  "file",
  "findutils",
  "git",
  "imagemagick",
  "jq",
  "less",
  "nodejs-current",
  "npm",
  "openssh-client",
  "poppler-utils",
  "py3-pip",
  "python3",
  "ripgrep",
  "tar",
  "unzip",
  "xz",
  "zip",
] as const;
const githubCliVersion = "2.83.0";

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
  [
    `apk add --no-cache ${agentPackages.map(shellArg).join(" ")}`,
    installGithubCliScript(),
    cleanupRootfsScript(),
    "cd /",
    "tar --exclude=out --exclude=proc --exclude=sys --exclude=dev --exclude=tmp -cf - . | tar -C /out -xf -",
    `chown -R ${getuid?.() ?? 0}:${getgid?.() ?? 0} /out`,
  ].join(" && "),
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

function shellArg(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function installGithubCliScript(): string {
  return [
    "apk_arch=$(apk --print-arch)",
    "case \"$apk_arch\" in x86_64) gh_arch=amd64 ;; aarch64) gh_arch=arm64 ;; *) echo unsupported gh architecture: \"$apk_arch\" >&2; exit 1 ;; esac",
    `gh_url=https://github.com/cli/cli/releases/download/v${githubCliVersion}/gh_${githubCliVersion}_linux_\${gh_arch}.tar.gz`,
    "tmp=$(mktemp -d)",
    "curl -fsSL \"$gh_url\" -o \"$tmp/gh.tar.gz\"",
    "tar -xzf \"$tmp/gh.tar.gz\" -C \"$tmp\"",
    `install -m 0755 "$tmp/gh_${githubCliVersion}_linux_\${gh_arch}/bin/gh" /usr/local/bin/gh`,
    "rm -rf \"$tmp\"",
  ].join(" && ");
}

function cleanupRootfsScript(): string {
  return [
    "rm -rf /var/cache/apk/* /etc/apk/cache/*",
    "rm -rf /root/.cache /tmp/* /var/tmp/*",
    "rm -rf /usr/share/doc /usr/share/man /usr/share/info",
  ].join(" && ");
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
