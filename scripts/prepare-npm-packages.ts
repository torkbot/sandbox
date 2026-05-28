import { copyFile, cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

type PackageJson = {
  readonly name: string;
  readonly version: string;
  readonly dependencies?: Record<string, string>;
};

type PlatformPackage = {
  readonly name: string;
  readonly target: string;
  readonly os: string[];
  readonly cpu: string[];
  readonly libc?: string[];
  readonly files: {
    readonly host: string;
    readonly erofsRootfs: string;
    readonly ext4Rootfs: string;
  };
};

const repoRoot = resolve(import.meta.dirname, "..");
const outRoot = resolve(repoRoot, "dist/npm");
const rootOut = resolve(outRoot, "sandbox");

const platformPackages = [
  {
    name: "@torkbot/sandbox-darwin-arm64",
    target: "aarch64-apple-darwin",
    os: ["darwin"],
    cpu: ["arm64"],
    libc: undefined,
    files: {
      host: "sandbox-host",
      erofsRootfs: "rootfs/alpine-3.23.erofs",
      ext4Rootfs: "rootfs/alpine-3.23.ext4",
    },
  },
  {
    name: "@torkbot/sandbox-linux-x64-gnu",
    target: "x86_64-unknown-linux-gnu",
    os: ["linux"],
    cpu: ["x64"],
    libc: ["glibc"],
    files: {
      host: "sandbox-host",
      erofsRootfs: "rootfs/alpine-3.23.erofs",
      ext4Rootfs: "rootfs/alpine-3.23.ext4",
    },
  },
] as const satisfies readonly PlatformPackage[];

const packageJson = JSON.parse(
  await readFile(resolve(repoRoot, "package.json"), "utf8"),
) as PackageJson;
const modes = new Set(process.argv.slice(2));
const prepareRoot = modes.size === 0 || modes.has("--root");
const preparePlatforms = modes.size === 0 || modes.has("--platform");
const currentOnly = modes.has("--current");
const installSelectedPlatforms = modes.has("--install");

if (modes.size === 0 || modes.has("--clean")) {
  await rm(outRoot, { recursive: true, force: true });
}

const optionalDependencies = Object.fromEntries(
  platformPackages.map((pkg) => [pkg.name, packageJson.version]),
);

if (prepareRoot) {
  await rm(rootOut, { recursive: true, force: true });
  await mkdir(rootOut, { recursive: true });
  await writeJson(resolve(rootOut, "package.json"), {
    name: packageJson.name,
    version: packageJson.version,
    private: false,
    type: "module",
    description: "A TypeScript-first Node.js library for spawning libkrun-backed microVMs.",
    license: "MIT OR Apache-2.0",
    repository: {
      type: "git",
      url: "https://github.com/torkbot/sandbox",
    },
    publishConfig: {
      access: "public",
    },
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        default: "./dist/index.js",
      },
    },
    types: "./dist/index.d.ts",
    bin: {
      sandbox: "./dist/cli.js",
    },
    files: ["dist", "README.md"],
    engines: {
      node: ">=24.0.0",
    },
    dependencies: packageJson.dependencies ?? {},
    optionalDependencies,
  });

  await copyFile(resolve(repoRoot, "README.md"), resolve(rootOut, "README.md"));
  await copyDist(resolve(repoRoot, "dist"), resolve(rootOut, "dist"));
}

const selectedPlatformPackages = currentOnly
  ? platformPackages.filter((pkg) => {
      return pkg.os.some((os) => os === process.platform) && pkg.cpu.some((cpu) => cpu === process.arch);
    })
  : platformPackages;

if (preparePlatforms && currentOnly && selectedPlatformPackages.length === 0) {
  throw new Error(`unsupported platform package target: ${process.platform}-${process.arch}`);
}

for (const platformPackage of preparePlatforms ? selectedPlatformPackages : []) {
  const packageRoot = resolve(outRoot, platformPackage.name.replace("@torkbot/", ""));
  await rm(packageRoot, { recursive: true, force: true });
  await mkdir(packageRoot, { recursive: true });
  await writeJson(resolve(packageRoot, "package.json"), {
    name: platformPackage.name,
    version: packageJson.version,
    private: false,
    description: `sandbox-host artifact for @torkbot/sandbox on ${platformPackage.target}.`,
    license: "MIT OR Apache-2.0",
    repository: {
      type: "git",
      url: "https://github.com/torkbot/sandbox",
    },
    publishConfig: {
      access: "public",
    },
    os: platformPackage.os,
    cpu: platformPackage.cpu,
    ...(platformPackage.libc === undefined ? {} : { libc: platformPackage.libc }),
    files: [platformPackage.files.host, "rootfs", "README.md"],
  });
  await writeFile(
    resolve(packageRoot, "README.md"),
    `# ${platformPackage.name}\n\nThis package contains the sandbox-host artifact for @torkbot/sandbox on ${platformPackage.target}. It is installed as an optional dependency of @torkbot/sandbox.\n`,
  );
  await copyFile(
    resolve(repoRoot, "target/release/sandbox-host"),
    resolve(packageRoot, platformPackage.files.host),
  );
  await mkdir(resolve(packageRoot, "rootfs"), { recursive: true });
  await copyFile(
    resolve(repoRoot, "dist/rootfs/alpine-3.23.erofs"),
    resolve(packageRoot, platformPackage.files.erofsRootfs),
  );
  await copyFile(
    resolve(repoRoot, "dist/rootfs/alpine-3.23.ext4"),
    resolve(packageRoot, platformPackage.files.ext4Rootfs),
  );

  if (installSelectedPlatforms) {
    const installRoot = resolve(repoRoot, "node_modules", ...platformPackage.name.split("/"));
    await rm(installRoot, { recursive: true, force: true });
    await mkdir(resolve(installRoot, ".."), { recursive: true });
    await cp(packageRoot, installRoot, { recursive: true });
  }
}

async function copyDist(source: string, destination: string): Promise<void> {
  await mkdir(destination, { recursive: true });
  for (const entry of await readdir(source, { withFileTypes: true })) {
    if (entry.name === "npm" || entry.name === "init" || entry.name === "kernel" || entry.name === "rootfs") {
      continue;
    }

    await cp(resolve(source, entry.name), resolve(destination, basename(entry.name)), {
      recursive: true,
    });
  }
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}
