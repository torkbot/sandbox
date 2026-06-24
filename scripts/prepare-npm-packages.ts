import { copyFile, cp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

type PackageJson = {
  readonly dependencies?: Record<string, string>;
};

type ReleasePackageJson = {
  readonly name: string;
  readonly private: false;
  readonly type: "module";
  readonly description: string;
  readonly license: string;
  readonly repository: {
    readonly type: string;
    readonly url: string;
  };
  readonly publishConfig: {
    readonly access: "public";
  };
  readonly exports: Record<string, unknown>;
  readonly types: string;
  readonly bin: Record<string, string>;
  readonly files: readonly string[];
  readonly engines: Record<string, string>;
};

type PlatformPackage = {
  readonly name: string;
  readonly target: string;
  readonly os: string[];
  readonly cpu: string[];
  readonly libc?: string[];
  readonly files: {
    readonly host: string;
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
    },
  },
] as const satisfies readonly PlatformPackage[];

const packageJson = JSON.parse(
  await readFile(resolve(repoRoot, "package.json"), "utf8"),
) as PackageJson;
const releasePackageJson = JSON.parse(
  await readFile(resolve(repoRoot, "release.package.json"), "utf8"),
) as ReleasePackageJson;
const modes = new Set(process.argv.slice(2));
const releaseVersion = parseReleaseVersion(process.argv.slice(2));
const prepareRoot = modes.size === 0 || modes.has("--root");
const preparePlatforms = modes.size === 0 || modes.has("--platform");
const currentOnly = modes.has("--current");
const installSelectedPlatforms = modes.has("--install");

if (modes.size === 0 || modes.has("--clean")) {
  await rm(outRoot, { recursive: true, force: true });
}

const optionalDependencies = Object.fromEntries(
  platformPackages.map((pkg) => [pkg.name, releaseVersion]),
);

if (prepareRoot) {
  await rm(rootOut, { recursive: true, force: true });
  await mkdir(rootOut, { recursive: true });
  await writeJson(resolve(rootOut, "package.json"), {
    ...releasePackageJson,
    version: releaseVersion,
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
    version: releaseVersion,
    private: false,
    description: `sandbox-host artifact for @torkbot/sandbox on ${platformPackage.target}.`,
    license: releasePackageJson.license,
    repository: releasePackageJson.repository,
    publishConfig: releasePackageJson.publishConfig,
    os: platformPackage.os,
    cpu: platformPackage.cpu,
    ...(platformPackage.libc === undefined ? {} : { libc: platformPackage.libc }),
    files: [platformPackage.files.host, "README.md"],
  });
  await writeFile(
    resolve(packageRoot, "README.md"),
    `# ${platformPackage.name}\n\nThis package contains the sandbox-host artifact for @torkbot/sandbox on ${platformPackage.target}. It is installed as an optional dependency of @torkbot/sandbox.\n`,
  );
  await copyFile(
    resolve(repoRoot, "target/release/sandbox-host"),
    resolve(packageRoot, platformPackage.files.host),
  );

  if (installSelectedPlatforms) {
    const installRoot = resolve(repoRoot, "node_modules", ...platformPackage.name.split("/"));
    await rm(installRoot, { recursive: true, force: true });
    await mkdir(resolve(installRoot, ".."), { recursive: true });
    await cp(packageRoot, installRoot, { recursive: true });
  }
}

function parseReleaseVersion(args: readonly string[]): string {
  const index = args.indexOf("--version");
  const version = index === -1 ? process.env.SANDBOX_RELEASE_VERSION : args[index + 1];
  if (version === undefined || version.length === 0 || version.startsWith("--")) {
    throw new Error("release version is required: pass --version <semver> or set SANDBOX_RELEASE_VERSION");
  }
  const normalized = version.startsWith("v") ? version.slice(1) : version;
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(normalized)) {
    throw new Error(`invalid release version: ${version}`);
  }
  return normalized;
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
