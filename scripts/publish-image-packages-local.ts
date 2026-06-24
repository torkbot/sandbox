import { mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { expectedImagePackageNames, parseImageReleaseTag } from "./image-release-publish-matrix.ts";

type ImagePublishMatrixEntry = {
  readonly image: string;
  readonly tag: string;
  readonly version: string;
};

const repo = "torkbot/sandbox";
const trustedPublisher = {
  owner: "torkbot",
  repository: "sandbox",
  workflowFilename: "image-release-publish.yml",
  allowedAction: "npm publish",
};

function requiredArg(args: readonly string[], name: string): string {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

function optionalArg(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

function hasFlag(args: readonly string[], name: string): boolean {
  return args.includes(name);
}

async function execFileChecked(
  command: string,
  args: readonly string[],
  options: {
    readonly cwd?: string;
    readonly env?: NodeJS.ProcessEnv;
    readonly quiet?: boolean;
  } = {},
): Promise<string> {
  const { execFile } = await import("node:child_process");
  return await new Promise((resolvePromise, reject) => {
    execFile(command, [...args], {
      cwd: options.cwd,
      env: options.env,
      maxBuffer: 1024 * 1024 * 50,
    }, (error, stdout, stderr) => {
      if (!options.quiet && stdout.length > 0) {
        process.stdout.write(stdout);
      }
      if (!options.quiet && stderr.length > 0) {
        process.stderr.write(stderr);
      }
      if (error !== null) {
        reject(new Error(`${command} ${args.join(" ")} failed with exit code ${error.code ?? "unknown"}`));
        return;
      }
      resolvePromise(stdout);
    });
  });
}

async function execFileInteractive(command: string, args: readonly string[]): Promise<void> {
  const { spawn } = await import("node:child_process");
  console.log(`$ ${[command, ...args].join(" ")}`);
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, [...args], {
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(`${command} ${args.join(" ")} failed with exit code ${code ?? "unknown"}`));
        return;
      }
      resolvePromise();
    });
  });
}

async function npmPackageVersionExists(packageSpec: string): Promise<boolean> {
  try {
    await execFileChecked("npm", ["view", packageSpec, "version"], { quiet: true });
    return true;
  } catch {
    return false;
  }
}

async function packageSpecForTarball(tarball: string): Promise<string> {
  const packageJson = await execFileChecked("tar", ["-xOf", tarball, "package/package.json"], { quiet: true });
  const parsed = JSON.parse(packageJson) as {
    readonly name?: unknown;
    readonly version?: unknown;
  };
  if (typeof parsed.name !== "string" || typeof parsed.version !== "string") {
    throw new Error(`tarball package.json must contain name and version: ${tarball}`);
  }
  return `${parsed.name}@${parsed.version}`;
}

async function selectedReleases(input: {
  readonly image: string;
  readonly tag: string | undefined;
}): Promise<readonly ImagePublishMatrixEntry[]> {
  if (input.tag !== undefined) {
    const parsed = parseImageReleaseTag(input.tag);
    return [{
      image: parsed.image,
      tag: input.tag,
      version: parsed.version,
    }];
  }

  const token = (await execFileChecked("gh", ["auth", "token"], { quiet: true })).trim();
  const output = await execFileChecked("node", ["./scripts/image-release-publish-matrix.ts", "--image", input.image], {
    quiet: true,
    env: {
      ...process.env,
      GITHUB_REPOSITORY: repo,
      GITHUB_TOKEN: token,
    },
  });
  const matrixLine = output.split("\n").find((line) => line.startsWith("matrix="));
  if (matrixLine === undefined) {
    throw new Error("image publish matrix did not emit matrix output");
  }
  const matrix = JSON.parse(matrixLine.slice("matrix=".length)) as {
    readonly include?: readonly ImagePublishMatrixEntry[];
  };
  return matrix.include ?? [];
}

async function publishRelease(input: {
  readonly release: ImagePublishMatrixEntry;
  readonly dryRun: boolean;
}): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), `sandbox-image-${input.release.image}-`));
  try {
    console.log(`\n${input.release.tag}`);
    await execFileChecked("gh", [
      "release",
      "download",
      input.release.tag,
      "--repo",
      repo,
      "--pattern",
      "*.tgz",
      "--dir",
      dir,
    ], { quiet: true });
    const tarballs = (await readdir(dir))
      .filter((entry) => entry.endsWith(".tgz"))
      .map((entry) => resolve(dir, entry))
      .sort((a, b) => tarballPublishOrder(a) - tarballPublishOrder(b) || basename(a).localeCompare(basename(b)));
    if (tarballs.length !== 3) {
      throw new Error(`expected exactly three image package tarballs for ${input.release.tag}, found ${tarballs.length}`);
    }

    for (const tarball of tarballs) {
      const packageSpec = await packageSpecForTarball(tarball);
      if (await npmPackageVersionExists(packageSpec)) {
        console.log(`already published ${packageSpec}`);
        continue;
      }
      if (input.dryRun) {
        console.log(`would publish ${packageSpec}`);
        continue;
      }
      console.log(`publishing ${packageSpec}`);
      await execFileInteractive("npm", [
        "publish",
        tarball,
        "--tag",
        "image",
        "--access",
        "public",
      ]);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

function tarballPublishOrder(path: string): number {
  const name = basename(path);
  if (name.includes("-arm64-") || name.includes("-x64-")) {
    return 0;
  }
  return 1;
}

function printTrustedPublisherChecklist(releases: readonly ImagePublishMatrixEntry[]): void {
  const packages = [...new Set(releases.flatMap((release) => {
    return expectedImagePackageNames({ image: release.image });
  }))].sort();
  console.log("\nTrusted publishing cannot be configured by the npm CLI.");
  console.log("For each package on npmjs.com, open Settings -> Trusted publishing and set:");
  console.log(`  Organization or user: ${trustedPublisher.owner}`);
  console.log(`  Repository: ${trustedPublisher.repository}`);
  console.log(`  Workflow filename: ${trustedPublisher.workflowFilename}`);
  console.log(`  Allowed action: ${trustedPublisher.allowedAction}`);
  console.log("Packages:");
  for (const packageName of packages) {
    console.log(`  https://www.npmjs.com/package/${encodeURIComponent(packageName)}/settings/access`);
  }
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const image = optionalArg(args, "--image") ?? "all";
  const tag = optionalArg(args, "--tag");
  if (tag !== undefined && args.includes("--image")) {
    throw new Error("pass --tag or --image, not both");
  }
  const dryRun = hasFlag(args, "--dry-run");
  const yes = hasFlag(args, "--yes");

  if (!dryRun) {
    await execFileChecked("npm", ["whoami"], { quiet: true });
  }
  await execFileChecked("gh", ["auth", "status"], { quiet: true });

  const releases = await selectedReleases({ image, tag });
  if (releases.length === 0) {
    console.log("No image package versions need local publish.");
    return;
  }

  console.log(`Selected ${releases.length} image release(s):`);
  for (const release of releases) {
    console.log(`  ${release.tag}`);
  }
  if (!dryRun && !yes) {
    throw new Error("rerun with --yes to publish these package versions from this machine");
  }

  for (const release of releases) {
    await publishRelease({ release, dryRun });
  }
  printTrustedPublisherChecklist(releases);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
