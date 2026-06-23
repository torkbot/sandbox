import { copyFile, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  imagePackageName,
  readImageDefinition,
  type ImagePackageJson,
} from "./image-manifest.ts";
import {
  assertImageReleaseVersion,
  sha256File,
} from "./image-release-version.ts";

type RootfsEnvironmentFactsManifest = {
  readonly schemaVersion: 1;
  readonly rootfs: string;
  readonly facts: readonly unknown[];
};

const repoRoot = resolve(import.meta.dirname, "..");
const supportedNodeArchitectures = ["arm64", "x64"] as const;
type SupportedNodeArchitecture = typeof supportedNodeArchitectures[number];

const args = process.argv.slice(2);
const imageId = requiredArg(args, "--image");
const version = requiredArg(args, "--version");
const architecture = parseArchitecture(requiredArg(args, "--architecture"));
const rootfsPath = resolve(requiredArg(args, "--rootfs"));
const factsPath = resolve(requiredArg(args, "--facts"));
const outRoot = resolve(requiredArg(args, "--out-dir"));
const releaseDigest = requiredArg(args, "--release-digest") as `sha256:${string}`;

const definition = await readImageDefinition(imageId);
const rootfsInfo = await stat(rootfsPath);
if (!rootfsInfo.isFile()) {
  throw new Error(`rootfs path must be a file: ${rootfsPath}`);
}

const factsManifest = JSON.parse(await readFile(factsPath, "utf8")) as RootfsEnvironmentFactsManifest;
if (factsManifest.schemaVersion !== 1 || !Array.isArray(factsManifest.facts)) {
  throw new Error(`facts path must contain a rootfs environment facts manifest: ${factsPath}`);
}

const contentDigest = await sha256File(rootfsPath);
assertImageReleaseVersion({
  version,
  exportCompatibility: definition.manifest.exportCompatibility,
  contentDigest: releaseDigest,
});

const packageJson = definition.packageJson;
const rootPackageName = imagePackageName(imageId);
const archPackageName = `${rootPackageName}-${architecture}`;
const rootPackageDir = resolve(outRoot, rootPackageName.replace("@torkbot/", ""));
const archPackageDir = resolve(outRoot, archPackageName.replace("@torkbot/", ""));

await writeRootPackage({
  imageId,
  packageJson,
  version,
  rootPackageDir,
});
await writeArchPackage({
  architecture,
  contentDigest,
  definition,
  factsPath,
  packageJson,
  rootfsPath,
  rootfsSizeBytes: BigInt(rootfsInfo.size),
  archPackageDir,
  version,
});

console.log(`${rootPackageName}@${version}`);
console.log(`${archPackageName}@${version}`);

async function writeRootPackage(input: {
  readonly imageId: string;
  readonly packageJson: ImagePackageJson;
  readonly version: string;
  readonly rootPackageDir: string;
}): Promise<void> {
  const optionalDependencies = Object.fromEntries(
    supportedNodeArchitectures.map((arch) => [`${input.packageJson.name}-${arch}`, input.version]),
  );
  await rm(input.rootPackageDir, { recursive: true, force: true });
  await mkdir(input.rootPackageDir, { recursive: true });
  await writeJson(resolve(input.rootPackageDir, "package.json"), {
    name: input.packageJson.name,
    version: input.version,
    private: false,
    type: "module",
    description: input.packageJson.description,
    license: input.packageJson.license,
    repository: input.packageJson.repository,
    publishConfig: {
      access: "public",
    },
    peerDependencies: input.packageJson.peerDependencies,
    optionalDependencies,
    exports: {
      ".": {
        types: "./index.d.ts",
        default: "./index.js",
      },
    },
    types: "./index.d.ts",
    files: [
      "index.d.ts",
      "index.js",
      "README.md",
    ],
    engines: {
      node: ">=24.0.0",
    },
  });
  await writeFile(
    resolve(input.rootPackageDir, "index.js"),
    rootPackageIndex(input.packageJson.name),
  );
  await writeFile(
    resolve(input.rootPackageDir, "index.d.ts"),
    [
      'import type { RootfsImageConfig } from "@torkbot/sandbox";',
      "export declare const image: RootfsImageConfig;",
      "export default image;",
      "",
    ].join("\n"),
  );
  await writeFile(
    resolve(input.rootPackageDir, "README.md"),
    [
      `# ${input.packageJson.name}`,
      "",
      `This package exports the ${input.imageId} sandbox rootfs image for @torkbot/sandbox.`,
      "",
    ].join("\n"),
  );
}

async function writeArchPackage(input: {
  readonly architecture: SupportedNodeArchitecture;
  readonly contentDigest: `sha256:${string}`;
  readonly definition: Awaited<ReturnType<typeof readImageDefinition>>;
  readonly factsPath: string;
  readonly packageJson: ImagePackageJson;
  readonly rootfsPath: string;
  readonly rootfsSizeBytes: bigint;
  readonly archPackageDir: string;
  readonly version: string;
}): Promise<void> {
  const archPackageName = `${input.packageJson.name}-${input.architecture}`;
  await rm(input.archPackageDir, { recursive: true, force: true });
  await mkdir(input.archPackageDir, { recursive: true });
  await writeJson(resolve(input.archPackageDir, "package.json"), {
    name: archPackageName,
    version: input.version,
    private: false,
    description: `${input.definition.manifest.imageName} QCOW2 rootfs artifact for linux/${input.architecture}.`,
    license: input.packageJson.license,
    repository: input.packageJson.repository,
    publishConfig: {
      access: "public",
    },
    main: "index.cjs",
    os: ["linux"],
    cpu: [input.architecture],
    files: [
      "environment-facts.json",
      "index.cjs",
      "README.md",
      "rootfs.qcow2",
    ],
  });
  await writeFile(
    resolve(input.archPackageDir, "index.cjs"),
    archPackageIndex({
      architecture: input.architecture,
      contentDigest: input.contentDigest,
      imageName: input.definition.manifest.imageName,
      rootfsSizeBytes: input.rootfsSizeBytes,
    }),
  );
  await writeFile(
    resolve(input.archPackageDir, "README.md"),
    [
      `# ${archPackageName}`,
      "",
      `This package contains the linux/${input.architecture} rootfs artifact for ${input.packageJson.name}.`,
      "",
    ].join("\n"),
  );
  await copyFile(input.rootfsPath, resolve(input.archPackageDir, "rootfs.qcow2"));
  await copyFile(input.factsPath, resolve(input.archPackageDir, "environment-facts.json"));
}

function rootPackageIndex(packageName: string): string {
  const architectureMap = Object.fromEntries(
    supportedNodeArchitectures.map((arch) => [arch, `${packageName}-${arch}`]),
  );
  return [
    'import { createRequire } from "node:module";',
    'import { rootfs as sandboxRootfs } from "@torkbot/sandbox";',
    "",
    "const require = createRequire(import.meta.url);",
    `const packageByArchitecture = ${JSON.stringify(architectureMap, null, 2)};`,
    "const packageName = packageByArchitecture[process.arch];",
    "if (packageName === undefined) {",
    "  throw new Error(`unsupported sandbox image architecture: ${process.arch}`);",
    "}",
    "",
    "const { artifact } = require(packageName);",
    "export const image = sandboxRootfs.image({",
    "  name: artifact.imageName,",
    "  path: artifact.path,",
    "  format: artifact.format,",
    "  architecture: artifact.architecture,",
    "  digest: artifact.digest,",
    "  sizeBytes: artifact.sizeBytes,",
    "  facts: artifact.facts,",
    "});",
    "export default image;",
    "",
  ].join("\n");
}

function archPackageIndex(input: {
  readonly architecture: SupportedNodeArchitecture;
  readonly contentDigest: `sha256:${string}`;
  readonly imageName: string;
  readonly rootfsSizeBytes: bigint;
}): string {
  return [
    '"use strict";',
    "",
    'const { readFileSync } = require("node:fs");',
    'const { join } = require("node:path");',
    "",
    'const rootfsPath = join(__dirname, "rootfs.qcow2");',
    'const factsPath = join(__dirname, "environment-facts.json");',
    "const factsManifest = JSON.parse(readFileSync(factsPath, \"utf8\"));",
    "",
    "exports.artifact = Object.freeze({",
    `  imageName: ${JSON.stringify(input.imageName)},`,
    "  path: rootfsPath,",
    '  format: "qcow2",',
    `  architecture: ${JSON.stringify(input.architecture)},`,
    `  digest: ${JSON.stringify(input.contentDigest)},`,
    `  sizeBytes: ${input.rootfsSizeBytes.toString()}n,`,
    "  facts: Object.freeze([...factsManifest.facts]),",
    "});",
    "",
  ].join("\n");
}

function parseArchitecture(value: string): SupportedNodeArchitecture {
  if (supportedNodeArchitectures.includes(value as SupportedNodeArchitecture)) {
    return value as SupportedNodeArchitecture;
  }
  throw new Error(`unsupported image architecture: ${value}`);
}

function requiredArg(values: readonly string[], name: string): string {
  const index = values.indexOf(name);
  const value = index === -1 ? undefined : values[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

if (process.argv[1] === undefined || resolve(process.argv[1]) !== fileURLToPath(import.meta.url)) {
  throw new Error("prepare-image-npm-packages.ts must be run as a script");
}
