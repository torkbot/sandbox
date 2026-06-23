import { readdir, readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export type ImageManifest = {
  readonly schemaVersion: 1;
  readonly imageName: string;
  readonly source: string;
  readonly exportCompatibility: string;
};

export type ImagePackageJson = {
  readonly name: string;
  readonly private: true;
  readonly type: "module";
  readonly description: string;
  readonly license: string;
  readonly repository: {
    readonly type: string;
    readonly url: string;
    readonly directory: string;
  };
  readonly peerDependencies: {
    readonly "@torkbot/sandbox": string;
  };
};

export type ImageDefinition = {
  readonly id: string;
  readonly root: string;
  readonly manifest: ImageManifest;
  readonly packageJson: ImagePackageJson;
};

export const imageManifestKeys = [
  "exportCompatibility",
  "imageName",
  "schemaVersion",
  "source",
] as const;

const repoRoot = resolve(import.meta.dirname, "..");
export const defaultImagesRoot = resolve(repoRoot, "images");
const normalSemver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const imageIdPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:\.[0-9]+)?(?:-[a-z0-9]+(?:\.[0-9]+)*)*$/;
const sourcePattern = /^[a-z0-9][a-z0-9._:-]*(?:\/[A-Za-z0-9._-]+)+:([^@]+)@(sha256:[a-f0-9]{64})$/;
const aliasTag = /(^|[-_.])(latest|stable|current|lts)([-_.]|$)/i;

export async function listImageDefinitions(imagesRoot = defaultImagesRoot): Promise<readonly ImageDefinition[]> {
  const entries = await readdir(imagesRoot, { withFileTypes: true });
  const ids = entries
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();

  return await Promise.all(ids.map((id) => readImageDefinition(id, imagesRoot)));
}

export async function readImageDefinition(id: string, imagesRoot = defaultImagesRoot): Promise<ImageDefinition> {
  assertImageId(id);
  const root = resolve(imagesRoot, id);
  const manifest = assertImageManifest(JSON.parse(
    await readFile(resolve(root, "image.json"), "utf8"),
  ));
  const packageJson = assertImagePackageJson(id, JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  ));

  return {
    id,
    root,
    manifest,
    packageJson,
  };
}

export function imagePackageName(id: string): string {
  assertImageId(id);
  return `@torkbot/sandbox-image-${id}`;
}

export function assertImageManifest(value: unknown): ImageManifest {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("image.json must be an object");
  }

  const record = value as Record<string, unknown>;
  const actualKeys = Object.keys(record).sort();
  const expectedKeys = [...imageManifestKeys].sort();
  if (actualKeys.join("\n") !== expectedKeys.join("\n")) {
    throw new Error(`image.json must contain only: ${expectedKeys.join(", ")}`);
  }

  if (record.schemaVersion !== 1) {
    throw new Error("image.json schemaVersion must be 1");
  }
  if (typeof record.imageName !== "string" || record.imageName.length === 0) {
    throw new Error("image.json imageName must be a non-empty string");
  }
  if (aliasTag.test(record.imageName)) {
    throw new Error(`image.json imageName must not use convenience aliases: ${record.imageName}`);
  }
  if (typeof record.source !== "string" || record.source.length === 0) {
    throw new Error("image.json source must be a non-empty string");
  }
  parseImageSource(record.source);
  if (typeof record.exportCompatibility !== "string" || !normalSemver.test(record.exportCompatibility)) {
    throw new Error("image.json exportCompatibility must be a normal semver version");
  }

  return record as ImageManifest;
}

export function assertImagePackageJson(id: string, value: unknown): ImagePackageJson {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${id}/package.json must be an object`);
  }

  const record = value as Record<string, unknown>;
  if (record.name !== imagePackageName(id)) {
    throw new Error(`${id}/package.json name must be ${imagePackageName(id)}`);
  }
  if (record.private !== true) {
    throw new Error(`${id}/package.json must remain private; release packages are generated`);
  }
  if (record.type !== "module") {
    throw new Error(`${id}/package.json type must be module`);
  }
  if (typeof record.description !== "string" || record.description.length === 0) {
    throw new Error(`${id}/package.json description must be a non-empty string`);
  }
  if (typeof record.license !== "string" || record.license.length === 0) {
    throw new Error(`${id}/package.json license must be a non-empty string`);
  }

  const repository = record.repository as Record<string, unknown> | undefined;
  if (repository?.type !== "git" || typeof repository.url !== "string" || repository.url.length === 0) {
    throw new Error(`${id}/package.json repository must identify the git repository`);
  }
  if (repository.directory !== `images/${id}`) {
    throw new Error(`${id}/package.json repository.directory must be images/${id}`);
  }

  const peerDependencies = record.peerDependencies as Record<string, unknown> | undefined;
  if (typeof peerDependencies?.["@torkbot/sandbox"] !== "string" || peerDependencies["@torkbot/sandbox"].length === 0) {
    throw new Error(`${id}/package.json must require @torkbot/sandbox as a peer dependency`);
  }

  return record as ImagePackageJson;
}

export function parseImageSource(source: string): {
  readonly tag: string;
  readonly digest: `sha256:${string}`;
} {
  const match = sourcePattern.exec(source);
  if (match === null || match[1] === undefined || match[2] === undefined) {
    throw new Error(`image source must be a tag pinned by sha256 digest: ${source}`);
  }

  const tag = match[1];
  if (aliasTag.test(tag)) {
    throw new Error(`image source tag must not be a convenience alias: ${source}`);
  }

  return {
    tag,
    digest: match[2] as `sha256:${string}`,
  };
}

function assertImageId(id: string): void {
  if (!imageIdPattern.test(id) || id !== basename(id)) {
    throw new Error(`invalid image id: ${id}`);
  }
}

async function main(): Promise<void> {
  const command = process.argv[2];
  if (command !== "validate") {
    throw new Error("usage: node ./scripts/image-manifest.ts validate");
  }

  const definitions = await listImageDefinitions();
  if (definitions.length === 0) {
    throw new Error("at least one image definition is required");
  }
  for (const definition of definitions) {
    console.log(`${definition.id}: ${definition.manifest.imageName}`);
  }
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
