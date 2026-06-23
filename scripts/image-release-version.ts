import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseImageSource } from "./image-manifest.ts";

export type ImageReleaseVersionInput = {
  readonly exportCompatibility: string;
  readonly generatedAt: Date;
  readonly contentDigest: `sha256:${string}`;
};

export type ParsedImageReleaseVersion = {
  readonly exportCompatibility: string;
  readonly generatedAt: string;
  readonly shortContentDigest: `sha${string}`;
};

const normalSemver = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const imageReleaseVersionPattern = /^((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))\-image\.(\d{8}T\d{6}Z)\.(sha[a-f0-9]{12})$/;

export function imageReleaseVersion(input: ImageReleaseVersionInput): string {
  validateExportCompatibility(input.exportCompatibility);
  const shortDigest = shortImageContentDigest(input.contentDigest);
  return `${input.exportCompatibility}-image.${compactUtcTimestamp(input.generatedAt)}.${shortDigest}`;
}

export function parseImageReleaseVersion(version: string): ParsedImageReleaseVersion {
  const match = imageReleaseVersionPattern.exec(version);
  if (match === null || match[1] === undefined || match[2] === undefined || match[3] === undefined) {
    throw new Error(`invalid image release version: ${version}`);
  }

  return {
    exportCompatibility: match[1],
    generatedAt: match[2],
    shortContentDigest: match[3] as `sha${string}`,
  };
}

export function assertImageReleaseVersion(input: {
  readonly version: string;
  readonly exportCompatibility: string;
  readonly contentDigest: `sha256:${string}`;
}): void {
  const parsed = parseImageReleaseVersion(input.version);
  if (parsed.exportCompatibility !== input.exportCompatibility) {
    throw new Error(`image release version ${input.version} is not compatible with ${input.exportCompatibility}`);
  }

  const expectedShortDigest = shortImageContentDigest(input.contentDigest);
  if (parsed.shortContentDigest !== expectedShortDigest) {
    throw new Error(`image release version ${input.version} does not match content digest ${input.contentDigest}`);
  }
}

export function compactUtcTimestamp(date: Date): string {
  if (Number.isNaN(date.getTime())) {
    throw new Error("generatedAt must be a valid date");
  }

  return [
    date.getUTCFullYear().toString().padStart(4, "0"),
    (date.getUTCMonth() + 1).toString().padStart(2, "0"),
    date.getUTCDate().toString().padStart(2, "0"),
    "T",
    date.getUTCHours().toString().padStart(2, "0"),
    date.getUTCMinutes().toString().padStart(2, "0"),
    date.getUTCSeconds().toString().padStart(2, "0"),
    "Z",
  ].join("");
}

export function shortImageContentDigest(digest: `sha256:${string}`): `sha${string}` {
  parseImageSource(`docker.io/library/sandbox:content@${digest}`);
  return `sha${digest.slice("sha256:".length, "sha256:".length + 12)}`;
}

export async function sha256File(path: string): Promise<`sha256:${string}`> {
  const hash = createHash("sha256");
  await new Promise<void>((resolvePromise, reject) => {
    const stream = createReadStream(path);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", resolvePromise);
  });
  return `sha256:${hash.digest("hex")}`;
}

function validateExportCompatibility(version: string): void {
  if (!normalSemver.test(version)) {
    throw new Error(`export compatibility must be a normal semver version: ${version}`);
  }
}

function requiredArg(args: readonly string[], name: string): string {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const exportCompatibility = requiredArg(args, "--compat");
  const generatedAt = new Date(requiredArg(args, "--generated-at"));
  const digestArg = args.includes("--digest") ? requiredArg(args, "--digest") : undefined;
  const fileArg = args.includes("--file") ? requiredArg(args, "--file") : undefined;

  if ((digestArg === undefined) === (fileArg === undefined)) {
    throw new Error("pass exactly one of --digest <sha256:digest> or --file <path>");
  }

  const contentDigest = digestArg === undefined
    ? await sha256File(resolve(fileArg as string))
    : digestArg as `sha256:${string}`;
  console.log(imageReleaseVersion({
    exportCompatibility,
    generatedAt,
    contentDigest,
  }));
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
