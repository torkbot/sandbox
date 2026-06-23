import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseImageSource, readImageDefinition } from "./image-manifest.ts";

export type ImageReleaseArtifactDigest = {
  readonly architecture: string;
  readonly digest: `sha256:${string}`;
};

export async function imageReleaseDigest(input: {
  readonly imageId: string;
  readonly artifacts: readonly ImageReleaseArtifactDigest[];
}): Promise<`sha256:${string}`> {
  const definition = await readImageDefinition(input.imageId);
  parseImageSource(definition.manifest.source);
  const artifacts = [...input.artifacts].sort((left, right) => left.architecture.localeCompare(right.architecture));
  const architectures = artifacts.map((artifact) => artifact.architecture);
  if (architectures.join(",") !== "arm64,x64") {
    throw new Error("image release artifacts must include exactly arm64 and x64");
  }
  for (const artifact of artifacts) {
    assertArchitecture(artifact.architecture);
    parseImageSource(`docker.io/library/sandbox:content@${artifact.digest}`);
  }

  const canonical = JSON.stringify({
    schemaVersion: 1,
    image: input.imageId,
    imageName: definition.manifest.imageName,
    source: definition.manifest.source,
    exportCompatibility: definition.manifest.exportCompatibility,
    artifacts,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
}

function parseArtifactDigest(value: string): ImageReleaseArtifactDigest {
  const separator = value.indexOf("=");
  if (separator === -1) {
    throw new Error(`artifact digest must be <architecture>=<sha256:digest>: ${value}`);
  }
  const architecture = value.slice(0, separator);
  const digest = value.slice(separator + 1) as `sha256:${string}`;
  assertArchitecture(architecture);
  parseImageSource(`docker.io/library/sandbox:content@${digest}`);
  return {
    architecture,
    digest,
  };
}

function assertArchitecture(value: string): void {
  if (value !== "arm64" && value !== "x64") {
    throw new Error(`unsupported image architecture: ${value}`);
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
  const imageId = requiredArg(args, "--image");
  const artifacts = args.flatMap((arg, index) => {
    if (arg !== "--artifact") {
      return [];
    }
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error("missing required argument: --artifact");
    }
    return [parseArtifactDigest(value)];
  });
  console.log(await imageReleaseDigest({
    imageId,
    artifacts,
  }));
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
