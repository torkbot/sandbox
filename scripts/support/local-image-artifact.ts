import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import { rootfs, type RootfsImageConfig } from "../../src/index.ts";
import type { RootfsEnvironmentFactsManifest } from "../../src/environment-facts.ts";

export const defaultLocalImageId = "alpine-3.23-agent";

export type LocalImageArchitecture = "arm64" | "x64";

export type LocalImageArtifactMetadata = {
  readonly path: string;
  readonly sha256: string;
  readonly bytes: number;
};

export type LocalImageArtifact = {
  readonly image: RootfsImageConfig;
  readonly rootfs: LocalImageArtifactMetadata;
  readonly factsPath: string;
};

export function localNodeArchitecture(): LocalImageArchitecture {
  if (process.arch === "arm64" || process.arch === "x64") {
    return process.arch;
  }
  throw new Error(`unsupported image artifact architecture: ${process.arch}`);
}

export function localImageArtifactPaths(input: {
  readonly repoRoot: string;
  readonly imageId: string;
  readonly architecture: LocalImageArchitecture;
}): {
  readonly rootDir: string;
  readonly rootfsPath: string;
  readonly factsPath: string;
  readonly digestPath: string;
} {
  const base = resolve(input.repoRoot, "dist/image-release", input.imageId, input.architecture);
  return {
    rootDir: resolve(base, "rootfs"),
    rootfsPath: resolve(base, "rootfs.qcow2"),
    factsPath: resolve(base, "environment-facts.json"),
    digestPath: resolve(base, "rootfs.digest"),
  };
}

export async function loadLocalImageArtifact(input: {
  readonly repoRoot: string;
  readonly imageId?: string;
  readonly architecture?: LocalImageArchitecture;
  readonly consumer: string;
}): Promise<LocalImageArtifact> {
  const imageId = input.imageId ?? defaultLocalImageId;
  const architecture = input.architecture ?? localNodeArchitecture();
  const paths = localImageArtifactPaths({
    repoRoot: input.repoRoot,
    imageId,
    architecture,
  });
  try {
    const [imageStat, manifest, digest] = await Promise.all([
      stat(paths.rootfsPath),
      readRootfsFactsManifest(paths.factsPath),
      readRootfsDigest(paths.digestPath),
    ]);
    if (!imageStat.isFile()) {
      throw new Error(`rootfs image path is not a file: ${paths.rootfsPath}`);
    }
    return {
      image: rootfs.image({
        name: manifest.rootfs,
        path: paths.rootfsPath,
        format: "qcow2",
        architecture,
        digest,
        sizeBytes: BigInt(imageStat.size),
        facts: manifest.facts,
      }),
      rootfs: {
        path: paths.rootfsPath,
        sha256: digest.slice("sha256:".length),
        bytes: imageStat.size,
      },
      factsPath: paths.factsPath,
    };
  } catch (error) {
    if (typeof error === "object" && error !== null && "code" in error && (error as { readonly code?: unknown }).code === "ENOENT") {
      throw new Error(
        `${input.consumer} image artifact is missing for ${imageId}/${architecture}. ` +
          `Run: npm run images:build-local -- --image ${imageId} --architecture ${architecture}`,
      );
    }
    throw error;
  }
}

async function readRootfsFactsManifest(path: string): Promise<RootfsEnvironmentFactsManifest> {
  const manifest = JSON.parse(await readFile(path, "utf8")) as RootfsEnvironmentFactsManifest;
  if (manifest.schemaVersion !== 1) {
    throw new Error(`unsupported rootfs facts manifest schema version: ${manifest.schemaVersion}`);
  }
  return manifest;
}

async function readRootfsDigest(path: string): Promise<`sha256:${string}`> {
  const digest = (await readFile(path, "utf8")).trim();
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) {
    throw new Error(`invalid rootfs digest at ${path}`);
  }
  return digest as `sha256:${string}`;
}
