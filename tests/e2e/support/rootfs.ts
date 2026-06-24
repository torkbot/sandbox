import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";
import type { TestContext } from "node:test";
import { rootfs, type RootfsImageConfig } from "../../../src/index.ts";
import type { RootfsEnvironmentFactsManifest } from "../../../src/environment-facts.ts";

const repoRoot = resolve(import.meta.dirname, "../../..");
const defaultImagePath = resolve(repoRoot, "dist/rootfs/alpine-3.23.qcow2");
const defaultFactsPath = resolve(repoRoot, "dist/rootfs/alpine-3.23-agent.environment-facts.json");

let cachedTestRootfs: Promise<RootfsImageConfig> | undefined;

export function testRootfsImage(): Promise<RootfsImageConfig> {
  cachedTestRootfs ??= loadTestRootfsImage();
  return cachedTestRootfs;
}

export async function testRootfsImageOrSkip(t: TestContext): Promise<RootfsImageConfig | undefined> {
  try {
    return await testRootfsImage();
  } catch (error) {
    if (isMissingFixture(error)) {
      t.skip(error instanceof Error ? error.message : "test rootfs fixture is not built");
      return undefined;
    }
    throw error;
  }
}

async function loadTestRootfsImage(): Promise<RootfsImageConfig> {
  const path = resolve(process.env.SANDBOX_TEST_ROOTFS_IMAGE ?? defaultImagePath);
  const factsPath = resolve(process.env.SANDBOX_TEST_ROOTFS_FACTS ?? defaultFactsPath);
  const [imageStat, manifest] = await Promise.all([
    stat(path),
    readRootfsFactsManifest(factsPath),
  ]);

  if (!imageStat.isFile()) {
    throw new Error(`test rootfs image path is not a file: ${path}`);
  }

  return rootfs.image({
    name: manifest.rootfs,
    path,
    format: "qcow2",
    architecture: process.arch,
    digest: `sha256:${await sha256File(path)}`,
    sizeBytes: BigInt(imageStat.size),
    facts: manifest.facts,
  });
}

async function readRootfsFactsManifest(path: string): Promise<RootfsEnvironmentFactsManifest> {
  const manifest = JSON.parse(await readFile(path, "utf8")) as RootfsEnvironmentFactsManifest;
  if (manifest.schemaVersion !== 1) {
    throw new Error(`unsupported rootfs facts manifest schema version: ${manifest.schemaVersion}`);
  }
  return manifest;
}

function isMissingFixture(error: unknown): boolean {
  return typeof error === "object"
    && error !== null
    && "code" in error
    && (error as { readonly code?: unknown }).code === "ENOENT";
}

function sha256File(path: string): Promise<string> {
  return new Promise((resolveDigest, reject) => {
    const hash = createHash("sha256");
    const stream = createReadStream(path);
    stream.on("data", (chunk) => {
      hash.update(chunk);
    });
    stream.on("error", reject);
    stream.on("end", () => {
      resolveDigest(hash.digest("hex"));
    });
  });
}
