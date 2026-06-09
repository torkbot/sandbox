import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

type ArtifactFile = {
  readonly path: string;
  readonly sha256: string;
};

type ReleaseArtifactManifest = {
  readonly schemaVersion: 1;
  readonly headSha: string;
  readonly platform: string;
  readonly fixtureKeys: {
    readonly kernel: string;
    readonly init: string;
    readonly rootfs: string;
  };
  readonly macosSigning?: {
    readonly authority: string;
    readonly teamIdentifier: string;
    readonly notarizationSubmissionId: string;
    readonly notarizationStatus: string;
  };
  readonly files: readonly ArtifactFile[];
};

const repoRoot = resolve(import.meta.dirname, "..");
const args = process.argv.slice(2);
const command = args[0];

switch (command) {
  case "write":
    await writeManifest();
    break;
  case "verify":
    await verifyManifest();
    break;
  default:
    throw new Error("usage: release-artifact-manifest.ts <write|verify> ...");
}

async function writeManifest(): Promise<void> {
  const headSha = requiredArg("--head-sha");
  const platform = requiredArg("--platform");
  const output = requiredArg("--output");
  const baseDir = resolve(repoRoot, optionalArg("--base-dir") ?? ".");
  const kernelKey = requiredArg("--kernel-key");
  const initKey = requiredArg("--init-key");
  const rootfsKey = requiredArg("--rootfs-key");
  const authority = optionalArg("--macos-codesign-authority");
  const teamIdentifier = optionalArg("--macos-codesign-team-identifier");
  const notarizationSubmissionId = optionalArg("--macos-notarization-submission-id");
  const notarizationStatus = optionalArg("--macos-notarization-status");
  const files = repeatedArgs("--file");

  if (files.length === 0) {
    throw new Error("at least one --file is required");
  }
  const macosSigningArgs = [
    authority,
    teamIdentifier,
    notarizationSubmissionId,
    notarizationStatus,
  ];
  if (macosSigningArgs.some((value) => value !== undefined) && macosSigningArgs.some((value) => value === undefined)) {
    throw new Error("macOS signing metadata requires authority, team identifier, notarization submission ID, and notarization status");
  }

  const manifest: ReleaseArtifactManifest = {
    schemaVersion: 1,
    headSha,
    platform,
    fixtureKeys: {
      kernel: kernelKey,
      init: initKey,
      rootfs: rootfsKey,
    },
    ...(authority !== undefined
      ? {
          macosSigning: {
            authority,
            teamIdentifier: teamIdentifier!,
            notarizationSubmissionId: notarizationSubmissionId!,
            notarizationStatus: notarizationStatus!,
          },
        }
      : {}),
    files: await Promise.all(
      files.map(async (file) => ({
        path: file,
        sha256: await sha256File(resolve(baseDir, file)),
      })),
    ),
  };

  await writeFile(resolve(repoRoot, output), `${JSON.stringify(manifest, null, 2)}\n`);
}

async function verifyManifest(): Promise<void> {
  const headSha = requiredArg("--head-sha");
  const platform = requiredArg("--platform");
  const manifestPath = requiredArg("--manifest");
  const baseDir = resolve(repoRoot, optionalArg("--base-dir") ?? ".");
  const manifest = JSON.parse(
    await readFile(resolve(repoRoot, manifestPath), "utf8"),
  ) as ReleaseArtifactManifest;

  if (manifest.schemaVersion !== 1) {
    throw new Error(`unsupported release artifact manifest schema: ${String(manifest.schemaVersion)}`);
  }
  if (manifest.headSha !== headSha) {
    throw new Error(`release artifact head SHA mismatch: expected ${headSha}, got ${manifest.headSha}`);
  }
  if (manifest.platform !== platform) {
    throw new Error(`release artifact platform mismatch: expected ${platform}, got ${manifest.platform}`);
  }
  if (platform === "darwin-arm64") {
    if (manifest.macosSigning === undefined) {
      throw new Error("darwin-arm64 release artifact is missing macOS signing metadata");
    }
    if (manifest.macosSigning.notarizationStatus !== "Accepted") {
      throw new Error(`darwin-arm64 release artifact notarization was not accepted: ${manifest.macosSigning.notarizationStatus}`);
    }
  }

  for (const file of manifest.files) {
    const actual = await sha256File(resolve(baseDir, file.path));
    if (actual !== file.sha256) {
      throw new Error(`release artifact digest mismatch for ${file.path}: expected ${file.sha256}, got ${actual}`);
    }
  }
}

function requiredArg(name: string): string {
  const value = optionalArg(name);
  if (value === undefined) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

function optionalArg(name: string): string | undefined {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined) {
    return undefined;
  }
  if (value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing value for argument: ${name}`);
  }
  return value;
}

function repeatedArgs(name: string): string[] {
  const values: string[] = [];
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === name) {
      const value = args[index + 1];
      if (value === undefined || value.length === 0 || value.startsWith("--")) {
        throw new Error(`missing value for argument: ${name}`);
      }
      values.push(value);
      index += 1;
    }
  }
  return values;
}

async function sha256File(path: string): Promise<string> {
  return createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
}
