import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { promisify } from "node:util";
import {
  imageManifestKeys,
  imagePackageName,
  listImageDefinitions,
} from "../../scripts/image-manifest.ts";
import {
  imageReleaseVersion,
  parseImageReleaseVersion,
  type ImageReleaseVersionInput,
} from "../../scripts/image-release-version.ts";
import { imageReleaseDigest } from "../../scripts/image-release-digest.ts";

const execFileAsync = promisify(execFile);
const repoRoot = resolve(import.meta.dirname, "../..");
const expectedImageIds = [
  "alpine-3.23-agent",
  "alpine-3.23-slim",
  "debian-13-agent",
  "debian-13-slim",
  "ubuntu-26.04-agent",
  "ubuntu-26.04-slim",
];

test("checked-in image manifests stay minimal and immutable", async () => {
  const definitions = await listImageDefinitions();

  assert.deepEqual(definitions.map((definition) => definition.id), expectedImageIds);
  for (const definition of definitions) {
    assert.deepEqual(Object.keys(definition.manifest).sort(), [...imageManifestKeys].sort());
    assert.match(definition.manifest.source, /^[^@]+:[^@]+@sha256:[a-f0-9]{64}$/);
    assert.doesNotMatch(definition.manifest.source, /:(latest|stable|current|lts)@/i);
    assert.doesNotMatch(definition.manifest.imageName, /(^|[-_.])(latest|stable|current|lts)([-_.]|$)/i);
    assert.match(definition.manifest.exportCompatibility, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/);
    assert.equal(definition.packageJson.name, imagePackageName(definition.id));
    assert.equal(definition.packageJson.private, true);
    assert.equal(definition.packageJson.peerDependencies["@torkbot/sandbox"], "^0.13.0");

    const dockerfile = await readFile(new URL(`../../images/${definition.id}/Dockerfile`, import.meta.url), "utf8");
    assert.match(dockerfile, /^ARG SOURCE_IMAGE$/m);
    assert.match(dockerfile, /^FROM \$\{SOURCE_IMAGE\}$/m);
  }
});

test("image prerelease versions sort by fixed-width UTC timestamp before digest", () => {
  const digest = "sha256:9c4f2a1b3c4d5e60718293a4b5c6d7e8091a2b3c4d5e6f708192a3b4c5d6e7f8";
  const input: ImageReleaseVersionInput = {
    exportCompatibility: "0.1.0",
    generatedAt: new Date("2026-06-23T14:23:55Z"),
    contentDigest: digest,
  };

  const version = imageReleaseVersion(input);

  assert.equal(version, "0.1.0-image.20260623T142355Z.sha9c4f2a1b3c4d");
  assert.deepEqual(parseImageReleaseVersion(version), {
    exportCompatibility: "0.1.0",
    generatedAt: "20260623T142355Z",
    shortContentDigest: "sha9c4f2a1b3c4d",
  });

  const older = imageReleaseVersion({
    ...input,
    generatedAt: new Date("2026-06-23T14:23:54Z"),
  });
  const newer = imageReleaseVersion({
    ...input,
    generatedAt: new Date("2026-06-23T14:23:56Z"),
  });
  assert.deepEqual([newer, older, version].sort(), [older, version, newer]);
});

test("image release digest is stable for the same multi-architecture content", async () => {
  const first = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      { architecture: "arm64", digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
      { architecture: "x64", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    ],
  });
  const second = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      { architecture: "x64", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
      { architecture: "arm64", digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    ],
  });

  assert.equal(first, second);
});

test("image package preparation emits a root package and architecture artifact package", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "sandbox-image-package-"));
  const rootfsPath = join(tempRoot, "rootfs.qcow2");
  const factsPath = join(tempRoot, "environment-facts.json");
  const outDir = join(tempRoot, "npm");

  await writeFile(rootfsPath, "rootfs bytes\n");
  await writeFile(
    factsPath,
    `${JSON.stringify({
      schemaVersion: 1,
      rootfs: "alpine:3.23-slim",
      facts: [
        { source: "config", topic: "rootfs-image", relation: "is", value: "alpine:3.23-slim" },
      ],
    }, null, 2)}\n`,
  );

  const rootfsDigest = `sha256:${createHash("sha256").update("rootfs bytes\n").digest("hex")}` as const;
  const releaseDigest = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      { architecture: "arm64", digest: rootfsDigest },
      { architecture: "x64", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    ],
  });
  const version = imageReleaseVersion({
    exportCompatibility: "0.1.0",
    generatedAt: new Date("2026-06-23T14:23:55Z"),
    contentDigest: releaseDigest,
  });

  await execFileAsync(process.execPath, [
    "./scripts/prepare-image-npm-packages.ts",
    "--image",
    "alpine-3.23-slim",
    "--version",
    version,
    "--architecture",
    "arm64",
    "--rootfs",
    rootfsPath,
    "--facts",
    factsPath,
    "--release-digest",
    releaseDigest,
    "--out-dir",
    outDir,
  ], { cwd: repoRoot });

  const rootPackage = JSON.parse(
    await readFile(join(outDir, "sandbox-image-alpine-3.23-slim", "package.json"), "utf8"),
  ) as {
    name?: string;
    version?: string;
    private?: boolean;
    peerDependencies?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
  };
  const archPackage = JSON.parse(
    await readFile(join(outDir, "sandbox-image-alpine-3.23-slim-arm64", "package.json"), "utf8"),
  ) as {
    name?: string;
    version?: string;
    private?: boolean;
    main?: string;
    os?: readonly string[];
    cpu?: readonly string[];
  };

  assert.equal(rootPackage.name, "@torkbot/sandbox-image-alpine-3.23-slim");
  assert.equal(rootPackage.version, version);
  assert.equal(rootPackage.private, false);
  assert.deepEqual(rootPackage.peerDependencies, {
    "@torkbot/sandbox": "^0.13.0",
  });
  assert.deepEqual(rootPackage.optionalDependencies, {
    "@torkbot/sandbox-image-alpine-3.23-slim-arm64": version,
    "@torkbot/sandbox-image-alpine-3.23-slim-x64": version,
  });

  assert.equal(archPackage.name, "@torkbot/sandbox-image-alpine-3.23-slim-arm64");
  assert.equal(archPackage.version, version);
  assert.equal(archPackage.private, false);
  assert.equal(archPackage.main, "index.cjs");
  assert.deepEqual(archPackage.os, ["linux"]);
  assert.deepEqual(archPackage.cpu, ["arm64"]);
  assert.equal((await stat(join(outDir, "sandbox-image-alpine-3.23-slim-arm64", "rootfs.qcow2"))).isFile(), true);

  const archIndex = await readFile(join(outDir, "sandbox-image-alpine-3.23-slim-arm64", "index.cjs"), "utf8");
  assert.match(archIndex, new RegExp(rootfsDigest));
});

test("image release workflows are GitHub-state driven", async () => {
  const reconcileWorkflow = await readFile(
    new URL("../../.github/workflows/image-release-reconcile.yml", import.meta.url),
    "utf8",
  );
  const publishWorkflow = await readFile(
    new URL("../../.github/workflows/image-release-publish.yml", import.meta.url),
    "utf8",
  );

  assert.match(reconcileWorkflow, /schedule:/);
  assert.match(reconcileWorkflow, /workflow_dispatch:/);
  assert.match(reconcileWorkflow, /image:\n\s+description: Image id to reconcile, or all\n\s+type: string\n\s+required: true/);
  assert.match(reconcileWorkflow, /image-manifest\.ts validate/);
  assert.match(reconcileWorkflow, /image-release-digest\.ts/);
  assert.match(reconcileWorkflow, /Release digest:/);
  assert.match(reconcileWorkflow, /gh api "repos\/\$\{GITHUB_REPOSITORY\}\/releases\?per_page=100"/);
  assert.match(reconcileWorkflow, /gh release create/);
  assert.match(reconcileWorkflow, /--draft --prerelease/);
  assert.doesNotMatch(reconcileWorkflow, /ubuntu:lts|debian:stable|latest/);

  assert.match(publishWorkflow, /release:\n\s+types:\n\s+- published/);
  assert.match(publishWorkflow, /startsWith\(github\.event\.release\.tag_name, 'image\/'\)/);
  assert.match(publishWorkflow, /gh release download/);
  assert.match(publishWorkflow, /npm publish/);
  assert.match(publishWorkflow, /id-token: write/);
});
