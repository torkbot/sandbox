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
import {
  assertImageReleaseAssets,
  expectedImagePackageNames,
  imageReleaseMatchesSelection,
  imageReleaseNeedsPublish,
  parseImageReleaseTag,
} from "../../scripts/image-release-publish-matrix.ts";

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
    if (definition.id.endsWith("-agent")) {
      assert.match(dockerfile, /gh_2\.83\.0_linux_\$\{gh_arch\}\.tar\.gz/);
      assert.match(dockerfile, /\/usr\/local\/bin\/gh/);
    }
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
  const digestScript = await readFile(
    new URL("../../scripts/image-release-digest.ts", import.meta.url),
    "utf8",
  );
  const first = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      {
        architecture: "arm64",
        rootfsDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        factsDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      },
      {
        architecture: "x64",
        rootfsDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        factsDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
    ],
  });
  const second = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      {
        architecture: "x64",
        rootfsDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        factsDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
      {
        architecture: "arm64",
        rootfsDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        factsDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      },
    ],
  });
  const changedFacts = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      {
        architecture: "arm64",
        rootfsDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        factsDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
      },
      {
        architecture: "x64",
        rootfsDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        factsDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
    ],
  });

  assert.equal(first, second);
  assert.notEqual(first, changedFacts);
  assert.match(digestScript, /packageJson/);
  assert.match(digestScript, /prepare-image-npm-packages\.ts/);
});

test("image publish matrix selects ready unpublished image releases", async () => {
  const release = {
    tag_name: "image/alpine-3.23-slim/v0.1.0-image.20260624T002044Z.sha57c1eece389c",
    draft: false,
    prerelease: true,
    published_at: "2026-06-24T00:30:05Z",
    assets: [
      {
        name: "torkbot-sandbox-image-alpine-3.23-slim-0.1.0-image.20260624T002044Z.sha57c1eece389c.tgz",
        state: "uploaded",
      },
      {
        name: "torkbot-sandbox-image-alpine-3.23-slim-arm64-0.1.0-image.20260624T002044Z.sha57c1eece389c.tgz",
        state: "uploaded",
      },
      {
        name: "torkbot-sandbox-image-alpine-3.23-slim-x64-0.1.0-image.20260624T002044Z.sha57c1eece389c.tgz",
        state: "uploaded",
      },
    ],
  };

  assert.deepEqual(parseImageReleaseTag(release.tag_name), {
    image: "alpine-3.23-slim",
    version: "0.1.0-image.20260624T002044Z.sha57c1eece389c",
  });
  assert.deepEqual(expectedImagePackageNames({ image: "alpine-3.23-slim" }), [
    "@torkbot/sandbox-image-alpine-3.23-slim",
    "@torkbot/sandbox-image-alpine-3.23-slim-arm64",
    "@torkbot/sandbox-image-alpine-3.23-slim-x64",
  ]);
  assert.doesNotThrow(() => assertImageReleaseAssets(release));
  assert.equal(imageReleaseMatchesSelection(release, "all"), true);
  assert.equal(imageReleaseMatchesSelection(release, "alpine-3.23-slim"), true);
  assert.equal(imageReleaseMatchesSelection(release, "debian-13-slim"), false);
  assert.equal(imageReleaseMatchesSelection({ ...release, draft: true }, "all"), false);
  assert.equal(imageReleaseMatchesSelection({ ...release, published_at: null }, "all"), false);

  const missingOne = async (url: string): Promise<Response> => {
    return new Response(null, { status: url.includes("-x64/") ? 404 : 200 });
  };
  const allPublished = async (): Promise<Response> => new Response(null, { status: 200 });

  assert.equal(await imageReleaseNeedsPublish({ release, fetch: missingOne as typeof fetch }), true);
  assert.equal(await imageReleaseNeedsPublish({ release, fetch: allPublished as typeof fetch }), false);
});

test("image package preparation emits a root package and architecture artifact package", async () => {
  const tempRoot = await mkdtemp(join(tmpdir(), "sandbox-image-package-"));
  const rootfsPath = join(tempRoot, "rootfs.qcow2");
  const factsPath = join(tempRoot, "environment-facts.json");
  const outDir = join(tempRoot, "npm");

  await writeFile(rootfsPath, "rootfs bytes\n");
  const factsJson = `${JSON.stringify({
    schemaVersion: 1,
    rootfs: "alpine:3.23-slim",
    facts: [
      { source: "config", topic: "rootfs-image", relation: "is", value: "alpine:3.23-slim" },
    ],
  }, null, 2)}\n`;
  await writeFile(factsPath, factsJson);

  const rootfsDigest = `sha256:${createHash("sha256").update("rootfs bytes\n").digest("hex")}` as const;
  const factsDigest = `sha256:${createHash("sha256").update(factsJson).digest("hex")}` as const;
  const releaseDigest = await imageReleaseDigest({
    imageId: "alpine-3.23-slim",
    artifacts: [
      { architecture: "arm64", rootfsDigest, factsDigest },
      {
        architecture: "x64",
        rootfsDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        factsDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      },
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
  assert.equal(archPackage.os, undefined);
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
  const releaseWorkflow = await readFile(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );

  assert.match(reconcileWorkflow, /schedule:/);
  assert.match(reconcileWorkflow, /workflow_dispatch:/);
  assert.match(reconcileWorkflow, /Verify image release source/);
  assert.match(reconcileWorkflow, /\$GITHUB_REF" != "refs\/heads\/main"/);
  assert.match(reconcileWorkflow, /image release source must be current origin\/main/);
  assert.match(reconcileWorkflow, /image:\n\s+description: Image id to reconcile, or all\n\s+type: string\n\s+required: true/);
  assert.match(reconcileWorkflow, /image-manifest\.ts validate/);
  assert.match(reconcileWorkflow, /image-release-digest\.ts/);
  assert.match(reconcileWorkflow, /environment-facts\.json/);
  assert.match(reconcileWorkflow, /--artifact "x64=\$\{x64_digest\},\$\{x64_facts_digest\}"/);
  assert.match(reconcileWorkflow, /--artifact "arm64=\$\{arm64_digest\},\$\{arm64_facts_digest\}"/);
  assert.doesNotMatch(reconcileWorkflow, /path: dist\/image-release\/\$\{\{ matrix\.image \}\}\/\$\{\{ matrix\.architecture \}\}\n/);
  assert.match(reconcileWorkflow, /Release digest:/);
  assert.match(reconcileWorkflow, /gh api --paginate "repos\/\$\{GITHUB_REPOSITORY\}\/releases\?per_page=100"/);
  assert.match(reconcileWorkflow, /gh release create/);
  assert.match(reconcileWorkflow, /--draft --prerelease/);
  assert.doesNotMatch(reconcileWorkflow, /ubuntu:lts|debian:stable|latest/);

  assert.match(publishWorkflow, /release:\n\s+types:\n\s+- published/);
  assert.match(publishWorkflow, /workflow_dispatch:/);
  assert.match(publishWorkflow, /image:\n\s+description: Image id to publish, or all\n\s+type: string\n\s+required: true\n\s+default: all/);
  assert.match(publishWorkflow, /Select image releases to publish/);
  assert.match(publishWorkflow, /image-release-publish-matrix\.ts --image "\$IMAGE_RELEASE_IMAGE"/);
  assert.match(publishWorkflow, /image-release-publish-matrix\.ts --tag "\$IMAGE_RELEASE_TAG"/);
  assert.match(publishWorkflow, /matrix: \$\{\{ fromJson\(needs\.select\.outputs\.matrix\) \}\}/);
  assert.match(publishWorkflow, /IMAGE_RELEASE_TAG: \$\{\{ matrix\.tag \}\}/);
  assert.match(publishWorkflow, /gh release download/);
  assert.match(publishWorkflow, /Validate release package assets/);
  assert.match(publishWorkflow, /expected exactly one root, arm64, and x64 image package/);
  assert.match(publishWorkflow, /tar -xOf "\$tarball" package\/package\.json/);
  assert.match(publishWorkflow, /npm view "\$package_spec" version/);
  assert.match(publishWorkflow, /already published %s/);
  assert.match(publishWorkflow, /--tag image --provenance --access public/);
  assert.match(publishWorkflow, /npm publish/);
  assert.match(publishWorkflow, /id-token: write/);

  assert.match(releaseWorkflow, /!startsWith\(github\.event\.release\.tag_name, 'image\/'\)/);
});

test("image rootfs builder preserves agent CLI facts and strips Docker markers", async () => {
  const buildImageRootfsScript = await readFile(
    new URL("../../scripts/build-image-rootfs.ts", import.meta.url),
    "utf8",
  );

  assert.match(buildImageRootfsScript, /"gh"/);
  assert.match(buildImageRootfsScript, /configCommandFact/);
  assert.match(buildImageRootfsScript, /resolve\(outDir, "\.dockerenv"\)/);
  assert.match(buildImageRootfsScript, /resolve\(outDir, "etc\/hostname"\)/);
  assert.match(buildImageRootfsScript, /127\.0\.0\.1 localhost sandbox/);
});
