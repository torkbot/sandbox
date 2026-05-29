import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("release package manifest is the checked-in publish source", async () => {
  const releasePackageJson = JSON.parse(
    await readFile(new URL("../../release.package.json", import.meta.url), "utf8"),
  ) as {
    name?: string;
    version?: string;
    private?: boolean;
    publishConfig?: { access?: string };
    bin?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    dependencies?: Record<string, string>;
  };

  assert.equal(releasePackageJson.name, "@torkbot/sandbox");
  assert.equal(releasePackageJson.version, undefined);
  assert.equal(releasePackageJson.private, false);
  assert.equal(releasePackageJson.publishConfig?.access, "public");
  assert.deepEqual(releasePackageJson.bin, {
    sandbox: "./dist/cli.js",
  });
  assert.equal(releasePackageJson.dependencies, undefined);
  assert.equal(releasePackageJson.optionalDependencies, undefined);
});

test("root package declares public release metadata and platform optional dependencies", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../dist/npm/sandbox/package.json", import.meta.url), "utf8"),
  ) as {
    private?: boolean;
    publishConfig?: { access?: string };
    bin?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    napi?: unknown;
    version?: string;
  };

  assert.equal(packageJson.private, false);
  assert.equal(packageJson.publishConfig?.access, "public");
  assert.deepEqual(packageJson.bin, {
    sandbox: "./dist/cli.js",
  });
  assert.deepEqual(Object.keys(packageJson.optionalDependencies ?? {}).sort(), [
    "@torkbot/sandbox-darwin-arm64",
    "@torkbot/sandbox-linux-x64-gnu",
  ]);
  assert.deepEqual(packageJson.optionalDependencies, {
    "@torkbot/sandbox-darwin-arm64": packageJson.version,
    "@torkbot/sandbox-linux-x64-gnu": packageJson.version,
  });
  assert.equal(packageJson.napi, undefined);
});

test("development package does not pin generated platform packages", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  ) as {
    private?: boolean;
    version?: string;
    publishConfig?: { access?: string };
    exports?: Record<string, unknown>;
    files?: readonly string[];
    optionalDependencies?: Record<string, string>;
  };

  assert.equal(packageJson.private, true);
  assert.equal(packageJson.version, "0.0.0-dev");
  assert.equal(packageJson.publishConfig, undefined);
  assert.equal(packageJson.exports, undefined);
  assert.equal(packageJson.files, undefined);
  assert.equal(packageJson.optionalDependencies, undefined);
});

test("release packaging derives platform dependency versions from the supplied release version", async () => {
  const prepareScript = await readFile(
    new URL("../../scripts/prepare-npm-packages.ts", import.meta.url),
    "utf8",
  );

  assert.match(prepareScript, /release\.package\.json/);
  assert.match(prepareScript, /platformPackages\.map\(\(pkg\) => \[pkg\.name, releaseVersion\]\)/);
  assert.match(prepareScript, /parseReleaseVersion/);
});

test("release workflow builds platform packages before publishing the root package", async () => {
  const workflow = await readFile(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );

  assert.match(workflow, /npm run build:host/);
  assert.doesNotMatch(workflow, /build:native/);
  assert.match(workflow, /Build kernel artifact/);
  assert.match(workflow, /Build rootfs artifact/);
  assert.match(workflow, /SANDBOX_KERNEL_ARCH/);
  assert.match(workflow, /Download kernel artifact/);
  assert.match(workflow, /Download rootfs artifact/);
  assert.match(workflow, /dist\/rootfs\/alpine-3\.23\.qcow2/);
  assert.doesNotMatch(workflow, /dist\/rootfs\/alpine-3\.23\.erofs/);
  assert.doesNotMatch(workflow, /dist\/rootfs\/alpine-3\.23\.ext4/);
  assert.doesNotMatch(workflow, /alpine-3\.20/);
  assert.match(workflow, /prepare-npm-packages\.ts --version "\$SANDBOX_RELEASE_VERSION" --platform --current/);
  assert.match(workflow, /Publish platform packages/);
  assert.match(workflow, /Publish root package/);
  assert.match(workflow, /SANDBOX_RELEASE_VERSION/);
  assert.doesNotMatch(workflow, /require\('\.\/package\.json'\)\.version/);
  assert.doesNotMatch(workflow, /0\.1\.0\.tgz/);
  assert.match(workflow, /id-token: write/);

  const publishJob = workflow.slice(workflow.indexOf("  publish:"));
  assert.match(publishJob, /uses: actions\/checkout@v4/);

  const rootfsJob = workflow.slice(workflow.indexOf("  build-rootfs:"), workflow.lastIndexOf("  publish:"));
  assert.match(rootfsJob, /submodules: recursive/);
});

test("local release scripts build current rootfs before packaging platform packages", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { scripts?: Record<string, string> };

  for (const scriptName of ["release:prepare", "release:pack"]) {
    const script = packageJson.scripts?.[scriptName] ?? "";
    const buildRootfs = script.indexOf("node --run build:rootfs:qcow2");
    const packageCurrentPlatform = script.indexOf("prepare-npm-packages.ts --version ${SANDBOX_RELEASE_VERSION:-0.0.0-dev} --platform --current");

    assert.notEqual(buildRootfs, -1, `${scriptName} should build the rootfs image`);
    assert.notEqual(packageCurrentPlatform, -1, `${scriptName} should package the current platform`);
    assert.ok(
      buildRootfs < packageCurrentPlatform,
      `${scriptName} should build the rootfs image before packaging the platform package`,
    );
  }
});

test("default rootfs includes agent utility packages", async () => {
  const buildRootfsScript = await readFile(
    new URL("../../scripts/build-rootfs.ts", import.meta.url),
    "utf8",
  );

  for (const packageName of [
    "bash",
    "coreutils",
    "curl",
    "exiftool",
    "ffmpeg",
    "file",
    "findutils",
    "git",
    "imagemagick",
    "jq",
    "less",
    "nodejs-current",
    "npm",
    "openssh-client",
    "poppler-utils",
    "py3-pip",
    "python3",
    "ripgrep",
    "tar",
    "unzip",
    "xz",
    "zip",
  ]) {
    assert.match(buildRootfsScript, new RegExp(`"${packageName}"`));
  }
  assert.match(buildRootfsScript, /githubCliVersion = "2\.83\.0"/);
  assert.match(buildRootfsScript, /gh_\$\{githubCliVersion\}_linux_/);
});

test("rootfs QCOW2 builder uses compressed images", async () => {
  const buildQcow2Script = await readFile(
    new URL("../../scripts/build-rootfs-qcow2.ts", import.meta.url),
    "utf8",
  );

  assert.match(buildQcow2Script, /SANDBOX_QCOW2_BUILDER_IMAGE \?\? "debian:bookworm"/);
  assert.match(buildQcow2Script, /decimalEnv\("SANDBOX_QCOW2_CLUSTER_SIZE", "32768"\)/);
  assert.match(buildQcow2Script, /decimalEnv\("SANDBOX_ROOTFS_FREE_SPACE_KIB", "131072"\)/);
  assert.match(buildQcow2Script, /qemu-img/);
  assert.match(buildQcow2Script, /-O qcow2/);
  assert.match(buildQcow2Script, /-c/);
  assert.match(buildQcow2Script, /compat=1\.1,cluster_size=/);
});
