import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("root package declares public release metadata and platform optional dependencies", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
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
  assert.equal(packageJson.napi, undefined);
});

test("release packaging aligns generated platform dependency versions", async () => {
  const prepareScript = await readFile(
    new URL("../../scripts/prepare-npm-packages.ts", import.meta.url),
    "utf8",
  );

  assert.match(prepareScript, /platformPackages\.map\(\(pkg\) => \[pkg\.name, packageJson\.version\]\)/);
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
  assert.match(workflow, /dist\/rootfs\/alpine-3\.23\.erofs/);
  assert.match(workflow, /dist\/rootfs\/alpine-3\.23\.ext4/);
  assert.doesNotMatch(workflow, /alpine-3\.20/);
  assert.match(workflow, /prepare-npm-packages\.ts --platform --current/);
  assert.match(workflow, /Publish platform packages/);
  assert.match(workflow, /Publish root package/);
  assert.match(workflow, /require\('\.\/package\.json'\)\.version/);
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
    const buildRootfs = script.indexOf("node --run build:rootfs:erofs");
    const buildWritableRootfs = script.indexOf("node --run build:rootfs:ext4");
    const packageCurrentPlatform = script.indexOf("prepare-npm-packages.ts --platform --current");

    assert.notEqual(buildRootfs, -1, `${scriptName} should build the rootfs image`);
    assert.notEqual(buildWritableRootfs, -1, `${scriptName} should build the writable rootfs image`);
    assert.notEqual(packageCurrentPlatform, -1, `${scriptName} should package the current platform`);
    assert.ok(
      buildRootfs < packageCurrentPlatform,
      `${scriptName} should build the rootfs image before packaging the platform package`,
    );
    assert.ok(
      buildWritableRootfs < packageCurrentPlatform,
      `${scriptName} should build the writable rootfs image before packaging the platform package`,
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
    "openssh-client",
    "poppler-utils",
    "ripgrep",
    "tar",
    "unzip",
    "xz",
    "zip",
  ]) {
    assert.match(buildRootfsScript, new RegExp(`"${packageName}"`));
  }
});

test("rootfs EROFS builder uses compressed images", async () => {
  const buildErofsScript = await readFile(
    new URL("../../scripts/build-rootfs-erofs.ts", import.meta.url),
    "utf8",
  );
  const x86KernelConfig = await readFile(
    new URL("../../deps/libkrunfw/config-libkrunfw_x86_64", import.meta.url),
    "utf8",
  );
  const armKernelConfig = await readFile(
    new URL("../../deps/libkrunfw/config-libkrunfw_aarch64", import.meta.url),
    "utf8",
  );

  assert.match(buildErofsScript, /SANDBOX_EROFS_BUILDER_IMAGE \?\? "alpine:3\.23"/);
  assert.match(buildErofsScript, /SANDBOX_EROFS_COMPRESSION \?\? "lz4hc,level=12"/);
  assert.match(buildErofsScript, /SANDBOX_EROFS_CLUSTER_SIZE \?\? "1048576"/);
  assert.match(buildErofsScript, /SANDBOX_EROFS_EXTENDED_OPTIONS \?\? "fragments"/);
  assert.match(buildErofsScript, /--quiet/);
  assert.match(buildErofsScript, /-z/);
  assert.match(buildErofsScript, /-E/);
  assert.match(x86KernelConfig, /^CONFIG_EROFS_FS_ZIP=y$/m);
  assert.match(armKernelConfig, /^CONFIG_EROFS_FS_ZIP=y$/m);
});
