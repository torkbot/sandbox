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

test("release artifact downloader waits for the exact main build", async () => {
  const downloadScript = await readFile(
    new URL("../../scripts/download-release-artifacts.ts", import.meta.url),
    "utf8",
  );

  assert.match(downloadScript, /waitForSuccessfulRun/);
  assert.match(downloadScript, /--branch/);
  assert.match(downloadScript, /"main"/);
  assert.match(downloadScript, /--commit/);
  assert.match(downloadScript, /targetSha/);
  assert.match(downloadScript, /timed out waiting for successful main/);
  assert.match(downloadScript, /main .* run failed/);
});

test("release workflow packages main-built platform artifacts before publishing", async () => {
  const workflow = await readFile(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );
  const ciWorkflow = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );

  assert.match(ciWorkflow, /release-platform-artifacts:/);
  assert.match(ciWorkflow, /sign-notarize-macos-release-artifact:/);
  assert.match(ciWorkflow, /environment: macos-release-signing/);
  assert.match(ciWorkflow, /unsigned-release-platform-darwin-arm64/);
  assert.match(ciWorkflow, /xcrun notarytool submit/);
  assert.match(ciWorkflow, /--macos-notarization-status "\$notarization_status"/);
  assert.match(ciWorkflow, /npm run build:host/);
  assert.match(ciWorkflow, /release-artifact-manifest\.ts write/);
  assert.match(ciWorkflow, /release-platform-\$\{\{ matrix\.platform \}\}/);
  assert.match(workflow, /download-release-artifacts\.ts --target-sha/);
  assert.match(workflow, /release-artifact-manifest\.ts verify/);
  assert.match(workflow, /needs\.verify\.outputs\.target-sha/);
  assert.match(workflow, /chmod 755 target\/release\/sandbox-host/);
  assert.doesNotMatch(workflow, /npm run build:host/);
  assert.doesNotMatch(workflow, /build:native/);
  assert.doesNotMatch(workflow, /Build kernel artifact/);
  assert.doesNotMatch(workflow, /Build rootfs artifact/);
  assert.doesNotMatch(workflow, /SANDBOX_KERNEL_ARCH/);
  assert.doesNotMatch(workflow, /Download kernel artifact/);
  assert.doesNotMatch(workflow, /Download rootfs artifact/);
  assert.doesNotMatch(workflow, /dist\/rootfs\/alpine-3\.23\.qcow2/);
  assert.doesNotMatch(workflow, /dist\/rootfs\/alpine-3\.23-agent\.environment-facts\.json/);
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
  assert.match(publishJob, /uses: actions\/checkout@[0-9a-f]{40}/);
  assert.doesNotMatch(publishJob, /uses: actions\/checkout@v\d+/);

  const platformJob = workflow.slice(workflow.indexOf("  build-platform:"), workflow.lastIndexOf("  build-root:"));
  assert.match(platformJob, /submodules: recursive/);
});

test("local release scripts package platform artifacts without rebuilding rootfs images", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { scripts?: Record<string, string> };

  for (const scriptName of ["release:prepare", "release:pack"]) {
    const script = packageJson.scripts?.[scriptName] ?? "";
    const packageCurrentPlatform = script.indexOf("prepare-npm-packages.ts --version ${SANDBOX_RELEASE_VERSION:-0.0.0-dev} --platform --current");

    assert.notEqual(packageCurrentPlatform, -1, `${scriptName} should package the current platform`);
    assert.doesNotMatch(script, /build:rootfs/);
  }
});

test("local build scripts rebuild kernel and initrd before embedding host artifact", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  ) as { scripts?: Record<string, string> };

  const buildScript = packageJson.scripts?.build ?? "";
  const buildKernelInBuild = buildScript.indexOf("build:kernel");
  const buildInitInBuild = buildScript.indexOf("build:init");
  const buildInitrdInBuild = buildScript.indexOf("build:initrd");
  const buildHostInBuild = buildScript.indexOf("build:host");

  assert.notEqual(buildKernelInBuild, -1, "build should build the kernel artifact");
  assert.notEqual(buildInitInBuild, -1, "build should build the init binary");
  assert.notEqual(buildInitrdInBuild, -1, "build should build the initrd artifact");
  assert.notEqual(buildHostInBuild, -1, "build should build the host artifact");
  assert.ok(buildKernelInBuild < buildHostInBuild, "build should build the kernel artifact before the host embeds it");
  assert.ok(buildInitInBuild < buildInitrdInBuild, "build should build the init binary before the initrd");
  assert.ok(buildInitrdInBuild < buildHostInBuild, "build should build the initrd before the host embeds it");

  for (const scriptName of ["release:prepare", "release:pack"]) {
    const script = packageJson.scripts?.[scriptName] ?? "";
    const build = script.indexOf("node --run build");
    const packageCurrentPlatform = script.indexOf("prepare-npm-packages.ts --version ${SANDBOX_RELEASE_VERSION:-0.0.0-dev} --platform --current");

    assert.notEqual(build, -1, `${scriptName} should run the full build`);
    assert.notEqual(packageCurrentPlatform, -1, `${scriptName} should package the current platform`);
    assert.ok(
      build < packageCurrentPlatform,
      `${scriptName} should run the full build before packaging the current platform`,
    );
  }
});

test("host build validates kernel artifact metadata before Cargo embeds it", async () => {
  const buildHost = await readFile(new URL("../../scripts/build-host.ts", import.meta.url), "utf8");
  const buildKernel = await readFile(new URL("../../scripts/build-kernel.ts", import.meta.url), "utf8");
  const fixtureCacheKeys = await readFile(new URL("../../scripts/fixture-cache-keys.ts", import.meta.url), "utf8");

  assert.match(buildKernel, /kernelMetadataFile/);
  assert.match(buildKernel, /expectedKernelArtifactMetadata/);
  assert.match(buildKernel, /await rm\(resolve\(libkrunfwRoot, metadata\.kernelBundle\)/);
  assert.match(buildKernel, /await rm\(resolve\(libkrunfwRoot, metadata\.kernelVersion\)/);
  assert.match(buildKernel, /SANDBOX_KERNEL_JOBS/);
  assert.match(buildKernel, /make -j/);
  assert.match(buildHost, /readKernelArtifactMetadata/);
  assert.match(buildHost, /assertKernelArtifactMetadataMatches/);
  assert.match(buildHost, /expectedKernelArtifactMetadata/);
  assert.match(buildHost, /SANDBOX_INITRD_IMAGE/);
  assert.match(fixtureCacheKeys, /kernel-artifact-metadata\.ts/);
  assert.match(fixtureCacheKeys, /scripts\/build-initrd\.ts/);
});

test("rootfs cache key tracks generated environment facts inputs", async () => {
  const fixtureCacheKeys = await readFile(new URL("../../scripts/fixture-cache-keys.ts", import.meta.url), "utf8");

  assert.match(fixtureCacheKeys, /scripts\/build-rootfs\.ts/);
  assert.match(fixtureCacheKeys, /scripts\/build-rootfs-qcow2\.ts/);
  assert.match(fixtureCacheKeys, /src\/environment-facts\.ts/);
});

test("vendored kernel configs include Docker bridge iptables-nft support", async () => {
  for (const arch of ["aarch64", "x86_64"]) {
    const config = await readFile(
      new URL(`../../deps/libkrunfw/config-libkrunfw_${arch}`, import.meta.url),
      "utf8",
    );

    for (const option of [
      "CONFIG_NFT_COMPAT=y",
      "CONFIG_NETFILTER_XTABLES=y",
      "CONFIG_NETFILTER_XT_TARGET_MASQUERADE=y",
      "CONFIG_NETFILTER_XT_MATCH_ADDRTYPE=y",
      "CONFIG_NETFILTER_XT_MATCH_COMMENT=y",
      "CONFIG_NETFILTER_XT_MATCH_CONNTRACK=y",
    ]) {
      assert.match(config, new RegExp(`^${option}$`, "m"));
    }
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
  assert.match(buildRootfsScript, /const image = process\.env\.SANDBOX_ROOTFS_IMAGE \?\? "alpine:3\.23"/);
  assert.match(buildRootfsScript, /const rootfsName = "alpine:3\.23-agent"/);
  assert.match(buildRootfsScript, /const githubCliVersion = "2\.83\.0"/);
  assert.match(buildRootfsScript, /gh_\$\{githubCliVersion\}_linux_/);
  for (const mountPoint of ["dev", "proc", "run", "sys", "tmp"]) {
    assert.match(
      buildRootfsScript,
      new RegExp(`mkdir\\(resolve\\(outDir, "${mountPoint}"\\)`),
    );
  }
});

test("default rootfs facts are tied to rootfs build inputs", async () => {
  const buildRootfsScript = await readFile(
    new URL("../../scripts/build-rootfs.ts", import.meta.url),
    "utf8",
  );
  const buildQcow2Script = await readFile(
    new URL("../../scripts/build-rootfs-qcow2.ts", import.meta.url),
    "utf8",
  );
  const preparePackagesScript = await readFile(
    new URL("../../scripts/prepare-npm-packages.ts", import.meta.url),
    "utf8",
  );
  const ciWorkflow = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );

  assert.match(buildRootfsScript, /const rootfsEnvironmentFactsManifest: RootfsEnvironmentFactsManifest/);
  assert.match(buildRootfsScript, /configRootfsImageFact\(rootfsName\)/);
  assert.match(buildRootfsScript, /configCommandFact/);
  assert.match(buildQcow2Script, /rootfsEnvironmentFactsArtifactName/);
  assert.match(buildQcow2Script, /alpine-3\.23-agent\.environment-facts\.json/);
  assert.doesNotMatch(preparePackagesScript, /alpine-3\.23.*environment-facts\.json/);
  assert.doesNotMatch(ciWorkflow, /--file rootfs\/alpine-3\.23-agent\.environment-facts\.json/);
});

test("rootfs QCOW2 builder uses compressed images", async () => {
  const buildQcow2Script = await readFile(
    new URL("../../scripts/build-rootfs-qcow2.ts", import.meta.url),
    "utf8",
  );

  assert.match(buildQcow2Script, /SANDBOX_QCOW2_BUILDER_IMAGE \?\? "debian:12"/);
  assert.match(buildQcow2Script, /decimalEnv\("SANDBOX_QCOW2_CLUSTER_SIZE", "32768"\)/);
  assert.match(buildQcow2Script, /sizeEnvKiB\("SANDBOX_ROOTFS_VIRTUAL_SIZE", "8gb"\)/);
  assert.match(buildQcow2Script, /rootfs contents exceed virtual image size/);
  assert.match(buildQcow2Script, /qemu-img/);
  assert.match(buildQcow2Script, /-O qcow2/);
  assert.match(buildQcow2Script, /-c/);
  assert.match(buildQcow2Script, /compat=1\.1,cluster_size=/);
});
