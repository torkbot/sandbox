import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("root package declares public release metadata and platform optional dependencies", async () => {
  const packageJson = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  ) as {
    private?: boolean;
    version?: string;
    publishConfig?: { access?: string };
    bin?: Record<string, string>;
    optionalDependencies?: Record<string, string>;
    napi?: unknown;
  };

  assert.equal(packageJson.private, false);
  assert.equal(packageJson.version, "0.1.0");
  assert.equal(packageJson.publishConfig?.access, "public");
  assert.deepEqual(packageJson.bin, {
    sandbox: "./dist/cli.js",
  });
  assert.deepEqual(packageJson.optionalDependencies, {
    "@torkbot/sandbox-darwin-arm64": "0.1.0",
    "@torkbot/sandbox-linux-x64-gnu": "0.1.0",
  });
  assert.equal(packageJson.napi, undefined);
});

test("release workflow builds platform packages before publishing the root package", async () => {
  const workflow = await readFile(
    new URL("../../.github/workflows/release.yml", import.meta.url),
    "utf8",
  );

  assert.match(workflow, /npm run build:host/);
  assert.doesNotMatch(workflow, /build:native/);
  assert.match(workflow, /Build kernel artifact/);
  assert.match(workflow, /SANDBOX_KERNEL_ARCH/);
  assert.match(workflow, /Download kernel artifact/);
  assert.match(workflow, /prepare-npm-packages\.ts --platform --current/);
  assert.match(workflow, /Publish platform packages/);
  assert.match(workflow, /Publish root package/);
  assert.match(workflow, /require\('\.\/package\.json'\)\.version/);
  assert.doesNotMatch(workflow, /0\.1\.0\.tgz/);
  assert.match(workflow, /id-token: write/);

  const publishJob = workflow.slice(workflow.indexOf("  publish:"));
  assert.match(publishJob, /uses: actions\/checkout@v4/);
});
