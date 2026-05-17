import test from "node:test";
import assert from "node:assert/strict";
import { platform } from "node:os";
import { inspectNativeArtifact } from "../support/artifact.ts";
import { writeEvidence } from "../support/evidence.ts";

test("host artifact has no libkrun/libkrunfw dynamic dependency and is signed on macOS", async () => {
  const artifact = await inspectNativeArtifact({
    forbiddenDynamicLibraries: ["libkrun", "libkrunfw"],
    macosEntitlements: platform() === "darwin"
      ? ["com.apple.security.hypervisor"]
      : [],
  });

  assert.equal(artifact.staticLinkage.ok, true);
  assert.equal(artifact.dynamicLibraries.some((lib) => /libkrun|libkrunfw/.test(lib)), false);

  if (platform() === "darwin") {
    assert.equal(artifact.codesign.valid, true);
  }

  await writeEvidence("linkage.json", artifact);
});
