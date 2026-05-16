import test from "node:test";
import assert from "node:assert/strict";
import { platform } from "node:os";
import { inspectSandboxArtifact } from "../../../src/index.ts";
import { writeEvidence } from "../support/evidence.ts";

test("host artifact is statically linked and macOS HVF entitlement is present when required", async () => {
  const artifact = await inspectSandboxArtifact({
    expectedStatic: true,
    forbiddenDynamicLibraries: ["libkrun", "libkrunfw"],
    macosEntitlements: platform() === "darwin"
      ? ["com.apple.security.hypervisor"]
      : [],
  });

  assert.equal(artifact.staticLinkage.ok, true);
  assert.equal(artifact.dynamicLibraries.some((lib) => /libkrun|libkrunfw/.test(lib)), false);

  if (platform() === "darwin") {
    assert.equal(artifact.codesign.valid, true);
    assert.equal(artifact.codesign.entitlements["com.apple.security.hypervisor"], true);
  }

  await writeEvidence("linkage.json", artifact);
});
