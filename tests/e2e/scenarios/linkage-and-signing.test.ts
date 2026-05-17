import test from "node:test";
import assert from "node:assert/strict";
import { platform } from "node:os";
import { existsSync } from "node:fs";
import { basename } from "node:path";
import { hostBinaryPath } from "../../../src/host-process.ts";
import { projectInit, projectKernel } from "../../../src/index.ts";
import { inspectNativeArtifact } from "../support/artifact.ts";
import { writeEvidence } from "../support/evidence.ts";
import { requireHostArtifact } from "../support/capabilities.ts";

test("VM host artifact has no libkrun/libkrunfw dynamic dependency and is signed on macOS", async (t) => {
  if (!requireHostArtifact(t)) {
    return;
  }

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
    assert.equal(artifact.codesign.hostExecutableHasRequiredEntitlements, true);
  }

  await writeEvidence("linkage.json", artifact);
});

test("unsigned Node is acceptable because VM launch goes through sandbox-host", (t) => {
  if (!requireHostArtifact(t)) {
    return;
  }

  const hostPath = hostBinaryPath();
  assert.equal(basename(hostPath), "sandbox-host");
  assert.notEqual(hostPath, process.execPath);
  assert.equal(existsSync(hostPath), true);
});

test("project kernel and init artifacts are selected explicitly", () => {
  assert.deepEqual(projectKernel(), {
    kind: "project-kernel",
  });
  assert.deepEqual(projectKernel({ format: "image-zstd" }), {
    kind: "project-kernel",
    format: "image-zstd",
  });
  assert.deepEqual(projectInit(), {
    kind: "project-init",
    crate: "sandbox-init",
  });
});

test("Linux host CI runs the core VM/control/network contract", () => {
  assert.fail("GitHub Actions must run the core VM/control/network e2e subset on a Linux host with KVM");
});

test("rootfs fixture builds reproducibly", () => {
  assert.fail("rootfs fixture builds must be reproducible and produce stable digest metadata");
});

test("kernel fixture builds reproducibly", () => {
  assert.fail("kernel fixture builds must be reproducible and produce stable digest metadata");
});
