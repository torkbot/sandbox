import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("a VM can run with a writable root overlay and publish a new EROFS rootfs", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "rootfs-shaping",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    rootfsOverlay: {
      mode: "writable",
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const install = await execGuestShell(vm, {
    id: "shape-rootfs",
    script: `
      set -eu
      mkdir -p /opt/sandbox
      printf shaped > /opt/sandbox/marker.txt
      test "$(cat /opt/sandbox/marker.txt)" = "shaped"
    `,
  });
  assert.equal(install.exitCode, 0);

  const snapshot = await vm.rootfs.snapshot({
    format: "erofs",
  });

  assert.equal(snapshot.format, "erofs");
  assert.match(snapshot.digest, /^sha256:/);
  assert.ok(snapshot.bytes instanceof Uint8Array);

  await writeEvidence("rootfs-shaping.json", {
    snapshot: {
      format: snapshot.format,
      digest: snapshot.digest,
    },
  });
});

test("immutable root remains the default when overlay mode is absent", () => {
  assert.fail("runtime rootfs writes must fail unless writable overlay mode is explicitly requested");
});

test("writable root overlay captures guest mutations", () => {
  assert.fail("writable root overlay must capture guest mutations without changing the supplied base rootfs");
});

test("rootfs snapshot returns bytes and digest without forcing a host output path", () => {
  assert.fail("rootfs snapshot must return an EROFS byte blob and digest without requiring an output path");
});

test("a VM can boot from a produced rootfs snapshot", () => {
  assert.fail("a rootfs snapshot produced by one VM must boot a second VM as a read-only rootfs");
});
