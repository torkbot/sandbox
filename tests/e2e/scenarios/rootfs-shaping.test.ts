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

test("a VM can run with a writable root overlay and publish a new EROFS rootfs", async (t) => {
  const vm = await spawnSandbox({
    name: "rootfs-shaping",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("test-fixtures/rootfs/base.erofs", {
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
