import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  type SandboxControlEvent,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuest } from "../support/guest-control.ts";

function isInitReady(event: SandboxControlEvent): event is Extract<SandboxControlEvent, { type: "init.ready" }> {
  return event.type === "init.ready";
}

test("Node can boot a sandbox VM and exchange control messages", async (t) => {
  const vm = await spawnSandbox({
    name: "boot-smoke",
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  const ready = await collectAsync(vm.control.incoming, isInitReady);
  assert.equal(ready.guest.root.readonly, true);
  assert.equal(ready.guest.init.name, "sandbox-init");

  const result = await execGuest(vm, {
    id: "uname",
    argv: ["/bin/uname", "-a"],
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /Linux/);

  await writeEvidence("control.json", {
    ready,
    result,
  });
});
