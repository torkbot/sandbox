import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
} from "../../../src/index.ts";
import { collectAsync } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("boots sandbox-init as PID 1", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "direct-rust-init",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "direct-rust-init",
    script: "cat /proc/1/comm; printf '\\n'; tr '\\0' ' ' < /proc/1/cmdline",
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /^sandbox-init\n/);
});
