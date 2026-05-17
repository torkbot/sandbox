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

test("HTTP networking uses an explicit virtio-net device, not TSI", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "explicit-network",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        async policy() {
          return { action: "allow" };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "explicit-network-check",
    script: `
      set -eu
      test -d /sys/class/net/eth0
      ip addr show dev eth0
      ip route show default
      curl --fail --silent http://10.0.2.1:8080/
    `,
  });

  assert.equal(
    result.exitCode,
    0,
    `guest network checks failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.match(result.stdout, /10\.0\.2\.2\/24/);
  assert.match(result.stdout, /default via 10\.0\.2\.1/);
  assert.match(result.stdout, /sandbox explicit network/);
});
