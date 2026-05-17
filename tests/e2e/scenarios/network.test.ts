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

test("HTTP networking transparently intercepts guest TCP over explicit virtio-net", async (t) => {
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
          return { action: "deny", reason: "sandbox explicit network" };
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
      curl --max-time 3 --connect-timeout 2 --silent http://203.0.113.10/
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

test("caller protected ranges extend the default network deny set", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let policyCalls = 0;
  const vm = await spawnSandbox({
    name: "custom-protected-network",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        protectedRanges: ["203.0.113.0/24"],
        async policy() {
          policyCalls += 1;
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
    id: "custom-protected-network",
    script: "curl --max-time 3 --connect-timeout 2 --silent --output /dev/null --write-out '%{http_code}' http://203.0.113.10/",
  });

  assert.equal(result.stdout, "403");
  assert.equal(policyCalls, 0);
});

test("public destinations reach JavaScript policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const policyUrls: string[] = [];
  const vm = await spawnSandbox({
    name: "public-network-policy",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        async policy(request) {
          policyUrls.push(request.url);
          return { action: "deny", reason: "public policy observed" };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "public-network-policy",
    script: "curl --max-time 3 --connect-timeout 2 --silent http://203.0.113.10/public",
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /public policy observed/);
  assert.deepEqual(policyUrls, ["http://203.0.113.10/public"]);
});

test("DNS-dependent traffic is observable and cannot bypass policy", () => {
  assert.fail("hostname-based guest traffic must be observable and unable to bypass HTTP policy");
});

test("DNS resolution to a protected IP is still blocked before policy", () => {
  assert.fail("hostnames resolving to protected IPs must be blocked before JavaScript policy");
});

test("IPv6 behavior is explicit", () => {
  assert.fail("IPv6 traffic must be either implemented or rejected with deterministic behavior");
});

test("UDP and non-HTTP traffic cannot silently bypass policy", () => {
  assert.fail("UDP and non-HTTP traffic must have documented enforcement behavior and cannot silently bypass policy");
});
