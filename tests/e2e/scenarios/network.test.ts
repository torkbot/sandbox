import test from "node:test";
import assert from "node:assert/strict";
import {
  acceptPublicInternet,
  acceptTcp,
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
      outbound: {
        policy: "deny",
        rules: [acceptTcp({ cidr: "203.0.113.10/32", ports: [80] })],
      },
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

test("outbound default deny blocks destinations before JavaScript policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let policyCalls = 0;
  const vm = await spawnSandbox({
    name: "outbound-default-deny",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [],
      },
      http: {
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
    id: "outbound-default-deny",
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
      outbound: {
        policy: "deny",
        rules: [acceptTcp({ cidr: "203.0.113.10/32", ports: [80] })],
      },
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

test("outbound-only policy creates the guest network device", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "outbound-only-network",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [acceptTcp({ cidr: "203.0.113.10/32", ports: [80] })],
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "outbound-only-network",
    script: `
      set -eu
      test -d /sys/class/net/eth0
      ip route show default
      curl --max-time 3 --connect-timeout 2 --silent http://203.0.113.10/
    `,
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /default via 10\.0\.2\.1/);
  assert.match(result.stdout, /sandbox explicit network/);
});

test("outbound-only default deny blocks HTTP without JavaScript policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "outbound-only-default-deny",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [],
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "outbound-only-default-deny",
    script: "curl --max-time 3 --connect-timeout 2 --silent --output /dev/null --write-out '%{http_code}' http://203.0.113.10/",
  });

  assert.equal(result.stdout, "403");
});

test("DNS-dependent traffic is observable and cannot bypass policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const policyUrls: string[] = [];
  const vm = await spawnSandbox({
    name: "dns-policy",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [acceptPublicInternet({ ports: [80] })],
      },
      http: {
        async policy(request) {
          policyUrls.push(`${request.destinationIp} ${request.url}`);
          return { action: "deny", reason: "dns policy observed" };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "dns-policy",
    script: "curl --max-time 4 --connect-timeout 2 --silent http://public.sandbox.test/hostname",
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /dns policy observed/);
  assert.equal(policyUrls.length, 1);
  assert.equal(policyUrls[0], "203.0.113.10 http://public.sandbox.test/hostname");
});

test("DNS resolution to a denied IP is blocked before policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let policyCalls = 0;
  const vm = await spawnSandbox({
    name: "dns-denied",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [acceptPublicInternet({ ports: [80] })],
      },
      http: {
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
    id: "dns-denied",
    script: "curl --max-time 4 --connect-timeout 2 --silent --output /dev/null --write-out '%{http_code}' http://protected.sandbox.test/",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "403");
  assert.equal(policyCalls, 0);
});

test("public internet allow rules do not allow IPv6 loopback resolution", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let policyCalls = 0;
  const vm = await spawnSandbox({
    name: "public-internet-ipv6-loopback",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [acceptPublicInternet({ ports: [80] })],
      },
      http: {
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
    id: "public-internet-ipv6-loopback",
    script: "curl --max-time 4 --connect-timeout 2 --silent --output /dev/null --write-out '%{http_code}' --connect-to localhost:80:203.0.113.10:80 http://localhost/",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "403");
  assert.equal(policyCalls, 0);
});

test("IPv6 behavior is explicit", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let policyCalls = 0;
  const vm = await spawnSandbox({
    name: "ipv6-explicit",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [],
      },
      http: {
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
    id: "ipv6-explicit",
    script: "curl --max-time 3 --connect-timeout 1 --silent --show-error --output /dev/null --write-out '%{exitcode}' 'http://[2001:db8::1]/'",
  });

  assert.notEqual(result.stdout, "0");
  assert.equal(policyCalls, 0);
});

test("UDP and non-HTTP traffic cannot silently bypass policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  let policyCalls = 0;
  const vm = await spawnSandbox({
    name: "udp-no-bypass",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [],
      },
      http: {
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
    id: "udp-no-bypass",
    script: `
      set +e
      if command -v nc >/dev/null 2>&1; then
        printf probe | nc -u -w 1 203.0.113.10 9 >/tmp/udp.out 2>/tmp/udp.err
        status=$?
      else
        status=127
      fi
      printf '%s\\n' "$status"
      cat /tmp/udp.out 2>/dev/null
      cat /tmp/udp.err 2>/dev/null
    `,
  });

  assert.match(result.stdout, /^(1|127)\n/);
  assert.equal(policyCalls, 0);
});
