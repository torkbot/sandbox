import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  type HttpPolicyRequest,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuest } from "../support/guest-control.ts";
import { createTestCertificateAuthority, startTestHttpOrigin, startTestHttpsOrigin } from "../support/http-origin.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("plain HTTP traffic is intercepted, policy checked, rewritten, and forwarded", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const decisions: Pick<HttpPolicyRequest, "url" | "destinationIp" | "headers">[] = [];

  const vm = await spawnSandbox({
    name: "http-policy",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        protectedRanges: ["169.254.169.254/32"],
        ca,
        async policy(request) {
          decisions.push({
            url: request.url,
            destinationIp: request.destinationIp,
            headers: request.headers,
          });

          if (request.url.includes("/blocked")) {
            return { action: "deny", reason: "test policy" };
          }

          return {
            action: "allow",
            headers: {
              ...request.headers,
              "x-sandbox-e2e": "http-policy",
            },
          };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const injectedCa = await execGuest(vm, {
    id: "injected-ca",
    argv: ["sh", "-lc", "test \"$SSL_CERT_FILE\" = /run/sandbox/http-ca.pem && cat /run/sandbox/http-ca.pem"],
  });
  assert.equal(injectedCa.exitCode, 0);
  assert.equal(injectedCa.stdout, ca.certificatePem);

  const origin = await startTestHttpOrigin({
    respond(request) {
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          rewritten: request.headers["x-sandbox-e2e"] === "http-policy",
        }),
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const allowed = await execGuest(vm, {
    id: "curl-allowed",
    argv: ["curl", "--max-time", "5", "-fsS", ...interceptedHttpArgs(`${origin.url}/allowed`)],
  });
  assert.equal(allowed.exitCode, 0);
  assert.deepEqual(JSON.parse(allowed.stdout), { rewritten: true });

  const denied = await execGuest(vm, {
    id: "curl-denied",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpArgs(`${origin.url}/blocked`),
    ],
  });
  assert.equal(denied.stdout, "451");

  const protectedDestination = await execGuest(vm, {
    id: "curl-protected-destination",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "http://169.254.169.254/protected",
    ],
  });
  assert.equal(protectedDestination.stdout, "403");

  assert.ok(decisions.some((decision) => decision.url.endsWith("/allowed")));
  assert.ok(decisions.some((decision) => decision.url.endsWith("/blocked")));
  assert.ok(!decisions.some((decision) => decision.destinationIp === "169.254.169.254"));

  await writeEvidence("proxy.json", {
    decisions,
    origin: origin.url,
  });
});

function interceptedHttpArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:80`,
    url,
  ];
}

test("HTTPS traffic is intercepted, policy checked, rewritten, and protected ranges are blocked", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const decisions: Pick<HttpPolicyRequest, "url" | "destinationIp" | "headers">[] = [];

  const vm = await spawnSandbox({
    name: "https-policy",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        protectedRanges: ["169.254.169.254/32"],
        ca,
        async policy(request) {
          decisions.push({
            url: request.url,
            destinationIp: request.destinationIp,
            headers: request.headers,
          });

          if (request.url.includes("/blocked")) {
            return { action: "deny", reason: "blocked over tls" };
          }

          return {
            action: "allow",
            headers: {
              ...request.headers,
              "x-sandbox-e2e": "https-policy",
            },
          };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const origin = await startTestHttpsOrigin({
    ca,
    respond(request) {
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          rewritten: request.headers["x-sandbox-e2e"] === "https-policy",
        }),
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const allowed = await execGuest(vm, {
    id: "curl-https-allowed",
    argv: ["curl", "--max-time", "5", "-fsS", ...interceptedHttpsArgs(`${origin.url}/allowed`)],
  });
  assert.equal(allowed.exitCode, 0);
  assert.deepEqual(JSON.parse(allowed.stdout), { rewritten: true });

  const denied = await execGuest(vm, {
    id: "curl-https-denied",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpsArgs(`${origin.url}/blocked`),
    ],
  });
  assert.equal(denied.stdout, "451");

  const protectedDestination = await execGuest(vm, {
    id: "curl-https-protected-destination",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-k",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "https://169.254.169.254/protected",
    ],
  });
  assert.equal(protectedDestination.stdout, "403");

  assert.ok(decisions.some((decision) => decision.url.endsWith("/allowed")));
  assert.ok(decisions.some((decision) => decision.url.endsWith("/blocked")));
  assert.ok(!decisions.some((decision) => decision.destinationIp === "169.254.169.254"));
});

test("transparent HTTPS generates a trusted leaf cert for the requested SNI hostname", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const decisions: Pick<HttpPolicyRequest, "url" | "destinationIp" | "headers" | "tls">[] = [];

  const vm = await spawnSandbox({
    name: "https-sni-leaf",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          decisions.push({
            url: request.url,
            destinationIp: request.destinationIp,
            headers: request.headers,
            tls: request.tls,
          });

          return { action: "deny", reason: "sni observed" };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const denied = await execGuest(vm, {
    id: "curl-sni-leaf",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpsAuthorityArgs("https://example.test/blocked", "203.0.113.10"),
    ],
  });
  assert.equal(
    denied.stdout,
    "451",
    `guest should trust the dynamically generated leaf certificate\nstderr:\n${denied.stderr}`,
  );

  assert.deepEqual(decisions.map((decision) => decision.tls?.serverName), ["example.test"]);
  assert.equal(decisions[0]?.headers.host, "example.test");
  assert.equal(decisions[0]?.url, "https://example.test/blocked");
});

test("transparent HTTPS exposes SNI and Host mismatch to one policy call", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const decisions: Pick<HttpPolicyRequest, "url" | "headers" | "tls">[] = [];

  const vm = await spawnSandbox({
    name: "https-sni-host-mismatch",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          decisions.push({
            url: request.url,
            headers: request.headers,
            tls: request.tls,
          });
          return { action: "deny", reason: "host mismatch observed" };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const denied = await execGuest(vm, {
    id: "curl-sni-host-mismatch",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-H",
      "Host: other.test",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpsAuthorityArgs("https://example.test/mismatch", "203.0.113.10"),
    ],
  });
  assert.equal(
    denied.stdout,
    "451",
    `guest should trust the dynamically generated leaf certificate\nstderr:\n${denied.stderr}`,
  );
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0]?.tls?.serverName, "example.test");
  assert.equal(decisions[0]?.headers.host, "other.test");
  assert.equal(decisions[0]?.url, "https://other.test/mismatch");
});

test("certificate pinning rejects MITM and fails closed before HTTP policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  let policyCalls = 0;

  const vm = await spawnSandbox({
    name: "https-pinning",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
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

  const origin = await startTestHttpsOrigin({
    ca,
    hostname: "127.0.0.1",
    respond() {
      return { status: 200, body: "should not be reached" };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const pinned = await execGuest(vm, {
    id: "curl-pinned-cert",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-fsS",
      "--pinnedpubkey",
      origin.pinnedPublicKeySha256,
      ...interceptedHttpsArgs(`${origin.url}/pinned`),
    ],
  });
  assert.notEqual(pinned.exitCode, 0);
  assert.match(pinned.stderr, /public key|pinned|SSL|certificate/i);
  assert.equal(policyCalls, 0);
});

function interceptedHttpsArgs(url: string): string[] {
  const parsed = new URL(url);
  return interceptedHttpsAuthorityArgs(url, "203.0.113.10", `${parsed.hostname}:${parsed.port}`);
}

function interceptedHttpsAuthorityArgs(
  url: string,
  connectAddress: string,
  matchAuthority?: string,
): string[] {
  const parsed = new URL(url);
  const sourceAuthority = matchAuthority ?? `${parsed.hostname}:${parsed.port || "443"}`;
  return [
    "--connect-to",
    `${sourceAuthority}:${connectAddress}:443`,
    url,
  ];
}
