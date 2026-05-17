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

function interceptedHttpsArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:443`,
    url,
  ];
}
