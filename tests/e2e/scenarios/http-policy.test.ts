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
import { startTestHttpsOrigin } from "../support/http-origin.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("HTTPS traffic is intercepted, policy checked, rewritten, and protected ranges are blocked", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const decisions: Pick<HttpPolicyRequest, "url" | "destinationIp" | "tls">[] = [];

  const vm = await spawnSandbox({
    name: "http-policy",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        async policy(request) {
          decisions.push({
            url: request.url,
            destinationIp: request.destinationIp,
            tls: request.tls,
          });

          if (request.url.includes("/blocked")) {
            return { action: "deny", reason: "test policy" };
          }

          return { action: "allow" };
        },
        async modifyRequestHeaders(headers) {
          return {
            ...headers,
            "x-sandbox-e2e": "http-policy",
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
    argv: ["curl", "-fsS", `${origin.url}/allowed`],
  });
  assert.equal(allowed.exitCode, 0);
  assert.deepEqual(JSON.parse(allowed.stdout), { rewritten: true });

  const denied = await execGuest(vm, {
    id: "curl-denied",
    argv: ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", `${origin.url}/blocked`],
  });
  assert.equal(denied.stdout, "451");

  const protectedHost = await execGuest(vm, {
    id: "curl-protected-host",
    argv: ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "https://127.0.0.1/"],
  });
  assert.equal(protectedHost.stdout, "403");

  assert.ok(decisions.some((decision) => decision.url.endsWith("/allowed")));
  assert.ok(decisions.some((decision) => decision.url.endsWith("/blocked")));

  await writeEvidence("proxy.json", {
    decisions,
    origin: origin.url,
  });
});
