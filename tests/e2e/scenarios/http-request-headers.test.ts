import test from "node:test";
import assert from "node:assert/strict";
import {
  acceptTcp,
  createSandbox,
  prebuiltRootfs,
  projectInit,
  projectKernel,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuest } from "../support/guest-control.ts";
import { startTestHttpOrigin } from "../support/http-origin.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("HTTP request-header hook injects host credentials only on the upstream leg", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const observed: Record<string, string>[] = [];
  const origin = await startTestHttpOrigin({
    respond(request) {
      observed.push(request.headers);
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          authorization: request.headers.authorization ?? null,
          guestSuppliedAuthorization: request.headers["x-guest-authorization"] ?? null,
        }),
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const sandbox = createSandbox({
    name: "http-request-header-hook",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [
          acceptTcp({ cidr: "127.0.0.1/32", ports: [urlPort(origin.url)] }),
          acceptTcp({ cidr: "203.0.113.10/32", ports: [80] }),
        ],
      },
    },
  });

  t.after(async () => {
    await sandbox[Symbol.asyncDispose]();
  });

  const hook = sandbox.http.onRequestHeaders(`${origin.url}/*`, (request) => {
    request.headers.set("authorization", "Bearer host-only-token");
  });

  const vm = await sandbox.run();
  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-host-authorized",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-fsS",
      "-H",
      "x-guest-authorization: none",
      ...interceptedHttpArgs(`${origin.url}/user`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    authorization: "Bearer host-only-token",
    guestSuppliedAuthorization: "none",
  });
  assert.equal(observed.length, 1);
  assert.equal(observed[0]?.authorization, "Bearer host-only-token");

  await hook[Symbol.asyncDispose]();

  const afterDispose = await execGuest(vm, {
    id: "curl-after-hook-dispose",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-fsS",
      ...interceptedHttpArgs(`${origin.url}/after-dispose`),
    ],
  });

  assert.equal(afterDispose.exitCode, 0, afterDispose.stderr);
  assert.deepEqual(JSON.parse(afterDispose.stdout), {
    authorization: null,
    guestSuppliedAuthorization: null,
  });
  assert.equal(observed.length, 2);
  assert.equal(observed[1]?.authorization, undefined);

  await writeEvidence("http-request-headers.json", {
    observed,
    origin: origin.url,
  });
});

test("HTTP credential hooks do not authorize DNS-rebound private destinations", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const sandbox = createSandbox({
    name: "http-request-header-dns-rebinding",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      outbound: {
        policy: "deny",
        rules: [
          acceptTcp({ cidr: "169.254.169.254/32", ports: [443] }),
        ],
      },
    },
  });

  t.after(async () => {
    await sandbox[Symbol.asyncDispose]();
  });

  sandbox.http.onRequestHeaders("https://api.github.com/*", (request) => {
    request.headers.set("authorization", "Bearer host-only-token");
  });

  const vm = await sandbox.run();
  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-rebound-github",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      "--connect-to",
      "api.github.com:443:169.254.169.254:443",
      "https://api.github.com/user",
    ],
  });

  assert.equal(result.stdout, "403");
});

function urlPort(url: string): number {
  const port = Number(new URL(url).port);
  assert.ok(Number.isInteger(port) && port > 0);
  return port;
}

function interceptedHttpArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:80`,
    url,
  ];
}
