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
import { startTestHttp2Origin, startTestHttpOrigin } from "../support/http-origin.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("HTTP request-header hook injects host credentials only on the upstream leg", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const observed: Record<string, string>[] = [];
  const hookRequests: Array<{
    readonly protocol: string;
    readonly method: string;
    readonly url: string;
    readonly originalIp: string;
    readonly originalPort: number;
    readonly upstreamIp: string;
    readonly upstreamPort: number;
  }> = [];
  const origin = await startTestHttpOrigin({
    respond(request) {
      observed.push(request.headers);
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          authorized: request.headers.authorization === "Bearer host-only-token",
          protocol: request.headers["x-sandbox-http-protocol"] ?? null,
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
    assert.equal(request.protocol, "http/1.1");
    assert.equal(request.method, "GET");
    assert.equal(request.url.href, `${origin.url}/user`);
    assert.equal(request.destination.originalIp, "203.0.113.10");
    assert.equal(request.destination.originalPort, 80);
    assert.equal(request.destination.upstreamIp, "127.0.0.1");
    assert.equal(request.destination.upstreamPort, urlPort(origin.url));
    hookRequests.push({
      protocol: request.protocol,
      method: request.method,
      url: request.url.href,
      originalIp: request.destination.originalIp,
      originalPort: request.destination.originalPort,
      upstreamIp: request.destination.upstreamIp,
      upstreamPort: request.destination.upstreamPort,
    });
    request.headers.set("authorization", "Bearer host-only-token");
    request.headers.set("x-sandbox-http-protocol", request.protocol);
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
    authorized: true,
    protocol: "http/1.1",
    guestSuppliedAuthorization: "none",
  });
  assert.equal(observed.length, 1);
  assert.equal(observed[0]?.authorization, "Bearer host-only-token");
  assert.deepEqual(hookRequests, [{
    protocol: "http/1.1",
    method: "GET",
    url: `${origin.url}/user`,
    originalIp: "203.0.113.10",
    originalPort: 80,
    upstreamIp: "127.0.0.1",
    upstreamPort: urlPort(origin.url),
  }]);

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
    authorized: false,
    protocol: null,
    guestSuppliedAuthorization: null,
  });
  assert.equal(observed.length, 2);
  assert.equal(observed[1]?.authorization, undefined);
  assert.equal(hookRequests.length, 1);

  await writeEvidence("http-request-headers.json", {
    hookRequests,
    observed,
    origin: origin.url,
  });
});

test("HTTP/2 request-header hook injects host credentials only on the upstream leg", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const observed: Record<string, string>[] = [];
  const hookRequests: Array<{
    readonly protocol: string;
    readonly method: string;
    readonly url: string;
    readonly originalIp: string;
    readonly originalPort: number;
    readonly upstreamIp: string;
    readonly upstreamPort: number;
  }> = [];
  const origin = await startTestHttp2Origin({
    respond(request) {
      observed.push(request.headers);
      return {
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          authorized: request.headers.authorization === "Bearer host-only-token",
          protocol: request.headers["x-sandbox-http-protocol"] ?? null,
        }),
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const sandbox = createSandbox({
    name: "http2-request-header-hook",
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

  sandbox.http.onRequestHeaders(`${origin.url}/*`, (request) => {
    assert.equal(request.protocol, "h2");
    assert.equal(request.method, "GET");
    assert.equal(request.url.href, `${origin.url}/user`);
    assert.equal(request.destination.originalIp, "203.0.113.10");
    assert.equal(request.destination.originalPort, 80);
    assert.equal(request.destination.upstreamIp, "127.0.0.1");
    assert.equal(request.destination.upstreamPort, urlPort(origin.url));
    hookRequests.push({
      protocol: request.protocol,
      method: request.method,
      url: request.url.href,
      originalIp: request.destination.originalIp,
      originalPort: request.destination.originalPort,
      upstreamIp: request.destination.upstreamIp,
      upstreamPort: request.destination.upstreamPort,
    });
    request.headers.set("authorization", "Bearer host-only-token");
    request.headers.set("x-sandbox-http-protocol", request.protocol);
  });

  const vm = await sandbox.run();
  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-http2-host-authorized",
    argv: [
      "curl",
      "--http2-prior-knowledge",
      "--max-time",
      "5",
      "-fsS",
      ...interceptedHttpArgs(`${origin.url}/user`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    authorized: true,
    protocol: "h2",
  });
  assert.equal(observed.length, 1);
  assert.equal(observed[0]?.authorization, "Bearer host-only-token");
  assert.equal(observed[0]?.["x-sandbox-http-protocol"], "h2");
  assert.deepEqual(hookRequests, [{
    protocol: "h2",
    method: "GET",
    url: `${origin.url}/user`,
    originalIp: "203.0.113.10",
    originalPort: 80,
    upstreamIp: "127.0.0.1",
    upstreamPort: urlPort(origin.url),
  }]);
});

test("HTTP request-header hooks default allow when no pattern matches", async (t) => {
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
          authorized: request.headers.authorization === "Bearer host-only-token",
          protocol: request.headers["x-sandbox-http-protocol"] ?? null,
        }),
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const sandbox = createSandbox({
    name: "http-request-header-default-allow",
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

  let hookInvocations = 0;
  sandbox.http.onRequestHeaders(`${origin.url}/private/*`, (request) => {
    hookInvocations += 1;
    request.headers.set("authorization", "Bearer host-only-token");
    request.headers.set("x-sandbox-http-protocol", request.protocol);
  });

  const vm = await sandbox.run();
  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-http-default-allow",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-fsS",
      ...interceptedHttpArgs(`${origin.url}/public`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    authorized: false,
    protocol: null,
  });
  assert.equal(observed.length, 1);
  assert.equal(observed[0]?.authorization, undefined);
  assert.equal(hookInvocations, 0);
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

  let hookInvocations = 0;
  sandbox.http.onRequestHeaders("https://api.github.com/*", (request) => {
    hookInvocations += 1;
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

  assert.notEqual(result.exitCode, 0);
  assert.equal(result.stdout, "000");
  assert.equal(hookInvocations, 0);
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
