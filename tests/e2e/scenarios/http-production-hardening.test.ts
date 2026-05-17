import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  type HttpPolicyRequest,
} from "../../../src/index.ts";
import { collectAsync } from "../support/evidence.ts";
import { execGuest, withTimeout } from "../support/guest-control.ts";
import { createTestCertificateAuthority, startTestHttpOrigin, startTestHttpsOrigin } from "../support/http-origin.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("HTTP interception streams response bodies without waiting for upstream completion", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const origin = await startStreamingHttpOrigin();
  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "http-streaming-response",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
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

  const result = await execGuest(vm, {
    id: "curl-streaming-http-response",
    argv: [
      "curl",
      "--max-time",
      "8",
      "-fsS",
      "-o",
      "/run/streaming-response.txt",
      "-w",
      "%{time_starttransfer} %{time_total}",
      ...interceptedHttpArgs(`${origin.url}/stream`),
    ],
  });

  assert.equal(
    result.exitCode,
    0,
    `streaming HTTP response failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  const [timeToFirstByteText, timeTotalText] = result.stdout.trim().split(/\s+/);
  assert.ok(timeToFirstByteText !== undefined && timeTotalText !== undefined, `unexpected curl timing output: ${result.stdout}`);
  const timeToFirstByte = Number(timeToFirstByteText);
  const timeTotal = Number(timeTotalText);
  assert.ok(timeToFirstByte < 0.75, `expected first byte before upstream finished, got ${timeToFirstByte}s`);
  assert.ok(timeTotal >= 1.4, `expected slow upstream response to take at least 1.4s, got ${timeTotal}s`);
});

test("closing a VM while HTTP policy is locked up cleans up the sandbox", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const origin = await startTestHttpOrigin({
    respond() {
      return { status: 200, body: "should not be reached" };
    },
  });
  t.after(async () => {
    await origin.close();
  });

  let policyStartedResolve: (() => void) | undefined;
  const policyStarted = new Promise<void>((resolve) => {
    policyStartedResolve = resolve;
  });

  const vm = await spawnSandbox({
    name: "http-policy-lockup-cleanup",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy() {
          policyStartedResolve?.();
          return await new Promise<never>(() => {});
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const request = execGuest(vm, {
    id: "curl-hung-policy",
    argv: ["curl", "--max-time", "10", "-fsS", ...interceptedHttpArgs(`${origin.url}/hung`)],
  });
  const requestRejects = assert.rejects(
    withTimeout(request, 5_000, "hung HTTP policy guest command"),
    /closed|exited|sandbox VM|sandbox-host/i,
  );

  await withTimeout(policyStarted, 2_000, "HTTP policy callback");
  await withTimeout(vm.close(), 3_000, "close VM with hung HTTP policy");
  await requestRejects;
});

test("plain HTTP egress header rewrite does not expose or modify request bodies", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const policyEvidence: Array<{
    readonly url: string;
    readonly keys: readonly string[];
  }> = [];
  const originEvidence: Array<{
    readonly body: string;
    readonly rewrite: string | undefined;
  }> = [];

  const origin = await startTestHttpOrigin({
    respond(request) {
      originEvidence.push({
        body: new TextDecoder().decode(request.body),
        rewrite: request.headers["x-sandbox-rewrite"],
      });
      return {
        status: 200,
        headers: {
          "content-type": "text/plain",
          "x-origin-response": "passthrough",
        },
        body: "origin response body",
      };
    },
  });
  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "http-egress-header-only",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          policyEvidence.push({
            url: request.url,
            keys: Object.keys(request).sort(),
          });
          assertPolicyRequestHasNoBody(request);
          return {
            action: "allow",
            headers: {
              ...request.headers,
              "x-sandbox-rewrite": "egress-only",
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

  const result = await execGuest(vm, {
    id: "curl-http-egress-header-only",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-fsS",
      "-X",
      "POST",
      "--data-binary",
      "guest request body",
      "-D",
      "/run/http-egress-headers.txt",
      ...interceptedHttpArgs(`${origin.url}/header-only`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "origin response body");
  assert.deepEqual(originEvidence, [{
    body: "guest request body",
    rewrite: "egress-only",
  }]);
  assert.deepEqual(policyEvidence, [{
    url: `${origin.url}/header-only`,
    keys: ["destinationIp", "headers", "method", "url"],
  }]);

  const headers = await execGuest(vm, {
    id: "cat-http-egress-response-headers",
    argv: ["cat", "/run/http-egress-headers.txt"],
  });
  assert.match(headers.stdout, /x-origin-response: passthrough/i);
});

test("HTTPS egress header rewrite does not expose or modify request bodies", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const policyEvidence: Array<{
    readonly url: string;
    readonly keys: readonly string[];
    readonly tlsServerName: string | undefined;
  }> = [];
  const originEvidence: Array<{
    readonly body: string;
    readonly rewrite: string | undefined;
  }> = [];

  const origin = await startTestHttpsOrigin({
    ca,
    respond(request) {
      originEvidence.push({
        body: new TextDecoder().decode(request.body),
        rewrite: request.headers["x-sandbox-rewrite"],
      });
      return {
        status: 200,
        headers: {
          "content-type": "text/plain",
          "x-origin-response": "passthrough",
        },
        body: "secure origin response body",
      };
    },
  });
  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "https-egress-header-only",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          policyEvidence.push({
            url: request.url,
            keys: Object.keys(request).sort(),
            tlsServerName: request.tls?.serverName,
          });
          assertPolicyRequestHasNoBody(request);
          return {
            action: "allow",
            headers: {
              ...request.headers,
              "x-sandbox-rewrite": "egress-only",
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

  const result = await execGuest(vm, {
    id: "curl-https-egress-header-only",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-fsS",
      "-X",
      "POST",
      "--data-binary",
      "secure guest request body",
      "-D",
      "/run/https-egress-headers.txt",
      ...interceptedHttpsArgs(`${origin.url}/header-only`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "secure origin response body");
  assert.deepEqual(originEvidence, [{
    body: "secure guest request body",
    rewrite: "egress-only",
  }]);
  assert.deepEqual(policyEvidence, [{
    url: `${origin.url}/header-only`,
    keys: ["destinationIp", "headers", "method", "tls", "url"],
    tlsServerName: undefined,
  }]);

  const headers = await execGuest(vm, {
    id: "cat-https-egress-response-headers",
    argv: ["cat", "/run/https-egress-headers.txt"],
  });
  assert.match(headers.stdout, /x-origin-response: passthrough/i);
});

test("redirects to protected destinations are blocked before JavaScript policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const policyUrls: string[] = [];
  const origin = await startTestHttpOrigin({
    respond() {
      return {
        status: 302,
        headers: {
          location: "http://169.254.169.254/latest/meta-data/",
        },
        body: "redirecting",
      };
    },
  });
  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "http-redirect-protected",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          policyUrls.push(request.url);
          return { action: "allow" };
        },
      },
    },
  });
  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-redirect-protected",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-L",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpArgs(`${origin.url}/redirect`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "403");
  assert.deepEqual(policyUrls, [`${origin.url}/redirect`]);
});

test("HTTPS interception buffers fragmented TLS plaintext before policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const largeHeader = "h".repeat(2 * 1024);
  const originEvidence: Array<{
    readonly headerBytes: number;
  }> = [];
  const policyUrls: string[] = [];

  const origin = await startTestHttpsOrigin({
    ca,
    respond(request) {
      originEvidence.push({
        headerBytes: request.headers["x-fragmented-header"]?.length ?? 0,
      });
      return {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "fragmented ok",
      };
    },
  });
  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "https-fragmented-request",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          policyUrls.push(request.url);
          return { action: "allow" };
        },
      },
    },
  });
  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-https-fragmented-request",
    argv: [
      "sh",
      "-lc",
      [
        "curl --max-time 10 -fsS",
        `-H ${shellQuote(`x-fragmented-header: ${largeHeader}`)}`,
        ...interceptedHttpsArgs(`${origin.url}/fragmented`).map(shellQuote),
      ].join(" "),
    ],
  });

  assert.equal(
    result.exitCode,
    0,
    `fragmented HTTPS request failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.stdout, "fragmented ok");
  assert.deepEqual(originEvidence, [{
    headerBytes: largeHeader.length,
  }]);
  assert.deepEqual(policyUrls, [`${origin.url}/fragmented`]);
});

test("HTTPS interception handles forwarded TLS ports without remapping to 443", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });

  const policyUrls: string[] = [];
  const origin = await startTestHttpsOrigin({
    ca,
    respond() {
      return {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: "non-443 ok",
      };
    },
  });
  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "https-forwarded-non-443",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          policyUrls.push(request.url);
          return { action: "allow" };
        },
      },
    },
  });
  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuest(vm, {
    id: "curl-https-forwarded-non-443",
    argv: [
      "curl",
      "--max-time",
      "5",
      "--retry",
      "2",
      "--retry-connrefused",
      "-fsS",
      ...interceptedHttpsAltPortArgs(`${origin.url}/non-443`),
    ],
  });

  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(result.stdout, "non-443 ok");
  assert.deepEqual(policyUrls, [`${origin.url}/non-443`]);
});

function interceptedHttpArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:80`,
    url,
  ];
}

function interceptedHttpsArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:443`,
    url,
  ];
}

function interceptedHttpsAltPortArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:8443`,
    url,
  ];
}

function assertPolicyRequestHasNoBody(request: HttpPolicyRequest): void {
  assert.equal("body" in request, false);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

async function startStreamingHttpOrigin(): Promise<{
  readonly url: string;
  close(): Promise<void>;
}> {
  const server = http.createServer((request, response) => {
    if (request.url !== "/stream") {
      response.writeHead(404);
      response.end();
      return;
    }

    response.writeHead(200, {
      "content-type": "text/plain",
    });
    response.write("first\n");
    setTimeout(() => {
      response.end("second\n");
    }, 1_500).unref();
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("streaming HTTP origin did not bind a TCP port");
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    async close() {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}
