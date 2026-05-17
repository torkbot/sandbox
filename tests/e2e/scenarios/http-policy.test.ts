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

test("protected host and private network destinations are blocked before JavaScript policy", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const policyDestinations: string[] = [];

  const vm = await spawnSandbox({
    name: "default-protected-ranges",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    network: {
      http: {
        ca,
        async policy(request) {
          policyDestinations.push(request.destinationIp);
          return { action: "allow" };
        },
      },
    },
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const protectedDestinations = [
    "10.1.2.3",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
  ];
  for (const destination of protectedDestinations) {
    const result = await execGuest(vm, {
      id: `curl-protected-${destination}`,
      argv: [
        "curl",
        "--max-time",
        "5",
        "-sS",
        "-o",
        "/dev/null",
        "-w",
        "%{http_code}",
        `http://${destination}/protected`,
      ],
    });
    assert.equal(result.stdout, "403", `${destination} should be blocked before policy`);
  }

  assert.deepEqual(policyDestinations, []);
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

test("HTTP interception forwards request and response bodies larger than a single TCP read", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const requestBodyBytes = 32 * 1024;
  const responseBodyBytes = 384 * 1024;
  const responseBody = Buffer.alloc(responseBodyBytes, "b");
  const decisions: Pick<HttpPolicyRequest, "method" | "url" | "headers">[] = [];

  const origin = await startTestHttpOrigin({
    respond(request) {
      return {
        status: request.body.byteLength === requestBodyBytes ? 200 : 400,
        headers: {
          "content-type": "application/octet-stream",
          "x-request-bytes": String(request.body.byteLength),
        },
        body: responseBody,
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "http-large-bodies",
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
            method: request.method,
            url: request.url,
            headers: request.headers,
          });
          return {
            action: "allow",
            headers: {
              ...request.headers,
              "x-large-body-policy": "observed",
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
    id: "curl-large-http-bodies",
    argv: [
      "sh",
      "-lc",
      [
        `dd if=/dev/zero of=/run/large-request.bin bs=${requestBodyBytes} count=1 status=none &&`,
        "curl --max-time 10 -fsS",
        "-X POST",
        "--data-binary @/run/large-request.bin",
        "-o /run/large-response.bin",
        ...interceptedHttpArgs(`${origin.url}/large`),
        "&& wc -c < /run/large-response.bin",
      ].join(" "),
    ],
  });

  assert.equal(
    result.exitCode,
    0,
    `large HTTP body transfer failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(Number(result.stdout.trim()), responseBodyBytes);
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0]?.method, "POST");
  assert.equal(decisions[0]?.headers["x-large-body-policy"], undefined);
});

test("HTTP interception handles concurrent guest requests without dropping policy calls", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const requestedPaths: string[] = [];
  const policyUrls: string[] = [];

  const origin = await startTestHttpOrigin({
    respond(request) {
      requestedPaths.push(request.url);
      return {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: request.url,
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "http-concurrent-requests",
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

  const urls = Array.from({ length: 8 }, (_, index) => `${origin.url}/concurrent-${index}`);
  const script = [
    "set -eu",
    "rm -f /run/sandbox-concurrent-*",
    ...urls.map((url, index) =>
      `curl --max-time 10 -fsS ${interceptedHttpArgs(url).map(shellQuote).join(" ")} > /run/sandbox-concurrent-${index} &`,
    ),
    "wait",
    "cat /run/sandbox-concurrent-*",
  ].join("\n");

  const result = await execGuest(vm, {
    id: "curl-concurrent-http",
    argv: ["sh", "-lc", script],
  });

  assert.equal(
    result.exitCode,
    0,
    `concurrent HTTP requests failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  for (let index = 0; index < urls.length; index += 1) {
    assert.match(result.stdout, new RegExp(`/concurrent-${index}`));
  }
  assert.equal(policyUrls.length, urls.length);
  assert.deepEqual([...requestedPaths].sort(), urls.map((url) => new URL(url).pathname).sort());
});

test("HTTPS interception forwards request and response bodies larger than a single TLS record", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const requestBodyBytes = 16 * 1024;
  const responseBodyBytes = 48 * 1024;
  const responseBody = Buffer.alloc(responseBodyBytes, "s");
  const decisions: Pick<HttpPolicyRequest, "method" | "url" | "tls">[] = [];

  const origin = await startTestHttpsOrigin({
    ca,
    respond(request) {
      return {
        status: request.body.byteLength === requestBodyBytes ? 200 : 400,
        headers: {
          "content-type": "application/octet-stream",
          "x-request-bytes": String(request.body.byteLength),
        },
        body: responseBody,
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "https-large-bodies",
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
            method: request.method,
            url: request.url,
            tls: request.tls,
          });
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
    id: "curl-large-https-bodies",
    argv: [
      "sh",
      "-lc",
      [
        `dd if=/dev/zero of=/run/large-https-request.bin bs=${requestBodyBytes} count=1 status=none &&`,
        "curl --max-time 10 -fsS",
        "-X POST",
        "--data-binary @/run/large-https-request.bin",
        "-o /run/large-https-response.bin",
        ...interceptedHttpsArgs(`${origin.url}/large`),
        "&& wc -c < /run/large-https-response.bin",
      ].join(" "),
    ],
  });

  assert.equal(
    result.exitCode,
    0,
    `large HTTPS body transfer failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(Number(result.stdout.trim()), responseBodyBytes);
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0]?.method, "POST");
  assert.ok(decisions[0]?.tls);
  assert.match(decisions[0]?.tls?.protocol ?? "", /TLS/);
});

test("HTTPS interception handles concurrent guest requests without dropping TLS policy calls", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const requestedPaths: string[] = [];
  const policyUrls: string[] = [];

  const origin = await startTestHttpsOrigin({
    ca,
    respond(request) {
      requestedPaths.push(request.url);
      return {
        status: 200,
        headers: { "content-type": "text/plain" },
        body: request.url,
      };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "https-concurrent-requests",
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

  const urls = Array.from({ length: 8 }, (_, index) => `${origin.url}/secure-concurrent-${index}`);
  const script = [
    "set -eu",
    "rm -f /run/sandbox-secure-concurrent-*",
    ...urls.map((url, index) =>
      `curl --max-time 10 -fsS ${interceptedHttpsArgs(url).map(shellQuote).join(" ")} > /run/sandbox-secure-concurrent-${index} &`,
    ),
    "wait",
    "cat /run/sandbox-secure-concurrent-*",
  ].join("\n");

  const result = await execGuest(vm, {
    id: "curl-concurrent-https",
    argv: ["sh", "-lc", script],
  });

  assert.equal(
    result.exitCode,
    0,
    `concurrent HTTPS requests failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  for (let index = 0; index < urls.length; index += 1) {
    assert.match(result.stdout, new RegExp(`/secure-concurrent-${index}`));
  }
  assert.equal(policyUrls.length, urls.length);
  assert.deepEqual([...requestedPaths].sort(), urls.map((url) => new URL(url).pathname).sort());
});

test("HTTP keep-alive behavior is explicit and deterministic", () => {
  assert.fail("HTTP keep-alive must either support connection reuse or return a documented deterministic close behavior");
});

test("upstream connection refused returns a deterministic guest-visible failure", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const refusedUrl = "http://127.0.0.1:1/refused";
  const policyUrls: string[] = [];

  const vm = await spawnSandbox({
    name: "http-upstream-refused",
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
    id: "curl-upstream-refused",
    argv: [
      "curl",
      "--max-time",
      "5",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpArgs(refusedUrl),
    ],
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "502");
  assert.deepEqual(policyUrls, [refusedUrl]);
});

test("upstream timeout returns a deterministic guest-visible failure", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  const ca = await createTestCertificateAuthority();
  t.after(async () => {
    await ca.close();
  });
  const policyUrls: string[] = [];

  const origin = await startTestHttpOrigin({
    async respond() {
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      return { status: 200, body: "too late" };
    },
  });

  t.after(async () => {
    await origin.close();
  });

  const vm = await spawnSandbox({
    name: "http-upstream-timeout",
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

  const url = `${origin.url}/timeout`;
  const result = await execGuest(vm, {
    id: "curl-upstream-timeout",
    argv: [
      "curl",
      "--max-time",
      "6",
      "-sS",
      "-o",
      "/dev/null",
      "-w",
      "%{http_code}",
      ...interceptedHttpArgs(url),
    ],
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "502");
  assert.deepEqual(policyUrls, [url]);
});

test("upstream reset mid-body returns a deterministic guest-visible failure", () => {
  assert.fail("mid-body upstream resets must produce a stable guest-visible failure");
});

test("TLS without SNI has deterministic certificate and policy metadata", () => {
  assert.fail("IP-literal TLS without SNI must have documented certificate behavior and policy metadata");
});

test("dynamic MITM certificates are reused or bounded intentionally", () => {
  assert.fail("MITM certificate generation must expose evidence that cache or bound behavior is intentional");
});

test("HTTP/2 ALPN behavior is explicit", () => {
  assert.fail("HTTP/2-capable clients must observe documented downgrade, denial, or implemented HTTP/2 behavior");
});

function interceptedHttpsArgs(url: string): string[] {
  const parsed = new URL(url);
  return interceptedHttpsAuthorityArgs(url, "203.0.113.10", `${parsed.hostname}:${parsed.port}`);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
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
