import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
} from "../../../src/index.ts";
import { collectAsync } from "../support/evidence.ts";
import { execGuest, withTimeout } from "../support/guest-control.ts";
import { createTestCertificateAuthority, startTestHttpOrigin } from "../support/http-origin.ts";
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

function interceptedHttpArgs(url: string): string[] {
  const parsed = new URL(url);
  return [
    "--connect-to",
    `${parsed.hostname}:${parsed.port}:203.0.113.10:80`,
    url,
  ];
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
