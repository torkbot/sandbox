import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import dgram from "node:dgram";
import net from "node:net";
import test, { type TestContext } from "node:test";
import tls from "node:tls";
import {
  defineSandbox,
  fs,
  network,
  rootfs,
  type NetworkConnectionRequest,
  type RootfsImageConfig,
} from "../../../src/index.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";
import { execGuestShell, withTimeout } from "../support/guest-control.ts";
import { testRootfsImageOrSkip } from "../support/rootfs.ts";

const execFileAsync = promisify(execFile);

async function testRootfsForVmTest(t: TestContext): Promise<RootfsImageConfig | undefined> {
  if (!requireVmLaunchSupport(t)) {
    return undefined;
  }

  return await testRootfsImageOrSkip(t);
}

test("network.policy allows plain HTTP over TCP", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nhttp-ok");
    });
  }, 8000);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.transport === "tcp") {
        conn.acceptHttp((request) => {
          request.headers.set("x-sandbox-policy", "allowed");
        });
      }
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-allow",
    script: `curl -fsS --max-time 5 http://${hostOriginAddress()}:${origin.port}/`,
  }), 10_000, "plain HTTP request");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "http-ok");
  assert.deepEqual(observedHeaders, ["allowed"]);
  assert.ok(origin.connections.length >= 1);
});

test("network.policy HTTP proxy handles real client framing variants", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const largeBody = "x".repeat(40_000);
  const observedRequests: Array<{ readonly method: string; readonly path: string }> = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      const [requestLine = ""] = request.split("\r\n", 1);
      const [method = "", path = ""] = requestLine.split(" ");
      observedRequests.push({ method, path });

      switch (path) {
        case "/content-length":
          socket.end("HTTP/1.1 200 OK\r\ncontent-length: 17\r\nconnection: close\r\n\r\ncontent-length-ok");
          break;
        case "/chunked":
          socket.end([
            "HTTP/1.1 200 OK",
            "transfer-encoding: chunked",
            "connection: close",
            "",
            "8",
            "chunked-",
            "2",
            "ok",
            "0",
            "",
            "",
          ].join("\r\n"));
          break;
        case "/close-delimited":
          socket.end("HTTP/1.1 200 OK\r\nconnection: close\r\n\r\nclose-delimited-ok");
          break;
        case "/large":
          socket.end(`HTTP/1.1 200 OK\r\ncontent-length: ${largeBody.length}\r\nconnection: close\r\n\r\n${largeBody}`);
          break;
        case "/slow":
          socket.write("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n5\r\nslow-\r\n");
          setTimeout(() => socket.end("2\r\nok\r\n0\r\n\r\n"), 50);
          break;
        case "/head":
          socket.end("HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\n");
          break;
        case "/no-content":
          socket.end("HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n");
          break;
        case "/not-modified":
          socket.end("HTTP/1.1 304 Not Modified\r\nconnection: close\r\n\r\n");
          break;
        default:
          socket.end("HTTP/1.1 404 Not Found\r\ncontent-length: 9\r\nconnection: close\r\n\r\nnot-found");
          break;
      }
    });
  }, 8000);
  t.after(() => void origin.close());

  const observedPolicy: Array<{ readonly protocol: string; readonly method: string; readonly path: string }> = [];
  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.transport === "tcp") {
        conn.acceptHttp((request) => {
          observedPolicy.push({
            protocol: request.protocol,
            method: request.method,
            path: request.url.pathname,
          });
        });
      }
    }),
  }).boot();

  const baseUrl = `http://${hostOriginAddress()}:${origin.port}`;
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-client-framing-compat",
    script: [
      "set -eux",
      `base=${JSON.stringify(baseUrl)}`,
      "curl -fsS --http1.1 --max-time 5 \"$base/content-length\" > /tmp/curl-content-length",
      "test \"$(cat /tmp/curl-content-length)\" = content-length-ok",
      "curl -fsS --http1.1 --max-time 5 \"$base/chunked\" > /tmp/curl-chunked",
      "test \"$(cat /tmp/curl-chunked)\" = chunked-ok",
      "curl -fsS --http1.1 --max-time 5 \"$base/close-delimited\" > /tmp/curl-close-delimited",
      "test \"$(cat /tmp/curl-close-delimited)\" = close-delimited-ok",
      "curl -fsS --http1.1 --max-time 5 \"$base/slow\" > /tmp/curl-slow",
      "test \"$(cat /tmp/curl-slow)\" = slow-ok",
      "curl -fsS --http1.1 --max-time 5 \"$base/large\" > /tmp/curl-large",
      "test \"$(wc -c < /tmp/curl-large)\" = 40000",
      "curl -fsSI --http1.1 --max-time 5 \"$base/head\" | grep -iq '^content-length: 7'",
      "test \"$(curl -fsS --http1.1 --max-time 5 -o /tmp/curl-no-content -w '%{http_code}' \"$base/no-content\")\" = 204",
      "test ! -s /tmp/curl-no-content",
      "test \"$(curl -fsS --http1.1 --max-time 5 -o /tmp/curl-not-modified -w '%{http_code}' \"$base/not-modified\")\" = 304",
      "test ! -s /tmp/curl-not-modified",
      "wget -q -O /tmp/wget-content-length \"$base/content-length\"",
      "test \"$(cat /tmp/wget-content-length)\" = content-length-ok",
      "wget -q -O /tmp/wget-chunked \"$base/chunked\"",
      "test \"$(cat /tmp/wget-chunked)\" = chunked-ok",
      "wget -q -O /tmp/wget-close-delimited \"$base/close-delimited\"",
      "test \"$(cat /tmp/wget-close-delimited)\" = close-delimited-ok",
      "wget -q -O /tmp/wget-slow \"$base/slow\"",
      "test \"$(cat /tmp/wget-slow)\" = slow-ok",
      "wget -q -O /tmp/wget-large \"$base/large\"",
      "test \"$(wc -c < /tmp/wget-large)\" = 40000",
      "printf compat-ok",
    ].join("; "),
  }), 20_000, "HTTP client framing compatibility matrix");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "compat-ok");
  assert.ok(observedRequests.some((request) => request.method === "HEAD" && request.path === "/head"));
  assert.ok(observedPolicy.every((request) => request.protocol === "http/1.1"));
  assert.ok(observedPolicy.some((request) => request.path === "/close-delimited"));
  assert.ok(observedPolicy.some((request) => request.path === "/large"));
});

test("network.policy allows HTTP middleware on non-standard TCP ports", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 14\r\nconnection: close\r\n\r\nnonstandard-ok");
    });
  }, 18080);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.transport === "tcp") {
        conn.acceptHttp((request) => {
          request.headers.set("x-sandbox-policy", "allowed");
        });
      }
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-nonstandard-port",
    script: `curl -fsS --max-time 5 http://${hostOriginAddress()}:${origin.port}/`,
  }), 10_000, "non-standard HTTP request");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "nonstandard-ok");
  assert.deepEqual(observedHeaders, ["allowed"]);
});

test("network.policy ignores spoofed Host headers for HTTP identity", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const observedDestinations: Array<{ readonly urlHost: string; readonly hostname?: string }> = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", () => {
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok");
    });
  }, 18081);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.transport === "tcp") {
        conn.acceptHttp((request) => {
          observedDestinations.push({
            urlHost: request.url.hostname,
            hostname: request.destination.hostname,
          });
        });
      }
    }),
  }).boot();

  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-host-spoof",
    script: `curl -fsS --max-time 5 -H 'Host: attacker.invalid' http://${hostOriginAddress()}:${origin.port}/`,
  }), 10_000, "spoofed Host HTTP request");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.deepEqual(observedDestinations, [{
    urlHost: hostOriginAddress(),
    hostname: undefined,
  }]);
});

test("network.policy accepts IP HTTP without advertising a hostname", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const observedDestinations: Array<{ readonly urlHost: string; readonly hostname?: string }> = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", () => {
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 5\r\nconnection: close\r\n\r\nip-ok");
    });
  }, 18082);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.transport === "tcp") {
        conn.acceptHttp((request) => {
          observedDestinations.push({
            urlHost: request.url.hostname,
            hostname: request.destination.hostname,
          });
        });
      }
    }),
  }).boot();

  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ip-authority",
    script: `curl -fsS --max-time 5 -H 'Host: attacker.invalid' http://${hostOriginAddress()}:${origin.port}/`,
  }), 10_000, "IP HTTP request");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "ip-ok");
  assert.deepEqual(observedDestinations, [{
    urlHost: hostOriginAddress(),
    hostname: undefined,
  }]);
});

test("network.policy rejects untrusted HTTPS upstream certificates", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const host = "localhost";
  const origin = await startTlsHttpServer(8443);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy(async (conn) => {
      if (conn.transport === "udp" && conn.dst.port === 53) {
        conn.accept();
        return;
      }
      if (conn.transport === "tcp") {
        conn.acceptHttp((request) => {
          request.headers.set("x-sandbox-policy", "allowed");
        });
      }
    }),
  }).boot();

  const result = await withTimeout(execGuestShell(sandbox, {
    id: "https-middleware",
    script: `curl -kfsS --max-time 5 --connect-to ${host}:${origin.port}:${hostOriginAddress()}:${origin.port} https://${host}:${origin.port}/`,
  }), 10_000, "HTTPS middleware request");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.deepEqual(origin.requests, []);
});

test("network.policy denies private HTTP by destination range before origin access", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const origin = await startTcpServer((socket) => {
    socket.end("HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nunexpected");
  });
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.dst.isLoopback() || conn.dst.isPrivate() || conn.dst.isLinkLocal()) return;
      conn.accept();
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-deny-range",
    script: `curl -fsS --max-time 3 http://${hostOriginAddress()}:${origin.port}/`,
  }), 8_000, "denied HTTP request");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(origin.connections.length, 0);
});

test("network.policy allows raw TCP echo traffic without HTTP parsing", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const echo = await startTcpServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  t.after(() => void echo.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tcp-echo-allow",
    script: pythonTcpExchange(echo.port, "tcp-echo"),
  }), 10_000, "raw TCP echo");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "tcp-echo");
  assert.equal(echo.connections.length, 1);
});

test("network.policy denies raw TCP before upstream receives bytes", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const echo = await startTcpServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  t.after(() => void echo.close());

  await using sandbox = await bootDenyingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tcp-echo-deny",
    script: pythonTcpRefused(echo.port),
  }), 8_000, "denied raw TCP echo");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "ECONNREFUSED");
  assert.equal(echo.connections.length, 0);
});

test("network.policy fails closed when the transport hook throws", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const echo = await startTcpServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  t.after(() => void echo.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy(() => {
      throw new Error("policy failed");
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tcp-policy-error-deny",
    script: pythonTcpRefused(echo.port),
  }), 8_000, "transport policy error");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "ECONNREFUSED");
  assert.equal(echo.connections.length, 0);
});

test("network.policy allows SSH handshake traffic as raw bidirectional TCP", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const ssh = await startSshBannerServer();
  t.after(() => void ssh.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "ssh-allow",
    script: [
      "ssh",
      "-o StrictHostKeyChecking=no",
      "-o UserKnownHostsFile=/dev/null",
      "-o BatchMode=yes",
      "-o ConnectTimeout=5",
      `-p ${ssh.port}`,
      `${hostOriginAddress()} true`,
    ].join(" "),
  }), 12_000, "SSH handshake");

  assert.match(result.stderr + result.stdout, /SSH|kex|Connection|Protocol|closed/i);
  assert.equal(ssh.connections.length, 1);
  assert.match(ssh.clientBanners.join("\n"), /^SSH-2\.0-/m);
});

test("network.policy denies SSH before the server banner is observed", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const ssh = await startSshBannerServer();
  t.after(() => void ssh.close());

  await using sandbox = await bootDenyingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "ssh-deny",
    script: [
      "ssh",
      "-o StrictHostKeyChecking=no",
      "-o UserKnownHostsFile=/dev/null",
      "-o BatchMode=yes",
      "-o ConnectTimeout=3",
      `-p ${ssh.port}`,
      `${hostOriginAddress()} true`,
    ].join(" "),
  }), 8_000, "denied SSH handshake");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(ssh.connections.length, 0);
  assert.equal(ssh.clientBanners.length, 0);
});

test("network.policy allows non-HTTP TLS passthrough without MITM", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const tlsEcho = await startTlsEchoServer();
  t.after(() => void tlsEcho.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tls-passthrough",
    script: pythonTlsExchange(tlsEcho.port, "tls-ping"),
  }), 10_000, "non-HTTP TLS passthrough");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "tls:tls-ping");
  assert.equal(tlsEcho.connections.length, 1);
});

test("network.policy acceptHttp without middleware still enforces HTTP", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const tlsEcho = await startTlsEchoServer();
  t.after(() => void tlsEcho.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.transport === "tcp") {
        conn.acceptHttp();
      }
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "accept-http-rejects-raw-tls",
    script: pythonTlsExchange(tlsEcho.port, "raw-tls"),
  }), 10_000, "acceptHttp rejects raw TLS");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(tlsEcho.connections.length, 0);
});

test("network.policy matchHttp accept without middleware preserves raw HTTPS", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const host = "tls-match.test";
  const dnsServer = await startUdpDnsServer(hostOriginAddress());
  const tlsEcho = await startTlsEchoServer();
  t.after(() => void dnsServer.close());
  t.after(() => void tlsEcho.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;

      conn.matchHttp(host)?.accept();
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "match-http-raw-https",
    script: pythonTlsExchange(tlsEcho.port, "matched-http", host),
  }), 10_000, "matchHttp raw HTTPS passthrough");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "tls:matched-http");
  assert.equal(tlsEcho.connections.length, 1);
});

test("network.policy allows a deterministic Redis-style TCP protocol exchange", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const redis = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      if (chunk.toString("utf8") === "PING\r\n") {
        socket.end("+PONG\r\n");
      } else {
        socket.end("-ERR unexpected\r\n");
      }
    });
  });
  t.after(() => void redis.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "redis-style",
    script: pythonTcpExchange(redis.port, "PING\r\n"),
  }), 10_000, "Redis-style TCP exchange");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "+PONG\r\n");
  assert.ok(redis.connections.length >= 1);
});

test("network.policy raw-relays token-space TCP commands without HTTP framing", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const commandServer = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      if (chunk.toString("utf8") === "GET key\r\n") {
        socket.end("VALUE key 0 5\r\nvalue\r\nEND\r\n");
      } else {
        socket.end("ERROR\r\n");
      }
    });
  });
  t.after(() => void commandServer.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "token-space-raw-tcp",
    script: pythonTcpExchange(commandServer.port, "GET key\r\n"),
  }), 10_000, "token-space raw TCP exchange");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "VALUE key 0 5\r\nvalue\r\nEND\r\n");
  assert.ok(commandServer.connections.length >= 1);
});

test("network.policy opens allowed raw relays for server-first TCP protocols", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const banner = await startTcpServer((socket) => {
    socket.end("220 sandbox.test service ready\r\n");
  });
  t.after(() => void banner.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "server-first-raw-tcp",
    script: pythonTcpReadBanner(banner.port),
  }), 10_000, "server-first raw TCP exchange");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "220 sandbox.test service ready\r\n");
  assert.ok(banner.connections.length >= 1);
});

test("network.policy allows generic UDP echo traffic", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const udp = await startUdpEchoServer();
  t.after(() => void udp.close());

  await using sandbox = await bootAllowingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "udp-echo-allow",
    script: pythonUdpExchange(udp.port, "udp-echo"),
  }), 10_000, "generic UDP echo");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "udp-echo");
  assert.equal(udp.messages.length, 1);
});

test("network.policy allows default DNS over UDP as accepted UDP", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await bootAllowingDns(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-udp-default",
    script: pythonDnsQuery({ transport: "udp", name: "localhost" }),
  }), 8_000, "default UDP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1");
});

test("network.policy matches default DNS over UDP with DNS capability", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept()) return;
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-udp-match",
    script: pythonDnsQuery({ transport: "udp", name: "localhost" }),
  }), 8_000, "matched UDP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1");
});

test("network.policy can answer DNS with custom accept resolvers", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const dnsServer = await startUdpDnsServer("203.0.113.44");
  t.after(() => {
    void dnsServer.close();
  });

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-custom-resolver",
    script: pythonDnsQuery({ transport: "udp", name: "custom.test" }),
  }), 8_000, "custom resolver DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.44");
  assert.equal(dnsServer.queries, 1);
});

test("network.policy uses DNS cache hostname as HTTP policy authority", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const hostname = "policy-cache.test";
  const dnsServer = await startUdpDnsServer(hostOriginAddress());
  t.after(() => {
    void dnsServer.close();
  });
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 12\r\nconnection: close\r\n\r\ndns-cache-ok");
    });
  }, 18084);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;

      conn.matchHttp(hostname)?.accept((request) => {
        request.headers.set("x-sandbox-policy", request.destination.hostname ?? "");
      });
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-dns-cache-authority",
    script: `curl -4fsS --max-time 5 http://${hostname}:${origin.port}/`,
  }), 10_000, "HTTP request matched by DNS cache hostname");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "dns-cache-ok");
  assert.equal(dnsServer.queries, 1);
  assert.deepEqual(observedHeaders, [hostname]);
});

test("network.policy uses DNS cache hostname for multi-answer Cloudflare-like A records", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const hostname = "registry.npmjs.org";
  const originAddress = hostOriginAddress();
  const dnsServer = await startUdpDnsServer([
    "104.16.7.34",
    "104.16.1.34",
    originAddress,
    "104.16.10.34",
  ]);
  t.after(() => {
    void dnsServer.close();
  });
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 18\r\nconnection: close\r\n\r\ncloudflare-dns-ok");
    });
  }, 18084);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;

      conn.matchHttp(hostname)?.accept((request) => {
        request.headers.set("x-sandbox-policy", request.destination.hostname ?? "");
      });
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-dns-cache-cloudflare-authority",
    script: [
      "python3 - <<'PY'",
      "import socket, time",
      `hostname = ${JSON.stringify(hostname)}`,
      `origin_address = ${JSON.stringify(originAddress)}`,
      `port = ${origin.port}`,
      "addresses = [info[4][0] for info in socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)]",
      "assert origin_address in addresses, addresses",
      "deadline = time.monotonic() + 5",
      "response = b''",
      "last_error = None",
      "while time.monotonic() < deadline:",
      "    try:",
      "        with socket.create_connection((origin_address, port), timeout=1) as conn:",
      "            conn.settimeout(1)",
      "            conn.sendall(b'GET / HTTP/1.1\\r\\nHost: untrusted-host-header.test\\r\\nConnection: close\\r\\n\\r\\n')",
      "            chunks = []",
      "            while True:",
      "                chunk = conn.recv(4096)",
      "                if not chunk:",
      "                    break",
      "                chunks.append(chunk)",
      "            response = b''.join(chunks)",
      "            if b'\\r\\n\\r\\n' in response:",
      "                break",
      "    except OSError as error:",
      "        last_error = error",
      "    time.sleep(0.05)",
      "if b'\\r\\n\\r\\n' not in response:",
      "    raise RuntimeError(f'no HTTP response after DNS resolution: response={response!r} error={last_error!r}')",
      "print(response.split(b'\\r\\n\\r\\n', 1)[1].decode(), end='')",
      "PY",
    ].join("\n"),
  }), 10_000, "HTTP request matched by multi-answer DNS cache hostname");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "cloudflare-dns-ok");
  assert.equal(dnsServer.queries, 1);
  assert.ok(observedHeaders.length >= 1);
  assert.equal(observedHeaders.every((header) => header === hostname), true);
});

test("network.policy keeps DNS cache hostname for delayed Cloudflare-like package fetches", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const hostname = "registry.npmjs.org";
  const originAddress = hostOriginAddress();
  const dnsServer = await startUdpDnsServer((request) => dnsAnswerWithTtl(request, [
    "104.16.8.34",
    originAddress,
    "104.16.10.34",
  ], 1));
  t.after(() => {
    void dnsServer.close();
  });
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 14\r\nconnection: close\r\n\r\ndelayed-dns-ok");
    });
  }, 18084);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;

      conn.matchHttp(hostname)?.accept((request) => {
        request.headers.set("x-sandbox-policy", request.destination.hostname ?? "");
      });
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-dns-cache-delayed-cloudflare-authority",
    script: [
      "python3 - <<'PY'",
      "import socket, time",
      `hostname = ${JSON.stringify(hostname)}`,
      `origin_address = ${JSON.stringify(originAddress)}`,
      `port = ${origin.port}`,
      "addresses = [info[4][0] for info in socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)]",
      "assert origin_address in addresses, addresses",
      "time.sleep(2)",
      "with socket.create_connection((origin_address, port), timeout=5) as conn:",
      "    conn.sendall(b'GET / HTTP/1.1\\r\\nHost: untrusted-host-header.test\\r\\nConnection: close\\r\\n\\r\\n')",
      "    response = b''",
      "    while True:",
      "        chunk = conn.recv(4096)",
      "        if not chunk:",
      "            break",
      "        response += chunk",
      "print(response.split(b'\\r\\n\\r\\n', 1)[1].decode(), end='')",
      "PY",
    ].join("\n"),
  }), 12_000, "delayed HTTP request matched by DNS cache hostname");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "delayed-dns-ok");
  assert.equal(dnsServer.queries, 1);
  assert.deepEqual(observedHeaders, [hostname]);
});

test("network.policy uses DNS cache hostname for CNAME additional-section A records", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const hostname = "registry.npmjs.org";
  const originAddress = hostOriginAddress();
  const dnsServer = await startUdpDnsServer((request) => dnsCnameAdditionalAnswer(request, {
    canonicalName: "registry-npmjs-org.cdn.cloudflare.net",
    address: originAddress,
  }));
  t.after(() => {
    void dnsServer.close();
  });
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 19\r\nconnection: close\r\n\r\ncname-additional-ok");
    });
  }, 18084);
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;

      conn.matchHttp(hostname)?.accept((request) => {
        request.headers.set("x-sandbox-policy", request.destination.hostname ?? "");
      });
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-dns-cache-cname-additional-authority",
    script: [
      "python3 - <<'PY'",
      "import socket",
      `hostname = ${JSON.stringify(hostname)}`,
      `origin_address = ${JSON.stringify(originAddress)}`,
      `port = ${origin.port}`,
      "packet = bytearray(b'\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00')",
      "for label in hostname.split('.'):",
      "    packet.append(len(label))",
      "    packet += label.encode()",
      "packet += b'\\x00\\x00\\x01\\x00\\x01'",
      "dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)",
      "dns.settimeout(3)",
      "dns.sendto(bytes(packet), ('10.0.2.1', 53))",
      "dns.recvfrom(4096)",
      "dns.close()",
      "with socket.create_connection((origin_address, port), timeout=5) as conn:",
      "    conn.sendall(b'GET / HTTP/1.1\\r\\nHost: untrusted-host-header.test\\r\\nConnection: close\\r\\n\\r\\n')",
      "    response = b''",
      "    while True:",
      "        chunk = conn.recv(4096)",
      "        if not chunk:",
      "            break",
      "        response += chunk",
      "print(response.split(b'\\r\\n\\r\\n', 1)[1].decode(), end='')",
      "PY",
    ].join("\n"),
  }), 10_000, "HTTP request matched by CNAME additional-section DNS cache hostname");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "cname-additional-ok");
  assert.equal(dnsServer.queries, 1);
  assert.deepEqual(observedHeaders, [hostname]);
});

test("network.policy resolver survives synthesized mount directories", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const dnsServer = await startUdpDnsServer("203.0.113.45");
  t.after(() => {
    void dnsServer.close();
  });

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;
    }),
  }).boot({
    mounts: {
      "/tmp/missing-network-mount": fs.virtual(fs.memory({ files: { "/note.txt": "mounted\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-synthesized-mount",
    script: "python3 -c 'import socket; print(socket.gethostbyname(\"custom.test\"), end=\"\")'",
  }), 8_000, "DNS through synthesized mount root");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.45");
  assert.equal(dnsServer.queries, 1);
});

test("network.policy resolver setup is isolated from /run/sandbox mounts", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const dnsServer = await startUdpDnsServer("203.0.113.46");
  t.after(() => {
    void dnsServer.close();
  });

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;
    }),
  }).boot({
    mounts: {
      "/run/sandbox": fs.virtual(fs.memory({ files: { "/note.txt": "mounted\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-run-sandbox-mount",
    script: "python3 -c 'import socket; print(socket.gethostbyname(\"custom.test\"), end=\"\")'",
  }), 8_000, "DNS through /run/sandbox mount");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.46");
  assert.equal(dnsServer.queries, 1);
});

test("network.policy HTTP CA setup survives /run/sandbox mounts", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot({
    mounts: {
      "/run/sandbox": fs.virtual(fs.memory({ files: { "/note.txt": "mounted\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-run-sandbox-mount",
    script: [
      "test -f /run/sandbox/note.txt",
      "test ! -e /usr/local/share/ca-certificates/sandbox-http-interception-ca.crt",
    ].join(" && "),
  }), 8_000, "HTTP CA setup with /run/sandbox mount");

  assert.equal(result.exitCode, 0, commandOutput(result));
});

test("network.policy HTTP CA setup survives /run mounts", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot({
    mounts: {
      "/run": fs.virtual(fs.memory({ files: { "/note.txt": "mounted\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-run-mount",
    script: [
      "test ! -e /usr/local/share/ca-certificates/sandbox-http-interception-ca.crt",
      "cat /run/note.txt",
    ].join(" && "),
  }), 8_000, "HTTP CA setup with /run mount");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "mounted\n");
});

test("network.policy preserves nested mounts below /run/sandbox after HTTP CA setup", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot({
    mounts: {
      "/run/sandbox": fs.virtual(fs.memory({
        files: {
          "/note.txt": "parent\n",
          "/cache/.keep": "",
        },
      })),
      "/run/sandbox/cache": fs.virtual(fs.memory({ files: { "/note.txt": "child\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-run-sandbox-nested-mount",
    script: [
      "test ! -e /usr/local/share/ca-certificates/sandbox-http-interception-ca.crt",
      "cat /run/sandbox/note.txt",
      "cat /run/sandbox/cache/note.txt",
    ].join(" && "),
  }), 8_000, "HTTP CA setup with nested /run/sandbox mounts");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "parent\nchild\n");
});

test("network.policy HTTP CA setup keeps read-only rootfs trust store unchanged", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot({
    mounts: {
      "/usr/local/share/ca-certificates": fs.virtual(fs.memory({})),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-trust-store-mount",
    script: [
      "test ! -e /usr/local/share/ca-certificates/sandbox-http-interception-ca.crt",
      "test -s /run/sandbox/http-ca/http-ca.pem",
    ].join(" && "),
  }), 8_000, "HTTP CA setup with mounted trust store");

  assert.equal(result.exitCode, 0, commandOutput(result));
});

test("network.policy HTTP CA setup populates writable ephemeral trust store", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: rootfs.ephemeral({ base: testRootfs }),
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-ephemeral-trust-store",
    script: "test -s /usr/local/share/ca-certificates/sandbox-http-interception-ca.crt",
  }), 8_000, "HTTP CA setup with writable ephemeral rootfs");

  assert.equal(result.exitCode, 0, commandOutput(result));
});

test("network.policy user mount can replace internal HTTP CA mount after setup", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot({
    mounts: {
      "/run/sandbox/http-ca": fs.virtual(fs.memory({ files: { "/note.txt": "mounted\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-user-mount",
    script: "cat /run/sandbox/http-ca/note.txt",
  }), 8_000, "HTTP CA setup with user mount at internal CA path");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "mounted\n");
});

test("network.policy user mount can replace internal HTTP CA mount with normalized path", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot({
    mounts: {
      "/run//sandbox/http-ca/": fs.virtual(fs.memory({ files: { "/note.txt": "mounted\n" } })),
    },
  });
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-ca-user-mount-normalized",
    script: "cat /run/sandbox/http-ca/note.txt",
  }), 8_000, "HTTP CA setup with normalized user mount at internal CA path");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "mounted\n");
});

test("network.policy preserves TCP DNS for custom accept resolvers", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  const dnsServer = await startTcpDnsServer("203.0.113.45");
  t.after(() => {
    void dnsServer.close();
  });

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      if (conn.matchDns()?.accept({
        resolvers: [{ ip: "127.0.0.1", port: dnsServer.port }],
      })) return;
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-custom-tcp-resolver",
    script: pythonDnsQuery({ transport: "tcp", name: "custom-tcp.test" }),
  }), 8_000, "custom TCP resolver DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.45");
  assert.equal(dnsServer.queries, 1);
});

test("network.policy allows default DNS over TCP as accepted TCP", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await bootAllowingDns(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-tcp-default",
    script: pythonDnsQuery({ transport: "tcp", name: "localhost" }),
  }), 8_000, "default TCP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1");
});

test("network.policy keeps DNS over TCP sessions reusable", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;

  await using sandbox = await bootAllowingDns(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-tcp-reuse",
    script: pythonTcpDnsTwoQueries("localhost", "localhost"),
  }), 8_000, "reused TCP DNS queries");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1,127.0.0.1");
});

test("network.policy denies generic UDP before upstream receives datagrams", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const udp = await startUdpEchoServer();
  t.after(() => void udp.close());

  await using sandbox = await bootDenyingNetwork(testRootfs);
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "udp-echo-deny",
    script: pythonUdpExchange(udp.port, "udp-denied"),
  }), 8_000, "denied generic UDP echo");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(udp.messages.length, 0);
});

test("network.policy exposes source and destination endpoint helpers for transport callbacks", async (t) => {
  const testRootfs = await testRootfsForVmTest(t);
  if (testRootfs === undefined) return;
  const observations: Array<{
    readonly transport: string;
    readonly srcIp: string;
    readonly srcPort: number;
    readonly dstIp: string;
    readonly dstPort: number;
    readonly dstPublic: boolean;
    readonly dstPrivate: boolean;
  }> = [];

  await using sandbox = await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      observations.push(observation(conn));
      conn.accept();
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "endpoint-observations",
    script: pythonDnsQuery({ transport: "udp", name: "localhost" }),
  }), 8_000, "endpoint helper observation");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1");
  assert.ok(observations.some((entry) => {
    return entry.transport === "udp"
      && entry.dstIp === "10.0.2.1"
      && entry.dstPort === 53
      && entry.dstPrivate === true;
  }), JSON.stringify(observations, null, 2));
});

async function bootAllowingNetwork(testRootfs: RootfsImageConfig) {
  return await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.accept();
    }),
  }).boot();
}

async function bootDenyingNetwork(testRootfs: RootfsImageConfig) {
  return await defineSandbox({
    rootfs: testRootfs,
    network: network.policy(() => {}),
  }).boot();
}

async function bootAllowingDns(testRootfs: RootfsImageConfig) {
  return await defineSandbox({
    rootfs: testRootfs,
    network: network.policy((conn) => {
      conn.matchDns()?.accept();
    }),
  }).boot();
}

function observation(conn: NetworkConnectionRequest) {
  return {
    transport: conn.transport,
    srcIp: conn.src.ip,
    srcPort: conn.src.port,
    dstIp: conn.dst.ip,
    dstPort: conn.dst.port,
    dstPublic: conn.dst.isPublicInternet(),
    dstPrivate: conn.dst.isPrivate(),
  };
}

function pythonTcpExchange(port: number, message: string): string {
  return `python3 - <<'PY'\nimport socket\ns = socket.create_connection((${JSON.stringify(hostOriginAddress())}, ${port}), timeout=3)\ns.settimeout(3)\ns.sendall(${JSON.stringify(message)}.encode())\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
}

function pythonTcpRefused(port: number): string {
  return `python3 - <<'PY'\nimport errno, socket\ntry:\n    socket.create_connection((${JSON.stringify(hostOriginAddress())}, ${port}), timeout=3)\nexcept OSError as error:\n    print(errno.errorcode.get(getattr(error, "errno", None), type(error).__name__), end="")\nPY`;
}

function pythonTcpReadBanner(port: number): string {
  return `python3 - <<'PY'\nimport socket\ns = socket.create_connection((${JSON.stringify(hostOriginAddress())}, ${port}), timeout=3)\ns.settimeout(3)\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
}

function pythonTlsExchange(port: number, message: string, host = hostOriginAddress()): string {
  return `python3 - <<'PY'\nimport socket, ssl\nctx = ssl._create_unverified_context()\nraw = socket.create_connection((${JSON.stringify(host)}, ${port}), timeout=3)\ns = ctx.wrap_socket(raw, server_hostname=${JSON.stringify(host)})\ns.settimeout(3)\ns.sendall(${JSON.stringify(message)}.encode())\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
}

function pythonUdpExchange(port: number, message: string): string {
  return `python3 - <<'PY'\nimport socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\ns.sendto(${JSON.stringify(message)}.encode(), (${JSON.stringify(hostOriginAddress())}, ${port}))\nprint(s.recvfrom(4096)[0].decode(), end="")\ns.close()\nPY`;
}

function pythonDnsQuery(input: { readonly transport: "tcp" | "udp"; readonly name: string }): string {
  return `python3 - <<'PY'\nimport socket, struct\n\ndef query(name):\n    packet = bytearray()\n    packet += b"\\x12\\x34\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"\n    for label in name.split("."):\n        packet.append(len(label))\n        packet += label.encode()\n    packet += b"\\x00\\x00\\x01\\x00\\x01"\n    return bytes(packet)\n\ndef read_name(packet, offset):\n    labels = []\n    jumped = False\n    original = offset\n    while True:\n        length = packet[offset]\n        if length & 0xc0 == 0xc0:\n            pointer = ((length & 0x3f) << 8) | packet[offset + 1]\n            if not jumped:\n                original = offset + 2\n            offset = pointer\n            jumped = True\n            continue\n        offset += 1\n        if length == 0:\n            return ".".join(labels), (original if jumped else offset)\n        labels.append(packet[offset:offset + length].decode())\n        offset += length\n\ndef answer_address(packet):\n    question_count = struct.unpack("!H", packet[4:6])[0]\n    answer_count = struct.unpack("!H", packet[6:8])[0]\n    offset = 12\n    for _ in range(question_count):\n        _, offset = read_name(packet, offset)\n        offset += 4\n    for _ in range(answer_count):\n        _, offset = read_name(packet, offset)\n        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])\n        offset += 10\n        data = packet[offset:offset + rdlen]\n        offset += rdlen\n        if rtype == 1 and rclass == 1 and rdlen == 4:\n            return ".".join(str(byte) for byte in data)\n    raise RuntimeError("missing A answer")\n\nrequest = query(${JSON.stringify(input.name)})\nif ${JSON.stringify(input.transport)} == "udp":\n    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n    s.settimeout(3)\n    s.sendto(request, ("10.0.2.1", 53))\n    response = s.recvfrom(4096)[0]\nelse:\n    s = socket.create_connection(("10.0.2.1", 53), timeout=3)\n    s.settimeout(3)\n    s.sendall(struct.pack("!H", len(request)) + request)\n    size = struct.unpack("!H", s.recv(2))[0]\n    response = b""\n    while len(response) < size:\n        response += s.recv(size - len(response))\nprint(answer_address(response), end="")\ns.close()\nPY`;
}

function pythonTcpDnsTwoQueries(first: string, second: string): string {
  return `python3 - <<'PY'\nimport socket, struct\n\ndef query(name, ident):\n    packet = bytearray()\n    packet += struct.pack("!H", ident) + b"\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00"\n    for label in name.split("."):\n        packet.append(len(label))\n        packet += label.encode()\n    packet += b"\\x00\\x00\\x01\\x00\\x01"\n    return bytes(packet)\n\ndef read_name(packet, offset):\n    labels = []\n    jumped = False\n    original = offset\n    while True:\n        length = packet[offset]\n        if length & 0xc0 == 0xc0:\n            pointer = ((length & 0x3f) << 8) | packet[offset + 1]\n            if not jumped:\n                original = offset + 2\n            offset = pointer\n            jumped = True\n            continue\n        offset += 1\n        if length == 0:\n            return ".".join(labels), (original if jumped else offset)\n        labels.append(packet[offset:offset + length].decode())\n        offset += length\n\ndef answer_address(packet):\n    question_count = struct.unpack("!H", packet[4:6])[0]\n    answer_count = struct.unpack("!H", packet[6:8])[0]\n    offset = 12\n    for _ in range(question_count):\n        _, offset = read_name(packet, offset)\n        offset += 4\n    for _ in range(answer_count):\n        _, offset = read_name(packet, offset)\n        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", packet[offset:offset + 10])\n        offset += 10\n        data = packet[offset:offset + rdlen]\n        offset += rdlen\n        if rtype == 1 and rclass == 1 and rdlen == 4:\n            return ".".join(str(byte) for byte in data)\n    raise RuntimeError("missing A answer")\n\ndef read_response(sock):\n    size = struct.unpack("!H", sock.recv(2))[0]\n    response = b""\n    while len(response) < size:\n        response += sock.recv(size - len(response))\n    return response\n\ns = socket.create_connection(("10.0.2.1", 53), timeout=3)\ns.settimeout(3)\nfor request in [query(${JSON.stringify(first)}, 0x1234), query(${JSON.stringify(second)}, 0x1235)]:\n    s.sendall(struct.pack("!H", len(request)) + request)\nanswers = [answer_address(read_response(s)), answer_address(read_response(s))]\nprint(",".join(answers), end="")\ns.close()\nPY`;
}

async function startTcpServer(onConnection: (socket: net.Socket) => void, port = 0): Promise<{
  readonly port: number;
  readonly connections: net.Socket[];
  close(): Promise<void>;
}> {
  const connections: net.Socket[] = [];
  const server = net.createServer((socket) => {
    connections.push(socket);
    socket.on("error", () => {});
    onConnection(socket);
  });
  await listen(server, port);
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("TCP server did not bind a port");
  }
  return {
    port: address.port,
    connections,
    async close() {
      for (const socket of connections) {
        socket.destroy();
      }
      await closeServer(server);
    },
  };
}

async function startSshBannerServer(): Promise<{
  readonly port: number;
  readonly connections: net.Socket[];
  readonly clientBanners: string[];
  close(): Promise<void>;
}> {
  const clientBanners: string[] = [];
  const server = await startTcpServer((socket) => {
    socket.write("SSH-2.0-sandbox-test\r\n");
    socket.once("data", (chunk) => {
      clientBanners.push(chunk.toString("utf8").trimEnd());
      socket.end();
    });
  });
  return { ...server, clientBanners };
}

async function startTlsEchoServer(): Promise<{
  readonly port: number;
  readonly connections: tls.TLSSocket[];
  close(): Promise<void>;
}> {
  const certificate = await createSelfSignedCertificate();
  const connections: tls.TLSSocket[] = [];
  const server = tls.createServer({
    key: await readFile(certificate.keyPath),
    cert: await readFile(certificate.certPath),
  }, (socket) => {
    connections.push(socket);
    socket.on("data", (chunk) => socket.write(`tls:${chunk.toString("utf8")}`));
  });
  await listen(server);
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("TLS server did not bind a port");
  }
  return {
    port: address.port,
    connections,
    async close() {
      for (const socket of connections) {
        socket.destroy();
      }
      await closeServer(server);
      await rm(certificate.workDir, { recursive: true, force: true });
    },
  };
}

async function startTlsHttpServer(port = 0): Promise<{
  readonly port: number;
  readonly requests: string[];
  close(): Promise<void>;
}> {
  const certificate = await createSelfSignedCertificate();
  const requests: string[] = [];
  const server = tls.createServer({
    key: await readFile(certificate.keyPath),
    cert: await readFile(certificate.certPath),
  }, (socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      const header = request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "";
      requests.push(header);
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 8\r\nconnection: close\r\n\r\nhttps-ok");
    });
  });
  await listen(server, port);
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("TLS HTTP server did not bind a port");
  }
  return {
    port: address.port,
    requests,
    async close() {
      await closeServer(server);
      await rm(certificate.workDir, { recursive: true, force: true });
    },
  };
}

async function startUdpEchoServer(): Promise<{
  readonly port: number;
  readonly messages: Buffer[];
  close(): Promise<void>;
}> {
  const socket = dgram.createSocket("udp4");
  const messages: Buffer[] = [];
  socket.on("message", (message, remote) => {
    messages.push(message);
    socket.send(message, remote.port, remote.address);
  });
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
      socket.bind(0, "0.0.0.0", () => {
      socket.off("error", reject);
      resolve();
    });
  });
  const address = socket.address();
  return {
    port: address.port,
    messages,
    async close() {
      await new Promise<void>((resolve) => socket.close(() => resolve()));
    },
  };
}

async function startUdpDnsServer(answer: string | readonly string[] | ((request: Buffer) => Buffer)): Promise<{
  readonly port: number;
  readonly queries: number;
  close(): Promise<void>;
}> {
  let queries = 0;
  const server = dgram.createSocket("udp4");
  server.on("message", (request, remote) => {
    queries += 1;
    const response = typeof answer === "function" ? answer(request) : dnsAnswer(request, answer);
    server.send(response, remote.port, remote.address);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (typeof address === "string") {
    throw new Error("UDP DNS server did not bind a port");
  }
  return {
    port: address.port,
    get queries() {
      return queries;
    },
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

async function startTcpDnsServer(answer: string): Promise<{
  readonly port: number;
  readonly queries: number;
  close(): Promise<void>;
}> {
  let queries = 0;
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length < 2) return;
      const requestLength = buffer.readUInt16BE(0);
      if (buffer.length < requestLength + 2) return;
      queries += 1;
      const response = dnsAnswer(buffer.subarray(2, requestLength + 2), answer);
      const frame = Buffer.alloc(response.length + 2);
      frame.writeUInt16BE(response.length, 0);
      response.copy(frame, 2);
      socket.end(frame);
    });
  });
  await listen(server, 0, "127.0.0.1");
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("TCP DNS server did not bind a port");
  }
  return {
    port: address.port,
    get queries() {
      return queries;
    },
    async close() {
      await closeServer(server);
    },
  };
}

function dnsAnswer(request: Buffer, answer: string | readonly string[]): Buffer {
  return dnsAnswerWithTtl(request, answer, 60);
}

function dnsAnswerWithTtl(request: Buffer, answer: string | readonly string[], ttl: number): Buffer {
  const answers = typeof answer === "string" ? [answer] : answer;
  let offset = 12;
  while (request[offset] !== 0) {
    offset += (request[offset] ?? 0) + 1;
  }
  const questionEnd = offset + 5;
  const qtype = request.readUInt16BE(offset + 1);
  const responseAnswers = qtype === 1 ? answers : [];
  const response = Buffer.alloc(questionEnd + (16 * responseAnswers.length));
  request.copy(response, 0, 0, questionEnd);
  response[2] = 0x81;
  response[3] = 0x80;
  response.writeUInt16BE(responseAnswers.length, 6);
  response.writeUInt16BE(0, 8);
  response.writeUInt16BE(0, 10);
  let answerOffset = questionEnd;
  for (const address of responseAnswers) {
    response[answerOffset++] = 0xc0;
    response[answerOffset++] = 0x0c;
    response.writeUInt16BE(1, answerOffset);
    answerOffset += 2;
    response.writeUInt16BE(1, answerOffset);
    answerOffset += 2;
    response.writeUInt32BE(ttl, answerOffset);
    answerOffset += 4;
    response.writeUInt16BE(4, answerOffset);
    answerOffset += 2;
    for (const part of address.split(".")) {
      response[answerOffset++] = Number(part);
    }
  }
  return response;
}

function dnsCnameAdditionalAnswer(
  request: Buffer,
  additional: { readonly canonicalName: string; readonly address: string },
): Buffer {
  let offset = 12;
  while (request[offset] !== 0) {
    offset += (request[offset] ?? 0) + 1;
  }
  const questionEnd = offset + 5;
  const qtype = request.readUInt16BE(offset + 1);
  if (qtype !== 1) {
    return dnsAnswer(request, []);
  }

  const canonicalName = dnsName(additional.canonicalName);
  const response = Buffer.alloc(questionEnd + 12 + canonicalName.length + canonicalName.length + 16);
  request.copy(response, 0, 0, questionEnd);
  response[2] = 0x81;
  response[3] = 0x80;
  response.writeUInt16BE(1, 6);
  response.writeUInt16BE(0, 8);
  response.writeUInt16BE(1, 10);

  let answerOffset = questionEnd;
  response[answerOffset++] = 0xc0;
  response[answerOffset++] = 0x0c;
  response.writeUInt16BE(5, answerOffset);
  answerOffset += 2;
  response.writeUInt16BE(1, answerOffset);
  answerOffset += 2;
  response.writeUInt32BE(60, answerOffset);
  answerOffset += 4;
  response.writeUInt16BE(canonicalName.length, answerOffset);
  answerOffset += 2;
  canonicalName.copy(response, answerOffset);
  answerOffset += canonicalName.length;

  canonicalName.copy(response, answerOffset);
  answerOffset += canonicalName.length;
  response.writeUInt16BE(1, answerOffset);
  answerOffset += 2;
  response.writeUInt16BE(1, answerOffset);
  answerOffset += 2;
  response.writeUInt32BE(60, answerOffset);
  answerOffset += 4;
  response.writeUInt16BE(4, answerOffset);
  answerOffset += 2;
  for (const part of additional.address.split(".")) {
    response[answerOffset++] = Number(part);
  }
  return response;
}

function dnsName(name: string): Buffer {
  return Buffer.concat([
    ...name.split(".").map((label) => Buffer.concat([Buffer.from([label.length]), Buffer.from(label)])),
    Buffer.from([0]),
  ]);
}

async function createSelfSignedCertificate(): Promise<{
  readonly workDir: string;
  readonly keyPath: string;
  readonly certPath: string;
}> {
  const workDir = await mkdtemp(join(tmpdir(), "sandbox-network-policy-"));
  const keyPath = join(workDir, "server.key");
  const certPath = join(workDir, "server.pem");
  const configPath = join(workDir, "openssl.cnf");
  await writeFile(configPath, [
    "[req]",
    "distinguished_name=req_distinguished_name",
    "x509_extensions=v3_req",
    "prompt=no",
    "[req_distinguished_name]",
    "CN=localhost",
    "[v3_req]",
    `subjectAltName=DNS:localhost,IP:${hostOriginAddress()}`,
    "",
  ].join("\n"));
  await execFileAsync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    certPath,
    "-days",
    "1",
    "-config",
    configPath,
  ]);
  return { workDir, keyPath, certPath };
}

async function listen(server: net.Server | tls.Server, port = 0, host = "0.0.0.0"): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function hostOriginAddress(): string {
  for (const addresses of Object.values(networkInterfaces())) {
    for (const address of addresses ?? []) {
      if (address.family === "IPv4" && !address.internal && !address.address.startsWith("169.254.")) {
        return address.address;
      }
    }
  }
  throw new Error("no non-internal IPv4 host address available for e2e origin");
}

async function closeServer(server: net.Server | tls.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => {
      if (error !== undefined) reject(error);
      else resolve();
    });
  });
}

function commandOutput(result: { readonly stdout: string; readonly stderr: string }): string {
  return `stdout:\n${result.stdout}\nstderr:\n${result.stderr}`;
}
