import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import dgram from "node:dgram";
import net from "node:net";
import test from "node:test";
import tls from "node:tls";
import {
  defineSandbox,
  network,
  rootfs,
  type NetworkConnectionRequest,
} from "../../../src/index.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";
import { execGuestShell, withTimeout } from "../support/guest-control.ts";

const execFileAsync = promisify(execFile);

test("network.policy allows plain HTTP over TCP", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const origin = await startTcpServer((socket) => {
    socket.once("data", () => {
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nhttp-ok");
    });
  });
  t.after(() => void origin.close());

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-allow",
    script: `curl -fsS --max-time 5 http://public.sandbox.test:${origin.port}/`,
  }), 10_000, "plain HTTP request");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "http-ok");
  assert.equal(origin.connections.length, 1);
});

test("network.policy allows HTTPS HTTP middleware", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const origin = await startTlsHttpServer();
  t.after(() => void origin.close());

  const observedHeaders: string[] = [];
  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy(async (conn) => {
      if (conn.protocol === "tcp") {
        conn.allow();
        return;
      }
      if (conn.protocol === "udp" && conn.dst.port === 53) {
        conn.allow();
        return;
      }
      if (conn.protocol === "http") {
        conn.allowHttp((request) => {
          request.headers.set("x-sandbox-policy", "allowed");
        });
      }
    }),
  }).boot();

  const result = await withTimeout(execGuestShell(sandbox, {
    id: "https-middleware",
    script: `curl -kfsS --max-time 5 https://public.sandbox.test:${origin.port}/`,
  }), 10_000, "HTTPS middleware request");

  assert.equal(result.exitCode, 0, commandOutput(result));
  observedHeaders.push(...origin.requests);
  assert.deepEqual(observedHeaders, ["allowed"]);
  assert.equal(result.stdout, "https-ok");
});

test("network.policy denies HTTP by destination range before origin access", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const origin = await startTcpServer((socket) => {
    socket.end("HTTP/1.1 200 OK\r\ncontent-length: 11\r\n\r\nunexpected");
  });
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      if (conn.dst.isLoopback() || conn.dst.isPrivate() || conn.dst.isLinkLocal()) return;
      conn.allow();
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "http-deny-range",
    script: `curl -fsS --max-time 3 http://public.sandbox.test:${origin.port}/`,
  }), 8_000, "denied HTTP request");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(origin.connections.length, 0);
});

test("network.policy allows raw TCP echo traffic without HTTP parsing", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const echo = await startTcpServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  t.after(() => void echo.close());

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tcp-echo-allow",
    script: pythonTcpExchange(echo.port, "tcp-echo"),
  }), 10_000, "raw TCP echo");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "tcp-echo");
  assert.equal(echo.connections.length, 1);
});

test("network.policy denies raw TCP before upstream receives bytes", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const echo = await startTcpServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  t.after(() => void echo.close());

  await using sandbox = await bootDenyingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tcp-echo-deny",
    script: pythonTcpExchange(echo.port, "tcp-denied"),
  }), 8_000, "denied raw TCP echo");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(echo.connections.length, 0);
});

test("network.policy allows SSH handshake traffic as raw bidirectional TCP", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const ssh = await startSshBannerServer();
  t.after(() => void ssh.close());

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "ssh-allow",
    script: [
      "ssh",
      "-o StrictHostKeyChecking=no",
      "-o UserKnownHostsFile=/dev/null",
      "-o BatchMode=yes",
      "-o ConnectTimeout=5",
      `-p ${ssh.port}`,
      "public.sandbox.test true",
    ].join(" "),
  }), 12_000, "SSH handshake");

  assert.match(result.stderr + result.stdout, /SSH|kex|Connection|Protocol|closed/i);
  assert.equal(ssh.connections.length, 1);
  assert.match(ssh.clientBanners.join("\n"), /^SSH-2\.0-/m);
});

test("network.policy denies SSH before the server banner is observed", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const ssh = await startSshBannerServer();
  t.after(() => void ssh.close());

  await using sandbox = await bootDenyingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "ssh-deny",
    script: [
      "ssh",
      "-o StrictHostKeyChecking=no",
      "-o UserKnownHostsFile=/dev/null",
      "-o BatchMode=yes",
      "-o ConnectTimeout=3",
      `-p ${ssh.port}`,
      "public.sandbox.test true",
    ].join(" "),
  }), 8_000, "denied SSH handshake");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(ssh.connections.length, 0);
  assert.equal(ssh.clientBanners.length, 0);
});

test("network.policy allows non-HTTP TLS passthrough without MITM", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const tlsEcho = await startTlsEchoServer();
  t.after(() => void tlsEcho.close());

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "tls-passthrough",
    script: pythonTlsExchange(tlsEcho.port, "tls-ping"),
  }), 10_000, "non-HTTP TLS passthrough");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "tls:tls-ping");
  assert.equal(tlsEcho.connections.length, 1);
});

test("network.policy allows a deterministic Redis-style TCP protocol exchange", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
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

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "redis-style",
    script: pythonTcpExchange(redis.port, "PING\\r\\n"),
  }), 10_000, "Redis-style TCP exchange");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "+PONG\r\n");
  assert.equal(redis.connections.length, 1);
});

test("network.policy allows generic UDP echo traffic", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const udp = await startUdpEchoServer();
  t.after(() => void udp.close());

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "udp-echo-allow",
    script: pythonUdpExchange(udp.port, "udp-echo"),
  }), 10_000, "generic UDP echo");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "udp-echo");
  assert.equal(udp.messages.length, 1);
});

test("network.policy denies generic UDP before upstream receives datagrams", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const udp = await startUdpEchoServer();
  t.after(() => void udp.close());

  await using sandbox = await bootDenyingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "udp-echo-deny",
    script: pythonUdpExchange(udp.port, "udp-denied"),
  }), 8_000, "denied generic UDP echo");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.equal(udp.messages.length, 0);
});

test("network.policy exposes source and destination endpoint helpers for transport callbacks", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const observations: Array<{
    readonly protocol: string;
    readonly srcIp: string;
    readonly srcPort: number;
    readonly dstIp: string;
    readonly dstPort: number;
    readonly dstPublic: boolean;
    readonly dstPrivate: boolean;
  }> = [];

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      observations.push(observation(conn));
      if (conn.protocol === "udp" && conn.dst.port === 53) {
        conn.allow();
      }
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "endpoint-observations",
    script: `python3 - <<'PY'\nimport socket\nprint(socket.gethostbyname("public.sandbox.test"))\nPY`,
  }), 8_000, "endpoint helper observation");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.match(result.stdout, /93\.184\.216\.34/);
  assert.ok(observations.some((entry) => {
    return entry.protocol === "udp"
      && entry.dstIp === "10.0.2.1"
      && entry.dstPort === 53
      && entry.dstPrivate === true;
  }), JSON.stringify(observations, null, 2));
});

async function bootAllowingNetwork() {
  return await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      conn.allow();
    }),
  }).boot();
}

async function bootDenyingNetwork() {
  return await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy(() => {}),
  }).boot();
}

function observation(conn: NetworkConnectionRequest) {
  return {
    protocol: conn.protocol,
    srcIp: conn.src.ip,
    srcPort: conn.src.port,
    dstIp: conn.dst.ip,
    dstPort: conn.dst.port,
    dstPublic: conn.dst.isPublicInternet(),
    dstPrivate: conn.dst.isPrivate(),
  };
}

function pythonTcpExchange(port: number, message: string): string {
  return `python3 - <<'PY'\nimport socket\ns = socket.create_connection(("public.sandbox.test", ${port}), timeout=3)\ns.settimeout(3)\ns.sendall(${JSON.stringify(message)}.encode())\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
}

function pythonTlsExchange(port: number, message: string): string {
  return `python3 - <<'PY'\nimport socket, ssl\nctx = ssl._create_unverified_context()\nraw = socket.create_connection(("public.sandbox.test", ${port}), timeout=3)\ns = ctx.wrap_socket(raw, server_hostname="localhost")\ns.settimeout(3)\ns.sendall(${JSON.stringify(message)}.encode())\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
}

function pythonUdpExchange(port: number, message: string): string {
  return `python3 - <<'PY'\nimport socket\ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.settimeout(3)\ns.sendto(${JSON.stringify(message)}.encode(), ("public.sandbox.test", ${port}))\nprint(s.recvfrom(4096)[0].decode(), end="")\ns.close()\nPY`;
}

async function startTcpServer(onConnection: (socket: net.Socket) => void): Promise<{
  readonly port: number;
  readonly connections: net.Socket[];
  close(): Promise<void>;
}> {
  const connections: net.Socket[] = [];
  const server = net.createServer((socket) => {
    connections.push(socket);
    onConnection(socket);
  });
  await listen(server);
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

async function startTlsHttpServer(): Promise<{
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
  await listen(server);
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
    socket.bind(0, "127.0.0.1", () => {
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
    "subjectAltName=DNS:localhost,DNS:public.sandbox.test",
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

async function listen(server: net.Server | tls.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
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
