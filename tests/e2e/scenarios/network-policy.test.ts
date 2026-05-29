import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { networkInterfaces, tmpdir } from "node:os";
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
  const observedHeaders: string[] = [];
  const origin = await startTcpServer((socket) => {
    socket.once("data", (chunk) => {
      const request = chunk.toString("utf8");
      observedHeaders.push(request.match(/^x-sandbox-policy: (.+)$/im)?.[1] ?? "");
      socket.end("HTTP/1.1 200 OK\r\ncontent-length: 7\r\nconnection: close\r\n\r\nhttp-ok");
    });
  });
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      if (conn.protocol === "http") {
        conn.allowHttp((request) => {
          request.headers.set("x-sandbox-policy", "allowed");
        });
      } else {
        conn.allow();
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

test("network.policy rejects untrusted HTTPS upstream certificates", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const origin = await startTlsHttpServer();
  t.after(() => void origin.close());

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy(async (conn) => {
      if (conn.transport === "tcp" && conn.protocol !== "http") {
        conn.allow();
        return;
      }
      if (conn.transport === "udp" && conn.dst.port === 53) {
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
    script: `curl -kfsS --max-time 5 https://${hostOriginAddress()}:${origin.port}/`,
  }), 10_000, "HTTPS middleware request");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
  assert.deepEqual(origin.requests, []);
});

test("network.policy denies private HTTP by destination range before origin access", async (t) => {
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
    script: `curl -fsS --max-time 3 http://${hostOriginAddress()}:${origin.port}/`,
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
    script: pythonTcpRefused(echo.port),
  }), 8_000, "denied raw TCP echo");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "ECONNREFUSED");
  assert.equal(echo.connections.length, 0);
});

test("network.policy fails closed when the transport hook throws", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
  const echo = await startTcpServer((socket) => {
    socket.on("data", (chunk) => socket.write(chunk));
  });
  t.after(() => void echo.close());

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
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
      `${hostOriginAddress()} true`,
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
      `${hostOriginAddress()} true`,
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
    script: pythonTcpExchange(redis.port, "PING\r\n"),
  }), 10_000, "Redis-style TCP exchange");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "+PONG\r\n");
  assert.ok(redis.connections.length >= 1);
});

test("network.policy raw-relays token-space TCP commands without HTTP framing", async (t) => {
  if (!requireVmLaunchSupport(t)) return;
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

  await using sandbox = await bootAllowingNetwork();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "token-space-raw-tcp",
    script: pythonTcpExchange(commandServer.port, "GET key\r\n"),
  }), 10_000, "token-space raw TCP exchange");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "VALUE key 0 5\r\nvalue\r\nEND\r\n");
  assert.ok(commandServer.connections.length >= 1);
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

test("network.policy allows default DNS over UDP with the DNS hook", async (t) => {
  if (!requireVmLaunchSupport(t)) return;

  await using sandbox = await bootAllowingDns();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-udp-default",
    script: pythonDnsQuery({ transport: "udp", name: "localhost" }),
  }), 8_000, "default UDP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1");
});

test("network.policy supports a custom DNS resolver over UDP", async (t) => {
  if (!requireVmLaunchSupport(t)) return;

  await using sandbox = await bootWithCustomDns("203.0.113.10");
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-udp-custom",
    script: pythonDnsQuery({ transport: "udp", name: "custom.sandbox.test" }),
  }), 8_000, "custom UDP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.10");
});

test("network.policy allows default DNS over TCP with the DNS hook", async (t) => {
  if (!requireVmLaunchSupport(t)) return;

  await using sandbox = await bootAllowingDns();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-tcp-default",
    script: pythonDnsQuery({ transport: "tcp", name: "localhost" }),
  }), 8_000, "default TCP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1");
});

test("network.policy keeps DNS over TCP sessions reusable", async (t) => {
  if (!requireVmLaunchSupport(t)) return;

  await using sandbox = await bootAllowingDns();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-tcp-reuse",
    script: pythonTcpDnsTwoQueries("localhost", "localhost"),
  }), 8_000, "reused TCP DNS queries");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "127.0.0.1,127.0.0.1");
});

test("network.policy supports a custom DNS resolver over TCP", async (t) => {
  if (!requireVmLaunchSupport(t)) return;

  await using sandbox = await bootWithCustomDns("203.0.113.20");
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-tcp-custom",
    script: pythonDnsQuery({ transport: "tcp", name: "custom.sandbox.test" }),
  }), 8_000, "custom TCP DNS query");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.20");
});

test("network.policy fails closed when the DNS hook throws", async (t) => {
  if (!requireVmLaunchSupport(t)) return;

  await using sandbox = await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      if (conn.protocol === "dns") {
        throw new Error("dns policy failed");
      }
      conn.allow();
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "dns-policy-error-deny",
    script: pythonDnsQuery({ transport: "udp", name: "localhost" }),
  }), 8_000, "DNS policy error");

  assert.notEqual(result.exitCode, 0, commandOutput(result));
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
    readonly transport: string;
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
      if (conn.protocol === "dns") {
        conn.allowDns(() => ({
          answers: [
            {
              type: "A",
              address: "203.0.113.30",
              ttl: 60,
            },
          ],
        }));
      }
    }),
  }).boot();
  const result = await withTimeout(execGuestShell(sandbox, {
    id: "endpoint-observations",
    script: pythonDnsQuery({ transport: "udp", name: "custom.sandbox.test" }),
  }), 8_000, "endpoint helper observation");

  assert.equal(result.exitCode, 0, commandOutput(result));
  assert.equal(result.stdout, "203.0.113.30");
  assert.ok(observations.some((entry) => {
    return entry.transport === "udp"
      && entry.protocol === "dns"
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

async function bootAllowingDns() {
  return await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      if (conn.protocol === "dns") {
        assert.equal(conn.questions[0]?.name, "localhost");
        conn.allowDns();
      }
    }),
  }).boot();
}

async function bootWithCustomDns(address: string) {
  return await defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
    network: network.policy((conn) => {
      if (conn.protocol === "dns") {
        conn.allowDns((request) => {
          assert.equal(request.questions[0]?.name, "custom.sandbox.test");
          return {
            answers: [
              {
                type: "A",
                address,
                ttl: 60,
              },
            ],
          };
        });
      }
    }),
  }).boot();
}

function observation(conn: NetworkConnectionRequest) {
  return {
    transport: conn.transport,
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
  return `python3 - <<'PY'\nimport socket\ns = socket.create_connection((${JSON.stringify(hostOriginAddress())}, ${port}), timeout=3)\ns.settimeout(3)\ns.sendall(${JSON.stringify(message)}.encode())\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
}

function pythonTcpRefused(port: number): string {
  return `python3 - <<'PY'\nimport errno, socket\ntry:\n    socket.create_connection((${JSON.stringify(hostOriginAddress())}, ${port}), timeout=3)\nexcept OSError as error:\n    print(errno.errorcode.get(getattr(error, "errno", None), type(error).__name__), end="")\nPY`;
}

function pythonTlsExchange(port: number, message: string): string {
  return `python3 - <<'PY'\nimport socket, ssl\nctx = ssl._create_unverified_context()\nraw = socket.create_connection((${JSON.stringify(hostOriginAddress())}, ${port}), timeout=3)\ns = ctx.wrap_socket(raw, server_hostname="localhost")\ns.settimeout(3)\ns.sendall(${JSON.stringify(message)}.encode())\nprint(s.recv(4096).decode(), end="")\ns.close()\nPY`;
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

async function startTcpServer(onConnection: (socket: net.Socket) => void): Promise<{
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

async function listen(server: net.Server | tls.Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "0.0.0.0", () => {
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
