import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { lookup } from "node:dns/promises";
import { once } from "node:events";
import { existsSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import net, { BlockList, isIP, type Socket } from "node:net";
import { resolve } from "node:path";
import { Binary, BSON } from "bson";
import type { HostControlChannel } from "./control.ts";
import type { NativeSpawnSandboxOptions } from "./native.ts";
import { isSandboxWritableFileSystem } from "./vfs.ts";
import type {
  HttpPolicyRequest,
  OutboundNetworkRule,
  SandboxOptions,
  SandboxFileSystem,
  SandboxPosixFileSystem,
} from "./index.ts";

const DEFAULT_PROTECTED_RANGES = [
  "0.0.0.0/8",
  "127.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.88.99.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4",
  "255.255.255.255/32",
  "::1/128",
  "fc00::/7",
  "fe80::/10",
] as const;

type ProxyMetadata = {
  readonly destinationIp: string;
  readonly destinationPort: number;
  readonly tls?: HttpPolicyRequest["tls"];
};

class HostHttpProxy {
  readonly #options: SandboxOptions;
  readonly #metadata = new WeakMap<Socket, ProxyMetadata>();
  readonly #sockets = new Set<Socket>();
  readonly #httpServer: http.Server;
  readonly #netServer: net.Server;

  private constructor(options: SandboxOptions) {
    this.#options = options;
    this.#httpServer = http.createServer((request, response) => {
      void this.#handleRequest(request, response);
    });
    this.#netServer = net.createServer((socket) => {
      this.#handleConnection(socket);
    });
  }

  static async start(options: SandboxOptions): Promise<{ readonly port: number; close(): Promise<void> }> {
    const proxy = new HostHttpProxy(options);
    proxy.#netServer.listen(0, "127.0.0.1");
    await once(proxy.#netServer, "listening");
    const address = proxy.#netServer.address();
    if (address === null || typeof address === "string") {
      throw new Error("HTTP proxy did not bind a TCP port");
    }
    return {
      port: address.port,
      async close() {
        for (const socket of proxy.#sockets) {
          socket.destroy();
        }
        await closeServer(proxy.#netServer);
      },
    };
  }

  #handleConnection(socket: Socket): void {
    this.#sockets.add(socket);
    socket.once("close", () => {
      this.#sockets.delete(socket);
    });

    let buffer = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      const lineEnd = buffer.indexOf(0x0a);
      if (lineEnd === -1) {
        return;
      }
      socket.off("data", onData);
      const line = buffer.subarray(0, lineEnd).toString("utf8");
      const metadata = parseProxyPreface(line);
      if (metadata === null) {
        socket.destroy();
        return;
      }
      this.#metadata.set(socket, metadata);
      const rest = buffer.subarray(lineEnd + 1);
      if (rest.byteLength > 0) {
        socket.unshift(rest);
      }
      this.#httpServer.emit("connection", socket);
    };
    socket.on("data", onData);
  }

  async #handleRequest(request: http.IncomingMessage, response: http.ServerResponse): Promise<void> {
    const metadata = this.#metadata.get(request.socket);
    const interception = this.#options.network?.http;
    if (metadata === undefined || interception === undefined) {
      response.writeHead(502, { "content-type": "text/plain" });
      response.end("upstream unavailable");
      return;
    }

    try {
      const headers = normalizeIncomingHeaders(request.headers);
      const url = requestUrl(request, metadata);
      const policyRequest: HttpPolicyRequest = {
        method: request.method ?? "GET",
        url,
        destinationIp: metadata.destinationIp,
        destinationPort: metadata.destinationPort,
        headers,
        ...(metadata.tls === undefined ? {} : { tls: metadata.tls }),
      };
      const outboundRules = this.#options.network?.outbound?.rules;
      const protection = outboundRules === undefined
        ? { blocked: false as const }
        : await inspectHttpProtection(policyRequest, outboundRules);
      if (protection.blocked) {
        response.writeHead(403, { "content-type": "text/plain" });
        response.end("outbound denied");
        return;
      }

      const decision = await interception.policy(policyRequest);
      if (decision.action === "deny") {
        if (typeof decision.reason !== "string") {
          throw new Error("HTTP policy deny action must include a string reason");
        }
        response.writeHead(451, { "content-type": "text/plain" });
        response.end(decision.reason);
        return;
      }
      if (decision.action !== "allow") {
        throw new Error(`HTTP policy returned unsupported action: ${String((decision as { action?: unknown }).action)}`);
      }
      if (protection.unresolved) {
        response.writeHead(502, { "content-type": "text/plain" });
        response.end("upstream unavailable");
        return;
      }

      const upstream = createUpstreamRequest(policyRequest.url, {
        method: policyRequest.method,
        headers: decision.headers ?? headers,
        upstreamIp: protection.upstreamIp,
      }, (upstreamResponse) => {
        response.writeHead(
          upstreamResponse.statusCode ?? 502,
          responseHeadersForProxy(upstreamResponse.headers),
        );
        upstreamResponse.pipe(response);
      });
      upstream.setTimeout(2_000, () => {
        upstream.destroy(new Error("upstream request timed out"));
      });
      upstream.once("error", () => {
        if (!response.headersSent) {
          response.writeHead(502, { "content-type": "text/plain" });
          response.end("upstream unavailable");
        } else {
          response.destroy();
        }
      });
      request.pipe(upstream);
    } catch (error) {
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "text/plain" });
        response.end(error instanceof Error ? error.message : String(error));
      } else {
        response.destroy();
      }
    }
  }
}

export class HostProcessSandboxVm implements HostControlChannel {
  readonly hasControlSocket = true;

  readonly #child: ChildProcessWithoutNullStreams;
  readonly #options: SandboxOptions;
  readonly #httpProxy?: { close(): Promise<void> };
  readonly #packets: Uint8Array[] = [];
  readonly #hostFs = new Map<string, SandboxFileSystem>();
  #buffer = new Uint8Array();
  #stderr = "";
  #closed = false;
  #exitError: Error | null = null;
  #stdinError: Error | null = null;

  private constructor(
    child: ChildProcessWithoutNullStreams,
    options: SandboxOptions,
    httpProxy?: { close(): Promise<void> },
  ) {
    this.#child = child;
    this.#options = options;
    this.#httpProxy = httpProxy;
    for (const mount of options.mounts ?? []) {
      if (mount.kind === "virtual-fs") {
        this.#hostFs.set(mount.path, mount.fileSystem);
      }
    }
    child.stdout.on("data", (chunk: Buffer) => {
      this.#receive(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8").trim();
      if (text.length > 0) {
        this.#stderr = this.#stderr.length === 0 ? text : `${this.#stderr}\n${text}`;
      }
    });
    child.stdin.on("error", (error: Error) => {
      this.#stdinError = error;
      if (this.#exitError === null) {
        this.#exitError = new Error(`sandbox-host stdin failed: ${error.message}`);
      }
    });
    child.on("exit", (code, signal) => {
      if (this.#closed) {
        return;
      }

      const exitText =
        signal === null
          ? `sandbox-host exited with ${code ?? "unknown status"}`
          : `sandbox-host exited from signal ${signal}`;
      this.#exitError = new Error(
        this.#stderr.length === 0 ? exitText : `${exitText}\n${this.#stderr}`,
      );
    });
  }

  static async spawn(
    options: SandboxOptions,
    nativeOptions: NativeSpawnSandboxOptions,
  ): Promise<HostProcessSandboxVm> {
    const httpProxy = options.network?.http === undefined
      ? undefined
      : await HostHttpProxy.start(options);
    try {
      const child = spawn(hostBinaryPath(), ["--stdio"], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      const vm = new HostProcessSandboxVm(child, options, httpProxy);
      await Promise.race([
        once(child, "spawn"),
        once(child, "error").then(([error]) => {
          throw error;
        }),
      ]);
      vm.#writeToHost(encodeHostSpawn(withHostProxyPort(nativeOptions, httpProxy?.port)));
      return vm;
    } catch (error) {
      await httpProxy?.close();
      throw error;
    }
  }

  writeControlPacket(packet: Uint8Array): void {
    this.#assertOpen();
    this.#writeToHost(packet);
  }

  tryReadControlPacket(): Uint8Array | null {
    this.#assertOpen();
    return this.#packets.shift() ?? null;
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    const exited = this.#child.exitCode !== null || this.#child.signalCode !== null
      ? Promise.resolve()
      : once(this.#child, "exit").then(() => undefined);

    this.#child.stdin.destroy();
    this.#child.kill("SIGTERM");
    await Promise.race([
      exited,
      delay(500),
    ]);

    if (this.#child.exitCode !== null || this.#child.signalCode !== null) {
      await this.#httpProxy?.close();
      return;
    }

    this.#child.kill("SIGKILL");
    await Promise.race([
      exited,
      delay(1_000),
    ]);
    await this.#httpProxy?.close();
  }

  async terminateHostForTest(): Promise<void> {
    if (this.#child.exitCode !== null || this.#child.signalCode !== null) {
      return;
    }

    const exited = once(this.#child, "exit").then(() => undefined);
    this.#child.kill("SIGTERM");
    await Promise.race([
      exited,
      delay(1_000),
    ]);
    if (this.#child.exitCode !== null || this.#child.signalCode !== null) {
      return;
    }

    this.#child.kill("SIGKILL");
    await exited;
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new Error("sandbox VM is closed");
    }
    if (this.#stdinError !== null) {
      throw this.#stdinError;
    }
    if (this.#exitError !== null) {
      throw this.#exitError;
    }
  }

  #writeToHost(packet: Uint8Array): void {
    this.#assertOpen();
    this.#writeOpenPacket(packet);
  }

  #writeOpenPacket(packet: Uint8Array): void {
    if (!this.#child.stdin.writable) {
      throw new Error("sandbox-host stdin is closed");
    }
    this.#child.stdin.write(packet, (error) => {
      if (error !== null && error !== undefined) {
        this.#stdinError = error;
        if (this.#exitError === null) {
          this.#exitError = new Error(`sandbox-host stdin failed: ${error.message}`);
        }
      }
    });
  }

  #tryWriteToHost(packet: Uint8Array): void {
    if (this.#closed || this.#stdinError !== null || this.#exitError !== null) {
      return;
    }
    try {
      this.#writeOpenPacket(packet);
    } catch (error) {
      if (!this.#closed && this.#stdinError === null && this.#exitError === null) {
        throw error;
      }
    }
  }

  #receive(chunk: Uint8Array): void {
    const next = new Uint8Array(this.#buffer.byteLength + chunk.byteLength);
    next.set(this.#buffer);
    next.set(chunk, this.#buffer.byteLength);
    this.#buffer = next;

    while (this.#buffer.byteLength >= 4) {
      const frameLength = new DataView(this.#buffer.buffer, this.#buffer.byteOffset, 4).getUint32(0, true);
      const packetLength = 4 + frameLength;
      if (this.#buffer.byteLength < packetLength) {
        return;
      }

      const packet = this.#buffer.slice(0, packetLength);
      this.#buffer = this.#buffer.slice(packetLength);
      if (!this.#routeHostPacket(packet)) {
        this.#packets.push(packet);
      }
    }
  }

  #routeHostPacket(packet: Uint8Array): boolean {
    let document: Record<string, unknown>;
    try {
      document = BSON.deserialize(packet.slice(4)) as Record<string, unknown>;
    } catch {
      return false;
    }

    const type = document.type;
    if (
      type !== "host.vfs.stat"
      && type !== "host.vfs.list"
      && type !== "host.vfs.read"
      && type !== "host.vfs.create"
      && type !== "host.vfs.write"
      && type !== "host.vfs.truncate"
      && type !== "host.vfs.mkdir"
      && type !== "host.vfs.unlink"
      && type !== "host.vfs.rmdir"
      && type !== "host.vfs.rename"
      && type !== "host.vfs.symlink"
      && type !== "host.vfs.readlink"
    ) {
      return false;
    }

    void this.#handleVirtualFsRequest(document);
    return true;
  }

  async #handleVirtualFsRequest(document: Record<string, unknown>): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const mountPath = assertString(document.mountPath, "mountPath");
      const fileSystem = this.#hostFs.get(mountPath);
      if (fileSystem === undefined) {
        throw new Error(`host filesystem mount not found: ${mountPath}`);
      }

      switch (document.type) {
        case "host.vfs.stat": {
          const path = assertString(document.path, "path");
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await fileSystem.stat(path),
          }));
          return;
        }
        case "host.vfs.list": {
          const path = assertString(document.path, "path");
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            entries: await fileSystem.list(path),
          }));
          return;
        }
        case "host.vfs.read": {
          const path = assertString(document.path, "path");
          const offset = assertNumber(document.offset, "offset");
          const size = assertNumber(document.size, "size");
          const contents = await fileSystem.read({
            path,
            range: { offset, length: size },
            signal: AbortSignal.timeout(30_000),
          });
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            contents,
          }));
          return;
        }
        case "host.vfs.create": {
          const path = assertString(document.path, "path");
          if (!isSandboxWritableFileSystem(fileSystem)) {
            throw new Error(`host filesystem mount is read-only: ${mountPath}`);
          }
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await fileSystem.createFile(path),
          }));
          return;
        }
        case "host.vfs.write": {
          const path = assertString(document.path, "path");
          if (!isSandboxWritableFileSystem(fileSystem)) {
            throw new Error(`host filesystem mount is read-only: ${mountPath}`);
          }
          const offset = assertNumber(document.offset, "offset");
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            written: await fileSystem.write({
              path,
              offset,
              contents: binaryField(document.contents, "contents"),
            }),
          }));
          return;
        }
        case "host.vfs.truncate": {
          const path = assertString(document.path, "path");
          if (!isSandboxWritableFileSystem(fileSystem)) {
            throw new Error(`host filesystem mount is read-only: ${mountPath}`);
          }
          const size = assertNumber(document.size, "size");
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await fileSystem.truncate(path, size),
          }));
          return;
        }
        case "host.vfs.mkdir": {
          const path = assertString(document.path, "path");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await posix.mkdir(path),
          }));
          return;
        }
        case "host.vfs.unlink": {
          const path = assertString(document.path, "path");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          await posix.unlink(path);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
          }));
          return;
        }
        case "host.vfs.rmdir": {
          const path = assertString(document.path, "path");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          await posix.rmdir(path);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
          }));
          return;
        }
        case "host.vfs.rename": {
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          const from = assertString(document.from, "from");
          const to = assertString(document.to, "to");
          const flags = assertNumber(document.flags, "flags");
          await posix.rename(from, to, flags);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
          }));
          return;
        }
        case "host.vfs.symlink": {
          const path = assertString(document.path, "path");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          const target = assertString(document.target, "target");
          const stat = await posix.symlink(target, path);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat,
          }));
          return;
        }
        case "host.vfs.readlink": {
          const path = assertString(document.path, "path");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            target: await posix.readlink(path),
          }));
          return;
        }
      }
    } catch (error) {
      this.#tryWriteToHost(encodePacket({
        type: "host.vfs.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }

}

function parseProxyPreface(line: string): ProxyMetadata | null {
  const [magic, version, destinationIp, portText, serverName, alpnProtocol, protocol] = line.split(" ");
  if (magic !== "SANDBOX_HTTP_PROXY" || version !== "1") {
    return null;
  }
  const destinationPort = Number(portText);
  if (destinationIp === undefined || !Number.isInteger(destinationPort) || destinationPort < 1 || destinationPort > 65_535) {
    return null;
  }
  const tls = serverName === "-" && alpnProtocol === "-" && protocol === "-"
    ? undefined
    : {
        serverName: serverName === "-" ? undefined : serverName,
        alpnProtocol: alpnProtocol === "-" ? undefined : alpnProtocol,
        protocol: protocol === "-" ? undefined : protocol,
      };
  return { destinationIp, destinationPort, ...(tls === undefined ? {} : { tls }) };
}

function requestUrl(request: http.IncomingMessage, metadata: ProxyMetadata): string {
  const target = request.url ?? "/";
  if (target.startsWith("http://") || target.startsWith("https://")) {
    return target;
  }
  const host = request.headers.host ?? metadata.destinationIp;
  return `${metadata.tls === undefined ? "http" : "https"}://${host}${target}`;
}

function normalizeIncomingHeaders(headers: http.IncomingHttpHeaders): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) {
      continue;
    }
    result[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return result;
}

function createUpstreamRequest(
  url: string,
  input: {
    readonly method: string;
    readonly headers: Record<string, string>;
    readonly upstreamIp?: string;
  },
  onResponse: (response: http.IncomingMessage) => void,
): http.ClientRequest {
  const parsed = new URL(url);
  const client = parsed.protocol === "https:" ? https : http;
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`unsupported upstream URL protocol: ${parsed.protocol}`);
  }
  return client.request({
    protocol: parsed.protocol,
    hostname: input.upstreamIp ?? parsed.hostname,
    port: parsed.port,
    path: `${parsed.pathname}${parsed.search}`,
    method: input.method,
    headers: outboundRequestHeaders(input.headers),
    servername: parsed.protocol === "https:" && isIP(parsed.hostname) === 0
      ? parsed.hostname
      : undefined,
    rejectUnauthorized: parsed.protocol === "https:" && parsed.hostname === "127.0.0.1"
      ? false
      : undefined,
  }, onResponse);
}

function responseHeadersForProxy(headers: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
  const result: http.OutgoingHttpHeaders = {};
  const hopByHop = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "upgrade"]);
  for (const [name, value] of Object.entries(headers)) {
    if (!hopByHop.has(name.toLowerCase()) && value !== undefined) {
      result[name] = value;
    }
  }
  return result;
}

function closeServer(server: net.Server | http.Server): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    server.close((error?: Error) => {
      if (error !== undefined) {
        reject(error);
      } else {
        resolvePromise();
      }
    });
  });
}

function withHostProxyPort(
  options: NativeSpawnSandboxOptions,
  port: number | undefined,
): NativeSpawnSandboxOptions {
  if (port === undefined || options.network === undefined) {
    return options;
  }
  return {
    ...options,
    network: {
      ...options.network,
      http: {
        ...options.network.http,
        hostProxyPort: port,
      },
    },
  };
}

export function hostBinaryPath(): string {
  const path = resolve(import.meta.dirname, "../target/release/sandbox-host");
  if (!existsSync(path)) {
    throw new Error(`sandbox-host is not built: ${path}`);
  }
  return path;
}

function assertString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`host vfs request ${field} must be a string`);
  }
  return value;
}

function assertNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`host vfs request ${field} must be a non-negative safe integer`);
  }
  return value;
}

function binaryField(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (value instanceof Binary) {
    return value.buffer;
  }
  throw new Error(`host request ${field} must be binary`);
}

function assertPosixFileSystem(
  fileSystem: SandboxFileSystem,
  mountPath: string,
): SandboxPosixFileSystem {
  const candidate = fileSystem as Partial<SandboxPosixFileSystem>;
  if (
    !isSandboxWritableFileSystem(fileSystem)
    || typeof candidate.mkdir !== "function"
    || typeof candidate.unlink !== "function"
    || typeof candidate.rmdir !== "function"
    || typeof candidate.rename !== "function"
    || typeof candidate.symlink !== "function"
    || typeof candidate.readlink !== "function"
  ) {
    throw new Error(`host filesystem mount does not support POSIX mutations: ${mountPath}`);
  }
  return candidate as SandboxPosixFileSystem;
}

function outboundRequestHeaders(headers: Record<string, string>): Record<string, string> {
  const hopByHop = new Set([
    "connection",
    "content-length",
    "expect",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);
  const result: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (!hopByHop.has(name.toLowerCase())) {
      result[name] = value;
    }
  }
  return result;
}

function isProtectedDestination(destinationIp: string, ranges: readonly string[]): boolean {
  const destinationFamily = ipFamily(destinationIp);
  if (destinationFamily === null) {
    return false;
  }

  const blockList = new BlockList();
  for (const range of ranges) {
    const [address, prefixText] = range.split("/");
    if (address === undefined || prefixText === undefined) {
      continue;
    }
    const prefix = Number(prefixText);
    const rangeFamily = ipFamily(address);
    const maxPrefix = rangeFamily === "ipv6" ? 128 : 32;
    if (rangeFamily === null || !Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
      continue;
    }
    blockList.addSubnet(address, prefix, rangeFamily);
  }
  return blockList.check(destinationIp, destinationFamily);
}

async function inspectHttpProtection(
  request: HttpPolicyRequest,
  rules: readonly OutboundNetworkRule[],
): Promise<{ readonly blocked: boolean; readonly unresolved?: boolean; readonly upstreamIp?: string }> {
  const parsed = new URL(request.url);
  const upstreamPort = parsed.port.length === 0
    ? (parsed.protocol === "https:" ? 443 : 80)
    : Number(parsed.port);

  if (!isAllowedTcpDestination(request.destinationIp, request.destinationPort, rules)) {
    return { blocked: true };
  }

  const resolvedAddresses = await resolveUrlAddresses(request.url);
  const addresses = resolvedAddresses.length === 0
    ? [request.destinationIp]
    : resolvedAddresses;
  for (const address of addresses) {
    if (!isAllowedTcpDestination(address, upstreamPort, rules)) {
      return { blocked: true };
    }
  }
  return {
    blocked: false,
    ...(addresses[0] === undefined ? {} : { upstreamIp: addresses[0] }),
  };
}

function isAllowedTcpDestination(
  address: string,
  port: number,
  rules: readonly OutboundNetworkRule[],
): boolean {
  return rules.some((rule) => {
    if (!portMatches(rule.ports, port)) {
      return false;
    }

    if ("scope" in rule) {
      return isPublicIpv4Destination(address);
    }

    return rule.protocol === "tcp" && isProtectedDestination(address, [rule.cidr]);
  });
}

function isPublicIpv4Destination(address: string): boolean {
  return ipFamily(address) === "ipv4" && !isProtectedDestination(address, DEFAULT_PROTECTED_RANGES);
}

function portMatches(ports: readonly number[] | undefined, port: number): boolean {
  return ports === undefined || ports.length === 0 || ports.includes(port);
}

async function resolveUrlAddresses(url: string): Promise<string[]> {
  const parsed = new URL(url);
  const literal = ipLiteral(parsed.hostname);
  if (literal !== null) {
    return [literal];
  }

  try {
    const records = await lookup(parsed.hostname, { all: true });
    return records
      .map((record) => record.address)
      .filter((address) => ipFamily(address) === "ipv4");
  } catch {
    return [];
  }
}

function ipLiteral(hostname: string): string | null {
  const unbracketed = hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
  return ipFamily(unbracketed) === null ? null : unbracketed;
}

function ipFamily(address: string): "ipv4" | "ipv6" | null {
  const family = isIP(address);
  if (family === 4) {
    return "ipv4";
  }
  if (family === 6) {
    return "ipv6";
  }
  return null;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function encodeHostSpawn(options: NativeSpawnSandboxOptions): Uint8Array {
  return encodePacket({
    type: "host.spawn",
    name: options.name,
    vcpus: options.cpu?.vcpus,
    memoryMib: options.memory?.mib,
    kernelFormat: options.kernel.format,
    initCrate: options.init.crateName,
    rootfsPath: options.rootfs.path,
    rootfsReadonly: options.rootfs.readonly,
    rootfsFormat: options.rootfs.format,
    rootfsOverlayMode: options.rootfsOverlay?.mode,
    mounts: options.mounts ?? [],
    networkOutbound: options.network?.outbound,
    networkHttp: options.network?.http === undefined
      ? undefined
      : {
          hostProxyPort: options.network.http.hostProxyPort,
        },
  });
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document, { ignoreUndefined: true });
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}
