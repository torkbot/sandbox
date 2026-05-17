import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import http from "node:http";
import https from "node:https";
import { resolve } from "node:path";
import { rootCertificates } from "node:tls";
import { Binary, BSON } from "bson";
import type { HostControlChannel } from "./control.ts";
import type { NativeSpawnSandboxOptions } from "./native.ts";
import { isSandboxWritableFileSystem } from "./vfs.ts";
import type {
  HttpPolicyRequest,
  SandboxOptions,
  SandboxFileSystem,
  SandboxPosixFileSystem,
} from "./index.ts";

const DEFAULT_PROTECTED_RANGES = [
  "10.0.0.0/8",
  "100.64.0.0/10",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.168.0.0/16",
] as const;

export class HostProcessSandboxVm implements HostControlChannel {
  readonly hasControlSocket = true;

  readonly #child: ChildProcessWithoutNullStreams;
  readonly #options: SandboxOptions;
  readonly #packets: Uint8Array[] = [];
  readonly #hostFs = new Map<string, SandboxFileSystem>();
  #buffer = new Uint8Array();
  #stderr = "";
  #closed = false;
  #exitError: Error | null = null;

  private constructor(
    child: ChildProcessWithoutNullStreams,
    options: SandboxOptions,
  ) {
    this.#child = child;
    this.#options = options;
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
    const child = spawn(hostBinaryPath(), ["--stdio"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const vm = new HostProcessSandboxVm(child, options);
    await Promise.race([
      once(child, "spawn"),
      once(child, "error").then(([error]) => {
        throw error;
      }),
    ]);
    child.stdin.write(encodeHostSpawn(nativeOptions));
    return vm;
  }

  writeControlPacket(packet: Uint8Array): void {
    this.#assertOpen();
    this.#child.stdin.write(packet);
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
      return;
    }

    this.#child.kill("SIGKILL");
    await Promise.race([
      exited,
      delay(1_000),
    ]);
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
    if (this.#exitError !== null) {
      throw this.#exitError;
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
    if (type === "host.http.request") {
      void this.#handleHttpRequest(document);
      return true;
    }

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
          this.#child.stdin.write(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await fileSystem.stat(path),
          }));
          return;
        }
        case "host.vfs.list": {
          const path = assertString(document.path, "path");
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
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
          this.#child.stdin.write(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            target: await posix.readlink(path),
          }));
          return;
        }
      }
    } catch (error) {
      this.#child.stdin.write(encodePacket({
        type: "host.vfs.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }

  async #handleHttpRequest(document: Record<string, unknown>): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const interception = this.#options.network?.http;
      if (interception === undefined) {
        throw new Error("HTTP interception is not configured");
      }

      const headers = headersFromWire(document.headers);
      const request: HttpPolicyRequest = {
        method: assertString(document.method, "method"),
        url: assertString(document.url, "url"),
        destinationIp: assertString(document.destinationIp, "destinationIp"),
        headers,
        tls: tlsFromWire(document.tls),
      };
      if (isProtectedDestination(request.destinationIp, [
        ...DEFAULT_PROTECTED_RANGES,
        ...(interception.protectedRanges ?? []),
      ])) {
        this.#child.stdin.write(encodePacket({
          type: "host.http.response",
          id,
          ok: true,
          status: 403,
          headers: [{ name: "content-type", value: "text/plain" }],
          body: new TextEncoder().encode("protected destination"),
        }));
        return;
      }

      const decision = await interception.policy(request);
      if (decision.action === "deny") {
        this.#child.stdin.write(encodePacket({
          type: "host.http.response",
          id,
          ok: true,
          status: 451,
          headers: [{ name: "content-type", value: "text/plain" }],
          body: new TextEncoder().encode(decision.reason),
        }));
        return;
      }

      const outboundHeaders = decision.headers ?? headers;
      if (request.tls === undefined) {
        this.#child.stdin.write(encodePacket({
          type: "host.http.response",
          id,
          ok: true,
          status: 0,
          headers: responseHeadersFromRecord(outboundHeaders),
          body: new Uint8Array(),
        }));
        return;
      }

      const upstream = await requestUpstream(request.url, {
        method: request.method,
        headers: outboundHeaders,
        body: request.method === "GET" || request.method === "HEAD"
          ? undefined
          : binaryField(document.body, "body"),
        extraCaCertificatePem: interception.ca === "ephemeral"
          ? undefined
          : interception.ca?.certificatePem,
      });
      this.#child.stdin.write(encodePacket({
        type: "host.http.response",
        id,
        ok: true,
        status: upstream.status,
        headers: responseHeadersFromNode(upstream.headers),
        body: upstream.body,
      }));
    } catch (error) {
      this.#child.stdin.write(encodePacket({
        type: "host.http.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }
}

function responseHeadersFromRecord(headers: Record<string, string>): { name: string; value: string }[] {
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
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

function headersFromWire(value: unknown): Record<string, string> {
  if (!Array.isArray(value)) {
    throw new Error("host HTTP request headers must be an array");
  }

  const headers: Record<string, string> = {};
  for (const entry of value) {
    if (typeof entry !== "object" || entry === null) {
      throw new Error("host HTTP request header must be an object");
    }
    const record = entry as Record<string, unknown>;
    headers[assertString(record.name, "header.name")] = assertString(record.value, "header.value");
  }
  return headers;
}

function tlsFromWire(value: unknown): HttpPolicyRequest["tls"] {
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value !== "object") {
    throw new TypeError("tls must be an object");
  }
  const record = value as Record<string, unknown>;
  return {
    serverName: optionalString(record.serverName, "tls.serverName"),
    alpnProtocol: optionalString(record.alpnProtocol, "tls.alpnProtocol"),
    protocol: optionalString(record.protocol, "tls.protocol"),
  };
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new TypeError(`${field} must be a string`);
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

async function requestUpstream(url: string, input: {
  readonly method: string;
  readonly headers: Record<string, string>;
  readonly body?: Uint8Array;
  readonly extraCaCertificatePem?: string;
}): Promise<{
  readonly status: number;
  readonly headers: http.IncomingHttpHeaders;
  readonly body: Uint8Array;
}> {
  const parsed = new URL(url);
  const client = parsed.protocol === "https:" ? https : http;
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`unsupported upstream URL protocol: ${parsed.protocol}`);
  }

  return await new Promise((resolvePromise, reject) => {
    const request = client.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname,
      port: parsed.port,
      path: `${parsed.pathname}${parsed.search}`,
      method: input.method,
      headers: outboundRequestHeaders(input.headers),
      ca: parsed.protocol === "https:" && input.extraCaCertificatePem !== undefined
        ? [...rootCertificates, input.extraCaCertificatePem]
        : undefined,
    }, (response) => {
      const chunks: Uint8Array[] = [];
      response.on("data", (chunk: Uint8Array) => {
        chunks.push(chunk);
      });
      response.once("aborted", () => {
        reject(new Error("upstream response aborted"));
      });
      response.once("error", reject);
      response.on("end", () => {
        resolvePromise({
          status: response.statusCode ?? 502,
          headers: response.headers,
          body: concatBytes(chunks),
        });
      });
    });
    request.setTimeout(2_000, () => {
      request.destroy(new Error("upstream request timed out"));
    });
    request.once("error", reject);
    if (input.body !== undefined) {
      request.write(input.body);
    }
    request.end();
  });
}

function outboundRequestHeaders(headers: Record<string, string>): Record<string, string> {
  const hopByHop = new Set([
    "connection",
    "content-length",
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

function concatBytes(chunks: readonly Uint8Array[]): Uint8Array {
  const size = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function responseHeadersFromNode(headers: http.IncomingHttpHeaders): { name: string; value: string }[] {
  const hopByHop = new Set([
    "connection",
    "content-length",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);
  const result: { name: string; value: string }[] = [];
  for (const [name, value] of Object.entries(headers)) {
    if (hopByHop.has(name.toLowerCase()) || value === undefined) {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        result.push({ name, value: item });
      }
    } else {
      result.push({ name, value });
    }
  }
  return result;
}

function isProtectedDestination(destinationIp: string, ranges: readonly string[]): boolean {
  const destination = ipv4ToInt(destinationIp);
  if (destination === null) {
    return false;
  }

  return ranges.some((range) => {
    const [address, prefixText] = range.split("/");
    if (address === undefined || prefixText === undefined) {
      return false;
    }
    const network = ipv4ToInt(address);
    const prefix = Number(prefixText);
    if (network === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (destination & mask) === (network & mask);
  });
}

function ipv4ToInt(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) {
    return null;
  }

  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      return null;
    }
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
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
    networkHttp: options.network?.http === undefined
      ? undefined
      : {
          protectedRanges: options.network.http.protectedRanges ?? [],
          caCertificatePem: options.network.http.caCertificatePem,
          caPrivateKeyPem: options.network.http.caPrivateKeyPem,
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
