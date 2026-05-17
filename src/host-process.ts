import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { BSON } from "bson";
import type { HostControlChannel } from "./control.ts";
import type { NativeSpawnSandboxOptions } from "./native.ts";
import type {
  HttpPolicyRequest,
  SandboxOptions,
  SandboxVirtualFileSystem,
} from "./index.ts";

export class HostProcessSandboxVm implements HostControlChannel {
  readonly hasControlSocket = true;

  readonly #child: ChildProcessWithoutNullStreams;
  readonly #options: SandboxOptions;
  readonly #packets: Uint8Array[] = [];
  readonly #virtualFs = new Map<string, SandboxVirtualFileSystem>();
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
        this.#virtualFs.set(mount.path, mount.fileSystem);
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

    if (type !== "host.vfs.stat" && type !== "host.vfs.list" && type !== "host.vfs.read") {
      return false;
    }

    void this.#handleVirtualFsRequest(document);
    return true;
  }

  async #handleVirtualFsRequest(document: Record<string, unknown>): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const mountPath = assertString(document.mountPath, "mountPath");
      const path = assertString(document.path, "path");
      const fileSystem = this.#virtualFs.get(mountPath);
      if (fileSystem === undefined) {
        throw new Error(`virtualFs mount not found: ${mountPath}`);
      }

      switch (document.type) {
        case "host.vfs.stat": {
          this.#child.stdin.write(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await fileSystem.stat(path),
          }));
          return;
        }
        case "host.vfs.list": {
          this.#child.stdin.write(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            entries: await fileSystem.list(path),
          }));
          return;
        }
        case "host.vfs.read": {
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
      const http = this.#options.network?.http;
      if (http === undefined) {
        throw new Error("HTTP interception is not configured");
      }

      const headers = headersFromWire(document.headers);
      const request: HttpPolicyRequest = {
        method: assertString(document.method, "method"),
        url: assertString(document.url, "url"),
        destinationIp: assertString(document.destinationIp, "destinationIp"),
        headers,
      };
      const decision = await http.policy(request);
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

      const outboundHeaders = http.modifyRequestHeaders === undefined
        ? headers
        : await http.modifyRequestHeaders(headers);
      const upstream = await fetch(request.url, {
        method: request.method,
        headers: outboundHeaders,
        body: request.method === "GET" || request.method === "HEAD"
          ? undefined
          : binaryField(document.body, "body"),
      });
      this.#child.stdin.write(encodePacket({
        type: "host.http.response",
        id,
        ok: true,
        status: upstream.status,
        headers: responseHeadersFromFetch(upstream.headers),
        body: new Uint8Array(await upstream.arrayBuffer()),
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

function binaryField(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  throw new Error(`host HTTP request ${field} must be binary`);
}

function responseHeadersFromFetch(headers: Headers): { name: string; value: string }[] {
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
  return Array.from(headers.entries())
    .filter(([name]) => !hopByHop.has(name.toLowerCase()))
    .map(([name, value]) => ({ name, value }));
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
