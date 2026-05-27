import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { Binary, BSON } from "bson";
import { hostBinaryPath, macosHostSigningError } from "./artifacts.ts";
import type { HostControlChannel } from "./control.ts";
import type { HostSpawnSandboxOptions } from "./spawn-options.ts";
import { isSandboxWritableFileSystem } from "./vfs.ts";
import type {
  SandboxFileSystem,
  SandboxPosixFileSystem,
} from "./index.ts";
import type {
  InternalSandboxOptions,
  RegisteredHttpRequestHeadersHook,
} from "./launch-options.ts";

const ROOT_OVERLAY_MOUNT_PATH = "__root_overlay__";
const DEFAULT_LAUNCH_TIMEOUT_MS = 60_000;

export class HostProcessSandboxVm implements HostControlChannel {
  readonly hasControlSocket = true;
  readonly packets: AsyncIterable<Uint8Array>;

  readonly #child: ChildProcessWithoutNullStreams;
  readonly #options: InternalSandboxOptions;
  readonly #packets = new AsyncQueue<Uint8Array>();
  readonly #packetActivity = new AsyncSignal();
  readonly #launchReady = new AsyncSignal("sandbox-host launch acknowledgement closed");
  readonly #hostFs = new Map<string, SandboxFileSystem>();
  readonly #requestHeaderHooks: Map<string, RegisteredHttpRequestHeadersHook>;
  #buffer = new Uint8Array();
  #stderr = "";
  #closed = false;
  #exitError: Error | null = null;
  #stdinError: Error | null = null;

  private constructor(
    child: ChildProcessWithoutNullStreams,
    options: InternalSandboxOptions,
    requestHeaderHooks: Map<string, RegisteredHttpRequestHeadersHook>,
  ) {
    this.#child = child;
    this.#options = options;
    this.packets = this.#packets;
    this.#requestHeaderHooks = requestHeaderHooks;
    if (options.overlay !== undefined) {
      this.#hostFs.set(ROOT_OVERLAY_MOUNT_PATH, options.overlay.fileSystem);
    }
    for (const mount of options.mounts ?? []) {
      this.#hostFs.set(mount.path, mount.fileSystem);
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
      this.#packets.close(this.#exitError);
      this.#packetActivity.close(this.#exitError);
      this.#launchReady.close(this.#exitError);
    });
  }

  static async spawn(
    options: InternalSandboxOptions,
    hostOptions: HostSpawnSandboxOptions,
    requestHeaderHooks: Map<string, RegisteredHttpRequestHeadersHook> = new Map(),
  ): Promise<HostProcessSandboxVm> {
    let vm: HostProcessSandboxVm | undefined;
    const hostPath = hostBinaryPath();
    try {
      const child = spawn(hostPath, ["--stdio"], {
        stdio: ["pipe", "pipe", "pipe"],
      });
      vm = new HostProcessSandboxVm(child, options, requestHeaderHooks);
      await Promise.race([
        once(child, "spawn"),
        once(child, "error").then(([error]) => {
          throw error;
        }),
      ]);
      vm.#writeToHost(encodeHostSpawn(hostOptions));
      await vm.#waitForLaunch();
      return vm;
    } catch (error) {
      await vm?.close();
      const signingError = macosHostSigningError(hostPath);
      if (signingError !== null) {
        throw signingError;
      }
      throw error;
    }
  }

  writeControlPacket(packet: Uint8Array): void {
    this.#assertOpen();
    this.#writeToHost(packet);
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#packets.close();
    this.#packetActivity.close();
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
      this.#packetActivity.notify();
      if (!this.#routeHostPacket(packet)) {
        if (isInitReadyPacket(packet)) {
          this.#launchReady.notify();
        }
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
      && type !== "host.vfs.link"
      && type !== "host.vfs.symlink"
      && type !== "host.vfs.readlink"
      && type !== "host.vfs.setxattr"
      && type !== "host.vfs.getxattr"
      && type !== "host.vfs.listxattr"
      && type !== "host.vfs.removexattr"
      && type !== "host.http.requestHeaders"
      && type !== "host.http.activeRequestHeaderHooks"
    ) {
      return false;
    }

    if (type === "host.http.requestHeaders") {
      void this.#handleHttpRequestHeaders(document);
    } else if (type === "host.http.activeRequestHeaderHooks") {
      void this.#handleActiveRequestHeaderHooks(document);
    } else {
      void this.#handleVirtualFsRequest(document);
    }
    return true;
  }

  async #handleHttpRequestHeaders(document: Record<string, unknown>): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const hookIds = assertStringArray(document.hookIds, "hookIds");
      const originalHeaders = assertHeaderPairs(document.headers, "headers");
      const headers = new Headers(originalHeaders);
      const mutatedHeaders = trackHeaderMutations(headers);
      const request = {
        protocol: assertProtocol(document.protocol),
        url: new URL(assertString(document.url, "url")),
        method: assertString(document.method, "method"),
        headers,
        destination: {
          originalIp: assertString(document.originalDestinationIp, "originalDestinationIp"),
          originalPort: assertNumber(document.originalDestinationPort, "originalDestinationPort"),
          upstreamIp: assertString(document.upstreamDialIp, "upstreamDialIp"),
          upstreamPort: assertNumber(document.upstreamDialPort, "upstreamDialPort"),
        },
        tls: optionalTlsMetadata(document.tls),
      };

      for (const hookId of hookIds) {
        const registration = this.#requestHeaderHooks.get(hookId);
        if (registration?.active === true) {
          await registration.hook(request);
        }
      }

      this.#tryWriteToHost(encodePacket({
        type: "host.http.response",
        id,
        ok: true,
        headers: mutatedHeaders()
          ? Array.from(headers.entries())
          : originalHeaders,
      }));
    } catch (error) {
      this.#tryWriteToHost(encodePacket({
        type: "host.http.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }

  async #handleActiveRequestHeaderHooks(document: Record<string, unknown>): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const hookIds = assertStringArray(document.hookIds, "hookIds");
      this.#tryWriteToHost(encodePacket({
        type: "host.http.response",
        id,
        ok: true,
        hookIds: hookIds.filter((hookId) => this.#requestHeaderHooks.get(hookId)?.active === true),
      }));
    } catch (error) {
      this.#tryWriteToHost(encodePacket({
        type: "host.http.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
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
        case "host.vfs.link": {
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          const from = assertString(document.from, "from");
          const to = assertString(document.to, "to");
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            stat: await posix.link(from, to),
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
        case "host.vfs.setxattr": {
          const path = assertString(document.path, "path");
          const name = assertString(document.name, "name");
          const value = binaryField(document.value, "value");
          const flags = assertNumber(document.flags, "flags");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          await posix.setxattr(path, name, value, flags);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
          }));
          return;
        }
        case "host.vfs.getxattr": {
          const path = assertString(document.path, "path");
          const name = assertString(document.name, "name");
          const size = assertNumber(document.size, "size");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          const value = await posix.getxattr(path, name);
          if (size === 0) {
            this.#tryWriteToHost(encodePacket({
              type: "host.vfs.response",
              id,
              ok: true,
              count: value.byteLength,
            }));
            return;
          }
          if (value.byteLength > size) {
            throw new Error("xattr value is larger than requested size");
          }
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            value: new Binary(value),
          }));
          return;
        }
        case "host.vfs.listxattr": {
          const path = assertString(document.path, "path");
          const size = assertNumber(document.size, "size");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          const names = encodeXattrNameList(await posix.listxattr(path));
          if (size === 0) {
            this.#tryWriteToHost(encodePacket({
              type: "host.vfs.response",
              id,
              ok: true,
              count: names.byteLength,
            }));
            return;
          }
          if (names.byteLength > size) {
            throw new Error("xattr name list is larger than requested size");
          }
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
            names: new Binary(names),
          }));
          return;
        }
        case "host.vfs.removexattr": {
          const path = assertString(document.path, "path");
          const name = assertString(document.name, "name");
          const posix = assertPosixFileSystem(fileSystem, mountPath);
          await posix.removexattr(path, name);
          this.#tryWriteToHost(encodePacket({
            type: "host.vfs.response",
            id,
            ok: true,
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

  async #waitForLaunch(): Promise<void> {
    const timeoutMs = launchTimeoutMs();
    await Promise.race([
      this.#launchReady.wait(),
      once(this.#child, "exit").then(() => {
        throw this.#exitError ?? new Error("sandbox-host exited before VM launch completed");
      }),
      unrefDelay(timeoutMs).then(() => {
        throw new Error(`sandbox-host did not produce a launch acknowledgement within ${timeoutMs}ms`);
      }),
    ]);
  }
}

function launchTimeoutMs(): number {
  const value = process.env.SANDBOX_LAUNCH_TIMEOUT_MS;
  if (value === undefined || value.length === 0) {
    return DEFAULT_LAUNCH_TIMEOUT_MS;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`SANDBOX_LAUNCH_TIMEOUT_MS must be a positive integer, got ${value}`);
  }
  return parsed;
}

function encodeXattrNameList(names: readonly string[]): Uint8Array {
  return new TextEncoder().encode(names.map((name) => `${name}\0`).join(""));
}

function isInitReadyPacket(packet: Uint8Array): boolean {
  try {
    const document = BSON.deserialize(packet.slice(4)) as Record<string, unknown>;
    return document.type === "init.ready";
  } catch {
    return false;
  }
}

export { hostBinaryPath };

function assertString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`host vfs request ${field} must be a string`);
  }
  return value;
}

function assertNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`host request ${field} must be a non-negative safe integer`);
  }
  return value;
}

function assertStringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string")) {
    throw new Error(`host request ${field} must be a string array`);
  }
  return value;
}

function assertHeaderPairs(value: unknown, field: string): [string, string][] {
  if (
    !Array.isArray(value)
    || value.some((entry) => {
      return !Array.isArray(entry)
        || entry.length !== 2
        || typeof entry[0] !== "string"
        || typeof entry[1] !== "string";
    })
  ) {
    throw new Error(`host request ${field} must be header pairs`);
  }
  return value as [string, string][];
}

function trackHeaderMutations(headers: Headers): () => boolean {
  let mutated = false;
  const set = headers.set.bind(headers);
  const append = headers.append.bind(headers);
  const deleteHeader = headers.delete.bind(headers);
  Object.defineProperties(headers, {
    set: {
      value(name: string, value: string) {
        mutated = true;
        set(name, value);
      },
    },
    append: {
      value(name: string, value: string) {
        mutated = true;
        append(name, value);
      },
    },
    delete: {
      value(name: string) {
        mutated = true;
        deleteHeader(name);
      },
    },
  });
  return () => mutated;
}

function assertProtocol(value: unknown): "http/1.1" | "h2" {
  if (value === "http/1.1" || value === "h2") {
    return value;
  }
  throw new Error("host request protocol must be http/1.1 or h2");
}

function optionalTlsMetadata(value: unknown): { readonly sni?: string; readonly alpn?: string } | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== "object") {
    throw new Error("host request tls must be a document");
  }
  const document = value as Record<string, unknown>;
  return {
    sni: document.sni === undefined || document.sni === null
      ? undefined
      : assertString(document.sni, "tls.sni"),
    alpn: document.alpn === undefined || document.alpn === null
      ? undefined
      : assertString(document.alpn, "tls.alpn"),
  };
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
    || typeof candidate.link !== "function"
    || typeof candidate.symlink !== "function"
    || typeof candidate.readlink !== "function"
    || typeof candidate.setxattr !== "function"
    || typeof candidate.getxattr !== "function"
    || typeof candidate.listxattr !== "function"
    || typeof candidate.removexattr !== "function"
  ) {
    throw new Error(`host filesystem mount does not support POSIX mutations: ${mountPath}`);
  }
  return candidate as SandboxPosixFileSystem;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds));
}

function unrefDelay(milliseconds: number): Promise<void> {
  return new Promise((resolvePromise) => {
    const timeout = setTimeout(resolvePromise, milliseconds);
    timeout.unref();
  });
}

class AsyncQueue<T> implements AsyncIterable<T> {
  readonly #values: T[] = [];
  readonly #nextWaiters: Array<{
    resolve(result: IteratorResult<T>): void;
    reject(error: unknown): void;
  }> = [];
  #closed = false;
  #error: unknown;

  get length(): number {
    return this.#values.length;
  }

  push(value: T): void {
    if (this.#closed) {
      return;
    }

    const nextWaiter = this.#nextWaiters.shift();
    if (nextWaiter !== undefined) {
      nextWaiter.resolve({ value, done: false });
    } else {
      this.#values.push(value);
    }

  }

  close(error?: unknown): void {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#error = error;
    for (const waiter of this.#nextWaiters.splice(0)) {
      if (error === undefined) {
        waiter.resolve({ value: undefined, done: true });
      } else {
        waiter.reject(error);
      }
    }
  }

  [Symbol.asyncIterator](): AsyncIterator<T> {
    return {
      next: async () => {
        const value = this.#values.shift();
        if (value !== undefined) {
          return { value, done: false };
        }

        if (this.#closed) {
          if (this.#error !== undefined) {
            throw this.#error;
          }
          return { value: undefined, done: true };
        }

        return await new Promise<IteratorResult<T>>((resolve, reject) => {
          this.#nextWaiters.push({
            resolve,
            reject,
          });
        });
      },
    };
  }
}

class AsyncSignal {
  readonly #waiters: Array<{
    resolve(): void;
    reject(error: unknown): void;
  }> = [];
  readonly #closedMessage: string;
  #signaled = false;
  #closed = false;
  #error: unknown;

  constructor(closedMessage = "sandbox-host packet activity closed") {
    this.#closedMessage = closedMessage;
  }

  notify(): void {
    if (this.#closed) {
      return;
    }
    this.#signaled = true;
    for (const waiter of this.#waiters.splice(0)) {
      waiter.resolve();
    }
  }

  close(error?: unknown): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#error = error;
    for (const waiter of this.#waiters.splice(0)) {
      if (error === undefined) {
        waiter.resolve();
      } else {
        waiter.reject(error);
      }
    }
  }

  async wait(): Promise<void> {
    if (this.#signaled) {
      return;
    }
    if (this.#closed) {
      if (this.#error !== undefined) {
        throw this.#error;
      }
      throw new Error(this.#closedMessage);
    }
    return await new Promise<void>((resolve, reject) => {
      this.#waiters.push({ resolve, reject });
    });
  }
}

function encodeHostSpawn(options: HostSpawnSandboxOptions): Uint8Array {
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
    rootfsOverlaySource: options.rootfsOverlay?.source,
    mounts: options.mounts ?? [],
    networkOutbound: options.network?.outbound,
    networkHttp: options.network?.http === undefined ? undefined : options.network.http,
  });
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document, { ignoreUndefined: true });
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}
