import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { appendFileSync, closeSync, mkdtempSync, openSync, readSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Binary, BSON } from "bson";
import { hostBinaryPath, macosHostSigningError } from "./artifacts.ts";
import type { HostControlChannel } from "./control.ts";
import type { HostSpawnSandboxOptions } from "./spawn-options.ts";
import { isSandboxWritableFileSystem } from "./vfs.ts";
import type {
  SandboxFileSystem,
  SandboxBlockStoreContext,
  SandboxBlockStore,
  SandboxBlockRange,
  SandboxPosixFileSystem,
} from "./index.ts";
import type {
  InternalSandboxOptions,
  RegisteredHttpRequestHeadersHook,
  RegisteredNetworkConnectionHook,
} from "./launch-options.ts";
import type {
  NetworkConnectionRequest,
  DnsConnectionMatch,
  DnsUpstreamResolver,
  HttpAuthoritySpec,
  HttpConnectionMatch,
  NetworkEndpoint,
  NetworkEndpointSpec,
  NetworkMatchPredicate,
  NetworkTransport,
  TcpConnectionMatch,
  HttpRequestMiddleware,
  UdpConnectionMatch,
} from "./index.ts";

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
  readonly #rootBlockStore?: SandboxBlockStore;
  readonly #rootBlockStoreContext?: SandboxBlockStoreContext;
  readonly #blockStores = new Map<string, {
    readonly blockStore: SandboxBlockStore;
    readonly context: SandboxBlockStoreContext;
  }>();
  readonly #requestHeaderHooks: Map<string, RegisteredHttpRequestHeadersHook>;
  readonly #networkConnectionHook?: RegisteredNetworkConnectionHook;
  readonly #httpMiddlewareByFlow = new Map<string, HttpRequestMiddleware | undefined>();
  readonly #consoleOutputPath?: string;
  readonly #consoleOutputCleanupPath?: string;
  #buffer = new Uint8Array();
  #stderr = "";
  #closed = false;
  #exitError: Error | null = null;
  #stdinError: Error | null = null;

  private constructor(
    child: ChildProcessWithoutNullStreams,
    options: InternalSandboxOptions,
    requestHeaderHooks: Map<string, RegisteredHttpRequestHeadersHook>,
    networkConnectionHook?: RegisteredNetworkConnectionHook,
    consoleOutputPath?: string,
    consoleOutputCleanupPath?: string,
  ) {
    this.#child = child;
    this.#options = options;
    this.packets = this.#packets;
    this.#requestHeaderHooks = requestHeaderHooks;
    this.#networkConnectionHook = networkConnectionHook;
    this.#consoleOutputPath = consoleOutputPath;
    this.#consoleOutputCleanupPath = consoleOutputCleanupPath;
    this.#rootBlockStore = options.rootfs.storage?.blockStore;
    this.#rootBlockStoreContext = options.rootfs.storage?.context;
    if (this.#rootBlockStore !== undefined && this.#rootBlockStoreContext !== undefined) {
      this.#blockStores.set("host.block", {
        blockStore: this.#rootBlockStore,
        context: this.#rootBlockStoreContext,
      });
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
        if (process.env.SANDBOX_HOST_STDERR === "1") {
          process.stderr.write(chunk);
        }
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
        hostExitMessage(exitText, this.#stderr, this.#consoleOutputPath),
      );
      this.#cleanupConsoleOutput();
      this.#packets.close(this.#exitError);
      this.#packetActivity.close(this.#exitError);
      this.#launchReady.close(this.#exitError);
    });
  }

  static async spawn(
    options: InternalSandboxOptions,
    hostOptions: HostSpawnSandboxOptions,
    requestHeaderHooks: Map<string, RegisteredHttpRequestHeadersHook> = new Map(),
    networkConnectionHook?: RegisteredNetworkConnectionHook,
  ): Promise<HostProcessSandboxVm> {
    let vm: HostProcessSandboxVm | undefined;
    const hostPath = hostBinaryPath();
    try {
      const consoleOutput = launchConsoleOutput();
      const child = spawn(hostPath, ["--stdio"], {
        stdio: ["pipe", "pipe", "pipe"],
        env: {
          ...process.env,
          SANDBOX_CONSOLE_OUTPUT: consoleOutput.path,
        },
      });
      vm = new HostProcessSandboxVm(
        child,
        options,
        requestHeaderHooks,
        networkConnectionHook,
        consoleOutput.path,
        consoleOutput.cleanupPath,
      );
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

  static async flattenQcow2(input: {
    readonly basePath: string;
    readonly overlay: SandboxBlockStore;
    readonly overlayContext: SandboxBlockStoreContext;
    readonly dest: SandboxBlockStore;
    readonly destContext: SandboxBlockStoreContext;
    readonly clusterSize: number;
  }): Promise<{ readonly sizeBytes: bigint }> {
    const hostPath = hostBinaryPath();
    const child = spawn(hostPath, ["--flatten-qcow2"], {
      stdio: ["pipe", "pipe", "pipe"],
      env: process.env,
    });
    const host = new HostProcessSandboxVm(
      child,
      {
        hostname: "flatten-qcow2",
        rootfs: { path: input.basePath, readonly: true, format: "qcow2" },
      },
      new Map(),
    );
    host.#blockStores.set("host.block.source", {
      blockStore: input.overlay,
      context: input.overlayContext,
    });
    host.#blockStores.set("host.block.dest", {
      blockStore: input.dest,
      context: input.destContext,
    });
    try {
      await Promise.race([
        once(child, "spawn"),
        once(child, "error").then(([error]) => {
          throw error;
        }),
      ]);
      const result = new Promise<{ readonly sizeBytes: bigint }>((resolve, reject) => {
        host.#packets[Symbol.asyncIterator]().next().then(({ value }) => {
          if (value === undefined) {
            reject(new Error("sandbox-host did not return a QCOW2 flatten result"));
            return;
          }
          const document = BSON.deserialize(value.slice(4)) as Record<string, unknown>;
          if (document.type !== "host.flattenQcow2.result" || document.ok !== true) {
            reject(new Error(typeof document.error === "string" ? document.error : "sandbox-host QCOW2 flatten failed"));
            return;
          }
          if (typeof document.sizeBytes !== "string") {
            reject(new Error("sandbox-host QCOW2 flatten result missing sizeBytes"));
            return;
          }
          resolve({ sizeBytes: BigInt(document.sizeBytes) });
        }, reject);
      });
      host.#writeToHost(encodePacket({
        type: "host.flattenQcow2",
        basePath: input.basePath,
        overlayBlockSize: input.overlay.blockSize.toString(),
        destBlockSize: input.dest.blockSize.toString(),
        clusterSize: input.clusterSize,
      }));
      const output = await result;
      await host.close();
      return output;
    } catch (error) {
      await host.close();
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

    try {
      if (this.#child.exitCode !== null || this.#child.signalCode !== null) {
        return;
      }

      this.#child.kill("SIGKILL");
      await Promise.race([
        exited,
        delay(1_000),
      ]);
    } finally {
      this.#cleanupConsoleOutput();
    }
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

  #cleanupConsoleOutput(): void {
    if (this.#consoleOutputCleanupPath === undefined) {
      return;
    }
    try {
      rmSync(this.#consoleOutputCleanupPath, { recursive: true, force: true });
    } catch {
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
      && type !== "host.network.connection"
      && type !== "host.network.closed"
      && type !== "host.block.list"
      && type !== "host.block.read"
      && type !== "host.block.write"
      && type !== "host.block.flush"
      && type !== "host.block.source.list"
      && type !== "host.block.source.read"
      && type !== "host.block.source.write"
      && type !== "host.block.source.flush"
      && type !== "host.block.dest.list"
      && type !== "host.block.dest.read"
      && type !== "host.block.dest.write"
      && type !== "host.block.dest.flush"
    ) {
      return false;
    }

    if (type === "host.http.requestHeaders") {
      void this.#handleHttpRequestHeaders(document);
    } else if (type === "host.http.activeRequestHeaderHooks") {
      void this.#handleActiveRequestHeaderHooks(document);
    } else if (type === "host.network.connection") {
      void this.#handleNetworkConnection(document);
    } else if (type === "host.network.closed") {
      this.#handleNetworkClosed(document);
    } else if (
      type === "host.block.list"
      || type === "host.block.read"
      || type === "host.block.write"
      || type === "host.block.flush"
      || type === "host.block.source.list"
      || type === "host.block.source.read"
      || type === "host.block.source.write"
      || type === "host.block.source.flush"
      || type === "host.block.dest.list"
      || type === "host.block.dest.read"
      || type === "host.block.dest.write"
      || type === "host.block.dest.flush"
    ) {
      void this.#handleBlockStoreRequest(document, packet.byteLength);
    } else {
      void this.#handleVirtualFsRequest(document);
    }
    return true;
  }

  async #handleNetworkConnection(document: Record<string, unknown>): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const transport = assertNetworkTransport(document.transport);
      const protocol = optionalString(document.protocol, "protocol");
      const srcIp = assertString(document.srcIp, "srcIp");
      const srcPort = assertNumber(document.srcPort, "srcPort");
      const dstIp = assertString(document.dstIp, "dstIp");
      const dstPort = assertNumber(document.dstPort, "dstPort");
      const hostname = optionalString(document.hostname, "hostname");
      const src = createNetworkEndpoint(srcIp, srcPort);
      const dst = createNetworkEndpoint(dstIp, dstPort);
      const decision: {
        action: "deny" | "accept" | "acceptHttp";
        dnsResolvers?: readonly { readonly ip: string; readonly port: number }[];
      } = { action: "deny" };
      let httpMiddleware: HttpRequestMiddleware | undefined;
      let acceptHttpMode: "matched" | "enforced" | undefined;
      const accept = () => {
        decision.action = "accept";
        decision.dnsResolvers = undefined;
        acceptHttpMode = undefined;
        return {};
      };
      const connection: NetworkConnectionRequest = {
        transport,
        src,
        dst,
        accept,
        matchDns() {
          if (protocol !== "dns") {
            return undefined;
          }
          return {
            src,
            dst,
            transport,
            accept(options?: { readonly resolvers?: readonly DnsUpstreamResolver[] }) {
              decision.action = "accept";
              decision.dnsResolvers = options?.resolvers?.map(normalizeDnsResolver);
              return {};
            },
          };
        },
        matchHttp(matcher: HttpAuthoritySpec | NetworkMatchPredicate<HttpConnectionMatch>) {
          if (transport !== "tcp" || hostname === undefined) {
            return undefined;
          }
          const candidate = {
            src,
            dst,
            hostname,
            port: dst.port,
            accept(middleware?: HttpRequestMiddleware) {
              decision.action = "acceptHttp";
              decision.dnsResolvers = undefined;
              httpMiddleware = middleware;
              acceptHttpMode = "matched";
              return {};
            },
          };
          return httpMatcherMatches(matcher, candidate) ? candidate : undefined;
        },
        ...(transport === "tcp"
          ? {
              acceptHttp(middleware?: HttpRequestMiddleware) {
                decision.action = "acceptHttp";
                decision.dnsResolvers = undefined;
                httpMiddleware = middleware;
                acceptHttpMode = "enforced";
                return {};
              },
              matchTcp(matcher: NetworkEndpointSpec | NetworkMatchPredicate<TcpConnectionMatch>) {
                const candidate = {
                  src,
                  dst,
                  accept,
                };
                return endpointMatcherMatches(matcher, candidate) ? candidate : undefined;
              },
            }
          : {
              matchUdp(matcher: NetworkEndpointSpec | NetworkMatchPredicate<UdpConnectionMatch>) {
                const candidate = {
                  src,
                  dst,
                  accept,
                };
                return endpointMatcherMatches(matcher, candidate) ? candidate : undefined;
              },
            }),
      } as NetworkConnectionRequest;

      if (this.#networkConnectionHook?.active === true) {
        await this.#networkConnectionHook.hook(connection);
      }
      const action = decision.action === "acceptHttp"
          && acceptHttpMode === "matched"
          && httpMiddleware === undefined
        ? "accept"
        : decision.action;
      if (action === "acceptHttp") {
        this.#httpMiddlewareByFlow.set(networkFlowKey(src, dst), httpMiddleware);
      }

      this.#tryWriteToHost(encodePacket({
        type: "host.network.response",
        id,
        ok: true,
        action,
        dnsResolvers: decision.dnsResolvers,
      }));
    } catch (error) {
      this.#tryWriteToHost(encodePacket({
        type: "host.network.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
  }

  #handleNetworkClosed(document: Record<string, unknown>): void {
    const id = typeof document.id === "string" ? document.id : "";
    try {
      const transport = assertNetworkTransport(document.transport);
      const srcIp = assertString(document.srcIp, "srcIp");
      const srcPort = assertNumber(document.srcPort, "srcPort");
      const dstIp = assertString(document.dstIp, "dstIp");
      const dstPort = assertNumber(document.dstPort, "dstPort");
      if (transport === "tcp") {
        this.#httpMiddlewareByFlow.delete(networkFlowKey(
          createNetworkEndpoint(srcIp, srcPort),
          createNetworkEndpoint(dstIp, dstPort),
        ));
      }
      this.#tryWriteToHost(encodePacket({
        type: "host.network.response",
        id,
        ok: true,
      }));
    } catch (error) {
      this.#tryWriteToHost(encodePacket({
        type: "host.network.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }));
    }
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
          sourceIp: assertString(document.sourceIp, "sourceIp"),
          sourcePort: assertNumber(document.sourcePort, "sourcePort"),
          originalIp: assertString(document.originalDestinationIp, "originalDestinationIp"),
          originalPort: assertNumber(document.originalDestinationPort, "originalDestinationPort"),
          hostname: optionalString(document.originalDestinationHostname, "originalDestinationHostname"),
        },
        tls: optionalTlsMetadata(document.tls),
      };

      await this.#httpMiddlewareByFlow.get(networkFlowKey(
        createNetworkEndpoint(request.destination.sourceIp, request.destination.sourcePort),
        createNetworkEndpoint(request.destination.originalIp, request.destination.originalPort),
      ))?.(request);

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

  async #handleBlockStoreRequest(document: Record<string, unknown>, requestBytes: number): Promise<void> {
    const id = typeof document.id === "string" ? document.id : "";
    const request = parseBlockStoreRequest(document.type);
    try {
      if (request === undefined) {
        throw new Error("unsupported block store request");
      }
      const entry = this.#blockStores.get(request.prefix);
      if (entry === undefined) {
        throw new Error(`${request.prefix} store is not configured`);
      }
      const { blockStore, context: blockStoreContext } = entry;

      switch (request.operation) {
        case "list": {
          const blocks = (await blockStore.list(blockStoreContext)).map((block) => block.toString());
          this.#writeBlockStoreResponse({
            type: "host.block.response",
            id,
            ok: true,
            blocks,
          }, {
            requestBytes,
            operation: "list",
            returnedBlocks: blocks.length,
          });
          return;
        }
        case "read": {
          const start = assertString(document.start, "start");
          const count = assertNumber(document.count, "count");
          const chunks = await blockStore.read({
            start: BigInt(start),
            count,
          }, blockStoreContext);
          const returnedBytes = chunks.reduce((total, chunk) => total + chunk.data.byteLength, 0);
          this.#writeBlockStoreResponse({
            type: "host.block.response",
            id,
            ok: true,
            chunks: chunks.map((chunk) => ({
              start: chunk.start.toString(),
              data: new Binary(chunk.data),
            })),
          }, {
            requestBytes,
            operation: "read",
            requestedBlocks: count,
            requestedBytes: count * blockStore.blockSize,
            returnedBlocks: chunks.length,
            returnedBytes,
          });
          return;
        }
        case "write": {
          const chunks = assertDocumentArray(document.chunks, "chunks").map((chunk) => ({
            start: BigInt(assertString(chunk.start, "chunks.start")),
            data: binaryField(chunk.data, "chunks.data").slice(),
          }));
          const writtenBytes = chunks.reduce((total, chunk) => total + chunk.data.byteLength, 0);
          await blockStore.write(chunks, blockStoreContext);
          this.#writeBlockStoreResponse({
            type: "host.block.response",
            id,
            ok: true,
          }, {
            requestBytes,
            operation: "write",
            requestedBlocks: chunks.length,
            requestedBytes: writtenBytes,
          });
          return;
        }
        case "flush": {
          await blockStore.flush?.(blockStoreContext);
          this.#writeBlockStoreResponse({
            type: "host.block.response",
            id,
            ok: true,
          }, {
            requestBytes,
            operation: "flush",
          });
          return;
        }
      }
    } catch (error) {
      this.#writeBlockStoreResponse({
        type: "host.block.response",
        id,
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      }, {
        requestBytes,
        operation: typeof document.type === "string" ? document.type : "unknown",
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  #writeBlockStoreResponse(
    document: Record<string, unknown>,
    trace: {
      readonly requestBytes: number;
      readonly operation: string;
      readonly requestedBlocks?: number;
      readonly requestedBytes?: number;
      readonly returnedBlocks?: number;
      readonly returnedBytes?: number;
      readonly error?: string;
    },
  ): void {
    const packet = encodePacket(document);
    traceBlockStoreRequest({
      ...trace,
      responseBytes: packet.byteLength,
    });
    this.#tryWriteToHost(packet);
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

function launchConsoleOutput(): { readonly path: string; readonly cleanupPath?: string } {
  const configured = process.env.SANDBOX_CONSOLE_OUTPUT;
  if (configured !== undefined) {
    try {
      if (statSync(configured).isDirectory()) {
        const outputPath = mkdtempSync(join(configured, "sandbox-console-"));
        return { path: join(outputPath, "console.log") };
      }
    } catch {
      // Non-existent configured paths are treated as explicit output files.
    }
    return { path: configured };
  }
  const cleanupPath = mkdtempSync(join(tmpdir(), "sandbox-console-"));
  return { path: join(cleanupPath, "console.log"), cleanupPath };
}

function hostExitMessage(exitText: string, stderr: string, consoleOutputPath: string | undefined): string {
  const parts = [exitText];
  if (stderr.length > 0) {
    parts.push(stderr);
  }

  const consoleOutput = consoleOutputPath === undefined ? "" : readConsoleTail(consoleOutputPath);
  if (consoleOutput.length > 0) {
    parts.push(`guest console output:\n${consoleOutput}`);
  }
  return parts.join("\n");
}

function readConsoleTail(path: string): string {
  const maxBytes = 8_000;
  let fd: number | undefined;
  try {
    const stat = statSync(path);
    const offset = Math.max(0, stat.size - maxBytes);
    const size = stat.size - offset;
    if (size <= 0) return "";
    const buffer = Buffer.alloc(size);
    fd = openSync(path, "r");
    readSync(fd, buffer, 0, size, offset);
    return buffer.toString("utf8").trimEnd();
  } catch {
    return "";
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
      }
    }
  }
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

function assertDocumentArray(value: unknown, field: string): Record<string, unknown>[] {
  if (!Array.isArray(value) || value.some((entry) => entry === null || typeof entry !== "object")) {
    throw new Error(`host request ${field} must be documents`);
  }
  return value as Record<string, unknown>[];
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

function assertNetworkTransport(value: unknown): NetworkTransport {
  if (value === "tcp" || value === "udp") {
    return value;
  }
  throw new Error("host network request transport must be tcp or udp");
}

function createNetworkEndpoint(ip: string, port: number): NetworkEndpoint {
  return {
    ip,
    port,
    isLoopback: () => isLoopbackIp(ip),
    isPrivate: () => isPrivateIp(ip),
    isLinkLocal: () => isLinkLocalIp(ip),
    isMulticast: () => isMulticastIp(ip),
    isBroadcast: () => ip === "255.255.255.255",
    isDocumentation: () => isDocumentationIp(ip),
    isReserved: () => isReservedIp(ip),
    isPublicInternet: () => isPublicInternetIp(ip),
  };
}

function normalizeDnsResolver(resolver: DnsUpstreamResolver): { readonly ip: string; readonly port: number } {
  const spec = typeof resolver === "string" ? { ip: resolver, port: 53 } : resolver;
  return {
    ip: spec.ip,
    port: spec.port ?? 53,
  };
}

function endpointMatcherMatches<TMatch extends { readonly dst: NetworkEndpoint }>(
  matcher: NetworkEndpointSpec | NetworkMatchPredicate<TMatch>,
  candidate: TMatch,
): boolean {
  if (typeof matcher === "function") {
    return matcher(candidate);
  }
  const endpoint = parseEndpointSpec(matcher);
  return candidate.dst.ip === endpoint.ip && candidate.dst.port === endpoint.port;
}

function httpMatcherMatches(
  matcher: HttpAuthoritySpec | NetworkMatchPredicate<HttpConnectionMatch>,
  candidate: HttpConnectionMatch,
): boolean {
  if (typeof matcher === "function") {
    return matcher(candidate);
  }
  const authority = parseHttpAuthoritySpec(matcher);
  return candidate.hostname === authority.hostname
    && (authority.port === undefined || candidate.port === authority.port);
}

function parseEndpointSpec(spec: NetworkEndpointSpec): { readonly ip: string; readonly port: number } {
  if (typeof spec !== "string") {
    return spec;
  }
  const ipv6Match = /^\[(.*)]:(\d+)$/.exec(spec);
  if (ipv6Match !== null) {
    return { ip: ipv6Match[1] ?? "", port: Number(ipv6Match[2]) };
  }
  const separator = spec.lastIndexOf(":");
  if (separator < 0) {
    throw new Error("network endpoint spec must include a port");
  }
  return {
    ip: spec.slice(0, separator),
    port: Number(spec.slice(separator + 1)),
  };
}

function parseHttpAuthoritySpec(spec: HttpAuthoritySpec): { readonly hostname: string; readonly port?: number } {
  if (typeof spec !== "string") {
    return spec;
  }
  const ipv6Match = /^\[(.*)](?::(\d+))?$/.exec(spec);
  if (ipv6Match !== null) {
    return {
      hostname: ipv6Match[1] ?? "",
      port: ipv6Match[2] === undefined ? undefined : Number(ipv6Match[2]),
    };
  }
  const separator = spec.lastIndexOf(":");
  if (separator > -1) {
    const portText = spec.slice(separator + 1);
    if (/^\d+$/.test(portText)) {
      return {
        hostname: spec.slice(0, separator),
        port: Number(portText),
      };
    }
  }
  return { hostname: spec };
}

function networkFlowKey(src: NetworkEndpoint, dst: NetworkEndpoint): string {
  return `${src.ip}:${src.port}->${dst.ip}:${dst.port}`;
}

function isLoopbackIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 127;
  }
  return ip.toLowerCase() === "::1";
}

function isPrivateIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 10
      || (ipv4[0] === 172 && ipv4[1] >= 16 && ipv4[1] <= 31)
      || (ipv4[0] === 192 && ipv4[1] === 168);
  }
  const lower = ip.toLowerCase();
  return lower.startsWith("fc") || lower.startsWith("fd");
}

function isLinkLocalIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 169 && ipv4[1] === 254;
  }
  return /^fe[89ab]/i.test(ip);
}

function isMulticastIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] >= 224 && ipv4[0] <= 239;
  }
  return ip.toLowerCase().startsWith("ff");
}

function isDocumentationIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return (ipv4[0] === 192 && ipv4[1] === 0 && ipv4[2] === 2)
      || (ipv4[0] === 198 && ipv4[1] === 51 && ipv4[2] === 100)
      || (ipv4[0] === 203 && ipv4[1] === 0 && ipv4[2] === 113);
  }
  return ip.toLowerCase().startsWith("2001:db8:");
}

function isReservedIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 0
      || (ipv4[0] === 100 && ipv4[1] >= 64 && ipv4[1] <= 127)
      || (ipv4[0] === 192 && ipv4[1] === 0 && ipv4[2] === 0)
      || (ipv4[0] === 192 && ipv4[1] === 88 && ipv4[2] === 99)
      || (ipv4[0] === 198 && (ipv4[1] === 18 || ipv4[1] === 19))
      || ipv4[0] >= 240
      || isDocumentationIp(ip);
  }
  return ip.toLowerCase().startsWith("2001:db8:");
}

function isPublicInternetIp(ip: string): boolean {
  return parseIpv4(ip) !== undefined
    && !isLoopbackIp(ip)
    && !isPrivateIp(ip)
    && !isLinkLocalIp(ip)
    && !isMulticastIp(ip)
    && !isReservedIp(ip)
    && !isDocumentationIp(ip)
    && ip !== "255.255.255.255";
}

function parseIpv4(ip: string): [number, number, number, number] | undefined {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return undefined;
  }
  const octets = parts.map((part) => {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) {
      return undefined;
    }
    const value = Number(part);
    return value <= 255 ? value : undefined;
  });
  return octets.every((part) => part !== undefined)
    ? octets as [number, number, number, number]
    : undefined;
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

function optionalString(value: unknown, field: string): string | undefined {
  return value === undefined || value === null ? undefined : assertString(value, field);
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
    hostname: options.hostname,
    vcpus: options.cpu?.vcpus,
    memoryMib: options.memory?.mib,
    kernelFormat: options.kernel.format,
    initCrate: options.init.crateName,
    rootfsPath: options.rootfs.path,
    rootfsReadonly: options.rootfs.readonly,
    rootfsFormat: options.rootfs.format,
    rootfsStorage: options.rootfs.storage === undefined
      ? undefined
      : {
        kind: options.rootfs.storage.kind,
        blockSize: options.rootfs.storage.blockSize,
        maxDirtyBytes: options.rootfs.storage.maxDirtyBytes,
      },
    mounts: options.mounts ?? [],
    networkOutbound: options.network?.outbound,
    networkHttp: options.network?.http === undefined ? undefined : options.network.http,
    networkPolicy: options.network?.policy === undefined ? undefined : options.network.policy,
  });
}

function parseBlockStoreRequest(type: unknown): {
  readonly prefix: string;
  readonly operation: "list" | "read" | "write" | "flush";
} | undefined {
  if (typeof type !== "string") {
    return undefined;
  }
  const match = /^(host\.block(?:\.(?:source|dest))?)\.(list|read|write|flush)$/.exec(type);
  if (match === null) {
    return undefined;
  }
  return {
    prefix: match[1] ?? "",
    operation: match[2] as "list" | "read" | "write" | "flush",
  };
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document, { ignoreUndefined: true });
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}

function traceBlockStoreRequest(event: {
  readonly requestBytes: number;
  readonly responseBytes: number;
  readonly operation: string;
  readonly requestedBlocks?: number;
  readonly requestedBytes?: number;
  readonly returnedBlocks?: number;
  readonly returnedBytes?: number;
  readonly error?: string;
}): void {
  const path = process.env.SANDBOX_BLOCK_TRACE;
  if (path === undefined || path.length === 0) {
    return;
  }
  appendFileSync(path, `${JSON.stringify({
    at: new Date().toISOString(),
    step: process.env.SANDBOX_BLOCK_TRACE_STEP,
    ...event,
  })}\n`);
}
