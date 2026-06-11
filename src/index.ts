import {
  builtInRootfsIdentity,
  builtInRootfsPath,
} from "./artifacts.ts";
import { randomUUID } from "node:crypto";
import { open } from "node:fs/promises";
import { HostControlTransport } from "./control.ts";
import { HostProcessSandboxVm } from "./host-process.ts";
import { createMemoryFileSystem } from "./memory-fs.ts";
import {
  isSandboxPosixFileSystem,
  isSandboxWritableFileSystem,
} from "./vfs.ts";
import type { HostSpawnSandboxOptions } from "./spawn-options.ts";
import type { ControlBackedSandboxProcess, ControlBackedSandboxPty, SandboxControl } from "./control.ts";
import type { SandboxControlEvent } from "./control-codec.ts";
import type {
  InternalNetworkConfig,
  InternalSandboxOptions,
  RegisteredHttpRequestHeadersHook,
  RegisteredNetworkConnectionHook,
  SandboxHttpRequestSelector,
} from "./launch-options.ts";

export type SandboxFileType = "file" | "directory" | "symlink";

export type SandboxFileStat = {
  readonly type: SandboxFileType;
  readonly sizeBytes: number | null;
  readonly mediaType: string | null;
  readonly modifiedAtMs: number | null;
  readonly writable?: boolean;
};

export type SandboxDirectoryEntry = {
  readonly name: string;
  readonly type: SandboxFileType;
};

export interface SandboxFileSystem {
  stat(path: string): Promise<SandboxFileStat>;
  list(path: string): Promise<readonly SandboxDirectoryEntry[]>;
  read(input: {
    readonly path: string;
    readonly range?: {
      readonly offset: number;
      readonly length: number;
    };
    readonly signal: AbortSignal;
  }): Promise<Uint8Array>;
}

export interface SandboxWritableFileSystem extends SandboxFileSystem {
  createFile(path: string): Promise<SandboxFileStat>;
  write(input: {
    readonly path: string;
    readonly offset: number;
    readonly contents: Uint8Array;
  }): Promise<number>;
  truncate(path: string, size: number): Promise<SandboxFileStat>;
}

export interface SandboxPosixFileSystem extends SandboxWritableFileSystem {
  mkdir(path: string): Promise<SandboxFileStat>;
  unlink(path: string): Promise<void>;
  rmdir(path: string): Promise<void>;
  rename(from: string, to: string, flags?: number): Promise<void>;
  link(from: string, to: string): Promise<SandboxFileStat>;
  symlink(target: string, path: string): Promise<SandboxFileStat>;
  readlink(path: string): Promise<string>;
  setxattr(path: string, name: string, value: Uint8Array, flags?: number): Promise<void>;
  getxattr(path: string, name: string): Promise<Uint8Array>;
  listxattr(path: string): Promise<readonly string[]>;
  removexattr(path: string, name: string): Promise<void>;
}

export interface MemoryFileSystemOptions {
  readonly files?: Readonly<Record<string, string | Uint8Array>>;
}

/**
 * HTTP request metadata exposed to HTTP network policy middleware.
 *
 * The request is already classified as HTTP or HTTPS and can be inspected or
 * mutated before it is forwarded upstream.
 */
export interface SandboxHttpRequest {
  /** HTTP version used by the intercepted request. */
  readonly protocol: "http/1.1" | "h2";
  /** Absolute URL reconstructed from the request target and destination metadata. */
  readonly url: URL;
  /** HTTP method exactly as received from the guest. */
  readonly method: string;
  /** Mutable request headers. Changes are applied before forwarding upstream. */
  readonly headers: Headers;
  /** IP-layer addressing observed for the connection carrying this request. */
  readonly destination: {
    /** Guest source IP address for the connection carrying this request. */
    readonly sourceIp: string;
    /** Guest source port for the connection carrying this request. */
    readonly sourcePort: number;
    /** Original destination IP address before host-side routing or proxying. */
    readonly originalIp: string;
    /** Original destination port before host-side routing or proxying. */
    readonly originalPort: number;
    /**
     * Hostname pinned by trusted connection metadata, when known.
     *
     * For cleartext HTTP this is populated only from the sandbox DNS answer
     * that resolved the destination IP. For HTTPS, use `tls.sni` for the
     * client-provided server name. The HTTP `Host` header is not trusted for
     * this field.
     */
    readonly hostname?: string;
  };
  /** TLS metadata when the request was carried over HTTPS. */
  readonly tls?: {
    /** Server Name Indication sent by the guest, when present. */
    readonly sni?: string;
    /** Negotiated ALPN protocol, when present. */
    readonly alpn?: string;
  };
}

export type BuiltInRootfsName = "alpine:3.23";

export type BuiltInRootfsConfig = {
  readonly kind: "built-in-rootfs";
  readonly name: BuiltInRootfsName;
};

export type ComposedRootfsConfig = {
  readonly kind: "composed-rootfs";
  readonly base: BuiltInRootfsConfig;
  readonly overlay: SandboxBlockStore;
};

export type CowRootfsConfig = {
  readonly kind: "cow-rootfs";
  readonly source: ComposedRootfsConfig;
  readonly maxDirtyBytes?: number;
};

export type Rootfs = BuiltInRootfsConfig | CowRootfsConfig;

export type Qcow2RootfsImage = {
  readonly kind: "rootfs-image";
  readonly format: "qcow2";
  readonly sizeBytes: bigint;
};

export type SandboxFileSystemSource = {
  readonly kind: "virtual-fs";
  readonly fileSystem: SandboxFileSystem;
};

export type SandboxWritableFileSystemSource = {
  readonly kind: "virtual-fs";
  readonly fileSystem: SandboxPosixFileSystem;
};

export type SandboxBlockRange = {
  readonly start: bigint;
  readonly count: number;
};

export type SandboxBlockChunk = {
  readonly start: bigint;
  readonly data: Uint8Array;
};

export type SandboxBlockStoreContext = {
  readonly base: string;
};

export interface SandboxBlockStore {
  readonly blockSize: number;
  list(context: SandboxBlockStoreContext): Promise<readonly bigint[]>;
  read(range: SandboxBlockRange, context: SandboxBlockStoreContext): Promise<readonly SandboxBlockChunk[]>;
  /**
   * Receives block bytes owned by the block store. Sandbox will not mutate
   * chunk data after calling write(), so stores may retain those arrays.
   */
  write(chunks: readonly SandboxBlockChunk[], context: SandboxBlockStoreContext): Promise<void>;
  flush?(context: SandboxBlockStoreContext): Promise<void>;
}

const DEFAULT_COW_MAX_DIRTY_BYTES = 64 * 1024 * 1024;
const MAX_PTY_SIZE = 65_535;
const rootfsImageStorage = new WeakMap<Qcow2RootfsImage, {
  readonly blockStore: SandboxBlockStore;
  readonly context: SandboxBlockStoreContext;
}>();

/**
 * Middleware invoked for an HTTP request allowed by a network policy.
 *
 * Middleware may mutate `request.headers` to add, replace, or remove outbound
 * request headers before the request leaves the sandbox boundary.
 */
export type HttpRequestMiddleware = (
  request: SandboxHttpRequest,
) => void | Promise<void>;

/**
 * Opaque grant returned by `conn.accept()`.
 *
 * Grants intentionally carry no public fields today. They reserve a stable
 * extension point for future instance-local grant state.
 */
export interface NetworkGrant {
}

/**
 * Opaque grant returned by `conn.acceptHttp(...)`.
 *
 * HTTP grants are distinct from generic network grants so future HTTP-specific
 * policy state can remain type-safe.
 */
export interface HttpNetworkGrant extends NetworkGrant {
}

/** IP transport observed by the network policy hook. */
export type NetworkTransport = "tcp" | "udp";

/** Endpoint accepted by transport match helpers. */
export type NetworkEndpointSpec =
  | `${string}:${number}`
  | {
    /** Numeric destination IP address. */
    readonly ip: string;
    /** Destination transport port. */
    readonly port: number;
  };

/** Upstream DNS resolver used to answer an accepted DNS flow. */
export type DnsUpstreamResolver =
  | string
  | {
    /** Numeric upstream resolver IP address. */
    readonly ip: string;
    /** Upstream resolver port. Defaults to 53. */
    readonly port?: number;
  };

/** Options for accepting a matched DNS flow. */
export interface DnsAcceptOptions {
  /**
   * Ordered upstream resolvers used to answer this DNS query. Omit to use the
   * host environment resolver.
   */
  readonly resolvers?: readonly DnsUpstreamResolver[];
}

/** HTTP authority accepted by HTTP match helpers. */
export type HttpAuthoritySpec =
  | string
  | {
    /** Trusted HTTP authority hostname. */
    readonly hostname: string;
    /** Trusted HTTP authority port. Omit to match any port. */
    readonly port?: number;
  };

/** Synchronous predicate used by protocol-specific match helpers. */
export type NetworkMatchPredicate<TMatch> = (candidate: TMatch) => boolean;

/**
 * Source or destination endpoint for a network policy event.
 *
 * Endpoint helpers classify the IP address only. They do not use DNS names,
 * HTTP host headers, TLS SNI, or any other application-layer metadata.
 */
export interface NetworkEndpoint {
  /** Numeric IP address observed at the sandbox network boundary. */
  readonly ip: string;
  /** Transport-layer port observed at the sandbox network boundary. */
  readonly port: number;
  /** True for IPv4 and IPv6 loopback addresses. */
  isLoopback(): boolean;
  /** True for private-use address ranges such as RFC 1918 and IPv6 ULA. */
  isPrivate(): boolean;
  /** True for link-local address ranges. */
  isLinkLocal(): boolean;
  /** True for multicast address ranges. */
  isMulticast(): boolean;
  /** True for the IPv4 limited broadcast address. */
  isBroadcast(): boolean;
  /** True for documentation and example address ranges. */
  isDocumentation(): boolean;
  /** True for reserved or otherwise non-public address ranges. */
  isReserved(): boolean;
  /** True when the address is not classified as local, private, reserved, or documentation. */
  isPublicInternet(): boolean;
}

/**
 * Capability returned when a DNS flow matches a policy predicate.
 *
 * DNS matching normalizes DNS over UDP and DNS over TCP. `accept()` permits the
 * matched DNS flow using the transport semantics observed by the runtime.
 */
export interface DnsConnectionMatch {
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: NetworkEndpoint;
  /** Internal DNS endpoint observed at the sandbox network boundary. */
  readonly dst: NetworkEndpoint;
  /** IP transport carrying this DNS flow. */
  readonly transport: NetworkTransport;
  /** Accepts this matched DNS flow. */
  accept(options?: DnsAcceptOptions): NetworkGrant;
}

/**
 * Capability returned when a raw TCP endpoint matches a policy predicate.
 */
export interface TcpConnectionMatch {
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: TcpNetworkEndpoint;
  /** Destination endpoint observed at the sandbox network boundary. */
  readonly dst: TcpNetworkEndpoint;
  /** Accepts this matched TCP flow without protocol-specific enforcement. */
  accept(): NetworkGrant;
}

/**
 * Capability returned when a raw UDP endpoint matches a policy predicate.
 */
export interface UdpConnectionMatch {
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: UdpNetworkEndpoint;
  /** Destination endpoint observed at the sandbox network boundary. */
  readonly dst: UdpNetworkEndpoint;
  /** Accepts this matched UDP flow. */
  accept(): NetworkGrant;
}

/**
 * Capability returned when trusted connection metadata matches an HTTP
 * authority predicate.
 *
 * This match does not trust the HTTP `Host` header. `accept(...)` still routes
 * the TCP flow through Sandbox's HTTP-family enforcement path, so non-HTTP
 * traffic fails closed even if its destination metadata matched.
 */
export interface HttpConnectionMatch {
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: TcpNetworkEndpoint;
  /** Destination endpoint observed at the sandbox network boundary. */
  readonly dst: TcpNetworkEndpoint;
  /** Trusted hostname for the HTTP authority. */
  readonly hostname: string;
  /** Destination port for the HTTP authority. */
  readonly port: number;
  /** Accepts this matched HTTP-family flow with optional request middleware. */
  accept(middleware?: HttpRequestMiddleware): HttpNetworkGrant;
}

/** TCP endpoint for a TCP network policy event. */
export interface TcpNetworkEndpoint extends NetworkEndpoint {
  readonly port: number;
}

/** UDP endpoint for a UDP network policy event. */
export interface UdpNetworkEndpoint extends NetworkEndpoint {
  readonly port: number;
}

/**
 * Common fields shared by all network policy events.
 *
 * `transport` is the only stable discriminant. Higher-level protocol semantics
 * are opt-in through protocol-specific accept helpers.
 */
export interface NetworkConnectionRequestBase<TTransport extends NetworkTransport> {
  /** IP transport that carried this event. Narrows TCP vs UDP request shapes. */
  readonly transport: TTransport;
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: NetworkEndpoint;
  /** Destination endpoint observed at the sandbox network boundary. */
  readonly dst: NetworkEndpoint;
  /**
   * Accepts this observed connection, request, or flow using transport-level
   * semantics.
   */
  accept(): NetworkGrant;
  /**
   * Returns a DNS capability when this policy event is DNS traffic.
   */
  matchDns(): DnsConnectionMatch | undefined;
  /**
   * Returns an HTTP capability when this TCP connection has trusted destination
   * metadata matching the authority predicate. Returns `undefined` for non-TCP
   * policy events.
   *
   * This helper does not classify arbitrary bytes as HTTP and does not inspect
   * the HTTP `Host` header. Use the returned capability's `accept(...)` method
   * to enter HTTP-family enforcement.
   */
  matchHttp(
    matcher: HttpAuthoritySpec | NetworkMatchPredicate<HttpConnectionMatch>,
  ): HttpConnectionMatch | undefined;
}

/**
 * TCP transport policy event.
 *
 * This event grants or denies TCP reachability for the observed flow.
 */
export interface TcpNetworkConnectionRequest extends NetworkConnectionRequestBase<"tcp"> {
  readonly src: TcpNetworkEndpoint;
  readonly dst: TcpNetworkEndpoint;
  /**
   * Accepts this TCP flow only through Sandbox's HTTP-family enforcement path.
   *
   * If the flow is not HTTP or HTTPS, the connection fails closed. Plain
   * `accept()` leaves bytes untouched and never enters HTTP middleware or MITM.
   */
  acceptHttp(middleware?: HttpRequestMiddleware): HttpNetworkGrant;
  /**
   * Returns a raw TCP capability when this connection matches the endpoint
   * predicate.
   */
  matchTcp(
    matcher: NetworkEndpointSpec | NetworkMatchPredicate<TcpConnectionMatch>,
  ): TcpConnectionMatch | undefined;
}

/**
 * UDP transport policy event.
 *
 * UDP is connectionless, so `accept()` permits the observed UDP flow according
 * to the runtime's flow-tracking semantics rather than establishing a stream.
 */
export interface UdpNetworkConnectionRequest extends NetworkConnectionRequestBase<"udp"> {
  readonly src: UdpNetworkEndpoint;
  readonly dst: UdpNetworkEndpoint;
  /**
   * Returns a raw UDP capability when this datagram flow matches the endpoint
   * predicate.
   */
  matchUdp(
    matcher: NetworkEndpointSpec | NetworkMatchPredicate<UdpConnectionMatch>,
  ): UdpConnectionMatch | undefined;
}

/**
 * Network policy event passed to `network.policy(...)`.
 *
 * Use `transport` to branch on TCP vs UDP. Protocol-specific behavior is only
 * entered through explicit helpers such as `acceptHttp(...)`.
 */
export type NetworkConnectionRequest =
  | TcpNetworkConnectionRequest
  | UdpNetworkConnectionRequest;

/** Callback invoked whenever the sandbox asks user policy to allow network egress. */
export type NetworkConnectionRequestHandler = (
  connection: NetworkConnectionRequest,
) => void | Promise<void>;

const networkPolicyHandler: unique symbol = Symbol("networkPolicyHandler");

export type NetworkPolicy = {
  /** Identifies this value as a network policy definition. */
  readonly kind: "network-policy";
  readonly [networkPolicyHandler]: NetworkConnectionRequestHandler;
};

type NetworkPolicyHookRegistration = {
  readonly hooks: readonly RegisteredHttpRequestHeadersHook[];
  readonly connectionHook: RegisteredNetworkConnectionHook;
  readonly network: InternalNetworkConfig;
};

export interface SandboxDefinitionOptions {
  readonly rootfs: Rootfs;
  readonly resources?: SandboxResourceLimits;
  readonly network?: NetworkPolicy;
}

export interface SandboxResourceLimits {
  readonly cpus?: number;
  readonly memoryMiB?: number;
}

export interface SandboxBootOptions {
  readonly mounts?: Readonly<Record<string, SandboxFileSystemSource>>;
  readonly cwd?: string;
  readonly hostname?: string;
}

export interface SandboxDefinition {
  boot(options?: SandboxBootOptions): Promise<SandboxInstance>;
}

export interface SandboxExecOptions {
  readonly cwd?: string;
  readonly env?: Record<string, string>;
  /**
   * Maximum wall-clock runtime for the guest process. When the timeout expires,
   * Sandbox terminates the guest process group and returns exit code 124.
   */
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
}

export interface SandboxSpawnOptions {
  readonly cwd?: string;
  readonly env?: Record<string, string>;
  readonly signal?: AbortSignal;
}

export interface SandboxPtyOptions {
  readonly cwd?: string;
  readonly env?: Record<string, string>;
  readonly size: SandboxPtySize;
  readonly signal?: AbortSignal;
}

export interface SandboxPtySize {
  readonly rows: number;
  readonly cols: number;
}

export interface SandboxExecResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SandboxProcess {
  readonly stdin: WritableStream<Uint8Array>;
  readonly stdout: ReadableStream<Uint8Array>;
  readonly stderr: ReadableStream<Uint8Array>;
  readonly ready: Promise<void>;
  readonly exit: Promise<SandboxProcessExit>;
  kill(signal?: SandboxSignal): void;
}

export interface SandboxPty {
  readonly input: WritableStream<Uint8Array>;
  readonly output: ReadableStream<Uint8Array>;
  readonly ready: Promise<void>;
  readonly exit: Promise<SandboxProcessExit>;
  resize(size: SandboxPtySize): void;
  kill(signal?: SandboxSignal): void;
}

export interface SandboxProcessExit {
  readonly exitCode: number | null;
  readonly signal: SandboxSignal | null;
}

export type SandboxSignal =
  | "SIGHUP"
  | "SIGINT"
  | "SIGQUIT"
  | "SIGTERM"
  | "SIGKILL";

export interface SandboxInstance {
  exec(
    command: string,
    args?: readonly string[],
    options?: SandboxExecOptions,
  ): Promise<SandboxExecResult>;
  spawn(
    command: string,
    args?: readonly string[],
    options?: SandboxSpawnOptions,
  ): SandboxProcess;
  pty(
    command: string,
    options: SandboxPtyOptions,
  ): SandboxPty;
  pty(
    command: string,
    args: readonly string[] | undefined,
    options: SandboxPtyOptions,
  ): SandboxPty;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface SandboxVm extends SandboxInstance {
  readonly control: SandboxControl;
  readonly diagnostics?: SandboxDiagnostics;
}

interface SandboxDiagnostics {
  terminateHostForTest(): Promise<void>;
}

export const rootfs = {
  builtIn(name: BuiltInRootfsName): BuiltInRootfsConfig {
    return {
      kind: "built-in-rootfs",
      name,
    };
  },
  compose(options: {
    readonly base: BuiltInRootfsConfig;
    readonly overlay: SandboxBlockStore;
  }): ComposedRootfsConfig {
    return composeRootfs(options);
  },
  cow(options: {
    readonly source: ComposedRootfsConfig;
    readonly maxDirtyBytes?: number;
  } | {
    readonly base: BuiltInRootfsConfig;
    readonly writable: SandboxBlockStore;
    readonly maxDirtyBytes?: number;
  }): Rootfs {
    const source = "source" in options
      ? options.source
      : composeRootfs({
        base: options.base,
        overlay: options.writable,
      });
    return {
      kind: "cow-rootfs",
      source,
      ...(options.maxDirtyBytes === undefined ? {} : { maxDirtyBytes: options.maxDirtyBytes }),
    };
  },
  async flatten(options: {
    readonly format: "qcow2";
    readonly source: BuiltInRootfsConfig | ComposedRootfsConfig;
    readonly dest: SandboxBlockStore;
    readonly clusterSize?: number;
  }): Promise<Qcow2RootfsImage> {
    if (options.format !== "qcow2") {
      throw new Error("invalid rootfs flatten options: format must be qcow2");
    }
    validateImageDestination(options.dest);
    validateQcow2Options(options);
    const source = options.source.kind === "built-in-rootfs"
      ? composeRootfs({
        base: options.source,
        overlay: createEphemeralCowBlockStore(),
      })
      : options.source;
    if (source.base.kind !== "built-in-rootfs") {
      throw new Error("invalid rootfs source: base must be created with rootfs.builtIn(...)");
    }
    validateBuiltInRootfsName(source.base.name);
    validateBlockStore(source.overlay);
    const destContext = {
      base: `rootfs-image:qcow2:${randomUUID()}`,
    };
    if ((await options.dest.list(destContext)).length !== 0) {
      throw new Error("invalid rootfs image destination: destination block store context must be empty");
    }
    const result = await HostProcessSandboxVm.flattenQcow2({
      basePath: builtInRootfsPath(source.base.name),
      overlay: source.overlay,
      overlayContext: {
        base: builtInRootfsIdentity(source.base.name),
      },
      dest: options.dest,
      destContext,
      clusterSize: options.clusterSize ?? 65536,
    });
    const image: Qcow2RootfsImage = {
      kind: "rootfs-image",
      format: "qcow2",
      sizeBytes: result.sizeBytes,
    };
    rootfsImageStorage.set(image, {
      blockStore: options.dest,
      context: destContext,
    });
    return image;
  },
  async *bytes(
    image: BuiltInRootfsConfig | Qcow2RootfsImage,
    options: {
      readonly chunkSize?: number;
      readonly signal?: AbortSignal;
    } = {},
  ): AsyncIterable<Uint8Array> {
    const chunkSize = validateByteStreamChunkSize(options.chunkSize);
    if (image.kind === "built-in-rootfs") {
      const file = await open(builtInRootfsPath(image.name), "r");
      try {
        const buffer = new Uint8Array(chunkSize);
        let offset = 0;
        while (true) {
          options.signal?.throwIfAborted();
          const { bytesRead } = await file.read(buffer, 0, buffer.byteLength, offset);
          if (bytesRead === 0) {
            return;
          }
          offset += bytesRead;
          yield buffer.slice(0, bytesRead);
        }
      } finally {
        await file.close();
      }
      return;
    }

    const storage = rootfsImageStorage.get(image);
    if (storage === undefined) {
      throw new Error("invalid rootfs image: image was not created by rootfs.flatten(...)");
    }
    let offset = 0n;
    while (offset < image.sizeBytes) {
      options.signal?.throwIfAborted();
      const remaining = image.sizeBytes - offset;
      const nextLength = Number(remaining < BigInt(chunkSize) ? remaining : BigInt(chunkSize));
      yield await readBlockStoreBytes(storage.blockStore, storage.context, offset, nextLength);
      offset += BigInt(nextLength);
    }
  },
};

function composeRootfs(options: {
  readonly base: BuiltInRootfsConfig;
  readonly overlay: SandboxBlockStore;
}): ComposedRootfsConfig {
  return {
    kind: "composed-rootfs",
    base: options.base,
    overlay: options.overlay,
  };
}

function virtualFs(fileSystem: SandboxPosixFileSystem): SandboxWritableFileSystemSource;
function virtualFs(fileSystem: SandboxFileSystem): SandboxFileSystemSource;
function virtualFs(fileSystem: SandboxFileSystem): SandboxFileSystemSource {
  return {
    kind: "virtual-fs",
    fileSystem,
  };
}

export const fs = {
  memory: createMemoryFileSystem,
  virtual: virtualFs,
};

export const network = {
  policy(onConnectionRequest: NetworkConnectionRequestHandler): NetworkPolicy {
    return {
      kind: "network-policy",
      [networkPolicyHandler]: onConnectionRequest,
    };
  },
};

export function defineSandbox(options: SandboxDefinitionOptions): SandboxDefinition {
  validateSandboxDefinitionOptions(options);
  return new DefinedSandbox(options);
}

type SpawnHttpRequestHeadersHook = {
  readonly id: string;
  readonly selector: SandboxHttpRequestSelector;
};

class DefinedSandbox implements SandboxDefinition {
  readonly #options: SandboxDefinitionOptions;

  constructor(options: SandboxDefinitionOptions) {
    this.#options = options;
  }

  async boot(options: SandboxBootOptions = {}): Promise<SandboxInstance> {
    validateSandboxBootOptions(options);
    const networkPolicy = this.#options.network === undefined
      ? undefined
      : createNetworkPolicyHookRegistration(this.#options.network);
    const launchOptions = await toInternalSandboxOptions(
      this.#options,
      options,
      networkPolicy?.network,
      (networkPolicy?.hooks.length ?? 0) > 0,
    );
    try {
      validateInternalSandboxOptions(launchOptions);
      const hostOptions = toHostSpawnOptions(launchOptions, networkPolicy?.hooks ?? []);
      const hostVm = await HostProcessSandboxVm.spawn(
        launchOptions,
        hostOptions,
        new Map((networkPolicy?.hooks ?? []).map((hook) => [hook.id, hook])),
        networkPolicy?.connectionHook,
      );
      return new HostBackedSandboxVm(hostVm, launchOptions);
    } catch (error) {
      throw error;
    }
  }
}

class HostBackedSandboxVm implements SandboxVm {
  readonly control: SandboxControl;
  readonly diagnostics?: SandboxDiagnostics;
  readonly #exec: ControlBackedSandboxExec;
  readonly #rootExec: ControlBackedSandboxExec;
  readonly #options: InternalSandboxOptions;

  readonly #hostVm: {
    readonly hasControlSocket: boolean;
    readonly packets: AsyncIterable<Uint8Array>;
    writeControlPacket(packet: Uint8Array): void;
    close(): Promise<void> | void;
    terminateHostForTest?(): Promise<void>;
  };
  #closed = false;

  constructor(
    hostVm: {
      readonly hasControlSocket: boolean;
      readonly packets: AsyncIterable<Uint8Array>;
      writeControlPacket(packet: Uint8Array): void;
      close(): Promise<void> | void;
      terminateHostForTest?(): Promise<void>;
    },
    options: InternalSandboxOptions,
  ) {
    this.#hostVm = hostVm;
    this.#options = options;
    this.control = new HostControlTransport({
      connected: hostVm.hasControlSocket,
      channel: hostVm,
    });
    this.#exec = new ControlBackedSandboxExec(this.control, options.cwd);
    this.#rootExec = new ControlBackedSandboxExec(this.control, "/");
    if (hostVm.terminateHostForTest !== undefined) {
      this.diagnostics = {
        terminateHostForTest: () => hostVm.terminateHostForTest?.() ?? Promise.resolve(),
      };
    }
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    let syncError: unknown;
    if (this.#options.rootfs.storage !== undefined) {
      try {
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const result = await this.#rootExec.exec("/bin/sync", []);
          if (result.exitCode !== 0) {
            throw new Error(`sandbox close sync failed with exit code ${result.exitCode}: ${result.stderr}`);
          }
          if (attempt === 0) {
            await delay(100);
          }
        }
      } catch (error) {
        syncError = error;
      }
    }
    try {
      await this.control.close();
      await this.#hostVm.close();
    } finally {
    }
    if (syncError !== undefined) {
      throw syncError;
    }
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  async exec(
    command: string,
    args: readonly string[] | undefined = [],
    options: SandboxExecOptions = {},
  ): Promise<SandboxExecResult> {
    args ??= [];
    validateSandboxProcessArgs(args, "sandbox exec");
    validateSandboxExecOptions(options);
    return await this.#exec.exec(command, args, options);
  }

  spawn(
    command: string,
    args: readonly string[] | undefined = [],
    options: SandboxSpawnOptions = {},
  ): SandboxProcess {
    args ??= [];
    validateSandboxProcessArgs(args, "sandbox spawn");
    validateSandboxSpawnOptions(options);
    const process = new ControlBackedSandboxSpawn(this.control, this.#options.cwd)
      .spawn(command, args, options);
    linkAbortSignal(options.signal, process);
    return process;
  }

  pty(
    command: string,
    argsOrOptions: readonly string[] | SandboxPtyOptions | undefined,
    options?: SandboxPtyOptions,
  ): SandboxPty {
    let args: readonly string[];
    let ptyOptions: SandboxPtyOptions | undefined;
    if (Array.isArray(argsOrOptions) || argsOrOptions === undefined) {
      args = argsOrOptions ?? [];
      ptyOptions = options;
    } else {
      args = [];
      ptyOptions = argsOrOptions as SandboxPtyOptions;
    }
    validateSandboxProcessArgs(args, "sandbox pty");
    validateSandboxPtyOptions(ptyOptions);
    const process = new ControlBackedSandboxSpawn(this.control, this.#options.cwd)
      .pty(command, args, ptyOptions);
    linkAbortSignal(ptyOptions.signal, process);
    return process;
  }
}

function linkAbortSignal(
  signal: AbortSignal | undefined,
  process: { readonly exit: Promise<unknown>; kill(signal?: SandboxSignal): void },
): void {
  if (signal === undefined) {
    return;
  }
  const abort = () => {
    process.kill("SIGTERM");
  };
  if (signal.aborted) {
    abort();
    return;
  }
  signal.addEventListener("abort", abort, { once: true });
  void process.exit.then(
    () => signal.removeEventListener("abort", abort),
    () => signal.removeEventListener("abort", abort),
  );
}

class ControlBackedSandboxExec {
  readonly #control: SandboxControl;
  readonly #cwd: string | undefined;

  constructor(control: SandboxControl, cwd: string | undefined) {
    this.#control = control;
    this.#cwd = cwd;
  }

  async exec(
    command: string,
    args: readonly string[] | undefined = [],
    options: SandboxExecOptions = {},
  ): Promise<SandboxExecResult> {
    args ??= [];
    const cwd = options.cwd ?? this.#cwd;
    const env = cwd === undefined
      ? options.env
      : {
          ...options.env,
          SANDBOX_EXEC_CWD: cwd,
          PWD: cwd,
        };
    const argv = cwd === undefined
      ? [command, ...args]
      : ["/bin/sh", "-lc", "cd \"$SANDBOX_EXEC_CWD\" && exec \"$@\"", "sandbox-exec", command, ...args];
    const result = await this.#control.exec({
      argv,
      env,
      timeoutMs: options.timeoutMs,
      signal: options.signal,
    });
    return {
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }

}

class ControlBackedSandboxSpawn {
  readonly #control: SandboxControl;
  readonly #cwd: string | undefined;

  constructor(control: SandboxControl, cwd: string | undefined) {
    this.#control = control;
    this.#cwd = cwd;
  }

  spawn(
    command: string,
    args: readonly string[] | undefined = [],
    options: SandboxSpawnOptions = {},
  ): ControlBackedSandboxProcess {
    args ??= [];
    const cwd = options.cwd ?? this.#cwd;
    const env = cwd === undefined
      ? options.env
      : {
          ...options.env,
          SANDBOX_EXEC_CWD: cwd,
          PWD: cwd,
        };
    const argv = cwd === undefined
      ? [command, ...args]
      : ["/bin/sh", "-lc", "cd \"$SANDBOX_EXEC_CWD\" && exec \"$@\"", "sandbox-spawn", command, ...args];
    return this.#control.spawn({
      argv,
      env,
    });
  }

  pty(
    command: string,
    args: readonly string[] | undefined,
    options: SandboxPtyOptions,
  ): ControlBackedSandboxPty {
    args ??= [];
    const cwd = options.cwd ?? this.#cwd;
    const env = cwd === undefined
      ? options.env
      : {
          ...options.env,
          SANDBOX_EXEC_CWD: cwd,
          PWD: cwd,
        };
    const argv = cwd === undefined
      ? [command, ...args]
      : ["/bin/sh", "-lc", "cd \"$SANDBOX_EXEC_CWD\" && exec \"$@\"", "sandbox-pty", command, ...args];
    return this.#control.pty({
      argv,
      env,
      size: options.size,
    });
  }
}

function toHostSpawnOptions(
  options: InternalSandboxOptions,
  requestHeaderHooks: readonly SpawnHttpRequestHeadersHook[],
): HostSpawnSandboxOptions {
  if (
    (requestHeaderHooks.length > 0 || options.network?.http !== undefined)
    && options.network?.outbound === undefined
  ) {
    throw new Error("invalid sandbox options: network.outbound is required when HTTP interception is configured");
  }
  const network = options.network === undefined && requestHeaderHooks.length === 0
    ? undefined
    : {
      outbound: options.network?.outbound,
      http: requestHeaderHooks.length === 0
        && options.network?.http?.caCertificatePem === undefined
        ? undefined
        : {
          caCertificatePem: options.network?.http?.caCertificatePem,
          caPrivateKeyPem: options.network?.http?.caPrivateKeyPem,
          requestHeaderHooks: requestHeaderHooks.map((hook) => ({
            id: hook.id,
            origin: hook.selector.origin,
          })),
        },
      policy: options.network?.policy,
    };

  return {
    kernel: {
      format: undefined,
    },
    cpu: {
      vcpus: options.resources?.cpus,
    },
    memory: {
      mib: options.resources?.memoryMiB,
    },
    init: {
      crateName: "sandbox-init",
    },
    hostname: options.hostname,
    rootfs: options.rootfs,
    mounts: options.mounts?.map((mount) => {
      return {
        kind: "virtual-fs",
        path: mount.path,
        writable: isSandboxWritableFileSystem(mount.fileSystem),
      };
    }),
    network,
  };
}

async function toInternalSandboxOptions(
  config: SandboxDefinitionOptions,
  boot: SandboxBootOptions,
  network?: InternalNetworkConfig,
  httpInterception = false,
): Promise<InternalSandboxOptions> {
  const rootfs = await lowerRootfs(config.rootfs, { httpInterception });
  return {
    resources: config.resources,
    rootfs,
    cwd: boot.cwd,
    hostname: boot.hostname ?? "sandbox",
    mounts: Object.entries(boot.mounts ?? {}).map(([path, source]) => {
      return {
        path,
        fileSystem: source.fileSystem,
      };
    }),
    network,
  };
}

function createNetworkPolicyHookRegistration(policy: NetworkPolicy): NetworkPolicyHookRegistration {
  const hook: HttpRequestMiddleware = async (request) => {
    void request;
  };
  const hooks: RegisteredHttpRequestHeadersHook[] = [
    {
      id: "network-policy-http",
      selector: { origin: "http://*" },
      hook,
      active: true,
    },
    {
      id: "network-policy-https",
      selector: { origin: "https://*" },
      hook,
      active: true,
    },
  ];
  return {
    hooks,
    connectionHook: {
      hook: policy[networkPolicyHandler],
      active: true,
    },
    network: {
      policy: {
        connectionHook: true,
      },
      outbound: {
        policy: "deny",
        rules: [
          { action: "accept", scope: "public-internet", ports: [] },
          { action: "accept", protocol: "tcp", cidr: "10.0.2.1/32", ports: [53] },
          { action: "accept", protocol: "udp", cidr: "10.0.2.1/32", ports: [53] },
        ],
      },
    },
  };
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

function isLoopbackIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 127;
  }
  return normalizeIpv6(ip) === "::1";
}

function isPrivateIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 10
      || (ipv4[0] === 172 && ipv4[1] >= 16 && ipv4[1] <= 31)
      || (ipv4[0] === 192 && ipv4[1] === 168);
  }
  return ipv6StartsWith(ip, "fc") || ipv6StartsWith(ip, "fd");
}

function isLinkLocalIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] === 169 && ipv4[1] === 254;
  }
  return ipv6StartsWith(ip, "fe8")
    || ipv6StartsWith(ip, "fe9")
    || ipv6StartsWith(ip, "fea")
    || ipv6StartsWith(ip, "feb");
}

function isMulticastIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return ipv4[0] >= 224 && ipv4[0] <= 239;
  }
  return ipv6StartsWith(ip, "ff");
}

function isDocumentationIp(ip: string): boolean {
  const ipv4 = parseIpv4(ip);
  if (ipv4 !== undefined) {
    return (ipv4[0] === 192 && ipv4[1] === 0 && ipv4[2] === 2)
      || (ipv4[0] === 198 && ipv4[1] === 51 && ipv4[2] === 100)
      || (ipv4[0] === 203 && ipv4[1] === 0 && ipv4[2] === 113);
  }
  return normalizeIpv6(ip).startsWith("2001:db8:");
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
  return normalizeIpv6(ip).startsWith("2001:db8:");
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

function normalizeIpv6(ip: string): string {
  return ip.toLowerCase();
}

function ipv6StartsWith(ip: string, prefix: string): boolean {
  return parseIpv4(ip) === undefined && normalizeIpv6(ip).startsWith(prefix);
}

async function lowerRootfs(
  rootfs: Rootfs,
  options: {
    readonly httpInterception?: boolean;
  } = {},
): Promise<InternalSandboxOptions["rootfs"]> {
  switch (rootfs.kind) {
    case "built-in-rootfs": {
      if (options.httpInterception === true) {
        const writable = createEphemeralCowBlockStore();
        return lowerCowRootfs(rootfs, writable, resolveCowMaxDirtyBytes(writable));
      }
      return {
        path: builtInRootfsPath(rootfs.name),
        readonly: true,
        format: "qcow2",
      };
    }
    case "cow-rootfs":
      return lowerCowRootfs(
        rootfs.source.base,
        rootfs.source.overlay,
        resolveCowMaxDirtyBytes(rootfs.source.overlay, rootfs.maxDirtyBytes),
      );
  }
}

function lowerCowRootfs(
  base: BuiltInRootfsConfig,
  writable: SandboxBlockStore,
  maxDirtyBytes: number,
): InternalSandboxOptions["rootfs"] {
  return {
    path: builtInRootfsPath(base.name),
    readonly: false,
    format: "qcow2",
    storage: {
      kind: "cow-block-store",
      blockSize: writable.blockSize,
      maxDirtyBytes,
      blockStore: writable,
      context: {
        base: builtInRootfsIdentity(base.name),
      },
    },
  };
}

function createEphemeralCowBlockStore(): SandboxBlockStore {
  const blocks = new Map<bigint, Uint8Array>();
  return {
    blockSize: 65536,
    async list() {
      return Array.from(blocks.keys());
    },
    async read(range) {
      const chunks: SandboxBlockChunk[] = [];
      for (let offset = 0; offset < range.count; offset += 1) {
        const start = range.start + BigInt(offset);
        const data = blocks.get(start);
        if (data !== undefined) {
          chunks.push({ start, data: data.slice() });
        }
      }
      return chunks;
    },
    async write(chunks) {
      for (const chunk of chunks) {
        blocks.set(chunk.start, chunk.data.slice());
      }
    },
  };
}

function validateRootfs(rootfs: Rootfs): void {
  switch (rootfs.kind) {
    case "built-in-rootfs":
      validateBuiltInRootfsName(rootfs.name);
      return;
    case "cow-rootfs":
      if (rootfs.source?.kind !== "composed-rootfs") {
        throw new Error("invalid sandbox definition: rootfs.cow source must be created with rootfs.compose(...)");
      }
      if (rootfs.source.base.kind !== "built-in-rootfs") {
        throw new Error("invalid sandbox definition: rootfs.cow base must be created with rootfs.builtIn(...)");
      }
      validateBuiltInRootfsName(rootfs.source.base.name);
      validateBlockStore(rootfs.source.overlay);
      validateCowMaxDirtyBytes(rootfs);
      return;
    default:
      throw new Error(
        "invalid sandbox definition: rootfs must be created with rootfs.builtIn(...) or rootfs.cow(...)",
      );
  }
}

function validateBlockStore(blockStore: SandboxBlockStore): void {
  if (!Number.isInteger(blockStore.blockSize) || blockStore.blockSize <= 0) {
    throw new Error("invalid sandbox definition: rootfs COW block size must be a positive integer");
  }
  if (blockStore.blockSize % 512 !== 0) {
    throw new Error("invalid sandbox definition: rootfs COW block size must be a multiple of 512 bytes");
  }
  if (typeof blockStore.list !== "function") {
    throw new Error("invalid sandbox definition: rootfs COW block store must provide list()");
  }
  if (typeof blockStore.read !== "function") {
    throw new Error("invalid sandbox definition: rootfs COW block store must provide read()");
  }
  if (typeof blockStore.write !== "function") {
    throw new Error("invalid sandbox definition: rootfs COW block store must provide write()");
  }
}

function validateImageDestination(blockStore: SandboxBlockStore): void {
  if (!Number.isInteger(blockStore.blockSize) || blockStore.blockSize <= 0) {
    throw new Error("invalid rootfs image destination: blockSize must be a positive integer");
  }
  if (blockStore.blockSize % 512 !== 0) {
    throw new Error("invalid rootfs image destination: blockSize must be a positive multiple of 512 bytes");
  }
  if (typeof blockStore.list !== "function") {
    throw new Error("invalid rootfs image destination: block store must provide list()");
  }
  if (typeof blockStore.read !== "function") {
    throw new Error("invalid rootfs image destination: block store must provide read()");
  }
  if (typeof blockStore.write !== "function") {
    throw new Error("invalid rootfs image destination: block store must provide write()");
  }
}

function validateQcow2Options(options: { readonly clusterSize?: number } | undefined): void {
  if (options?.clusterSize !== undefined) {
    const size = options.clusterSize;
    if (!Number.isInteger(size) || size < 512 || size > 2 * 1024 * 1024 || (size & (size - 1)) !== 0) {
      throw new Error("invalid rootfs QCOW2 options: clusterSize must be a power of two between 512 and 2097152 bytes");
    }
  }
}

function validateByteStreamChunkSize(chunkSize: number | undefined): number {
  if (chunkSize === undefined) {
    return 1024 * 1024;
  }
  if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
    throw new Error("invalid rootfs bytes options: chunkSize must be a positive safe integer");
  }
  return chunkSize;
}

async function readBlockStoreBytes(
  blockStore: SandboxBlockStore,
  context: SandboxBlockStoreContext,
  offset: bigint,
  length: number,
): Promise<Uint8Array> {
  const output = new Uint8Array(length);
  const blockSize = BigInt(blockStore.blockSize);
  const firstBlock = offset / blockSize;
  const blockOffset = Number(offset % blockSize);
  const count = Math.ceil((blockOffset + length) / blockStore.blockSize);
  const chunks = await blockStore.read({ start: firstBlock, count }, context);
  for (const chunk of chunks) {
    const chunkStart = chunk.start * blockSize;
    const chunkEnd = chunkStart + BigInt(chunk.data.byteLength);
    const outputStart = offset > chunkStart ? Number(offset - chunkStart) : 0;
    const sourceStart = chunkStart > offset ? Number(chunkStart - offset) : 0;
    const readable = Number((chunkEnd < offset + BigInt(length) ? chunkEnd : offset + BigInt(length)) - (chunkStart > offset ? chunkStart : offset));
    if (readable > 0) {
      output.set(chunk.data.subarray(outputStart, outputStart + readable), sourceStart);
    }
  }
  return output;
}

function validateCowMaxDirtyBytes(rootfs: CowRootfsConfig): void {
  if (rootfs.maxDirtyBytes === undefined) {
    return;
  }
  if (!Number.isSafeInteger(rootfs.maxDirtyBytes) || rootfs.maxDirtyBytes <= 0) {
    throw new Error("invalid sandbox definition: rootfs COW maxDirtyBytes must be a positive safe integer");
  }
  if (rootfs.maxDirtyBytes < rootfs.source.overlay.blockSize) {
    throw new Error("invalid sandbox definition: rootfs COW maxDirtyBytes must be at least the COW block size");
  }
}

function resolveCowMaxDirtyBytes(blockStore: SandboxBlockStore, maxDirtyBytes?: number): number {
  if (maxDirtyBytes !== undefined) {
    return maxDirtyBytes;
  }
  return Math.ceil(DEFAULT_COW_MAX_DIRTY_BYTES / blockStore.blockSize) * blockStore.blockSize;
}

function validateSandboxDefinitionOptions(options: SandboxDefinitionOptions): void {
  validateRootfs(options.rootfs);
  if (options.resources?.cpus !== undefined && (!Number.isInteger(options.resources.cpus) || options.resources.cpus <= 0)) {
    throw new Error("invalid sandbox definition: resources.cpus must be a positive integer");
  }
  if (options.resources?.cpus !== undefined && options.resources.cpus > 255) {
    throw new Error("invalid sandbox definition: resources.cpus must be less than or equal to 255");
  }
  if (
    options.resources?.memoryMiB !== undefined
    && (!Number.isInteger(options.resources.memoryMiB) || options.resources.memoryMiB <= 0)
  ) {
    throw new Error("invalid sandbox definition: resources.memoryMiB must be a positive integer");
  }
  if (options.network !== undefined && options.network.kind !== "network-policy") {
    throw new Error("invalid sandbox definition: network must be created with network.policy(...)");
  }
}

function validateSandboxExecOptions(options: SandboxExecOptions): void {
  if (
    options.timeoutMs !== undefined
    && (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs <= 0)
  ) {
    throw new Error("invalid sandbox exec options: timeoutMs must be a positive safe integer");
  }
}

function validateSandboxSpawnOptions(_options: SandboxSpawnOptions): void {}

function validateSandboxPtyOptions(options: SandboxPtyOptions | undefined): asserts options is SandboxPtyOptions {
  if (options === undefined || options === null) {
    throw new Error("invalid sandbox pty options: size is required");
  }
  validatePtySize(options.size, "invalid sandbox pty options: size");
}

function validateSandboxProcessArgs(args: readonly string[], label: string): void {
  if (!Array.isArray(args)) {
    throw new Error(`invalid ${label} arguments: args must be an array`);
  }
  for (const [index, arg] of args.entries()) {
    if (typeof arg !== "string") {
      throw new Error(`invalid ${label} arguments: args[${index}] must be a string`);
    }
  }
}

function validatePtySize(size: SandboxPtySize, field: string): void {
  if (!Number.isSafeInteger(size.rows) || size.rows <= 0 || size.rows > MAX_PTY_SIZE) {
    throw new Error(`${field}.rows must be an integer between 1 and ${MAX_PTY_SIZE}`);
  }
  if (!Number.isSafeInteger(size.cols) || size.cols <= 0 || size.cols > MAX_PTY_SIZE) {
    throw new Error(`${field}.cols must be an integer between 1 and ${MAX_PTY_SIZE}`);
  }
}

function validateBuiltInRootfsName(name: string): void {
  if (name !== "alpine:3.23") {
    throw new Error(`unsupported built-in rootfs: ${name}`);
  }
}

function validateSandboxBootOptions(options: SandboxBootOptions): void {
  if (options.hostname !== undefined) {
    validateHostname(options.hostname, "hostname");
  }
  const mountPaths = new Set<string>();
  for (const [path, source] of Object.entries(options.mounts ?? {})) {
    validateGuestPath(path, "mount.path");
    if (mountPaths.has(path)) {
      throw new Error(`invalid sandbox boot options: duplicate mount path: ${path}`);
    }
    if (
      isSandboxWritableFileSystem(source.fileSystem)
      && !isSandboxPosixFileSystem(source.fileSystem)
    ) {
      throw new Error(`invalid sandbox boot options: writable mount must implement the POSIX filesystem interface: ${path}`);
    }
    mountPaths.add(path);
  }
  if (options.cwd !== undefined && !options.cwd.startsWith("/")) {
    throw new Error("invalid sandbox boot options: cwd must be absolute");
  }
}

function validateHostname(hostname: string, field: string): void {
  if (hostname.length === 0) {
    throw new Error(`invalid sandbox boot options: ${field} must not be empty`);
  }
  if (hostname.length > 64) {
    throw new Error(`invalid sandbox boot options: ${field} must be at most 64 characters`);
  }
  if (!/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(hostname)) {
    throw new Error(`invalid sandbox boot options: ${field} must be a valid hostname`);
  }
  for (const label of hostname.split(".")) {
    if (label.length === 0) {
      throw new Error(`invalid sandbox boot options: ${field} must be a valid hostname`);
    }
    if (label.length > 63) {
      throw new Error(`invalid sandbox boot options: ${field} labels must be at most 63 characters`);
    }
    if (label.startsWith("-") || label.endsWith("-")) {
      throw new Error(`invalid sandbox boot options: ${field} must be a valid hostname`);
    }
  }
}

function validateInternalSandboxOptions(options: InternalSandboxOptions): void {
  if (options.rootfs.path.length === 0) {
    throw new Error("invalid sandbox options: rootfs.path must not be empty");
  }
  if (options.rootfs.format !== "qcow2") {
    throw new Error("invalid sandbox options: rootfs.format must be qcow2");
  }

  const mountPaths = new Set<string>();
  for (const mount of options.mounts ?? []) {
    validateGuestPath(mount.path, "mount.path");
    if (mountPaths.has(mount.path)) {
      throw new Error(`invalid sandbox options: duplicate mount path: ${mount.path}`);
    }
    mountPaths.add(mount.path);
  }

  if (options.network?.outbound?.policy !== undefined && options.network.outbound.policy !== "deny") {
    throw new Error("invalid sandbox options: network.outbound.policy must be deny");
  }
  for (const rule of options.network?.outbound?.rules ?? []) {
    if ("cidr" in rule) {
      validateCidr(rule.cidr);
    }
    validateOutboundPorts(rule.ports);
  }
}

function validateGuestPath(path: string, field: "mount.path"): void {
  if (!path.startsWith("/")) {
    throw new Error(`invalid sandbox options: ${field} must be absolute`);
  }
  if (path === "/") {
    throw new Error(`invalid sandbox options: ${field} must not be root`);
  }
  if (path.includes("\0")) {
    throw new Error(`invalid sandbox options: ${field} must not contain NUL bytes`);
  }
  if (path.split("/").some((component) => component === "." || component === "..")) {
    throw new Error(`invalid sandbox options: ${field} must not contain '.' or '..' components`);
  }
}

function validateOutboundPorts(ports: readonly number[] | undefined): void {
  for (const port of ports ?? []) {
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new Error(`invalid sandbox options: invalid outbound network port: ${port}`);
    }
  }
}

function validateCidr(range: string): void {
  const [address, prefixText, extra] = range.split("/");
  if (address === undefined || prefixText === undefined || extra !== undefined) {
    throw new Error(`invalid sandbox options: invalid CIDR range: ${range}`);
  }

  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix)) {
    throw new Error(`invalid sandbox options: invalid CIDR prefix: ${range}`);
  }

  if (address.includes(":")) {
    if (prefix < 0 || prefix > 128) {
      throw new Error(`invalid sandbox options: invalid CIDR prefix: ${range}`);
    }
    if (parseIpv6Address(address) === null) {
      throw new Error(`invalid sandbox options: invalid CIDR address: ${range}`);
    }
    throw new Error(`invalid sandbox options: IPv6 outbound CIDR ranges are not supported yet: ${range}`);
  }

  if (prefix < 0 || prefix > 32) {
    throw new Error(`invalid sandbox options: invalid CIDR prefix: ${range}`);
  }
  if (parseIpv4Address(address) === null) {
    throw new Error(`invalid sandbox options: invalid CIDR address: ${range}`);
  }
}

function parseIpv4Address(address: string): number | null {
  const parts = address.split(".");
  if (parts.length !== 4) {
    return null;
  }
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) {
      return null;
    }
    const octet = Number(part);
    if (octet < 0 || octet > 255) {
      return null;
    }
    value = ((value << 8) | octet) >>> 0;
  }
  return value;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parseIpv6Address(address: string): bigint | null {
  const zoneIndex = address.indexOf("%");
  if (zoneIndex !== -1) {
    return null;
  }
  const doubleColonParts = address.split("::");
  if (doubleColonParts.length > 2) {
    return null;
  }

  const head = doubleColonParts[0] === "" ? [] : doubleColonParts[0]?.split(":") ?? [];
  const tail = doubleColonParts.length === 1 || doubleColonParts[1] === ""
    ? []
    : doubleColonParts[1]?.split(":") ?? [];
  const hasCompression = doubleColonParts.length === 2;
  const missing = 8 - head.length - tail.length;
  if ((!hasCompression && missing !== 0) || (hasCompression && missing < 1)) {
    return null;
  }

  const groups = [...head, ...Array<string>(hasCompression ? missing : 0).fill("0"), ...tail];
  if (groups.length !== 8) {
    return null;
  }

  let value = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) {
      return null;
    }
    value = (value << 16n) | BigInt(Number.parseInt(group, 16));
  }
  return value;
}
