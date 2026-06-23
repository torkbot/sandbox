import {
  type SandboxCommandEnvironmentFact,
  type SandboxDistroEnvironmentFact,
  type SandboxDistroVersion,
  type SandboxDistroVersionEnvironmentFact,
  type SandboxEnvironmentFact,
  type SandboxNetworkEgressEnvironmentFact,
  type SandboxPackageManagerEnvironmentFact,
  type SandboxRootfsEnvironmentFact,
  type SandboxShellEnvironmentFact,
} from "./environment-facts.ts";
import { randomUUID } from "node:crypto";
import { createReadStream, lstatSync, readdirSync, realpathSync } from "node:fs";
import { open } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve } from "node:path";
import { HostControlTransport } from "./control.ts";
import { HostProcessSandboxVm } from "./host-process.ts";
import { createMemoryFileSystem } from "./memory-fs.ts";
import {
  isSandboxPosixFileSystem,
  isSandboxWritableFileSystem,
} from "./vfs.ts";
import type { HostSpawnMount, HostSpawnSandboxOptions } from "./spawn-options.ts";
import type { ControlBackedSandboxProcess, ControlBackedSandboxPty, SandboxControl } from "./control.ts";
import type { SandboxControlEvent } from "./control-codec.ts";
import type {
  InternalMount,
  InternalNetworkConfig,
  InternalSandboxOptions,
  RegisteredHttpRequestHeadersHook,
  RegisteredNetworkConnectionHook,
  SandboxHttpRequestSelector,
} from "./launch-options.ts";

export type {
  SandboxCommandEnvironmentFact,
  SandboxDistroEnvironmentFact,
  SandboxDistroVersion,
  SandboxDistroVersionEnvironmentFact,
  SandboxEnvironmentCommand,
  SandboxEnvironmentFact,
  SandboxEnvironmentFactSource,
  SandboxNetworkEgressEnvironmentFact,
  SandboxPackageManagerEnvironmentFact,
  SandboxRootfsEnvironmentFact,
  SandboxRootfsImageEnvironmentFact,
  SandboxShellEnvironmentFact,
} from "./environment-facts.ts";

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

export type RootfsImageConfig = {
  readonly kind: "rootfs-image";
  readonly name: string;
  readonly path: string;
  readonly format: "qcow2";
  readonly architecture: NodeJS.Architecture;
  readonly digest: `sha256:${string}`;
  readonly sizeBytes: bigint;
  readonly facts: readonly SandboxEnvironmentFact[];
};

export type RootfsImageInput = Omit<RootfsImageConfig, "kind">;

export type ComposedRootfsConfig = {
  readonly kind: "composed-rootfs";
  readonly base: RootfsImageConfig;
  readonly overlay: SandboxBlockStore;
};

export type CowRootfsConfig = {
  readonly kind: "cow-rootfs";
  readonly source: ComposedRootfsConfig;
  readonly maxDirtyBytes?: number;
};

export type EphemeralRootfsConfig = {
  readonly kind: "ephemeral-rootfs";
  readonly base: RootfsImageConfig;
  readonly maxDirtyBytes?: number;
};

export type PersistentRootfsConfig = {
  readonly kind: "persistent-rootfs";
  readonly base: RootfsImageConfig;
  readonly path: string;
};

export type Rootfs = RootfsImageConfig | CowRootfsConfig | EphemeralRootfsConfig | PersistentRootfsConfig;

export type Qcow2RootfsImage = {
  readonly kind: "flattened-rootfs-image";
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

export type SandboxHostDirectoryMaskStorageSource = {
  readonly kind: "host-directory";
  readonly source: string;
  readonly access: "rw";
};

export type SandboxReadOnlyHostDirectoryMask = {
  readonly paths: readonly string[];
};

export type SandboxReadWriteHostDirectoryMask = {
  readonly paths: readonly string[];
  readonly storage: SandboxHostDirectoryMaskStorageSource;
};

export type SandboxReadOnlyHostDirectorySource = {
  readonly kind: "host-directory";
  readonly source: string;
  readonly access: "ro";
  readonly mask?: SandboxReadOnlyHostDirectoryMask;
};

export type SandboxReadWriteHostDirectorySource = {
  readonly kind: "host-directory";
  readonly source: string;
  readonly access: "rw";
  readonly mask?: SandboxReadWriteHostDirectoryMask;
};

export type SandboxHostDirectorySource = SandboxReadOnlyHostDirectorySource | SandboxReadWriteHostDirectorySource;

export type SandboxMountSource = SandboxFileSystemSource | SandboxHostDirectorySource;

type HostDirectorySourceForValidation = {
  readonly kind: "host-directory";
  readonly source: string;
  readonly access: "ro" | "rw";
  readonly mask?: {
    readonly paths: readonly string[];
    readonly storage?: SandboxHostDirectoryMaskStorageSource;
  };
};

type LoweredHostDirectoryMask = {
  readonly paths: readonly string[];
  readonly storage?: SandboxHostDirectoryMaskStorageSource;
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
  readonly mounts?: Readonly<Record<string, SandboxMountSource>>;
  readonly cwd?: string;
  readonly hostname?: string;
}

export interface SandboxDefinition {
  /**
   * Returns facts recoverable from sandbox configuration without launching a VM.
   */
  environmentFacts(): readonly SandboxEnvironmentFact[];
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

export type SandboxFsEntryType = "file" | "directory" | "symlink" | "other";

export type SandboxFsStat = {
  readonly type: SandboxFsEntryType;
  readonly sizeBytes: number;
  readonly modifiedAtMs: number;
};

export type SandboxFsDirectoryEntry = {
  /**
   * UTF-8 filename for ordinary entries. If the guest filename is not valid
   * UTF-8, replacement characters are used and `nameBytes` remains exact.
   */
  readonly name: string;
  /**
   * Exact filename bytes as reported by the guest directory entry.
   */
  readonly nameBytes: Uint8Array;
  readonly stat: SandboxFsStat;
};

export interface SandboxReadFileOptions {
  readonly range?: {
    readonly offset: number;
    readonly length: number;
  };
}

export interface SandboxWriteFileOptions {
  readonly createParents?: boolean;
}

export interface SandboxMkdirOptions {
  readonly recursive?: boolean;
}

export interface SandboxRemoveOptions {
  readonly recursive?: boolean;
  readonly force?: boolean;
}

export interface SandboxGuestFileSystem {
  /**
   * Returns metadata for an absolute guest path without following symlinks.
   */
  stat(path: string): Promise<SandboxFsStat>;
  /**
   * Lists a directory and includes metadata for each entry in the same guest
   * round trip.
   */
  readDir(path: string): Promise<readonly SandboxFsDirectoryEntry[]>;
  /**
   * Reads a full file, or the byte range selected by `options.range`.
   */
  readFile(path: string, options?: SandboxReadFileOptions): Promise<Uint8Array>;
  /**
   * Creates or replaces a file. `createParents` creates missing parent
   * directories before writing.
   */
  writeFile(path: string, contents: string | Uint8Array, options?: SandboxWriteFileOptions): Promise<void>;
  /**
   * Creates a directory. `recursive` matches `mkdir -p` semantics.
   */
  mkdir(path: string, options?: SandboxMkdirOptions): Promise<void>;
  /**
   * Removes a file, symlink, or directory. `recursive` permits non-empty
   * directory trees. `force` suppresses missing-target errors only.
   */
  remove(path: string, options?: SandboxRemoveOptions): Promise<void>;
  /**
   * Renames a path in one guest operation. Parent directories are not created;
   * the target parent must already exist.
   */
  rename(from: string, to: string): Promise<void>;
}

export class SandboxFileSystemError extends Error {
  readonly code?: string;

  constructor(message: string, code?: string) {
    super(message);
    this.name = "SandboxFileSystemError";
    this.code = code;
  }
}

export interface SandboxInstance {
  readonly fs: SandboxGuestFileSystem;
  /**
   * Returns config-derived facts plus facts observed from the running guest.
   */
  environmentFacts(): Promise<readonly SandboxEnvironmentFact[]>;
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
  hostPid(): number;
}

export const rootfs = {
  image(input: RootfsImageInput): RootfsImageConfig {
    return {
      kind: "rootfs-image",
      name: input.name,
      path: input.path,
      format: input.format,
      architecture: input.architecture,
      digest: input.digest,
      sizeBytes: input.sizeBytes,
      facts: [...input.facts],
    };
  },
  compose(options: {
    readonly base: RootfsImageConfig;
    readonly overlay: SandboxBlockStore;
  }): ComposedRootfsConfig {
    return composeRootfs(options);
  },
  cow(options: {
    readonly source: ComposedRootfsConfig;
    readonly maxDirtyBytes?: number;
  } | {
    readonly base: RootfsImageConfig;
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
  ephemeral(options: {
    readonly base: RootfsImageConfig;
    readonly maxDirtyBytes?: number;
  }): Rootfs {
    return {
      kind: "ephemeral-rootfs",
      base: options.base,
      ...(options.maxDirtyBytes === undefined ? {} : { maxDirtyBytes: options.maxDirtyBytes }),
    };
  },
  persistent(options: {
    readonly base: RootfsImageConfig;
    readonly path: string;
  }): Rootfs {
    return {
      kind: "persistent-rootfs",
      base: options.base,
      path: options.path,
    };
  },
  async flatten(options: {
    readonly format: "qcow2";
    readonly source: RootfsImageConfig | ComposedRootfsConfig;
    readonly dest: SandboxBlockStore;
    readonly clusterSize?: number;
  }): Promise<Qcow2RootfsImage> {
    if (options.format !== "qcow2") {
      throw new Error("invalid rootfs flatten options: format must be qcow2");
    }
    validateImageDestination(options.dest);
    validateQcow2Options(options);
    const source = options.source.kind === "rootfs-image"
      ? composeRootfs({
        base: options.source,
        overlay: createEphemeralCowBlockStore(),
      })
      : options.source;
    if (source.base.kind !== "rootfs-image") {
      throw new Error("invalid rootfs source: base must be created with rootfs.image(...)");
    }
    validateRootfsImage(source.base, "rootfs source image");
    validateBlockStore(source.overlay);
    const destContext = {
      base: `rootfs-image:qcow2:${randomUUID()}`,
    };
    if ((await options.dest.list(destContext)).length !== 0) {
      throw new Error("invalid rootfs image destination: destination block store context must be empty");
    }
    const result = await HostProcessSandboxVm.flattenQcow2({
      basePath: source.base.path,
      overlay: source.overlay,
      overlayContext: {
        base: rootfsImageIdentity(source.base),
      },
      dest: options.dest,
      destContext,
      clusterSize: options.clusterSize ?? 65536,
    });
    const image: Qcow2RootfsImage = {
      kind: "flattened-rootfs-image",
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
    image: RootfsImageConfig | Qcow2RootfsImage,
    options: {
      readonly chunkSize?: number;
      readonly signal?: AbortSignal;
    } = {},
  ): AsyncIterable<Uint8Array> {
    const chunkSize = validateByteStreamChunkSize(options.chunkSize);
    if (image.kind === "rootfs-image") {
      validateRootfsImage(image, "rootfs image");
      const file = await open(image.path, "r");
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
  readonly base: RootfsImageConfig;
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

function bindHostDirectory(options: {
  readonly source: string;
  readonly access: "ro";
  readonly mask?: SandboxReadOnlyHostDirectoryMask;
}): SandboxReadOnlyHostDirectorySource;
function bindHostDirectory(options: {
  readonly source: string;
  readonly access: "rw";
  readonly mask?: SandboxReadWriteHostDirectoryMask;
}): SandboxReadWriteHostDirectorySource;
function bindHostDirectory(options: {
  readonly source: string;
  readonly access: "ro" | "rw";
}): SandboxHostDirectorySource;
function bindHostDirectory(options: {
  readonly source: string;
  readonly access: "ro" | "rw";
  readonly mask?: SandboxReadOnlyHostDirectoryMask | SandboxReadWriteHostDirectoryMask;
}): SandboxHostDirectorySource {
  if (options.access === "ro") {
    return {
      kind: "host-directory",
      source: options.source,
      access: "ro",
      ...(options.mask === undefined ? {} : { mask: options.mask as SandboxReadOnlyHostDirectoryMask }),
    };
  }
  return {
    kind: "host-directory",
    source: options.source,
    access: options.access as "rw",
    ...(options.mask === undefined ? {} : { mask: options.mask as SandboxReadWriteHostDirectoryMask }),
  };
}

export const fs = {
  memory: createMemoryFileSystem,
  virtual: virtualFs,
  bind: bindHostDirectory,
};

export const network = {
  policy(onConnectionRequest: NetworkConnectionRequestHandler): NetworkPolicy {
    return {
      kind: "network-policy",
      [networkPolicyHandler]: onConnectionRequest,
    };
  },
};

function environmentFactsForDefinition(
  options: SandboxDefinitionOptions,
): readonly SandboxEnvironmentFact[] {
  const base = rootfsBase(options.rootfs);
  const facts: SandboxEnvironmentFact[] = [
    ...base.facts,
  ];

  facts.push(configRootfsWriteFact(options.rootfs));
  facts.push(configNetworkEgressFact(options.network));

  return facts;
}

function rootfsBase(rootfs: Rootfs): RootfsImageConfig {
  switch (rootfs.kind) {
    case "rootfs-image":
      return rootfs;
    case "cow-rootfs":
      return rootfs.source.base;
    case "ephemeral-rootfs":
      return rootfs.base;
    case "persistent-rootfs":
      return rootfs.base;
  }
}

function configRootfsWriteFact(rootfs: Rootfs): SandboxRootfsEnvironmentFact {
  switch (rootfs.kind) {
    case "rootfs-image":
      return {
        source: "config",
        topic: "rootfs",
        relation: "write-mode",
        value: "read-only",
      };
    case "cow-rootfs":
      return {
        source: "config",
        topic: "rootfs",
        relation: "write-mode",
        value: "writable-persistent-cow",
      };
    case "ephemeral-rootfs":
      return {
        source: "config",
        topic: "rootfs",
        relation: "write-mode",
        value: "writable-ephemeral",
      };
    case "persistent-rootfs":
      return {
        source: "config",
        topic: "rootfs",
        relation: "write-mode",
        value: "writable-persistent-file",
      };
  }
}

function configNetworkEgressFact(
  network: NetworkPolicy | undefined,
): SandboxNetworkEgressEnvironmentFact {
  if (network === undefined) {
    return {
      source: "config",
      topic: "network-egress",
      relation: "is",
      value: "not-configured",
    };
  }

  return {
    source: "config",
    topic: "network-egress",
    relation: "requires",
    value: "policy-grant",
  };
}

function guestEnvironmentFactScript(
  configFacts: readonly SandboxEnvironmentFact[],
): string {
  const commands = Array.from(new Set(
    configFacts
      .filter((fact): fact is SandboxCommandEnvironmentFact => {
        return fact.source === "config" && fact.topic === "command" && fact.relation === "exists";
      })
      .map((fact) => fact.value),
  ));
  const commandArgs = commands.map(shellSingleQuote).join(" ");
  const commandProbe = commandArgs.length === 0
    ? ":"
    : `for sandbox_command in ${commandArgs}; do if command -v "$sandbox_command" >/dev/null 2>&1; then printf 'command=%s\\n' "$sandbox_command"; fi; done`;

  return [
    "set -eu",
    "os_release_value() {",
    "  awk -F= -v key=\"$1\" '",
    "    $1 == key {",
    "      value = substr($0, index($0, \"=\") + 1)",
    "      if (value ~ /^\"/ && value ~ /\"$/) {",
    "        value = substr(value, 2, length(value) - 2)",
    "      }",
    "      print value",
    "      found = 1",
    "      exit",
    "    }",
    "    END { if (found != 1) exit 1 }",
    "  ' /etc/os-release",
    "}",
    "distro_id=$(os_release_value ID)",
    "distro_version=$(os_release_value VERSION_ID)",
    "printf 'distro=%s\\n' \"$distro_id\"",
    "printf 'distro-version=%s\\n' \"$distro_version\"",
    "if command -v apk >/dev/null 2>&1; then printf 'package-manager=apk\\n'; elif command -v apt-get >/dev/null 2>&1; then printf 'package-manager=apt\\n'; fi",
    "if test -x /bin/sh; then printf 'shell=/bin/sh\\n'; fi",
    commandProbe,
    "root_options=$(awk '$2 == \"/\" { print $4; exit }' /proc/mounts)",
    [
      "case \",$root_options,\" in",
      "*,rw,*) printf 'rootfs=read-write\\n' ;;",
      "*,ro,*) printf 'rootfs=read-only\\n' ;;",
      "*) echo \"unable to determine rootfs mount mode: $root_options\" >&2; exit 1 ;;",
      "esac",
    ].join(" "),
  ].join("\n");
}

function shellSingleQuote(value: string): string {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function parseGuestEnvironmentFacts(text: string): readonly SandboxEnvironmentFact[] {
  const facts: SandboxEnvironmentFact[] = [];

  for (const line of text.split("\n")) {
    if (line.length === 0) {
      continue;
    }

    const separator = line.indexOf("=");
    if (separator === -1) {
      throw new Error(`invalid sandbox environment fact line: ${line}`);
    }

    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);

    switch (key) {
      case "distro":
        facts.push(guestDistroFact(value));
        break;
      case "distro-version":
        facts.push(guestDistroVersionFact(value));
        break;
      case "package-manager":
        facts.push(guestPackageManagerFact(value));
        break;
      case "shell":
        facts.push(guestShellFact(value));
        break;
      case "rootfs":
        facts.push(guestRootfsMountFact(value));
        break;
      case "command":
        facts.push(guestCommandFact(value));
        break;
      default:
        throw new Error(`unsupported sandbox environment fact key: ${key}`);
    }
  }

  return facts;
}

function guestDistroFact(value: string): SandboxDistroEnvironmentFact {
  return {
    source: "guest",
    topic: "distro",
    relation: "is",
    value,
  };
}

function guestDistroVersionFact(value: string): SandboxDistroVersionEnvironmentFact {
  return {
    source: "guest",
    topic: "distro-version",
    relation: "is",
    value,
  };
}

function guestPackageManagerFact(value: string): SandboxPackageManagerEnvironmentFact {
  return {
    source: "guest",
    topic: "package-manager",
    relation: "is",
    value,
  };
}

function guestShellFact(value: string): SandboxShellEnvironmentFact {
  return {
    source: "guest",
    topic: "shell",
    relation: "is",
    value,
  };
}

function guestRootfsMountFact(value: string): SandboxRootfsEnvironmentFact {
  if (value !== "read-only" && value !== "read-write") {
    throw new Error(`unsupported guest rootfs mount environment fact: ${value}`);
  }

  return {
    source: "guest",
    topic: "rootfs",
    relation: "mount-mode",
    value,
  };
}

function guestCommandFact(value: string): SandboxCommandEnvironmentFact {
  return {
    source: "guest",
    topic: "command",
    relation: "exists",
    value,
  };
}

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

  environmentFacts(): readonly SandboxEnvironmentFact[] {
    return environmentFactsForDefinition(this.#options);
  }

  async boot(options: SandboxBootOptions = {}): Promise<SandboxInstance> {
    validateSandboxBootOptions(options);
    const networkPolicy = this.#options.network === undefined
      ? undefined
      : createNetworkPolicyHookRegistration(this.#options.network);
    const configEnvironmentFacts = environmentFactsForDefinition(this.#options);
    const launchOptions = await toInternalSandboxOptions(
      this.#options,
      options,
      networkPolicy?.network,
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
      return new HostBackedSandboxVm(hostVm, launchOptions, configEnvironmentFacts);
    } catch (error) {
      throw error;
    }
  }
}

class HostBackedSandboxVm implements SandboxVm {
  readonly control: SandboxControl;
  readonly diagnostics?: SandboxDiagnostics;
  readonly fs: SandboxGuestFileSystem;
  readonly #exec: ControlBackedSandboxExec;
  readonly #rootExec: ControlBackedSandboxExec;
  readonly #options: InternalSandboxOptions;
  readonly #configEnvironmentFacts: readonly SandboxEnvironmentFact[];

  readonly #hostVm: {
    readonly hasControlSocket: boolean;
    readonly packets: AsyncIterable<Uint8Array>;
    writeControlPacket(packet: Uint8Array): void;
    close(): Promise<void> | void;
    hostPid?(): number;
    terminateHostForTest?(): Promise<void>;
  };
  #closed = false;

  constructor(
    hostVm: {
      readonly hasControlSocket: boolean;
      readonly packets: AsyncIterable<Uint8Array>;
      writeControlPacket(packet: Uint8Array): void;
      close(): Promise<void> | void;
      hostPid?(): number;
      terminateHostForTest?(): Promise<void>;
    },
    options: InternalSandboxOptions,
    configEnvironmentFacts: readonly SandboxEnvironmentFact[],
  ) {
    this.#hostVm = hostVm;
    this.#options = options;
    this.#configEnvironmentFacts = configEnvironmentFacts;
    this.control = new HostControlTransport({
      connected: hostVm.hasControlSocket,
      channel: hostVm,
    });
    this.fs = new ControlBackedSandboxGuestFileSystem(this.control);
    this.#exec = new ControlBackedSandboxExec(this.control, options.cwd);
    this.#rootExec = new ControlBackedSandboxExec(this.control, "/");
    if (hostVm.terminateHostForTest !== undefined) {
      this.diagnostics = {
        terminateHostForTest: () => hostVm.terminateHostForTest?.() ?? Promise.resolve(),
        hostPid: () => {
          if (hostVm.hostPid === undefined) {
            throw new Error("sandbox host PID is not available");
          }
          return hostVm.hostPid();
        },
      };
    }
  }

  async environmentFacts(): Promise<readonly SandboxEnvironmentFact[]> {
    const result = await this.#rootExec.exec("/bin/sh", [
      "-lc",
      guestEnvironmentFactScript(this.#configEnvironmentFacts),
    ]);

    if (result.exitCode !== 0) {
      throw new Error(
        `sandbox environment fact introspection failed with exit code ${result.exitCode}: ${result.stderr}`,
      );
    }

    return [
      ...this.#configEnvironmentFacts,
      ...parseGuestEnvironmentFacts(result.stdout),
    ];
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
    throwIfAborted(options.signal);
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
    throwIfAborted(ptyOptions.signal);
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

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    const reason = signal.reason;
    if (reason instanceof Error) {
      throw reason;
    }
    const error = new Error("sandbox spawn aborted");
    error.name = "AbortError";
    throw error;
  }
}

class ControlBackedSandboxGuestFileSystem implements SandboxGuestFileSystem {
  readonly #control: SandboxControl;

  constructor(control: SandboxControl) {
    this.#control = control;
  }

  async stat(path: string): Promise<SandboxFsStat> {
    validateSandboxFsPath(path, "sandbox fs stat path");
    const result = await this.#request({
      type: "guest.fs.stat",
      path,
    });
    if (result.stat === undefined) {
      throw new Error("sandbox fs stat response missing stat");
    }
    return result.stat;
  }

  async readDir(path: string): Promise<readonly SandboxFsDirectoryEntry[]> {
    validateSandboxFsPath(path, "sandbox fs readDir path");
    const result = await this.#request({
      type: "guest.fs.readDir",
      path,
    });
    if (result.entries === undefined) {
      throw new Error("sandbox fs readDir response missing entries");
    }
    return result.entries;
  }

  async readFile(path: string, options: SandboxReadFileOptions = {}): Promise<Uint8Array> {
    validateSandboxFsPath(path, "sandbox fs readFile path");
    validateSandboxFsOptions(options, "sandbox fs readFile options");
    const range = optionalSandboxFsReadRange(options);
    const result = await this.#request({
      type: "guest.fs.readFile",
      path,
      ...(range === undefined ? {} : { range }),
    });
    if (result.contents === undefined) {
      throw new Error("sandbox fs readFile response missing contents");
    }
    return result.contents;
  }

  async writeFile(
    path: string,
    contents: string | Uint8Array,
    options: SandboxWriteFileOptions = {},
  ): Promise<void> {
    validateSandboxFsMutationPath(path, "sandbox fs writeFile path");
    validateSandboxFsOptions(options, "sandbox fs writeFile options");
    if (typeof contents !== "string" && !(contents instanceof Uint8Array)) {
      throw new Error("invalid sandbox fs writeFile contents: contents must be a string or Uint8Array");
    }
    await this.#request({
      type: "guest.fs.writeFile",
      path,
      contents: typeof contents === "string" ? new TextEncoder().encode(contents) : contents,
      createParents: optionalSandboxFsBoolean(options, "createParents", "sandbox fs writeFile createParents"),
    });
  }

  async mkdir(path: string, options: SandboxMkdirOptions = {}): Promise<void> {
    validateSandboxFsMutationPath(path, "sandbox fs mkdir path");
    validateSandboxFsOptions(options, "sandbox fs mkdir options");
    await this.#request({
      type: "guest.fs.mkdir",
      path,
      recursive: optionalSandboxFsBoolean(options, "recursive", "sandbox fs mkdir recursive"),
    });
  }

  async remove(path: string, options: SandboxRemoveOptions = {}): Promise<void> {
    validateSandboxFsMutationPath(path, "sandbox fs remove path");
    validateSandboxFsOptions(options, "sandbox fs remove options");
    await this.#request({
      type: "guest.fs.remove",
      path,
      recursive: optionalSandboxFsBoolean(options, "recursive", "sandbox fs remove recursive"),
      force: optionalSandboxFsBoolean(options, "force", "sandbox fs remove force"),
    });
  }

  async rename(from: string, to: string): Promise<void> {
    validateSandboxFsMutationPath(from, "sandbox fs rename from");
    validateSandboxFsMutationPath(to, "sandbox fs rename to");
    await this.#request({
      type: "guest.fs.rename",
      from,
      to,
    });
  }

  async #request(
    command: Parameters<SandboxControl["requestFileSystem"]>[0],
  ): Promise<Extract<Awaited<ReturnType<SandboxControl["requestFileSystem"]>>["result"], { ok: true }>> {
    const response = await this.#control.requestFileSystem(command);
    if (!response.result.ok) {
      throw new SandboxFileSystemError(response.result.error.message, response.result.error.code);
    }
    return response.result;
  }
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
    mounts: options.mounts?.map((mount) => lowerHostSpawnMount(mount)),
    network,
  };
}

async function toInternalSandboxOptions(
  config: SandboxDefinitionOptions,
  boot: SandboxBootOptions,
  network?: InternalNetworkConfig,
): Promise<InternalSandboxOptions> {
  const rootfs = await lowerRootfs(config.rootfs);
  return {
    resources: config.resources,
    rootfs,
    cwd: boot.cwd,
    hostname: boot.hostname ?? "sandbox",
    mounts: Object.entries(boot.mounts ?? {}).map(([path, source]) => {
      return lowerInternalMount(path, source);
    }),
    network,
  };
}

function lowerInternalMount(path: string, source: SandboxMountSource): InternalMount {
  switch (source.kind) {
    case "virtual-fs":
      return {
        kind: "virtual-fs",
        path,
        fileSystem: source.fileSystem,
      };
    case "host-directory":
      return {
        kind: "host-directory",
        path,
        source: source.source,
        access: source.access,
        mask: lowerHostDirectoryMask(source.mask),
      };
  }
}

function lowerHostDirectoryMask(mask: SandboxHostDirectorySource["mask"]): LoweredHostDirectoryMask | undefined {
  if (mask === undefined) {
    return undefined;
  }
  const storage = "storage" in mask ? mask.storage : undefined;
  return {
    paths: [...mask.paths],
    ...(storage !== undefined
      ? {
        storage: {
          kind: storage.kind,
          source: storage.source,
          access: storage.access,
        },
      }
      : {}),
  };
}

function lowerHostSpawnMount(mount: InternalMount): HostSpawnMount {
  switch (mount.kind) {
    case "virtual-fs":
      return {
        kind: "virtual-fs",
        path: mount.path,
        writable: isSandboxWritableFileSystem(mount.fileSystem),
      };
    case "host-directory":
      return {
        kind: "host-directory",
        path: mount.path,
        source: mount.source,
        access: mount.access,
        mask: mount.mask,
      };
  }
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

async function lowerRootfs(rootfs: Rootfs): Promise<InternalSandboxOptions["rootfs"]> {
  switch (rootfs.kind) {
    case "rootfs-image": {
      return {
        path: rootfs.path,
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
    case "ephemeral-rootfs":
      return lowerEphemeralRootfs(rootfs.base, rootfs.maxDirtyBytes);
    case "persistent-rootfs":
      return lowerPersistentRootfs(rootfs.base, rootfs.path);
  }
}

function lowerCowRootfs(
  base: RootfsImageConfig,
  writable: SandboxBlockStore,
  maxDirtyBytes: number,
): InternalSandboxOptions["rootfs"] {
  return {
    path: base.path,
    readonly: false,
    format: "qcow2",
    storage: {
      kind: "cow-block-store",
      blockSize: writable.blockSize,
      maxDirtyBytes,
      blockStore: writable,
      context: {
        base: rootfsImageIdentity(base),
      },
    },
  };
}

function lowerEphemeralRootfs(
  base: RootfsImageConfig,
  maxDirtyBytes: number | undefined,
): InternalSandboxOptions["rootfs"] {
  const blockSize = 65536;
  return {
    path: base.path,
    readonly: false,
    format: "qcow2",
    storage: {
      kind: "ephemeral-cow",
      blockSize,
      maxDirtyBytes: maxDirtyBytes ?? DEFAULT_COW_MAX_DIRTY_BYTES,
    },
  };
}

async function lowerPersistentRootfs(
  base: RootfsImageConfig,
  path: string,
): Promise<InternalSandboxOptions["rootfs"]> {
  return {
    path: base.path,
    readonly: false,
    format: "qcow2",
    storage: {
      kind: "persistent-qcow2-overlay",
      path,
      baseIdentity: rootfsImageIdentity(base),
      baseDigest: rootfsImageDigestHex(base),
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
    case "rootfs-image":
      validateRootfsImage(rootfs, "rootfs image");
      return;
    case "cow-rootfs":
      if (rootfs.source?.kind !== "composed-rootfs") {
        throw new Error("invalid sandbox definition: rootfs.cow source must be created with rootfs.compose(...)");
      }
      if (rootfs.source.base.kind !== "rootfs-image") {
        throw new Error("invalid sandbox definition: rootfs.cow base must be created with rootfs.image(...)");
      }
      validateRootfsImage(rootfs.source.base, "rootfs.cow base");
      validateBlockStore(rootfs.source.overlay);
      validateCowMaxDirtyBytes(rootfs);
      return;
    case "ephemeral-rootfs":
      if (rootfs.base?.kind !== "rootfs-image") {
        throw new Error("invalid sandbox definition: rootfs.ephemeral base must be created with rootfs.image(...)");
      }
      validateRootfsImage(rootfs.base, "rootfs.ephemeral base");
      validateEphemeralRootfs(rootfs);
      return;
    case "persistent-rootfs":
      if (rootfs.base?.kind !== "rootfs-image") {
        throw new Error("invalid sandbox definition: rootfs.persistent base must be created with rootfs.image(...)");
      }
      validateRootfsImage(rootfs.base, "rootfs.persistent base");
      validatePersistentRootfs(rootfs);
      return;
    default:
      throw new Error(
        "invalid sandbox definition: rootfs must be created with rootfs.image(...), rootfs.ephemeral(...), rootfs.cow(...), or rootfs.persistent(...)",
      );
  }
}

function validateRootfsImage(image: RootfsImageConfig, label: string): void {
  if (image === null || typeof image !== "object" || image.kind !== "rootfs-image") {
    throw new Error(`invalid sandbox definition: ${label} must be created with rootfs.image(...)`);
  }
  if (typeof image.name !== "string" || image.name.length === 0) {
    throw new Error(`invalid sandbox definition: ${label} name must not be empty`);
  }
  if (image.name.includes("\0")) {
    throw new Error(`invalid sandbox definition: ${label} name must not contain NUL bytes`);
  }
  if (isConvenienceImageAlias(image.name)) {
    throw new Error(`invalid sandbox definition: ${label} name must be a concrete image version, not a convenience alias`);
  }
  if (typeof image.path !== "string" || image.path.length === 0) {
    throw new Error(`invalid sandbox definition: ${label} path must not be empty`);
  }
  if (!isAbsolute(image.path)) {
    throw new Error(`invalid sandbox definition: ${label} path must be absolute`);
  }
  if (image.path.includes("\0")) {
    throw new Error(`invalid sandbox definition: ${label} path must not contain NUL bytes`);
  }
  if (image.format !== "qcow2") {
    throw new Error(`invalid sandbox definition: ${label} format must be qcow2`);
  }
  if (image.architecture !== process.arch) {
    throw new Error(`invalid sandbox definition: ${label} architecture must match the host architecture ${process.arch}`);
  }
  validateRootfsImageDigest(image.digest, label);
  if (typeof image.sizeBytes !== "bigint" || image.sizeBytes <= 0n) {
    throw new Error(`invalid sandbox definition: ${label} sizeBytes must be a positive bigint`);
  }
  if (!Array.isArray(image.facts)) {
    throw new Error(`invalid sandbox definition: ${label} facts must be an array`);
  }
  const hasImageFact = image.facts.some((fact) => {
    return fact.source === "config"
      && fact.topic === "rootfs-image"
      && fact.relation === "is"
      && fact.value === image.name;
  });
  if (!hasImageFact) {
    throw new Error(`invalid sandbox definition: ${label} facts must include the rootfs-image identity fact`);
  }
  for (const [index, fact] of image.facts.entries()) {
    validateRootfsImageFact(fact, `${label} facts[${index}]`);
  }
}

function validateRootfsImageDigest(
  digest: string,
  label: string,
): asserts digest is `sha256:${string}` {
  if (typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
    throw new Error(`invalid sandbox definition: ${label} digest must be sha256:<64 lowercase hex characters>`);
  }
}

function validateRootfsImageFact(fact: SandboxEnvironmentFact, label: string): void {
  if (fact === null || typeof fact !== "object") {
    throw new Error(`invalid sandbox definition: ${label} must be an environment fact object`);
  }
  if (fact.source !== "config") {
    throw new Error(`invalid sandbox definition: ${label} source must be config`);
  }
  switch (fact.topic) {
    case "rootfs-image":
      if (fact.relation !== "is" || typeof fact.value !== "string" || fact.value.length === 0) {
        throw new Error(`invalid sandbox definition: ${label} must be a rootfs-image identity fact`);
      }
      return;
    case "distro":
    case "distro-version":
    case "package-manager":
    case "shell":
      if (fact.relation !== "is") {
        throw new Error(`invalid sandbox definition: ${label} relation must be is`);
      }
      if (typeof fact.value !== "string" || fact.value.length === 0) {
        throw new Error(`invalid sandbox definition: ${label} value must not be empty`);
      }
      return;
    case "command":
      if (fact.relation !== "exists") {
        throw new Error(`invalid sandbox definition: ${label} relation must be exists`);
      }
      if (typeof fact.value !== "string" || fact.value.length === 0) {
        throw new Error(`invalid sandbox definition: ${label} value must not be empty`);
      }
      return;
    default:
      throw new Error(`invalid sandbox definition: ${label} topic is not valid image metadata`);
  }
}

function validatePersistentRootfs(rootfs: PersistentRootfsConfig): void {
  if (typeof rootfs.path !== "string" || rootfs.path.length === 0) {
    throw new Error("invalid sandbox definition: persistent rootfs path must not be empty");
  }
  if (!isAbsolute(rootfs.path)) {
    throw new Error("invalid sandbox definition: persistent rootfs path must be absolute");
  }
  if (rootfs.path.includes("\0")) {
    throw new Error("invalid sandbox definition: persistent rootfs path must not contain NUL bytes");
  }
}

function rootfsImageIdentity(image: RootfsImageConfig): string {
  return [
    "rootfs-image",
    image.name,
    image.format,
    image.architecture,
    image.digest,
  ].join(":");
}

function rootfsImageDigestHex(image: RootfsImageConfig): string {
  validateRootfsImageDigest(image.digest, "rootfs image");
  return image.digest.slice("sha256:".length);
}

function isConvenienceImageAlias(name: string): boolean {
  const tag = name.includes(":") ? name.slice(name.lastIndexOf(":") + 1) : name;
  return tag === "latest" || tag === "stable" || tag === "lts" || tag === "current";
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

function validateEphemeralRootfs(rootfs: EphemeralRootfsConfig): void {
  if (rootfs.maxDirtyBytes === undefined) {
    return;
  }
  if (!Number.isSafeInteger(rootfs.maxDirtyBytes) || rootfs.maxDirtyBytes <= 0) {
    throw new Error("invalid sandbox definition: ephemeral rootfs maxDirtyBytes must be a positive safe integer");
  }
  if (rootfs.maxDirtyBytes < 65536) {
    throw new Error("invalid sandbox definition: ephemeral rootfs maxDirtyBytes must be at least the COW block size");
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
      source.kind === "virtual-fs"
      &&
      isSandboxWritableFileSystem(source.fileSystem)
      && !isSandboxPosixFileSystem(source.fileSystem)
    ) {
      throw new Error(`invalid sandbox boot options: writable mount must implement the POSIX filesystem interface: ${path}`);
    }
    if (source.kind === "host-directory") {
      validateHostDirectorySource(source);
    }
    mountPaths.add(path);
  }
  if (options.cwd !== undefined && !options.cwd.startsWith("/")) {
    throw new Error("invalid sandbox boot options: cwd must be absolute");
  }
}

function validateHostDirectorySource(source: HostDirectorySourceForValidation): void {
  if (!source.source.startsWith("/")) {
    throw new Error("invalid sandbox boot options: host directory source must be absolute");
  }
  if (source.source.includes("\0")) {
    throw new Error("invalid sandbox boot options: host directory source must not contain NUL bytes");
  }
  if (source.access !== "ro" && source.access !== "rw") {
    throw new Error("invalid sandbox boot options: host directory access must be 'ro' or 'rw'");
  }
  validateHostDirectoryMask(source);
}

function validateHostDirectoryMask(source: HostDirectorySourceForValidation): void {
  const mask = source.mask;
  if (mask === undefined) {
    return;
  }
  if (!Array.isArray(mask.paths) || mask.paths.length === 0) {
    throw new Error("invalid sandbox boot options: host directory mask paths must not be empty");
  }
  const paths = new Set<string>();
  for (const path of mask.paths) {
    validateHostDirectoryMaskPath(path);
    if (paths.has(path)) {
      throw new Error(`invalid sandbox boot options: duplicate host directory mask path: ${path}`);
    }
    for (const existing of paths) {
      if (isMaskPathNested(existing, path)) {
        throw new Error(`invalid sandbox boot options: nested host directory mask path: ${path}`);
      }
    }
    paths.add(path);
  }
  if (source.access === "ro") {
    if ("storage" in mask && mask.storage !== undefined) {
      throw new Error("invalid sandbox boot options: read-only host directory masks must not declare mask.storage");
    }
    return;
  }
  if (!("storage" in mask) || mask.storage === undefined) {
    throw new Error("invalid sandbox boot options: writable host directory masks require mask.storage");
  }
  validateHostDirectoryMaskStorage(mask.storage);
  const sourcePath = realpathOrResolve(source.source);
  const storagePath = realpathOrResolve(mask.storage.source);
  if (isPathInsideOrEqual(sourcePath, storagePath)) {
    throw new Error("invalid sandbox boot options: host directory mask storage source must not be inside the bind source");
  }
  for (const path of mask.paths) {
    const upperPath = realpathOrResolve(storagePath, path.slice(1));
    if (isPathInsideOrEqual(sourcePath, upperPath)) {
      throw new Error("invalid sandbox boot options: host directory mask storage entries must not resolve inside the bind source");
    }
  }
  rejectMaskStorageHardLinks(sourcePath, storagePath, mask.paths);
}

function realpathOrResolve(path: string, ...paths: string[]): string {
  const resolved = resolve(path, ...paths);
  try {
    return realpathSync.native(resolved);
  } catch {
    const parent = dirname(resolved);
    if (parent === resolved) {
      return resolved;
    }
    const canonicalParent = realpathOrResolve(parent);
    return resolve(canonicalParent, relative(parent, resolved));
  }
}

function isPathInsideOrEqual(parent: string, child: string): boolean {
  const path = relative(parent, child);
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

function isMaskPathNested(left: string, right: string): boolean {
  const leftComponents = left.split("/").slice(1);
  const rightComponents = right.split("/").slice(1);
  const shortestLength = Math.min(leftComponents.length, rightComponents.length);
  return (
    leftComponents.slice(0, shortestLength).every((component, index) => component === rightComponents[index]) &&
    leftComponents.length !== rightComponents.length
  );
}

function rejectMaskStorageHardLinks(sourcePath: string, storagePath: string, maskPaths: readonly string[]): void {
  const upperInodes = new Set<string>();
  for (const maskPath of maskPaths) {
    collectLinkedRegularFileInodes(realpathOrResolve(storagePath, maskPath.slice(1)), upperInodes);
  }
  if (upperInodes.size === 0) {
    return;
  }
  if (treeContainsRegularFileInode(sourcePath, upperInodes)) {
    throw new Error("invalid sandbox boot options: host directory mask storage entries must not hard-link to the bind source");
  }
}

function collectLinkedRegularFileInodes(path: string, inodes: Set<string>): void {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return;
  }
  if (stat.isFile() && stat.nlink > 1) {
    inodes.add(`${stat.dev}:${stat.ino}`);
    return;
  }
  if (!stat.isDirectory()) {
    return;
  }
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    collectLinkedRegularFileInodes(resolve(path, entry.name), inodes);
  }
}

function treeContainsRegularFileInode(path: string, inodes: ReadonlySet<string>): boolean {
  let stat;
  try {
    stat = lstatSync(path);
  } catch {
    return false;
  }
  if (stat.isFile()) {
    return inodes.has(`${stat.dev}:${stat.ino}`);
  }
  if (!stat.isDirectory()) {
    return false;
  }
  let entries;
  try {
    entries = readdirSync(path, { withFileTypes: true });
  } catch {
    return false;
  }
  return entries.some((entry) => treeContainsRegularFileInode(resolve(path, entry.name), inodes));
}

function validateHostDirectoryMaskPath(path: string): void {
  if (typeof path !== "string") {
    throw new Error("invalid sandbox boot options: host directory mask path must be a string");
  }
  if (!path.startsWith("/")) {
    throw new Error("invalid sandbox boot options: host directory mask path must be absolute");
  }
  if (path === "/") {
    throw new Error("invalid sandbox boot options: host directory mask path must not be root");
  }
  if (path.includes("\0")) {
    throw new Error("invalid sandbox boot options: host directory mask path must not contain NUL bytes");
  }
  if (path.split("/").slice(1).some((component) => component === "")) {
    throw new Error("invalid sandbox boot options: host directory mask path must not contain empty components");
  }
  if (path.split("/").some((component) => component === "." || component === "..")) {
    throw new Error("invalid sandbox boot options: host directory mask path must not contain '.' or '..' components");
  }
}

function validateHostDirectoryMaskStorage(storage: SandboxHostDirectoryMaskStorageSource): void {
  if (storage.kind !== "host-directory") {
    throw new Error("invalid sandbox boot options: host directory mask storage must be created with fs.bind(...)");
  }
  if (!storage.source.startsWith("/")) {
    throw new Error("invalid sandbox boot options: host directory mask storage source must be absolute");
  }
  if (storage.source.includes("\0")) {
    throw new Error("invalid sandbox boot options: host directory mask storage source must not contain NUL bytes");
  }
  if (storage.access !== "rw") {
    throw new Error("invalid sandbox boot options: host directory mask storage access must be 'rw'");
  }
  if ("mask" in storage && storage.mask !== undefined) {
    throw new Error("invalid sandbox boot options: host directory mask storage must not declare mask");
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
    if (mount.kind === "host-directory") {
      validateHostDirectorySource(mount);
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

function validateSandboxFsPath(path: string, field: string): void {
  if (typeof path !== "string") {
    throw new Error(`invalid ${field}: path must be a string`);
  }
  if (!path.startsWith("/")) {
    throw new Error(`invalid ${field}: path must be absolute`);
  }
  if (path.includes("\0")) {
    throw new Error(`invalid ${field}: path must not contain NUL bytes`);
  }
  if (path.length > 1 && path.endsWith("/")) {
    throw new Error(`invalid ${field}: path must not end with a trailing slash`);
  }
  if (path.split("/").some((component) => component === "." || component === "..")) {
    throw new Error(`invalid ${field}: path must not contain '.' or '..' components`);
  }
}

function validateSandboxFsMutationPath(path: string, field: string): void {
  validateSandboxFsPath(path, field);
  if (path === "/") {
    throw new Error(`invalid ${field}: path must not be root`);
  }
}

function validateSandboxFsOptions(options: unknown, field: string): asserts options is Record<string, unknown> {
  if (typeof options !== "object" || options === null || Array.isArray(options)) {
    throw new Error(`invalid ${field}: options must be an object`);
  }
}

function optionalSandboxFsReadRange(options: Record<string, unknown>): { readonly offset: number; readonly length: number } | undefined {
  const range = options.range;
  if (range === undefined) {
    return undefined;
  }
  if (typeof range !== "object" || range === null || Array.isArray(range)) {
    throw new Error("invalid sandbox fs readFile range: range must be an object");
  }
  const document = range as Record<string, unknown>;
  const offset = document.offset;
  const length = document.length;
  validateNonNegativeSafeInteger(offset, "sandbox fs readFile range offset");
  validateNonNegativeSafeInteger(length, "sandbox fs readFile range length");
  return { offset, length };
}

function optionalSandboxFsBoolean(options: Record<string, unknown>, key: string, field: string): boolean {
  const value = options[key];
  if (value === undefined) {
    return false;
  }
  if (typeof value !== "boolean") {
    throw new Error(`invalid ${field}: value must be a boolean`);
  }
  return value;
}

function validateNonNegativeSafeInteger(value: unknown, field: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new Error(`invalid ${field}: value must be a non-negative safe integer`);
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
