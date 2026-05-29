import {
  builtInRootfsIdentity,
  builtInRootfsPath,
} from "./artifacts.ts";
import { HostControlTransport } from "./control.ts";
import { HostProcessSandboxVm } from "./host-process.ts";
import { createMemoryFileSystem } from "./memory-fs.ts";
import {
  isSandboxPosixFileSystem,
  isSandboxWritableFileSystem,
} from "./vfs.ts";
import type { HostSpawnSandboxOptions } from "./spawn-options.ts";
import type { ControlBackedSandboxProcess, SandboxControl } from "./control.ts";
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

export type CowRootfsConfig = {
  readonly kind: "cow-rootfs";
  readonly base: BuiltInRootfsConfig;
  readonly writable: SandboxBlockStore;
};

export type Rootfs = BuiltInRootfsConfig | CowRootfsConfig;

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
  write(chunks: readonly SandboxBlockChunk[], context: SandboxBlockStoreContext): Promise<void>;
  flush?(context: SandboxBlockStoreContext): Promise<void>;
}

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
 * Opaque grant returned by `conn.allow()`.
 *
 * Grants intentionally carry no public fields today. They reserve a stable
 * extension point for future instance-local grant state.
 */
export interface NetworkGrant {
}

/**
 * Opaque grant returned by `conn.allowHttp(...)`.
 *
 * HTTP grants are distinct from generic network grants so future HTTP-specific
 * policy state can remain type-safe.
 */
export interface HttpNetworkGrant extends NetworkGrant {
}

/**
 * Opaque grant returned by `conn.allowDns(...)`.
 *
 * DNS grants are distinct from generic network grants so DNS-specific response
 * behavior can remain type-safe across UDP and TCP transports.
 */
export interface DnsNetworkGrant extends NetworkGrant {
}

/** IP transport observed by the network policy hook. */
export type NetworkTransport = "tcp" | "udp";

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

/** Application-layer protocol classification currently known for a policy event. */
export type NetworkApplicationProtocol = "http" | "dns" | "tls" | "unknown";

/**
 * Best-effort application-layer metadata associated with a TCP policy event.
 *
 * Classification is intentionally partial: early TCP decisions may have no
 * application metadata, TLS flows may expose SNI or ALPN before the runtime can
 * classify HTTP, and non-HTTP protocols may remain `unknown`.
 */
export interface NetworkApplicationClassification {
  /** Current application-layer classification. */
  readonly protocol: NetworkApplicationProtocol;
  /** ALPN protocol names offered or negotiated for the flow, when observed. */
  readonly alpn?: readonly string[];
  /** TLS Server Name Indication, when observed. */
  readonly sni?: string;
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
 * `transport` is the discriminant to use when code needs to branch between TCP
 * and UDP semantics. Higher-level classifications are represented by
 * `protocol`.
 */
export interface NetworkConnectionRequestBase<TTransport extends NetworkTransport> {
  /** IP transport that carried this event. Narrows TCP vs UDP request shapes. */
  readonly transport: TTransport;
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: NetworkEndpoint;
  /** Destination endpoint observed at the sandbox network boundary. */
  readonly dst: NetworkEndpoint;
  /**
   * Allows this observed connection, request, or flow using the default semantics
   * for its protocol.
   */
  allow(): NetworkGrant;
}

/**
 * TCP transport policy event.
 *
 * This event grants or denies TCP reachability for the observed flow. It may
 * include partial application metadata when the runtime has already observed
 * enough bytes to classify the flow.
 */
export interface TcpNetworkConnectionRequest extends NetworkConnectionRequestBase<"tcp"> {
  /** Current classification for an unrefined TCP transport event. */
  readonly protocol: "tcp";
  readonly src: TcpNetworkEndpoint;
  readonly dst: TcpNetworkEndpoint;
  /** Optional application-layer metadata observed for this TCP flow. */
  readonly application?: NetworkApplicationClassification;
  /** HTTP-specific grants are only available on `protocol: "http"` events. */
  readonly allowHttp?: never;
  /** DNS-specific grants are only available on `protocol: "dns"` events. */
  readonly allowDns?: never;
}

/**
 * UDP transport policy event.
 *
 * UDP is connectionless, so `allow()` permits the observed UDP flow according
 * to the runtime's flow-tracking semantics rather than establishing a stream.
 */
export interface UdpNetworkConnectionRequest extends NetworkConnectionRequestBase<"udp"> {
  /** Current classification for a UDP transport event. */
  readonly protocol: "udp";
  readonly src: UdpNetworkEndpoint;
  readonly dst: UdpNetworkEndpoint;
  /** HTTP-specific grants are only available on `protocol: "http"` events. */
  readonly allowHttp?: never;
  /** DNS-specific grants are only available on `protocol: "dns"` events. */
  readonly allowDns?: never;
}

/** DNS record type name exposed by DNS policy hooks. */
export type DnsRecordType =
  | "A"
  | "AAAA"
  | "CAA"
  | "CNAME"
  | "HTTPS"
  | "MX"
  | "NS"
  | "PTR"
  | "SOA"
  | "SRV"
  | "SVCB"
  | "TXT"
  | "UNKNOWN";

/** DNS question class name exposed by DNS policy hooks. */
export type DnsRecordClass = "IN" | "UNKNOWN";

/** A single DNS question from a DNS policy event. */
export interface DnsQuestion {
  /** Fully qualified DNS name as sent by the guest, without a trailing dot. */
  readonly name: string;
  /** DNS record type requested by the guest. */
  readonly type: DnsRecordType;
  /** DNS class requested by the guest. */
  readonly class: DnsRecordClass;
}

/** DNS response code for programmable DNS policy. */
export type DnsResponseCode = "NOERROR" | "NXDOMAIN" | "SERVFAIL" | "REFUSED";

/** DNS answer returned by programmable DNS policy. */
export type DnsAnswer =
  | {
      /** IPv4 address answer. */
      readonly type: "A";
      /** Name this answer applies to. Defaults to the matching question name. */
      readonly name?: string;
      /** IPv4 address string. */
      readonly address: string;
      /** Answer TTL in seconds. */
      readonly ttl?: number;
    }
  | {
      /** IPv6 address answer. */
      readonly type: "AAAA";
      /** Name this answer applies to. Defaults to the matching question name. */
      readonly name?: string;
      /** IPv6 address string. */
      readonly address: string;
      /** Answer TTL in seconds. */
      readonly ttl?: number;
    }
  | {
      /** Canonical name answer. */
      readonly type: "CNAME";
      /** Name this answer applies to. Defaults to the matching question name. */
      readonly name?: string;
      /** Canonical target name. */
      readonly target: string;
      /** Answer TTL in seconds. */
      readonly ttl?: number;
    }
  | {
      /** Text answer. */
      readonly type: "TXT";
      /** Name this answer applies to. Defaults to the matching question name. */
      readonly name?: string;
      /** TXT strings for this answer. */
      readonly values: readonly string[];
      /** Answer TTL in seconds. */
      readonly ttl?: number;
    };

/** Programmable DNS policy response. */
export interface DnsResponse {
  /** DNS response code. Defaults to `NOERROR` when answers are provided. */
  readonly code?: DnsResponseCode;
  /** DNS answers to return to the guest. */
  readonly answers?: readonly DnsAnswer[];
}

/** DNS request metadata exposed to programmable DNS policy. */
export interface SandboxDnsRequest {
  /** Transport carrying the DNS message. */
  readonly transport: NetworkTransport;
  /** Source endpoint observed at the sandbox network boundary. */
  readonly src: NetworkEndpoint;
  /** Destination endpoint observed at the sandbox network boundary. */
  readonly dst: NetworkEndpoint;
  /** DNS questions from the request. */
  readonly questions: readonly DnsQuestion[];
}

/**
 * Resolver invoked by `conn.allowDns(...)`.
 *
 * Returning `undefined` delegates to the runtime's default DNS behavior.
 */
export type DnsResolver = (
  request: SandboxDnsRequest,
) => DnsResponse | undefined | Promise<DnsResponse | undefined>;

/**
 * DNS policy event refined from either UDP DNS or TCP DNS.
 *
 * DNS is modeled as an application protocol rather than a UDP-only feature so
 * policy can use one ergonomic API for both DNS transports.
 */
export interface DnsNetworkConnectionRequest<TTransport extends NetworkTransport = NetworkTransport>
  extends NetworkConnectionRequestBase<TTransport> {
  /** Current classification for DNS request policy. */
  readonly protocol: "dns";
  /** DNS application metadata. */
  readonly application: NetworkApplicationClassification & {
    readonly protocol: "dns";
  };
  /** DNS questions from the request. */
  readonly questions: readonly DnsQuestion[];
  /**
   * Allows the DNS request and optionally supplies programmable DNS behavior.
   *
   * Use this when policy needs DNS semantics such as synthetic answers,
   * NXDOMAIN, or selective delegation to the runtime's default resolver.
   */
  allowDns(resolver?: DnsResolver): DnsNetworkGrant;
  /** HTTP-specific grants are only available on `protocol: "http"` events. */
  readonly allowHttp?: never;
}

/**
 * HTTP policy event refined from a TCP flow.
 *
 * HTTP events expose hostname-oriented fields and `allowHttp(...)` because the
 * runtime has classified the flow as HTTP or HTTPS and can apply HTTP-specific
 * semantics such as request middleware.
 */
export interface HttpNetworkConnectionRequest extends Omit<TcpNetworkConnectionRequest, "protocol" | "application" | "allowHttp"> {
  /** Current classification for HTTP or HTTPS request policy. */
  readonly protocol: "http";
  /** Application metadata for the classified HTTP flow. */
  readonly application: NetworkApplicationClassification & {
    readonly protocol: "http";
  };
  /** Hostname associated with the HTTP request. */
  readonly host: string;
  /** Upstream IP address selected for this HTTP request. */
  readonly ip: string;
  /** Upstream port selected for this HTTP request. */
  readonly port: number;
  /**
   * Allows the HTTP request and optionally applies request middleware.
   *
   * Use this when policy needs HTTP semantics such as header injection. Use
   * `allow()` when the policy wants the default grant for the classified event.
   */
  allowHttp(middleware?: HttpRequestMiddleware): HttpNetworkGrant;
  /** DNS-specific grants are only available on `protocol: "dns"` events. */
  readonly allowDns?: never;
}

/**
 * Network policy event passed to `network.policy(...)`.
 *
 * Use `transport` to branch on TCP vs UDP. Use `protocol` to branch on the
 * current classification (`"tcp"`, `"udp"`, or the HTTP refinement `"http"`).
 */
export type NetworkConnectionRequest =
  | HttpNetworkConnectionRequest
  | DnsNetworkConnectionRequest<"tcp">
  | DnsNetworkConnectionRequest<"udp">
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
}

export interface SandboxDefinition {
  boot(options?: SandboxBootOptions): Promise<SandboxInstance>;
}

export interface SandboxExecOptions {
  readonly cwd?: string;
  readonly env?: Record<string, string>;
}

export type SandboxSpawnOptions = SandboxExecOptions;

export interface SandboxExecResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SandboxProcess {
  readonly stdout: AsyncIterable<Uint8Array>;
  readonly stderr: AsyncIterable<Uint8Array>;
  readonly exit: Promise<{ readonly exitCode: number }>;
}

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
  ): Promise<SandboxProcess>;
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
  cow(options: { readonly base: BuiltInRootfsConfig; readonly writable: SandboxBlockStore }): Rootfs {
    return {
      kind: "cow-rootfs",
      base: options.base,
      writable: options.writable,
    };
  },
};

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
    const launchOptions = await toInternalSandboxOptions(this.#options, options, networkPolicy?.network);
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
          const result = await this.#rootExec.exec("/bin/sync");
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
    args: readonly string[] = [],
    options: SandboxExecOptions = {},
  ): Promise<SandboxExecResult> {
    return await this.#exec.exec(command, args, options);
  }

  async spawn(
    command: string,
    args: readonly string[] = [],
    options: SandboxSpawnOptions = {},
  ): Promise<SandboxProcess> {
    return await new ControlBackedSandboxSpawn(this.control, this.#options.cwd)
      .spawn(command, args, options);
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
    args: readonly string[] = [],
    options: SandboxExecOptions = {},
  ): Promise<SandboxExecResult> {
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

  async spawn(
    command: string,
    args: readonly string[] = [],
    options: SandboxSpawnOptions = {},
  ): Promise<ControlBackedSandboxProcess> {
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
    return await this.#control.spawn({
      argv,
      env,
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
): Promise<InternalSandboxOptions> {
  const rootfs = await lowerRootfs(config.rootfs);
  return {
    resources: config.resources,
    rootfs,
    cwd: boot.cwd,
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
    const grants: Array<{
      readonly kind: "http";
      readonly middleware?: HttpRequestMiddleware;
    }> = [];
    const connection: NetworkConnectionRequest = {
      protocol: "http",
      transport: "tcp",
      src: createNetworkEndpoint(
        request.destination.sourceIp,
        request.destination.sourcePort,
      ),
      dst: createNetworkEndpoint(
        request.destination.originalIp,
        request.destination.originalPort,
      ),
      application: {
        protocol: "http",
        alpn: request.tls?.alpn === undefined ? undefined : [request.tls.alpn],
        sni: request.tls?.sni,
      },
      host: request.url.hostname,
      ip: request.destination.originalIp,
      port: request.destination.originalPort,
      allow() {
        grants.push({ kind: "http" });
        return {};
      },
      allowHttp(middleware?: HttpRequestMiddleware) {
        grants.push({ kind: "http", middleware });
        return {};
      },
    };

    await policy[networkPolicyHandler](connection);

    if (grants.length === 0) {
      throw new Error(`network connection denied: ${request.url.origin}`);
    }

    for (const grant of grants) {
      if (grant.kind === "http") {
        await grant.middleware?.(request);
      }
    }
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
): Promise<InternalSandboxOptions["rootfs"]> {
  switch (rootfs.kind) {
    case "built-in-rootfs":
      return {
        path: builtInRootfsPath(rootfs.name),
        readonly: true,
        format: "qcow2",
      };
    case "cow-rootfs":
      return {
        path: builtInRootfsPath(rootfs.base.name),
        readonly: false,
        format: "qcow2",
        storage: {
          kind: "cow-block-store",
          blockSize: rootfs.writable.blockSize,
          blockStore: rootfs.writable,
          context: {
            base: builtInRootfsIdentity(rootfs.base.name),
          },
        },
      };
  }
}

function validateRootfs(rootfs: Rootfs): void {
  switch (rootfs.kind) {
    case "built-in-rootfs":
      validateBuiltInRootfsName(rootfs.name);
      return;
    case "cow-rootfs":
      if (rootfs.base.kind !== "built-in-rootfs") {
        throw new Error("invalid sandbox definition: rootfs.cow base must be created with rootfs.builtIn(...)");
      }
      validateBuiltInRootfsName(rootfs.base.name);
      validateBlockStore(rootfs.writable);
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

function validateBuiltInRootfsName(name: string): void {
  if (name !== "alpine:3.23") {
    throw new Error(`unsupported built-in rootfs: ${name}`);
  }
}

function validateSandboxBootOptions(options: SandboxBootOptions): void {
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
