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
import type { SandboxControl } from "./control.ts";
import type { SandboxControlEvent } from "./control-codec.ts";
import type {
  InternalNetworkConfig,
  InternalSandboxOptions,
  RegisteredHttpRequestHeadersHook,
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

export interface SandboxHttpRequest {
  readonly protocol: "http/1.1" | "h2";
  readonly url: URL;
  readonly method: string;
  readonly headers: Headers;
  readonly destination: {
    readonly originalIp: string;
    readonly originalPort: number;
    readonly upstreamIp: string;
    readonly upstreamPort: number;
  };
  readonly tls?: {
    readonly sni?: string;
    readonly alpn?: string;
  };
}

export type BuiltInRootfsName = "alpine:3.20";

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

export type HttpRequestMiddleware = (
  request: SandboxHttpRequest,
) => void | Promise<void>;

export interface NetworkGrant {
}

export interface HttpNetworkGrant extends NetworkGrant {
}

export interface NetworkConnectionRequest {
  readonly transport: "tcp" | "udp";
  readonly host?: string;
  readonly ip?: string;
  readonly port: number;
  /**
   * Allows HTTP(S)-classified traffic for this connection without request middleware.
   * Raw non-HTTP egress is not exposed by the first public policy API.
   */
  allow(): NetworkGrant;
  allowHttp(middleware?: HttpRequestMiddleware): HttpNetworkGrant;
}

export type NetworkConnectionRequestHandler = (
  connection: NetworkConnectionRequest,
) => void | Promise<void>;

const networkPolicyHandler: unique symbol = Symbol("networkPolicyHandler");

export type NetworkPolicy = {
  readonly kind: "network-policy";
  readonly [networkPolicyHandler]: NetworkConnectionRequestHandler;
};

type NetworkPolicyHookRegistration = {
  readonly hooks: readonly RegisteredHttpRequestHeadersHook[];
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

export interface SandboxExecResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SandboxInstance {
  exec(
    command: string,
    args?: readonly string[],
    options?: SandboxExecOptions,
  ): Promise<SandboxExecResult>;
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
        const result = await this.#rootExec.exec("/bin/sync");
        if (result.exitCode !== 0) {
          throw new Error(`sandbox close sync failed with exit code ${result.exitCode}: ${result.stderr}`);
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
      transport: "tcp",
      host: request.url.hostname,
      ip: request.destination.upstreamIp,
      port: request.destination.upstreamPort,
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
    network: {
      outbound: {
        policy: "deny",
        rules: [
          { action: "accept", scope: "public-internet", ports: [] },
          { action: "accept", protocol: "udp", cidr: "10.0.2.1/32", ports: [53] },
        ],
      },
    },
  };
}

async function lowerRootfs(
  rootfs: Rootfs,
): Promise<InternalSandboxOptions["rootfs"]> {
  switch (rootfs.kind) {
    case "built-in-rootfs":
      return {
        path: builtInRootfsPath(rootfs.name),
        readonly: true,
        format: "erofs",
      };
    case "cow-rootfs":
      return {
        path: builtInRootfsPath(rootfs.base.name, "ext4"),
        readonly: false,
        format: "ext4",
        storage: {
          kind: "cow-block-store",
          blockSize: rootfs.writable.blockSize,
          blockStore: rootfs.writable,
          context: {
            base: builtInRootfsIdentity(rootfs.base.name, "ext4"),
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
  if (name !== "alpine:3.20") {
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
  if (options.rootfs.format !== "erofs" && options.rootfs.format !== "ext4") {
    throw new Error("invalid sandbox options: rootfs.format must be erofs or ext4");
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
