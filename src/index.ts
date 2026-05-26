import { HostControlTransport } from "./control.ts";
import { HostProcessSandboxVm } from "./host-process.ts";
import { isSandboxWritableFileSystem } from "./vfs.ts";
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
  symlink(target: string, path: string): Promise<SandboxFileStat>;
  readlink(path: string): Promise<string>;
}

export type SandboxVirtualFileSystem = SandboxFileSystem;
export type SandboxMountedFileSystem = SandboxFileSystem;

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

export type SandboxHttpRequestHook = (
  request: SandboxHttpRequest,
) => void | Promise<void>;

export type BuiltInRootfsName = "alpine:3.20";

export type BuiltInRootfsConfig = {
  readonly kind: "built-in-rootfs";
  readonly name: BuiltInRootfsName;
};

export type Rootfs = BuiltInRootfsConfig;

export type SandboxFileSystemSource = {
  readonly kind: "virtual-fs";
  readonly fileSystem: SandboxVirtualFileSystem;
};

export type SandboxWritableFileSystemSource = {
  readonly kind: "virtual-fs";
  readonly fileSystem: SandboxWritableFileSystem;
};

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
  allow(): NetworkGrant;
  allowHttp(middleware?: HttpRequestMiddleware): HttpNetworkGrant;
}

export type NetworkConnectionRequestHandler = (
  connection: NetworkConnectionRequest,
) => void | Promise<void>;

export type NetworkPolicy = {
  readonly kind: "network-policy";
  readonly onConnectionRequest: NetworkConnectionRequestHandler;
};

type NetworkPolicyHookRegistration = {
  readonly hooks: readonly RegisteredHttpRequestHeadersHook[];
  readonly network: InternalNetworkConfig;
};

export interface SandboxConfigOptions {
  readonly rootfs: Rootfs;
  readonly overlay?: SandboxWritableFileSystemSource;
  readonly network?: NetworkPolicy;
}

export interface SandboxBootOptions {
  readonly mounts?: Readonly<Record<string, SandboxFileSystemSource>>;
  readonly cwd?: string;
}

export interface SandboxConfig {
  boot(options?: SandboxBootOptions): Promise<SandboxRuntime>;
}

export interface SandboxProcessExecOptions {
  readonly cwd?: string;
  readonly env?: Record<string, string>;
}

export interface SandboxProcessExecResult {
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
}

export interface SandboxProcess {
  exec(
    command: string,
    args?: readonly string[],
    options?: SandboxProcessExecOptions,
  ): Promise<SandboxProcessExecResult>;
}

export interface SandboxRuntime {
  readonly process: SandboxProcess;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface SandboxVm extends SandboxRuntime {
  readonly control: SandboxControl;
  readonly diagnostics?: SandboxDiagnostics;
}

interface SandboxDiagnostics {
  terminateHostForTest(): Promise<void>;
}

export const rootfs = {
  builtIn(name: BuiltInRootfsName): Rootfs {
    return {
      kind: "built-in-rootfs",
      name,
    };
  },
};

export function virtualFs(fileSystem: SandboxWritableFileSystem): SandboxWritableFileSystemSource;
export function virtualFs(fileSystem: SandboxVirtualFileSystem): SandboxFileSystemSource;
export function virtualFs(fileSystem: SandboxVirtualFileSystem): SandboxFileSystemSource {
  return {
    kind: "virtual-fs",
    fileSystem,
  };
}

export const fs = {
  virtual: virtualFs,
};

export const network = {
  buildPolicy(input: {
    readonly onConnectionRequest: NetworkConnectionRequestHandler;
  }): NetworkPolicy {
    return {
      kind: "network-policy",
      onConnectionRequest: input.onConnectionRequest,
    };
  },
};

export function createSandboxConfig(options: SandboxConfigOptions): SandboxConfig {
  validateSandboxConfigOptions(options);
  return new ConfiguredSandboxConfig(options);
}

type SpawnHttpRequestHeadersHook = {
  readonly id: string;
  readonly selector: SandboxHttpRequestSelector;
};

class ConfiguredSandboxConfig implements SandboxConfig {
  readonly #options: SandboxConfigOptions;

  constructor(options: SandboxConfigOptions) {
    this.#options = options;
  }

  async boot(options: SandboxBootOptions = {}): Promise<SandboxRuntime> {
    validateSandboxBootOptions(options);
    const networkPolicy = this.#options.network === undefined
      ? undefined
      : createNetworkPolicyHookRegistration(this.#options.network);
    const launchOptions = toInternalSandboxOptions(this.#options, options, networkPolicy?.network);
    validateInternalSandboxOptions(launchOptions);
    const hostOptions = toHostSpawnOptions(launchOptions, networkPolicy?.hooks ?? []);
    const hostVm = await HostProcessSandboxVm.spawn(
      launchOptions,
      hostOptions,
      new Map((networkPolicy?.hooks ?? []).map((hook) => [hook.id, hook])),
    );
    return new HostBackedSandboxVm(hostVm, launchOptions);
  }
}

class HostBackedSandboxVm implements SandboxVm {
  readonly control: SandboxControl;
  readonly process: SandboxProcess;
  readonly diagnostics?: SandboxDiagnostics;

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
    _options: InternalSandboxOptions,
  ) {
    this.#hostVm = hostVm;
    this.control = new HostControlTransport({
      connected: hostVm.hasControlSocket,
      channel: hostVm,
    });
    this.process = new ControlBackedSandboxProcess(this.control, _options.cwd);
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
    await this.control.close();
    await this.#hostVm.close();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

class ControlBackedSandboxProcess implements SandboxProcess {
  readonly #control: SandboxControl;
  readonly #cwd: string | undefined;

  constructor(control: SandboxControl, cwd: string | undefined) {
    this.#control = control;
    this.#cwd = cwd;
  }

  async exec(
    command: string,
    args: readonly string[] = [],
    options: SandboxProcessExecOptions = {},
  ): Promise<SandboxProcessExecResult> {
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
    init: {
      crateName: "sandbox-init",
    },
    rootfs: options.rootfs,
    rootfsOverlay: options.overlay === undefined
      ? undefined
      : {
        mode: "writable",
        source: "virtual-fs",
      },
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

function toInternalSandboxOptions(
  config: SandboxConfigOptions,
  boot: SandboxBootOptions,
  network?: InternalNetworkConfig,
): InternalSandboxOptions {
  const baseRootfs = lowerBuiltInRootfs(config.rootfs);
  return {
    rootfs: baseRootfs,
    overlay: config.overlay,
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
  const hook: SandboxHttpRequestHook = async (request) => {
    const grants: Array<{
      readonly kind: "raw" | "http";
      readonly middleware?: HttpRequestMiddleware;
    }> = [];
    const connection: NetworkConnectionRequest = {
      transport: "tcp",
      host: request.url.hostname,
      ip: request.destination.upstreamIp,
      port: request.destination.originalPort,
      allow() {
        grants.push({ kind: "raw" });
        return {};
      },
      allowHttp(middleware?: HttpRequestMiddleware) {
        grants.push({ kind: "http", middleware });
        return {};
      },
    };

    await policy.onConnectionRequest(connection);

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
          { action: "accept", protocol: "tcp", cidr: "0.0.0.0/0", ports: [80, 443, 8080, 8443] },
          { action: "accept", protocol: "udp", cidr: "10.0.2.1/32", ports: [53] },
        ],
      },
    },
  };
}

function lowerBuiltInRootfs(rootfs: Rootfs): InternalSandboxOptions["rootfs"] {
  const path = builtInRootfsPath(rootfs.name);
  return {
    path,
    readonly: true,
    format: "erofs",
  };
}

function builtInRootfsPath(name: BuiltInRootfsName): string {
  if (name === "alpine:3.20") {
    return "dist/rootfs/alpine-3.20.erofs";
  }
  throw new Error(`unsupported built-in rootfs: ${name satisfies never}`);
}

function validateSandboxConfigOptions(options: SandboxConfigOptions): void {
  if (options.rootfs.kind !== "built-in-rootfs") {
    throw new Error("invalid sandbox config: rootfs must be selected with rootfs.builtIn(...)");
  }
  builtInRootfsPath(options.rootfs.name);
  if (options.overlay !== undefined && !isSandboxWritableFileSystem(options.overlay.fileSystem)) {
    throw new Error("invalid sandbox config: overlay filesystem must be writable");
  }
  if (options.network !== undefined && options.network.kind !== "network-policy") {
    throw new Error("invalid sandbox config: network must be created with network.buildPolicy(...)");
  }
}

function validateSandboxBootOptions(options: SandboxBootOptions): void {
  const mountPaths = new Set<string>();
  for (const path of Object.keys(options.mounts ?? {})) {
    validateGuestPath(path, "mount.path");
    if (mountPaths.has(path)) {
      throw new Error(`invalid sandbox boot options: duplicate mount path: ${path}`);
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
  if (options.rootfs.format !== "erofs") {
    throw new Error("invalid sandbox options: rootfs.format must be erofs");
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
