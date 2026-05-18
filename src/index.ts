import { HostControlTransport } from "./control.ts";
import { HostProcessSandboxVm } from "./host-process.ts";
import { createSandboxHostFileSystemTools } from "./host-filesystem-tools.ts";
import { isSandboxWritableFileSystem } from "./vfs.ts";
import type { NativeSpawnSandboxOptions } from "./native.ts";
export { HostControlTransport } from "./control.ts";

export interface Transport<TIncoming = unknown, TOutgoing = unknown> {
  readonly incoming: AsyncIterable<TIncoming>;
  send(message: TOutgoing): Promise<void>;
  close(): Promise<void>;
}

export interface SandboxCpuOptions {
  readonly vcpus?: number;
}

export interface SandboxMemoryOptions {
  readonly mib?: number;
}

export type KernelConfig = {
  readonly kind: "project-kernel";
  readonly format?: "auto" | "raw" | "elf" | "pe-gz" | "image-gz" | "image-zstd";
};

export type InitConfig = {
  readonly kind: "project-init";
  readonly crate: "sandbox-init";
};

export type SandboxFsConfig = PrebuiltRootfsConfig | LinuxOverlayRootfsConfig | ScratchFsConfig;

export type RootfsConfig = PrebuiltRootfsConfig | LinuxOverlayRootfsConfig;

export type PrebuiltRootfsConfig = {
  readonly kind: "prebuilt-rootfs";
  readonly path: string;
  readonly readonly?: boolean;
  readonly format: "directory" | "erofs";
};

export type LinuxOverlayRootfsConfig = {
  readonly kind: "linux-overlay-fs";
  readonly lower: SandboxFsConfig;
  readonly upper: SandboxFsConfig;
};

export type ScratchFsConfig = {
  readonly kind: "scratch-fs";
};

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

export type SandboxHostReadResult = {
  readonly path: string;
  readonly content: string;
  readonly totalLines: number;
  readonly truncated: boolean;
};

export type SandboxHostPatchEdit = {
  readonly oldText: string;
  readonly newText: string;
};

export type SandboxHostBashResult = {
  readonly stdout: string;
  readonly stderr: string;
  readonly exitCode: number;
};

export interface SandboxHostFileSystemTools {
  read(input: {
    readonly path: string;
    readonly offset?: number;
    readonly limit?: number;
    readonly signal?: AbortSignal;
  }): Promise<SandboxHostReadResult>;
  write(input: {
    readonly path: string;
    readonly content: string;
    readonly signal?: AbortSignal;
  }): Promise<void>;
  patch(input: {
    readonly path: string;
    readonly edits: readonly SandboxHostPatchEdit[];
    readonly signal?: AbortSignal;
  }): Promise<void>;
  bash(input: {
    readonly command: string;
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
  }): Promise<SandboxHostBashResult>;
}

export type VirtualFsMountConfig = {
  readonly kind: "virtual-fs";
  readonly path: string;
  readonly fileSystem: SandboxVirtualFileSystem;
};

export type FileSystemBindingConfig = {
  readonly kind: "filesystem-binding";
  readonly path: string;
  readonly fileSystem: SandboxVirtualFileSystem;
};

export type MountConfig = VirtualFsMountConfig;

export interface HttpPolicyRequest {
  readonly method: string;
  readonly url: string;
  readonly destinationIp: string;
  readonly headers: Record<string, string>;
  readonly tls?: {
    readonly serverName?: string;
    readonly alpnProtocol?: string;
    readonly protocol?: string;
  };
}

export type HttpPolicyDecision =
  | { readonly action: "allow"; readonly headers?: Record<string, string> }
  | { readonly action: "deny"; readonly reason: string };

export interface HttpInterceptionConfig {
  policy(request: HttpPolicyRequest): Promise<HttpPolicyDecision>;
}

export type OutboundNetworkRule =
  | {
      readonly action: "accept";
      readonly protocol: "tcp";
      readonly cidr: string;
      readonly ports?: readonly number[];
    }
  | {
      readonly action: "accept";
      readonly protocol: "udp";
      readonly cidr: string;
      readonly ports?: readonly number[];
    }
  | {
      readonly action: "accept";
      readonly scope: "public-internet";
      readonly ports?: readonly number[];
    };

export interface OutboundNetworkPolicy {
  readonly policy: "deny";
  readonly rules: readonly OutboundNetworkRule[];
}

export interface NetworkConfig {
  readonly outbound?: OutboundNetworkPolicy;
  readonly http?: HttpInterceptionConfig;
}

export interface SandboxOptions {
  readonly name?: string;
  readonly cpu?: SandboxCpuOptions;
  readonly memory?: SandboxMemoryOptions;
  readonly kernel: KernelConfig;
  readonly init: InitConfig;
  readonly rootfs: RootfsConfig;
  readonly mounts?: readonly MountConfig[];
  readonly bindings?: readonly FileSystemBindingConfig[];
  readonly network?: NetworkConfig;
}

export interface SandboxMounts {
  get(path: string): SandboxMountedFileSystem;
  virtualFs(path: string): SandboxVirtualFileSystem;
  host(path: string): SandboxHostFileSystemTools;
}

export type SandboxControlEvent =
  | {
      readonly type: "init.ready";
      readonly guest: {
        readonly root: { readonly readonly: boolean };
        readonly init: { readonly name: string };
      };
    }
  | {
      readonly type: "guest.exec.complete";
      readonly id: string;
      readonly exitCode: number;
      readonly stdout: string;
      readonly stderr: string;
    };

export type SandboxControlCommand = {
  readonly type: "guest.exec";
  readonly id: string;
  readonly argv: readonly string[];
  readonly env?: Record<string, string>;
};

export interface SandboxControl extends Transport<SandboxControlEvent, SandboxControlCommand> {
  exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>;
}

export interface SandboxVm {
  readonly control: SandboxControl;
  readonly mounts: SandboxMounts;
  readonly diagnostics?: SandboxDiagnostics;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

export interface SandboxDiagnostics {
  terminateHostForTest(): Promise<void>;
}

export function projectKernel(options: Omit<KernelConfig, "kind"> = {}): KernelConfig {
  return {
    kind: "project-kernel",
    ...options,
  };
}

export function projectInit(): InitConfig {
  return {
    kind: "project-init",
    crate: "sandbox-init",
  };
}

export function prebuiltRootfs(path: string, options: Omit<PrebuiltRootfsConfig, "kind" | "path">): PrebuiltRootfsConfig {
  return {
    kind: "prebuilt-rootfs",
    path,
    readonly: options.readonly ?? true,
    format: options.format,
  };
}

export function scratchFs(): ScratchFsConfig {
  return {
    kind: "scratch-fs",
  };
}

export function linuxOverlayFs(input: {
  readonly lower: SandboxFsConfig;
  readonly upper: SandboxFsConfig;
}): LinuxOverlayRootfsConfig {
  return {
    kind: "linux-overlay-fs",
    lower: input.lower,
    upper: input.upper,
  };
}

export function virtualFsMount(path: string, fileSystem: SandboxVirtualFileSystem): VirtualFsMountConfig {
  return {
    kind: "virtual-fs",
    path,
    fileSystem,
  };
}

export function mount(path: string, fileSystem: SandboxVirtualFileSystem): VirtualFsMountConfig {
  return virtualFsMount(path, fileSystem);
}

export function binding(path: string, fileSystem: SandboxVirtualFileSystem): FileSystemBindingConfig {
  return {
    kind: "filesystem-binding",
    path,
    fileSystem,
  };
}

export function acceptTcp(input: {
  readonly cidr: string;
  readonly ports?: readonly number[];
}): OutboundNetworkRule {
  return {
    action: "accept",
    protocol: "tcp",
    cidr: input.cidr,
    ports: input.ports,
  };
}

export function acceptUdp(input: {
  readonly cidr: string;
  readonly ports?: readonly number[];
}): OutboundNetworkRule {
  return {
    action: "accept",
    protocol: "udp",
    cidr: input.cidr,
    ports: input.ports,
  };
}

export function acceptPublicInternet(input: {
  readonly ports?: readonly number[];
} = {}): OutboundNetworkRule {
  return {
    action: "accept",
    scope: "public-internet",
    ports: input.ports,
  };
}

export async function spawnSandbox(options: SandboxOptions): Promise<SandboxVm> {
  validateSandboxOptions(options);
  const nativeOptions = toNativeSpawnOptions(options);
  const nativeVm = await HostProcessSandboxVm.spawn(options, nativeOptions);
  return new NativeBackedSandboxVm(nativeVm, options);
}

class NativeBackedSandboxVm implements SandboxVm {
  readonly mounts: SandboxMounts;
  readonly control: SandboxControl;
  readonly diagnostics?: SandboxDiagnostics;

  readonly #nativeVm: {
    readonly hasControlSocket: boolean;
    writeControlPacket(packet: Uint8Array): void;
    tryReadControlPacket(): Uint8Array | null;
    close(): Promise<void> | void;
    terminateHostForTest?(): Promise<void>;
  };
  #closed = false;

  constructor(
    nativeVm: {
      readonly hasControlSocket: boolean;
      writeControlPacket(packet: Uint8Array): void;
      tryReadControlPacket(): Uint8Array | null;
      close(): Promise<void> | void;
      terminateHostForTest?(): Promise<void>;
    },
    options: SandboxOptions,
  ) {
    this.#nativeVm = nativeVm;
    this.mounts = new ConfiguredSandboxMounts(options.mounts ?? [], options.bindings ?? []);
    this.control = new HostControlTransport({
      connected: nativeVm.hasControlSocket,
      channel: nativeVm,
    });
    if (nativeVm.terminateHostForTest !== undefined) {
      this.diagnostics = {
        terminateHostForTest: () => nativeVm.terminateHostForTest?.() ?? Promise.resolve(),
      };
    }
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    await this.control.close();
    await this.#nativeVm.close();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }
}

class ConfiguredSandboxMounts implements SandboxMounts {
  readonly #mounts = new Map<string, SandboxMountedFileSystem>();
  readonly #virtualMounts = new Map<string, SandboxVirtualFileSystem>();
  readonly #hostTools = new Map<string, SandboxHostFileSystemTools>();

  constructor(
    mounts: readonly MountConfig[],
    bindings: readonly FileSystemBindingConfig[],
  ) {
    for (const mount of mounts) {
      this.#mounts.set(mount.path, mount.fileSystem);
      this.#virtualMounts.set(mount.path, mount.fileSystem);
      this.#hostTools.set(mount.path, createSandboxHostFileSystemTools(mount.fileSystem));
    }
    for (const binding of bindings) {
      this.#hostTools.set(binding.path, createSandboxHostFileSystemTools(binding.fileSystem));
    }
  }

  get(path: string): SandboxMountedFileSystem {
    const mount = this.#mounts.get(path);
    if (mount === undefined) {
      throw new Error(`sandbox mount not found: ${path}`);
    }
    return mount;
  }

  virtualFs(path: string): SandboxVirtualFileSystem {
    const mount = this.#virtualMounts.get(path);
    if (mount === undefined) {
      throw new Error(`virtualFs mount not found: ${path}`);
    }
    return mount;
  }

  host(path: string): SandboxHostFileSystemTools {
    const tools = this.#hostTools.get(path);
    if (tools === undefined) {
      throw new Error(`host filesystem tools not found: ${path}`);
    }
    return tools;
  }
}

function toNativeSpawnOptions(options: SandboxOptions): NativeSpawnSandboxOptions {
  const rootfs = lowerNativeRootfs(options.rootfs);

  return {
    name: options.name,
    cpu: options.cpu,
    memory: options.memory,
    kernel: {
      format: options.kernel.format,
    },
    init: {
      crateName: options.init.crate,
    },
    rootfs: {
      path: rootfs.path,
      readonly: rootfs.readonly,
      format: rootfs.format,
    },
    rootfsOverlay: options.rootfs.kind === "linux-overlay-fs"
      ? { mode: "writable" }
      : undefined,
    mounts: options.mounts?.map((mount) => {
      return {
        kind: mount.kind,
        path: mount.path,
        writable: isSandboxWritableFileSystem(mount.fileSystem),
      };
    }),
    network: options.network === undefined
      ? undefined
      : {
          outbound: options.network.outbound,
          http: options.network.http === undefined
            ? undefined
            : {},
        },
  };
}

function lowerNativeRootfs(rootfs: RootfsConfig): PrebuiltRootfsConfig {
  if (rootfs.kind === "prebuilt-rootfs") {
    return rootfs;
  }

  if (rootfs.lower.kind !== "prebuilt-rootfs") {
    throw new Error(`rootfs ${rootfs.kind} lower ${rootfs.lower.kind} is not implemented yet`);
  }
  if (rootfs.upper.kind !== "scratch-fs") {
    throw new Error(`rootfs ${rootfs.kind} upper ${rootfs.upper.kind} is not implemented yet`);
  }
  return {
    ...rootfs.lower,
    readonly: true,
  };
}

function validateSandboxOptions(options: SandboxOptions): void {
  if (options.cpu?.vcpus !== undefined && options.cpu.vcpus <= 0) {
    throw new Error("invalid spawnSandbox options: cpu.vcpus must be greater than zero");
  }
  if (options.memory?.mib !== undefined && options.memory.mib <= 0) {
    throw new Error("invalid spawnSandbox options: memory.mib must be greater than zero");
  }
  if (options.init.crate !== "sandbox-init") {
    throw new Error(`invalid spawnSandbox options: unsupported init crate: ${options.init.crate}`);
  }
  if (options.rootfs.kind === "prebuilt-rootfs") {
    if (options.rootfs.path.length === 0) {
      throw new Error("invalid spawnSandbox options: rootfs.path must not be empty");
    }
    if (options.rootfs.format === "directory") {
      throw new Error("invalid spawnSandbox options: directory rootfs is not supported for sandboxed VM launch; use an EROFS rootfs");
    }
  }

  const mountPaths = new Set<string>();
  for (const mount of options.mounts ?? []) {
    if (!mount.path.startsWith("/")) {
      throw new Error("invalid spawnSandbox options: mount.path must be absolute");
    }
    if (mount.path.includes("=") || mount.path.includes(";")) {
      throw new Error("invalid spawnSandbox options: mount.path must not contain '=' or ';'");
    }
    if (mountPaths.has(mount.path)) {
      throw new Error(`invalid spawnSandbox options: duplicate mount path: ${mount.path}`);
    }
    mountPaths.add(mount.path);
  }

  const bindingPaths = new Set<string>();
  for (const binding of options.bindings ?? []) {
    if (!binding.path.startsWith("/")) {
      throw new Error("invalid spawnSandbox options: binding.path must be absolute");
    }
    if (mountPaths.has(binding.path)) {
      throw new Error(`invalid spawnSandbox options: binding path conflicts with mount path: ${binding.path}`);
    }
    if (bindingPaths.has(binding.path)) {
      throw new Error(`invalid spawnSandbox options: duplicate binding path: ${binding.path}`);
    }
    bindingPaths.add(binding.path);
  }

  if (options.network?.outbound?.policy !== undefined && options.network.outbound.policy !== "deny") {
    throw new Error("invalid spawnSandbox options: network.outbound.policy must be deny");
  }

  for (const rule of options.network?.outbound?.rules ?? []) {
    if ("cidr" in rule) {
      validateCidr(rule.cidr);
    }
    validateOutboundPorts(rule.ports);
  }
}

function validateOutboundPorts(ports: readonly number[] | undefined): void {
  for (const port of ports ?? []) {
    if (!Number.isInteger(port) || port < 1 || port > 65_535) {
      throw new Error(`invalid spawnSandbox options: invalid outbound network port: ${port}`);
    }
  }
}

function validateCidr(range: string): void {
  const [address, prefixText, extra] = range.split("/");
  if (address === undefined || prefixText === undefined || extra !== undefined) {
    throw new Error(`invalid spawnSandbox options: invalid CIDR range: ${range}`);
  }

  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix)) {
    throw new Error(`invalid spawnSandbox options: invalid CIDR prefix: ${range}`);
  }

  if (address.includes(":")) {
    if (prefix < 0 || prefix > 128) {
      throw new Error(`invalid spawnSandbox options: invalid CIDR prefix: ${range}`);
    }
    return;
  }

  if (prefix < 0 || prefix > 32) {
    throw new Error(`invalid spawnSandbox options: invalid CIDR prefix: ${range}`);
  }
}
