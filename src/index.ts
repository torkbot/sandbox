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

export type RootfsConfig = {
  readonly kind: "prebuilt-rootfs";
  readonly path: string;
  readonly readonly?: boolean;
  readonly format: "directory" | "erofs";
};

export type RootfsOverlayConfig = {
  readonly mode: "writable";
};

export type SandboxFileType = "file" | "directory";

export type SandboxFileStat = {
  readonly type: SandboxFileType;
  readonly sizeBytes: number | null;
  readonly mediaType: string | null;
  readonly modifiedAtMs: number | null;
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

export type SandboxVirtualFileSystem = SandboxFileSystem;
export type SandboxMountedFileSystem = SandboxFileSystem;

export type SqliteFsMountConfig = {
  readonly kind: "sqlite-fs";
  readonly path: string;
  readonly name: string;
  readonly database: SqliteFsDatabase;
};

export interface SqliteFsDatabase {
  readonly open: boolean;
  prepare(sql: string): SqliteFsStatement;
  exec(sql: string): Promise<void>;
  transaction<TArgs extends readonly unknown[], TResult>(
    fn: (...args: TArgs) => Promise<TResult>,
  ): (...args: TArgs) => Promise<TResult>;
}

export interface SqliteFsStatement {
  run(...parameters: readonly unknown[]): Promise<{
    readonly changes: number;
    readonly lastInsertRowid: number;
  }>;
  get(...parameters: readonly unknown[]): Promise<unknown>;
  all(...parameters: readonly unknown[]): Promise<readonly unknown[]>;
}

export type VirtualFsMountConfig = {
  readonly kind: "virtual-fs";
  readonly path: string;
  readonly fileSystem: SandboxVirtualFileSystem;
};

export type MountConfig = SqliteFsMountConfig | VirtualFsMountConfig;

export interface HttpPolicyRequest {
  readonly method: string;
  readonly url: string;
  readonly destinationIp: string;
  readonly headers: Record<string, string>;
  readonly tls?: {
    readonly serverName?: string;
    readonly protocol?: string;
  };
}

export type HttpPolicyDecision =
  | { readonly action: "allow" }
  | { readonly action: "deny"; readonly reason: string };

export interface HttpInterceptionConfig {
  readonly ca?: "ephemeral" | { readonly certificatePem: string; readonly privateKeyPem: string };
  readonly protectedRanges?: readonly string[];
  policy(request: HttpPolicyRequest): Promise<HttpPolicyDecision>;
  modifyRequestHeaders?(headers: Record<string, string>): Promise<Record<string, string>>;
}

export interface NetworkConfig {
  readonly http?: HttpInterceptionConfig;
}

export interface SandboxOptions {
  readonly name?: string;
  readonly cpu?: SandboxCpuOptions;
  readonly memory?: SandboxMemoryOptions;
  readonly kernel: KernelConfig;
  readonly init: InitConfig;
  readonly rootfs: RootfsConfig;
  readonly rootfsOverlay?: RootfsOverlayConfig;
  readonly mounts?: readonly MountConfig[];
  readonly network?: NetworkConfig;
}

export interface SqliteFsSnapshot {
  readonly files: Record<string, { readonly type: "file"; readonly contents: string }>;
}

export interface SqliteFsHandle extends SandboxMountedFileSystem {
  snapshot(): Promise<SqliteFsSnapshot>;
}

export interface SandboxMounts {
  get(path: string): SandboxMountedFileSystem;
  sqliteFs(path: string): SqliteFsHandle;
  virtualFs(path: string): SandboxVirtualFileSystem;
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
};

export interface SandboxControl extends Transport<SandboxControlEvent, SandboxControlCommand> {
  exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>;
}

export interface RootfsSnapshotOptions {
  readonly format: "erofs";
}

export interface RootfsSnapshot {
  readonly format: "erofs";
  readonly digest: string;
  readonly bytes: Uint8Array;
}

export interface SandboxVm {
  readonly control: SandboxControl;
  readonly mounts: SandboxMounts;
  readonly rootfs: {
    hash(): Promise<string>;
    snapshot(options: RootfsSnapshotOptions): Promise<RootfsSnapshot>;
  };
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
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

export function prebuiltRootfs(path: string, options: Omit<RootfsConfig, "kind" | "path">): RootfsConfig {
  return {
    kind: "prebuilt-rootfs",
    path,
    readonly: options.readonly ?? true,
    format: options.format,
  };
}

export function sqliteFsMount(input: {
  readonly path: string;
  readonly name: string;
  readonly database: SqliteFsDatabase;
}): SqliteFsMountConfig {
  return {
    kind: "sqlite-fs",
    ...input,
  };
}

export function virtualFsMount(path: string, fileSystem: SandboxVirtualFileSystem): VirtualFsMountConfig {
  return {
    kind: "virtual-fs",
    path,
    fileSystem,
  };
}

export async function spawnSandbox(_options: SandboxOptions): Promise<SandboxVm> {
  throw new Error("spawnSandbox is not implemented yet");
}

export interface SandboxArtifactInspectionOptions {
  readonly expectedStatic: boolean;
  readonly forbiddenDynamicLibraries: readonly string[];
  readonly macosEntitlements?: readonly string[];
}

export interface SandboxArtifactInspection {
  readonly staticLinkage: { readonly ok: boolean };
  readonly dynamicLibraries: readonly string[];
  readonly codesign: {
    readonly valid: boolean;
    readonly entitlements: Record<string, boolean>;
  };
}

export async function inspectSandboxArtifact(
  _options: SandboxArtifactInspectionOptions,
): Promise<SandboxArtifactInspection> {
  throw new Error("inspectSandboxArtifact is not implemented yet");
}
