import { createRequire } from "node:module";

type NativeSandboxVm = {
  readonly hasControlSocket: boolean;
  writeControlPacket(packet: Uint8Array): void;
  tryReadControlPacket(): Uint8Array | null;
  close(): Promise<void>;
};

export type NativeSpawnSandboxOptions = {
  readonly name?: string;
  readonly cpu?: {
    readonly vcpus?: number;
  };
  readonly memory?: {
    readonly mib?: number;
  };
  readonly kernel: {
    readonly format?: "auto" | "raw" | "elf" | "pe-gz" | "image-gz" | "image-zstd";
  };
  readonly init: {
    readonly crateName: "sandbox-init";
  };
  readonly rootfs: {
    readonly path: string;
    readonly readonly?: boolean;
    readonly format: "directory" | "erofs";
  };
  readonly rootfsOverlay?: {
    readonly mode: "writable";
  };
  readonly mounts?: readonly (
    | {
        readonly kind: "sqlite-fs";
        readonly path: string;
        readonly name: string;
      }
    | {
        readonly kind: "virtual-fs";
        readonly path: string;
      }
  )[];
  readonly network?: {
    readonly http?: {
      readonly protectedRanges?: readonly string[];
    };
  };
};

type NativeBinding = {
  spawnSandbox(options: NativeSpawnSandboxOptions): Promise<NativeSandboxVm>;
};

const require = createRequire(import.meta.url);

function nativeModuleName(): string {
  if (process.platform === "darwin" && process.arch === "arm64") {
    return "index.darwin-arm64.node";
  }

  if (process.platform === "linux" && process.arch === "x64") {
    return "index.linux-x64-gnu.node";
  }

  throw new Error(
    `unsupported native sandbox target: ${process.platform}-${process.arch}`,
  );
}

export function nativeBindingPath(): string {
  return new URL(`../crates/sandbox-node/${nativeModuleName()}`, import.meta.url).pathname;
}

export function loadNativeBinding(): NativeBinding {
  return require(nativeBindingPath()) as NativeBinding;
}
