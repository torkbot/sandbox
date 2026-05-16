import { createRequire } from "node:module";

type NativeSandboxVm = {
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

export type NativeArtifactInspectionOptions = {
  readonly expectedStatic: boolean;
  readonly forbiddenDynamicLibraries: readonly string[];
  readonly macosEntitlements?: readonly string[];
  readonly artifactPath: string;
};

type NativeArtifactInspection = {
  readonly staticLinkageOk: boolean;
  readonly dynamicLibraries: readonly string[];
  readonly codesignValid: boolean;
  readonly entitlementNames: readonly string[];
};

type NativeBinding = {
  spawnSandbox(options: NativeSpawnSandboxOptions): Promise<NativeSandboxVm>;
  inspectSandboxArtifact(
    options: NativeArtifactInspectionOptions,
  ): Promise<NativeArtifactInspection>;
};

const require = createRequire(import.meta.url);

function nativeModuleName(): string {
  if (process.platform === "darwin" && process.arch === "arm64") {
    return "index.darwin-arm64.node";
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
