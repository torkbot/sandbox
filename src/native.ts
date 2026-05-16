import { createRequire } from "node:module";

type NativeSandboxVm = {
  close(): Promise<void>;
};

type NativeSpawnSandboxOptions = {
  readonly name?: string;
};

type NativeArtifactInspectionOptions = {
  readonly expectedStatic: boolean;
};

type NativeArtifactInspection = {
  readonly staticLinkageOk: boolean;
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

export function loadNativeBinding(): NativeBinding {
  return require(`../crates/sandbox-node/${nativeModuleName()}`) as NativeBinding;
}
