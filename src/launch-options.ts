import type {
  SandboxFileSystem,
  HttpRequestMiddleware,
  SandboxBlockStore,
} from "./index.ts";

export interface SandboxHttpRequestSelector {
  readonly origin: string;
}

export type InternalOutboundNetworkRule =
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

export interface InternalNetworkConfig {
  readonly outbound?: {
    readonly policy: "deny";
    readonly rules: readonly InternalOutboundNetworkRule[];
  };
  readonly http?: {
    readonly caCertificatePem?: string;
    readonly caPrivateKeyPem?: string;
    readonly requestHeaderHooks?: readonly {
      readonly id: string;
      readonly origin: string;
    }[];
  };
}

export interface InternalMount {
  readonly path: string;
  readonly fileSystem: SandboxFileSystem;
}

export interface InternalSandboxOptions {
  readonly resources?: {
    readonly cpus?: number;
    readonly memoryMiB?: number;
  };
  readonly rootfs: {
    readonly path: string;
    readonly readonly?: boolean;
    readonly format: "erofs" | "ext4";
    readonly storage?: {
      readonly kind: "cow-block-store";
      readonly blockSize: number;
      readonly blockStore: SandboxBlockStore;
    };
  };
  readonly mounts?: readonly InternalMount[];
  readonly network?: InternalNetworkConfig;
  readonly cwd?: string;
}

export type RegisteredHttpRequestHeadersHook = {
  readonly id: string;
  readonly selector: SandboxHttpRequestSelector;
  readonly hook: HttpRequestMiddleware;
  active: boolean;
};
