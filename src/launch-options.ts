import type {
  SandboxFileSystem,
  HttpRequestMiddleware,
  NetworkConnectionRequestHandler,
  SandboxBlockStore,
  SandboxBlockStoreContext,
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
  readonly policy?: {
    readonly connectionHook: true;
  };
}

export type InternalMount =
  | {
      readonly kind: "virtual-fs";
      readonly path: string;
      readonly fileSystem: SandboxFileSystem;
    }
  | {
      readonly kind: "host-directory";
      readonly path: string;
      readonly source: string;
      readonly access: "ro" | "rw";
      readonly mask?: {
        readonly paths: readonly string[];
        readonly storage?: {
          readonly kind: "host-directory";
          readonly source: string;
          readonly access: "rw";
        };
      };
    };

export interface InternalSandboxOptions {
  readonly resources?: {
    readonly cpus?: number;
    readonly memoryMiB?: number;
  };
  readonly rootfs: {
    readonly path: string;
    readonly readonly?: boolean;
    readonly format: "qcow2";
    readonly storage?:
      | {
          readonly kind: "cow-block-store";
          readonly blockSize: number;
          readonly maxDirtyBytes: number;
          readonly blockStore: SandboxBlockStore;
          readonly context: SandboxBlockStoreContext;
        }
      | {
          readonly kind: "ephemeral-cow";
          readonly blockSize: number;
          readonly maxDirtyBytes: number;
        }
      | {
          readonly kind: "persistent-qcow2-overlay";
          readonly path: string;
          readonly baseIdentity: string;
          readonly baseDigest: string;
        };
  };
  readonly mounts?: readonly InternalMount[];
  readonly network?: InternalNetworkConfig;
  readonly cwd?: string;
  readonly hostname: string;
}

export type RegisteredHttpRequestHeadersHook = {
  readonly id: string;
  readonly selector: SandboxHttpRequestSelector;
  readonly hook: HttpRequestMiddleware;
  active: boolean;
};

export type RegisteredNetworkConnectionHook = {
  readonly hook: NetworkConnectionRequestHandler;
  active: boolean;
};
