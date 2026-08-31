import type { InternalOutboundNetworkRule } from "./launch-options.ts";

export type HostSpawnMount =
  | {
      readonly kind: "virtual-fs";
      readonly path: string;
      readonly writable?: boolean;
    }
  | {
      readonly kind: "block-device";
      readonly path: string;
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

export type HostBlobBlockProvider =
  | {
      readonly kind: "local";
      readonly path: string;
      readonly prefix?: string;
    }
  | {
      readonly kind: "s3";
      readonly bucket: string;
      readonly region: string;
      readonly endpoint?: string;
      readonly prefix?: string;
      readonly auth:
        | { readonly kind: "environment" }
        | {
            readonly kind: "access-key";
            readonly accessKeyId: string;
            readonly secretAccessKey: string;
            readonly sessionToken?: string;
          };
    }
  | {
      readonly kind: "gcs";
      readonly bucket: string;
      readonly prefix?: string;
      readonly auth:
        | { readonly kind: "environment" }
        | { readonly kind: "service-account"; readonly key: string }
        | { readonly kind: "bearer-token"; readonly token: string };
    }
  | {
      readonly kind: "azure";
      readonly account: string;
      readonly container: string;
      readonly endpoint?: string;
      readonly prefix?: string;
      readonly auth:
        | { readonly kind: "environment" }
        | { readonly kind: "access-key"; readonly accessKey: string }
        | { readonly kind: "bearer-token"; readonly token: string }
        | {
            readonly kind: "client-secret";
            readonly clientId: string;
            readonly clientSecret: string;
            readonly tenantId: string;
          };
    };

export type HostBlobBlockAcquireOptions = {
  readonly provider: HostBlobBlockProvider;
  readonly volume: string;
  readonly sizeBytes: bigint;
};

export type HostSpawnSandboxOptions = {
  readonly name?: string;
  readonly hostname: string;
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
    readonly format: "qcow2";
    readonly storage?:
      | {
          readonly kind: "cow-block-store" | "ephemeral-cow";
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
  readonly mounts?: readonly HostSpawnMount[];
  readonly network?: {
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
  };
};
