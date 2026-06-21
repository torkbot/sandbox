import type { InternalOutboundNetworkRule } from "./launch-options.ts";

export type HostSpawnMount =
  | {
      readonly kind: "virtual-fs";
      readonly path: string;
      readonly writable?: boolean;
    }
  | {
      readonly kind: "host-directory";
      readonly path: string;
      readonly source: string;
      readonly access: "ro" | "rw";
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
    readonly storage?: {
      readonly kind: "cow-block-store" | "ephemeral-cow";
      readonly blockSize: number;
      readonly maxDirtyBytes: number;
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
