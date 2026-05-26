import type { OutboundNetworkRule } from "./index.ts";

export type HostSpawnSandboxOptions = {
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
    readonly source?: "virtual-fs";
  };
  readonly mounts?: readonly {
    readonly kind: "virtual-fs";
    readonly path: string;
    readonly writable?: boolean;
  }[];
  readonly network?: {
    readonly outbound?: {
      readonly policy: "deny";
      readonly rules: readonly OutboundNetworkRule[];
    };
    readonly http?: {
      readonly caCertificatePem?: string;
      readonly caPrivateKeyPem?: string;
      readonly requestHeaderHooks?: readonly {
        readonly id: string;
        readonly origin: string;
      }[];
    };
  };
};
