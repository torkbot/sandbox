export type SandboxEnvironmentFactSource = "config" | "guest";

export type SandboxEnvironmentCommand = string;
export type SandboxDistroVersion = string;

export type SandboxDistroEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "distro";
  readonly relation: "is";
  readonly value: string;
};

export type SandboxDistroVersionEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "distro-version";
  readonly relation: "is";
  readonly value: SandboxDistroVersion;
};

export type SandboxRootfsImageEnvironmentFact = {
  readonly source: "config";
  readonly topic: "rootfs-image";
  readonly relation: "is";
  readonly value: string;
};

export type SandboxPackageManagerEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "package-manager";
  readonly relation: "is";
  readonly value: string;
};

export type SandboxShellEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "shell";
  readonly relation: "is";
  readonly value: string;
};

export type SandboxRootfsEnvironmentFact =
  | {
      readonly source: "config";
      readonly topic: "rootfs";
      readonly relation: "write-mode";
      readonly value:
        | "read-only"
        | "writable-ephemeral"
        | "writable-persistent-file"
        | "writable-persistent-cow";
    }
  | {
      readonly source: "guest";
      readonly topic: "rootfs";
      readonly relation: "mount-mode";
      readonly value: "read-only" | "read-write";
    };

export type SandboxNetworkEgressEnvironmentFact =
  | {
      readonly source: "config";
      readonly topic: "network-egress";
      readonly relation: "is";
      readonly value: "not-configured";
    }
  | {
      readonly source: "config";
      readonly topic: "network-egress";
      readonly relation: "requires";
      readonly value: "policy-grant";
    };

export type SandboxCommandEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "command";
  readonly relation: "exists";
  readonly value: SandboxEnvironmentCommand;
};

/**
 * Structured statement about a sandbox execution environment.
 *
 * Facts are intentionally small triples with required provenance so callers can
 * render them into prompts, logs, or policy decisions without parsing prose.
 */
export type SandboxEnvironmentFact =
  | SandboxDistroEnvironmentFact
  | SandboxDistroVersionEnvironmentFact
  | SandboxRootfsImageEnvironmentFact
  | SandboxPackageManagerEnvironmentFact
  | SandboxShellEnvironmentFact
  | SandboxRootfsEnvironmentFact
  | SandboxNetworkEgressEnvironmentFact
  | SandboxCommandEnvironmentFact;

export type RootfsEnvironmentFactsManifest = {
  readonly schemaVersion: 1;
  readonly rootfs: string;
  readonly facts: readonly SandboxEnvironmentFact[];
};

export const rootfsEnvironmentFactsManifestFile = "environment-facts.json";

export function configRootfsImageFact(value: string): SandboxRootfsImageEnvironmentFact {
  return {
    source: "config",
    topic: "rootfs-image",
    relation: "is",
    value,
  };
}

export function configCommandFact(value: string): SandboxCommandEnvironmentFact {
  return {
    source: "config",
    topic: "command",
    relation: "exists",
    value,
  };
}
