export type BuiltInRootfsName = "alpine:3.23";

export type SandboxEnvironmentFactSource = "config" | "guest";

export type SandboxDistroVersion = "3.23" | `3.23.${number}`;

/**
 * Commands that the current built-in agent rootfs intentionally exposes as
 * stable developer-facing tools. The list is affirmative rather than
 * exhaustive: absence from this union means the command is not part of this
 * metadata contract, not that the command cannot exist in the guest.
 */
export type SandboxEnvironmentCommand =
  | "bash"
  | "curl"
  | "git"
  | "gh"
  | "jq"
  | "node"
  | "npm"
  | "pip3"
  | "python3"
  | "rg";

export type SandboxDistroEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "distro";
  readonly relation: "is";
  readonly value: "alpine";
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
  readonly value: BuiltInRootfsName;
};

export type SandboxPackageManagerEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "package-manager";
  readonly relation: "is";
  readonly value: "apk";
};

export type SandboxShellEnvironmentFact = {
  readonly source: SandboxEnvironmentFactSource;
  readonly topic: "shell";
  readonly relation: "is";
  readonly value: "/bin/sh";
};

export type SandboxRootfsEnvironmentFact =
  | {
      readonly source: "config";
      readonly topic: "rootfs";
      readonly relation: "write-mode";
      readonly value:
        | "read-only"
        | "writable-ephemeral"
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
  readonly rootfs: BuiltInRootfsName;
  readonly facts: readonly SandboxEnvironmentFact[];
};

export const rootfsEnvironmentFactsManifestFile = "environment-facts.json";
export const rootfsEnvironmentFactsArtifactName = "alpine-3.23.environment-facts.json";

const alpine323ApkPackages = [
  "bash",
  "ca-certificates",
  "coreutils",
  "curl",
  "exiftool",
  "ffmpeg",
  "file",
  "findutils",
  "git",
  "imagemagick",
  "jq",
  "less",
  "nodejs-current",
  "npm",
  "openssh-client",
  "poppler-utils",
  "py3-pip",
  "python3",
  "ripgrep",
  "tar",
  "unzip",
  "xz",
  "zip",
] as const;

const alpine323GithubCliVersion = "2.83.0";

const alpine323CommandSources = [
  { kind: "apk", apkPackage: "bash", command: "bash" },
  { kind: "apk", apkPackage: "curl", command: "curl" },
  { kind: "apk", apkPackage: "git", command: "git" },
  { kind: "github-cli", version: alpine323GithubCliVersion, command: "gh" },
  { kind: "apk", apkPackage: "jq", command: "jq" },
  { kind: "apk", apkPackage: "nodejs-current", command: "node" },
  { kind: "apk", apkPackage: "npm", command: "npm" },
  { kind: "apk", apkPackage: "python3", command: "python3" },
  { kind: "apk", apkPackage: "py3-pip", command: "pip3" },
  { kind: "apk", apkPackage: "ripgrep", command: "rg" },
] as const satisfies readonly (
  | {
      readonly kind: "apk";
      readonly apkPackage: (typeof alpine323ApkPackages)[number];
      readonly command: SandboxEnvironmentCommand;
    }
  | {
      readonly kind: "github-cli";
      readonly version: string;
      readonly command: "gh";
    }
)[];

const alpine323ImageIdentityFacts = [
  {
    source: "config",
    topic: "rootfs-image",
    relation: "is",
    value: "alpine:3.23",
  },
  {
    source: "config",
    topic: "distro",
    relation: "is",
    value: "alpine",
  },
  {
    source: "config",
    topic: "distro-version",
    relation: "is",
    value: "3.23",
  },
  {
    source: "config",
    topic: "package-manager",
    relation: "is",
    value: "apk",
  },
  {
    source: "config",
    topic: "shell",
    relation: "is",
    value: "/bin/sh",
  },
] as const satisfies readonly SandboxEnvironmentFact[];

const alpine323CommandFacts: readonly SandboxCommandEnvironmentFact[] =
  alpine323CommandSources.map(({ command }) => configCommandFact(command));

const alpine323ImageFacts = [
  ...alpine323ImageIdentityFacts,
  ...alpine323CommandFacts,
] as const satisfies readonly SandboxEnvironmentFact[];

export function builtInRootfsApkPackages(
  name: BuiltInRootfsName,
): readonly string[] {
  switch (name) {
    case "alpine:3.23":
      return alpine323ApkPackages;
  }
}

export function builtInRootfsGithubCliVersion(
  name: BuiltInRootfsName,
): string {
  switch (name) {
    case "alpine:3.23":
      return alpine323GithubCliVersion;
  }
}

export function builtInRootfsEnvironmentFacts(
  name: BuiltInRootfsName,
): readonly SandboxEnvironmentFact[] {
  switch (name) {
    case "alpine:3.23":
      return alpine323ImageFacts;
  }
}

export function builtInRootfsEnvironmentIdentityFacts(
  name: BuiltInRootfsName,
): readonly SandboxEnvironmentFact[] {
  switch (name) {
    case "alpine:3.23":
      return alpine323ImageIdentityFacts;
  }
}

export function builtInRootfsEnvironmentCommandFacts(
  name: BuiltInRootfsName,
): readonly SandboxCommandEnvironmentFact[] {
  switch (name) {
    case "alpine:3.23":
      return alpine323CommandFacts;
  }
}

export function builtInRootfsEnvironmentFactsManifest(
  name: BuiltInRootfsName,
): RootfsEnvironmentFactsManifest {
  return {
    schemaVersion: 1,
    rootfs: name,
    facts: builtInRootfsEnvironmentFacts(name),
  };
}

function configCommandFact(
  value: SandboxEnvironmentCommand,
): SandboxCommandEnvironmentFact {
  return {
    source: "config",
    topic: "command",
    relation: "exists",
    value,
  };
}
