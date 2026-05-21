import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";

const require = createRequire(import.meta.url);

type SandboxTarget = {
  readonly packageName: string;
  readonly hostBinaryName: string;
  readonly platform: NodeJS.Platform;
  readonly arch: NodeJS.Architecture;
  readonly libc?: "glibc";
};

const targets = [
  {
    packageName: "@torkbot/sandbox-darwin-arm64",
    hostBinaryName: "sandbox-host",
    platform: "darwin",
    arch: "arm64",
  },
  {
    packageName: "@torkbot/sandbox-linux-x64-gnu",
    hostBinaryName: "sandbox-host",
    platform: "linux",
    arch: "x64",
    libc: "glibc",
  },
] as const satisfies readonly SandboxTarget[];

export function currentSandboxTarget(): SandboxTarget {
  const target = targets.find((candidate) => {
    return candidate.platform === process.platform && candidate.arch === process.arch;
  });

  if (target === undefined) {
    throw new Error(
      `unsupported native sandbox target: ${process.platform}-${process.arch}`,
    );
  }

  return target;
}

export function hostBinaryPath(): string {
  const path = rawHostBinaryPath();
  assertMacosHostIsSigned(path);
  return path;
}

export function rawHostBinaryPath(): string {
  const target = currentSandboxTarget();
  return resolveArtifactPath(target, target.hostBinaryName);
}

function resolveArtifactPath(
  target: SandboxTarget,
  artifactName: string,
): string {
  try {
    return require.resolve(`${target.packageName}/${artifactName}`);
  } catch (error) {
    const installError = error instanceof Error ? error.message : String(error);
    throw new Error(
      `missing ${target.packageName} artifact ${artifactName}; reinstall @torkbot/sandbox for ${process.platform}-${process.arch}, or run npm run artifacts:link-current after building local artifacts. ${installError}`,
    );
  }
}

function assertMacosHostIsSigned(path: string): void {
  if (process.platform !== "darwin") {
    return;
  }

  let entitlements: string;
  try {
    entitlements = execFileSync("codesign", ["-d", "--entitlements", ":-", path], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(macosSigningError(path, detail));
  }

  if (!entitlements.includes("<key>com.apple.security.hypervisor</key>")) {
    throw new Error(macosSigningError(path, "missing com.apple.security.hypervisor entitlement"));
  }
}

function macosSigningError(path: string, detail: string): string {
  return [
    "sandbox-host is not signed for macOS Hypervisor.framework access.",
    "",
    "Run this once after installing @torkbot/sandbox:",
    "  npx @torkbot/sandbox setup-macos",
    "",
    `Artifact: ${path}`,
    `Reason: ${detail}`,
  ].join("\n");
}
