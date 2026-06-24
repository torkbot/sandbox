import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";

const require = createRequire(import.meta.url);

type SandboxTarget = {
  readonly packageName: string;
  readonly hostBinaryName: string;
  readonly platform: NodeJS.Platform;
  readonly arch: NodeJS.Architecture;
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
  return rawHostBinaryPath();
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

export function assertMacosHostIsSigned(path: string): void {
  if (process.platform !== "darwin") {
    return;
  }

  let entitlements: string;
  const result = spawnSync("codesign", ["-d", "--entitlements", ":-", path], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.error !== undefined) {
    throw new Error(macosSigningError(path, result.error.message));
  }

  if (result.status !== 0) {
    throw new Error(macosSigningError(path, `${result.stdout}\n${result.stderr}`.trim()));
  }

  entitlements = `${result.stdout}\n${result.stderr}`;
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

export function macosHostSigningError(path: string): Error | null {
  if (process.platform !== "darwin") {
    return null;
  }

  try {
    assertMacosHostIsSigned(path);
    return null;
  } catch (error) {
    return error instanceof Error ? error : new Error(String(error));
  }
}
