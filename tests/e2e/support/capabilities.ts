import type { TestContext } from "node:test";
import { existsSync } from "node:fs";
import { hostBinaryPath } from "../../../src/host-process.ts";

export function requireVmLaunchSupport(t: TestContext): boolean {
  let hostPath: string;
  try {
    hostPath = hostBinaryPath();
  } catch (error) {
    t.skip(error instanceof Error ? error.message : "sandbox-host is not built");
    return false;
  }

  if (process.platform === "linux" && !existsSync("/dev/kvm")) {
    t.skip("Linux KVM is not available on this host");
    return false;
  }

  if (process.platform !== "darwin" && process.platform !== "linux") {
    t.skip(`unsupported VM launch host platform: ${process.platform}`);
    return false;
  }

  void hostPath;
  return true;
}

export function skipUntilImplemented(t: TestContext, feature: string): boolean {
  t.skip(`${feature} is not implemented through sandbox-host yet`);
  return false;
}

export function requireHostArtifact(t: TestContext): boolean {
  try {
    hostBinaryPath();
    return true;
  } catch (error) {
    t.skip(error instanceof Error ? error.message : "sandbox-host is not built");
    return false;
  }
}
