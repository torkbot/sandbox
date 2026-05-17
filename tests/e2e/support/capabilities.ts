import type { TestContext } from "node:test";

export function requireVmLaunchSupport(): boolean {
  return true;
}

export function skipUntilImplemented(t: TestContext, feature: string): boolean {
  t.skip(`${feature} is not implemented through sandbox-host yet`);
  return false;
}
