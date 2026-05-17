import type { TestContext } from "node:test";

export function requireVmLaunchSupport(t: TestContext): boolean {
  if (process.platform !== "darwin") {
    return true;
  }

  t.skip("macOS VM launch must route through signed sandbox-host, not the Node process");
  return false;
}
