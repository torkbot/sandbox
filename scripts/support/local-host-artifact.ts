import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { resolve } from "node:path";
import { assertMacosHostIsSigned } from "../../src/artifacts.ts";
import { hostBinaryPath } from "../../src/host-process.ts";

const execFileAsync = promisify(execFile);

export async function ensureLocalSandboxHost(input: {
  readonly repoRoot: string;
  readonly consumer: string;
}): Promise<string> {
  const hostPath = hostBinaryPath();
  if (process.platform !== "darwin") {
    return hostPath;
  }

  try {
    assertMacosHostIsSigned(hostPath);
    return hostPath;
  } catch {
    process.stderr.write(`Signing sandbox-host for ${input.consumer}: ${hostPath}\n`);
  }

  await execFileAsync("codesign", [
    "--force",
    "--sign",
    "-",
    "--entitlements",
    resolve(input.repoRoot, "entitlements/macos-hvf.plist"),
    hostPath,
  ]);
  assertMacosHostIsSigned(hostPath);
  return hostPath;
}
