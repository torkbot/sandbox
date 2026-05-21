#!/usr/bin/env node

import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { hostBinaryPath, rawHostBinaryPath } from "./artifacts.ts";

const execFileAsync = promisify(execFile);

const macosHypervisorEntitlements = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.hypervisor</key>
  <true/>
</dict>
</plist>
`;

const command = process.argv[2];

if (command === "setup-macos") {
  await setupMacos();
} else {
  console.error("usage: sandbox setup-macos");
  process.exit(2);
}

async function setupMacos(): Promise<void> {
  if (process.platform !== "darwin") {
    console.error("sandbox setup-macos is only needed on macOS.");
    return;
  }

  const hostPath = rawHostBinaryPath();
  const tempDir = await mkdtemp(join(tmpdir(), "torkbot-sandbox-entitlements-"));
  const entitlementsPath = join(tempDir, "macos-hvf.plist");

  try {
    await writeFile(entitlementsPath, macosHypervisorEntitlements);
    await execFileAsync("codesign", [
      "--force",
      "--sign",
      "-",
      "--entitlements",
      entitlementsPath,
      hostPath,
    ]);

    hostBinaryPath();
    console.log(`Signed sandbox-host for macOS Hypervisor.framework access: ${hostPath}`);
  } finally {
    await rm(tempDir, { recursive: true, force: true });
  }
}
