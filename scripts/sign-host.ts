import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

if (process.platform !== "darwin") {
  process.exit(0);
}

const artifactPath = resolve(import.meta.dirname, "../target/release/sandbox-host");
const entitlementsPath = resolve(import.meta.dirname, "../entitlements/macos-hvf.plist");

await access(artifactPath);
await execFileAsync("codesign", [
  "--force",
  "--sign",
  "-",
  "--entitlements",
  entitlementsPath,
  artifactPath,
]);
