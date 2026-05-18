import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { promisify } from "node:util";
import { nativeBindingPath } from "../src/native.ts";

const execFileAsync = promisify(execFile);

if (process.platform !== "darwin") {
  process.exit(0);
}

const artifactPath = nativeBindingPath();

await access(artifactPath);
await execFileAsync("codesign", [
  "--force",
  "--sign",
  "-",
  artifactPath,
]);
