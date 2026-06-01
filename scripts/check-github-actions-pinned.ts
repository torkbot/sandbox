import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const workflowDir = ".github/workflows";
const mutableRefs: string[] = [];
const shaRef = /^[0-9a-f]{40}$/;

for (const file of await readdir(workflowDir)) {
  if (!file.endsWith(".yml") && !file.endsWith(".yaml")) {
    continue;
  }
  const path = join(workflowDir, file);
  const lines = (await readFile(path, "utf8")).split("\n");
  lines.forEach((line, index) => {
    const match = line.match(/^\s*uses:\s+([^@\s]+)@([^#\s]+)/);
    if (match === null) {
      return;
    }
    const action = match[1];
    const ref = match[2];
    if (action === undefined || ref === undefined) {
      throw new Error(`failed to parse workflow action ref at ${path}:${index + 1}`);
    }
    if (action.startsWith("./") || shaRef.test(ref)) {
      return;
    }
    mutableRefs.push(`${path}:${index + 1}: ${action}@${ref}`);
  });
}

if (mutableRefs.length > 0) {
  throw new Error(`workflow action refs must be pinned to full commit SHAs:\n${mutableRefs.join("\n")}`);
}
