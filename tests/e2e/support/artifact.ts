import { execFile } from "node:child_process";
import { platform } from "node:os";
import { promisify } from "node:util";
import { nativeBindingPath } from "../../../src/native.ts";

const execFileAsync = promisify(execFile);

export interface ArtifactInspection {
  readonly staticLinkage: { readonly ok: boolean };
  readonly dynamicLibraries: readonly string[];
  readonly codesign: {
    readonly valid: boolean;
    readonly entitlements: Record<string, boolean>;
    readonly hostExecutableEntitlements: Record<string, boolean>;
    readonly hostExecutableHasRequiredEntitlements: boolean;
  };
}

export async function inspectNativeArtifact(input: {
  readonly forbiddenDynamicLibraries: readonly string[];
  readonly macosEntitlements: readonly string[];
}): Promise<ArtifactInspection> {
  const artifactPath = nativeBindingPath();
  const dynamicLibraries = await readDynamicLibraries(artifactPath);
  const codesignValid = platform() !== "darwin" || await validateCodesign(artifactPath);
  const entitlements = platform() === "darwin" ? await readCodesignEntitlements(artifactPath) : {};
  const hostExecutableEntitlements = platform() === "darwin"
    ? await readCodesignEntitlements(process.execPath)
    : {};
  const forbidden = input.forbiddenDynamicLibraries.some((pattern) =>
    dynamicLibraries.some((library) => library.includes(pattern))
  );
  const requiredHostEntitlementsPresent = input.macosEntitlements.every(
    (name) => hostExecutableEntitlements[name] === true,
  );

  return {
    staticLinkage: { ok: !forbidden },
    dynamicLibraries,
    codesign: {
      valid: codesignValid,
      entitlements,
      hostExecutableEntitlements,
      hostExecutableHasRequiredEntitlements: requiredHostEntitlementsPresent,
    },
  };
}

async function validateCodesign(artifactPath: string): Promise<boolean> {
  try {
    await execFileAsync("codesign", ["-v", artifactPath]);
    return true;
  } catch {
    return false;
  }
}

async function readDynamicLibraries(artifactPath: string): Promise<string[]> {
  if (platform() !== "darwin") {
    return [];
  }

  const { stdout } = await execFileAsync("otool", ["-L", artifactPath]);
  return stdout
    .split("\n")
    .slice(1)
    .map((line) => line.trim().split(/\s+/, 1)[0])
    .filter((library): library is string => library !== undefined && library.length > 0);
}

async function readCodesignEntitlements(
  artifactPath: string,
): Promise<Record<string, boolean>> {
  try {
    const { stdout, stderr } = await execFileAsync("codesign", [
      "-d",
      "--entitlements",
      ":-",
      artifactPath,
    ]);
    const output = `${stdout}\n${stderr}`;
    return Object.fromEntries(
      output
        .split("\n")
        .map((line) => line.trim().match(/^<key>(.+)<\/key>$/)?.[1])
        .filter((name): name is string => name !== undefined)
        .map((name) => [name, true] as const),
    );
  } catch {
    return {};
  }
}
