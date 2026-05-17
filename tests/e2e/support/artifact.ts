import { execFile } from "node:child_process";
import { platform } from "node:os";
import { promisify } from "node:util";
import { nativeBindingPath } from "../../../src/native.ts";

const execFileAsync = promisify(execFile);

export interface ArtifactInspection {
  readonly vmHostPath: string;
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
  const vmHostPath = hostBinaryPath();
  const dynamicLibraries = [
    ...await readDynamicLibraries(artifactPath),
    ...await readDynamicLibraries(vmHostPath),
  ];
  const codesignValid = platform() !== "darwin" || await validateCodesign(vmHostPath);
  const entitlements = platform() === "darwin" ? await readCodesignEntitlements(vmHostPath) : {};
  const hostExecutableEntitlements = platform() === "darwin"
    ? entitlements
    : {};
  const forbidden = input.forbiddenDynamicLibraries.some((pattern) =>
    dynamicLibraries.some((library) => library.includes(pattern))
  );
  const requiredHostEntitlementsPresent = input.macosEntitlements.every(
    (name) => hostExecutableEntitlements[name] === true,
  );

  return {
    vmHostPath,
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

function hostBinaryPath(): string {
  return new URL("../../../target/release/sandbox-host", import.meta.url).pathname;
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
  if (platform() === "darwin") {
    const { stdout } = await execFileAsync("otool", ["-L", artifactPath]);
    return stdout
      .split("\n")
      .slice(1)
      .map((line) => line.trim().split(/\s+/, 1)[0])
      .filter((library): library is string => library !== undefined && library.length > 0);
  }

  if (platform() === "linux") {
    try {
      const { stdout } = await execFileAsync("ldd", [artifactPath]);
      return parseLddOutput(stdout);
    } catch (error) {
      const output = commandOutput(error);
      if (/not a dynamic executable|statically linked/i.test(output)) {
        return [];
      }
      throw error;
    }
  }

  return [];
}

function parseLddOutput(output: string): string[] {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) =>
      line.length > 0
      && !/not a dynamic executable|statically linked/i.test(line)
    )
    .map((line) => {
      const linked = line.match(/^\S+\s+=>\s+(\S+)/);
      if (linked?.[1] !== undefined && linked[1] !== "not") {
        return linked[1];
      }
      return line.split(/\s+/, 1)[0] ?? "";
    })
    .filter((library) => library.length > 0);
}

function commandOutput(error: unknown): string {
  if (typeof error !== "object" || error === null) {
    return "";
  }

  const stdout = "stdout" in error && typeof error.stdout === "string" ? error.stdout : "";
  const stderr = "stderr" in error && typeof error.stderr === "string" ? error.stderr : "";
  return `${stdout}\n${stderr}`;
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
      [...output.matchAll(/<key>([^<]+)<\/key>/g)]
        .map((match) => match[1])
        .filter((name): name is string => name !== undefined)
        .map((name) => [name, true] as const),
    );
  } catch {
    return {};
  }
}
