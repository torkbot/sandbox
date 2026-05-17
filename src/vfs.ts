import type { SandboxWritableFileSystem } from "./index.ts";

export function isSandboxWritableFileSystem(
  fileSystem: unknown,
): fileSystem is SandboxWritableFileSystem {
  return typeof fileSystem === "object"
    && fileSystem !== null
    && "createFile" in fileSystem
    && "write" in fileSystem
    && "truncate" in fileSystem;
}
