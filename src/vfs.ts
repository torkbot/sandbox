import type {
  SandboxPosixFileSystem,
  SandboxWritableFileSystem,
} from "./index.ts";

export function isSandboxWritableFileSystem(
  fileSystem: unknown,
): fileSystem is SandboxWritableFileSystem {
  return typeof fileSystem === "object"
    && fileSystem !== null
    && "createFile" in fileSystem
    && "write" in fileSystem
    && "truncate" in fileSystem;
}

export function isSandboxPosixFileSystem(
  fileSystem: unknown,
): fileSystem is SandboxPosixFileSystem {
  return isSandboxWritableFileSystem(fileSystem)
    && "mkdir" in fileSystem
    && "unlink" in fileSystem
    && "rmdir" in fileSystem
    && "rename" in fileSystem
    && "link" in fileSystem
    && "symlink" in fileSystem
    && "readlink" in fileSystem
    && "setxattr" in fileSystem
    && "getxattr" in fileSystem
    && "listxattr" in fileSystem
    && "removexattr" in fileSystem;
}
