import { posix } from "node:path";
import {
  Bash,
  type CpOptions,
  type FileContent,
  type FsStat,
  type IFileSystem,
  type MkdirOptions,
  type RmOptions,
} from "just-bash";
import { isSandboxWritableFileSystem } from "./vfs.ts";
import type {
  SandboxFileStat,
  SandboxFileSystem,
  SandboxHostBashResult,
  SandboxHostFileSystemTools,
  SandboxHostPatchEdit,
  SandboxHostReadResult,
  SandboxPosixFileSystem,
  SandboxWritableFileSystem,
} from "./index.ts";

export function createSandboxHostFileSystemTools(
  fileSystem: SandboxFileSystem,
): SandboxHostFileSystemTools {
  return new MountedHostFileSystemTools(fileSystem);
}

class MountedHostFileSystemTools implements SandboxHostFileSystemTools {
  readonly #fileSystem: SandboxFileSystem;

  constructor(fileSystem: SandboxFileSystem) {
    this.#fileSystem = fileSystem;
  }

  async read(input: {
    readonly path: string;
    readonly offset?: number;
    readonly limit?: number;
    readonly signal?: AbortSignal;
  }): Promise<SandboxHostReadResult> {
    const path = normalizeMountedPath(input.path);
    const content = await this.#readWholeText(path, input.signal);
    const lines = content.split("\n");
    const startLine = Math.max(1, input.offset ?? 1);
    const limit = Math.max(1, input.limit ?? 2_000);
    const selected = lines.slice(startLine - 1, startLine - 1 + limit);

    return {
      path,
      content: selected.join("\n"),
      totalLines: lines.length,
      truncated: startLine > 1 || selected.length < lines.length,
    };
  }

  async write(input: {
    readonly path: string;
    readonly content: string;
    readonly signal?: AbortSignal;
  }): Promise<void> {
    const path = normalizeMountedPath(input.path);
    const fileSystem = this.#assertWritable();
    const contents = Buffer.from(input.content, "utf8");

    try {
      await this.#fileSystem.stat(path);
    } catch {
      await fileSystem.createFile(path);
    }

    await fileSystem.truncate(path, 0);
    const written = await fileSystem.write({
      path,
      offset: 0,
      contents,
    });
    if (written !== contents.byteLength) {
      throw new Error(`short host filesystem write to ${path}: ${written} of ${contents.byteLength} bytes`);
    }
  }

  async patch(input: {
    readonly path: string;
    readonly edits: readonly SandboxHostPatchEdit[];
    readonly signal?: AbortSignal;
  }): Promise<void> {
    const path = normalizeMountedPath(input.path);
    let content = (await this.read({
      path,
      signal: input.signal,
      limit: Number.MAX_SAFE_INTEGER,
    })).content;

    for (const edit of input.edits) {
      const first = content.indexOf(edit.oldText);
      if (first === -1) {
        throw new Error(`oldText not found in ${path}`);
      }
      if (content.indexOf(edit.oldText, first + edit.oldText.length) !== -1) {
        throw new Error(`oldText is not unique in ${path}`);
      }
      content =
        content.slice(0, first) +
        edit.newText +
        content.slice(first + edit.oldText.length);
    }

    await this.write({
      path,
      content,
      signal: input.signal,
    });
  }

  async bash(input: {
    readonly command: string;
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
  }): Promise<SandboxHostBashResult> {
    const abortController = new AbortController();
    const timeout = input.timeoutMs === undefined
      ? undefined
      : setTimeout(() => {
          abortController.abort(new Error(`bash timeout after ${input.timeoutMs}ms`));
        }, input.timeoutMs);
    const onAbort = () => {
      abortController.abort(input.signal?.reason);
    };

    try {
      if (input.signal?.aborted) {
        abortController.abort(input.signal.reason);
      } else {
        input.signal?.addEventListener("abort", onAbort, { once: true });
      }

      const bash = new Bash({
        fs: new JustBashMountedFileSystem(this.#fileSystem),
        cwd: "/",
        env: {
          HOME: "/",
          PWD: "/",
        },
      });
      const result = await bash.exec(input.command, {
        cwd: "/",
        signal: abortController.signal,
      });
      return {
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.exitCode,
      };
    } finally {
      if (timeout !== undefined) {
        clearTimeout(timeout);
      }
      input.signal?.removeEventListener("abort", onAbort);
    }
  }

  async #readWholeText(path: string, signal?: AbortSignal): Promise<string> {
    const stat = await this.#fileSystem.stat(path);
    if (stat.type !== "file") {
      throw new Error(`host filesystem path is not a file: ${path}`);
    }
    if (stat.sizeBytes === null) {
      throw new Error(`host filesystem file has unknown size: ${path}`);
    }
    const bytes = await this.#fileSystem.read({
      path,
      range: {
        offset: 0,
        length: stat.sizeBytes,
      },
      signal: signal ?? AbortSignal.timeout(30_000),
    });
    return Buffer.from(bytes).toString("utf8");
  }

  #assertWritable(): SandboxWritableFileSystem {
    if (!isSandboxWritableFileSystem(this.#fileSystem)) {
      throw new Error("host filesystem mount is read-only");
    }
    return this.#fileSystem;
  }
}

function normalizeMountedPath(path: string): string {
  if (path.length === 0) {
    throw new Error("host filesystem path must not be empty");
  }
  return path.startsWith("/") ? path : `/${path}`;
}

class JustBashMountedFileSystem implements IFileSystem {
  readonly #fileSystem: SandboxFileSystem;

  constructor(fileSystem: SandboxFileSystem) {
    this.#fileSystem = fileSystem;
  }

  async readFile(path: string): Promise<string> {
    return Buffer.from(await this.readFileBuffer(path)).toString("utf8");
  }

  async readFileBuffer(path: string): Promise<Uint8Array> {
    const normalized = normalizeMountedPath(path);
    const stat = await this.#fileSystem.stat(normalized);
    if (stat.type !== "file") {
      throw new Error(`not a file: ${path}`);
    }
    if (stat.sizeBytes === null) {
      throw new Error(`file has unknown size: ${path}`);
    }
    return await this.#fileSystem.read({
      path: normalized,
      range: {
        offset: 0,
        length: stat.sizeBytes,
      },
      signal: AbortSignal.timeout(30_000),
    });
  }

  async writeFile(path: string, content: FileContent): Promise<void> {
    const normalized = normalizeMountedPath(path);
    const fileSystem = this.#assertWritable();
    const bytes = typeof content === "string"
      ? Buffer.from(content, "utf8")
      : content;

    try {
      await this.#fileSystem.stat(normalized);
    } catch {
      await fileSystem.createFile(normalized);
    }

    await fileSystem.truncate(normalized, 0);
    const written = await fileSystem.write({
      path: normalized,
      offset: 0,
      contents: bytes,
    });
    if (written !== bytes.byteLength) {
      throw new Error(`short write to ${normalized}`);
    }
  }

  async appendFile(path: string, content: FileContent): Promise<void> {
    const normalized = normalizeMountedPath(path);
    const fileSystem = this.#assertWritable();
    const bytes = typeof content === "string"
      ? Buffer.from(content, "utf8")
      : content;
    let offset = 0;

    try {
      const stat = await this.#fileSystem.stat(normalized);
      if (stat.type !== "file") {
        throw new Error(`not a file: ${path}`);
      }
      offset = stat.sizeBytes ?? 0;
    } catch {
      await fileSystem.createFile(normalized);
    }

    const written = await fileSystem.write({
      path: normalized,
      offset,
      contents: bytes,
    });
    if (written !== bytes.byteLength) {
      throw new Error(`short append to ${normalized}`);
    }
  }

  async exists(path: string): Promise<boolean> {
    try {
      await this.#fileSystem.stat(normalizeMountedPath(path));
      return true;
    } catch {
      return false;
    }
  }

  async stat(path: string): Promise<FsStat> {
    return toJustBashStat(await this.#fileSystem.stat(normalizeMountedPath(path)));
  }

  async mkdir(path: string, options?: MkdirOptions): Promise<void> {
    const normalized = normalizeMountedPath(path);
    if (normalized === "/" || (options?.recursive === true && path === ".")) {
      return;
    }
    const fileSystem = this.#assertPosix();
    if (options?.recursive === true) {
      let current = "";
      for (const component of normalized.split("/").filter((part) => part.length > 0)) {
        current = `${current}/${component}`;
        let stat: SandboxFileStat | null = null;
        try {
          stat = await this.#fileSystem.stat(current);
        } catch {
          await fileSystem.mkdir(current);
          continue;
        }
        if (stat.type !== "directory") {
          throw new Error(`not a directory: ${current}`);
        }
      }
      return;
    }
    await fileSystem.mkdir(normalized);
  }

  async readdir(path: string): Promise<string[]> {
    return (await this.#fileSystem.list(normalizeMountedPath(path))).map((entry) => entry.name);
  }

  async readdirWithFileTypes(path: string): Promise<
    {
      name: string;
      isFile: boolean;
      isDirectory: boolean;
      isSymbolicLink: boolean;
    }[]
  > {
    return (await this.#fileSystem.list(normalizeMountedPath(path))).map((entry) => ({
      name: entry.name,
      isFile: entry.type === "file",
      isDirectory: entry.type === "directory",
      isSymbolicLink: entry.type === "symlink",
    }));
  }

  async rm(path: string, _options?: RmOptions): Promise<void> {
    throw new Error(`rm is not supported by this sandbox filesystem: ${path}`);
  }

  async cp(_src: string, _dest: string, _options?: CpOptions): Promise<void> {
    throw new Error("cp is not supported by this sandbox filesystem");
  }

  async mv(_src: string, _dest: string): Promise<void> {
    throw new Error("mv is not supported by this sandbox filesystem");
  }

  resolvePath(base: string, path: string): string {
    return normalizeMountedPath(posix.resolve(base, path));
  }

  getAllPaths(): string[] {
    return [];
  }

  async chmod(path: string, _mode: number): Promise<void> {
    await this.#fileSystem.stat(normalizeMountedPath(path));
  }

  async symlink(): Promise<void> {
    throw new Error("symlink is not supported by this sandbox filesystem");
  }

  async link(): Promise<void> {
    throw new Error("link is not supported by this sandbox filesystem");
  }

  async readlink(path: string): Promise<string> {
    throw new Error(`not a symbolic link: ${path}`);
  }

  async lstat(path: string): Promise<FsStat> {
    return await this.stat(path);
  }

  async realpath(path: string): Promise<string> {
    const normalized = normalizeMountedPath(path);
    await this.#fileSystem.stat(normalized);
    return normalized;
  }

  async utimes(path: string): Promise<void> {
    await this.#fileSystem.stat(normalizeMountedPath(path));
  }

  #assertWritable(): SandboxWritableFileSystem {
    if (!isSandboxWritableFileSystem(this.#fileSystem)) {
      throw new Error("host filesystem mount is read-only");
    }
    return this.#fileSystem;
  }

  #assertPosix(): SandboxPosixFileSystem {
    const candidate = this.#assertWritable() as Partial<SandboxPosixFileSystem>;
    if (typeof candidate.mkdir !== "function") {
      throw new Error("mkdir is not supported by this sandbox filesystem");
    }
    return candidate as SandboxPosixFileSystem;
  }
}

function toJustBashStat(stat: SandboxFileStat): FsStat {
  return {
    isFile: stat.type === "file",
    isDirectory: stat.type === "directory",
    isSymbolicLink: false,
    mode: stat.writable === true ? 0o666 : 0o444,
    size: stat.sizeBytes ?? 0,
    mtime: stat.modifiedAtMs === null ? new Date(0) : new Date(stat.modifiedAtMs),
  };
}
