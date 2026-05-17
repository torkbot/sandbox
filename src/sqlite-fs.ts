import { posix } from "node:path";
import type {
  SandboxDirectoryEntry,
  SandboxFileStat,
  SandboxWritableFileSystem,
  SqliteFsDatabase,
  SqliteFsHandle,
  SqliteFsSnapshot,
} from "./index.ts";

type NodeRow = {
  readonly path: string;
  readonly type: "file" | "directory";
  readonly contents: Uint8Array | null;
  readonly updated_at_ms: number;
};

export class SqliteFsHandleImpl implements SqliteFsHandle {
  readonly #name: string;
  readonly #database: SqliteFsDatabase;
  #initialized: Promise<void> | null = null;

  constructor(input: {
    readonly name: string;
    readonly database: SqliteFsDatabase;
  }) {
    this.#name = input.name;
    this.#database = input.database;
  }

  async stat(path: string): Promise<SandboxFileStat> {
    const row = await this.#getNode(normalizePath(path));
    if (row === null) {
      throw new Error(`sqliteFs path not found: ${path}`);
    }

    return statFromRow(row);
  }

  async list(path: string): Promise<readonly SandboxDirectoryEntry[]> {
    const normalized = normalizePath(path);
    const row = await this.#getNode(normalized);
    if (row === null || row.type !== "directory") {
      throw new Error(`sqliteFs directory not found: ${path}`);
    }

    await this.#ensureInitialized();
    const prefix = normalized === "/" ? "/" : `${normalized}/`;
    const rows = await this.#database
      .prepare(`
        SELECT path, type
        FROM sandbox_sqlitefs_nodes
        WHERE mount_name = ? AND path != ? AND path LIKE ?
        ORDER BY path
      `)
      .all(this.#name, normalized, `${prefix}%`);

    return rows
      .map(assertNodeListRow)
      .filter((entry) => !entry.path.slice(prefix.length).includes("/"))
      .map((entry) => ({
        name: entry.path.slice(prefix.length),
        type: entry.type,
      }));
  }

  async read(input: {
    readonly path: string;
    readonly range?: {
      readonly offset: number;
      readonly length: number;
    };
    readonly signal: AbortSignal;
  }): Promise<Uint8Array> {
    input.signal.throwIfAborted();
    const row = await this.#getNode(normalizePath(input.path));
    if (row === null || row.type !== "file") {
      throw new Error(`sqliteFs file not found: ${input.path}`);
    }

    const contents = row.contents ?? new Uint8Array();
    if (input.range === undefined) {
      return contents;
    }

    return contents.slice(input.range.offset, input.range.offset + input.range.length);
  }

  async createFile(path: string): Promise<SandboxFileStat> {
    const normalized = normalizePath(path);
    await this.#ensureParentDirectory(normalized);
    await this.#ensureInitialized();
    const now = Date.now();
    await this.#database
      .prepare(`
        INSERT INTO sandbox_sqlitefs_nodes (mount_name, path, type, contents, updated_at_ms)
        VALUES (?, ?, 'file', ?, ?)
        ON CONFLICT(mount_name, path) DO UPDATE SET
          type = 'file',
          contents = excluded.contents,
          updated_at_ms = excluded.updated_at_ms
      `)
      .run(this.#name, normalized, new Uint8Array(), now);
    return {
      type: "file",
      sizeBytes: 0,
      mediaType: null,
      modifiedAtMs: now,
      writable: true,
    };
  }

  async write(input: {
    readonly path: string;
    readonly offset: number;
    readonly contents: Uint8Array;
  }): Promise<number> {
    const normalized = normalizePath(input.path);
    const row = await this.#getNode(normalized);
    if (row === null || row.type !== "file") {
      throw new Error(`sqliteFs file not found: ${input.path}`);
    }

    const previous = row.contents ?? new Uint8Array();
    const size = Math.max(previous.byteLength, input.offset + input.contents.byteLength);
    const next = new Uint8Array(size);
    next.set(previous);
    next.set(input.contents, input.offset);
    await this.#database
      .prepare(`
        UPDATE sandbox_sqlitefs_nodes
        SET contents = ?, updated_at_ms = ?
        WHERE mount_name = ? AND path = ? AND type = 'file'
      `)
      .run(this.#toBuffer(next), Date.now(), this.#name, normalized);
    return input.contents.byteLength;
  }

  async truncate(path: string, size: number): Promise<SandboxFileStat> {
    const normalized = normalizePath(path);
    const row = await this.#getNode(normalized);
    if (row === null || row.type !== "file") {
      throw new Error(`sqliteFs file not found: ${path}`);
    }

    const previous = row.contents ?? new Uint8Array();
    const next = new Uint8Array(size);
    next.set(previous.slice(0, size));
    const now = Date.now();
    await this.#database
      .prepare(`
        UPDATE sandbox_sqlitefs_nodes
        SET contents = ?, updated_at_ms = ?
        WHERE mount_name = ? AND path = ? AND type = 'file'
      `)
      .run(this.#toBuffer(next), now, this.#name, normalized);
    return {
      type: "file",
      sizeBytes: size,
      mediaType: null,
      modifiedAtMs: now,
      writable: true,
    };
  }

  async snapshot(): Promise<SqliteFsSnapshot> {
    await this.#ensureInitialized();
    const rows = await this.#database
      .prepare(`
        SELECT path, type, contents, updated_at_ms
        FROM sandbox_sqlitefs_nodes
        WHERE mount_name = ? AND type = 'file'
        ORDER BY path
      `)
      .all(this.#name);

    const files: SqliteFsSnapshot["files"] = {};
    for (const row of rows.map(assertNodeRow)) {
      files[row.path] = {
        type: "file",
        contents: Buffer.from(row.contents ?? new Uint8Array()).toString("utf8"),
      };
    }
    return { files };
  }

  async #getNode(path: string): Promise<NodeRow | null> {
    await this.#ensureInitialized();
    const row = await this.#database
      .prepare(`
        SELECT path, type, contents, updated_at_ms
        FROM sandbox_sqlitefs_nodes
        WHERE mount_name = ? AND path = ?
      `)
      .get(this.#name, path);
    return row === undefined ? null : assertNodeRow(row);
  }

  async #ensureParentDirectory(path: string): Promise<void> {
    const parent = posix.dirname(path);
    const row = await this.#getNode(parent === "." ? "/" : parent);
    if (row === null || row.type !== "directory") {
      throw new Error(`sqliteFs parent directory not found: ${path}`);
    }
  }

  async #ensureInitialized(): Promise<void> {
    this.#initialized ??= this.#initialize();
    await this.#initialized;
  }

  async #initialize(): Promise<void> {
    if (!this.#database.open) {
      throw new Error("sqliteFs database handle is not open");
    }

    await this.#database.exec(`
      CREATE TABLE IF NOT EXISTS sandbox_sqlitefs_nodes (
        mount_name TEXT NOT NULL,
        path TEXT NOT NULL,
        type TEXT NOT NULL CHECK (type IN ('file', 'directory')),
        contents BLOB,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY (mount_name, path)
      );
    `);
    await this.#database
      .prepare(`
        INSERT OR IGNORE INTO sandbox_sqlitefs_nodes
          (mount_name, path, type, contents, updated_at_ms)
        VALUES (?, '/', 'directory', NULL, ?)
      `)
      .run(this.#name, Date.now());
  }

  #toBuffer(contents: Uint8Array): Uint8Array {
    return Buffer.from(contents);
  }
}

export function isSandboxWritableFileSystem(
  fileSystem: unknown,
): fileSystem is SandboxWritableFileSystem {
  return typeof fileSystem === "object"
    && fileSystem !== null
    && "createFile" in fileSystem
    && "write" in fileSystem
    && "truncate" in fileSystem;
}

function normalizePath(path: string): string {
  if (!path.startsWith("/")) {
    throw new Error(`sqliteFs path must be absolute: ${path}`);
  }
  const normalized = posix.normalize(path);
  return normalized === "." ? "/" : normalized;
}

function statFromRow(row: NodeRow): SandboxFileStat {
  return {
    type: row.type,
    sizeBytes: row.type === "file" ? row.contents?.byteLength ?? 0 : null,
    mediaType: null,
    modifiedAtMs: row.updated_at_ms,
    writable: true,
  };
}

function assertNodeListRow(value: unknown): Pick<NodeRow, "path" | "type"> {
  if (typeof value !== "object" || value === null) {
    throw new Error("sqliteFs row must be an object");
  }
  const row = value as Record<string, unknown>;
  const path = assertString(row.path, "path");
  const type = assertNodeType(row.type);
  return { path, type };
}

function assertNodeRow(value: unknown): NodeRow {
  if (typeof value !== "object" || value === null) {
    throw new Error("sqliteFs row must be an object");
  }
  const row = value as Record<string, unknown>;
  const path = assertString(row.path, "path");
  const type = assertNodeType(row.type);
  const contents = row.contents === null ? null : assertBytes(row.contents, "contents");
  const updatedAtMs = assertNumber(row.updated_at_ms, "updated_at_ms");
  return {
    path,
    type,
    contents,
    updated_at_ms: updatedAtMs,
  };
}

function assertNodeType(value: unknown): "file" | "directory" {
  if (value === "file" || value === "directory") {
    return value;
  }
  throw new Error(`sqliteFs row has invalid type: ${String(value)}`);
}

function assertString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new Error(`sqliteFs ${field} must be a string`);
  }
  return value;
}

function assertNumber(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new Error(`sqliteFs ${field} must be an integer`);
  }
  return value;
}

function assertBytes(value: unknown, field: string): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  throw new Error(`sqliteFs ${field} must be bytes`);
}
