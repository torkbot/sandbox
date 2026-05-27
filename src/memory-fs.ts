import type {
  MemoryFileSystemOptions,
  SandboxDirectoryEntry,
  SandboxFileStat,
  SandboxPosixFileSystem,
} from "./index.ts";

type MemoryNode =
  | {
      readonly type: "directory";
      readonly entries: Map<string, MemoryNode>;
      readonly writable: boolean;
    }
  | {
      readonly type: "file";
      contents: Uint8Array;
      readonly writable: boolean;
    }
  | {
      readonly type: "symlink";
      readonly target: string;
      readonly writable: boolean;
    };

type MemoryDirectory = Extract<MemoryNode, { type: "directory" }>;
type MemoryFile = Extract<MemoryNode, { type: "file" }>;

export function createMemoryFileSystem(options: MemoryFileSystemOptions = {}): SandboxPosixFileSystem {
  const root: MemoryDirectory = {
    type: "directory",
    entries: new Map(),
    writable: true,
  };
  const encoder = new TextEncoder();

  for (const [path, contents] of Object.entries(options.files ?? {})) {
    writeFileNode(path, typeof contents === "string" ? encoder.encode(contents) : contents);
  }

  return {
    async stat(path) {
      return nodeStat(lookup(path));
    },
    async list(path) {
      const node = lookup(path);
      if (node.type !== "directory") {
        throw new Error(`not a directory: ${path}`);
      }
      return Array.from(node.entries, ([name, child]): SandboxDirectoryEntry => ({
        name,
        type: child.type,
      }));
    },
    async read(input) {
      const node = lookup(input.path);
      if (node.type !== "file") {
        throw new Error(`not a file: ${input.path}`);
      }
      const offset = input.range?.offset ?? 0;
      const end = input.range === undefined ? node.contents.byteLength : offset + input.range.length;
      return node.contents.slice(offset, end);
    },
    async createFile(path) {
      writeFileNode(path, new Uint8Array());
      return nodeStat(lookup(path));
    },
    async write(input) {
      const node = ensureFile(input.path);
      const nextLength = Math.max(node.contents.byteLength, input.offset + input.contents.byteLength);
      const next = new Uint8Array(nextLength);
      next.set(node.contents);
      next.set(input.contents, input.offset);
      node.contents = next;
      return input.contents.byteLength;
    },
    async truncate(path, size) {
      const node = ensureFile(path);
      const next = new Uint8Array(size);
      next.set(node.contents.slice(0, size));
      node.contents = next;
      return nodeStat(node);
    },
    async mkdir(path) {
      const parent = ensureDirectory(parentPath(path));
      const name = baseName(path);
      const existing = parent.entries.get(name);
      if (existing !== undefined && existing.type !== "directory") {
        throw new Error(`path exists and is not a directory: ${path}`);
      }
      if (existing === undefined) {
        parent.entries.set(name, {
          type: "directory",
          entries: new Map(),
          writable: true,
        });
      }
      return nodeStat(parent.entries.get(name) ?? parent);
    },
    async unlink(path) {
      const parent = ensureDirectory(parentPath(path));
      const node = parent.entries.get(baseName(path));
      if (node === undefined) {
        throw new Error(`not found: ${path}`);
      }
      if (node.type === "directory") {
        throw new Error(`is a directory: ${path}`);
      }
      parent.entries.delete(baseName(path));
    },
    async rmdir(path) {
      const parent = ensureDirectory(parentPath(path));
      const node = parent.entries.get(baseName(path));
      if (node === undefined) {
        throw new Error(`not found: ${path}`);
      }
      if (node.type !== "directory") {
        throw new Error(`not a directory: ${path}`);
      }
      if (node.entries.size > 0) {
        throw new Error(`directory not empty: ${path}`);
      }
      parent.entries.delete(baseName(path));
    },
    async rename(from, to) {
      const fromParent = ensureDirectory(parentPath(from));
      const node = fromParent.entries.get(baseName(from));
      if (node === undefined) {
        throw new Error(`not found: ${from}`);
      }
      const toParent = ensureDirectory(parentPath(to));
      fromParent.entries.delete(baseName(from));
      toParent.entries.set(baseName(to), node);
    },
    async symlink(target, path) {
      const parent = ensureDirectory(parentPath(path));
      const node: MemoryNode = {
        type: "symlink",
        target,
        writable: true,
      };
      parent.entries.set(baseName(path), node);
      return nodeStat(node);
    },
    async readlink(path) {
      const node = lookup(path);
      if (node.type !== "symlink") {
        throw new Error(`not a symlink: ${path}`);
      }
      return node.target;
    },
  };

  function writeFileNode(path: string, contents: Uint8Array): void {
    const parent = ensureDirectory(parentPath(path));
    parent.entries.set(baseName(path), {
      type: "file",
      contents,
      writable: true,
    });
  }

  function ensureFile(path: string): MemoryFile {
    let node: MemoryNode;
    try {
      node = lookup(path);
    } catch {
      writeFileNode(path, new Uint8Array());
      node = lookup(path);
    }
    if (node.type !== "file") {
      throw new Error(`not a file: ${path}`);
    }
    return node;
  }

  function ensureDirectory(path: string): MemoryDirectory {
    if (path === "/") {
      return root;
    }
    const parent = ensureDirectory(parentPath(path));
    const name = baseName(path);
    const existing = parent.entries.get(name);
    if (existing === undefined) {
      const directory: MemoryNode = {
        type: "directory",
        entries: new Map(),
        writable: true,
      };
      parent.entries.set(name, directory);
      return directory;
    }
    if (existing.type !== "directory") {
      throw new Error(`not a directory: ${path}`);
    }
    return existing;
  }

  function lookup(path: string): MemoryNode {
    if (path === "/") {
      return root;
    }
    let node: MemoryNode = root;
    for (const component of pathComponents(path)) {
      if (node.type !== "directory") {
        throw new Error(`not a directory: ${path}`);
      }
      const child = node.entries.get(component);
      if (child === undefined) {
        throw new Error(`not found: ${path}`);
      }
      node = child;
    }
    return node;
  }
}

function nodeStat(node: MemoryNode): SandboxFileStat {
  return {
    type: node.type,
    sizeBytes: node.type === "file" ? node.contents.byteLength : null,
    mediaType: null,
    modifiedAtMs: null,
    writable: node.writable,
  };
}

function pathComponents(path: string): string[] {
  return path.split("/").filter((component) => component.length > 0);
}

function parentPath(path: string): string {
  const components = pathComponents(path);
  components.pop();
  return components.length === 0 ? "/" : `/${components.join("/")}`;
}

function baseName(path: string): string {
  const components = pathComponents(path);
  const name = components.at(-1);
  if (name === undefined) {
    throw new Error("path does not have a basename");
  }
  return name;
}
