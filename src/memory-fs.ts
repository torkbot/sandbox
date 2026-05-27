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
      readonly xattrs: Map<string, Uint8Array>;
      readonly writable: boolean;
    }
  | {
      readonly type: "file";
      contents: Uint8Array;
      readonly xattrs: Map<string, Uint8Array>;
      readonly writable: boolean;
    }
  | {
      readonly type: "symlink";
      readonly target: string;
      readonly xattrs: Map<string, Uint8Array>;
      readonly writable: boolean;
    };

type MemoryDirectory = Extract<MemoryNode, { type: "directory" }>;
type MemoryFile = Extract<MemoryNode, { type: "file" }>;

export function createMemoryFileSystem(options: MemoryFileSystemOptions = {}): SandboxPosixFileSystem {
  const root: MemoryDirectory = {
    type: "directory",
    entries: new Map(),
    xattrs: new Map(),
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
      const parent = lookupDirectory(parentPath(path));
      const name = baseName(path);
      if (parent.entries.has(name)) {
        throw new Error(`path exists: ${path}`);
      }
      const node: MemoryNode = {
        type: "file",
        contents: new Uint8Array(),
        xattrs: new Map(),
        writable: true,
      };
      parent.entries.set(name, node);
      return nodeStat(node);
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
      const parent = lookupDirectory(parentPath(path));
      const name = baseName(path);
      const existing = parent.entries.get(name);
      if (existing !== undefined) {
        throw new Error(`path exists: ${path}`);
      }
      const node: MemoryNode = {
        type: "directory",
        entries: new Map(),
        xattrs: new Map(),
        writable: true,
      };
      parent.entries.set(name, node);
      return nodeStat(node);
    },
    async unlink(path) {
      const parent = lookupDirectory(parentPath(path));
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
      const parent = lookupDirectory(parentPath(path));
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
    async rename(from, to, flags = 0) {
      const supportedFlags = 1;
      if ((flags & ~supportedFlags) !== 0) {
        throw new Error(`unsupported rename flags: ${flags}`);
      }
      const fromParent = lookupDirectory(parentPath(from));
      const node = fromParent.entries.get(baseName(from));
      if (node === undefined) {
        throw new Error(`not found: ${from}`);
      }
      if (node.type === "directory" && isDescendantPath(from, to)) {
        throw new Error(`invalid rename target: ${to}`);
      }
      const toParent = lookupDirectory(parentPath(to));
      const destinationName = baseName(to);
      const existing = toParent.entries.get(destinationName);
      if (existing === node) {
        return;
      }
      if ((flags & 1) !== 0 && existing !== undefined) {
        throw new Error(`path exists: ${to}`);
      }
      if (existing !== undefined) {
        validateRenameReplacement(node, existing, to);
      }
      fromParent.entries.delete(baseName(from));
      toParent.entries.set(destinationName, node);
    },
    async link(from, to) {
      const node = lookup(from);
      if (node.type === "directory") {
        throw new Error(`cannot hard link directory: ${from}`);
      }
      const toParent = lookupDirectory(parentPath(to));
      if (toParent.entries.has(baseName(to))) {
        throw new Error(`path exists: ${to}`);
      }
      toParent.entries.set(baseName(to), node);
      return nodeStat(node);
    },
    async symlink(target, path) {
      const parent = lookupDirectory(parentPath(path));
      if (parent.entries.has(baseName(path))) {
        throw new Error(`path exists: ${path}`);
      }
      const node: MemoryNode = {
        type: "symlink",
        target,
        xattrs: new Map(),
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
    async setxattr(path, name, value, flags = 0) {
      const node = lookup(path);
      const exists = node.xattrs.has(name);
      if ((flags & 1) !== 0 && exists) {
        throw new Error(`xattr already exists: ${name}`);
      }
      if ((flags & 2) !== 0 && !exists) {
        throw new Error(`xattr does not exist: ${name}`);
      }
      node.xattrs.set(name, value.slice());
    },
    async getxattr(path, name) {
      const value = lookup(path).xattrs.get(name);
      if (value === undefined) {
        throw new Error(`xattr not found: ${name}`);
      }
      return value.slice();
    },
    async listxattr(path) {
      return Array.from(lookup(path).xattrs.keys());
    },
    async removexattr(path, name) {
      const removed = lookup(path).xattrs.delete(name);
      if (!removed) {
        throw new Error(`xattr not found: ${name}`);
      }
    },
  };

  function writeFileNode(path: string, contents: Uint8Array): void {
    const parent = ensureDirectory(parentPath(path));
    parent.entries.set(baseName(path), {
      type: "file",
      contents,
      xattrs: new Map(),
      writable: true,
    });
  }

  function ensureFile(path: string): MemoryFile {
    const node = lookup(path);
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
        xattrs: new Map(),
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

  function lookupDirectory(path: string): MemoryDirectory {
    const node = lookup(path);
    if (node.type !== "directory") {
      throw new Error(`not a directory: ${path}`);
    }
    return node;
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

function validateRenameReplacement(source: MemoryNode, destination: MemoryNode, path: string): void {
  if (source.type === "directory") {
    if (destination.type !== "directory") {
      throw new Error(`not a directory: ${path}`);
    }
    if (destination.entries.size > 0) {
      throw new Error(`directory not empty: ${path}`);
    }
    return;
  }

  if (destination.type === "directory") {
    throw new Error(`is a directory: ${path}`);
  }
}

function isDescendantPath(parent: string, child: string): boolean {
  if (parent === "/") {
    return child !== "/";
  }
  return child.startsWith(`${parent}/`);
}

function nodeStat(node: MemoryNode): SandboxFileStat {
  return {
    type: node.type,
    sizeBytes: node.type === "file"
      ? node.contents.byteLength
      : node.type === "symlink"
        ? new TextEncoder().encode(node.target).byteLength
        : null,
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
