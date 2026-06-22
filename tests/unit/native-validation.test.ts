import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  defineSandbox,
  fs,
  rootfs,
  type SandboxBlockStore,
  type SandboxFileSystem,
  type SandboxWritableFileSystem,
} from "../../src/index.ts";

test("defineSandbox rejects non-built-in rootfs objects", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: { kind: "prebuilt-rootfs", path: "rootfs.qcow2", format: "qcow2" } as never,
    }),
    /invalid sandbox definition: rootfs must be created with rootfs\.builtIn\(\.\.\.\), rootfs\.ephemeral\(\.\.\.\), or rootfs\.cow\(\.\.\.\)/,
  );
});

test("defineSandbox rejects unsupported built-in rootfs names", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: { kind: "built-in-rootfs", name: "debian:13" } as never,
    }),
    /unsupported built-in rootfs: debian:13/,
  );
});

test("defineSandbox rejects invalid COW rootfs", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: { kind: "cow-rootfs", base: { kind: "other-rootfs" }, writable: memoryBlockStore() } as never,
    }),
    /invalid sandbox definition: rootfs.cow source must be created with rootfs\.compose\(\.\.\.\)/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: {
        kind: "cow-rootfs",
        source: {
          kind: "composed-rootfs",
          base: { kind: "other-rootfs" },
          overlay: memoryBlockStore(),
        },
      } as never,
    }),
    /invalid sandbox definition: rootfs.cow base must be created with rootfs\.builtIn\(\.\.\.\)/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.cow({
        base: rootfs.builtIn("alpine:3.23"),
        writable: {
          ...memoryBlockStore(),
          blockSize: 0,
        },
      }),
    }),
    /invalid sandbox definition: rootfs COW block size must be a positive integer/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.cow({
        base: rootfs.builtIn("alpine:3.23"),
        writable: memoryBlockStore(),
        maxDirtyBytes: 1024,
      }),
    }),
    /invalid sandbox definition: rootfs COW maxDirtyBytes must be at least the COW block size/,
  );
});

test("defineSandbox rejects invalid ephemeral rootfs", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.ephemeral({
        // @ts-expect-error invalid rootfs object exercises runtime validation.
        base: { kind: "built-in-rootfs", name: "ubuntu:latest" },
      }),
    }),
    /unsupported built-in rootfs: ubuntu:latest/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.ephemeral({
        base: rootfs.builtIn("alpine:3.23"),
        maxDirtyBytes: 1024,
      }),
    }),
    /invalid sandbox definition: ephemeral rootfs maxDirtyBytes must be at least the COW block size/,
  );
});

test("defineSandbox rejects invalid resource limits", () => {
  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.23"),
      resources: { cpus: 0 },
    }),
    /invalid sandbox definition: resources\.cpus must be a positive integer/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.23"),
      resources: { cpus: 256 },
    }),
    /invalid sandbox definition: resources\.cpus must be less than or equal to 255/,
  );

  assert.throws(
    () => defineSandbox({
      rootfs: rootfs.builtIn("alpine:3.23"),
      resources: { memoryMiB: 0 },
    }),
    /invalid sandbox definition: resources\.memoryMiB must be a positive integer/,
  );
});

test("boot rejects relative mount paths before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        workspace: fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must be absolute/,
  );
});

test("boot rejects root and dot-component mount paths before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not be root/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/tmp/../proc": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not contain '\.' or '\.\.' components/,
  );
});

test("boot rejects mount paths with NUL bytes before runtime launch", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/bad\0path": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox options: mount\.path must not contain NUL bytes/,
  );
});

test("boot rejects writable mounts without POSIX filesystem support", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.virtual(writableFileSystem()),
      },
    }),
    /invalid sandbox boot options: writable mount must implement the POSIX filesystem interface: \/mnt/,
  );
});

test("boot rejects host directory mounts without absolute sources", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({ source: "workspace", access: "ro" }),
      },
    }),
    /invalid sandbox boot options: host directory source must be absolute/,
  );
});

test("boot rejects host directory mounts without explicit access", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({ source: "/tmp/workspace", access: "inherit" as "ro" }),
      },
    }),
    /invalid sandbox boot options: host directory access must be 'ro' or 'rw'/,
  );
});

test("boot rejects invalid host directory mask paths", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "ro",
          mask: {
            paths: ["node_modules"],
          },
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask path must be absolute/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "ro",
          mask: {
            paths: ["/"],
          },
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask path must not be root/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "ro",
          mask: {
            paths: ["/node_modules/"],
          },
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask path must not contain empty components/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "ro",
          mask: {
            paths: ["/node_modules", "/node_modules/.bin"],
          },
        }),
      },
    }),
    /invalid sandbox boot options: nested host directory mask path: \/node_modules\/\.bin/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "ro",
          mask: {
            paths: ["/node_modules/.bin", "/node_modules"],
          },
        }),
      },
    }),
    /invalid sandbox boot options: nested host directory mask path: \/node_modules/,
  );
});

test("boot requires writable mask storage for writable host directory masks", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "rw",
          mask: {
            paths: ["/node_modules"],
          } as never,
        }),
      },
    }),
    /invalid sandbox boot options: writable host directory masks require mask.storage/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "rw",
          mask: {
            paths: ["/node_modules"],
            storage: fs.bind({
              source: "/tmp/mask-storage",
              access: "ro",
            }),
          } as never,
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask storage access must be 'rw'/,
  );
});

test("boot rejects writable mask storage that resolves inside the bind source", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "rw",
          mask: {
            paths: ["/node_modules"],
            storage: fs.bind({
              source: "/tmp/workspace/.",
              access: "rw",
            }),
          },
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask storage source must not be inside the bind source/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "rw",
          mask: {
            paths: ["/node_modules"],
            storage: fs.bind({
              source: "/tmp/workspace/.sandbox-mask",
              access: "rw",
            }),
          },
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask storage source must not be inside the bind source/,
  );

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "rw",
          mask: {
            paths: ["/workspace"],
            storage: fs.bind({
              source: "/tmp",
              access: "rw",
            }),
          },
        }),
      },
    }),
    /invalid sandbox boot options: host directory mask storage entries must not resolve inside the bind source/,
  );

  const source = await mkdtemp(join(tmpdir(), "sandbox-mask-source-"));
  const sourceLink = `${source}-link`;
  await symlink(source, sourceLink);
  try {
    await assert.rejects(
      sandbox.boot({
        mounts: {
          "/mnt": fs.bind({
            source,
            access: "rw",
            mask: {
              paths: ["/node_modules"],
              storage: fs.bind({
                source: sourceLink,
                access: "rw",
              }),
            },
          }),
        },
      }),
      /invalid sandbox boot options: host directory mask storage source must not be inside the bind source/,
    );
  } finally {
    await rm(sourceLink, { force: true });
    await rm(source, { recursive: true, force: true });
  }
});

test("boot rejects mask storage on read-only host directory masks", async () => {
  const sandbox = defineSandbox({
    rootfs: rootfs.builtIn("alpine:3.23"),
  });

  await assert.rejects(
    sandbox.boot({
      mounts: {
        "/mnt": fs.bind({
          source: "/tmp/workspace",
          access: "ro",
          mask: {
            paths: ["/node_modules"],
            storage: fs.bind({
              source: "/tmp/mask-storage",
              access: "rw",
            }),
          } as never,
        }),
      },
    }),
    /invalid sandbox boot options: read-only host directory masks must not declare mask.storage/,
  );
});

function readOnlyFileSystem(): SandboxFileSystem {
  return {
    async stat() {
      throw new Error("not reached");
    },
    async list() {
      throw new Error("not reached");
    },
    async read() {
      throw new Error("not reached");
    },
  };
}

function writableFileSystem(): SandboxWritableFileSystem {
  return {
    ...readOnlyFileSystem(),
    async createFile() {
      throw new Error("not reached");
    },
    async write() {
      throw new Error("not reached");
    },
    async truncate() {
      throw new Error("not reached");
    },
  };
}

function memoryBlockStore(): SandboxBlockStore {
  return {
    blockSize: 4096,
    async list() {
      return [];
    },
    async read() {
      return [];
    },
    async write() {
    },
  };
}
