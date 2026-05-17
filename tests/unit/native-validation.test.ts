import test from "node:test";
import assert from "node:assert/strict";
import {
  binding,
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  virtualFsMount,
} from "../../src/index.ts";

test("spawnSandbox rejects invalid CPU config before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      cpu: { vcpus: 0 },
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
    }),
    /invalid spawnSandbox options: cpu\.vcpus must be greater than zero/,
  );
});

test("spawnSandbox rejects directory rootfs before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20", {
        format: "directory",
      }),
    }),
    /invalid spawnSandbox options: directory rootfs is not supported for sandboxed VM launch; use an EROFS rootfs/,
  );
});

test("spawnSandbox rejects relative mount paths before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        {
          kind: "virtual-fs",
          path: "sandbox",
          fileSystem: {
            async stat() {
              throw new Error("not reached");
            },
            async list() {
              throw new Error("not reached");
            },
            async read() {
              throw new Error("not reached");
            },
          },
        },
      ],
    }),
    /invalid spawnSandbox options: mount\.path must be absolute/,
  );
});

test("spawnSandbox rejects duplicate mount paths before runtime launch", async () => {
  const fileSystem = {
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

  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        { kind: "virtual-fs", path: "/sandbox", fileSystem },
        { kind: "virtual-fs", path: "/sandbox", fileSystem },
      ],
    }),
    /invalid spawnSandbox options: duplicate mount path: \/sandbox/,
  );
});

test("spawnSandbox rejects mount paths that cannot be encoded for guest init", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        virtualFsMount("/bad=path", {
          async stat() {
            return {
              type: "directory",
              sizeBytes: null,
              mediaType: null,
              modifiedAtMs: null,
            };
          },
          async list() {
            return [];
          },
          async read() {
            return new Uint8Array();
          },
        }),
      ],
    }),
    /invalid spawnSandbox options: mount\.path must not contain '=' or ';'/,
  );
});

test("spawnSandbox rejects relative binding paths before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      bindings: [
        binding("workspace", unreachableFileSystem()),
      ],
    }),
    /invalid spawnSandbox options: binding\.path must be absolute/,
  );
});

test("spawnSandbox rejects duplicate binding paths before runtime launch", async () => {
  const fileSystem = unreachableFileSystem();

  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      bindings: [
        binding("/workspace", fileSystem),
        binding("/workspace", fileSystem),
      ],
    }),
    /invalid spawnSandbox options: duplicate binding path: \/workspace/,
  );
});

test("spawnSandbox rejects binding paths that conflict with guest mounts", async () => {
  const fileSystem = unreachableFileSystem();

  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        virtualFsMount("/workspace", fileSystem),
      ],
      bindings: [
        binding("/workspace", fileSystem),
      ],
    }),
    /invalid spawnSandbox options: binding path conflicts with mount path: \/workspace/,
  );
});

test("spawnSandbox rejects unsupported init crates before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: {
        kind: "project-init",
        crate: "other-init" as "sandbox-init",
      },
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
    }),
    /invalid spawnSandbox options: unsupported init crate: other-init/,
  );
});

test("spawnSandbox rejects invalid protected CIDR ranges before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      network: {
        http: {
          protectedRanges: ["127.0.0.0/33"],
          async policy() {
            return { action: "allow" };
          },
        },
      },
    }),
    /invalid spawnSandbox options: invalid CIDR prefix: 127\.0\.0\.0\/33/,
  );
});

test("virtualFsMount preserves the host filesystem object", () => {
  const virtualFs = {
    async stat() {
      return {
        type: "directory" as const,
        sizeBytes: null,
        mediaType: null,
        modifiedAtMs: null,
      };
    },
    async list() {
      return [];
    },
    async read() {
      return new Uint8Array();
    },
  };

  const mount = virtualFsMount("/sandbox", virtualFs);

  assert.equal(mount.kind, "virtual-fs");
  assert.equal(mount.path, "/sandbox");
  assert.equal(mount.fileSystem, virtualFs);
});

test("binding preserves the host filesystem object without creating a mount", () => {
  const virtualFs = unreachableFileSystem();
  const config = binding("/workspace", virtualFs);

  assert.equal(config.kind, "filesystem-binding");
  assert.equal(config.path, "/workspace");
  assert.equal(config.fileSystem, virtualFs);
});

function unreachableFileSystem() {
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
