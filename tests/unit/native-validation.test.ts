import test from "node:test";
import assert from "node:assert/strict";
import {
  acceptTcp,
  binding,
  createSandbox,
  linuxOverlayFs,
  prebuiltRootfs,
  projectInit,
  projectKernel,
  scratchFs,
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

test("spawnSandbox rejects CPU counts the native spec cannot represent before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      cpu: { vcpus: 256 },
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
    }),
    /invalid spawnSandbox options: cpu\.vcpus must be less than or equal to 255/,
  );
});

test("spawnSandbox rejects fractional resource config before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      cpu: { vcpus: 1.5 },
      memory: { mib: 128.5 },
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

test("spawnSandbox rejects invalid overlay lower rootfs before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: linuxOverlayFs({
        lower: prebuiltRootfs("", { format: "erofs" }),
        upper: scratchFs(),
      }),
    }),
    /invalid spawnSandbox options: rootfs\.lower\.path must not be empty/,
  );

  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: linuxOverlayFs({
        lower: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20", {
          format: "directory",
        }),
        upper: scratchFs(),
      }),
    }),
    /invalid spawnSandbox options: rootfs\.lower directory rootfs is not supported for sandboxed VM launch; use an EROFS rootfs/,
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

test("spawnSandbox rejects root and dot-component mount paths before runtime launch", async () => {
  const fileSystem = unreachableFileSystem();

  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        virtualFsMount("/", fileSystem),
      ],
    }),
    /invalid spawnSandbox options: mount\.path must not be root/,
  );

  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        virtualFsMount("/tmp/../proc", fileSystem),
      ],
    }),
    /invalid spawnSandbox options: mount\.path must not contain '\.' or '\.\.' components/,
  );
});

test("spawnSandbox rejects mount paths with NUL bytes before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      mounts: [
        virtualFsMount("/bad\0path", unreachableFileSystem()),
      ],
    }),
    /invalid spawnSandbox options: mount\.path must not contain NUL bytes/,
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

test("spawnSandbox rejects invalid outbound CIDR ranges before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      network: {
        outbound: {
          policy: "deny",
          rules: [acceptTcp({ cidr: "127.0.0.0/33" })],
        },
      },
    }),
    /invalid spawnSandbox options: invalid CIDR prefix: 127\.0\.0\.0\/33/,
  );
});

test("spawnSandbox rejects invalid outbound CIDR addresses before runtime launch", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      network: {
        outbound: {
          policy: "deny",
          rules: [acceptTcp({ cidr: "999.0.0.0/8" })],
        },
      },
    }),
    /invalid spawnSandbox options: invalid CIDR address: 999\.0\.0\.0\/8/,
  );
});

test("spawnSandbox rejects IPv6 outbound CIDR ranges until IPv6 egress is supported", async () => {
  await assert.rejects(
    spawnSandbox({
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      network: {
        outbound: {
          policy: "deny",
          rules: [acceptTcp({ cidr: "2001:db8::/32" })],
        },
      },
    }),
    /invalid spawnSandbox options: IPv6 outbound CIDR ranges are not supported yet: 2001:db8::\/32/,
  );
});

test("createSandbox requires outbound policy when request-header hooks are configured", async () => {
  const sandbox = createSandbox({
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });
  sandbox.http.onRequestHeaders("https://api.github.com/*", () => {});

  await assert.rejects(
    sandbox.run(),
    /invalid spawnSandbox options: network\.outbound is required when HTTP interception is configured/,
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
