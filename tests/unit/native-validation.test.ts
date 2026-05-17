import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  virtualFsMount,
} from "../../src/index.ts";
import { loadNativeBinding } from "../../src/native.ts";

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

test("spawnSandbox returns an owned VM handle before guest launch is implemented", async () => {
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

  const vm = await spawnSandbox({
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("test-fixtures/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [virtualFsMount("/sandbox", virtualFs)],
  });

  assert.equal(vm.mounts.virtualFs("/sandbox"), virtualFs);
  await assert.rejects(
    vm.control.exec({ id: "test", argv: ["/bin/true"] }),
    /sandbox control plane is not connected yet/,
  );
  await vm.close();
  await vm.close();
});

test("native spawn owns a host control socket", async () => {
  const nativeVm = await loadNativeBinding().spawnSandbox({
    kernel: {},
    init: { crateName: "sandbox-init" },
    rootfs: {
      path: "test-fixtures/rootfs/alpine-3.20.erofs",
      readonly: true,
      format: "erofs",
    },
  });

  assert.equal(nativeVm.hasControlSocket, true);
  assert.equal(nativeVm.tryReadControlPacket(), null);
  await nativeVm.close();
  assert.equal(nativeVm.hasControlSocket, false);
  assert.throws(
    () => nativeVm.tryReadControlPacket(),
    /sandbox VM is closed/,
  );
});
