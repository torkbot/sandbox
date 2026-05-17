import test from "node:test";
import assert from "node:assert/strict";
import {
  linuxOverlayFs,
  mount,
  prebuiltRootfs,
  projectInit,
  projectKernel,
  scratchFs,
  spawnSandbox,
  virtualFsMount,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

test("linuxOverlayFs composes a prebuilt lower filesystem with a scratch upper filesystem", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "rootfs-shaping",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: linuxOverlayFs({
      lower: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      upper: scratchFs(),
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  const ready = await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");
  assert.equal(ready.guest.root.readonly, false);

  const install = await execGuestShell(vm, {
    id: "shape-rootfs",
    script: `
      set -eu
      mkdir -p /opt/sandbox
      printf shaped > /opt/sandbox/marker.txt
      test "$(cat /opt/sandbox/marker.txt)" = "shaped"
    `,
  });
  assert.equal(install.exitCode, 0);

  await writeEvidence("rootfs-shaping.json", {
    rootfs: "linux-overlay-fs",
  });
});

test("immutable root remains the default when overlay mode is absent", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "immutable-root-default",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "immutable-root-default",
    script: "mkdir -p /opt/sandbox",
  });

  assert.notEqual(result.exitCode, 0);
  assert.match(result.stderr, /Read-only file system|read-only/i);
});

test("linuxOverlayFs does not mutate its prebuilt lower filesystem", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const lower = prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
    format: "erofs",
  });
  const overlayVm = await spawnSandbox({
    name: "overlay-does-not-mutate-lower",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: linuxOverlayFs({
      lower,
      upper: scratchFs(),
    }),
  });

  t.after(async () => {
    await overlayVm.close();
  });

  await collectAsync(overlayVm.control.incoming, (event) => event.type === "init.ready");

  const write = await execGuestShell(overlayVm, {
    id: "write-overlay",
    script: "mkdir -p /opt/sandbox && printf overlay > /opt/sandbox/lower-check.txt",
  });
  assert.equal(write.exitCode, 0);
  await overlayVm.close();

  const lowerVm = await spawnSandbox({
    name: "overlay-lower-check",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: lower,
  });

  t.after(async () => {
    await lowerVm.close();
  });

  await collectAsync(lowerVm.control.incoming, (event) => event.type === "init.ready");

  const check = await execGuestShell(lowerVm, {
    id: "check-lower",
    script: "test ! -e /opt/sandbox/lower-check.txt",
  });

  assert.equal(check.exitCode, 0);
});

test("scratchFs upper state is isolated between VM instances", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const rootfs = linuxOverlayFs({
    lower: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    upper: scratchFs(),
  });
  const first = await spawnSandbox({
    name: "scratch-isolated-first",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs,
  });

  t.after(async () => {
    await first.close();
  });

  await collectAsync(first.control.incoming, (event) => event.type === "init.ready");

  const write = await execGuestShell(first, {
    id: "write-scratch",
    script: "mkdir -p /opt/sandbox && printf first > /opt/sandbox/scratch.txt",
  });
  assert.equal(write.exitCode, 0);
  await first.close();

  const second = await spawnSandbox({
    name: "scratch-isolated-second",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: linuxOverlayFs({
      lower: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
        format: "erofs",
      }),
      upper: scratchFs(),
    }),
  });

  t.after(async () => {
    await second.close();
  });

  await collectAsync(second.control.incoming, (event) => event.type === "init.ready");

  const check = await execGuestShell(second, {
    id: "check-scratch",
    script: "test ! -e /opt/sandbox/scratch.txt",
  });

  assert.equal(check.exitCode, 0);
});

test("mount creates a guest-visible mount boundary", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "guest-visible-mount",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      mount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return {
              type: "directory",
              sizeBytes: null,
              mediaType: null,
              modifiedAtMs: null,
            };
          }
          if (path === "/visible.txt") {
            return {
              type: "file",
              sizeBytes: 7,
              mediaType: "text/plain",
              modifiedAtMs: null,
            };
          }
          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") throw new Error(`missing directory ${path}`);
          return [{ name: "visible.txt", type: "file" }];
        },
        async read(input) {
          if (input.path !== "/visible.txt") throw new Error(`missing file ${input.path}`);
          return new TextEncoder().encode("visible");
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const result = await execGuestShell(vm, {
    id: "guest-visible-mount",
    script: "cat /sandbox/visible.txt && grep ' /sandbox ' /proc/mounts",
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /visible/);
});

test("virtualFsMount remains an alias for guest-visible mounts while bindings are a separate future primitive", () => {
  const fileSystem = {
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

  assert.deepEqual(mount("/sandbox", fileSystem), virtualFsMount("/sandbox", fileSystem));
});
