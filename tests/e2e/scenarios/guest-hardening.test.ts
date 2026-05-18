import test from "node:test";
import assert from "node:assert/strict";
import {
  linuxOverlayFs,
  prebuiltRootfs,
  projectInit,
  projectKernel,
  scratchFs,
  spawnSandbox,
  type SandboxControlEvent,
  type SandboxVm,
} from "../../../src/index.ts";
import { collectAsync } from "../support/evidence.ts";
import { execGuest, execGuestShell, withTimeout } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

function isInitReady(event: SandboxControlEvent): event is Extract<SandboxControlEvent, { type: "init.ready" }> {
  return event.type === "init.ready";
}

test("guest memory exhaustion is contained and the host can launch a fresh VM", async (t) => {
  const vm = await spawnHardeningVm(t, "guest-memory-exhaustion", {
    memoryMib: 192,
  });
  if (vm === null) {
    return;
  }

  const result = await withTimeout(execGuestShell(vm, {
    id: "guest-memory-exhaustion",
    script: "awk 'BEGIN { s=\"\"; while (1) { s = s s \"0123456789abcdef\" } }'",
  }), 20_000, "guest memory exhaustion");

  assert.match(
    `${result.exitCode}\n${result.stdout}\n${result.stderr}`,
    /sandbox VM|sandbox-host|control closed|exited|closed|out of memory|killed|137/i,
  );
  await withTimeout(vm.close(), 3_000, "close memory-exhausted VM");

  const freshVm = await spawnHardeningVm(t, "guest-memory-exhaustion-fresh-check");
  if (freshVm === null) {
    return;
  }
  const freshResult = await execGuest(freshVm, {
    id: "fresh-after-memory-exhaustion",
    argv: ["/bin/true"],
  });
  assert.equal(freshResult.exitCode, 0);
});

test("guest CPU exhaustion can be stopped without wedging the host API", async (t) => {
  const vm = await spawnHardeningVm(t, "guest-cpu-exhaustion", {
    vcpus: 1,
  });
  if (vm === null) {
    return;
  }

  const hotLoop = execGuestShell(vm, {
    id: "guest-cpu-exhaustion",
    script: `
      i=0
      while [ "$i" -lt 16 ]; do
        (while :; do :; done) &
        i=$((i + 1))
      done
      wait
    `,
  });
  const hotLoopRejects = assert.rejects(
    withTimeout(hotLoop, 5_000, "CPU exhaustion command"),
    /sandbox VM|sandbox-host|control closed|exited|closed/i,
  );

  await delay(500);
  await withTimeout(vm.close(), 3_000, "close CPU-exhausted VM");
  await hotLoopRejects;
});

test("guest fork pressure can be stopped without wedging the host API", async (t) => {
  const vm = await spawnHardeningVm(t, "guest-fork-pressure", {
    vcpus: 1,
    memoryMib: 256,
  });
  if (vm === null) {
    return;
  }

  const forkPressure = execGuestShell(vm, {
    id: "guest-fork-pressure",
    script: `
      while :; do
        (sleep 60) &
      done
    `,
  });
  const forkPressureRejects = assert.rejects(
    withTimeout(forkPressure, 5_000, "fork pressure command"),
    /sandbox VM|sandbox-host|control closed|exited|closed/i,
  );

  await delay(500);
  await withTimeout(vm.close(), 3_000, "close fork-pressure VM");
  await forkPressureRejects;
});

test("guest disk exhaustion is bounded to the sandbox upper filesystem", async (t) => {
  const vm = await spawnHardeningVm(t, "guest-disk-exhaustion", {
    writableRoot: true,
  });
  if (vm === null) {
    return;
  }

  const result = await withTimeout(execGuestShell(vm, {
    id: "guest-disk-exhaustion",
    script: `
      set +e
      mkdir -p /tmp
      dd if=/dev/zero of=/tmp/sandbox-fill.bin bs=1M count=768 2>/run/disk-fill.err
      status=$?
      cat /run/disk-fill.err >&2
      exit "$status"
    `,
  }), 30_000, "guest disk exhaustion");

  assert.notEqual(result.exitCode, 0, "disk fill should hit a sandbox quota before writing 768 MiB");
  assert.match(result.stderr, /No space left|Disk quota exceeded|I\/O error/i);

  await withTimeout(vm.close(), 3_000, "close disk-exhausted VM");

  const freshVm = await spawnHardeningVm(t, "guest-disk-exhaustion-fresh-check", {
    writableRoot: true,
  });
  if (freshVm === null) {
    return;
  }
  const freshResult = await execGuestShell(freshVm, {
    id: "fresh-after-disk-exhaustion",
    script: "test ! -e /tmp/sandbox-fill.bin",
  });
  assert.equal(freshResult.exitCode, 0);
});

test("guest rootfs provides a sticky world-writable tmp directory", async (t) => {
  const vm = await spawnHardeningVm(t, "guest-rootfs-tmp-mode");
  if (vm === null) {
    return;
  }

  const result = await execGuestShell(vm, {
    id: "guest-rootfs-tmp-mode",
    script: "stat -c '%a %F' /tmp && touch /tmp/sandbox-tmp-check",
  });

  assert.equal(
    result.exitCode,
    0,
    `guest /tmp check failed\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`,
  );
  assert.equal(result.stdout, "1777 directory\n");
});

test("guest kernel object pressure can be stopped without wedging the host API", async (t) => {
  const vm = await spawnHardeningVm(t, "guest-kernel-object-pressure", {
    memoryMib: 256,
  });
  if (vm === null) {
    return;
  }

  const kernelPressure = execGuestShell(vm, {
    id: "guest-kernel-object-pressure",
    script: `
      while :; do
        exec 3<>/dev/null
      done
    `,
  });
  const kernelPressureRejects = assert.rejects(
    withTimeout(kernelPressure, 5_000, "kernel object pressure command"),
    /sandbox VM|sandbox-host|control closed|exited|closed/i,
  );

  await delay(500);
  await withTimeout(vm.close(), 3_000, "close kernel-pressure VM");
  await kernelPressureRejects;
});

async function spawnHardeningVm(
  t: test.TestContext,
  name: string,
  options: {
    readonly memoryMib?: number;
    readonly vcpus?: number;
    readonly writableRoot?: boolean;
  } = {},
): Promise<SandboxVm | null> {
  if (!requireVmLaunchSupport(t)) {
    return null;
  }

  const rootfs = prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
    format: "erofs",
  });
  const vm = await spawnSandbox({
    name,
    cpu: { vcpus: options.vcpus ?? 1 },
    memory: { mib: options.memoryMib ?? 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: options.writableRoot
      ? linuxOverlayFs({ lower: rootfs, upper: scratchFs() })
      : rootfs,
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);
  return vm;
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
