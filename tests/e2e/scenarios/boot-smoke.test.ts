import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  type SandboxVm,
  type SandboxControlEvent,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuest, execGuestShell, withTimeout } from "../support/guest-control.ts";
import { requireVmLaunchSupport } from "../support/capabilities.ts";

function isInitReady(event: SandboxControlEvent): event is Extract<SandboxControlEvent, { type: "init.ready" }> {
  return event.type === "init.ready";
}

test("Node can boot a sandbox VM and exchange control messages", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "boot-smoke",
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  const ready = await collectAsync(vm.control.incoming, isInitReady);
  assert.equal(ready.guest.root.readonly, true);
  assert.equal(ready.guest.init.name, "sandbox-init");

  const result = await execGuest(vm, {
    id: "uname",
    argv: ["/bin/uname", "-a"],
  });

  assert.equal(result.exitCode, 0);
  assert.match(result.stdout, /Linux/);

  await writeEvidence("control.json", {
    ready,
    result,
  });
});

test("spawnSandbox rejects host launch failures before returning a VM", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  await assert.rejects(
    spawnSandbox({
      name: "missing-rootfs-launch-failure",
      kernel: projectKernel(),
      init: projectInit(),
      rootfs: prebuiltRootfs("dist/rootfs/missing.erofs", {
        format: "erofs",
      }),
    }),
    /sandbox-host exited|krun_add_disk|failed/i,
  );
});

test("guest init resists fatal signals from guest workloads", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "guest-init-death",
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);

  const kill = await withTimeout(execGuestShell(vm, {
    id: "signal-init",
    script: "kill -9 1; printf survived",
  }), 1_000, "kill init").catch(() => undefined);
  assert.equal(kill?.exitCode, 0);
  assert.equal(kill?.stdout, "survived");

  const followup = await withTimeout(execGuest(vm, {
    id: "after-init-signal",
    argv: ["/bin/true"],
  }), 1_000, "exec after init signal");
  assert.equal(followup.exitCode, 0);
});

test("guest exec receives explicit environment variables", async (t) => {
  const vm = await spawnBootVm(t, "guest-exec-env");
  if (vm === null) {
    return;
  }

  const result = await execGuestShell(vm, {
    id: "guest-exec-env",
    env: { SANDBOX_E2E_ENV: "typed-env-value" },
    script: "printf '%s' \"$SANDBOX_E2E_ENV\"",
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, "typed-env-value");
  assert.equal(result.stderr, "");
});

test("guest exec reports missing commands without killing init", async (t) => {
  const vm = await spawnBootVm(t, "guest-exec-missing-command");
  if (vm === null) {
    return;
  }

  const missing = await execGuest(vm, {
    id: "guest-exec-missing-command",
    argv: ["/definitely-not-a-command"],
  });

  assert.equal(missing.exitCode, 127);
  assert.match(missing.stderr, /spawn guest command/);

  const followup = await execGuestShell(vm, {
    id: "guest-exec-after-missing-command",
    script: "printf alive",
  });
  assert.equal(followup.exitCode, 0);
  assert.equal(followup.stdout, "alive");
});

test("guest exec preserves stderr and non-zero exit status", async (t) => {
  const vm = await spawnBootVm(t, "guest-exec-status");
  if (vm === null) {
    return;
  }

  const result = await execGuestShell(vm, {
    id: "guest-exec-status",
    script: "printf 'out'; printf 'err' >&2; exit 23",
  });

  assert.equal(result.exitCode, 23);
  assert.equal(result.stdout, "out");
  assert.equal(result.stderr, "err");
});

test("guest exec preserves large stdout and stderr payloads", async (t) => {
  const vm = await spawnBootVm(t, "guest-exec-large-output");
  if (vm === null) {
    return;
  }

  const stdoutBytes = 96 * 1024;
  const stderrBytes = 80 * 1024;
  const result = await execGuestShell(vm, {
    id: "guest-exec-large-output",
    script: [
      `head -c ${stdoutBytes} /dev/zero | tr '\\0' A`,
      `head -c ${stderrBytes} /dev/zero | tr '\\0' B >&2`,
    ].join("\n"),
  });

  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout.length, stdoutBytes);
  assert.equal(result.stderr.length, stderrBytes);
  assert.equal(result.stdout, "A".repeat(stdoutBytes));
  assert.equal(result.stderr, "B".repeat(stderrBytes));
});

test("guest exec supports multiple in-flight commands", async (t) => {
  const vm = await spawnBootVm(t, "guest-exec-concurrent");
  if (vm === null) {
    return;
  }

  const results = await Promise.all(
    Array.from({ length: 6 }, (_, index) =>
      execGuestShell(vm, {
        id: `guest-exec-concurrent-${index}`,
        script: `sleep 0.${6 - index}; printf 'result-${index}'`,
      }),
    ),
  );

  assert.deepEqual(
    results.map((result) => ({
      id: result.id,
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
    })),
    Array.from({ length: 6 }, (_, index) => ({
      id: `guest-exec-concurrent-${index}`,
      exitCode: 0,
      stdout: `result-${index}`,
      stderr: "",
    })),
  );
});

test("closing a VM terminates resources and rejects later operations", async (t) => {
  const vm = await spawnBootVm(t, "guest-close-rejects");
  if (vm === null) {
    return;
  }

  await vm.close();

  await assert.rejects(
    execGuest(vm, {
      id: "after-close",
      argv: ["/bin/true"],
    }),
    /closed/i,
  );
});

test("guest command lockup can be cleaned up by closing the VM", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "guest-command-lockup",
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);

  const locked = execGuestShell(vm, {
    id: "guest-command-lockup",
    script: "while :; do sleep 1; done",
  });
  const lockedRejects = assert.rejects(
    withTimeout(locked, 5_000, "locked guest command"),
    /sandbox VM|sandbox-host|control closed|exited|closed/i,
  );

  await delay(250);
  await withTimeout(vm.close(), 3_000, "close locked guest command VM");
  await lockedRejects;
});

test("host process exit is surfaced through the VM API", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "host-process-exit",
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);

  await hostFailureDiagnostics(vm).terminateHostForTest();

  await assert.rejects(
    withTimeout(execGuest(vm, {
      id: "after-host-exit",
      argv: ["/bin/true"],
    }), 1_000, "exec after host process exit"),
    /sandbox VM|sandbox-host|control closed|exited|closed/i,
  );
});

test("guest OOM is surfaced through the VM API", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "guest-oom",
    cpu: { vcpus: 1 },
    memory: { mib: 192 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);

  const result = await withTimeout(execGuestShell(vm, {
    id: "guest-oom",
    script: "awk 'BEGIN { s=\"\"; while (1) { s = s s \"0123456789abcdef\" } }'",
  }), 20_000, "guest OOM");

  assert.match(
    `${result.exitCode}\n${result.stdout}\n${result.stderr}`,
    /sandbox VM|sandbox-host|control closed|exited|closed|out of memory|killed|137/i,
  );
});

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function spawnBootVm(t: test.TestContext, name: string): Promise<SandboxVm | null> {
  if (!requireVmLaunchSupport(t)) {
    return null;
  }

  const vm = await spawnSandbox({
    name,
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);
  return vm;
}

function hostFailureDiagnostics(vm: SandboxVm): {
  terminateHostForTest(): Promise<void>;
} {
  assert.ok(
    "diagnostics" in vm,
    "SandboxVm should expose a diagnostics surface that can terminate the host process in e2e tests",
  );
  const diagnostics = (vm as { diagnostics?: unknown }).diagnostics;
  assert.ok(
    diagnostics !== null && typeof diagnostics === "object" && "terminateHostForTest" in diagnostics,
    "SandboxVm diagnostics should expose terminateHostForTest()",
  );
  return diagnostics as { terminateHostForTest(): Promise<void> };
}
