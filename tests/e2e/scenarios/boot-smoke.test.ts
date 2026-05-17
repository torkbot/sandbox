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
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20", {
      format: "directory",
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

test("guest init death is surfaced through the VM API", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "guest-init-death",
    cpu: { vcpus: 1 },
    memory: { mib: 512 },
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20", {
      format: "directory",
    }),
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, isInitReady);

  await execGuestShell(vm, {
    id: "kill-init",
    script: "kill -9 1",
  });

  await assert.rejects(
    withTimeout(execGuest(vm, {
      id: "after-init-death",
      argv: ["/bin/true"],
    }), 1_000, "exec after init death"),
    /sandbox VM|sandbox-host|control closed|exited|closed/i,
  );
});

test("guest exec receives explicit environment variables", () => {
  assert.fail("guest exec env propagation must be proven through the guest control channel");
});

test("guest exec preserves stderr and non-zero exit status", () => {
  assert.fail("guest exec stderr and non-zero exit status must be surfaced without lossy wrapping");
});

test("guest exec preserves large stdout and stderr payloads", () => {
  assert.fail("guest exec output framing must preserve large stdout and stderr payloads exactly");
});

test("guest exec supports multiple in-flight commands", () => {
  assert.fail("guest control must correlate concurrent exec completions by request id");
});

test("closing a VM terminates resources and rejects later operations", () => {
  assert.fail("VM close must deterministically reject later control and mount operations");
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
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20", {
      format: "directory",
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
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20", {
      format: "directory",
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
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20", {
      format: "directory",
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
