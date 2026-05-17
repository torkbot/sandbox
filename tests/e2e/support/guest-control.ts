import type { SandboxControlEvent, SandboxVm } from "../../../src/index.ts";
import { collectAsync } from "./evidence.ts";

function isExecComplete(
  id: string,
): (event: SandboxControlEvent) => event is Extract<SandboxControlEvent, { type: "guest.exec.complete" }> {
  return (event): event is Extract<SandboxControlEvent, { type: "guest.exec.complete" }> =>
    event.type === "guest.exec.complete" && event.id === id;
}

export async function execGuest(
  vm: SandboxVm,
  input: {
    readonly id: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
  },
): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
  return await vm.control.exec(input);
}

export async function execGuestShell(
  vm: SandboxVm,
  input: {
    readonly id: string;
    readonly script: string;
    readonly env?: Record<string, string>;
  },
): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
  return await execGuest(vm, {
    id: input.id,
    argv: ["/bin/sh", "-lc", input.script],
    env: input.env,
  });
}
