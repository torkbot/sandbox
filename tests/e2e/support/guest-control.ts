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

export async function withTimeout<T>(
  promise: Promise<T>,
  milliseconds: number,
  label: string,
): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          reject(new Error(`${label} timed out after ${milliseconds}ms`));
        }, milliseconds);
        timeout.unref();
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}
