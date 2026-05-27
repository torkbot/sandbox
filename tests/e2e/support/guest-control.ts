import type { SandboxExecResult, SandboxInstance } from "../../../src/index.ts";

export async function execGuest(
  vm: SandboxInstance,
  input: {
    readonly id: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
  },
): Promise<SandboxExecResult> {
  const [command, ...args] = input.argv;
  if (command === undefined) {
    throw new Error("argv must contain a command");
  }
  return await vm.exec(command, args, { env: input.env });
}

export async function execGuestShell(
  vm: SandboxInstance,
  input: {
    readonly id: string;
    readonly script: string;
    readonly env?: Record<string, string>;
  },
): Promise<SandboxExecResult> {
  return await vm.exec("/bin/sh", ["-lc", input.script], { env: input.env });
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
