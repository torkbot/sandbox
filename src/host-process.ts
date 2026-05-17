import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { once } from "node:events";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { BSON } from "bson";
import type { HostControlChannel } from "./control.ts";
import type { NativeSpawnSandboxOptions } from "./native.ts";

export class HostProcessSandboxVm implements HostControlChannel {
  readonly hasControlSocket = true;

  readonly #child: ChildProcessWithoutNullStreams;
  readonly #packets: Uint8Array[] = [];
  #buffer = new Uint8Array();
  #closed = false;
  #exitError: Error | null = null;

  private constructor(child: ChildProcessWithoutNullStreams) {
    this.#child = child;
    child.stdout.on("data", (chunk: Buffer) => {
      this.#receive(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString("utf8").trim();
      if (text.length > 0) {
        this.#exitError = new Error(`sandbox-host stderr: ${text}`);
      }
    });
    child.on("exit", (code, signal) => {
      if (this.#closed) {
        return;
      }

      this.#exitError = new Error(
        signal === null
          ? `sandbox-host exited with ${code ?? "unknown status"}`
          : `sandbox-host exited from signal ${signal}`,
      );
    });
  }

  static async spawn(options: NativeSpawnSandboxOptions): Promise<HostProcessSandboxVm> {
    const child = spawn(hostBinaryPath(), ["--stdio"], {
      stdio: ["pipe", "pipe", "pipe"],
    });
    const vm = new HostProcessSandboxVm(child);
    await Promise.race([
      once(child, "spawn"),
      once(child, "error").then(([error]) => {
        throw error;
      }),
    ]);
    child.stdin.write(encodeHostSpawn(options));
    return vm;
  }

  writeControlPacket(packet: Uint8Array): void {
    this.#assertOpen();
    this.#child.stdin.write(packet);
  }

  tryReadControlPacket(): Uint8Array | null {
    this.#assertOpen();
    return this.#packets.shift() ?? null;
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#child.stdin.destroy();
    this.#child.kill();
    await Promise.race([
      once(this.#child, "exit"),
      new Promise<void>((resolvePromise) => setTimeout(resolvePromise, 100)),
    ]);
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new Error("sandbox VM is closed");
    }
    if (this.#exitError !== null) {
      throw this.#exitError;
    }
  }

  #receive(chunk: Uint8Array): void {
    const next = new Uint8Array(this.#buffer.byteLength + chunk.byteLength);
    next.set(this.#buffer);
    next.set(chunk, this.#buffer.byteLength);
    this.#buffer = next;

    while (this.#buffer.byteLength >= 4) {
      const frameLength = new DataView(this.#buffer.buffer, this.#buffer.byteOffset, 4).getUint32(0, true);
      const packetLength = 4 + frameLength;
      if (this.#buffer.byteLength < packetLength) {
        return;
      }

      this.#packets.push(this.#buffer.slice(0, packetLength));
      this.#buffer = this.#buffer.slice(packetLength);
    }
  }
}

export function hostBinaryPath(): string {
  const path = resolve(import.meta.dirname, "../target/release/sandbox-host");
  if (!existsSync(path)) {
    throw new Error(`sandbox-host is not built: ${path}`);
  }
  return path;
}

function encodeHostSpawn(options: NativeSpawnSandboxOptions): Uint8Array {
  return encodePacket({
    type: "host.spawn",
    name: options.name,
    vcpus: options.cpu?.vcpus,
    memoryMib: options.memory?.mib,
    kernelFormat: options.kernel.format,
    initCrate: options.init.crateName,
    rootfsPath: options.rootfs.path,
    rootfsReadonly: options.rootfs.readonly,
    rootfsFormat: options.rootfs.format,
    rootfsOverlayMode: options.rootfsOverlay?.mode,
    mounts: options.mounts ?? [],
    networkHttp: options.network?.http === undefined
      ? undefined
      : {
          protectedRanges: options.network.http.protectedRanges ?? [],
        },
  });
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document, { ignoreUndefined: true });
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}
