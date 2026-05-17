import type {
  SandboxControl,
  SandboxControlCommand,
  SandboxControlEvent,
} from "./index.ts";
import {
  decodeControlEvent,
  encodeControlCommand,
} from "./control-codec.ts";

export interface HostControlChannel {
  writeControlPacket(packet: Uint8Array): void;
  tryReadControlPacket(): Uint8Array | null;
}

export class HostControlTransport implements SandboxControl {
  readonly incoming: AsyncIterable<SandboxControlEvent>;

  readonly #events: AsyncQueue<SandboxControlEvent>;
  readonly #connected: boolean;
  readonly #channel: HostControlChannel | null;
  readonly #pendingExec = new Map<string, {
    resolve(event: Extract<SandboxControlEvent, { type: "guest.exec.complete" }>): void;
    reject(error: unknown): void;
  }>();
  #closed = false;

  constructor(options: {
    readonly connected?: boolean;
    readonly channel?: HostControlChannel;
  } = {}) {
    this.#channel = options.channel ?? null;
    this.#connected = options.connected ?? true;
    this.#events = new AsyncQueue();
    this.incoming = this.#connected
      ? this.#events
      : {
          async *[Symbol.asyncIterator]() {
            throw new Error("sandbox control plane is not connected yet");
          },
        };

    if (this.#channel !== null && this.#connected) {
      void this.#pumpIncoming();
    }
  }

  async send(message: SandboxControlCommand): Promise<void> {
    this.#assertOpen();
    if (this.#channel === null) {
      throw new Error("sandbox control send is not connected yet");
    }
    this.#channel.writeControlPacket(encodeControlCommand(message));
  }

  async exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
    this.#assertOpen();
    const id = input.id ?? crypto.randomUUID();
    const completion = new Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>((resolve, reject) => {
      this.#pendingExec.set(id, { resolve, reject });
    });
    try {
      await this.send({
        type: "guest.exec",
        id,
        argv: input.argv,
        env: input.env,
      });
    } catch (error) {
      this.#pendingExec.delete(id);
      throw error;
    }
    return await completion;
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#rejectPendingExec(new Error("sandbox control is closed"));
    this.#events.close();
  }

  emit(event: SandboxControlEvent): void {
    this.#assertOpen();
    this.#dispatchEvent(event);
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new Error("sandbox control is closed");
    }
    if (!this.#connected) {
      throw new Error("sandbox control plane is not connected yet");
    }
  }

  async #pumpIncoming(): Promise<void> {
    while (!this.#closed && this.#channel !== null) {
      let packet: Uint8Array | null;
      try {
        packet = this.#channel.tryReadControlPacket();
      } catch (error) {
        if (this.#closed) {
          return;
        }
        this.#closed = true;
        this.#rejectPendingExec(error);
        this.#events.close(error);
        return;
      }
      if (packet !== null) {
        if (this.#closed) {
          return;
        }
        this.#dispatchEvent(decodeControlEvent(packet));
        continue;
      }

      await sleep(10);
    }
  }

  #dispatchEvent(event: SandboxControlEvent): void {
    this.#events.push(event);
    if (event.type !== "guest.exec.complete") {
      return;
    }
    const pending = this.#pendingExec.get(event.id);
    if (pending === undefined) {
      return;
    }
    this.#pendingExec.delete(event.id);
    pending.resolve(event);
  }

  #rejectPendingExec(error: unknown): void {
    for (const pending of this.#pendingExec.values()) {
      pending.reject(error);
    }
    this.#pendingExec.clear();
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, ms);
    timeout.unref();
  });
}

class AsyncQueue<T> implements AsyncIterable<T> {
  readonly #values: T[] = [];
  readonly #waiters: Array<{
    resolve(result: IteratorResult<T>): void;
    reject(error: unknown): void;
  }> = [];
  #closed = false;
  #error: unknown;

  push(value: T): void {
    if (this.#closed) {
      throw new Error("async queue is closed");
    }

    const waiter = this.#waiters.shift();
    if (waiter !== undefined) {
      waiter.resolve({ value, done: false });
      return;
    }

    this.#values.push(value);
  }

  close(error?: unknown): void {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#error = error;
    for (const waiter of this.#waiters.splice(0)) {
      if (error === undefined) {
        waiter.resolve({ value: undefined, done: true });
      } else {
        waiter.reject(error);
      }
    }
  }

  [Symbol.asyncIterator](): AsyncIterator<T> {
    return {
      next: async () => {
        const value = this.#values.shift();
        if (value !== undefined) {
          return { value, done: false };
        }

        if (this.#closed) {
          if (this.#error !== undefined) {
            throw this.#error;
          }
          return { value: undefined, done: true };
        }

        return await new Promise<IteratorResult<T>>((resolve, reject) => {
          this.#waiters.push({
            resolve,
            reject,
          });
        });
      },
    };
  }
}
