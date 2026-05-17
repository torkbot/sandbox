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
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
    this.#assertOpen();
    const id = input.id ?? crypto.randomUUID();
    const completion = waitForExecComplete(this.incoming, id);
    await this.send({
      type: "guest.exec",
      id,
      argv: input.argv,
    });
    return await completion;
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#events.close();
  }

  emit(event: SandboxControlEvent): void {
    this.#assertOpen();
    this.#events.push(event);
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
      const packet = this.#channel.tryReadControlPacket();
      if (packet !== null) {
        this.#events.push(decodeControlEvent(packet));
        continue;
      }

      await sleep(10);
    }
  }
}

async function waitForExecComplete(
  incoming: AsyncIterable<SandboxControlEvent>,
  id: string,
): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
  for await (const event of incoming) {
    if (event.type === "guest.exec.complete" && event.id === id) {
      return event;
    }
  }

  throw new Error(`sandbox control closed before exec completed: ${id}`);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timeout = setTimeout(resolve, ms);
    timeout.unref();
  });
}

class AsyncQueue<T> implements AsyncIterable<T> {
  readonly #values: T[] = [];
  readonly #waiters: ((result: IteratorResult<T>) => void)[] = [];
  #closed = false;

  push(value: T): void {
    if (this.#closed) {
      throw new Error("async queue is closed");
    }

    const waiter = this.#waiters.shift();
    if (waiter !== undefined) {
      waiter({ value, done: false });
      return;
    }

    this.#values.push(value);
  }

  close(): void {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    for (const waiter of this.#waiters.splice(0)) {
      waiter({ value: undefined, done: true });
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
          return { value: undefined, done: true };
        }

        return await new Promise<IteratorResult<T>>((resolve) => {
          this.#waiters.push(resolve);
        });
      },
    };
  }
}
