import type {
  SandboxControl,
  SandboxControlCommand,
  SandboxControlEvent,
} from "./index.ts";

export class HostControlTransport implements SandboxControl {
  readonly incoming: AsyncIterable<SandboxControlEvent>;

  readonly #events: AsyncQueue<SandboxControlEvent>;
  readonly #connected: boolean;
  #closed = false;

  constructor(options: { readonly connected?: boolean } = {}) {
    this.#connected = options.connected ?? true;
    this.#events = new AsyncQueue();
    this.incoming = this.#connected
      ? this.#events
      : {
          async *[Symbol.asyncIterator]() {
            throw new Error("sandbox control plane is not connected yet");
          },
        };
  }

  async send(_message: SandboxControlCommand): Promise<void> {
    this.#assertOpen();
    throw new Error("sandbox control send is not connected yet");
  }

  async exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
    this.#assertOpen();
    await this.send({
      type: "guest.exec",
      id: input.id ?? crypto.randomUUID(),
      argv: input.argv,
    });
    throw new Error("sandbox control exec is not connected yet");
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
