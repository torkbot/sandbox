import type {
  SandboxControlCommand,
  SandboxControlEvent,
} from "./control-codec.ts";
import {
  decodeControlEvent,
  encodeControlCommand,
} from "./control-codec.ts";

export interface SandboxControl extends Transport<SandboxControlEvent, SandboxControlCommand> {
  exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly timeoutMs?: number;
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>;
  spawn(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
  }): Promise<ControlBackedSandboxProcess>;
}

export interface Transport<TIncoming = unknown, TOutgoing = unknown> {
  readonly incoming: AsyncIterable<TIncoming>;
  send(message: TOutgoing): Promise<void>;
  close(): Promise<void>;
}

export interface HostControlChannel {
  readonly packets: AsyncIterable<Uint8Array>;
  writeControlPacket(packet: Uint8Array): void;
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
  readonly #pendingSpawn = new Map<string, {
    resolve(process: ControlBackedSandboxProcess): void;
    reject(error: unknown): void;
    process: ControlBackedSandboxProcess;
    returned: boolean;
    exited: boolean;
    streamsClosed: boolean;
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
    readonly timeoutMs?: number;
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
    this.#assertOpen();
    const id = input.id ?? crypto.randomUUID();
    if (this.#pendingExec.has(id)) {
      throw new Error(`sandbox exec id is already in flight: ${id}`);
    }
    const completion = new Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>((resolve, reject) => {
      this.#pendingExec.set(id, { resolve, reject });
    });
    try {
      await this.send({
        type: "guest.exec",
        id,
        argv: input.argv,
        env: input.env,
        timeoutMs: input.timeoutMs,
      });
    } catch (error) {
      this.#pendingExec.delete(id);
      throw error;
    }
    return await completion;
  }

  async spawn(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
  }): Promise<ControlBackedSandboxProcess> {
    this.#assertOpen();
    const id = input.id ?? crypto.randomUUID();
    if (this.#pendingSpawn.has(id)) {
      throw new Error(`sandbox spawn id is already in flight: ${id}`);
    }
    const process = new ControlBackedSandboxProcess(id, this);
    const started = new Promise<ControlBackedSandboxProcess>((resolve, reject) => {
      this.#pendingSpawn.set(id, {
        resolve,
        reject,
        process,
        returned: false,
        exited: false,
        streamsClosed: false,
      });
    });
    try {
      await this.send({
        type: "guest.spawn",
        id,
        argv: input.argv,
        env: input.env,
      });
    } catch (error) {
      this.#pendingSpawn.delete(id);
      throw error;
    }
    return await started;
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#rejectPendingExec(new Error("sandbox control is closed"));
    this.#rejectPendingSpawn(new Error("sandbox control is closed"));
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
    if (this.#channel === null) {
      return;
    }
    try {
      for await (const packet of this.#channel.packets) {
        if (this.#closed) {
          return;
        }
        const event = decodeControlEvent(packet);
        this.#dispatchEvent(event);
      }
    } catch (error) {
      if (this.#closed) {
        return;
      }
      this.#fail(error);
    }
  }

  #dispatchEvent(event: SandboxControlEvent): void {
    if (event.type === "guest.spawn.stdout" || event.type === "guest.spawn.stderr") {
      this.#dispatchSpawnEvent(event);
      return;
    }
    this.#events.push(event);
    if (event.type !== "guest.exec.complete") {
      this.#dispatchSpawnEvent(event);
      return;
    }
    const pending = this.#pendingExec.get(event.id);
    if (pending === undefined) {
      return;
    }
    this.#pendingExec.delete(event.id);
    pending.resolve(event);
  }

  #dispatchSpawnEvent(event: SandboxControlEvent): void {
    if (
      event.type !== "guest.spawn.stdout"
      && event.type !== "guest.spawn.stderr"
      && event.type !== "guest.spawn.started"
      && event.type !== "guest.spawn.exit"
      && event.type !== "guest.spawn.streams.closed"
    ) {
      return;
    }
    const pending = this.#pendingSpawn.get(event.id);
    if (pending === undefined) {
      return;
    }
    if (event.type === "guest.spawn.started") {
      pending.returned = true;
      pending.resolve(pending.process);
      return;
    }
    if (event.type === "guest.spawn.exit") {
      pending.returned = true;
      pending.exited = true;
      pending.resolve(pending.process);
    }
    if (event.type === "guest.spawn.streams.closed") {
      pending.streamsClosed = true;
    }
    pending.process.emit(event);
    if (pending.exited && pending.streamsClosed) {
      this.#pendingSpawn.delete(event.id);
    }
  }

  #fail(error: unknown): void {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#rejectPendingExec(error);
    this.#rejectPendingSpawn(error);
    this.#events.close(error);
  }

  #rejectPendingExec(error: unknown): void {
    for (const pending of this.#pendingExec.values()) {
      pending.reject(error);
    }
    this.#pendingExec.clear();
  }

  #rejectPendingSpawn(error: unknown): void {
    for (const pending of this.#pendingSpawn.values()) {
      pending.reject(error);
      if (pending.returned) {
        pending.process.fail(error);
      }
    }
    this.#pendingSpawn.clear();
  }
}

export class ControlBackedSandboxProcess {
  readonly stdout: AsyncIterable<Uint8Array>;
  readonly stderr: AsyncIterable<Uint8Array>;
  readonly exit: Promise<{ readonly exitCode: number }>;

  readonly #id: string;
  readonly #control: SandboxControl;
  readonly #stdout = new AsyncQueue<Uint8Array>();
  readonly #stderr = new AsyncQueue<Uint8Array>();
  #resolveExit!: (result: { readonly exitCode: number }) => void;
  #rejectExit!: (error: unknown) => void;
  #exited = false;

  constructor(id: string, control: SandboxControl) {
    this.#id = id;
    this.#control = control;
    this.stdout = this.#stdout;
    this.stderr = this.#stderr;
    this.exit = new Promise((resolve, reject) => {
      this.#resolveExit = resolve;
      this.#rejectExit = reject;
    });
  }

  emit(event: Extract<SandboxControlEvent, {
    type: "guest.spawn.stdout" | "guest.spawn.stderr" | "guest.spawn.exit" | "guest.spawn.streams.closed";
  }>): void {
    switch (event.type) {
      case "guest.spawn.stdout":
        this.#stdout.push(event.data);
        return;
      case "guest.spawn.stderr":
        this.#stderr.push(event.data);
        return;
      case "guest.spawn.exit":
        this.#exited = true;
        this.#resolveExit({ exitCode: event.exitCode });
        return;
      case "guest.spawn.streams.closed":
        this.#stdout.close();
        this.#stderr.close();
        return;
    }
  }

  fail(error: unknown): void {
    this.#exited = true;
    this.#stdout.close(error);
    this.#stderr.close(error);
    this.#rejectExit(error);
  }
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
