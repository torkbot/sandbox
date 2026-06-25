import type {
  SandboxControlCommand,
  SandboxControlEvent,
  SandboxControlFsCommand,
} from "./control-codec.ts";
import {
  decodeControlEvent,
  encodeControlCommand,
} from "./control-codec.ts";

type SandboxControlFsRequest = SandboxControlFsCommand extends infer T
  ? T extends SandboxControlFsCommand
    ? Omit<T, "id">
    : never
  : never;

export interface SandboxControl extends Transport<SandboxControlEvent, SandboxControlCommand> {
  requestFileSystem(
    command: SandboxControlFsRequest,
  ): Promise<Extract<SandboxControlEvent, { type: "guest.fs.response" }>>;
  exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly cwd: string;
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>;
  spawn(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly cwd: string;
  }): ControlBackedSandboxProcess;
  pty(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly cwd: string;
    readonly size: { readonly rows: number; readonly cols: number };
  }): ControlBackedSandboxPty;
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

type SandboxProcessSignal = "SIGHUP" | "SIGINT" | "SIGQUIT" | "SIGTERM" | "SIGKILL";

const MAX_PTY_SIZE = 65_535;

export class HostControlTransport implements SandboxControl {
  readonly incoming: AsyncIterable<SandboxControlEvent>;

  readonly #events: AsyncQueue<SandboxControlEvent>;
  readonly #connected: boolean;
  readonly #channel: HostControlChannel | null;
  readonly #pendingExec = new Map<string, {
    resolve(event: Extract<SandboxControlEvent, { type: "guest.exec.complete" }>): void;
    reject(error: unknown): void;
    aborted: boolean;
  }>();
  readonly #pendingSpawn = new Map<string, {
    resolve(): void;
    reject(error: unknown): void;
    process: ControlBackedSandboxProcess | ControlBackedSandboxPty;
    ready: boolean;
    exited: boolean;
    streamsClosed: boolean;
  }>();
  readonly #pendingFileSystem = new Map<string, {
    resolve(event: Extract<SandboxControlEvent, { type: "guest.fs.response" }>): void;
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

  async requestFileSystem(
    command: SandboxControlFsRequest,
  ): Promise<Extract<SandboxControlEvent, { type: "guest.fs.response" }>> {
    this.#assertOpen();
    const id = crypto.randomUUID();
    const completion = new Promise<Extract<SandboxControlEvent, { type: "guest.fs.response" }>>((resolve, reject) => {
      this.#pendingFileSystem.set(id, { resolve, reject });
    });
    try {
      await this.send({ ...command, id } as SandboxControlFsCommand);
    } catch (error) {
      this.#pendingFileSystem.delete(id);
      throw error;
    }
    return await completion;
  }

  async exec(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly cwd: string;
    readonly timeoutMs?: number;
    readonly signal?: AbortSignal;
  }): Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>> {
    this.#assertOpen();
    throwIfAborted(input.signal);
    const id = input.id ?? crypto.randomUUID();
    if (this.#pendingExec.has(id)) {
      throw new Error(`sandbox exec id is already in flight: ${id}`);
    }
    let abortListener: (() => void) | undefined;
    const completion = new Promise<Extract<SandboxControlEvent, { type: "guest.exec.complete" }>>((resolve, reject) => {
      this.#pendingExec.set(id, {
        aborted: false,
        resolve: (event) => {
          if (abortListener !== undefined) {
            input.signal?.removeEventListener("abort", abortListener);
          }
          resolve(event);
        },
        reject: (error) => {
          if (abortListener !== undefined) {
            input.signal?.removeEventListener("abort", abortListener);
          }
          reject(error);
        },
      });
    });
    abortListener = () => {
      if (input.signal?.aborted !== true) {
        return;
      }
      const pending = this.#pendingExec.get(id);
      if (pending === undefined) {
        return;
      }
      if (pending.aborted) {
        return;
      }
      pending.aborted = true;
      void this.send({ type: "guest.exec.abort", id }).catch(() => {});
      pending.reject(abortError(input.signal));
    };
    input.signal?.addEventListener("abort", abortListener, { once: true });
    try {
      await this.send({
        type: "guest.exec",
        id,
        argv: input.argv,
        env: input.env,
        cwd: input.cwd,
        timeoutMs: input.timeoutMs,
      });
    } catch (error) {
      this.#pendingExec.delete(id);
      if (abortListener !== undefined) {
        input.signal?.removeEventListener("abort", abortListener);
      }
      throw error;
    }
    if (input.signal?.aborted === true) {
      abortListener();
    }
    return await completion;
  }

  spawn(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly cwd: string;
  }): ControlBackedSandboxProcess {
    this.#assertOpen();
    const id = input.id ?? crypto.randomUUID();
    if (this.#pendingSpawn.has(id)) {
      throw new Error(`sandbox spawn id is already in flight: ${id}`);
    }
    const process = new ControlBackedSandboxProcess(id, this);
    this.#pendingSpawn.set(id, {
      resolve: () => process.resolveReady(),
      reject: (error) => process.fail(error),
      process,
      ready: false,
      exited: false,
      streamsClosed: false,
    });
    void this.send({
        type: "guest.spawn",
        id,
        argv: input.argv,
        env: input.env,
        cwd: input.cwd,
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      }).catch((error) => {
        this.#pendingSpawn.delete(id);
        process.fail(error);
      });
    return process;
  }

  pty(input: {
    readonly id?: string;
    readonly argv: readonly string[];
    readonly env?: Record<string, string>;
    readonly cwd: string;
    readonly size: { readonly rows: number; readonly cols: number };
  }): ControlBackedSandboxPty {
    this.#assertOpen();
    const id = input.id ?? crypto.randomUUID();
    if (this.#pendingSpawn.has(id)) {
      throw new Error(`sandbox spawn id is already in flight: ${id}`);
    }
    const process = new ControlBackedSandboxPty(id, this);
    this.#pendingSpawn.set(id, {
      resolve: () => process.resolveReady(),
      reject: (error) => process.fail(error),
      process,
      ready: false,
      exited: false,
      streamsClosed: false,
    });
    void this.send({
      type: "guest.spawn",
      id,
      argv: input.argv,
      env: input.env,
      cwd: input.cwd,
      stdin: "pty",
      stdout: "pty",
      stderr: "pty",
      pty: input.size,
    }).catch((error) => {
      this.#pendingSpawn.delete(id);
      process.fail(error);
    });
    return process;
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }

    this.#closed = true;
    this.#rejectPendingExec(new Error("sandbox control is closed"));
    this.#rejectPendingSpawn(new Error("sandbox control is closed"));
    this.#rejectPendingFileSystem(new Error("sandbox control is closed"));
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
    if (event.type === "guest.fs.response") {
      const pending = this.#pendingFileSystem.get(event.id);
      if (pending === undefined) {
        return;
      }
      this.#pendingFileSystem.delete(event.id);
      pending.resolve(event);
      return;
    }
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
      pending.ready = true;
      pending.resolve();
      return;
    }
    if (event.type === "guest.spawn.exit") {
      pending.exited = true;
      if (pending.ready) {
        pending.resolve();
      } else {
        pending.process.rejectReady(new Error(`sandbox spawn exited before ready: ${event.id}`));
      }
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
    this.#rejectPendingFileSystem(error);
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
      pending.process.fail(error);
    }
    this.#pendingSpawn.clear();
  }

  #rejectPendingFileSystem(error: unknown): void {
    for (const pending of this.#pendingFileSystem.values()) {
      pending.reject(error);
    }
    this.#pendingFileSystem.clear();
  }
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) {
    throw abortError(signal);
  }
}

function abortError(signal: AbortSignal | undefined): Error {
  const reason = signal?.reason;
  if (reason instanceof Error) {
    return reason;
  }
  const error = new Error("sandbox exec aborted");
  error.name = "AbortError";
  return error;
}

export class ControlBackedSandboxProcess {
  readonly stdin: WritableStream<Uint8Array>;
  readonly stdout: ReadableStream<Uint8Array>;
  readonly stderr: ReadableStream<Uint8Array>;
  readonly ready: Promise<void>;
  readonly exit: Promise<{ readonly exitCode: number | null; readonly signal: SandboxProcessSignal | null }>;

  readonly #id: string;
  readonly #control: SandboxControl;
  readonly #stdin: ControlWritable;
  readonly #stdout = new ReadableByteQueue();
  readonly #stderr = new ReadableByteQueue();
  #resolveReady!: () => void;
  #rejectReady!: (error: unknown) => void;
  #resolveExit!: (result: { readonly exitCode: number | null; readonly signal: SandboxProcessSignal | null }) => void;
  #rejectExit!: (error: unknown) => void;
  #exited = false;

  constructor(id: string, control: SandboxControl) {
    this.#id = id;
    this.#control = control;
    this.#stdin = new ControlWritable(control, id);
    this.stdin = this.#stdin.stream;
    this.stdout = this.#stdout.stream;
    this.stderr = this.#stderr.stream;
    this.ready = new Promise((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
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
        this.#stdout.enqueue(event.data);
        return;
      case "guest.spawn.stderr":
        this.#stderr.enqueue(event.data);
        return;
      case "guest.spawn.exit":
        this.#exited = true;
        this.#resolveExit({ exitCode: event.exitCode, signal: readSpawnSignal(event.signal) });
        return;
      case "guest.spawn.streams.closed":
        this.#stdin.closeFromGuest(new Error(`sandbox process stdin is closed: ${this.#id}`));
        this.#stdout.close();
        this.#stderr.close();
        return;
    }
  }

  resolveReady(): void {
    this.#resolveReady();
  }

  rejectReady(error: unknown): void {
    this.#rejectReady(error);
  }

  kill(signal: SandboxProcessSignal = "SIGTERM"): void {
    void this.#control.send({ type: "guest.spawn.signal", id: this.#id, signal }).catch((error) => {
      this.fail(error);
    });
  }

  fail(error: unknown): void {
    this.#exited = true;
    this.#stdin.closeFromGuest(error);
    this.#stdout.close(error);
    this.#stderr.close(error);
    this.#rejectReady(error);
    this.#rejectExit(error);
  }
}

export class ControlBackedSandboxPty {
  readonly input: WritableStream<Uint8Array>;
  readonly output: ReadableStream<Uint8Array>;
  readonly ready: Promise<void>;
  readonly exit: Promise<{ readonly exitCode: number | null; readonly signal: SandboxProcessSignal | null }>;

  readonly #id: string;
  readonly #control: SandboxControl;
  readonly #input: ControlWritable;
  readonly #output = new ReadableByteQueue();
  #resolveReady!: () => void;
  #rejectReady!: (error: unknown) => void;
  #resolveExit!: (result: { readonly exitCode: number | null; readonly signal: SandboxProcessSignal | null }) => void;
  #rejectExit!: (error: unknown) => void;

  constructor(id: string, control: SandboxControl) {
    this.#id = id;
    this.#control = control;
    this.#input = new ControlWritable(control, id);
    this.input = this.#input.stream;
    this.output = this.#output.stream;
    this.ready = new Promise((resolve, reject) => {
      this.#resolveReady = resolve;
      this.#rejectReady = reject;
    });
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
      case "guest.spawn.stderr":
        this.#output.enqueue(event.data);
        return;
      case "guest.spawn.exit":
        this.#resolveExit({ exitCode: event.exitCode, signal: readSpawnSignal(event.signal) });
        return;
      case "guest.spawn.streams.closed":
        this.#input.closeFromGuest(new Error(`sandbox pty input is closed: ${this.#id}`));
        this.#output.close();
        return;
    }
  }

  resolveReady(): void {
    this.#resolveReady();
  }

  rejectReady(error: unknown): void {
    this.#rejectReady(error);
  }

  resize(size: { readonly rows: number; readonly cols: number }): void {
    validatePtySize(size, "invalid sandbox pty resize");
    void this.#control.send({
      type: "guest.spawn.resize",
      id: this.#id,
      rows: size.rows,
      cols: size.cols,
    }).catch((error) => {
      this.fail(error);
    });
  }

  kill(signal: SandboxProcessSignal = "SIGTERM"): void {
    void this.#control.send({ type: "guest.spawn.signal", id: this.#id, signal }).catch((error) => {
      this.fail(error);
    });
  }

  fail(error: unknown): void {
    this.#input.closeFromGuest(error);
    this.#output.close(error);
    this.#rejectReady(error);
    this.#rejectExit(error);
  }
}

function readSpawnSignal(signal: string | undefined): SandboxProcessSignal | null {
  if (signal === undefined) {
    return null;
  }
  switch (signal) {
    case "SIGHUP":
    case "SIGINT":
    case "SIGQUIT":
    case "SIGTERM":
    case "SIGKILL":
      return signal;
    default:
      throw new Error(`unknown sandbox process signal: ${signal}`);
  }
}

class ControlWritable {
  readonly stream: WritableStream<Uint8Array>;
  readonly #control: SandboxControl;
  readonly #id: string;
  #controller: WritableStreamDefaultController | null = null;
  #closed = false;

  constructor(control: SandboxControl, id: string) {
    this.#control = control;
    this.#id = id;
    this.stream = new WritableStream<Uint8Array>({
      start: (controller) => {
        this.#controller = controller;
      },
      write: async (chunk) => {
        if (this.#closed) {
          throw new Error(`sandbox process stdin is closed: ${this.#id}`);
        }
        await this.#control.send({ type: "guest.spawn.stdin", id: this.#id, data: chunk });
      },
      close: async () => {
        if (this.#closed) {
          return;
        }
        this.#closed = true;
        await this.#control.send({ type: "guest.spawn.stdin.close", id: this.#id });
      },
      abort: async () => {
        if (this.#closed) {
          return;
        }
        this.#closed = true;
        await this.#control.send({ type: "guest.spawn.stdin.close", id: this.#id });
      },
    });
  }

  closeFromGuest(error: unknown): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#controller?.error(error);
    this.#controller = null;
  }
}

class ReadableByteQueue {
  readonly stream: ReadableStream<Uint8Array>;
  #controller: ReadableStreamDefaultController<Uint8Array> | null = null;
  #closed = false;

  constructor() {
    this.stream = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#controller = controller;
      },
      cancel: () => {
        this.#closed = true;
        this.#controller = null;
      },
    });
  }

  enqueue(chunk: Uint8Array): void {
    if (this.#closed) {
      return;
    }
    try {
      this.#controller?.enqueue(chunk);
    } catch {
      this.#closed = true;
      this.#controller = null;
    }
  }

  close(error?: unknown): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    if (error === undefined) {
      this.#controller?.close();
    } else {
      this.#controller?.error(error);
    }
  }
}

function validatePtySize(size: { readonly rows: number; readonly cols: number }, field: string): void {
  if (!Number.isSafeInteger(size.rows) || size.rows <= 0 || size.rows > MAX_PTY_SIZE) {
    throw new Error(`${field}.rows must be an integer between 1 and ${MAX_PTY_SIZE}`);
  }
  if (!Number.isSafeInteger(size.cols) || size.cols <= 0 || size.cols > MAX_PTY_SIZE) {
    throw new Error(`${field}.cols must be an integer between 1 and ${MAX_PTY_SIZE}`);
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
