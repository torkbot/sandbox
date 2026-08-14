import { AsyncLocalStorage } from "node:async_hooks";
import { Duplex } from "node:stream";
import type { Socket } from "node:net";
import {
  Agent,
  Request,
  fetch as undiciFetch,
  type buildConnector,
  type Response,
} from "undici";
import type { ControlBackedGuestConnection, SandboxControl } from "./control.ts";

const MAX_READ_BYTES = 1024 * 1024;
const CONNECT_TIMEOUT_MS = 10_000;

export class GuestFetch {
  readonly #agent: Agent;
  readonly #requestSignal = new AsyncLocalStorage<AbortSignal>();

  constructor(control: SandboxControl) {
    this.#agent = new Agent({
      allowH2: false,
      connect: guestConnector(control, this.#requestSignal),
    });
  }

  async fetch(request: Request): Promise<Response> {
    if (!(request instanceof Request)) {
      throw new TypeError("sandbox.fetch requires the Request exported by @torkbot/sandbox");
    }
    return await this.#requestSignal.run(
      request.signal,
      async () => await undiciFetch(request, { dispatcher: this.#agent }),
    );
  }

  async close(): Promise<void> {
    await this.#agent.destroy();
  }
}

function guestConnector(
  control: SandboxControl,
  requestSignal: AsyncLocalStorage<AbortSignal>,
): buildConnector.connector {
  return (options, callback) => {
    const port = Number(options.port || (options.protocol === "https:" ? 443 : 80));
    const secure = options.protocol === "https:";
    const connection = control.openConnection({
      hostname: options.hostname,
      port,
      secure,
      timeoutMs: CONNECT_TIMEOUT_MS,
      ...(options.servername === undefined ? {} : { serverName: options.servername }),
    });
    const socket = new GuestSocket(connection, {
      hostname: options.hostname,
      port,
      secure,
    }, requestSignal.getStore());
    const absorbConnectError = () => {};
    socket.on("error", absorbConnectError);
    void connection.opened.then(
      () => {
        socket.off("error", absorbConnectError);
        callback(null, socket as unknown as Socket);
      },
      (error: unknown) => callback(asError(error), null),
    );
  };
}

class GuestSocket extends Duplex {
  readonly remoteAddress: string;
  readonly remotePort: number;
  readonly encrypted: boolean;
  readonly alpnProtocol: "http/1.1" | undefined;

  readonly #connection: ControlBackedGuestConnection;
  #reading = false;
  readonly #connectTimeout: NodeJS.Timeout;
  readonly #connectSignal: AbortSignal | undefined;
  readonly #onConnectAbort: (() => void) | undefined;

  constructor(
    connection: ControlBackedGuestConnection,
    endpoint: {
      readonly hostname: string;
      readonly port: number;
      readonly secure: boolean;
    },
    connectSignal: AbortSignal | undefined,
  ) {
    super({ allowHalfOpen: false, readableHighWaterMark: 64 * 1024, writableHighWaterMark: 64 * 1024 });
    this.#connection = connection;
    this.remoteAddress = endpoint.hostname;
    this.remotePort = endpoint.port;
    this.encrypted = endpoint.secure;
    this.alpnProtocol = endpoint.secure ? "http/1.1" : undefined;
    this.#connectSignal = connectSignal;
    this.#onConnectAbort = connectSignal === undefined
      ? undefined
      : () => this.destroy(asError(connectSignal.reason));
    if (this.#onConnectAbort !== undefined) {
      connectSignal?.addEventListener("abort", this.#onConnectAbort, { once: true });
    }
    connection.onError((error) => this.destroy(error));
    this.#connectTimeout = setTimeout(() => {
      this.destroy(new Error(`sandbox guest connection timed out after ${CONNECT_TIMEOUT_MS} ms`));
    }, CONNECT_TIMEOUT_MS);
    this.#connectTimeout.unref();
    void connection.opened.then(
      () => this.#finishConnecting(),
      () => this.#finishConnecting(),
    );
  }

  override _read(size: number): void {
    if (this.#reading) {
      return;
    }
    this.#reading = true;
    void this.#connection.read(Math.max(1, Math.min(size, MAX_READ_BYTES))).then(
      (data) => {
        this.#reading = false;
        if (data === null) {
          this.push(null);
          return;
        }
        this.push(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
      },
      (error: unknown) => {
        this.#reading = false;
        this.destroy(asError(error));
      },
    );
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const data = typeof chunk === "string" ? Buffer.from(chunk, encoding) : chunk;
    void this.#connection.write(data).then(
      () => callback(),
      (error: unknown) => callback(asError(error)),
    );
  }

  override _destroy(error: Error | null, callback: (error?: Error | null) => void): void {
    this.#finishConnecting();
    this.#connection.close();
    callback(error);
  }

  #finishConnecting(): void {
    clearTimeout(this.#connectTimeout);
    if (this.#onConnectAbort !== undefined) {
      this.#connectSignal?.removeEventListener("abort", this.#onConnectAbort);
    }
  }

  setNoDelay(_noDelay?: boolean): this {
    return this;
  }

  setKeepAlive(_enable?: boolean, _initialDelay?: number): this {
    return this;
  }

  ref(): this {
    return this;
  }

  unref(): this {
    return this;
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}
