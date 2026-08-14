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

export class GuestFetch {
  readonly #agent: Agent;

  constructor(control: SandboxControl) {
    this.#agent = new Agent({
      allowH2: false,
      connect: guestConnector(control),
    });
  }

  async fetch(request: Request): Promise<Response> {
    if (!(request instanceof Request)) {
      throw new TypeError("sandbox.fetch requires the Request exported by @torkbot/sandbox");
    }
    return await undiciFetch(request, { dispatcher: this.#agent });
  }

  async close(): Promise<void> {
    await this.#agent.destroy();
  }
}

function guestConnector(control: SandboxControl): buildConnector.connector {
  return (options, callback) => {
    const port = Number(options.port || (options.protocol === "https:" ? 443 : 80));
    const secure = options.protocol === "https:";
    const connection = control.openConnection({
      hostname: options.hostname,
      port,
      secure,
      ...(options.servername === undefined ? {} : { serverName: options.servername }),
    });
    const socket = new GuestSocket(connection, {
      hostname: options.hostname,
      port,
      secure,
    });
    void connection.opened.then(
      () => callback(null, socket as unknown as Socket),
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

  constructor(
    connection: ControlBackedGuestConnection,
    endpoint: {
      readonly hostname: string;
      readonly port: number;
      readonly secure: boolean;
    },
  ) {
    super({ allowHalfOpen: false, readableHighWaterMark: 64 * 1024, writableHighWaterMark: 64 * 1024 });
    this.#connection = connection;
    this.remoteAddress = endpoint.hostname;
    this.remotePort = endpoint.port;
    this.encrypted = endpoint.secure;
    this.alpnProtocol = endpoint.secure ? "http/1.1" : undefined;
    connection.onError((error) => this.destroy(error));
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
    this.#connection.close();
    callback(error);
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
