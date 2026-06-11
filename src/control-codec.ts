import { Binary, BSON } from "bson";

export type SandboxControlEvent =
  | {
      readonly type: "init.ready";
      readonly guest: {
        readonly root: { readonly readonly: boolean };
        readonly init: { readonly name: string };
      };
    }
  | {
      readonly type: "guest.exec.complete";
      readonly id: string;
      readonly exitCode: number;
      readonly stdout: string;
      readonly stderr: string;
    }
  | {
      readonly type: "guest.spawn.stdout" | "guest.spawn.stderr";
      readonly id: string;
      readonly data: Uint8Array;
    }
  | {
      readonly type: "guest.spawn.started";
      readonly id: string;
    }
  | {
      readonly type: "guest.spawn.exit";
      readonly id: string;
      readonly exitCode: number | null;
      readonly signal?: string;
    }
  | {
      readonly type: "guest.spawn.streams.closed";
      readonly id: string;
    };

export type SandboxControlCommand =
  | {
      readonly type: "guest.exec";
      readonly id: string;
      readonly argv: readonly string[];
      readonly env?: Record<string, string>;
      readonly timeoutMs?: number;
    }
  | {
      readonly type: "guest.exec.abort";
      readonly id: string;
    }
  | {
      readonly type: "guest.spawn";
      readonly id: string;
      readonly argv: readonly string[];
      readonly env?: Record<string, string>;
      readonly stdin: "pipe" | "pty";
      readonly stdout: "pipe" | "pty";
      readonly stderr: "pipe" | "pty";
      readonly pty?: {
        readonly rows: number;
        readonly cols: number;
      };
    }
  | {
      readonly type: "guest.spawn.stdin";
      readonly id: string;
      readonly data: Uint8Array;
    }
  | {
      readonly type: "guest.spawn.stdin.close";
      readonly id: string;
    }
  | {
      readonly type: "guest.spawn.signal";
      readonly id: string;
      readonly signal: string;
    }
  | {
      readonly type: "guest.spawn.resize";
      readonly id: string;
      readonly rows: number;
      readonly cols: number;
    }
;

export function encodeControlCommand(command: SandboxControlCommand): Uint8Array {
  switch (command.type) {
    case "guest.exec":
      return encodePacket({
        type: "guest.exec",
        id: command.id,
        argv: [...command.argv],
        env: Object.entries(command.env ?? {}).map(([key, value]) => ({ key, value })),
        ...(command.timeoutMs === undefined ? {} : { timeoutMs: command.timeoutMs }),
      });
    case "guest.exec.abort":
      return encodePacket({
        type: "guest.exec.abort",
        id: command.id,
      });
    case "guest.spawn":
      return encodePacket({
        type: "guest.spawn",
        id: command.id,
        argv: [...command.argv],
        env: Object.entries(command.env ?? {}).map(([key, value]) => ({ key, value })),
        stdin: command.stdin,
        stdout: command.stdout,
        stderr: command.stderr,
        ...(command.pty === undefined ? {} : { pty: { rows: command.pty.rows, cols: command.pty.cols } }),
      });
    case "guest.spawn.stdin":
      return encodePacket({
        type: "guest.spawn.stdin",
        id: command.id,
        data: new Binary(command.data),
      });
    case "guest.spawn.stdin.close":
      return encodePacket({
        type: "guest.spawn.stdin.close",
        id: command.id,
      });
    case "guest.spawn.signal":
      return encodePacket({
        type: "guest.spawn.signal",
        id: command.id,
        signal: command.signal,
      });
    case "guest.spawn.resize":
      return encodePacket({
        type: "guest.spawn.resize",
        id: command.id,
        rows: command.rows,
        cols: command.cols,
      });
  }
}

export function decodeControlEvent(packet: Uint8Array): SandboxControlEvent {
  const document = decodePacket(packet);
  const frameType = readString(document, "type");

  switch (frameType) {
    case "init.ready":
      return {
        type: "init.ready",
        guest: {
          root: { readonly: readBoolean(document, "rootReadonly") },
          init: { name: readString(document, "initName") },
        },
      };
    case "guest.exec.complete":
      return {
        type: "guest.exec.complete",
        id: readString(document, "id"),
        exitCode: readNumber(document, "exitCode"),
        stdout: new TextDecoder().decode(readBytes(document, "stdout")),
        stderr: new TextDecoder().decode(readBytes(document, "stderr")),
      };
    case "guest.spawn.stdout":
    case "guest.spawn.stderr":
      return {
        type: frameType,
        id: readString(document, "id"),
        data: readBytes(document, "data"),
      };
    case "guest.spawn.started":
      return {
        type: "guest.spawn.started",
        id: readString(document, "id"),
      };
    case "guest.spawn.exit":
      return {
        type: "guest.spawn.exit",
        id: readString(document, "id"),
        exitCode: readOptionalNumber(document, "exitCode"),
        ...optionalStringField(document, "signal"),
      };
    case "guest.spawn.streams.closed":
      return {
        type: "guest.spawn.streams.closed",
        id: readString(document, "id"),
      };
    default:
      throw new Error(`unknown control frame type: ${frameType}`);
  }
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document);
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}

function decodePacket(packet: Uint8Array): Record<string, unknown> {
  if (packet.byteLength < 4) {
    throw new Error("control packet missing length prefix");
  }

  const frameLength = new DataView(packet.buffer, packet.byteOffset, 4).getUint32(0, true);
  if (packet.byteLength < 4 + frameLength) {
    throw new Error("control packet body is truncated");
  }
  if (packet.byteLength !== 4 + frameLength) {
    throw new Error("control packet has trailing bytes");
  }

  return BSON.deserialize(packet.subarray(4)) as Record<string, unknown>;
}

function readString(document: Record<string, unknown>, key: string): string {
  const value = document[key];
  if (typeof value !== "string") {
    throw new Error(`control frame field must be a string: ${key}`);
  }
  return value;
}

function optionalStringField(document: Record<string, unknown>, key: string): Record<string, string> {
  const value = document[key];
  if (value === undefined) {
    return {};
  }
  if (typeof value !== "string") {
    throw new Error(`control frame field must be a string: ${key}`);
  }
  return { [key]: value };
}

function readBoolean(document: Record<string, unknown>, key: string): boolean {
  const value = document[key];
  if (typeof value !== "boolean") {
    throw new Error(`control frame field must be a boolean: ${key}`);
  }
  return value;
}

function readNumber(document: Record<string, unknown>, key: string): number {
  const value = document[key];
  if (typeof value !== "number") {
    throw new Error(`control frame field must be a number: ${key}`);
  }
  return value;
}

function readOptionalNumber(document: Record<string, unknown>, key: string): number | null {
  if (!(key in document)) {
    return null;
  }
  return readNumber(document, key);
}

function readBytes(document: Record<string, unknown>, key: string): Uint8Array {
  const value = document[key];
  if (value instanceof Binary) {
    return value.buffer;
  }
  if (value instanceof Uint8Array) {
    return value;
  }
  throw new Error(`control frame field must be binary: ${key}`);
}
