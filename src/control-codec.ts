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
    }
  | {
      readonly type: "guest.fs.response";
      readonly id: string;
      readonly result:
        | {
            readonly ok: true;
            readonly stat?: SandboxControlFsStat;
            readonly entries?: readonly SandboxControlFsDirectoryEntry[];
            readonly contents?: Uint8Array;
          }
        | {
            readonly ok: false;
            readonly error: {
              readonly message: string;
              readonly code?: string;
            };
          };
    };

export type SandboxControlFsStat = {
  readonly type: "file" | "directory" | "symlink" | "other";
  readonly sizeBytes: number;
  readonly modifiedAtMs: number;
};

export type SandboxControlFsDirectoryEntry = {
  readonly name: string;
  readonly nameBytes: Uint8Array;
  readonly stat: SandboxControlFsStat;
};

export type SandboxControlFsCommand =
  | {
      readonly type: "guest.fs.stat";
      readonly id: string;
      readonly path: string;
    }
  | {
      readonly type: "guest.fs.readDir";
      readonly id: string;
      readonly path: string;
    }
  | {
      readonly type: "guest.fs.readFile";
      readonly id: string;
      readonly path: string;
      readonly range?: {
        readonly offset: number;
        readonly length: number;
      };
    }
  | {
      readonly type: "guest.fs.writeFile";
      readonly id: string;
      readonly path: string;
      readonly contents: Uint8Array;
      readonly createParents: boolean;
    }
  | {
      readonly type: "guest.fs.mkdir";
      readonly id: string;
      readonly path: string;
      readonly recursive: boolean;
    }
  | {
      readonly type: "guest.fs.remove";
      readonly id: string;
      readonly path: string;
      readonly recursive: boolean;
      readonly force: boolean;
    }
  | {
      readonly type: "guest.fs.rename";
      readonly id: string;
      readonly from: string;
      readonly to: string;
    };

export type SandboxControlCommand =
  | {
      readonly type: "guest.exec";
      readonly id: string;
      readonly argv: readonly string[];
      readonly env?: Record<string, string>;
      readonly cwd: string;
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
      readonly cwd: string;
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
  | SandboxControlFsCommand
;

export function encodeControlCommand(command: SandboxControlCommand): Uint8Array {
  switch (command.type) {
    case "guest.exec":
      return encodePacket({
        type: "guest.exec",
        id: command.id,
        argv: [...command.argv],
        env: Object.entries(command.env ?? {}).map(([key, value]) => ({ key, value })),
        cwd: command.cwd,
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
        cwd: command.cwd,
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
    case "guest.fs.stat":
      return encodePacket({
        type: "guest.fs.stat",
        id: command.id,
        path: command.path,
      });
    case "guest.fs.readDir":
      return encodePacket({
        type: "guest.fs.readDir",
        id: command.id,
        path: command.path,
      });
    case "guest.fs.readFile":
      return encodePacket({
        type: "guest.fs.readFile",
        id: command.id,
        path: command.path,
        ...(command.range === undefined
          ? {}
          : {
              offset: command.range.offset,
              length: command.range.length,
            }),
      });
    case "guest.fs.writeFile":
      return encodePacket({
        type: "guest.fs.writeFile",
        id: command.id,
        path: command.path,
        contents: new Binary(command.contents),
        createParents: command.createParents,
      });
    case "guest.fs.mkdir":
      return encodePacket({
        type: "guest.fs.mkdir",
        id: command.id,
        path: command.path,
        recursive: command.recursive,
      });
    case "guest.fs.remove":
      return encodePacket({
        type: "guest.fs.remove",
        id: command.id,
        path: command.path,
        recursive: command.recursive,
        force: command.force,
      });
    case "guest.fs.rename":
      return encodePacket({
        type: "guest.fs.rename",
        id: command.id,
        from: command.from,
        to: command.to,
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
    case "guest.fs.response":
      return {
        type: "guest.fs.response",
        id: readString(document, "id"),
        result: readFsResponseResult(document),
      };
    default:
      throw new Error(`unknown control frame type: ${frameType}`);
  }
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frameSize = BSON.calculateObjectSize(document);
  // BSON supports this option at runtime but omits it from the published type.
  const frame = BSON.serialize(document, {
    minInternalBufferSize: frameSize,
  } as Parameters<typeof BSON.serialize>[1] & {
    readonly minInternalBufferSize: number;
  });
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

function readFsResponseResult(document: Record<string, unknown>): Extract<SandboxControlEvent, { type: "guest.fs.response" }>["result"] {
  const ok = readBoolean(document, "ok");
  if (!ok) {
    return {
      ok: false,
      error: {
        message: readString(document, "error"),
        ...optionalStringField(document, "code"),
      },
    };
  }
  return {
    ok: true,
    ...optionalFsStatField(document, "stat"),
    ...optionalFsDirectoryEntriesField(document, "entries"),
    ...optionalBytesField(document, "contents"),
  };
}

function optionalFsStatField(document: Record<string, unknown>, key: string): Record<string, SandboxControlFsStat> {
  const value = document[key];
  if (value === undefined) {
    return {};
  }
  return { [key]: readFsStat(value, key) };
}

function readFsStat(value: unknown, label: string): SandboxControlFsStat {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array || value instanceof Binary) {
    throw new Error(`control frame field must be a document: ${label}`);
  }
  const document = value as Record<string, unknown>;
  const type = readString(document, "type");
  if (type !== "file" && type !== "directory" && type !== "symlink" && type !== "other") {
    throw new Error(`control frame field has invalid filesystem type: ${label}.type`);
  }
  return {
    type,
    sizeBytes: readNumber(document, "sizeBytes"),
    modifiedAtMs: readNumber(document, "modifiedAtMs"),
  };
}

function optionalFsDirectoryEntriesField(
  document: Record<string, unknown>,
  key: string,
): Record<string, readonly SandboxControlFsDirectoryEntry[]> {
  const value = document[key];
  if (value === undefined) {
    return {};
  }
  if (!Array.isArray(value)) {
    throw new Error(`control frame field must be an array: ${key}`);
  }
  return {
    [key]: value.map((entry, index) => readFsDirectoryEntry(entry, `${key}[${index}]`)),
  };
}

function readFsDirectoryEntry(value: unknown, label: string): SandboxControlFsDirectoryEntry {
  if (typeof value !== "object" || value === null || value instanceof Uint8Array || value instanceof Binary) {
    throw new Error(`control frame field must be a document: ${label}`);
  }
  const document = value as Record<string, unknown>;
  return {
    name: readString(document, "name"),
    nameBytes: readBytes(document, "nameBytes"),
    stat: readFsStat(document.stat, `${label}.stat`),
  };
}

function optionalBytesField(document: Record<string, unknown>, key: string): Record<string, Uint8Array> {
  const value = document[key];
  if (value === undefined) {
    return {};
  }
  return { [key]: readBytes(document, key) };
}
