import test from "node:test";
import assert from "node:assert/strict";
import { Binary, BSON } from "bson";
import {
  decodeControlEvent,
  encodeControlCommand,
} from "../../src/control-codec.ts";

test("control command codec emits length-prefixed BSON", () => {
  const packet = encodeControlCommand({
    type: "guest.exec",
    id: "test",
    argv: ["/bin/true"],
    env: { FOO: "bar" },
    cwd: "/workspace",
  });

  const frameLength = new DataView(packet.buffer, packet.byteOffset, 4).getUint32(0, true);
  assert.equal(packet.byteLength, 4 + frameLength);
  assert.deepEqual(BSON.deserialize(packet.subarray(4)), {
    type: "guest.exec",
    id: "test",
    argv: ["/bin/true"],
    env: [{ key: "FOO", value: "bar" }],
    cwd: "/workspace",
  });
});

test("control command codec encodes guest spawn commands", () => {
  const packet = encodeControlCommand({
    type: "guest.spawn",
    id: "spawn",
    argv: ["/bin/cat"],
    env: { FOO: "bar" },
    cwd: "/workspace",
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });

  assert.deepEqual(BSON.deserialize(packet.subarray(4)), {
    type: "guest.spawn",
    id: "spawn",
    argv: ["/bin/cat"],
    env: [{ key: "FOO", value: "bar" }],
    cwd: "/workspace",
    stdin: "pipe",
    stdout: "pipe",
    stderr: "pipe",
  });
});

test("control command codec encodes guest exec abort commands", () => {
  const packet = encodeControlCommand({
    type: "guest.exec.abort",
    id: "exec",
  });

  assert.deepEqual(BSON.deserialize(packet.subarray(4)), {
    type: "guest.exec.abort",
    id: "exec",
  });
});

test("control command codec encodes guest filesystem commands", () => {
  assert.deepEqual(
    BSON.deserialize(encodeControlCommand({
      type: "guest.fs.readFile",
      id: "read",
      path: "/tmp/input.txt",
      range: { offset: 6, length: 5 },
    }).subarray(4)),
    {
      type: "guest.fs.readFile",
      id: "read",
      path: "/tmp/input.txt",
      offset: 6,
      length: 5,
    },
  );

  assert.deepEqual(
    BSON.deserialize(encodeControlCommand({
      type: "guest.fs.writeFile",
      id: "write",
      path: "/tmp/output.txt",
      contents: new TextEncoder().encode("contents"),
      createParents: true,
    }).subarray(4)),
    {
      type: "guest.fs.writeFile",
      id: "write",
      path: "/tmp/output.txt",
      contents: new Binary(new TextEncoder().encode("contents")),
      createParents: true,
    },
  );

  const largeContents = new Uint8Array(18 * 1024 * 1024);
  largeContents.fill(7);
  const largeWrite = BSON.deserialize(encodeControlCommand({
    type: "guest.fs.writeFile",
    id: "large-write",
    path: "/tmp/large.bin",
    contents: largeContents,
    createParents: false,
  }).subarray(4));
  assert.equal(largeWrite.type, "guest.fs.writeFile");
  assert.equal(largeWrite.path, "/tmp/large.bin");
  assert.ok(largeWrite.contents instanceof Binary);
  assert.equal(largeWrite.contents.buffer.byteLength, largeContents.byteLength);

  assert.deepEqual(
    BSON.deserialize(encodeControlCommand({
      type: "guest.fs.remove",
      id: "remove",
      path: "/tmp/tree",
      recursive: true,
      force: false,
    }).subarray(4)),
    {
      type: "guest.fs.remove",
      id: "remove",
      path: "/tmp/tree",
      recursive: true,
      force: false,
    },
  );

  assert.deepEqual(
    BSON.deserialize(encodeControlCommand({
      type: "guest.fs.rename",
      id: "rename",
      from: "/tmp/source",
      to: "/tmp/target",
    }).subarray(4)),
    {
      type: "guest.fs.rename",
      id: "rename",
      from: "/tmp/source",
      to: "/tmp/target",
    },
  );
});

test("control event codec decodes init ready and binary exec output", () => {
  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "init.ready",
        rootReadonly: true,
        initName: "sandbox-init",
      }),
    ),
    {
      type: "init.ready",
      guest: {
        root: { readonly: true },
        init: { name: "sandbox-init" },
      },
    },
  );

  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "guest.exec.complete",
        id: "test",
        exitCode: 0,
        stdout: new Binary(new TextEncoder().encode("ok\n")),
        stderr: new Binary(new Uint8Array()),
      }),
    ),
    {
      type: "guest.exec.complete",
      id: "test",
      exitCode: 0,
      stdout: "ok\n",
      stderr: "",
    },
  );

  const stdout = decodeControlEvent(
    encodePacket({
      type: "guest.spawn.stdout",
      id: "spawn",
      data: new Binary(new Uint8Array([0, 1, 2])),
    }),
  );
  assert.equal(stdout.type, "guest.spawn.stdout");
  assert.equal(stdout.id, "spawn");
  assert.deepEqual([...stdout.data], [0, 1, 2]);

  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "guest.spawn.exit",
        id: "spawn",
        signal: "SIGKILL",
      }),
    ),
    {
      type: "guest.spawn.exit",
      id: "spawn",
      exitCode: null,
      signal: "SIGKILL",
    },
  );

  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "guest.spawn.streams.closed",
        id: "spawn",
      }),
    ),
    {
      type: "guest.spawn.streams.closed",
      id: "spawn",
    },
  );

});

test("control event codec decodes guest filesystem responses", () => {
  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "guest.fs.response",
        id: "stat",
        ok: true,
        stat: {
          type: "file",
          sizeBytes: 7,
          modifiedAtMs: 12_345,
        },
      }),
    ),
    {
      type: "guest.fs.response",
      id: "stat",
      result: {
        ok: true,
        stat: {
          type: "file",
          sizeBytes: 7,
          modifiedAtMs: 12_345,
        },
      },
    },
  );

  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "guest.fs.response",
        id: "list",
        ok: true,
        entries: [
          {
            name: "a.txt",
            nameBytes: new Binary(new TextEncoder().encode("a.txt")),
            stat: {
              type: "file",
              sizeBytes: 5,
              modifiedAtMs: 1,
            },
          },
        ],
      }),
    ),
    {
      type: "guest.fs.response",
      id: "list",
      result: {
        ok: true,
        entries: [
          {
            name: "a.txt",
            nameBytes: Buffer.from("a.txt"),
            stat: {
              type: "file",
              sizeBytes: 5,
              modifiedAtMs: 1,
            },
          },
        ],
      },
    },
  );

  const read = decodeControlEvent(
    encodePacket({
      type: "guest.fs.response",
      id: "read",
      ok: true,
      contents: new Binary(new TextEncoder().encode("hello")),
    }),
  );
  assert.equal(read.type, "guest.fs.response");
  assert.equal(read.id, "read");
  assert.equal(read.result.ok, true);
  assert.deepEqual(
    read.result.ok && read.result.contents !== undefined
      ? [...read.result.contents]
      : undefined,
    [...new TextEncoder().encode("hello")],
  );

  assert.deepEqual(
    decodeControlEvent(
      encodePacket({
        type: "guest.fs.response",
        id: "missing",
        ok: false,
        error: "not found",
        code: "ENOENT",
      }),
    ),
    {
      type: "guest.fs.response",
      id: "missing",
      result: {
        ok: false,
        error: {
          message: "not found",
          code: "ENOENT",
        },
      },
    },
  );
});

test("control event codec rejects malformed packets", () => {
  assert.throws(
    () => decodeControlEvent(new Uint8Array([0, 1, 2])),
    /control packet missing length prefix/,
  );

  const packet = encodePacket({ type: "unknown" });
  assert.throws(
    () => decodeControlEvent(packet),
    /unknown control frame type: unknown/,
  );
});

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document);
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}
