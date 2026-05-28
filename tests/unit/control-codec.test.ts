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
  });

  const frameLength = new DataView(packet.buffer, packet.byteOffset, 4).getUint32(0, true);
  assert.equal(packet.byteLength, 4 + frameLength);
  assert.deepEqual(BSON.deserialize(packet.subarray(4)), {
    type: "guest.exec",
    id: "test",
    argv: ["/bin/true"],
    env: [{ key: "FOO", value: "bar" }],
  });
});

test("control command codec encodes guest spawn commands", () => {
  const packet = encodeControlCommand({
    type: "guest.spawn",
    id: "spawn",
    argv: ["/bin/cat"],
    env: { FOO: "bar" },
  });

  assert.deepEqual(BSON.deserialize(packet.subarray(4)), {
    type: "guest.spawn",
    id: "spawn",
    argv: ["/bin/cat"],
    env: [{ key: "FOO", value: "bar" }],
  });
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
        exitCode: 7,
      }),
    ),
    {
      type: "guest.spawn.exit",
      id: "spawn",
      exitCode: 7,
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
