import test from "node:test";
import assert from "node:assert/strict";
import { Binary, BSON } from "bson";
import {
  HostControlTransport,
  type HostControlChannel,
} from "../../src/control.ts";

test("HostControlTransport yields emitted events", async () => {
  const control = new HostControlTransport();
  const next = control.incoming[Symbol.asyncIterator]().next();

  control.emit({
    type: "init.ready",
    guest: {
      root: { readonly: true },
      init: { name: "sandbox-init" },
    },
  });

  assert.deepEqual(await next, {
    done: false,
    value: {
      type: "init.ready",
      guest: {
        root: { readonly: true },
        init: { name: "sandbox-init" },
      },
    },
  });
});

test("HostControlTransport closes its event stream", async () => {
  const control = new HostControlTransport();
  const iterator = control.incoming[Symbol.asyncIterator]();

  await control.close();

  assert.deepEqual(await iterator.next(), {
    done: true,
    value: undefined,
  });
});

test("HostControlTransport fails sends until native channel is connected", async () => {
  const control = new HostControlTransport();

  await assert.rejects(
    control.exec({ id: "test", argv: ["/bin/true"] }),
    /sandbox control send is not connected yet/,
  );
});

test("HostControlTransport sends commands as packets", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });

  await control.send({
    type: "guest.exec",
    id: "test",
    argv: ["/bin/true"],
  });

  const write = channel.writes[0];
  assert.ok(write);
  assert.deepEqual(BSON.deserialize(write.subarray(4)), {
    type: "guest.exec",
    id: "test",
    argv: ["/bin/true"],
  });
  await control.close();
});

test("HostControlTransport pumps native packets into incoming events", async () => {
  const channel = new MemoryControlChannel();
  channel.reads.push(
    encodePacket({
      type: "init.ready",
      rootReadonly: true,
      initName: "sandbox-init",
    }),
  );
  const control = new HostControlTransport({ channel });

  assert.deepEqual(await control.incoming[Symbol.asyncIterator]().next(), {
    done: false,
    value: {
      type: "init.ready",
      guest: {
        root: { readonly: true },
        init: { name: "sandbox-init" },
      },
    },
  });
  await control.close();
});

test("HostControlTransport exec waits for matching completion", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const exec = control.exec({ id: "test", argv: ["/bin/true"] });

  channel.reads.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "test",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("ok\n")),
      stderr: new Binary(new Uint8Array()),
    }),
  );

  assert.deepEqual(await exec, {
    type: "guest.exec.complete",
    id: "test",
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
  });
  await control.close();
});

class MemoryControlChannel implements HostControlChannel {
  readonly writes: Uint8Array[] = [];
  readonly reads: Uint8Array[] = [];

  writeControlPacket(packet: Uint8Array): void {
    this.writes.push(packet);
  }

  tryReadControlPacket(): Uint8Array | null {
    return this.reads.shift() ?? null;
  }
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document);
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}
