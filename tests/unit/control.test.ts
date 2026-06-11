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
    env: [],
  });
  await control.close();
});

test("HostControlTransport pumps native packets into incoming events", async () => {
  const channel = new MemoryControlChannel();
  channel.packets.push(
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

  channel.packets.push(
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

test("HostControlTransport sends exec timeout to guest", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const exec = control.exec({ id: "test", argv: ["/bin/sleep", "10"], timeoutMs: 250 });

  assert.deepEqual(BSON.deserialize(channel.writes[0]!.subarray(4)), {
    type: "guest.exec",
    id: "test",
    argv: ["/bin/sleep", "10"],
    env: [],
    timeoutMs: 250,
  });

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "test",
      exitCode: 124,
      stdout: new Binary(new Uint8Array()),
      stderr: new Binary(new TextEncoder().encode("sandbox exec timed out after 250ms\n")),
    }),
  );

  assert.equal((await exec).exitCode, 124);
  await control.close();
});

test("HostControlTransport sends exec abort and rejects aborted call", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const abort = new AbortController();
  const exec = control.exec({
    id: "test",
    argv: ["/bin/sleep", "10"],
    signal: abort.signal,
  });

  abort.abort();

  await assert.rejects(exec, { name: "AbortError" });
  assert.deepEqual(
    channel.writes.map((packet) => BSON.deserialize(packet.subarray(4))),
    [
      {
        type: "guest.exec",
        id: "test",
        argv: ["/bin/sleep", "10"],
        env: [],
      },
      {
        type: "guest.exec.abort",
        id: "test",
      },
    ],
  );

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "test",
      exitCode: 130,
      stdout: new Binary(new Uint8Array()),
      stderr: new Binary(new TextEncoder().encode("sandbox exec aborted\n")),
    }),
  );

  const followup = control.exec({ id: "followup", argv: ["/bin/true"] });
  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "followup",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("ok")),
      stderr: new Binary(new Uint8Array()),
    }),
  );
  assert.equal((await followup).stdout, "ok");
  await control.close();
});

test("HostControlTransport keeps aborted exec id reserved until completion arrives", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const abort = new AbortController();
  const exec = control.exec({
    id: "reused",
    argv: ["/bin/sleep", "10"],
    signal: abort.signal,
  });

  abort.abort();
  await assert.rejects(exec, { name: "AbortError" });
  await assert.rejects(
    control.exec({ id: "reused", argv: ["/bin/true"] }),
    /sandbox exec id is already in flight: reused/,
  );

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "reused",
      exitCode: 130,
      stdout: new Binary(new Uint8Array()),
      stderr: new Binary(new TextEncoder().encode("sandbox exec aborted\n")),
    }),
  );
  assert.equal(
    (await control.incoming[Symbol.asyncIterator]().next()).value?.type,
    "guest.exec.complete",
  );

  const followup = control.exec({ id: "reused", argv: ["/bin/true"] });
  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "reused",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("ok")),
      stderr: new Binary(new Uint8Array()),
    }),
  );

  assert.equal((await followup).stdout, "ok");
  await control.close();
});

test("HostControlTransport omits exec timeout when not requested", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const exec = control.exec({ id: "test", argv: ["/bin/true"] });

  assert.deepEqual(BSON.deserialize(channel.writes[0]!.subarray(4)), {
    type: "guest.exec",
    id: "test",
    argv: ["/bin/true"],
    env: [],
  });

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "test",
      exitCode: 0,
      stdout: new Binary(new Uint8Array()),
      stderr: new Binary(new Uint8Array()),
    }),
  );

  await exec;
  await control.close();
});

test("HostControlTransport spawn streams stdio and resolves exit", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const spawned = startSpawn(control, channel, "spawn");

  assert.deepEqual(
    channel.writes.map((packet) => BSON.deserialize(packet.subarray(4))),
    [
      {
        type: "guest.spawn",
        id: "spawn",
        argv: ["/bin/cat"],
        env: [],
        stdin: "pipe",
        stdout: "pipe",
        stderr: "pipe",
      },
    ],
  );

  await spawned.ready;
  const writer = spawned.stdin.getWriter();
  await writer.write(new TextEncoder().encode("input"));
  await writer.close();

  assert.deepEqual(
    channel.writes.slice(1).map((packet) => BSON.deserialize(packet.subarray(4))),
    [
      {
        type: "guest.spawn.stdin",
        id: "spawn",
        data: new Binary(new TextEncoder().encode("input")),
      },
      {
        type: "guest.spawn.stdin.close",
        id: "spawn",
      },
    ],
  );

  channel.packets.push(
    encodePacket({
      type: "guest.spawn.stdout",
      id: "spawn",
      data: new Binary(new TextEncoder().encode("out")),
    }),
    encodePacket({
      type: "guest.spawn.stderr",
      id: "spawn",
      data: new Binary(new TextEncoder().encode("err")),
    }),
    encodePacket({
      type: "guest.spawn.exit",
      id: "spawn",
      exitCode: 7,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "spawn",
    }),
  );

  assert.equal(await readAll(spawned.stdout), "out");
  assert.equal(await readAll(spawned.stderr), "err");
  assert.deepEqual(await spawned.exit, { exitCode: 7, signal: null });
  await control.close();
});

test("HostControlTransport does not duplicate spawn output in incoming events", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const incoming = control.incoming[Symbol.asyncIterator]();
  const spawned = startSpawn(control, channel, "spawn");
  await spawned.ready;

  assert.equal((await incoming.next()).value?.type, "guest.spawn.started");

  channel.packets.push(
    encodePacket({
      type: "guest.spawn.stdout",
      id: "spawn",
      data: new Binary(new TextEncoder().encode("out")),
    }),
    encodePacket({
      type: "guest.spawn.stderr",
      id: "spawn",
      data: new Binary(new TextEncoder().encode("err")),
    }),
    encodePacket({
      type: "guest.spawn.exit",
      id: "spawn",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "spawn",
    }),
  );

  assert.equal(await readAll(spawned.stdout), "out");
  assert.equal(await readAll(spawned.stderr), "err");
  assert.equal((await incoming.next()).value?.type, "guest.spawn.exit");
  await control.close();
});

test("HostControlTransport keeps spawn streams open after process exit", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const spawned = startSpawn(control, channel, "spawn");
  await spawned.ready;

  channel.packets.push(
    encodePacket({
      type: "guest.spawn.exit",
      id: "spawn",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.stdout",
      id: "spawn",
      data: new Binary(new TextEncoder().encode("tail")),
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "spawn",
    }),
  );

  assert.deepEqual(await spawned.exit, { exitCode: 0, signal: null });
  assert.equal(await readAll(spawned.stdout), "tail");
  await control.close();
});

test("HostControlTransport rejects pre-start spawn failures without exposing a process", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const spawned = control.spawn({ id: "spawn", argv: ["/bin/cat"] });

  await control.close();

  await assert.rejects(spawned.ready, /sandbox control is closed/);
  await assert.rejects(spawned.exit, /sandbox control is closed/);
});

test("HostControlTransport demultiplexes concurrent spawn output", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const first = startSpawn(control, channel, "first");
  const second = startSpawn(control, channel, "second");
  await Promise.all([first.ready, second.ready]);

  channel.packets.push(
    encodePacket({
      type: "guest.spawn.stdout",
      id: "second",
      data: new Binary(new TextEncoder().encode("second")),
    }),
    encodePacket({
      type: "guest.spawn.stdout",
      id: "first",
      data: new Binary(new TextEncoder().encode("first")),
    }),
    encodePacket({
      type: "guest.spawn.exit",
      id: "first",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "first",
    }),
    encodePacket({
      type: "guest.spawn.exit",
      id: "second",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "second",
    }),
  );

  assert.equal(await readAll(first.stdout), "first");
  assert.equal(await readAll(second.stdout), "second");
  assert.deepEqual(await first.exit, { exitCode: 0, signal: null });
  assert.deepEqual(await second.exit, { exitCode: 0, signal: null });
  await control.close();
});

test("HostControlTransport rejects duplicate in-flight spawn ids", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const first = control.spawn({ id: "duplicate", argv: ["/bin/cat"] });

  channel.packets.push(encodePacket({ type: "guest.spawn.started", id: "duplicate" }));
  await first.ready;
  assert.throws(
    () => control.spawn({ id: "duplicate", argv: ["/bin/cat"] }),
    /sandbox spawn id is already in flight: duplicate/,
  );

  channel.packets.push(
    encodePacket({
      type: "guest.spawn.exit",
      id: "duplicate",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "duplicate",
    }),
  );

  assert.deepEqual(await first.exit, { exitCode: 0, signal: null });
  await control.close();
});

test("HostControlTransport pty streams terminal data and sends resize", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const pty = control.pty({
    id: "pty",
    argv: ["/bin/sh"],
    size: { rows: 24, cols: 80 },
  });

  assert.deepEqual(BSON.deserialize(channel.writes[0]!.subarray(4)), {
    type: "guest.spawn",
    id: "pty",
    argv: ["/bin/sh"],
    env: [],
    stdin: "pty",
    stdout: "pty",
    stderr: "pty",
    pty: { rows: 24, cols: 80 },
  });

  channel.packets.push(encodePacket({ type: "guest.spawn.started", id: "pty" }));
  await pty.ready;

  pty.resize({ rows: 40, cols: 120 });
  const writer = pty.input.getWriter();
  await writer.write(new TextEncoder().encode("echo hi\r"));
  await writer.close();

  assert.deepEqual(
    channel.writes.slice(1).map((packet) => BSON.deserialize(packet.subarray(4))),
    [
      {
        type: "guest.spawn.resize",
        id: "pty",
        rows: 40,
        cols: 120,
      },
      {
        type: "guest.spawn.stdin",
        id: "pty",
        data: new Binary(new TextEncoder().encode("echo hi\r")),
      },
      {
        type: "guest.spawn.stdin.close",
        id: "pty",
      },
    ],
  );

  channel.packets.push(
    encodePacket({
      type: "guest.spawn.stdout",
      id: "pty",
      data: new Binary(new TextEncoder().encode("hi\r\n")),
    }),
    encodePacket({
      type: "guest.spawn.exit",
      id: "pty",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "pty",
    }),
  );

  assert.equal(await readAll(pty.output), "hi\r\n");
  assert.deepEqual(await pty.exit, { exitCode: 0, signal: null });
  await control.close();
});

test("HostControlTransport rejects invalid pty resize before sending", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const pty = control.pty({
    id: "pty",
    argv: ["/bin/sh"],
    size: { rows: 24, cols: 80 },
  });

  channel.packets.push(encodePacket({ type: "guest.spawn.started", id: "pty" }));
  await pty.ready;

  assert.throws(
    () => pty.resize({ rows: 65_536, cols: 80 }),
    /invalid sandbox pty resize\.rows must be an integer between 1 and 65535/,
  );
  assert.equal(channel.writes.length, 1);
  channel.packets.push(
    encodePacket({
      type: "guest.spawn.exit",
      id: "pty",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "pty",
    }),
  );
  assert.deepEqual(await pty.exit, { exitCode: 0, signal: null });
  await control.close();
});

test("HostControlTransport ignores spawn output after stream cancellation", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const spawned = startSpawn(control, channel, "spawn");
  await spawned.ready;

  await spawned.stdout.cancel();
  channel.packets.push(
    encodePacket({
      type: "guest.spawn.stdout",
      id: "spawn",
      data: new Binary(new TextEncoder().encode("ignored")),
    }),
    encodePacket({
      type: "guest.spawn.exit",
      id: "spawn",
      exitCode: 0,
    }),
    encodePacket({
      type: "guest.spawn.streams.closed",
      id: "spawn",
    }),
  );

  assert.deepEqual(await spawned.exit, { exitCode: 0, signal: null });
  await control.close();
});

test("HostControlTransport demultiplexes concurrent exec completions", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const first = control.exec({ id: "first", argv: ["/bin/true"] });
  const second = control.exec({ id: "second", argv: ["/bin/true"] });

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "second",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("second")),
      stderr: new Binary(new Uint8Array()),
    }),
    encodePacket({
      type: "guest.exec.complete",
      id: "first",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("first")),
      stderr: new Binary(new Uint8Array()),
    }),
  );

  assert.equal((await first).stdout, "first");
  assert.equal((await second).stdout, "second");
  await control.close();
});

test("HostControlTransport exec is not starved by incoming consumers", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const iterator = control.incoming[Symbol.asyncIterator]();
  const exec = control.exec({ id: "test", argv: ["/bin/true"] });

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "test",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("ok")),
      stderr: new Binary(new Uint8Array()),
    }),
  );

  assert.deepEqual(await exec, {
    type: "guest.exec.complete",
    id: "test",
    exitCode: 0,
    stdout: "ok",
    stderr: "",
  });
  assert.deepEqual(await iterator.next(), {
    done: false,
    value: {
      type: "guest.exec.complete",
      id: "test",
      exitCode: 0,
      stdout: "ok",
      stderr: "",
    },
  });
  await control.close();
});

test("HostControlTransport rejects duplicate in-flight exec ids", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const first = control.exec({ id: "duplicate", argv: ["/bin/true"] });

  await assert.rejects(
    control.exec({ id: "duplicate", argv: ["/bin/true"] }),
    /sandbox exec id is already in flight: duplicate/,
  );

  channel.packets.push(
    encodePacket({
      type: "guest.exec.complete",
      id: "duplicate",
      exitCode: 0,
      stdout: new Binary(new TextEncoder().encode("ok")),
      stderr: new Binary(new Uint8Array()),
    }),
  );

  assert.equal((await first).stdout, "ok");
  await control.close();
});

test("HostControlTransport closes and rejects pending execs on malformed frames", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const iterator = control.incoming[Symbol.asyncIterator]();
  const exec = control.exec({ id: "pending", argv: ["/bin/true"] });

  channel.packets.push(encodePacket({ type: "unknown.control.frame" }));

  await assert.rejects(exec, /unknown control frame type: unknown.control.frame/);
  await assert.rejects(iterator.next(), /unknown control frame type: unknown.control.frame/);
  await assert.rejects(
    control.exec({ id: "after-failure", argv: ["/bin/true"] }),
    /sandbox control is closed/,
  );
});

class MemoryControlChannel implements HostControlChannel {
  readonly writes: Uint8Array[] = [];
  readonly packets = new MemoryPacketStream();

  writeControlPacket(packet: Uint8Array): void {
    this.writes.push(packet);
  }
}

class MemoryPacketStream implements AsyncIterable<Uint8Array> {
  readonly #queue: Uint8Array[] = [];
  readonly #waiters: Array<(value: Uint8Array) => void> = [];

  push(...packets: Uint8Array[]): void {
    for (const packet of packets) {
      const waiter = this.#waiters.shift();
      if (waiter !== undefined) {
        waiter(packet);
      } else {
        this.#queue.push(packet);
      }
    }
  }

  [Symbol.asyncIterator](): AsyncIterator<Uint8Array> {
    return {
      next: async () => {
        const value = this.#queue.shift();
        if (value !== undefined) {
          return { value, done: false };
        }
        return await new Promise<IteratorResult<Uint8Array>>((resolve) => {
          this.#waiters.push((packet) => resolve({ value: packet, done: false }));
        });
      },
    };
  }
}

function startSpawn(
  control: HostControlTransport,
  channel: MemoryControlChannel,
  id: string,
) {
  const spawned = control.spawn({ id, argv: ["/bin/cat"] });
  channel.packets.push(encodePacket({ type: "guest.spawn.started", id }));
  return spawned;
}

async function readAll(source: ReadableStream<Uint8Array>): Promise<string> {
  const chunks: Uint8Array[] = [];
  const reader = source.getReader();
  try {
    while (true) {
      const next = await reader.read();
      if (next.done) {
        break;
      }
      chunks.push(next.value);
    }
  } finally {
    reader.releaseLock();
  }
  const size = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
  const data = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(data);
}

function encodePacket(document: Record<string, unknown>): Uint8Array {
  const frame = BSON.serialize(document);
  const packet = new Uint8Array(4 + frame.byteLength);
  new DataView(packet.buffer, packet.byteOffset, 4).setUint32(0, frame.byteLength, true);
  packet.set(frame, 4);
  return packet;
}
