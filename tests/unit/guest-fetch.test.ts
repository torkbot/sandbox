import assert from "node:assert/strict";
import test from "node:test";
import { BSON } from "bson";
import { Request } from "undici";
import {
  HostControlTransport,
  type HostControlChannel,
} from "../../src/control.ts";
import { GuestFetch } from "../../src/guest-fetch.ts";

test("GuestFetch closes a guest connection when its request is aborted during connect", async () => {
  const channel = new MemoryControlChannel();
  const control = new HostControlTransport({ channel });
  const guestFetch = new GuestFetch(control);
  const abort = new AbortController();
  const response = guestFetch.fetch(new Request("https://example.com/", {
    signal: abort.signal,
  }));

  const open = await waitForCommand(channel, "guest.connection.open");
  assert.equal(open.timeoutMs, 10_000);
  abort.abort();

  await assert.rejects(response, { name: "AbortError" });
  const close = await waitForCommand(channel, "guest.connection.close");
  assert.equal(close.id, open.id);

  await guestFetch.close();
  await control.close();
});

async function waitForCommand(
  channel: MemoryControlChannel,
  type: string,
): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    for (const packet of channel.writes) {
      const command = BSON.deserialize(packet.subarray(4));
      if (command.type === type) {
        return command;
      }
    }
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
  throw new Error(`timed out waiting for ${type}`);
}

class MemoryControlChannel implements HostControlChannel {
  readonly writes: Uint8Array[] = [];
  readonly packets: AsyncIterable<Uint8Array> = {
    async *[Symbol.asyncIterator]() {
      await new Promise(() => {});
    },
  };

  writeControlPacket(packet: Uint8Array): void {
    this.writes.push(packet);
  }
}
