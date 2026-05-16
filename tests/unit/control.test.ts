import test from "node:test";
import assert from "node:assert/strict";
import { HostControlTransport } from "../../src/control.ts";

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
