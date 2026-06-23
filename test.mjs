import { Readable, Writable } from "node:stream";
import { defineSandbox, network, rootfs } from "./src/index.ts";

const vm = await defineSandbox({
  rootfs: rootfs.ephemeral({
    base: rootfs.builtIn("alpine:3.23"),
    maxDirtyBytes: 1024 * 1024 * 1024,
  }),
  network: network.policy((conn) => conn.accept()),
}).boot();

const sh = vm.pty("/bin/sh", ["-i"], {
  env: { TERM: process.env.TERM ?? "xterm-256color" },
  size: {
    rows: process.stdout.rows ?? 24,
    cols: process.stdout.columns ?? 80,
  },
});

process.stdin.setRawMode(true);
process.stdin.resume();

Readable.toWeb(process.stdin).pipeTo(sh.input);
sh.output.pipeTo(Writable.toWeb(process.stdout));

await sh.exit;

vm.close();
