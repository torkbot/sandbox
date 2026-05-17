import test from "node:test";
import assert from "node:assert/strict";
import {
  prebuiltRootfs,
  projectInit,
  projectKernel,
  spawnSandbox,
  sqliteFsMount,
  virtualFsMount,
} from "../../../src/index.ts";
import { collectAsync, writeEvidence } from "../support/evidence.ts";
import { execGuestShell } from "../support/guest-control.ts";
import { requireVmLaunchSupport, skipUntilImplemented } from "../support/capabilities.ts";

const sqliteFsDatabase = {
  open: true,
  prepare(_sql: string) {
    return {
      async run(..._parameters: readonly unknown[]) {
        throw new Error("fixture sqlite filesystem statement is not implemented yet");
      },
      async get(..._parameters: readonly unknown[]) {
        throw new Error("fixture sqlite filesystem statement is not implemented yet");
      },
      async all(..._parameters: readonly unknown[]) {
        throw new Error("fixture sqlite filesystem statement is not implemented yet");
      },
    };
  },
  async exec(_sql: string) {
    throw new Error("fixture sqlite filesystem database is not implemented yet");
  },
  transaction<TArgs extends readonly unknown[], TResult>(
    fn: (...args: TArgs) => Promise<TResult>,
  ) {
    return async (...args: TArgs) => await fn(...args);
  },
};

test("virtual filesystem mounts are backed by host JavaScript callbacks", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }

  const vm = await spawnSandbox({
    name: "virtual-filesystem",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      virtualFsMount("/sandbox", {
        async stat(path) {
          if (path === "/") {
            return {
              type: "directory",
              sizeBytes: null,
              mediaType: null,
              modifiedAtMs: null,
            };
          }

          if (path === "/status.json") {
            return {
              type: "file",
              sizeBytes: 19,
              mediaType: "application/json",
              modifiedAtMs: null,
            };
          }

          throw new Error(`missing path ${path}`);
        },
        async list(path) {
          if (path !== "/") {
            throw new Error(`missing directory ${path}`);
          }

          return [{ name: "status.json", type: "file" }];
        },
        async read(input) {
          assert.equal(input.path, "/status.json");
          return Buffer.from('{"status":"ready"}\n');
        },
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const checks = await execGuestShell(vm, {
    id: "virtual-filesystem-checks",
    script: `
      set -u
      root_status=0
      test ! -w / || root_status=$?
      contents="$(cat /sandbox/status.json)"
      echo "root_status=$root_status"
      echo "contents=$contents"
      test "$root_status" = "0"
      test "$contents" = '{"status":"ready"}'
    `,
  });

  assert.equal(
    checks.exitCode,
    0,
    `guest filesystem checks failed\nstdout:\n${checks.stdout}\nstderr:\n${checks.stderr}`,
  );

  assert.equal((await vm.mounts.get("/sandbox").stat("/status.json")).type, "file");
  assert.deepEqual(await vm.mounts.get("/sandbox").list("/"), [
    { name: "status.json", type: "file" },
  ]);

  const virtualRead = await vm.mounts.virtualFs("/sandbox").read({
    path: "/status.json",
    signal: AbortSignal.timeout(1_000),
  });
  assert.equal(Buffer.from(virtualRead).toString("utf8"), '{"status":"ready"}\n');

  await writeEvidence("fs.json", {
    virtualRead: Buffer.from(virtualRead).toString("utf8"),
  });
});

test("immutable root and SQLite-backed filesystem mounts behave as designed", async (t) => {
  if (!requireVmLaunchSupport(t)) {
    return;
  }
  if (!skipUntilImplemented(t, "guest sqlite filesystem mounts")) {
    return;
  }

  const vm = await spawnSandbox({
    name: "sqlite-filesystem",
    kernel: projectKernel(),
    init: projectInit(),
    rootfs: prebuiltRootfs("dist/rootfs/alpine-3.20.erofs", {
      format: "erofs",
    }),
    mounts: [
      sqliteFsMount({
        path: "/workspace",
        name: "workspace",
        database: sqliteFsDatabase,
      }),
    ],
  });

  t.after(async () => {
    await vm.close();
  });

  await collectAsync(vm.control.incoming, (event) => event.type === "init.ready");

  const checks = await execGuestShell(vm, {
    id: "sqlite-filesystem-checks",
    script: `
      set -eu
      test ! -w /
      echo hello > /workspace/hello.txt
      test "$(cat /workspace/hello.txt)" = "hello"
    `,
  });

  assert.equal(checks.exitCode, 0);

  const snapshot = await vm.mounts.sqliteFs("/workspace").snapshot();
  assert.deepEqual(snapshot.files["/hello.txt"], {
    type: "file",
    contents: "hello\n",
  });
});
