#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineSandbox, network, rootfs } from "../src/index.ts";

const repoRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const stamp = new Date().toISOString().replaceAll(/[:.]/g, "-");
const outDir = resolve(repoRoot, "dist", "repros", `heavy-apk-network-${stamp}`);
const packageName = flagValue("--package") ?? "chromium";
const keepGoing = !process.argv.includes("--stop-on-failure");
const install = !process.argv.includes("--no-install");

await mkdir(outDir, { recursive: true });

const events = [];
function record(event) {
  events.push({ at: new Date().toISOString(), ...event });
  console.log(JSON.stringify(events.at(-1)));
}

function flagValue(name) {
  const index = process.argv.indexOf(name);
  if (index === -1) return undefined;
  return process.argv[index + 1];
}

async function runStep(sandbox, id, script, timeoutMs = 120_000) {
  record({ type: "step.start", id, timeoutMs });
  const started = Date.now();
  const result = await withTimeout(
    sandbox.exec("/bin/sh", ["-lc", script], {}),
    timeoutMs,
    id,
  );
  const elapsedMs = Date.now() - started;
  await writeFile(join(outDir, `${id}.json`), JSON.stringify({ elapsedMs, result }, null, 2));
  await writeFile(join(outDir, `${id}.stdout.log`), result.stdout);
  await writeFile(join(outDir, `${id}.stderr.log`), result.stderr);
  record({
    type: "step.end",
    id,
    elapsedMs,
    exitCode: result.exitCode,
    stdoutBytes: Buffer.byteLength(result.stdout),
    stderrBytes: Buffer.byteLength(result.stderr),
  });
  if (result.exitCode !== 0 && !keepGoing) {
    throw new Error(`${id} failed with exit ${result.exitCode}`);
  }
  return result;
}

async function withTimeout(promise, timeoutMs, id) {
  let timeout;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeout = setTimeout(() => {
          reject(new Error(`${id} timed out after ${timeoutMs}ms`));
        }, timeoutMs);
        timeout.unref();
      }),
    ]);
  } finally {
    if (timeout !== undefined) {
      clearTimeout(timeout);
    }
  }
}

record({ type: "repro.start", outDir, packageName, install });

const sandbox = await defineSandbox({
  rootfs: rootfs.builtIn("alpine:3.23"),
  network: network.policy((conn) => {
    conn.matchDns()?.accept();

    if (conn.transport === "tcp") {
      conn.matchHttp(() => true)?.accept();
    }
  }),
}).boot();

try {
  await runStep(sandbox, "00-env", [
    "set -eux",
    "cat /etc/alpine-release",
    "cat /etc/apk/repositories",
    "df -h",
    "ip addr || true",
    "ip route || true",
  ].join("; "));

  await runStep(sandbox, "01-apkindex-probes", [
    "set -eux",
    "arch=$(apk --print-arch)",
    "url=https://dl-cdn.alpinelinux.org/alpine/v3.23/main/$arch/APKINDEX.tar.gz",
    "curl -I --connect-timeout 10 --max-time 30 \"$url\"",
    "curl --http1.1 -sS --connect-timeout 10 --max-time 60 -D /tmp/apkindex.h1.headers -o /tmp/apkindex.h1 \"$url\"",
    "wc -c /tmp/apkindex.h1",
    "sed -n '1,40p' /tmp/apkindex.h1.headers",
    "wget -S -O /tmp/apkindex.wget \"$url\" 2> /tmp/apkindex.wget.stderr",
    "wc -c /tmp/apkindex.wget",
    "sed -n '1,80p' /tmp/apkindex.wget.stderr",
  ].join("; "));

  await runStep(sandbox, "02-apk-update", [
    "set -eux",
    "time apk update",
    "ls -lh /var/cache/apk || true",
    "find /var/cache/apk -maxdepth 1 -type f -print -exec wc -c {} \\; || true",
  ].join("; "), 180_000);

  await runStep(sandbox, "03-apk-fetch-deps", [
    "set -eux",
    `apk fetch --simulate --recursive ${packageName}`,
    `apk info --depends ${packageName} || true`,
  ].join("; "), 180_000);

  await runStep(sandbox, "04-sustained-apkindex-loop", [
    "set -eux",
    "arch=$(apk --print-arch)",
    "url=https://dl-cdn.alpinelinux.org/alpine/v3.23/main/$arch/APKINDEX.tar.gz",
    "for i in $(seq 1 25); do",
    "  echo loop=$i",
    "  curl --http1.1 -fsS --connect-timeout 10 --max-time 60 -o /tmp/apkindex.loop \"$url\"",
    "  test \"$(wc -c < /tmp/apkindex.loop)\" -gt 100000",
    "done",
  ].join("\n"), 300_000);

  if (install) {
    await runStep(sandbox, `05-apk-add-${packageName}`, [
      "set -eux",
      "df -h",
      `time apk add --no-cache ${packageName}`,
      "df -h",
      `command -v ${packageName} || true`,
      "find /var/cache/apk -maxdepth 1 -type f -print -exec wc -c {} \\; || true",
    ].join("; "), 900_000);
  }

  await runStep(sandbox, "06-post-install-probes", [
    "set -eux",
    "df -h",
    "apk info | sort | wc -l",
    "command -v chromium-browser || true",
    "command -v chromium || true",
    "chromium-browser --version || chromium --version || true",
  ].join("; "), 120_000);
} finally {
  await sandbox.close();
  await writeFile(join(outDir, "events.json"), JSON.stringify(events, null, 2));
  record({ type: "repro.end", outDir });
}
