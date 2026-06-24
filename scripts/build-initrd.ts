import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const repoRoot = resolve(import.meta.dirname, "..");
const target = process.env.SANDBOX_INIT_TARGET ?? guestTarget();
const initPath = resolve(
  repoRoot,
  process.env.SANDBOX_INIT_BINARY_PATH ?? `dist/init/${target}/sandbox-init`,
);
const outPath = resolve(
  repoRoot,
  process.env.SANDBOX_INITRD_OUT ?? `dist/initrd/${target}/sandbox-initrd.cpio`,
);

const init = await readFile(initPath);
const archive = cpioNewc([
  directory("dev"),
  directory("proc"),
  directory("sys"),
  directory("newroot"),
  file("init", 0o100755, init),
]);

await mkdir(dirname(outPath), { recursive: true });
await writeFile(outPath, archive);

console.log(`initrd artifact written to ${outPath}`);

type CpioEntry = {
  readonly name: string;
  readonly mode: number;
  readonly nlink: number;
  readonly data: Uint8Array;
};

function directory(name: string): CpioEntry {
  return {
    name,
    mode: 0o040755,
    nlink: 2,
    data: new Uint8Array(),
  };
}

function file(name: string, mode: number, data: Uint8Array): CpioEntry {
  return {
    name,
    mode,
    nlink: 1,
    data,
  };
}

function cpioNewc(entries: readonly CpioEntry[]): Uint8Array {
  const chunks: Uint8Array[] = [];
  let ino = 1;
  for (const entry of entries) {
    chunks.push(cpioEntry({ ...entry, ino }));
    ino += 1;
  }
  chunks.push(cpioEntry({
    name: "TRAILER!!!",
    mode: 0,
    nlink: 1,
    data: new Uint8Array(),
    ino,
  }));
  return concat(chunks);
}

function cpioEntry(entry: CpioEntry & { readonly ino: number }): Uint8Array {
  const name = new TextEncoder().encode(`${entry.name}\0`);
  const header = [
    "070701",
    hex(entry.ino),
    hex(entry.mode),
    hex(0),
    hex(0),
    hex(entry.nlink),
    hex(0),
    hex(entry.data.byteLength),
    hex(0),
    hex(0),
    hex(0),
    hex(0),
    hex(name.byteLength),
    hex(0),
  ].join("");
  return concat([
    new TextEncoder().encode(header),
    name,
    padding(header.length + name.byteLength),
    entry.data,
    padding(entry.data.byteLength),
  ]);
}

function hex(value: number): string {
  return value.toString(16).padStart(8, "0");
}

function padding(length: number): Uint8Array {
  return new Uint8Array((4 - (length % 4)) % 4);
}

function concat(chunks: readonly Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function guestTarget(): string {
  switch (process.arch) {
    case "arm64":
      return "aarch64-unknown-linux-musl";
    case "x64":
      return "x86_64-unknown-linux-musl";
    default:
      throw new Error(`unsupported host architecture for initrd build: ${process.arch}`);
  }
}
