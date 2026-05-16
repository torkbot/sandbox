import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function writeEvidence(name: string, value: unknown): Promise<void> {
  const resultDir = process.env.SANDBOX_E2E_RESULT_DIR;
  if (!resultDir) {
    return;
  }

  await mkdir(resultDir, { recursive: true });
  await writeFile(join(resultDir, name), `${JSON.stringify(value, null, 2)}\n`);
}

export async function collectAsync<T, U extends T>(
  iterable: AsyncIterable<T>,
  predicate: (item: T) => item is U,
): Promise<U>;
export async function collectAsync<T>(
  iterable: AsyncIterable<T>,
  predicate: (item: T) => boolean,
): Promise<T>;
export async function collectAsync<T>(
  iterable: AsyncIterable<T>,
  predicate: (item: T) => boolean,
): Promise<T> {
  for await (const item of iterable) {
    if (predicate(item)) {
      return item;
    }
  }

  throw new Error("Async iterable ended before the expected event was observed");
}
