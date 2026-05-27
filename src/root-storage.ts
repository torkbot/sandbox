import { copyFile, mkdtemp, open, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  SandboxBlockChunk,
  SandboxRootStorage,
} from "./index.ts";

export type MaterializedRootStorage = {
  readonly path: string;
  readonly cleanup: () => Promise<void>;
};

export async function materializeCowRootStorage(
  basePath: string,
  storage: SandboxRootStorage,
): Promise<MaterializedRootStorage> {
  const tempDir = await mkdtemp(join(tmpdir(), "torkbot-sandbox-root-"));
  const rootfsPath = join(tempDir, "rootfs.ext4");
  await copyFile(basePath, rootfsPath);
  await applyStoredBlocks(rootfsPath, storage);

  return {
    path: rootfsPath,
    cleanup: async () => {
      try {
        await checkpointBlocks(rootfsPath, storage);
      } finally {
        await rm(tempDir, { recursive: true, force: true });
      }
    },
  };
}

async function applyStoredBlocks(
  rootfsPath: string,
  storage: SandboxRootStorage,
): Promise<void> {
  const blockSize = storage.blockStore.blockSize;
  const size = (await stat(rootfsPath)).size;
  const blockCount = Math.ceil(size / blockSize);
  const chunks = await storage.blockStore.read({
    start: 0n,
    count: blockCount,
  });

  if (chunks.length === 0) {
    return;
  }

  const file = await open(rootfsPath, "r+");
  try {
    for (const chunk of chunks) {
      validateChunk(chunk, blockSize);
      await file.write(chunk.data, 0, chunk.data.byteLength, Number(chunk.start) * blockSize);
    }
  } finally {
    await file.close();
  }
}

async function checkpointBlocks(
  rootfsPath: string,
  storage: SandboxRootStorage,
): Promise<void> {
  const blockSize = storage.blockStore.blockSize;
  const size = (await stat(rootfsPath)).size;
  const blockCount = Math.ceil(size / blockSize);
  const file = await open(rootfsPath, "r");

  try {
    for (let start = 0; start < blockCount; start += 256) {
      const chunks: SandboxBlockChunk[] = [];
      const count = Math.min(256, blockCount - start);
      for (let offset = 0; offset < count; offset += 1) {
        const blockIndex = start + offset;
        const position = blockIndex * blockSize;
        const length = Math.min(blockSize, size - position);
        const data = new Uint8Array(length);
        await file.read(data, 0, length, position);
        chunks.push({
          start: BigInt(blockIndex),
          data,
        });
      }
      await storage.blockStore.write(chunks);
    }
  } finally {
    await file.close();
  }

  await storage.blockStore.flush?.();
}

function validateChunk(chunk: SandboxBlockChunk, blockSize: number): void {
  if (chunk.start < 0n) {
    throw new Error("invalid sandbox storage block: start must be non-negative");
  }
  if (chunk.data.byteLength > blockSize) {
    throw new Error("invalid sandbox storage block: chunk exceeds storage block size");
  }
}
