import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import https from "node:https";
import type { IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface TestHttpsOrigin {
  readonly url: string;
  close(): Promise<void>;
}

export async function startTestHttpsOrigin(input: {
  respond(request: {
    readonly headers: Record<string, string>;
    readonly url: string;
  }): {
    readonly status: number;
    readonly headers?: Record<string, string>;
    readonly body?: string;
  };
}): Promise<TestHttpsOrigin> {
  const workDir = await mkdtemp(join(tmpdir(), "sandbox-origin-"));
  const keyPath = join(workDir, "origin.key");
  const certPath = join(workDir, "origin.pem");
  await execFileAsync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=127.0.0.1",
    "-addext",
    "subjectAltName=IP:127.0.0.1",
    "-keyout",
    keyPath,
    "-out",
    certPath,
  ]);

  const server = https.createServer({
    key: await readFile(keyPath),
    cert: await readFile(certPath),
  }, (request, response) => {
    const result = input.respond({
      headers: normalizeHeaders(request.headers),
      url: request.url ?? "/",
    });
    response.writeHead(result.status, result.headers);
    response.end(result.body ?? "");
  });

  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolvePromise();
    });
  });

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("test HTTPS origin did not bind a TCP port");
  }

  return {
    url: `https://127.0.0.1:${address.port}`,
    async close() {
      await new Promise<void>((resolvePromise) => {
        server.close(() => resolvePromise());
      });
      await rm(workDir, { recursive: true, force: true });
    },
  };
}

function normalizeHeaders(headers: IncomingHttpHeaders): Record<string, string> {
  const normalized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === "string") {
      normalized[key] = value;
    }
  }
  return normalized;
}
