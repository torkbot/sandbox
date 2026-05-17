import { execFile } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import type { IncomingHttpHeaders } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface TestHttpsOrigin {
  readonly url: string;
  readonly pinnedPublicKeySha256: string;
  close(): Promise<void>;
}

export interface TestCertificateAuthority {
  readonly certificatePem: string;
  readonly privateKeyPem: string;
  close(): Promise<void>;
}

export interface TestHttpOrigin {
  readonly url: string;
  close(): Promise<void>;
}

export async function startTestHttpOrigin(input: {
  respond(request: {
    readonly headers: Record<string, string>;
    readonly url: string;
  }): {
    readonly status: number;
    readonly headers?: Record<string, string>;
    readonly body?: string;
  };
}): Promise<TestHttpOrigin> {
  const server = http.createServer((request, response) => {
    const result = input.respond({
      headers: normalizeHeaders(request.headers),
      url: request.url ?? "/",
    });
    response.writeHead(result.status, result.headers);
    response.end(result.body ?? "");
  });

  await listen(server);
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("test HTTP origin did not bind a TCP port");
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    async close() {
      await close(server);
    },
  };
}

export async function startTestHttpsOrigin(input: {
  readonly ca: Pick<TestCertificateAuthority, "certificatePem" | "privateKeyPem">;
  readonly hostname?: string;
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
  const caKeyPath = join(workDir, "ca.key");
  const caCertPath = join(workDir, "ca.pem");
  const keyPath = join(workDir, "origin.key");
  const csrPath = join(workDir, "origin.csr");
  const certPath = join(workDir, "origin.pem");
  const configPath = join(workDir, "openssl.cnf");
  const hostname = input.hostname ?? "127.0.0.1";
  const subjectAltName = isIpv4Address(hostname)
    ? `IP:${hostname}`
    : `DNS:${hostname}`;
  await writeFile(caKeyPath, input.ca.privateKeyPem);
  await writeFile(caCertPath, input.ca.certificatePem);
  await writeFile(configPath, [
    "[req]",
    "distinguished_name=req_distinguished_name",
    "req_extensions=v3_req",
    "prompt=no",
    "[req_distinguished_name]",
    `CN=${hostname}`,
    "[v3_req]",
    `subjectAltName=${subjectAltName}`,
    "",
  ].join("\n"));
  await execFileAsync("openssl", [
    "req",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-keyout",
    keyPath,
    "-out",
    csrPath,
    "-config",
    configPath,
  ]);
  await execFileAsync("openssl", [
    "x509",
    "-req",
    "-in",
    csrPath,
    "-CA",
    caCertPath,
    "-CAkey",
    caKeyPath,
    "-CAcreateserial",
    "-out",
    certPath,
    "-days",
    "1",
    "-extensions",
    "v3_req",
    "-extfile",
    configPath,
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

  await listen(server);

  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("test HTTPS origin did not bind a TCP port");
  }
  const certificatePem = await readFile(certPath, "utf8");

  return {
    url: `https://127.0.0.1:${address.port}`,
    pinnedPublicKeySha256: publicKeyPin(certificatePem),
    async close() {
      await close(server);
      await rm(workDir, { recursive: true, force: true });
    },
  };
}

function publicKeyPin(certificatePem: string): string {
  const publicKeyDer = new X509Certificate(certificatePem)
    .publicKey
    .export({ type: "spki", format: "der" });
  return `sha256//${createHash("sha256").update(publicKeyDer).digest("base64")}`;
}

function isIpv4Address(value: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(value);
}

export async function createTestCertificateAuthority(): Promise<TestCertificateAuthority> {
  const workDir = await mkdtemp(join(tmpdir(), "sandbox-ca-"));
  const keyPath = join(workDir, "ca.key");
  const certPath = join(workDir, "ca.pem");
  await execFileAsync("openssl", [
    "req",
    "-x509",
    "-newkey",
    "rsa:2048",
    "-nodes",
    "-days",
    "1",
    "-subj",
    "/CN=Sandbox Test CA",
    "-keyout",
    keyPath,
    "-out",
    certPath,
  ]);

  return {
    certificatePem: await readFile(certPath, "utf8"),
    privateKeyPem: await readFile(keyPath, "utf8"),
    async close() {
      await rm(workDir, { recursive: true, force: true });
    },
  };
}

async function listen(server: http.Server | https.Server): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolvePromise();
    });
  });
}

async function close(server: http.Server | https.Server): Promise<void> {
  await new Promise<void>((resolvePromise) => {
    server.close(() => resolvePromise());
  });
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
