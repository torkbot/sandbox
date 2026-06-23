import { mkdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  configCommandFact,
  configRootfsImageFact,
  rootfsEnvironmentFactsManifestFile,
  type RootfsEnvironmentFactsManifest,
  type SandboxEnvironmentFact,
} from "../src/environment-facts.ts";
import { readImageDefinition } from "./image-manifest.ts";

const supportedArchitectures = ["arm64", "x64"] as const;
type SupportedArchitecture = typeof supportedArchitectures[number];

const args = process.argv.slice(2);
const imageId = requiredArg(args, "--image");
const architecture = parseArchitecture(requiredArg(args, "--architecture"));
const outDir = resolve(requiredArg(args, "--out-dir"));

const definition = await readImageDefinition(imageId);
const dockerfile = resolve(definition.root, "Dockerfile");
const dockerPlatform = architecture === "arm64" ? "linux/arm64" : "linux/amd64";
const tag = `sandbox-rootfs-${imageId}-${architecture}-${process.pid}`;

await rm(outDir, { recursive: true, force: true });
await mkdir(outDir, { recursive: true });
await run("docker", [
  "build",
  "--platform",
  dockerPlatform,
  "--build-arg",
  `SOURCE_IMAGE=${definition.manifest.source}`,
  "--file",
  dockerfile,
  "--tag",
  tag,
  definition.root,
]);

const containerId = (await output("docker", ["create", tag])).trim();
try {
  await exportContainer(containerId, outDir);
} finally {
  await run("docker", ["rm", "-f", containerId], { allowFailure: true });
  await run("docker", ["rmi", "-f", tag], { allowFailure: true });
}
await rm(resolve(outDir, ".dockerenv"), { force: true });
await mkdir(resolve(outDir, "etc"), { recursive: true });
await writeFile(resolve(outDir, "etc/hostname"), "sandbox\n");
await writeFile(
  resolve(outDir, "etc/hosts"),
  "127.0.0.1 localhost sandbox\n::1 localhost ip6-localhost ip6-loopback\n",
);

await writeFile(
  resolve(outDir, rootfsEnvironmentFactsManifestFile),
  `${JSON.stringify(environmentFactsManifest(imageId, definition.manifest.imageName), null, 2)}\n`,
);

console.log(`image rootfs directory written to ${outDir}`);

function environmentFactsManifest(id: string, imageName: string): RootfsEnvironmentFactsManifest {
  const facts: SandboxEnvironmentFact[] = [
    configRootfsImageFact(imageName),
    distroFact(id),
    distroVersionFact(id),
    packageManagerFact(id),
    { source: "config", topic: "shell", relation: "is", value: "/bin/sh" },
  ];
  if (id.endsWith("-agent")) {
    facts.push(...[
      "bash",
      "curl",
      "git",
      "gh",
      "jq",
      "node",
      "npm",
      "pip3",
      "python3",
      "rg",
    ].map(configCommandFact));
  }
  return {
    schemaVersion: 1,
    rootfs: imageName,
    facts,
  };
}

function distroFact(id: string): SandboxEnvironmentFact {
  if (id.startsWith("alpine-")) {
    return { source: "config", topic: "distro", relation: "is", value: "alpine" };
  }
  if (id.startsWith("ubuntu-")) {
    return { source: "config", topic: "distro", relation: "is", value: "ubuntu" };
  }
  if (id.startsWith("debian-")) {
    return { source: "config", topic: "distro", relation: "is", value: "debian" };
  }
  throw new Error(`unsupported image distro: ${id}`);
}

function distroVersionFact(id: string): SandboxEnvironmentFact {
  const match = /^(alpine|ubuntu|debian)-([0-9]+(?:\.[0-9]+)?)-/.exec(id);
  if (match?.[2] === undefined) {
    throw new Error(`unsupported image version: ${id}`);
  }
  return { source: "config", topic: "distro-version", relation: "is", value: match[2] };
}

function packageManagerFact(id: string): SandboxEnvironmentFact {
  if (id.startsWith("alpine-")) {
    return { source: "config", topic: "package-manager", relation: "is", value: "apk" };
  }
  if (id.startsWith("ubuntu-") || id.startsWith("debian-")) {
    return { source: "config", topic: "package-manager", relation: "is", value: "apt" };
  }
  throw new Error(`unsupported image package manager: ${id}`);
}

function parseArchitecture(value: string): SupportedArchitecture {
  if (supportedArchitectures.includes(value as SupportedArchitecture)) {
    return value as SupportedArchitecture;
  }
  throw new Error(`unsupported image architecture: ${value}`);
}

function requiredArg(values: readonly string[], name: string): string {
  const index = values.indexOf(name);
  const value = index === -1 ? undefined : values[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

async function exportContainer(containerId: string, destination: string): Promise<void> {
  const docker = spawn("docker", ["export", containerId], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  const tar = spawn("tar", ["-C", destination, "-xf", "-"], {
    stdio: ["pipe", "inherit", "inherit"],
  });
  if (docker.stdout === null || tar.stdin === null) {
    throw new Error("failed to open docker export pipeline");
  }
  await Promise.all([
    pipeline(docker.stdout, tar.stdin),
    wait(docker, "docker export"),
    wait(tar, "tar"),
  ]);
}

async function output(command: string, commandArgs: readonly string[]): Promise<string> {
  const chunks: Buffer[] = [];
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, commandArgs, {
      stdio: ["ignore", "pipe", "inherit"],
    });
    child.stdout?.on("data", (chunk: Buffer) => chunks.push(chunk));
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise();
      } else {
        reject(new Error(`${command} exited with ${code}`));
      }
    });
  });
  return Buffer.concat(chunks).toString("utf8");
}

async function run(command: string, commandArgs: readonly string[], options: { readonly allowFailure?: boolean } = {}): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, commandArgs, {
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0 || options.allowFailure === true) {
        resolvePromise();
      } else {
        reject(new Error(`${command} exited with ${code}`));
      }
    });
  });
}

async function wait(child: ReturnType<typeof spawn>, label: string): Promise<void> {
  await new Promise<void>((resolvePromise, reject) => {
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) {
        resolvePromise();
      } else {
        reject(new Error(`${label} exited with ${code}`));
      }
    });
  });
}

if (process.argv[1] === undefined || resolve(process.argv[1]) !== fileURLToPath(import.meta.url)) {
  throw new Error("build-image-rootfs.ts must be run as a script");
}
