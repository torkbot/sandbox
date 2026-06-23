import { appendFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { listImageDefinitions, readImageDefinition } from "./image-manifest.ts";

const architectureRunners = [
  { architecture: "x64", runner: "ubuntu-24.04" },
  { architecture: "arm64", runner: "ubuntu-24.04-arm" },
] as const;

function requiredArg(args: readonly string[], name: string): string {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

async function main(): Promise<void> {
  const selectedImage = requiredArg(process.argv.slice(2), "--image");
  const definitions = selectedImage === "all"
    ? await listImageDefinitions()
    : [await readImageDefinition(selectedImage)];
  const matrix = {
    include: definitions.flatMap((definition) => {
      return architectureRunners.map((entry) => ({
        image: definition.id,
        architecture: entry.architecture,
        runner: entry.runner,
      }));
    }),
  };
  const images = {
    include: definitions.map((definition) => ({
      image: definition.id,
    })),
  };
  const output = [
    `matrix=${JSON.stringify(matrix)}`,
    `images=${JSON.stringify(images)}`,
    "",
  ].join("\n");
  if (process.env.GITHUB_OUTPUT === undefined) {
    process.stdout.write(output);
    return;
  }
  await appendFile(process.env.GITHUB_OUTPUT, output);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
