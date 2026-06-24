import { appendFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { imagePackageName, listImageDefinitions, readImageDefinition } from "./image-manifest.ts";

type GitHubReleaseAsset = {
  readonly name: string;
  readonly state: string;
};

type GitHubRelease = {
  readonly tag_name: string;
  readonly draft: boolean;
  readonly prerelease: boolean;
  readonly published_at: string | null;
  readonly assets: readonly GitHubReleaseAsset[];
};

type ImagePublishMatrixEntry = {
  readonly image: string;
  readonly tag: string;
  readonly version: string;
};

const imageReleaseTagPattern = /^image\/(.+)\/v(.+)$/;
const supportedArchitectures = ["arm64", "x64"] as const;

export function parseImageReleaseTag(tag: string): {
  readonly image: string;
  readonly version: string;
} {
  const match = imageReleaseTagPattern.exec(tag);
  if (match === null || match[1] === undefined || match[2] === undefined) {
    throw new Error(`image release tag must be image/<image>/v<version>: ${tag}`);
  }
  return {
    image: match[1],
    version: match[2],
  };
}

export function expectedImagePackageNames(input: {
  readonly image: string;
}): readonly string[] {
  const rootPackageName = imagePackageName(input.image);
  return [
    rootPackageName,
    ...supportedArchitectures.map((architecture) => `${rootPackageName}-${architecture}`),
  ];
}

export function assertImageReleaseAssets(release: GitHubRelease): void {
  const { image, version } = parseImageReleaseTag(release.tag_name);
  const expectedAssets = [
    `torkbot-sandbox-image-${image}-${version}.tgz`,
    ...supportedArchitectures.map((architecture) => {
      return `torkbot-sandbox-image-${image}-${architecture}-${version}.tgz`;
    }),
  ].sort();
  const actualAssets = release.assets
    .filter((asset) => asset.state === "uploaded")
    .map((asset) => asset.name)
    .sort();
  if (actualAssets.join("\n") !== expectedAssets.join("\n")) {
    throw new Error(`image release ${release.tag_name} must contain exactly: ${expectedAssets.join(", ")}`);
  }
}

export function imageReleaseMatchesSelection(release: GitHubRelease, image: string): boolean {
  if (release.draft || !release.prerelease || release.published_at === null) {
    return false;
  }
  const parsed = parseImageReleaseTag(release.tag_name);
  return image === "all" || parsed.image === image;
}

export async function imageReleaseNeedsPublish(input: {
  readonly release: GitHubRelease;
  readonly fetch: typeof fetch;
}): Promise<boolean> {
  const { image, version } = parseImageReleaseTag(input.release.tag_name);
  const packageStates = await Promise.all(expectedImagePackageNames({ image }).map(async (packageName) => {
    return await npmPackageVersionExists({
      fetch: input.fetch,
      packageName,
      version,
    });
  }));
  return packageStates.some((exists) => !exists);
}

async function npmPackageVersionExists(input: {
  readonly fetch: typeof fetch;
  readonly packageName: string;
  readonly version: string;
}): Promise<boolean> {
  const url = `https://registry.npmjs.org/${encodeURIComponent(input.packageName)}/${input.version}`;
  const response = await input.fetch(url);
  if (response.status === 200) {
    return true;
  }
  if (response.status === 404) {
    return false;
  }
  throw new Error(`npm registry lookup failed for ${input.packageName}@${input.version}: ${response.status}`);
}

async function listGitHubReleases(input: {
  readonly fetch: typeof fetch;
  readonly repository: string;
  readonly token: string;
}): Promise<readonly GitHubRelease[]> {
  const releases: GitHubRelease[] = [];
  let page = 1;
  while (true) {
    const response = await input.fetch(
      `https://api.github.com/repos/${input.repository}/releases?per_page=100&page=${page}`,
      {
        headers: {
          "Accept": "application/vnd.github+json",
          "Authorization": `Bearer ${input.token}`,
          "X-GitHub-Api-Version": "2022-11-28",
        },
      },
    );
    if (!response.ok) {
      throw new Error(`GitHub release lookup failed: ${response.status}`);
    }
    const pageReleases = await response.json() as readonly GitHubRelease[];
    releases.push(...pageReleases);
    if (pageReleases.length < 100) {
      return releases;
    }
    page += 1;
  }
}

function requiredArg(args: readonly string[], name: string): string {
  const index = args.indexOf(name);
  const value = index === -1 ? undefined : args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

function optionalArg(args: readonly string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) {
    return undefined;
  }
  const value = args[index + 1];
  if (value === undefined || value.length === 0 || value.startsWith("--")) {
    throw new Error(`missing required argument: ${name}`);
  }
  return value;
}

async function selectedImageIds(image: string): Promise<ReadonlySet<string>> {
  if (image === "all") {
    const definitions = await listImageDefinitions();
    return new Set(definitions.map((definition) => definition.id));
  }
  await readImageDefinition(image);
  return new Set([image]);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const image = optionalArg(args, "--image");
  const tag = optionalArg(args, "--tag");
  if ((image === undefined) === (tag === undefined)) {
    throw new Error("pass exactly one of --image <image|all> or --tag <image release tag>");
  }

  const matrixEntries = tag === undefined
    ? await releaseMatrixForImageSelection(image as string)
    : releaseMatrixForTag(tag);
  const output = [
    `count=${matrixEntries.length}`,
    `matrix=${JSON.stringify({ include: matrixEntries })}`,
    "",
  ].join("\n");
  if (process.env.GITHUB_OUTPUT === undefined) {
    process.stdout.write(output);
    return;
  }
  await appendFile(process.env.GITHUB_OUTPUT, output);
}

function releaseMatrixForTag(tag: string): readonly ImagePublishMatrixEntry[] {
  const parsed = parseImageReleaseTag(tag);
  return [{
    image: parsed.image,
    tag,
    version: parsed.version,
  }];
}

async function releaseMatrixForImageSelection(image: string): Promise<readonly ImagePublishMatrixEntry[]> {
  const repository = process.env.GITHUB_REPOSITORY;
  if (repository === undefined || repository.length === 0) {
    throw new Error("GITHUB_REPOSITORY is required");
  }
  const token = process.env.GITHUB_TOKEN;
  if (token === undefined || token.length === 0) {
    throw new Error("GITHUB_TOKEN is required");
  }

  const imageIds = await selectedImageIds(image);
  const releases = await listGitHubReleases({
    fetch,
    repository,
    token,
  });
  const selectedReleases = releases.filter((release) => {
    if (!release.tag_name.startsWith("image/")) {
      return false;
    }
    const parsed = parseImageReleaseTag(release.tag_name);
    return imageIds.has(parsed.image) && imageReleaseMatchesSelection(release, image);
  });
  const entries: ImagePublishMatrixEntry[] = [];
  for (const release of selectedReleases) {
    assertImageReleaseAssets(release);
    if (!await imageReleaseNeedsPublish({ release, fetch })) {
      continue;
    }
    const parsed = parseImageReleaseTag(release.tag_name);
    entries.push({
      image: parsed.image,
      tag: release.tag_name,
      version: parsed.version,
    });
  }
  return entries.sort((a, b) => a.tag.localeCompare(b.tag));
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main();
}
