import Type from "typebox";
import { Value } from "typebox/value";

import type {
  SandboxArtifactInspectionOptions,
  SandboxOptions,
} from "./index.ts";

const RootfsSchema = Type.Object({
  kind: Type.Literal("prebuilt-rootfs"),
  path: Type.String(),
  readonly: Type.Optional(Type.Boolean()),
  format: Type.Union([Type.Literal("directory"), Type.Literal("erofs")]),
});

const RootfsOverlaySchema = Type.Object({
  mode: Type.Literal("writable"),
});

const NativeSpawnSandboxRequestSchema = Type.Object({
  name: Type.Optional(Type.String()),
  cpu: Type.Optional(Type.Object({ vcpus: Type.Optional(Type.Number()) })),
  memory: Type.Optional(Type.Object({ mib: Type.Optional(Type.Number()) })),
  rootfs: RootfsSchema,
  rootfsOverlay: Type.Optional(RootfsOverlaySchema),
  mounts: Type.Optional(
    Type.Array(
      Type.Union([
        Type.Object({
          kind: Type.Literal("sqlite-fs"),
          path: Type.String(),
          name: Type.String(),
        }),
        Type.Object({
          kind: Type.Literal("virtual-fs"),
          path: Type.String(),
        }),
      ]),
    ),
  ),
  network: Type.Optional(
    Type.Object({
      http: Type.Optional(
        Type.Object({
          protectedRanges: Type.Optional(Type.Array(Type.String())),
        }),
      ),
    }),
  ),
});

const NativeArtifactInspectionRequestSchema = Type.Object({
  expectedStatic: Type.Boolean(),
  forbiddenDynamicLibraries: Type.Array(Type.String()),
  macosEntitlements: Type.Optional(Type.Array(Type.String())),
});

export function encodeSpawnSandboxRequest(options: SandboxOptions): string {
  return JSON.stringify(
    Value.Parse(NativeSpawnSandboxRequestSchema, {
      name: options.name,
      cpu: options.cpu,
      memory: options.memory,
      rootfs: options.rootfs,
      rootfsOverlay: options.rootfsOverlay,
      mounts: options.mounts?.map((mount) => {
        switch (mount.kind) {
          case "sqlite-fs":
            return {
              kind: mount.kind,
              path: mount.path,
              name: mount.name,
            };
          case "virtual-fs":
            return {
              kind: mount.kind,
              path: mount.path,
            };
        }
      }),
      network: options.network === undefined
        ? undefined
        : {
            http: options.network.http === undefined
              ? undefined
              : {
                  protectedRanges: options.network.http.protectedRanges,
                },
          },
    }),
  );
}

export function encodeArtifactInspectionRequest(
  options: SandboxArtifactInspectionOptions,
): string {
  return JSON.stringify(Value.Parse(NativeArtifactInspectionRequestSchema, options));
}
