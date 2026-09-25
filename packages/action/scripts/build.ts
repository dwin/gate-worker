/**
 * Bundles the action into dist/. dist/ is committed because the runner
 * executes it directly; CI rebuilds and fails if the committed copy is stale.
 */
import { rmSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");
// Start clean so stale chunks never linger in the committed bundle.
rmSync(resolve(root, "dist"), { recursive: true, force: true });

await build({
  entryPoints: { main: resolve(root, "src/main.ts"), post: resolve(root, "src/post.ts") },
  outdir: resolve(root, "dist"),
  bundle: true,
  platform: "node",
  target: "node24",
  format: "esm",
  splitting: true,
  chunkNames: "chunks/[name]-[hash]",
  legalComments: "eof",
  banner: {
    js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
  },
  logLevel: "info",
});
