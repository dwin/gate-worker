/**
 * Bundles the Node and Lambda entry points into single ESM files. The Worker
 * bundle is produced by `wrangler deploy --dry-run`; Bun runs the TypeScript
 * source directly; Vercel builds from source.
 */
import { resolve } from "node:path";
import { build } from "esbuild";

const root = resolve(import.meta.dirname, "..");

await Promise.all(
  (["node", "lambda"] as const).map((target) =>
    build({
      entryPoints: [resolve(root, `src/platforms/${target}/entry.ts`)],
      outfile: resolve(root, `dist/${target}/index.mjs`),
      bundle: true,
      platform: "node",
      target: "node22",
      format: "esm",
      sourcemap: true,
      banner: {
        js: "import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);",
      },
      logLevel: "info",
    }),
  ),
);
