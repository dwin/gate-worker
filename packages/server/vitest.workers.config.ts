import { generateKeyPairSync, randomBytes } from "node:crypto";
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

/**
 * Runs test/workers inside workerd (Miniflare) with the real wrangler.jsonc,
 * including the revocation queue. The App key is PKCS#1, as GitHub downloads
 * it, to prove the PKCS#1 → PKCS#8 wrapping works in the Workers runtime.
 */
const appKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({
  type: "pkcs1",
  format: "pem",
});

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "../../wrangler.jsonc" },
      miniflare: {
        bindings: {
          // The values the Deploy to Cloudflare button collects, in the same shape.
          GATE_GITHUB_APP_CLIENT_ID: "Iv23liTest",
          GATE_GITHUB_ORGANIZATION: "acme-inc",
          GATE_GITHUB_APP_PRIVATE_KEY: appKey.toString(),
          GATE_REVOCATION_KEYS: randomBytes(32).toString("base64"),
        },
      },
    }),
  ],
  test: {
    include: ["test/workers/**/*.test.ts"],
  },
});
