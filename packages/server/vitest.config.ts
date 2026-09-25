import { defineConfig } from "vitest/config";

/** Integration tests on Node. The same files run on Bun via `bun test test/integration`. */
export default defineConfig({
  test: {
    include: ["test/integration/**/*.test.ts"],
  },
});
