// @ts-check
import js from "@eslint/js";
import { defineConfig, globalIgnores } from "eslint/config";
import prettier from "eslint-config-prettier";
import { createTypeScriptImportResolver } from "eslint-import-resolver-typescript";
import { importX } from "eslint-plugin-import-x";
import tseslint from "typescript-eslint";

export default defineConfig(
  globalIgnores([
    "**/dist/**",
    "**/node_modules/**",
    "**/.wrangler/**",
    "**/*.generated.ts",
    "packages/testkit/fixtures/**",
  ]),

  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  importX.flatConfigs.recommended,
  importX.flatConfigs.typescript,
  {
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ["eslint.config.js", "packages/core/vitest.config.ts"],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    settings: {
      "import-x/resolver-next": [
        createTypeScriptImportResolver({
          project: ["packages/*/tsconfig.json", "packages/core/test/tsconfig.json"],
        }),
      ],
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/no-import-type-side-effects": "error",
      "@typescript-eslint/switch-exhaustiveness-check": [
        "error",
        { considerDefaultExhaustiveForUnions: true },
      ],
      "@typescript-eslint/explicit-module-boundary-types": "off",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: false }],
      "import-x/no-cycle": "error",
      // Runtime-provided modules and Vite raw imports have no files to resolve.
      "import-x/no-unresolved": ["error", { ignore: ["^cloudflare:", "\\?raw$"] }],
      "import-x/no-duplicates": "error",
      "import-x/no-extraneous-dependencies": "error",
      "import-x/no-default-export": "error",
      "import-x/order": [
        "error",
        {
          groups: ["builtin", "external", "internal", "parent", "sibling", "index"],
          alphabetize: { order: "asc", caseInsensitive: true },
          "newlines-between": "never",
        },
      ],
      "no-console": "error",
      eqeqeq: ["error", "always"],
    },
  },

  // The core must run on every JavaScript runtime: only fetch, WebCrypto, and
  // standard globals. Platform APIs belong in @gate/server adapters.
  {
    files: ["packages/core/src/**/*.ts"],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          patterns: [
            {
              group: ["node:*"],
              message: "@gate/core must not depend on Node APIs; add a port instead.",
            },
            {
              group: ["cloudflare:*"],
              message: "@gate/core must not depend on Workers APIs; add a port instead.",
            },
            {
              group: ["hono", "hono/*", "@hono/*"],
              message: "HTTP concerns belong in @gate/server.",
            },
            {
              group: ["@actions/*", "@gate/server", "@gate/action", "@gate/testkit"],
              message: "@gate/core must not depend on outer packages.",
            },
          ],
        },
      ],
      "no-restricted-globals": [
        "error",
        { name: "process", message: "Use a port (SecretSource, Clock) instead of process." },
        { name: "Buffer", message: "Use Uint8Array and the helpers in util/encoding.ts." },
        { name: "require", message: "ESM only." },
        { name: "__dirname", message: "ESM only." },
      ],
    },
  },

  // Platforms require default exports from their entry points.
  {
    files: [
      "packages/server/src/platforms/*/entry.ts",
      "**/vitest*.config.ts",
      "**/*.d.ts",
      "eslint.config.js",
    ],
    rules: { "import-x/no-default-export": "off" },
  },

  // Build scripts and tests may use Node and dev dependencies freely.
  {
    files: ["**/scripts/**/*.ts", "**/test/**/*.ts", "**/vitest*.config.ts"],
    rules: {
      "no-console": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
    },
  },

  {
    files: ["eslint.config.js"],
    extends: [tseslint.configs.disableTypeChecked],
    rules: { "import-x/no-named-as-default-member": "off" },
  },

  prettier,
);
