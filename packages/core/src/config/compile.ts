import { parse as parseYaml, YAMLParseError } from "yaml";
import { z } from "zod";
import { ConfigError, formatZodIssues } from "./errors.ts";
import { centralConfigSchema, IGNORED_TOP_LEVEL_KEYS, type CentralConfig } from "./schema.ts";

export interface CompiledConfig {
  config: CentralConfig;
  warnings: string[];
}

/**
 * Parses and validates central configuration YAML. Runs at build and deploy
 * time so an invalid configuration never reaches a running service.
 */
export function compileCentralConfig(yamlText: string): CompiledConfig {
  let raw: unknown;
  try {
    raw = parseYaml(yamlText, { prettyErrors: true, uniqueKeys: true });
  } catch (error) {
    const message = error instanceof YAMLParseError ? error.message : String(error);
    throw new ConfigError([`YAML syntax: ${message}`]);
  }
  const result = centralConfigSchema.safeParse(raw ?? {});
  if (!result.success) {
    throw new ConfigError(formatZodIssues(result.error.issues));
  }
  const warnings: string[] = [];
  if (raw !== null && typeof raw === "object") {
    for (const key of IGNORED_TOP_LEVEL_KEYS) {
      if (key in raw) {
        warnings.push(`${key}: ignored on this platform`);
      }
    }
  }
  return { config: result.data, warnings };
}

/** Re-validates a configuration object, for example after applying overrides. */
export function validateCentralConfig(input: unknown): CentralConfig {
  const result = centralConfigSchema.safeParse(input);
  if (!result.success) {
    throw new ConfigError(formatZodIssues(result.error.issues));
  }
  return result.data;
}

type OverrideKind = "string" | "integer" | "boolean";

/**
 * Environment overrides, named as upstream binds them through Viper
 * (`GATE_<SECTION>_<KEY>`). Only scalar settings are overridable; structured
 * settings (providers, max_permissions, apps) come from the compiled file.
 */
const ENV_OVERRIDES: readonly (readonly [string, readonly [string, string], OverrideKind])[] = [
  ["GATE_LOGGER_LEVEL", ["logger", "level"], "string"],
  ["GATE_LOGGER_FORMAT", ["logger", "format"], "string"],
  ["GATE_OIDC_AUDIENCE", ["oidc", "audience"], "string"],
  ["GATE_POLICY_TRUST_POLICY_PATH", ["policy", "trust_policy_path"], "string"],
  ["GATE_POLICY_DEFAULT_TOKEN_TTL", ["policy", "default_token_ttl"], "integer"],
  ["GATE_POLICY_MAX_TOKEN_TTL", ["policy", "max_token_ttl"], "integer"],
  ["GATE_POLICY_REQUIRE_EXPLICIT_POLICY", ["policy", "require_explicit_policy"], "boolean"],
  ["GATE_POLICY_GITHUB_API_BASE_URL", ["policy", "github_api_base_url"], "string"],
  ["GATE_ORIGIN_ENABLED", ["origin", "enabled"], "boolean"],
  ["GATE_ORIGIN_HEADER_NAME", ["origin", "header_name"], "string"],
];

function coerce(name: string, value: string, kind: OverrideKind): string | number | boolean {
  switch (kind) {
    case "string":
      return value;
    case "integer":
      if (!/^-?\d+$/.test(value.trim())) {
        throw new ConfigError([`${name}: expected an integer, got ${JSON.stringify(value)}`]);
      }
      return Number(value);
    case "boolean":
      if (value !== "true" && value !== "false") {
        throw new ConfigError([`${name}: expected true or false, got ${JSON.stringify(value)}`]);
      }
      return value === "true";
  }
}

const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";
const GITHUB_OWNER_NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;

/**
 * Single-App quick setup, used by the Deploy to Cloudflare button: the App's
 * client ID and organization come from secrets entered at deploy time, and the
 * organization also restricts GitHub Actions callers to that organization's
 * workflows (`required_claims.repository_owner`).
 */
function applyQuickSetup(
  config: CentralConfig,
  env: Readonly<Record<string, string | undefined>>,
): CentralConfig | undefined {
  const clientId = env["GATE_GITHUB_APP_CLIENT_ID"]?.trim();
  const organization = env["GATE_GITHUB_ORGANIZATION"]?.trim();
  if (!clientId && !organization) {
    return undefined;
  }
  const [app, ...others] = config.github_apps;
  if (!app || others.length > 0) {
    throw new ConfigError([
      "GATE_GITHUB_APP_CLIENT_ID and GATE_GITHUB_ORGANIZATION apply only when config.yaml defines exactly one GitHub App",
    ]);
  }
  if (organization && !GITHUB_OWNER_NAME.test(organization)) {
    throw new ConfigError([
      `GATE_GITHUB_ORGANIZATION: ${JSON.stringify(organization)} is not a valid GitHub owner name`,
    ]);
  }
  return {
    ...config,
    github_apps: [
      {
        ...app,
        ...(clientId ? { client_id: clientId } : {}),
        ...(organization ? { organization } : {}),
      },
    ],
    policy: {
      ...config.policy,
      providers: config.policy.providers.map((provider) =>
        organization && provider.issuer === GITHUB_ACTIONS_ISSUER
          ? {
              ...provider,
              // Owner names are alphanumerics and hyphens, so no regex escaping is needed.
              required_claims: {
                ...provider.required_claims,
                repository_owner: `^${organization}$`,
              },
            }
          : provider,
      ),
    },
  };
}

/** Applies `GATE_*` environment overrides and re-validates the result. */
export function applyEnvOverrides(
  config: CentralConfig,
  env: Readonly<Record<string, string | undefined>>,
): CentralConfig {
  const quick = applyQuickSetup(config, env);
  const draft = structuredClone(quick ?? config) as unknown as Record<
    string,
    Record<string, unknown>
  >;
  let changed = quick !== undefined;
  for (const [name, [section, key], kind] of ENV_OVERRIDES) {
    const value = env[name];
    if (value === undefined || value === "") {
      continue;
    }
    const target = draft[section];
    if (target) {
      target[key] = coerce(name, value, kind);
      changed = true;
    }
  }
  return changed ? validateCentralConfig(draft) : config;
}

/** JSON Schema for the central configuration file, for editors and CI. */
export function centralConfigJsonSchema(): Record<string, unknown> {
  return z.toJSONSchema(centralConfigSchema, { io: "input", unrepresentable: "any" });
}
