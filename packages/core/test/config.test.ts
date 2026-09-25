import { describe, expect, it } from "vitest";
import {
  applyEnvOverrides,
  centralConfigJsonSchema,
  compileCentralConfig,
  ConfigError,
} from "../src/index.ts";

const MINIMAL = `
policy:
  trust_policy_path: .github/gate/trust-policy.yaml
  providers:
    - issuer: https://token.actions.githubusercontent.com
      name: GitHub Actions
      required_claims:
        repository_owner: "^example-org$"
  max_permissions:
    contents: read
    metadata: read
github_apps:
  - client_id: Iv1.example
    organization: example-org
    private_key_secret: GATE_APP_KEY
`;

function issuesOf(yaml: string): readonly string[] {
  try {
    compileCentralConfig(yaml);
  } catch (error) {
    if (error instanceof ConfigError) return error.issues;
    throw error;
  }
  throw new Error("expected compileCentralConfig to fail");
}

describe("compileCentralConfig", () => {
  it("applies upstream defaults", () => {
    const { config, warnings } = compileCentralConfig(MINIMAL);
    expect(warnings).toEqual([]);
    expect(config.oidc.audience).toBe("gate");
    expect(config.logger).toEqual({ level: "info", format: "json" });
    expect(config.policy).toMatchObject({
      version: "1.0",
      default_token_ttl: 900,
      max_token_ttl: 3600,
      require_explicit_policy: false,
      github_api_base_url: "https://api.github.com",
    });
    expect(config.origin).toEqual({
      enabled: false,
      header_value_secret: "GATE_ORIGIN_HEADER_VALUE",
    });
    expect(config.revocation.key_secret).toBe("GATE_REVOCATION_KEYS");
  });

  it("accepts the README's { pattern, description } claim form", () => {
    const { config } = compileCentralConfig(
      MINIMAL.replace(
        'repository_owner: "^example-org$"',
        'repository_owner:\n          pattern: "^example-org$"\n          description: only our org',
      ),
    );
    expect(config.policy.providers[0]?.required_claims).toEqual({
      repository_owner: "^example-org$",
    });
  });

  it("warns about upstream keys that have no meaning here", () => {
    const { warnings } = compileCentralConfig(
      `${MINIMAL}\nserver:\n  port: 8080\naws_region: us-east-1\n`,
    );
    expect(warnings).toEqual([
      "server: ignored on this platform",
      "aws_region: ignored on this platform",
    ]);
  });

  it.each([
    [
      "default TTL above max",
      "  trust_policy_path",
      "  default_token_ttl: 7200\n  trust_policy_path",
      "default token TTL must be less than or equal to max token TTL",
    ],
    [
      "invalid permission level",
      "contents: read",
      "contents: admin",
      'invalid permission level "admin"',
    ],
    [
      "invalid claim regex",
      '"^example-org$"',
      '"[unclosed"',
      'invalid claim pattern for "repository_owner"',
    ],
    [
      "unknown key (typo)",
      "  trust_policy_path",
      "  trust_polcy_path: x\n  trust_policy_path",
      "trust_polcy_path",
    ],
    [
      "missing providers",
      / {2}providers:[\s\S]*?(?= {2}max_permissions)/,
      "  providers: []\n",
      "at least one provider is required",
    ],
    [
      "secret in file",
      "private_key_secret: GATE_APP_KEY",
      "private_key_path: /keys/app.pem",
      "private_key_path is not supported",
    ],
    [
      "unsupported audit backend",
      "github_apps:",
      "audit:\n  backend: sql\ngithub_apps:",
      'audit backend "sql" is not supported',
    ],
    [
      "unsupported selector",
      "github_apps:",
      "selector:\n  type: redis\ngithub_apps:",
      'selector type "redis" is not supported',
    ],
    [
      "origin value in file",
      "github_apps:",
      "origin:\n  enabled: true\n  header_name: X-Origin\n  header_value: s3cret\ngithub_apps:",
      "header_value must not be stored in config",
    ],
    [
      "origin enabled without header",
      "github_apps:",
      "origin:\n  enabled: true\ngithub_apps:",
      "origin header name is required",
    ],
    [
      "bad hour window",
      "      required_claims:",
      "      time_restrictions:\n        allowed_hours: { start: 25, end: 3 }\n      required_claims:",
      "start hour must be 0-23",
    ],
    [
      "unquoted version",
      "  trust_policy_path",
      "  version: 2.0\n  trust_policy_path",
      "invalid policy version",
    ],
  ] as const)("rejects %s", (_name, find, replace, expected) => {
    expect(issuesOf(MINIMAL.replace(find, replace)).join("\n")).toContain(expected);
  });

  it("reports YAML syntax errors", () => {
    expect(issuesOf("policy: [unclosed")[0]).toMatch(/^YAML syntax:/);
  });

  it("reports every problem at once", () => {
    expect(issuesOf("github_apps: []\npolicy: {}\n").length).toBeGreaterThanOrEqual(3);
  });
});

describe("applyEnvOverrides", () => {
  const { config } = compileCentralConfig(MINIMAL);

  it("returns the same object when nothing is overridden", () => {
    expect(applyEnvOverrides(config, {})).toBe(config);
  });

  it("applies and coerces GATE_* overrides", () => {
    const overridden = applyEnvOverrides(config, {
      GATE_LOGGER_LEVEL: "debug",
      GATE_OIDC_AUDIENCE: "my-gate",
      GATE_POLICY_DEFAULT_TOKEN_TTL: "600",
      GATE_POLICY_REQUIRE_EXPLICIT_POLICY: "true",
    });
    expect(overridden.logger.level).toBe("debug");
    expect(overridden.oidc.audience).toBe("my-gate");
    expect(overridden.policy.default_token_ttl).toBe(600);
    expect(overridden.policy.require_explicit_policy).toBe(true);
  });

  it("re-validates after overriding", () => {
    expect(() => applyEnvOverrides(config, { GATE_POLICY_DEFAULT_TOKEN_TTL: "99999" })).toThrow(
      /default token TTL must be less than or equal to max token TTL/,
    );
    expect(() => applyEnvOverrides(config, { GATE_POLICY_MAX_TOKEN_TTL: "soon" })).toThrow(
      /expected an integer/,
    );
    expect(() => applyEnvOverrides(config, { GATE_ORIGIN_ENABLED: "yes" })).toThrow(
      /expected true or false/,
    );
  });
});

describe("centralConfigJsonSchema", () => {
  it("describes the input shape for editors", () => {
    const schema = centralConfigJsonSchema();
    expect(schema).toHaveProperty("properties.policy.properties.max_token_ttl");
    expect(schema).toHaveProperty("required", ["policy", "github_apps"]);
  });
});
