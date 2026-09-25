import { readdirSync } from "node:fs";
import { loadPolicyFixture } from "@gate/testkit/fixtures";
import { describe, expect, it } from "vitest";
import { parseTrustPolicy, TrustPolicyError, trustPolicyJsonSchema } from "../src/index.ts";
import { compilePattern } from "../src/util/regex.ts";

const ISSUER = "https://oidc.gate.test";

function problems(yaml: string): string {
  try {
    parseTrustPolicy(yaml);
  } catch (error) {
    if (error instanceof TrustPolicyError) return error.issues.join("\n");
    throw error;
  }
  throw new Error("expected parseTrustPolicy to fail");
}

describe("parseTrustPolicy with upstream fixtures", () => {
  // Same fixtures and expectations as upstream TestParsing_PolicyErrors, with the message upstream produces.
  it.each([
    // Upstream's fixture is valid YAML despite its name; it fails schema validation.
    ["invalid_syntax.yaml", /^version is required$/m],
    ["missing_version.yaml", /^version is required$/m],
    ["wrong_version.yaml", /unsupported trust policy version: 2\.0 \(expected 1\.0\)/],
    ["missing_name.yaml", /^policy 0 \(\): name is required$/m],
    ["missing_issuer.yaml", /^policy 0 \(default\): issuer is required$/m],
    ["missing_permissions.yaml", /^policy 0 \(default\): at least one permission is required$/m],
    ["empty_rules.yaml", /^policy 0 \(empty\): at least one rule is required$/m],
    [
      "missing_conditions.yaml",
      /^policy 0 \(default\): rule 0 \(empty-rule\): at least one condition is required$/m,
    ],
    ["invalid_permission_level.yaml", /permission "contents" has invalid level "invalid_level"/],
    [
      "invalid_regex_pattern.yaml",
      /rule 0 \(allow-main\): condition 0: invalid pattern "\[invalid\(regex"/,
    ],
    ["duplicate_policy_names.yaml", /duplicate policy name: default/],
  ])("%s fails with upstream's message", (fixture, expected) => {
    expect(problems(loadPolicyFixture(fixture))).toMatch(expected);
  });

  it("reports malformed YAML as a parse error", () => {
    expect(problems('version: "1.0\ntrust_policies: []\n')).toMatch(/^parsing YAML:/);
  });

  it("an empty file fails like upstream (version is required)", () => {
    expect(problems("")).toMatch(/version is required/);
  });

  it("valid.yaml parses", () => {
    const file = parseTrustPolicy(loadPolicyFixture("valid.yaml"));
    expect(file.trust_policies[0]).toMatchObject({
      name: "default",
      permissions: { contents: "read", metadata: "read" },
    });
    expect(file.trust_policies[0]?.rules[0]?.logic).toBe("AND");
  });

  const templates = readdirSync(
    new URL("../../testkit/fixtures/policies/", import.meta.url),
  ).filter((name) => name.endsWith(".tpl.yaml"));

  it.each(templates)("template %s parses and compiles every pattern", (fixture) => {
    const file = parseTrustPolicy(loadPolicyFixture(fixture, ISSUER));
    expect(file.trust_policies.length).toBeGreaterThan(0);
  });
});

describe("trust policy parsing details", () => {
  const base = (extra: string) => `version: "1.0"
trust_policies:
  - name: p
    issuer: ${ISSUER}
    rules:
      - name: r
        ${extra}
        conditions:
          - field: ref
            pattern: "^refs/heads/main$"
    permissions:
      contents: read
    token_ttl: 600
`;

  it("keeps unquoted versions as written, like Go's yaml.v3 into a string", () => {
    const file = parseTrustPolicy(base("").replace('version: "1.0"', "version: 1.0"));
    expect(file.version).toBe("1.0");
  });

  it("reads integer fields from failsafe YAML", () => {
    expect(parseTrustPolicy(base("")).trust_policies[0]?.token_ttl).toBe(600);
  });

  it("rejects unknown rule logic", () => {
    expect(problems(base("logic: XOR"))).toMatch(/logic must be AND or OR, got "XOR"/);
  });

  it("rejects RE2-incompatible syntax such as lookahead", () => {
    expect(problems(base("").replace("^refs/heads/main$", "^(?=refs)"))).toMatch(/invalid pattern/);
  });

  it("publishes a JSON Schema repositories can lint against", () => {
    expect(trustPolicyJsonSchema()).toHaveProperty("properties.trust_policies");
  });
});

describe("RE2 matching", () => {
  it("is unanchored like Go's MatchString", () => {
    expect(
      compilePattern("example-org/example-repo").test("repo:example-org/example-repo:ref"),
    ).toBe(true);
  });

  it("runs in linear time on patterns that make backtracking engines explode", () => {
    const start = performance.now();
    expect(compilePattern("^(a+)+$").test(`${"a".repeat(100_000)}!`)).toBe(false);
    expect(performance.now() - start).toBeLessThan(2000);
  });
});
