import { loadPolicyFixture } from "@gate/testkit/fixtures";
import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer } from "./harness.ts";

describe("TestParsing", () => {
  it.each([
    ["invalid YAML", "invalid_syntax.yaml"],
    ["missing version", "missing_version.yaml"],
    ["wrong version", "wrong_version.yaml"],
    ["missing required fields/missing name", "missing_name.yaml"],
    ["missing required fields/missing issuer", "missing_issuer.yaml"],
    ["missing required fields/missing permissions", "missing_permissions.yaml"],
    ["missing required fields/empty rules", "empty_rules.yaml"],
    ["missing required fields/missing conditions", "missing_conditions.yaml"],
    ["invalid permission level", "invalid_permission_level.yaml"],
    ["invalid regex pattern", "invalid_regex_pattern.yaml"],
    ["duplicate policy names", "duplicate_policy_names.yaml"],
  ])("PolicyErrors/%s", async (_name, fixture) => {
    const server = await startServer();
    server.github.setPolicy(DEFAULT_REPOSITORY, loadPolicyFixture(fixture));
    server.github.setInstallation(DEFAULT_REPOSITORY);
    const got = await server.exchangeDefault();
    expect(got.status).toBe(500);
    expect(got.body["error_code"]).toBe("POLICY_LOAD_FAILED");
  });

  it("DeeplyNestedStructure", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "deeply_nested.tpl.yaml");
    const got = await server.exchange({
      oidc_token: await server.oidc.token({ environment: "staging" }),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(got.body["matched_policy"]).toBe("policy-two");
  });

  it("UnicodeContent", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "unicode_content.tpl.yaml");
    expect((await server.exchangeDefault()).body["token"]).toBeTruthy();
  });
});
