import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer, type ServerOptions } from "./harness.ts";

async function run(fixture: string, policyName?: string, options: ServerOptions = {}) {
  const server = await startServer(options);
  server.setupPolicy(DEFAULT_REPOSITORY, fixture);
  return server.exchange({
    oidc_token: await server.oidc.token(),
    target_repository: DEFAULT_REPOSITORY,
    ...(policyName === undefined ? {} : { policy_name: policyName }),
  });
}

describe("TestExplicit", () => {
  it("PolicyNameProvided", async () => {
    expect(
      (await run("explicit_production_development.tpl.yaml", "production")).body["matched_policy"],
    ).toBe("production");
  });

  it("PolicyNameNotFound", async () => {
    const got = await run("explicit_production_only.tpl.yaml", "nonexistent");
    expect(got.body["error_code"]).toBe("POLICY_NOT_FOUND");
    expect(got.status).toBe(404);
  });

  it("PolicyNameSelectsCorrectPolicy", async () => {
    expect(
      (await run("multi_policy_readonly_readwrite.tpl.yaml", "readwrite")).body["matched_policy"],
    ).toBe("readwrite");
  });

  it("RequireExplicitPolicyWithoutName", async () => {
    const got = await run("contents_read.tpl.yaml", undefined, { requireExplicitPolicy: true });
    expect(got.body["error_code"]).toBe("POLICY_NAME_REQUIRED");
  });

  it.each([
    ["uppercase Production matches", "Production", true],
    ["lowercase production matches", "production", true],
    ["mixed case does not match", "PRODUCTION", false],
  ])("CaseSensitivePolicyNames/%s", async (_name, policy, matches) => {
    const got = await run("explicit_case_sensitivity.tpl.yaml", policy);
    if (matches) {
      expect(got.body["matched_policy"]).toBe(policy);
    } else {
      expect(got.body["error_code"]).toBe("POLICY_NOT_FOUND");
    }
  });

  it.each([["deploy-prod"], ["deploy_staging"]])(
    "SpecialCharactersInPolicyNames/%s",
    async (policy) => {
      expect((await run("explicit_special_chars.tpl.yaml", policy)).body["matched_policy"]).toBe(
        policy,
      );
    },
  );

  it("EmptyPolicyNameWithExplicitRequired", async () => {
    const got = await run("multi_policy_readonly_readwrite.tpl.yaml", "", {
      requireExplicitPolicy: true,
    });
    expect(got.body["error_code"]).toBe("POLICY_NAME_REQUIRED");
  });

  it("MultiplePoliciesFirstByOrder", async () => {
    expect((await run("multi_policy_readonly_readwrite.tpl.yaml")).body["matched_policy"]).toBe(
      "readonly",
    );
  });
});
