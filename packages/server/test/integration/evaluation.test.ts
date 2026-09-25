import { loadPolicyFixture } from "@gate/testkit/fixtures";
import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer } from "./harness.ts";

async function run(fixture: string, overrides: Record<string, unknown> = {}) {
  const server = await startServer();
  server.setupPolicy(DEFAULT_REPOSITORY, fixture);
  return server.exchange({
    oidc_token: await server.oidc.token(overrides),
    target_repository: DEFAULT_REPOSITORY,
  });
}

type Case = readonly [name: string, value: string, matches: boolean];

function claimMatch(fixture: string, claim: string, cases: readonly Case[]) {
  it.each(cases)("%s", async (_name, value, matches) => {
    const got = await run(fixture, { [claim]: value });
    if (matches) expect(got.status).toBe(200);
    else expect(got.body["error_code"]).toBe("NO_RULES_MATCHED");
  });
}

function refMatch(fixture: string, cases: readonly Case[]) {
  it.each(cases)("%s", async (_name, value, matches) => {
    const got = await run(fixture, { ref: value, sub: `repo:${DEFAULT_REPOSITORY}:ref:${value}` });
    if (matches) expect(got.status).toBe(200);
    else expect(got.body["error_code"]).toBe("NO_RULES_MATCHED");
  });
}

describe("TestEvaluation", () => {
  it("NoRulesMatched", async () => {
    expect((await run("no_match_other_repo.tpl.yaml")).body["error_code"]).toBe("NO_RULES_MATCHED");
  });

  it("ANDLogicAllMatch", async () => {
    expect((await run("and_logic_main_branch.tpl.yaml")).body["matched_policy"]).toBe("default");
  });

  it("ANDLogicPartialMatch", async () => {
    const got = await run("and_logic_main_branch_contents_only.tpl.yaml", {
      ref: "refs/heads/feature",
      sub: "repo:example-org/example-repo:ref:refs/heads/feature",
    });
    expect(got.body["error_code"]).toBe("NO_RULES_MATCHED");
  });

  it("ORLogicOneMatch", async () => {
    expect((await run("or_logic_multiple_repos.tpl.yaml")).status).toBe(200);
  });

  it("ORLogicNoneMatch", async () => {
    expect((await run("or_logic_no_match.tpl.yaml")).body["error_code"]).toBe("NO_RULES_MATCHED");
  });

  it("RegexWildcard", async () => {
    expect((await run("regex_wildcard.tpl.yaml")).status).toBe(200);
  });

  it("IssuerMismatch", async () => {
    const server = await startServer();
    server.github.setPolicy(DEFAULT_REPOSITORY, loadPolicyFixture("wrong_issuer.yaml"));
    server.github.setInstallation(DEFAULT_REPOSITORY);
    expect((await server.exchangeDefault()).body["error_code"]).toBe("NO_RULES_MATCHED");
  });

  describe("ComplexRegexPatterns", () => {
    refMatch("complex_regex_patterns.tpl.yaml", [
      ["main branch matches", "refs/heads/main", true],
      ["release branch matches", "refs/heads/release/v1.0", true],
      ["feature branch does not match", "refs/heads/feature/new-feature", false],
      ["develop branch does not match", "refs/heads/develop", false],
    ]);
  });

  describe("TagRefMatching", () => {
    refMatch("tag_refs.tpl.yaml", [
      ["valid semver tag matches", "refs/tags/v1.2.3", true],
      ["valid semver tag with higher version matches", "refs/tags/v10.20.30", true],
      ["invalid tag format does not match", "refs/tags/release-1.0", false],
      ["branch ref does not match tag pattern", "refs/heads/main", false],
    ]);
  });

  it("MultipleRulesFirstMatches", async () => {
    expect((await run("multiple_rules_first_matches.tpl.yaml")).body["matched_policy"]).toBe(
      "default",
    );
  });

  describe("EnvironmentClaimMatching", () => {
    it.each([
      ["production environment matches", "production", true],
      ["staging environment does not match", "staging", false],
      ["empty environment does not match", "", false],
    ])("%s", async (_name, environment, matches) => {
      const got = await run("environment_claim.tpl.yaml", environment ? { environment } : {});
      if (matches) expect(got.status).toBe(200);
      else expect(got.body["error_code"]).toBe("NO_RULES_MATCHED");
    });
  });

  describe("ActorClaimMatching", () => {
    claimMatch("actor_claim.tpl.yaml", "actor", [
      ["admin user matches", "admin-user", true],
      ["deploy bot matches", "deploy-bot", true],
      ["regular user does not match", "regular-user", false],
    ]);
  });

  describe("WorkflowRefMatching", () => {
    claimMatch("workflow_ref_claim.tpl.yaml", "job_workflow_ref", [
      [
        "approved workflow matches",
        "example-org/shared-workflows/.github/workflows/deploy.yml@refs/heads/main",
        true,
      ],
      [
        "unapproved workflow does not match",
        "example-org/other-repo/.github/workflows/deploy.yml@refs/heads/main",
        false,
      ],
    ]);
  });

  describe("EventNameMatching", () => {
    claimMatch("event_name_claim.tpl.yaml", "event_name", [
      ["push event matches", "push", true],
      ["workflow_dispatch event matches", "workflow_dispatch", true],
      ["pull_request event does not match", "pull_request", false],
    ]);
  });

  describe("SubjectClaimPatternMatching", () => {
    claimMatch("subject_claim.tpl.yaml", "sub", [
      ["main branch subject matches", "repo:example-org/example-repo:ref:refs/heads/main", true],
      [
        "release branch subject matches",
        "repo:example-org/example-repo:ref:refs/heads/release/v1.0",
        true,
      ],
      [
        "feature branch subject does not match",
        "repo:example-org/example-repo:ref:refs/heads/feature/new",
        false,
      ],
    ]);
  });

  describe("NestedClaimMatching", () => {
    it.each([
      ["nested value matches", { preferences: { theme: "dark" } }, true],
      ["nested value does not match", { preferences: { theme: "light" } }, false],
      ["missing nested object does not match", undefined, false],
    ])("%s", async (_name, metadata, matches) => {
      const got = await run("nested_claim.tpl.yaml", metadata ? { app_metadata: metadata } : {});
      if (matches) expect(got.status).toBe(200);
      else expect(got.body["error_code"]).toBe("NO_RULES_MATCHED");
    });
  });

  describe("ORLogicMultipleConditions", () => {
    refMatch("or_logic_multi_condition.tpl.yaml", [
      ["main branch matches first OR condition", "refs/heads/main", true],
      ["develop branch matches second OR condition", "refs/heads/develop", true],
      ["feature branch does not match any OR condition", "refs/heads/feature/test", false],
    ]);
  });

  it("MultiplePoliciesThirdMatches", async () => {
    const got = await run("deeply_nested.tpl.yaml", { environment: "production" });
    expect(got.body["matched_policy"]).toBe("policy-three");
    expect((got.body["permissions"] as Record<string, string>)["packages"]).toBe("write");
  });
});
