import { loadPolicyFixture } from "@gate/testkit/fixtures";
import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer, type ServerOptions, type TestServer } from "./harness.ts";

const twoApps: ServerOptions = {
  apps: [
    { clientId: "client-1", organization: "example-org" },
    { clientId: "client-2", organization: "other-org" },
  ],
};

describe("TestGitHub", () => {
  it.each<[string, ServerOptions, (server: TestServer) => void, string, string]>([
    [
      "installation not found",
      {},
      (s) => {
        s.setupDefaultPolicy();
        s.github.setError("/orgs/example-org/installation", 404, "Not Found");
        s.github.setError("/users/example-org/installation", 404, "Not Found");
      },
      DEFAULT_REPOSITORY,
      "REPOSITORY_NOT_FOUND",
    ],
    [
      "token creation error",
      {},
      (s) => {
        s.setupDefaultPolicy();
        s.github.setError("/app/installations/123456/access_tokens", 500, "Internal Server Error");
      },
      DEFAULT_REPOSITORY,
      "POLICY_LOAD_FAILED",
    ],
    [
      "rate limited",
      {},
      (s) => {
        s.setupDefaultPolicy();
        s.github.setError(
          "/app/installations/123456/access_tokens",
          403,
          "API rate limit exceeded",
          60,
        );
      },
      DEFAULT_REPOSITORY,
      "POLICY_LOAD_FAILED",
    ],
    [
      "multiple apps wrong org",
      twoApps,
      (s) => {
        s.setupPolicy("third-org/some-repo", "contents_read_metadata_read.tpl.yaml");
      },
      "third-org/some-repo",
      "POLICY_LOAD_FAILED",
    ],
  ])("ErrorScenarios/%s", async (_name, options, setup, repository, code) => {
    const server = await startServer(options);
    setup(server);
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: repository,
    });
    expect(got.body["error_code"]).toBe(code);
  });

  it("MultipleAppsCorrectOrg", async () => {
    const server = await startServer(twoApps);
    server.github.setPolicy(
      "other-org/repo",
      loadPolicyFixture("contents_read_metadata_read.tpl.yaml", server.oidc.issuer),
    );
    server.github.setInstallation("other-org/repo", 789012);
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: "other-org/repo",
    });
    expect(got.status).toBe(200);
    expect(server.github.wasRequested("/app/installations/789012/access_tokens")).toBe(true);
  });

  it("SingleAppBasicSuccess", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    expect((await server.exchangeDefault()).status).toBe(200);
    expect(server.github.wasRequested("/app/installations/123456/access_tokens")).toBe(true);
  });

  it("TokenWithCustomPermissions", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "contents_write_metadata_read.tpl.yaml");
    server.github.setToken(
      123456,
      "ghs_custom_token",
      { contents: "write", metadata: "read" },
      new Date(Date.now() + 3600_000),
    );
    const got = await server.exchangeDefault();
    expect(got.body["token"]).toBe("ghs_custom_token");
    expect(got.body["permissions"]).toEqual({ contents: "write", metadata: "read" });
  });

  it("MultipleRequestsSameInstallation", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    for (let attempt = 0; attempt < 3; attempt++) {
      const got = await server.exchangeDefault();
      expect(got.body["matched_policy"]).toBe("default");
    }
    expect(server.github.count("/installation", "GET")).toBe(1);
  });

  it("minting failure after authorization returns GITHUB_API_ERROR (502) (added)", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    await server.exchangeDefault(); // warm the policy cache, which needs its own token
    server.github.setError("/access_tokens", 500, "boom");
    const got = await server.exchangeDefault();
    expect(got.status).toBe(502);
    expect(got.body["error_code"]).toBe("GITHUB_API_ERROR");
  });

  it("records rate-limit usage and returns 429 with Retry-After when exhausted (added)", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    server.github.setRateLimit(0, new Date(Date.now() + 42_000));
    expect((await server.exchangeDefault()).status).toBe(200);
    await server.settle();
    const got = await server.exchangeDefault();
    expect(got.status).toBe(429);
    expect(got.body["error_code"]).toBe("RATE_LIMITED");
    const retryAfter = Number(got.headers.get("Retry-After"));
    expect(retryAfter).toBeGreaterThan(30);
    expect(got.body["retry_after_seconds"]).toBe(retryAfter);
  });
});
