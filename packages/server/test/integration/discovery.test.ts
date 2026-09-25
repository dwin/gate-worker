import { loadPolicyFixture } from "@gate/testkit/fixtures";
import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer, type TestServer } from "./harness.ts";

const contents = "/repos/example-org/example-repo/contents";

describe("TestDiscovery", () => {
  it.each<[string, (server: TestServer) => void, string, number]>([
    [
      "no policy file",
      (s) => {
        s.github.setInstallation(DEFAULT_REPOSITORY);
      },
      "TRUST_POLICY_NOT_FOUND",
      403,
    ],
    [
      "API error",
      (s) => {
        s.github.setInstallation(DEFAULT_REPOSITORY);
        s.github.setError(contents, 500, "Internal Server Error");
      },
      "POLICY_LOAD_FAILED",
      500,
    ],
    [
      "rate limit",
      (s) => {
        s.github.setInstallation(DEFAULT_REPOSITORY);
        s.github.setError(contents, 429, "Rate limit exceeded");
      },
      "POLICY_LOAD_FAILED",
      500,
    ],
    [
      "forbidden",
      (s) => {
        s.github.setInstallation(DEFAULT_REPOSITORY);
        s.github.setError(contents, 403, "Resource not accessible");
      },
      "POLICY_LOAD_FAILED",
      500,
    ],
    [
      "empty policy file",
      (s) => {
        s.github.setPolicy(DEFAULT_REPOSITORY, "");
        s.github.setInstallation(DEFAULT_REPOSITORY);
      },
      "POLICY_LOAD_FAILED",
      500,
    ],
    [
      "unauthorized",
      (s) => {
        s.github.setInstallation(DEFAULT_REPOSITORY);
        s.github.setError(contents, 401, "Unauthorized");
      },
      "POLICY_LOAD_FAILED",
      500,
    ],
    [
      "service unavailable",
      (s) => {
        s.github.setInstallation(DEFAULT_REPOSITORY);
        s.github.setError(contents, 503, "Service Unavailable");
      },
      "POLICY_LOAD_FAILED",
      500,
    ],
  ])("PolicyLoadFailures/%s", async (_name, setup, code, status) => {
    const server = await startServer();
    setup(server);
    const got = await server.exchangeDefault();
    expect(got.body["error_code"]).toBe(code);
    expect(got.status).toBe(status);
  });

  it("tries .yaml then .yml when the configured path has no extension (added)", async () => {
    const server = await startServer({
      env: { GATE_POLICY_TRUST_POLICY_PATH: ".github/gate/{org}-policy" },
    });
    server.github.setPolicy(
      DEFAULT_REPOSITORY,
      loadPolicyFixture("contents_read.tpl.yaml", server.oidc.issuer),
      ".github/gate/example-org-policy.yml",
    );
    server.github.setInstallation(DEFAULT_REPOSITORY);
    expect((await server.exchangeDefault()).status).toBe(200);
    expect(server.github.wasRequested("/contents/.github/gate/example-org-policy.yaml")).toBe(true);
  });

  it("PolicyWithTimeout", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    server.github.setLatency(100);
    expect((await server.exchangeDefault()).status).toBe(200);
  });

  it("CrossOrgAccessWithPolicy", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "cross_org_access.tpl.yaml");
    const got = await server.exchange({
      oidc_token: await server.oidc.token({
        sub: "repo:otherorg/workflow-repo:ref:refs/heads/main",
        repository: "otherorg/workflow-repo",
      }),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(got.status).toBe(200);
  });

  it("MultiplePoliciesInFile", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "deeply_nested.tpl.yaml");
    const got = await server.exchange({
      oidc_token: await server.oidc.token({ environment: "development" }),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(got.body["matched_policy"]).toBe("policy-one");
  });

  it("ConcurrentRequests share one policy fetch", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const token = await server.oidc.token();
    const results = await Promise.all(
      Array.from({ length: 5 }, () =>
        server.exchange({ oidc_token: token, target_repository: DEFAULT_REPOSITORY }),
      ),
    );
    for (const got of results) {
      expect(got.status).toBe(200);
    }
    expect(server.github.count("/contents/")).toBe(1);
    expect(
      server.oidc.requests.filter((path) => path.endsWith("openid-configuration")),
    ).toHaveLength(1);
  });

  it("caches the parsed policy across requests (added)", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    await server.exchangeDefault();
    await server.exchangeDefault();
    expect(server.github.count("/contents/")).toBe(1);
  });
});
