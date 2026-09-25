import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer } from "./harness.ts";

const now = () => Math.floor(Date.now() / 1000);

describe("TestOIDC", () => {
  it.each([
    ["empty token", "", "INVALID_REQUEST"],
    ["not a JWT", "not-a-jwt-token", "INVALID_TOKEN"],
    ["incomplete JWT", "header.payload", "INVALID_TOKEN"],
    ["random base64", "YWJj.ZGVm.Z2hp", "INVALID_TOKEN"],
  ])("MalformedToken/%s", async (_name, token, code) => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchange({ oidc_token: token, target_repository: DEFAULT_REPOSITORY });
    expect(got.body["error_code"]).toBe(code);
  });

  it.each([
    ["ExpiredToken", { exp: now() - 3600, iat: now() - 7200, nbf: now() - 7200 }],
    ["NotYetValidToken", { exp: now() + 7200, nbf: now() + 3600 }],
    ["FutureIssuedAt", { exp: now() + 7200, iat: now() + 3600 }],
    ["UntrustedIssuer", { iss: "https://untrusted-issuer.example.com" }],
    ["WrongAudience", { aud: "https://wrong-audience.example.com" }],
    ["MissingClaims/missing issuer", { iss: undefined }],
    ["MissingClaims/missing expiration", { exp: undefined }],
  ])("%s is rejected with INVALID_TOKEN (401)", async (_name, overrides) => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token(overrides),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(got.status).toBe(401);
    expect(got.body["error_code"]).toBe("INVALID_TOKEN");
  });

  it("UntrustedIssuer never reaches the network", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    await server.exchange({
      oidc_token: await server.oidc.token({ iss: "https://untrusted-issuer.example.com" }),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(server.router.calls).toHaveLength(0);
  });

  it.each([
    ["MissingSubjectSucceeds", { sub: undefined }],
    ["ValidToken", {}],
    ["MultipleAudiences", { aud: ["https://other.example.com", "https://oidc.gate.test"] }],
  ])("%s", async (_name, overrides) => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token(overrides),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(got.status).toBe(200);
    expect(got.body["token"]).toBeTruthy();
  });

  it("MissingSubjectSucceeds records a placeholder caller in the audit entry (added)", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    await server.exchange({
      oidc_token: await server.oidc.token({ sub: undefined }),
      target_repository: DEFAULT_REPOSITORY,
    });
    const audit = server.logEntries().find((line) => line["msg"] === "audit");
    expect(audit?.["entry"]).toMatchObject({ outcome: "granted", caller: "(missing sub claim)" });
  });

  it("AdditionalClaims", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "environment_claim.tpl.yaml");
    const got = await server.exchange({
      oidc_token: await server.oidc.token({ environment: "production", actor: "deploy-bot" }),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect(got.status).toBe(200);
  });

  it("TokenWithAllClaims", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token({
        jti: "unique-token-id-12345",
        repository_owner: "example-org",
        repository_owner_id: "12345678",
        repository_id: "87654321",
        repository_visibility: "private",
        ref_type: "branch",
        sha: "abc123def456",
        actor: "test-user",
        actor_id: "11111111",
        workflow: "CI",
        workflow_ref: "example-org/example-repo/.github/workflows/ci.yml@refs/heads/main",
        event_name: "push",
        run_id: "9876543210",
        run_number: "42",
        run_attempt: "1",
      }),
      target_repository: DEFAULT_REPOSITORY,
    });
    expect((got.body["permissions"] as Record<string, string>)["contents"]).toBe("read");
  });
});
