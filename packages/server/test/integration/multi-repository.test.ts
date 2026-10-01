import { describe, expect, it } from "vitest";
import { startServer, type TestServer } from "./harness.ts";

const REPO_A = "example-org/repo-a";
const REPO_B = "example-org/repo-b";

/** An inline policy that admits the default caller (example-org/example-repo). */
function policy(issuer: string, name: string, permissions: string, extra = ""): string {
  return `version: "1.0"
trust_policies:
  - name: ${name}
    issuer: ${issuer}
    rules:
      - name: caller
        conditions:
          - field: repository
            pattern: "^example-org/example-repo$"
    permissions:
${permissions}
${extra}`;
}

function setPolicy(server: TestServer, repository: string, content: string): void {
  server.github.setPolicy(repository, content);
  server.github.setInstallation(repository);
}

async function exchangeMany(
  server: TestServer,
  targets: string[],
  extra: Record<string, unknown> = {},
) {
  return server.exchange({
    oidc_token: await server.oidc.token(),
    target_repositories: targets,
    requested_permissions: { contents: "read" },
    ...extra,
  });
}

describe("multi-repository tokens", () => {
  it("mints one token covering every repository when each trust policy allows it", async () => {
    const server = await startServer({ defaultTtl: 600 });
    server.setupPolicy(REPO_A, "contents_read_metadata_read.tpl.yaml");
    setPolicy(server, REPO_B, policy(server.oidc.issuer, "b-read", "      contents: write"));

    const got = await exchangeMany(server, [REPO_A, REPO_B]);
    expect(got.status).toBe(200);
    expect(got.body).toMatchObject({
      permissions: { contents: "read" },
      matched_policy: "default, b-read",
      repositories: [REPO_A, REPO_B],
      matched_policies: { [REPO_A]: "default", [REPO_B]: "b-read" },
    });

    const mints = server.github.requests.filter(
      (request) => request.path.endsWith("/access_tokens") && request.body !== undefined,
    );
    const repositoryMint = mints.find(
      (request) => (request.body as { repositories?: string[] }).repositories !== undefined,
    );
    expect(repositoryMint?.body).toEqual({
      permissions: { contents: "read" },
      repositories: ["repo-a", "repo-b"],
    });
    expect(server.scheduled).toHaveLength(1);
  });

  it("writes one granted audit entry per repository, sharing the token hash", async () => {
    const server = await startServer();
    server.setupPolicy(REPO_A, "contents_read.tpl.yaml");
    server.setupPolicy(REPO_B, "contents_read.tpl.yaml");
    await exchangeMany(server, [REPO_A, REPO_B]);

    const entries = server
      .logEntries()
      .filter((line) => line["msg"] === "audit")
      .map((line) => line["entry"] as Record<string, unknown>);
    expect(entries.map((entry) => entry["target_repository"])).toEqual([REPO_A, REPO_B]);
    expect(entries.every((entry) => entry["outcome"] === "granted")).toBe(true);
    expect(new Set(entries.map((entry) => entry["token_hash"])).size).toBe(1);
  });

  it("caps the TTL at the shortest one any matched policy allows", async () => {
    const server = await startServer({ defaultTtl: 3600 });
    server.setupPolicy(REPO_A, "contents_read.tpl.yaml");
    setPolicy(
      server,
      REPO_B,
      policy(server.oidc.issuer, "short", "      contents: read", "    token_ttl: 300"),
    );
    const got = await exchangeMany(server, [REPO_A, REPO_B]);
    expect(got.status).toBe(200);
    const expiresAt = Date.parse(got.body["expires_at"] as string);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + 300_000 + 5000);
    expect(server.scheduled[0]?.delaySeconds).toBeLessThanOrEqual(300);
  });

  it("denies the whole request, naming the repository, when one trust policy denies", async () => {
    const server = await startServer();
    server.setupPolicy(REPO_A, "contents_write.tpl.yaml");
    server.setupPolicy(REPO_B, "contents_read.tpl.yaml");
    const got = await exchangeMany(server, [REPO_A, REPO_B], {
      requested_permissions: { contents: "write" },
    });
    expect(got.status).toBe(403);
    expect(got.body["error_code"]).toBe("PERMISSION_EXCEEDS_POLICY");
    expect(got.body["error"]).toMatch(/^example-org\/repo-b: /);
    expect(
      server.github.requests.some(
        (request) => (request.body as { repositories?: unknown } | undefined)?.repositories,
      ),
    ).toBe(false);

    await server.settle();
    const denied = server
      .logEntries()
      .filter((line) => line["msg"] === "audit")
      .map((line) => line["entry"] as Record<string, unknown>);
    expect(denied.map((entry) => entry["target_repository"])).toEqual([REPO_A, REPO_B]);
    expect(denied.every((entry) => entry["outcome"] === "denied")).toBe(true);
  });

  it("denies when a repository has no trust policy", async () => {
    const server = await startServer();
    server.setupPolicy(REPO_A, "contents_read.tpl.yaml");
    server.github.setInstallation(REPO_B);
    const got = await exchangeMany(server, [REPO_A, REPO_B]);
    expect(got.status).toBe(403);
    expect(got.body["error_code"]).toBe("TRUST_POLICY_NOT_FOUND");
    expect(got.body["error"]).toMatch(/^example-org\/repo-b: /);
  });

  it("accepts a single-entry list and reports the multi-repository fields", async () => {
    const server = await startServer();
    server.setupPolicy(REPO_A, "contents_read.tpl.yaml");
    const got = await exchangeMany(server, [REPO_A]);
    expect(got.status).toBe(200);
    expect(got.body["repositories"]).toEqual([REPO_A]);
    expect(got.body["matched_policies"]).toEqual({ [REPO_A]: "default" });
  });

  it("leaves single-repository responses in upstream's shape", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchangeDefault();
    expect(got.status).toBe(200);
    expect(got.body).not.toHaveProperty("repositories");
    expect(got.body).not.toHaveProperty("matched_policies");
  });

  it.each<[string, Record<string, unknown>]>([
    ["empty list", { target_repositories: [] }],
    ["both fields", { target_repository: REPO_A, target_repositories: [REPO_A, REPO_B] }],
    ["both fields, one empty", { target_repository: "", target_repositories: [REPO_A, REPO_B] }],
    ["different owners", { target_repositories: [REPO_A, "other-org/repo-b"] }],
    ["owners spelled differently", { target_repositories: [REPO_A, "Example-Org/repo-b"] }],
    ["duplicate, ignoring case", { target_repositories: [REPO_A, "Example-Org/Repo-A"] }],
    ["malformed entry", { target_repositories: [REPO_A, "repo-b"] }],
    ["no requested permissions", { requested_permissions: undefined }],
    ["empty requested permissions", { requested_permissions: {} }],
    ["more than the maximum", { target_repositories: [REPO_A, REPO_B, "example-org/c"] }],
  ])("rejects %s as INVALID_REQUEST", async (_name, overrides) => {
    const server = await startServer({ maxTargetRepositories: 2 });
    server.setupPolicy(REPO_A, "contents_read.tpl.yaml");
    server.setupPolicy(REPO_B, "contents_read.tpl.yaml");
    const got = await exchangeMany(server, [REPO_A, REPO_B], overrides);
    expect(got.status).toBe(400);
    expect(got.body["error_code"]).toBe("INVALID_REQUEST");
    expect(server.github.requests).toHaveLength(0);
  });
});
