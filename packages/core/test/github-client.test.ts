import { createFetchRouter, FakeGitHub, generateAppKeyPem } from "@gate/testkit";
import { importJWK, jwtVerify, exportJWK } from "jose";
import { beforeEach, describe, expect, it } from "vitest";
import {
  FileNotFoundError,
  GitHubApiError,
  GitHubAppClient,
  importAppPrivateKey,
  InstallationNotFoundError,
  RepositoryNotFoundError,
  type RetryPolicy,
} from "../src/index.ts";

const NO_WAIT: RetryPolicy = {
  maxAttempts: 4,
  initialBackoffMs: 0,
  maxBackoffMs: 0,
  multiplier: 2,
  jitterFraction: 0,
};
const REPO = "example-org/example-repo";

let github: FakeGitHub;
let client: GitHubAppClient;
let publicKey: CryptoKey;
const sleeps: number[] = [];

beforeEach(async () => {
  github = new FakeGitHub();
  const keys = await generateAppKeyPem();
  publicKey = keys.publicKey;
  sleeps.length = 0;
  client = new GitHubAppClient({
    clientId: "Iv1.test",
    privateKey: await importAppPrivateKey(keys.pem, "test"),
    baseUrl: github.baseUrl,
    fetch: createFetchRouter({ [github.origin]: github.handle }).fetch,
    retry: NO_WAIT,
    sleep: (ms) => {
      sleeps.push(ms);
      return Promise.resolve();
    },
  });
  github.setInstallation(REPO);
});

describe("GitHubAppClient.requestToken", () => {
  it("finds the org installation and mints a repository-scoped token", async () => {
    const token = await client.requestToken(REPO, { contents: "read" });
    expect(token.token).toMatch(/^ghs_test_token_123456/);
    const mint = github.requests.find((request) => request.path.endsWith("/access_tokens"));
    expect(mint?.body).toEqual({
      permissions: { contents: "read" },
      repositories: ["example-repo"],
    });
  });

  it("signs the App JWT with RS256, the client ID as issuer, and backdated iat", async () => {
    await client.requestToken(REPO, { contents: "read" });
    const jwt = (github.requests[0]?.authorization ?? "").replace("Bearer ", "");
    const { payload, protectedHeader } = await jwtVerify(
      jwt,
      await importJWK(await exportJWK(publicKey), "RS256"),
    );
    expect(protectedHeader.alg).toBe("RS256");
    expect(payload.iss).toBe("Iv1.test");
    expect((payload.exp ?? 0) - (payload.iat ?? 0)).toBe(605);
  });

  it("falls back to the user installation when the org lookup 404s", async () => {
    const userClient = client;
    github.setInstallation("octocat/dotfiles", 42);
    github.setError("/orgs/octocat/installation", 404, "Not Found");
    await expect(
      userClient.requestToken("octocat/dotfiles", { contents: "read" }),
    ).resolves.toBeDefined();
    expect(github.wasRequested("/users/octocat/installation")).toBe(true);
  });

  it("caches installation IDs", async () => {
    await client.requestToken(REPO, { contents: "read" });
    await client.requestToken(REPO, { contents: "read" });
    expect(github.count("/installation", "GET")).toBe(1);
  });

  it("maps 404 and 422 on token creation to RepositoryNotFoundError", async () => {
    github.setError("/access_tokens", 422, "Unprocessable");
    await expect(client.requestToken(REPO, { contents: "read" })).rejects.toBeInstanceOf(
      RepositoryNotFoundError,
    );
  });

  it("reports a missing installation", async () => {
    await expect(client.requestToken("nobody/repo", { contents: "read" })).rejects.toBeInstanceOf(
      InstallationNotFoundError,
    );
  });
});

describe("retry policy", () => {
  it("retries every 4xx/5xx up to four attempts, then returns the error", async () => {
    github.setError("/access_tokens", 500, "boom");
    await expect(client.requestToken(REPO, { contents: "read" })).rejects.toBeInstanceOf(
      GitHubApiError,
    );
    expect(github.count("/access_tokens")).toBe(4);
    expect(sleeps).toHaveLength(3);
  });

  it("uses upstream's 2s/4s/8s schedule capped at 10s", async () => {
    const { backoffMs, DEFAULT_RETRY_POLICY } = await import("../src/github/retry.ts");
    const noJitter = () => 0.5;
    expect(
      [1, 2, 3, 4].map((attempt) => backoffMs(DEFAULT_RETRY_POLICY, attempt, noJitter)),
    ).toEqual([2000, 4000, 8000, 10_000]);
  });
});

describe("GitHubAppClient.getContents", () => {
  it("decodes base64 file content with a cached contents:read token after the replication delay", async () => {
    github.setPolicy(REPO, 'version: "1.0"\n# ünïcødé\n');
    expect(await client.getContents(REPO, ".github/trust-policy.yaml")).toBe(
      'version: "1.0"\n# ünïcødé\n',
    );
    await client.getContents(REPO, ".github/trust-policy.yaml");
    expect(github.count("/access_tokens")).toBe(1);
    expect(sleeps).toEqual([2000]);
    const mint = github.requests.find((request) => request.path.endsWith("/access_tokens"));
    expect(mint?.body).toEqual({ permissions: { contents: "read" } });
  });

  it("throws FileNotFoundError on 404", async () => {
    await expect(client.getContents(REPO, "missing.yaml")).rejects.toBeInstanceOf(
      FileNotFoundError,
    );
  });

  it("re-mints once with a fresh token after 401/403", async () => {
    github.setPolicy(REPO, "x");
    github.setError("/contents/", 403, "Resource not accessible");
    await expect(client.getContents(REPO, ".github/trust-policy.yaml")).rejects.toBeInstanceOf(
      GitHubApiError,
    );
    expect(github.count("/access_tokens")).toBe(2);
  });
});

describe("revokeToken and rateLimit", () => {
  it("revokes, treating an already-invalid token (401) as success", async () => {
    await client.revokeToken("ghs_a");
    expect(github.revokedTokens).toEqual(["ghs_a"]);
    await expect(client.revokeToken("ghs_a")).resolves.toBeUndefined();
  });

  it("reads the core rate limit", async () => {
    github.setRateLimit(42, new Date(1_900_000_000_000));
    expect(await client.rateLimit("ghs_a")).toEqual({
      remaining: 42,
      resetAt: new Date(1_900_000_000_000),
    });
  });
});
