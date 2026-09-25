import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer } from "./harness.ts";

describe("TestTTL", () => {
  it.each([
    ["default used when not requested", { defaultTtl: 1800, maxTtl: 3600 }, 0, 1800],
    ["custom within limits", { defaultTtl: 3600, maxTtl: 7200 }, 1800, 1800],
    ["exactly at maximum", { defaultTtl: 900, maxTtl: 1800 }, 1800, 1800],
  ])("SuccessScenarios/%s", async (_name, options, ttl, maxExpiry) => {
    const server = await startServer(options);
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: DEFAULT_REPOSITORY,
      requested_ttl: ttl,
    });
    expect(got.status).toBe(200);
    const expiresAt = Date.parse(got.body["expires_at"] as string);
    expect(expiresAt).toBeLessThanOrEqual(Date.now() + maxExpiry * 1000 + 30_000);
    expect(expiresAt).toBeGreaterThan(Date.now() + maxExpiry * 1000 - 30_000);
  });

  it.each([
    ["exceeds maximum rejected", { defaultTtl: 900, maxTtl: 1800 }, 7200],
    ["negative rejected", {}, -100],
  ])("ErrorScenarios/%s", async (_name, options, requestedTtl) => {
    const server = await startServer(options);
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: DEFAULT_REPOSITORY,
      requested_ttl: requestedTtl,
    });
    expect(got.status).toBe(400);
    expect(got.body["error_code"]).toBe("INVALID_REQUEST");
  });
});
