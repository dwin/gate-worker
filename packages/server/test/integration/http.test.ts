import { describe, expect, it } from "vitest";
import { startServer } from "./harness.ts";

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "x-xss-protection": "1; mode=block",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
};

describe("HTTP surface", () => {
  it("serves /health as liveness with upstream's security headers", async () => {
    const { app } = await startServer();
    const response = await app.request("/health");
    expect(response.status).toBe(200);
    expect(await response.text()).toBe(".");
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(response.headers.get(name)).toBe(value);
    }
    expect(response.headers.get("strict-transport-security")).toBeNull();
  });

  it("adds HSTS only for HTTPS requests", async () => {
    const { app } = await startServer();
    expect(
      (await app.request("https://gate.test/health")).headers.get("strict-transport-security"),
    ).toBe("max-age=31536000; includeSubDomains");
    expect(
      (await app.request("/health", { headers: { "X-Forwarded-Proto": "https" } })).headers.get(
        "strict-transport-security",
      ),
    ).toContain("max-age");
  });

  it("reports FIPS status on /api/v1/info", async () => {
    const { app } = await startServer();
    expect(await (await app.request("/api/v1/info")).json()).toEqual({ fips_enabled: false });
  });

  it("normalizes trailing and repeated slashes", async () => {
    const { app } = await startServer();
    expect((await app.request("/api/v1/info/")).status).toBe(200);
    expect((await app.request("//api//v1/info")).status).toBe(200);
    expect((await app.request("/health/")).status).toBe(200);
  });

  it("generates request IDs and ignores client-supplied ones", async () => {
    const { app } = await startServer();
    const response = await app.request("/api/v1/info", {
      headers: { "X-Request-Id": "attacker-chosen" },
    });
    expect(response.headers.get("x-request-id")).toMatch(/^[0-9a-f-]{36}$/);
  });

  it.each([
    ["malformed JSON", "{not json"],
    ["wrong types", JSON.stringify({ oidc_token: 42, target_repository: "a/b" })],
    [
      "fractional TTL",
      JSON.stringify({ oidc_token: "x", target_repository: "a/b", requested_ttl: 1.5 }),
    ],
  ])("returns a sanitized INVALID_REQUEST for %s", async (_name, body) => {
    const { app } = await startServer();
    const response = await app.request("/api/v1/exchange", { method: "POST", body });
    expect(response.status).toBe(400);
    const json = (await response.json()) as Record<string, unknown>;
    expect(json).toMatchObject({ error_code: "INVALID_REQUEST", error: "Invalid request" });
    expect(Object.keys(json).sort()).toEqual(["error", "error_code", "request_id"]);
  });

  it("rejects bodies over 1 MB", async () => {
    const { app } = await startServer();
    const response = await app.request("/api/v1/exchange", {
      method: "POST",
      body: JSON.stringify({ oidc_token: "x".repeat(1 << 20), target_repository: "a/b" }),
    });
    expect(response.status).toBe(400);
  });

  it("never leaks denial details to clients", async () => {
    const server = await startServer();
    server.setupPolicy("example-org/example-repo", "no_match_other_repo.tpl.yaml");
    const got = await server.exchangeDefault();
    expect(Object.keys(got.body).sort()).toEqual(["error", "error_code", "request_id"]);
  });

  describe("origin verification", () => {
    const origin = { headerName: "X-Origin-Verify", value: "shared-secret" };

    it("rejects API requests without the shared secret and allows them with it", async () => {
      const server = await startServer({ origin });
      expect((await server.app.request("/api/v1/info")).status).toBe(403);
      const denied = await server.app.request("/api/v1/info", {
        headers: { "X-Origin-Verify": "wrong" },
      });
      expect(await denied.json()).toMatchObject({ error_code: "ORIGIN_VERIFICATION_FAILED" });
      expect(
        (
          await server.app.request("/api/v1/info", {
            headers: { "X-Origin-Verify": "shared-secret" },
          })
        ).status,
      ).toBe(200);
    });

    it("leaves /health open for probes", async () => {
      const server = await startServer({ origin });
      expect((await server.app.request("/health")).status).toBe(200);
    });
  });

  it("returns 500 without details when secrets are missing", async () => {
    const server = await startServer({ env: { GATE_REVOCATION_KEYS: "" } });
    const response = await server.app.request("/api/v1/info");
    expect(response.status).toBe(500);
    expect(await response.json()).toMatchObject({
      error_code: "INTERNAL_ERROR",
      error: "Internal server error",
    });
  });
});
