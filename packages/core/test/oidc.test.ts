import { createFetchRouter, FakeOidcProvider } from "@gate/testkit";
import { beforeEach, describe, expect, it } from "vitest";
import { OidcValidationError, OidcValidator } from "../src/index.ts";

let provider: FakeOidcProvider;
let router: ReturnType<typeof createFetchRouter>;
let validator: OidcValidator;

beforeEach(async () => {
  provider = await FakeOidcProvider.create();
  router = createFetchRouter({ [provider.origin]: provider.handle });
  validator = new OidcValidator({
    audience: provider.issuer,
    issuers: [provider.issuer],
    fetch: router.fetch,
  });
});

const now = () => Math.floor(Date.now() / 1000);

/** Wraps a router with fetch's redirect modes, so tests see what a real fetch would do. */
function withRedirects(inner: typeof router.fetch): typeof router.fetch {
  const wrapped: typeof router.fetch = async (input, init) => {
    const response = await inner(input, init);
    const location = response.headers.get("location");
    if (response.status < 300 || response.status >= 400 || location === null) return response;
    if (init?.redirect === "error") throw new TypeError("fetch failed: unexpected redirect");
    if (init?.redirect === "manual") return response;
    const base = input instanceof Request ? input.url : String(input);
    return wrapped(new URL(location, base).href, init);
  };
  return wrapped;
}

async function rejects(token: string, message?: RegExp): Promise<void> {
  const error = await validator.validate(token).catch((caught: unknown) => caught);
  expect(error).toBeInstanceOf(OidcValidationError);
  if (message) expect((error as Error).message).toMatch(message);
}

// Upstream TestOIDC_* cases, at the validator level.
describe("OidcValidator", () => {
  it("accepts a valid token and separates registered from custom claims", async () => {
    const claims = await validator.validate(
      await provider.token({ jti: "id-1", actor: "octocat" }),
    );
    expect(claims.issuer).toBe(provider.issuer);
    expect(claims.subject).toBe("repo:example-org/example-repo:ref:refs/heads/main");
    expect(claims.audience).toEqual([provider.issuer]);
    expect(claims.custom).toEqual({
      repository: "example-org/example-repo",
      ref: "refs/heads/main",
      actor: "octocat",
    });
  });

  it.each([
    ["empty", "", /token is empty/],
    ["not a JWT", "not-a-jwt-token", /malformed token/],
    ["incomplete JWT", "header.payload", /malformed token/],
    ["random base64", "YWJj.ZGVm.Z2hp", /malformed token/],
  ])("rejects a malformed token (%s)", async (_name, token, message) => {
    await rejects(token, message);
  });

  it("rejects an untrusted issuer without making any network request", async () => {
    await rejects(
      await provider.token({ iss: "https://untrusted-issuer.example.com" }),
      /issuer not in allowed list/,
    );
    expect(router.calls).toHaveLength(0);
  });

  it("rejects expired, not-yet-valid, and future-issued tokens", async () => {
    await rejects(
      await provider.token({ exp: now() - 3600, iat: now() - 7200, nbf: now() - 7200 }),
    );
    await rejects(await provider.token({ exp: now() + 7200, nbf: now() + 3600 }));
    await rejects(
      await provider.token({ exp: now() + 7200, iat: now() + 3600 }),
      /issued in the future/,
    );
  });

  it("allows 5 minutes of clock skew on nbf but none on exp", async () => {
    await expect(
      validator.validate(await provider.token({ nbf: now() + 120 })),
    ).resolves.toBeDefined();
    await rejects(await provider.token({ exp: now() - 1 }));
  });

  it("rejects missing iss or exp, but accepts a missing sub", async () => {
    await rejects(await provider.token({ iss: undefined }), /missing issuer/);
    await rejects(await provider.token({ exp: undefined }));
    expect((await validator.validate(await provider.token({ sub: undefined }))).subject).toBe("");
  });

  it("checks the audience, accepting it anywhere in an audience list", async () => {
    await rejects(await provider.token({ aud: "https://wrong-audience.example.com" }));
    await expect(
      validator.validate(
        await provider.token({ aud: ["https://other.example.com", provider.issuer] }),
      ),
    ).resolves.toBeDefined();
  });

  it("rejects a signature from another key", async () => {
    const impostor = await FakeOidcProvider.create(provider.issuer);
    await rejects(await impostor.token(), /verifying token/);
  });

  it("caches discovery and JWKS across validations", async () => {
    await validator.validate(await provider.token());
    await validator.validate(await provider.token());
    expect(provider.requests.filter((path) => path.endsWith("openid-configuration"))).toHaveLength(
      1,
    );
    expect(provider.requests.filter((path) => path === "/jwks")).toHaveLength(1);
  });

  it("shares one rediscovery among concurrent callers once the cache is stale", async () => {
    let clockMs = Date.now();
    const clocked = new OidcValidator({
      audience: provider.issuer,
      issuers: [provider.issuer],
      fetch: router.fetch,
      clock: { now: () => clockMs },
    });
    await clocked.validate(await provider.token());
    clockMs += 2 * 60 * 60 * 1000;
    const issuedAt = Math.floor(clockMs / 1000);
    const later = { iat: issuedAt, nbf: issuedAt, exp: issuedAt + 600 };
    const tokens = await Promise.all([1, 2, 3].map(() => provider.token(later)));
    await Promise.all(tokens.map((token) => clocked.validate(token)));
    expect(provider.requests.filter((path) => path.endsWith("openid-configuration"))).toHaveLength(
      2,
    );
  });

  it("rejects a plaintext jwks_uri from discovery", async () => {
    const provider2 = await FakeOidcProvider.create("https://plain-jwks.gate.test");
    const router2 = createFetchRouter({
      [provider2.origin]: () =>
        Response.json({ issuer: provider2.issuer, jwks_uri: "http://keys.gate.test/jwks" }),
    });
    const strict = new OidcValidator({
      audience: provider2.issuer,
      issuers: [provider2.issuer],
      fetch: router2.fetch,
    });
    await expect(strict.validate(await provider2.token({ aud: provider2.issuer }))).rejects.toThrow(
      /jwks_uri must use https/,
    );
  });

  it("does not follow a discovery redirect to plaintext", async () => {
    const moved = await FakeOidcProvider.create("https://moved.gate.test");
    const redirecting = createFetchRouter({
      [moved.origin]: () =>
        new Response(null, {
          status: 302,
          headers: { location: "http://evil.gate.test/.well-known/openid-configuration" },
        }),
      "http://evil.gate.test": () =>
        Response.json({ issuer: moved.issuer, jwks_uri: "https://evil.gate.test/jwks" }),
    });
    const strict = new OidcValidator({
      audience: moved.issuer,
      issuers: [moved.issuer],
      fetch: withRedirects(redirecting.fetch),
    });
    await expect(strict.validate(await moved.token({ aud: moved.issuer }))).rejects.toThrow(
      /discovering issuer .*HTTP 302/,
    );
    expect(redirecting.calls.some((call) => call.url.includes("evil.gate.test"))).toBe(false);
  });

  it("does not follow a JWKS redirect", async () => {
    const hosted = await FakeOidcProvider.create("https://hosted.gate.test");
    const impostor = await FakeOidcProvider.create(hosted.issuer);
    const redirecting = createFetchRouter({
      [hosted.origin]: (request) =>
        new URL(request.url).pathname === "/jwks"
          ? new Response(null, {
              status: 302,
              headers: { location: "http://evil.gate.test/jwks" },
            })
          : hosted.handle(request),
      "http://evil.gate.test": (request) => impostor.handle(request),
    });
    const strict = new OidcValidator({
      audience: hosted.issuer,
      issuers: [hosted.issuer],
      fetch: withRedirects(redirecting.fetch),
    });
    await expect(strict.validate(await impostor.token({ aud: hosted.issuer }))).rejects.toThrow(
      OidcValidationError,
    );
    expect(redirecting.calls.some((call) => call.url.includes("evil.gate.test"))).toBe(false);
  });

  it("rejects a discovery document for a different issuer", async () => {
    const liar = await FakeOidcProvider.create("https://liar.gate.test");
    const lyingRouter = createFetchRouter({
      [liar.origin]: () =>
        Response.json({ issuer: "https://someone-else.test", jwks_uri: `${liar.issuer}/jwks` }),
    });
    const strict = new OidcValidator({
      audience: liar.issuer,
      issuers: [liar.issuer],
      fetch: lyingRouter.fetch,
    });
    await expect(strict.validate(await liar.token({ aud: liar.issuer }))).rejects.toThrow(
      /issuer did not match/,
    );
  });
});
