import { exportJWK, generateKeyPair, SignJWT, type JWK } from "jose";

export const FAKE_OIDC_ISSUER = "https://oidc.gate.test";
export const DEFAULT_REPOSITORY = "example-org/example-repo";

/**
 * A fake OIDC provider serving discovery and JWKS, and signing arbitrary claim
 * sets. Port of upstream `internal/testutil/oidc.go`.
 */
export class FakeOidcProvider {
  readonly issuer: string;
  readonly requests: string[] = [];
  #privateKey: CryptoKey | undefined;
  #jwk: JWK | undefined;

  constructor(issuer: string = FAKE_OIDC_ISSUER) {
    this.issuer = issuer;
  }

  static async create(issuer?: string): Promise<FakeOidcProvider> {
    const provider = new FakeOidcProvider(issuer);
    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
    provider.#privateKey = privateKey;
    provider.#jwk = { ...(await exportJWK(publicKey)), kid: "test-key", alg: "RS256", use: "sig" };
    return provider;
  }

  get origin(): string {
    return new URL(this.issuer).origin;
  }

  readonly handle = (request: Request): Response => {
    const { pathname } = new URL(request.url);
    this.requests.push(pathname);
    if (pathname === "/.well-known/openid-configuration") {
      return Response.json({
        issuer: this.issuer,
        jwks_uri: `${this.issuer}/jwks`,
        authorization_endpoint: `${this.issuer}/authorize`,
        token_endpoint: `${this.issuer}/token`,
        id_token_signing_alg_values_supported: ["RS256"],
      });
    }
    if (pathname === "/jwks") {
      return Response.json({ keys: [this.#jwk] });
    }
    return new Response("not found", { status: 404 });
  };

  /** Upstream harness `DefaultClaims`. Note the audience defaults to the issuer URL, as upstream's does. */
  defaultClaims(now: number = Date.now()): Record<string, unknown> {
    const seconds = Math.floor(now / 1000);
    return {
      iss: this.issuer,
      sub: `repo:${DEFAULT_REPOSITORY}:ref:refs/heads/main`,
      aud: this.issuer,
      exp: seconds + 3600,
      iat: seconds,
      nbf: seconds,
      repository: DEFAULT_REPOSITORY,
      ref: "refs/heads/main",
    };
  }

  async sign(claims: Readonly<Record<string, unknown>>): Promise<string> {
    if (!this.#privateKey) {
      throw new Error("FakeOidcProvider not initialized; use FakeOidcProvider.create()");
    }
    return new SignJWT({ ...claims })
      .setProtectedHeader({ alg: "RS256", kid: "test-key", typ: "JWT" })
      .sign(this.#privateKey);
  }

  /** Signs the default claims with `overrides` applied; `undefined` removes a claim. */
  async token(overrides: Readonly<Record<string, unknown>> = {}): Promise<string> {
    const merged = { ...this.defaultClaims(), ...overrides };
    return this.sign(
      Object.fromEntries(Object.entries(merged).filter(([, value]) => value !== undefined)),
    );
  }
}
