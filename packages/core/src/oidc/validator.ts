import {
  createRemoteJWKSet,
  customFetch,
  decodeJwt,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import type { Clock, FetchLike } from "../ports/index.ts";
import { epochSeconds, systemClock } from "../util/time.ts";
import { insecureUrlReason } from "../util/url.ts";

/** Claims that upstream exposes as fields rather than in `Custom`. */
const REGISTERED_CLAIMS = new Set(["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]);
/** Asymmetric JWS algorithms accepted from discovery; symmetric algorithms never are. */
const ASYMMETRIC_ALGORITHMS = new Set([
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
]);
/** Leeway for `nbf` and `iat`, matching go-oidc's allowed clock skew. */
const CLOCK_SKEW_SECONDS = 300;
const DISCOVERY_TTL_MS = 60 * 60 * 1000;

export class OidcValidationError extends Error {
  override name = "OidcValidationError";
}

export interface ValidatedClaims {
  readonly issuer: string;
  readonly subject: string;
  readonly audience: readonly string[];
  readonly expiresAt: number;
  readonly issuedAt: number | undefined;
  /** Every non-registered claim (repository, ref, actor, ...). */
  readonly custom: Readonly<Record<string, unknown>>;
}

interface Provider {
  readonly keys: JWTVerifyGetKey;
  readonly algorithms: readonly string[];
  readonly fetchedAt: number;
}

export interface OidcValidatorOptions {
  readonly audience: string;
  readonly issuers: readonly string[];
  readonly fetch: FetchLike;
  readonly clock?: Clock;
}

/**
 * Validates OIDC tokens from a fixed allowlist of issuers. The allowlist is
 * checked on the unverified `iss` before any network request, so a crafted
 * token can never make the service fetch from an arbitrary URL (upstream
 * threat S2). Discovery documents and JWKS are cached per process or isolate.
 */
export class OidcValidator {
  readonly #audience: string;
  readonly #issuers: ReadonlySet<string>;
  readonly #fetch: FetchLike;
  readonly #clock: Clock;
  readonly #providers = new Map<string, Promise<Provider>>();

  constructor(options: OidcValidatorOptions) {
    if (!options.audience) {
      throw new Error("audience is required");
    }
    if (options.issuers.length === 0) {
      throw new Error("at least one allowed issuer is required");
    }
    this.#audience = options.audience;
    this.#issuers = new Set(options.issuers);
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? systemClock;
  }

  async validate(rawToken: string): Promise<ValidatedClaims> {
    if (!rawToken) {
      throw new OidcValidationError("token is empty");
    }
    let unverified: JWTPayload;
    try {
      unverified = decodeJwt(rawToken);
    } catch (error) {
      throw new OidcValidationError(`malformed token: ${describe(error)}`);
    }
    const issuer = unverified.iss;
    if (!issuer) {
      throw new OidcValidationError("token missing issuer claim");
    }
    if (!this.#issuers.has(issuer)) {
      throw new OidcValidationError(`issuer not in allowed list: ${issuer}`);
    }

    const provider = await this.#provider(issuer);
    const now = epochSeconds(this.#clock.now());
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(rawToken, provider.keys, {
        issuer,
        audience: this.#audience,
        algorithms: [...provider.algorithms],
        requiredClaims: ["exp"],
        currentDate: new Date(now * 1000),
        clockTolerance: CLOCK_SKEW_SECONDS,
      }));
    } catch (error) {
      throw new OidcValidationError(`verifying token: ${describe(error)}`);
    }
    // jose applies one tolerance to every time claim; go-oidc allows no leeway on exp.
    const expiresAt = payload.exp ?? 0;
    if (expiresAt <= now) {
      throw new OidcValidationError("verifying token: token is expired");
    }
    if (payload.iat !== undefined && payload.iat > now + CLOCK_SKEW_SECONDS) {
      throw new OidcValidationError("verifying token: token issued in the future");
    }

    const custom: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(payload)) {
      if (!REGISTERED_CLAIMS.has(name)) {
        custom[name] = value;
      }
    }
    const audience = payload.aud === undefined ? [] : [payload.aud].flat();
    return {
      issuer,
      subject: payload.sub ?? "",
      audience,
      expiresAt,
      issuedAt: payload.iat,
      custom,
    };
  }

  #provider(issuer: string): Promise<Provider> {
    const cached = this.#providers.get(issuer);
    if (cached) {
      return cached.then((provider) =>
        this.#clock.now() - provider.fetchedAt < DISCOVERY_TTL_MS
          ? provider
          : this.#refresh(issuer),
      );
    }
    return this.#refresh(issuer);
  }

  #refresh(issuer: string): Promise<Provider> {
    const pending = this.#discover(issuer);
    this.#providers.set(issuer, pending);
    pending.catch(() => {
      if (this.#providers.get(issuer) === pending) {
        this.#providers.delete(issuer);
      }
    });
    return pending;
  }

  async #discover(issuer: string): Promise<Provider> {
    const url = `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`;
    let document: {
      issuer?: unknown;
      jwks_uri?: unknown;
      id_token_signing_alg_values_supported?: unknown;
    };
    try {
      const response = await this.#fetch(url, {
        headers: { accept: "application/json" },
        // A followed redirect could leave https, so any 3xx fails the `ok` check below.
        // "manual" rather than "error": Workers' fetch does not support "error".
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${String(response.status)}`);
      }
      document = (await response.json()) as typeof document;
    } catch (error) {
      throw new OidcValidationError(`discovering issuer ${issuer}: ${describe(error)}`);
    }
    if (document.issuer !== issuer) {
      throw new OidcValidationError(
        `discovering issuer ${issuer}: issuer did not match the issuer returned by provider, got ${String(document.issuer)}`,
      );
    }
    if (typeof document.jwks_uri !== "string") {
      throw new OidcValidationError(`discovering issuer ${issuer}: missing jwks_uri`);
    }
    // Signing keys fetched over plaintext could be substituted on the wire.
    const jwksProblem = insecureUrlReason(document.jwks_uri);
    if (jwksProblem !== undefined) {
      throw new OidcValidationError(`discovering issuer ${issuer}: jwks_uri ${jwksProblem}`);
    }
    const advertised = Array.isArray(document.id_token_signing_alg_values_supported)
      ? document.id_token_signing_alg_values_supported.filter(
          (algorithm): algorithm is string =>
            typeof algorithm === "string" && ASYMMETRIC_ALGORITHMS.has(algorithm),
        )
      : [];
    const fetchImpl = this.#fetch;
    return {
      keys: createRemoteJWKSet(new URL(document.jwks_uri), {
        // jose already refuses anything but a 200; pinning "manual" keeps a redirect
        // from ever being followed to an unvalidated key location.
        [customFetch]: (input: string | URL | Request, init?: RequestInit) =>
          fetchImpl(input, { ...init, redirect: "manual" }),
      }),
      algorithms: advertised.length > 0 ? advertised : ["RS256"],
      fetchedAt: this.#clock.now(),
    };
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
