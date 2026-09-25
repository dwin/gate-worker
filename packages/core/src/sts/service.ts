import type { AuditLog } from "../audit/audit-log.ts";
import type { AuditEntry } from "../audit/entry.ts";
import type { Authorizer } from "../authorizer/authorizer.ts";
import type { Permissions } from "../authorizer/permission-levels.ts";
import type { GitHubAppClient } from "../github/client.ts";
import type { OidcValidator, ValidatedClaims } from "../oidc/validator.ts";
import type { Background, Clock, Logger, RevocationScheduler } from "../ports/index.ts";
import type { TokenSealer } from "../revocation/sealer.ts";
import { AppsExhaustedError, type AppSelector } from "../selector/selector.ts";
import { hashToken } from "../util/hash.ts";
import { epochSeconds } from "../util/time.ts";
import { ServiceErrorCode, type ErrorCode, type ExchangeResponseBody } from "./wire.ts";

/** Owner and repository names: alphanumerics, hyphens, underscores, and dots. */
const GITHUB_NAME = /^[A-Za-z0-9._-]+$/;

export interface ExchangeRequest {
  readonly oidcToken: string;
  readonly targetRepository: string;
  readonly policyName?: string | undefined;
  readonly requestedPermissions?: Readonly<Record<string, string>> | undefined;
  readonly requestedTtl?: number | undefined;
}

export interface Caller {
  readonly issuer: string;
  readonly subject: string;
}

/** A failed exchange. `details` and `caller` are for logs only and never sent to clients. */
export interface ExchangeFailure {
  readonly code: ErrorCode;
  readonly message: string;
  readonly details?: string;
  readonly requestId: string;
  readonly retryAfterSeconds?: number;
  readonly caller?: Caller;
}

export type ExchangeOutcome =
  | { readonly ok: true; readonly response: ExchangeResponseBody }
  | { readonly ok: false; readonly error: ExchangeFailure };

export interface TokenExchangeDependencies {
  readonly maxTtl: number;
  readonly oidc: OidcValidator;
  readonly authorizer: Authorizer;
  readonly selector: AppSelector;
  readonly clients: ReadonlyMap<string, GitHubAppClient>;
  readonly audit: AuditLog;
  readonly sealer: TokenSealer;
  readonly scheduler: RevocationScheduler;
  readonly logger: Logger;
  readonly clock: Clock;
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Audit `caller`. Tokens without `sub` are valid, but upstream's audit schema
 * requires a caller, so an explicit placeholder keeps the entry valid.
 */
function auditCaller(claims: ValidatedClaims): string {
  return claims.subject || "(missing sub claim)";
}

/** Upstream `flattenClaims`: iss, sub, and custom claims as strings for audit storage. */
function flattenClaims(claims: ValidatedClaims): Record<string, string> {
  const flat: Record<string, string> = { iss: claims.issuer, sub: claims.subject };
  for (const [name, value] of Object.entries(claims.custom)) {
    flat[name] = typeof value === "string" ? value : JSON.stringify(value);
  }
  return flat;
}

/** Upstream `claimsToMap`: the claim set rules and central policy evaluate against. */
function claimsForPolicy(claims: ValidatedClaims): Record<string, unknown> {
  return {
    iss: claims.issuer,
    sub: claims.subject,
    aud: claims.audience,
    exp: claims.expiresAt,
    ...claims.custom,
  };
}

/**
 * Orchestrates one exchange: request validation, OIDC validation, two-layer
 * authorization, App selection, token minting, revocation scheduling, and
 * audit. Mirrors upstream `internal/sts/sts.go`, with two hardening changes:
 * a token whose revocation cannot be scheduled, or whose audit record cannot
 * be written, is revoked immediately and never returned.
 */
export class TokenExchangeService {
  readonly #deps: TokenExchangeDependencies;

  constructor(deps: TokenExchangeDependencies) {
    this.#deps = deps;
  }

  async exchange(
    requestId: string,
    request: ExchangeRequest,
    background: Background,
  ): Promise<ExchangeOutcome> {
    const outcome = await this.#exchange(requestId, request, background);
    this.#logOutcome(requestId, request, outcome);
    return outcome;
  }

  async #exchange(
    requestId: string,
    request: ExchangeRequest,
    background: Background,
  ): Promise<ExchangeOutcome> {
    const { oidc, authorizer, selector, clients, logger, clock } = this.#deps;
    const invalid = this.#validateRequest(request);
    if (invalid) {
      return fail({
        code: ServiceErrorCode.InvalidRequest,
        message: "Invalid request",
        details: invalid,
        requestId,
      });
    }

    let claims: ValidatedClaims;
    try {
      claims = await oidc.validate(request.oidcToken);
    } catch (error) {
      return fail({
        code: ServiceErrorCode.InvalidToken,
        message: "OIDC token validation failed",
        details: describe(error),
        requestId,
      });
    }
    const caller: Caller = { issuer: claims.issuer, subject: claims.subject };
    logger.debug("oidc validated", {
      request_id: requestId,
      issuer: claims.issuer,
      subject: claims.subject,
    });

    const decision = await authorizer.authorize({
      claims: claimsForPolicy(claims),
      issuer: claims.issuer,
      targetRepository: request.targetRepository,
      policyName: request.policyName ?? "",
      requestedPermissions: request.requestedPermissions,
      requestedTtl: request.requestedTtl ?? 0,
    });
    if (!decision.allowed) {
      this.#auditDenied(requestId, claims, request, decision.denial.code, background);
      return fail(
        {
          code: decision.denial.code,
          message: decision.denial.message,
          ...(decision.denial.details === undefined ? {} : { details: decision.denial.details }),
          requestId,
        },
        caller,
      );
    }

    let clientId: string;
    try {
      clientId = (await selector.select(request.targetRepository)).clientId;
    } catch (error) {
      if (error instanceof AppsExhaustedError) {
        this.#auditDenied(requestId, claims, request, ServiceErrorCode.RateLimited, background);
        return fail(
          {
            code: ServiceErrorCode.RateLimited,
            message: "All GitHub Apps exhausted rate limits",
            requestId,
            retryAfterSeconds: error.retryAfterSeconds,
          },
          caller,
        );
      }
      this.#auditDenied(requestId, claims, request, "APP_SELECTION_FAILED", background);
      return fail(
        {
          code: ServiceErrorCode.InternalError,
          message: "Failed to select GitHub App",
          details: describe(error),
          requestId,
        },
        caller,
      );
    }
    const client = clients.get(clientId);
    if (!client) {
      this.#auditDenied(requestId, claims, request, "GITHUB_CLIENT_NOT_FOUND", background);
      return fail(
        {
          code: ServiceErrorCode.InternalError,
          message: "GitHub client not found for app",
          details: clientId,
          requestId,
        },
        caller,
      );
    }

    let minted: { token: string; expiresAt: Date };
    try {
      minted = await client.requestToken(request.targetRepository, decision.permissions);
    } catch (error) {
      this.#auditDenied(requestId, claims, request, ServiceErrorCode.GitHubApiError, background);
      return fail(
        {
          code: ServiceErrorCode.GitHubApiError,
          message: "Failed to request GitHub token",
          details: describe(error),
          requestId,
        },
        caller,
      );
    }

    background.defer(async () => {
      const usage = await client.rateLimit(minted.token);
      await selector.recordUsage(clientId, usage.remaining, usage.resetAt);
    });

    const expiresAt = Math.min(minted.expiresAt.getTime(), clock.now() + decision.ttl * 1000);
    const tokenHash = await hashToken(minted.token);

    const scheduled = await this.#scheduleRevocation(minted.token, tokenHash, clientId, expiresAt);
    if (!scheduled.ok) {
      this.#revokeNow(client, minted.token, tokenHash, background);
      this.#auditDenied(requestId, claims, request, "REVOCATION_SCHEDULE_FAILED", background);
      return fail(
        {
          code: ServiceErrorCode.InternalError,
          message: "Failed to schedule token revocation",
          details: scheduled.error,
          requestId,
        },
        caller,
      );
    }

    try {
      await this.#auditGranted(
        requestId,
        claims,
        request,
        decision.matchedPolicy,
        decision.permissions,
        decision.ttl,
        clientId,
        tokenHash,
        background,
      );
    } catch (error) {
      this.#revokeNow(client, minted.token, tokenHash, background);
      return fail(
        {
          code: ServiceErrorCode.InternalError,
          message: "Audit log failed",
          details: describe(error),
          requestId,
        },
        caller,
      );
    }

    logger.info("token exchange granted", {
      request_id: requestId,
      repository: request.targetRepository,
      issuer: caller.issuer,
      subject: caller.subject,
      policy: decision.matchedPolicy,
      client_id: clientId,
      token_hash: tokenHash,
      ttl: decision.ttl,
      expires_at: new Date(expiresAt).toISOString(),
      permissions_count: Object.keys(decision.permissions).length,
    });
    return {
      ok: true,
      response: {
        token: minted.token,
        expires_at: new Date(expiresAt).toISOString(),
        matched_policy: decision.matchedPolicy,
        permissions: decision.permissions,
        request_id: requestId,
      },
    };
  }

  #validateRequest(request: ExchangeRequest): string | undefined {
    if (!request.oidcToken) {
      return "oidc_token is required";
    }
    if (!request.targetRepository) {
      return "target_repository is required";
    }
    const parts = request.targetRepository.split("/");
    if (parts.length !== 2 || !parts.every((part) => GITHUB_NAME.test(part))) {
      return "target_repository must be in owner/repo format (alphanumeric, hyphens, underscores, dots only)";
    }
    const ttl = request.requestedTtl ?? 0;
    if (ttl < 0) {
      return "requested_ttl cannot be negative";
    }
    if (ttl > this.#deps.maxTtl) {
      return `requested_ttl (${String(ttl)}) exceeds maximum (${String(this.#deps.maxTtl)})`;
    }
    return undefined;
  }

  async #scheduleRevocation(
    token: string,
    tokenHash: string,
    githubClientId: string,
    expiresAtMs: number,
  ): Promise<{ ok: true } | { ok: false; error: string }> {
    try {
      const job = await this.#deps.sealer.seal({
        token,
        tokenHash,
        githubClientId,
        expiresAt: epochSeconds(expiresAtMs),
      });
      const delaySeconds = Math.max(0, Math.ceil((expiresAtMs - this.#deps.clock.now()) / 1000));
      await this.#deps.scheduler.schedule(job, delaySeconds);
      return { ok: true };
    } catch (error) {
      return { ok: false, error: describe(error) };
    }
  }

  #revokeNow(
    client: GitHubAppClient,
    token: string,
    tokenHash: string,
    background: Background,
  ): void {
    background.defer(async () => {
      await client.revokeToken(token);
      this.#deps.logger.warn("token revoked immediately after failed exchange", {
        token_hash: tokenHash,
      });
    });
  }

  async #auditGranted(
    requestId: string,
    claims: ValidatedClaims,
    request: ExchangeRequest,
    policyName: string,
    permissions: Permissions,
    ttl: number,
    clientId: string,
    tokenHash: string,
    background: Background,
  ): Promise<void> {
    await this.#deps.audit.granted(
      {
        request_id: requestId,
        timestamp: epochSeconds(this.#deps.clock.now()),
        caller: auditCaller(claims),
        claims: flattenClaims(claims),
        target_repository: request.targetRepository,
        policy_name: policyName,
        permissions,
        outcome: "granted",
        token_hash: tokenHash,
        ttl,
        github_client_id: clientId,
      },
      background,
    );
  }

  #auditDenied(
    requestId: string,
    claims: ValidatedClaims,
    request: ExchangeRequest,
    reason: string,
    background: Background,
  ): void {
    const entry: AuditEntry = {
      request_id: requestId,
      timestamp: epochSeconds(this.#deps.clock.now()),
      caller: auditCaller(claims),
      claims: flattenClaims(claims),
      target_repository: request.targetRepository,
      policy_name: request.policyName ?? "",
      outcome: "denied",
      deny_reason: reason,
    };
    this.#deps.audit.denied(entry, background);
  }

  #logOutcome(requestId: string, request: ExchangeRequest, outcome: ExchangeOutcome): void {
    if (outcome.ok) {
      return;
    }
    const { error } = outcome;
    const attributes: Record<string, unknown> = {
      request_id: requestId,
      repository: request.targetRepository,
      code: error.code,
      message: error.message,
    };
    if (error.details) {
      attributes["details"] = error.details;
    }
    if (error.caller?.issuer) {
      attributes["issuer"] = error.caller.issuer;
    }
    if (error.caller?.subject) {
      attributes["subject"] = error.caller.subject;
    }
    if (error.code === ServiceErrorCode.InternalError) {
      this.#deps.logger.error("token exchange denied", attributes);
    } else {
      this.#deps.logger.warn("token exchange denied", attributes);
    }
  }
}

function fail(error: ExchangeFailure, caller?: Caller): ExchangeOutcome {
  return { ok: false, error: caller ? { ...error, caller } : error };
}
