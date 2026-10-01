import type { AuditLog } from "../audit/audit-log.ts";
import type { AuditEntry } from "../audit/entry.ts";
import type { Authorizer, AuthorizationResult } from "../authorizer/authorizer.ts";
import { DenialCode } from "../authorizer/denial.ts";
import type { Permissions } from "../authorizer/permission-levels.ts";
import { intersectPermissions } from "../authorizer/permissions.ts";
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
  /**
   * Several repositories of one owner for one token. Mutually exclusive with
   * `targetRepository`, and requires `requestedPermissions`.
   */
  readonly targetRepositories?: readonly string[] | undefined;
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
  /** Most repositories one `targetRepositories` request may name. */
  readonly maxTargetRepositories: number;
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

type Allowed = Extract<AuthorizationResult, { allowed: true }>;

/** The repositories a request targets, in request order. */
function targetsOf(request: ExchangeRequest): readonly string[] {
  return request.targetRepositories ?? [request.targetRepository];
}

/** Log attributes naming the target: `repository` as upstream, or `repositories`. */
function targetAttributes(request: ExchangeRequest): Record<string, unknown> {
  return request.targetRepositories === undefined
    ? { repository: request.targetRepository }
    : { repositories: request.targetRepositories };
}

/** Upstream's message for a malformed repository, or undefined. */
function repositoryProblem(field: string, repository: string): string | undefined {
  if (!repository) {
    return `${field} is required`;
  }
  const parts = repository.split("/");
  if (parts.length !== 2 || !parts.every((part) => GITHUB_NAME.test(part))) {
    return `${field} must be in owner/repo format (alphanumeric, hyphens, underscores, dots only)`;
  }
  return undefined;
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

    // Every repository's trust policy must allow the request on its own, so a
    // multi-repository token never grants more than separate tokens would.
    const targets = targetsOf(request);
    const multi = request.targetRepositories !== undefined;
    const results = await Promise.all(
      targets.map(async (repository) => ({
        repository,
        decision: await authorizer.authorize({
          claims: claimsForPolicy(claims),
          issuer: claims.issuer,
          targetRepository: repository,
          policyName: request.policyName ?? "",
          requestedPermissions: request.requestedPermissions,
          requestedTtl: request.requestedTtl ?? 0,
        }),
      })),
    );
    const allowed: { repository: string; decision: Allowed }[] = [];
    for (const { repository, decision } of results) {
      if (!decision.allowed) {
        this.#auditDenied(requestId, claims, request, decision.denial.code, background);
        return fail(
          {
            code: decision.denial.code,
            message: multi ? `${repository}: ${decision.denial.message}` : decision.denial.message,
            ...(decision.denial.details === undefined ? {} : { details: decision.denial.details }),
            requestId,
          },
          caller,
        );
      }
      allowed.push({ repository, decision });
    }
    const decision = this.#combine(allowed);
    if (!decision) {
      this.#auditDenied(requestId, claims, request, DenialCode.PermissionDenied, background);
      return fail(
        {
          code: DenialCode.PermissionDenied,
          message: "no permissions to grant",
          details: "the matched policies share no permissions",
          requestId,
        },
        caller,
      );
    }

    let clientId: string;
    try {
      // Validation guarantees one owner, so the first target selects for all.
      clientId = (await selector.select(targets[0] ?? "")).clientId;
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
      minted = await client.requestToken(targets, decision.permissions);
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
        decision.matchedPolicies,
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
      ...targetAttributes(request),
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
        ...(multi
          ? {
              repositories: targets,
              matched_policies: Object.fromEntries(decision.matchedPolicies),
            }
          : {}),
      },
    };
  }

  /**
   * Merges per-repository decisions: the permissions every decision grants,
   * the shortest TTL, and each repository's matched policy. Undefined when the
   * decisions share no permissions.
   */
  #combine(allowed: readonly { repository: string; decision: Allowed }[]):
    | {
        matchedPolicy: string;
        matchedPolicies: ReadonlyMap<string, string>;
        permissions: Permissions;
        ttl: number;
      }
    | undefined {
    const permissions = intersectPermissions(allowed.map(({ decision }) => decision.permissions));
    if (Object.keys(permissions).length === 0) {
      return undefined;
    }
    const matchedPolicies = new Map(
      allowed.map(({ repository, decision }) => [repository, decision.matchedPolicy]),
    );
    return {
      matchedPolicy: [...new Set(matchedPolicies.values())].join(", "),
      matchedPolicies,
      permissions,
      ttl: Math.min(...allowed.map(({ decision }) => decision.ttl)),
    };
  }

  #validateRequest(request: ExchangeRequest): string | undefined {
    if (!request.oidcToken) {
      return "oidc_token is required";
    }
    const targetProblem =
      request.targetRepositories === undefined
        ? repositoryProblem("target_repository", request.targetRepository)
        : this.#targetListProblem(request.targetRepositories, request);
    if (targetProblem) {
      return targetProblem;
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

  #targetListProblem(targets: readonly string[], request: ExchangeRequest): string | undefined {
    if (request.targetRepository) {
      return "target_repository and target_repositories are mutually exclusive";
    }
    if (targets.length === 0) {
      return "target_repositories must not be empty";
    }
    const maximum = this.#deps.maxTargetRepositories;
    if (targets.length > maximum) {
      return `target_repositories has ${String(targets.length)} entries, exceeding the maximum (${String(maximum)})`;
    }
    const seen = new Set<string>();
    for (const repository of targets) {
      const problem = repositoryProblem("target_repositories entry", repository);
      if (problem) {
        return problem;
      }
      // GitHub names are case-insensitive.
      const key = repository.toLowerCase();
      if (seen.has(key)) {
        return `target_repositories lists ${repository} more than once`;
      }
      seen.add(key);
    }
    const owners = new Set(targets.map((repository) => repository.split("/", 1)[0]?.toLowerCase()));
    if (owners.size > 1) {
      return "target_repositories must all belong to one owner, because a token covers one App installation";
    }
    // Defaulting to each policy's full grant would silently intersect differing
    // grants, so the caller must say what the token needs.
    if (Object.keys(request.requestedPermissions ?? {}).length === 0) {
      return "requested_permissions is required with target_repositories";
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

  /** One entry per repository, sharing the token hash, so upstream's schema holds. */
  async #auditGranted(
    requestId: string,
    claims: ValidatedClaims,
    matchedPolicies: ReadonlyMap<string, string>,
    permissions: Permissions,
    ttl: number,
    clientId: string,
    tokenHash: string,
    background: Background,
  ): Promise<void> {
    const timestamp = epochSeconds(this.#deps.clock.now());
    await Promise.all(
      [...matchedPolicies].map(([repository, policyName]) =>
        this.#deps.audit.granted(
          {
            request_id: requestId,
            timestamp,
            caller: auditCaller(claims),
            claims: flattenClaims(claims),
            target_repository: repository,
            policy_name: policyName,
            permissions,
            outcome: "granted",
            token_hash: tokenHash,
            ttl,
            github_client_id: clientId,
          },
          background,
        ),
      ),
    );
  }

  #auditDenied(
    requestId: string,
    claims: ValidatedClaims,
    request: ExchangeRequest,
    reason: string,
    background: Background,
  ): void {
    const timestamp = epochSeconds(this.#deps.clock.now());
    for (const repository of targetsOf(request)) {
      const entry: AuditEntry = {
        request_id: requestId,
        timestamp,
        caller: auditCaller(claims),
        claims: flattenClaims(claims),
        target_repository: repository,
        policy_name: request.policyName ?? "",
        outcome: "denied",
        deny_reason: reason,
      };
      this.#deps.audit.denied(entry, background);
    }
  }

  #logOutcome(requestId: string, request: ExchangeRequest, outcome: ExchangeOutcome): void {
    if (outcome.ok) {
      return;
    }
    const { error } = outcome;
    const attributes: Record<string, unknown> = {
      request_id: requestId,
      ...targetAttributes(request),
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
