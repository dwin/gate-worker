import type { CentralConfig } from "../config/schema.ts";
import type { Clock } from "../ports/index.ts";
import { systemClock } from "../util/time.ts";
import { CentralPolicy } from "./central.ts";
import type { Claims } from "./claims.ts";
import { deny, DenialCode, type Denial } from "./denial.ts";
import { matchAutomatic, matchExplicit, resolveTtl } from "./match.ts";
import type { Permissions } from "./permission-levels.ts";
import { resolvePermissions } from "./permissions.ts";
import {
  PolicyFileNotFoundError,
  RepositoryNotAccessibleError,
  type PolicyLoader,
} from "./policy-loader.ts";
import type { TrustPolicyFile } from "./trust-policy.ts";

export interface AuthorizationRequest {
  readonly claims: Claims;
  readonly issuer: string;
  readonly targetRepository: string;
  readonly policyName: string;
  readonly requestedPermissions: Readonly<Record<string, string>> | undefined;
  readonly requestedTtl: number;
}

export type AuthorizationResult =
  | {
      readonly allowed: true;
      readonly matchedPolicy: string;
      readonly permissions: Permissions;
      readonly ttl: number;
    }
  | { readonly allowed: false; readonly denial: Denial };

/**
 * Two-layer authorization. Layer 1 applies the central policy (issuer, claim
 * patterns, time windows); layer 2 applies the repository's trust policy
 * (rule matching, permission intersection, TTL).
 */
export class Authorizer {
  readonly #policy: CentralConfig["policy"];
  readonly #central: CentralPolicy;
  readonly #loader: PolicyLoader;
  readonly #clock: Clock;

  constructor(policy: CentralConfig["policy"], loader: PolicyLoader, clock: Clock = systemClock) {
    this.#policy = policy;
    this.#central = new CentralPolicy(policy.providers);
    this.#loader = loader;
    this.#clock = clock;
  }

  async authorize(request: AuthorizationRequest): Promise<AuthorizationResult> {
    if (!request.issuer) {
      return denied(deny(DenialCode.IssuerNotAllowed, "issuer is required"));
    }
    const centralDenial = this.#central.evaluate(
      request.issuer,
      request.claims,
      new Date(this.#clock.now()),
    );
    if (centralDenial) {
      return denied(centralDenial);
    }
    if (this.#policy.require_explicit_policy && !request.policyName) {
      return denied(
        deny(DenialCode.PolicyNameRequired, "policy_name is required but not provided"),
      );
    }

    let file: TrustPolicyFile;
    try {
      file = await this.#loader.load(request.targetRepository);
    } catch (error) {
      return denied(loadFailureDenial(error));
    }

    const match = request.policyName
      ? matchExplicit(file, request.policyName, request.issuer, request.claims)
      : matchAutomatic(file, request.issuer, request.claims);
    if (!match.ok) {
      return denied(match.denial);
    }

    const resolution = resolvePermissions(
      request.requestedPermissions,
      match.policy,
      this.#policy.max_permissions,
    );
    if (!resolution.ok) {
      return denied(resolution.denial);
    }
    return {
      allowed: true,
      matchedPolicy: match.policy.name,
      permissions: resolution.permissions,
      ttl: resolveTtl(
        request.requestedTtl,
        match.policy,
        this.#policy.default_token_ttl,
        this.#policy.max_token_ttl,
      ),
    };
  }
}

function denied(denial: Denial): AuthorizationResult {
  return { allowed: false, denial };
}

function loadFailureDenial(error: unknown): Denial {
  const details = error instanceof Error ? error.message : String(error);
  if (error instanceof RepositoryNotAccessibleError) {
    return deny(DenialCode.RepositoryNotFound, "repository not found or not accessible", details);
  }
  if (error instanceof PolicyFileNotFoundError) {
    return deny(
      DenialCode.TrustPolicyNotFound,
      "trust policy file not found in repository",
      details,
    );
  }
  return deny(DenialCode.PolicyLoadFailed, "failed to load trust policy", details);
}
