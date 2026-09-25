import { claimString, type Claims } from "./claims.ts";
import { deny, DenialCode, type Denial } from "./denial.ts";
import type { Condition, PolicyRule, TrustPolicy, TrustPolicyFile } from "./trust-policy.ts";

export type PolicyMatch =
  | { readonly ok: true; readonly policy: TrustPolicy }
  | { readonly ok: false; readonly denial: Denial };

function conditionMatches(condition: Condition, claims: Claims): boolean {
  const value = claimString(claims, condition.field);
  return value !== undefined && condition.pattern.test(value);
}

function evaluateRule(rule: PolicyRule, claims: Claims): boolean {
  const matches = (condition: Condition): boolean => conditionMatches(condition, claims);
  return rule.logic === "AND" ? rule.conditions.every(matches) : rule.conditions.some(matches);
}

/** A policy matches when any of its rules matches. */
function evaluateRules(policy: TrustPolicy, claims: Claims): boolean {
  return policy.rules.some((rule) => evaluateRule(rule, claims));
}

/** Finds the named policy and requires its issuer and rules to match. */
export function matchExplicit(
  file: TrustPolicyFile,
  policyName: string,
  issuer: string,
  claims: Claims,
): PolicyMatch {
  const policy = file.trust_policies.find((candidate) => candidate.name === policyName);
  if (!policy) {
    return {
      ok: false,
      denial: deny(DenialCode.PolicyNotFound, `policy "${policyName}" not found in repository`),
    };
  }
  if (policy.issuer !== issuer) {
    return {
      ok: false,
      denial: deny(
        DenialCode.IssuerNotAllowed,
        `policy "${policyName}" does not accept issuer ${issuer}`,
      ),
    };
  }
  if (!evaluateRules(policy, claims)) {
    return {
      ok: false,
      denial: deny(
        DenialCode.NoRulesMatched,
        `policy "${policyName}" rules did not match the request`,
      ),
    };
  }
  return { ok: true, policy };
}

/** Returns the first policy, in file order, whose issuer and rules match. */
export function matchAutomatic(file: TrustPolicyFile, issuer: string, claims: Claims): PolicyMatch {
  const policy = file.trust_policies.find(
    (candidate) => candidate.issuer === issuer && evaluateRules(candidate, claims),
  );
  return policy
    ? { ok: true, policy }
    : { ok: false, denial: deny(DenialCode.NoRulesMatched, "no policy rules matched the request") };
}

/** Requested TTL (or the default), capped by the policy's `token_ttl`, then by the global maximum. */
export function resolveTtl(
  requestedTtl: number,
  policy: TrustPolicy,
  defaultTtl: number,
  maxTtl: number,
): number {
  let ttl = requestedTtl === 0 ? defaultTtl : requestedTtl;
  if (policy.token_ttl !== undefined && policy.token_ttl > 0 && policy.token_ttl < ttl) {
    ttl = policy.token_ttl;
  }
  return Math.min(ttl, maxTtl);
}
