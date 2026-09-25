/** Authorization denial codes, identical to upstream `internal/sts/authorizer/errors.go`. */
export const DenialCode = {
  IssuerNotAllowed: "ISSUER_NOT_ALLOWED",
  RequiredClaimMismatch: "REQUIRED_CLAIM_MISMATCH",
  ForbiddenClaimMatched: "FORBIDDEN_CLAIM_MATCHED",
  TimeRestriction: "TIME_RESTRICTION",
  PolicyLoadFailed: "POLICY_LOAD_FAILED",
  TrustPolicyNotFound: "TRUST_POLICY_NOT_FOUND",
  RepositoryNotFound: "REPOSITORY_NOT_FOUND",
  PolicyNotFound: "POLICY_NOT_FOUND",
  NoRulesMatched: "NO_RULES_MATCHED",
  PermissionNotInPolicy: "PERMISSION_NOT_IN_POLICY",
  PermissionExceedsPolicy: "PERMISSION_EXCEEDS_POLICY",
  PermissionExceedsMax: "PERMISSION_EXCEEDS_ORG_MAX",
  PermissionDenied: "PERMISSION_DENIED",
  PermissionNotInMaxPermissions: "PERMISSION_NOT_IN_MAX_PERMISSIONS",
  NonRepositoryPermission: "NON_REPOSITORY_PERMISSION",
  PolicyNameRequired: "POLICY_NAME_REQUIRED",
} as const;

export type DenialCode = (typeof DenialCode)[keyof typeof DenialCode];

/** An authorization denial. Denials are values, never thrown. */
export interface Denial {
  readonly code: DenialCode;
  readonly message: string;
  readonly details?: string;
}

export function deny(code: DenialCode, message: string, details?: string): Denial {
  return details === undefined ? { code, message } : { code, message, details };
}
