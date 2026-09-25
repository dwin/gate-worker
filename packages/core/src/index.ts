// Composition
export { createGate, type Gate, type GateOptions, type RevocationStrategy } from "./gate.ts";

// Ports and portable adapters
export type * from "./ports/index.ts";
export { MemoryAppStateStore } from "./adapters/memory/app-state-store.ts";
export { FireAndForgetBackground } from "./adapters/memory/background.ts";
export { MemoryCache } from "./adapters/memory/cache.ts";
export { TimerRevocationScheduler, timerRevocation } from "./adapters/memory/timer-revocation.ts";

// Configuration
export {
  applyEnvOverrides,
  centralConfigJsonSchema,
  compileCentralConfig,
  ConfigError,
  importAppPrivateKey,
  validateCentralConfig,
  wrapPkcs1InPkcs8,
  type CentralConfig,
  type CompiledConfig,
  type GitHubAppConfig,
  type ProviderConfig,
} from "./config/index.ts";

// Authorization
export {
  Authorizer,
  type AuthorizationRequest,
  type AuthorizationResult,
} from "./authorizer/authorizer.ts";
export { CentralPolicy } from "./authorizer/central.ts";
export { claimString, lookupClaim, type Claims } from "./authorizer/claims.ts";
export { DenialCode, type Denial } from "./authorizer/denial.ts";
export { matchAutomatic, matchExplicit, resolveTtl } from "./authorizer/match.ts";
export {
  isLevelAllowed,
  isPermissionLevel,
  PERMISSION_LEVELS,
  type PermissionLevel,
  type Permissions,
} from "./authorizer/permission-levels.ts";
export { NON_REPOSITORY_PERMISSIONS, resolvePermissions } from "./authorizer/permissions.ts";
export {
  extensionVariants,
  PolicyFileNotFoundError,
  PolicyLoader,
  RepositoryNotAccessibleError,
} from "./authorizer/policy-loader.ts";
export {
  parseTrustPolicy,
  TrustPolicyError,
  trustPolicyJsonSchema,
  type TrustPolicy,
  type TrustPolicyFile,
} from "./authorizer/trust-policy.ts";

// OIDC
export { OidcValidationError, OidcValidator, type ValidatedClaims } from "./oidc/validator.ts";

// GitHub
export * from "./github/index.ts";

// App selection
export {
  AppSelector,
  AppsExhaustedError,
  isFresherThan,
  NoMatchingAppError,
  type GitHubApp,
} from "./selector/selector.ts";

// Audit
export { AuditLog, type AuditSinkRegistration } from "./audit/audit-log.ts";
export { auditEntryProblem, type AuditEntry, type AuditOutcome } from "./audit/entry.ts";
export { LogAuditSink } from "./audit/log-sink.ts";

// Revocation
export { revocationJobSchema, type RevocationJob } from "./revocation/job.ts";
export { revocationRetryDelaySeconds } from "./revocation/retry.ts";
export { Revoker } from "./revocation/revoker.ts";
export { TokenSealer } from "./revocation/sealer.ts";

// Token exchange
export {
  TokenExchangeService,
  type Caller,
  type ExchangeFailure,
  type ExchangeOutcome,
  type ExchangeRequest,
} from "./sts/service.ts";
export {
  exchangeRequestBodySchema,
  httpStatusFor,
  ServiceErrorCode,
  type ErrorCode,
  type ErrorResponseBody,
  type ExchangeRequestBody,
  type ExchangeResponseBody,
} from "./sts/wire.ts";

// Utilities
export { createLogger, type LogFormat, type LogWriter } from "./logging/logger.ts";
export { hashToken } from "./util/hash.ts";
export { timingSafeEqual } from "./util/timing-safe-equal.ts";
export { systemClock, timerSleep } from "./util/time.ts";
