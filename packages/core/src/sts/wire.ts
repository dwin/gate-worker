/**
 * HTTP wire format of `POST /api/v1/exchange`, identical to upstream. Shared
 * with the GitHub Action so client and server cannot drift.
 */
import { z } from "zod";
import type { DenialCode } from "../authorizer/denial.ts";

/**
 * Validates a decoded request body. Unknown fields are ignored and `null`
 * counts as absent, as with upstream's Go JSON decoding. Semantic checks
 * (repository format, TTL bounds) happen in the service so their messages
 * match upstream.
 */
export const exchangeRequestBodySchema = z.object({
  oidc_token: z
    .string()
    .nullish()
    .transform((value) => value ?? ""),
  target_repository: z
    .string()
    .nullish()
    .transform((value) => value ?? ""),
  policy_name: z
    .string()
    .nullish()
    .transform((value) => value ?? undefined),
  requested_permissions: z
    .record(z.string(), z.string())
    .nullish()
    .transform((value) => value ?? undefined),
  requested_ttl: z
    .int()
    .nullish()
    .transform((value) => value ?? undefined),
});

export interface ExchangeRequestBody {
  readonly oidc_token: string;
  readonly target_repository: string;
  readonly policy_name?: string;
  readonly requested_permissions?: Readonly<Record<string, string>>;
  readonly requested_ttl?: number;
}

export interface ExchangeResponseBody {
  readonly token: string;
  /** RFC 3339 timestamp, capped to the effective TTL. */
  readonly expires_at: string;
  readonly matched_policy: string;
  readonly permissions: Readonly<Record<string, string>>;
  readonly request_id: string;
}

export const ServiceErrorCode = {
  InvalidRequest: "INVALID_REQUEST",
  InvalidToken: "INVALID_TOKEN",
  RateLimited: "RATE_LIMITED",
  InternalError: "INTERNAL_ERROR",
  GitHubApiError: "GITHUB_API_ERROR",
} as const;

export type ServiceErrorCode = (typeof ServiceErrorCode)[keyof typeof ServiceErrorCode];

/** Every `error_code` the API can return. */
export type ErrorCode = ServiceErrorCode | DenialCode | "ORIGIN_VERIFICATION_FAILED";

export interface ErrorResponseBody {
  readonly error_code: ErrorCode;
  readonly error: string;
  readonly request_id: string;
  readonly retry_after_seconds?: number;
}

/** HTTP status for each error code, as upstream `httpStatusCode` maps them. */
export function httpStatusFor(code: ErrorCode): 400 | 401 | 403 | 404 | 429 | 500 | 502 {
  switch (code) {
    case "INVALID_REQUEST":
      return 400;
    case "INVALID_TOKEN":
      return 401;
    case "RATE_LIMITED":
      return 429;
    case "POLICY_NOT_FOUND":
    case "REPOSITORY_NOT_FOUND":
      return 404;
    case "GITHUB_API_ERROR":
      return 502;
    case "POLICY_LOAD_FAILED":
    case "INTERNAL_ERROR":
      return 500;
    default:
      return 403;
  }
}
