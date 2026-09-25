import type { ErrorResponseBody, ExchangeRequestBody, ExchangeResponseBody } from "@gate/core";
import { InputError, readInputs, type ActionInputs } from "./inputs.ts";
import type { ActionIO, Fetch, Sleep } from "./io.ts";

/** Statuses worth retrying: rate limiting and gateway failures. Denials are final. */
const RETRYABLE = new Set([429, 502, 503, 504]);
export const STATE_TOKEN = "gate-token";
export const STATE_API_URL = "gate-api-url";

function describeFailure(status: number, text: string): string {
  try {
    const body = JSON.parse(text) as Partial<ErrorResponseBody>;
    if (body.error_code) {
      return `${body.error_code}: ${body.error ?? "exchange failed"} (HTTP ${String(status)}, request_id ${body.request_id ?? "unknown"})`;
    }
  } catch {
    // Not JSON; fall through.
  }
  return `HTTP ${String(status)}: ${text.slice(0, 200)}`;
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

/**
 * Checks a 2xx body before anything is published, so a proxy's `200 {}` fails the
 * step instead of handing later steps an empty token. A token that did arrive is
 * masked first, since the error path may still log parts of the response.
 */
function parseSuccess(text: string, io: ActionIO): ExchangeResponseBody {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error("exchange succeeded but the response is not JSON");
  }
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new Error("exchange succeeded but the response is not a JSON object");
  }
  const candidate = body as Partial<Record<keyof ExchangeResponseBody, unknown>>;
  if (isNonEmptyString(candidate.token)) {
    io.setSecret(candidate.token);
  }
  const permissions = candidate.permissions;
  const missing = [
    isNonEmptyString(candidate.token) ? undefined : "token",
    isNonEmptyString(candidate.expires_at) ? undefined : "expires_at",
    isNonEmptyString(candidate.matched_policy) ? undefined : "matched_policy",
    isNonEmptyString(candidate.request_id) ? undefined : "request_id",
    typeof permissions === "object" &&
    permissions !== null &&
    !Array.isArray(permissions) &&
    Object.values(permissions).every(isNonEmptyString)
      ? undefined
      : "permissions",
  ].filter((field) => field !== undefined);
  if (missing.length > 0) {
    throw new Error(`exchange succeeded but the response is malformed (${missing.join(", ")})`);
  }
  return candidate as unknown as ExchangeResponseBody;
}

async function exchange(
  inputs: ActionInputs,
  oidcToken: string,
  io: ActionIO,
  fetchImpl: Fetch,
  sleep: Sleep,
  now: () => number,
): Promise<ExchangeResponseBody> {
  const body: ExchangeRequestBody = {
    oidc_token: oidcToken,
    target_repository: inputs.repository,
    ...(inputs.policyName === undefined ? {} : { policy_name: inputs.policyName }),
    ...(inputs.permissions === undefined ? {} : { requested_permissions: inputs.permissions }),
    ...(inputs.ttl === undefined ? {} : { requested_ttl: inputs.ttl }),
  };
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "user-agent": "gate-action",
  };
  if (inputs.originHeader) {
    headers[inputs.originHeader.name] = inputs.originHeader.value;
  }
  const deadline = now() + inputs.timeoutMs;

  for (let attempt = 1; ; attempt++) {
    let response: Response | undefined;
    let networkError: unknown;
    try {
      response = await fetchImpl(`${inputs.endpoint}/api/v1/exchange`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        // A 307/308 would replay the OIDC token to a target secureUrl never checked.
        redirect: "error",
        signal: AbortSignal.timeout(Math.max(1000, deadline - now())),
      });
    } catch (error) {
      networkError = error;
    }
    if (response?.ok) {
      return parseSuccess(await response.text(), io);
    }
    const text = response ? await response.text() : "";
    const failure = response
      ? describeFailure(response.status, text)
      : `network error: ${String(networkError)}`;
    if (response && !RETRYABLE.has(response.status)) {
      throw new Error(failure);
    }
    const retryAfter = Number(response?.headers.get("retry-after"));
    const waitMs =
      Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : Math.min(2 ** attempt * 1000, 10_000);
    if (now() + waitMs >= deadline) {
      throw new Error(`${failure}; giving up after ${String(attempt)} attempt(s)`);
    }
    io.warning(`${failure}; retrying in ${String(Math.round(waitMs / 1000))}s`);
    await sleep(waitMs);
  }
}

/** Main step: exchange the workflow's OIDC token for a GitHub App token. */
export async function runExchange(
  io: ActionIO,
  fetchImpl: Fetch,
  sleep: Sleep,
  now: () => number = Date.now,
): Promise<void> {
  try {
    const inputs = readInputs(io);
    let oidcToken: string;
    try {
      oidcToken = await io.getIDToken(inputs.audience);
    } catch (error) {
      throw new Error(
        `could not get an OIDC token; the job needs "permissions: id-token: write" (${String(error)})`,
        { cause: error },
      );
    }
    io.setSecret(oidcToken);

    const result = await exchange(inputs, oidcToken, io, fetchImpl, sleep, now);
    // parseSuccess has already masked the token, before it can reach any output or log.
    io.setOutput("token", result.token);
    io.setOutput("expires-at", result.expires_at);
    io.setOutput("matched-policy", result.matched_policy);
    io.setOutput("permissions", JSON.stringify(result.permissions));
    io.setOutput("request-id", result.request_id);
    if (inputs.revokeOnCompletion) {
      io.saveState(STATE_TOKEN, result.token);
      io.saveState(STATE_API_URL, inputs.apiUrl);
    }
    io.info(
      `Issued a token for ${inputs.repository} via policy "${result.matched_policy}" with ${JSON.stringify(result.permissions)}, expiring ${result.expires_at} (request ${result.request_id}).`,
    );
  } catch (error) {
    io.setFailed(
      error instanceof InputError
        ? `invalid input: ${error.message}`
        : error instanceof Error
          ? error.message
          : String(error),
    );
  }
}
