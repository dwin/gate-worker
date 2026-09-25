import type { FetchLike, Sleep } from "../ports/index.ts";

export interface RetryPolicy {
  readonly maxAttempts: number;
  readonly initialBackoffMs: number;
  readonly maxBackoffMs: number;
  readonly multiplier: number;
  readonly jitterFraction: number;
}

/**
 * Upstream's retry policy (`internal/clients/github/retry.go`): four attempts,
 * 2 s / 4 s / 8 s backoff capped at 10 s with 10% jitter, retrying every 4xx,
 * 5xx, and network error. GitHub replicates new installation tokens with a lag,
 * so freshly minted tokens can briefly return 401, 403, or 404.
 */
export const DEFAULT_RETRY_POLICY: RetryPolicy = {
  maxAttempts: 4,
  initialBackoffMs: 2000,
  maxBackoffMs: 10_000,
  multiplier: 2,
  jitterFraction: 0.1,
};

export function backoffMs(
  policy: RetryPolicy,
  attempt: number,
  random: () => number = Math.random,
): number {
  const base = Math.min(
    policy.initialBackoffMs * policy.multiplier ** (attempt - 1),
    policy.maxBackoffMs,
  );
  const jitter = base * policy.jitterFraction * (random() * 2 - 1);
  return Math.max(0, base + jitter);
}

/**
 * Issues `fetch(url, init)` with retries. Returns the last response when every
 * attempt fails with an HTTP error; rethrows the last network error otherwise.
 * `init.body`, when present, must be a string so it can be resent.
 */
export async function fetchWithRetry(
  fetchImpl: FetchLike,
  url: string,
  init: RequestInit & { body?: string },
  policy: RetryPolicy,
  sleep: Sleep,
): Promise<Response> {
  const signal = init.signal ?? undefined;
  let lastError: unknown;
  for (let attempt = 0; attempt < policy.maxAttempts; attempt++) {
    if (attempt > 0) {
      await sleep(backoffMs(policy, attempt), signal);
    }
    let response: Response;
    try {
      response = await fetchImpl(url, init);
    } catch (error) {
      if (signal?.aborted) {
        throw error;
      }
      lastError = error;
      continue;
    }
    if (response.status < 400 || attempt === policy.maxAttempts - 1) {
      return response;
    }
    await response.body?.cancel();
  }
  throw lastError instanceof Error ? lastError : new Error(String(lastError));
}
