import type { RevocationJob } from "./job.ts";

/** GitHub installation tokens expire at most one hour after they are minted. */
const GITHUB_TOKEN_LIFETIME_SECONDS = 3600;
const INITIAL_RETRY_DELAY_SECONDS = 30;
const MAX_RETRY_DELAY_SECONDS = 300;

/**
 * Delay before retrying a failed revocation, or `undefined` once retrying is
 * pointless. Minting happens before the capped `expires_at`, so the token is
 * certainly dead at `expires_at` plus GitHub's one-hour lifetime; until then a
 * failed revocation must keep being retried. Delays back off from 30 s to 5 min.
 */
export function revocationRetryDelaySeconds(
  job: RevocationJob,
  attempt: number,
  nowMs: number,
): number | undefined {
  const nowSeconds = Math.floor(nowMs / 1000);
  const deadline = job.expires_at + GITHUB_TOKEN_LIFETIME_SECONDS;
  if (nowSeconds >= deadline) {
    return undefined;
  }
  return Math.min(
    INITIAL_RETRY_DELAY_SECONDS * 2 ** Math.max(0, attempt - 1),
    MAX_RETRY_DELAY_SECONDS,
    Math.max(1, deadline - nowSeconds),
  );
}
