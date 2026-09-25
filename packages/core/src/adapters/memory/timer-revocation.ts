import type { RevocationStrategy } from "../../gate.ts";
import type { Clock, Logger, RevocationScheduler } from "../../ports/index.ts";
import type { RevocationJob } from "../../revocation/job.ts";
import { revocationRetryDelaySeconds } from "../../revocation/retry.ts";
import type { Revoker } from "../../revocation/revoker.ts";
import { systemClock } from "../../util/time.ts";

/**
 * Revokes tokens from in-process timers, equivalent to upstream's tracker and
 * one-minute revocation loop. A failed revocation is retried with backoff for
 * as long as the token could still be valid, as upstream retries failed tokens
 * on every sweep. Pending revocations are lost if the process exits, as
 * upstream's are. Suitable for long-lived Node and Bun processes only.
 */
export class TimerRevocationScheduler implements RevocationScheduler {
  readonly #revoker: Revoker;
  readonly #logger: Logger;
  readonly #clock: Clock;
  readonly #timers = new Set<ReturnType<typeof setTimeout>>();
  #stopped = false;

  constructor(revoker: Revoker, logger: Logger, clock: Clock = systemClock) {
    this.#revoker = revoker;
    this.#logger = logger;
    this.#clock = clock;
  }

  schedule(job: RevocationJob, delaySeconds: number): Promise<void> {
    this.#arm(job, delaySeconds, 1);
    return Promise.resolve();
  }

  /** Cancels pending timers and retries, for graceful shutdown and tests. */
  stop(): void {
    this.#stopped = true;
    for (const timer of this.#timers) {
      clearTimeout(timer);
    }
    this.#timers.clear();
  }

  #arm(job: RevocationJob, delaySeconds: number, attempt: number): void {
    if (this.#stopped) {
      return;
    }
    const timer = setTimeout(() => {
      this.#timers.delete(timer);
      void this.#attempt(job, attempt);
    }, delaySeconds * 1000);
    // Do not keep a Node or Bun process alive just to revoke tokens.
    (timer as { unref?: () => void }).unref?.();
    this.#timers.add(timer);
  }

  async #attempt(job: RevocationJob, attempt: number): Promise<void> {
    try {
      await this.#revoker.revoke(job);
    } catch (error) {
      const retryIn = revocationRetryDelaySeconds(job, attempt, this.#clock.now());
      if (retryIn === undefined) {
        this.#logger.warn("giving up on revocation; the token has expired at GitHub", {
          token_hash: job.token_hash,
          attempts: attempt,
          error: String(error),
        });
        return;
      }
      this.#logger.error("token revocation failed; will retry", {
        token_hash: job.token_hash,
        attempts: attempt,
        retry_in_seconds: retryIn,
        error: String(error),
      });
      this.#arm(job, retryIn, attempt + 1);
    }
  }
}

/** Revocation from in-process timers; jobs never leave the process. */
export function timerRevocation(logger?: Logger): RevocationStrategy {
  return {
    durable: false,
    create: (revoker, gateLogger) => new TimerRevocationScheduler(revoker, logger ?? gateLogger),
  };
}
