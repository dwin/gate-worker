import type { RevocationStrategy } from "../../gate.ts";
import type { Logger, RevocationScheduler } from "../../ports/index.ts";
import type { RevocationJob } from "../../revocation/job.ts";
import type { Revoker } from "../../revocation/revoker.ts";

/**
 * Revokes tokens from in-process timers, equivalent to upstream's tracker and
 * one-minute revocation loop. Pending revocations are lost if the process
 * exits, as upstream's are. Suitable for long-lived Node and Bun processes only.
 */
export class TimerRevocationScheduler implements RevocationScheduler {
  readonly #revoker: Revoker;
  readonly #logger: Logger;
  readonly #timers = new Set<ReturnType<typeof setTimeout>>();

  constructor(revoker: Revoker, logger: Logger) {
    this.#revoker = revoker;
    this.#logger = logger;
  }

  schedule(job: RevocationJob, delaySeconds: number): Promise<void> {
    const timer = setTimeout(() => {
      this.#timers.delete(timer);
      this.#revoker.revoke(job).catch((error: unknown) => {
        this.#logger.error("failed to revoke token", {
          token_hash: job.token_hash,
          error: String(error),
        });
      });
    }, delaySeconds * 1000);
    // Do not keep a Node or Bun process alive just to revoke tokens.
    (timer as { unref?: () => void }).unref?.();
    this.#timers.add(timer);
    return Promise.resolve();
  }

  /** Cancels pending timers, for graceful shutdown and tests. */
  stop(): void {
    for (const timer of this.#timers) {
      clearTimeout(timer);
    }
    this.#timers.clear();
  }
}

/** Revocation from in-process timers; jobs never leave the process. */
export function timerRevocation(logger?: Logger): RevocationStrategy {
  return {
    durable: false,
    create: (revoker, gateLogger) => new TimerRevocationScheduler(revoker, logger ?? gateLogger),
  };
}
