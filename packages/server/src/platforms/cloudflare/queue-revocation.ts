import {
  revocationRetryDelaySeconds,
  Revoker,
  type Logger,
  type RevocationJob,
  type RevocationStrategy,
} from "@gate/core";

/** Cloudflare Queues caps message delivery delay at 24 hours. */
const MAX_DELAY_SECONDS = 86_400;

/**
 * Revocation through a Cloudflare Queue: one delayed message per issued token.
 * Messages carry the token sealed with AES-256-GCM, never in plaintext.
 */
export function queueRevocation(queue: Queue<RevocationJob>): RevocationStrategy {
  return {
    durable: true,
    create: () => ({
      async schedule(job, delaySeconds) {
        await queue.send(job, {
          contentType: "json",
          delaySeconds: Math.min(Math.max(0, delaySeconds), MAX_DELAY_SECONDS),
        });
      },
    }),
  };
}

/**
 * Queue consumer for the revocation queue and its dead-letter queue.
 *
 * Failed revocations are retried with growing delays for as long as the token
 * could still be valid: GitHub tokens expire at most an hour after minting,
 * and minting happens before the capped `expires_at`, so after
 * `expires_at + 1h` the token is dead and the job can be dropped. Until then a
 * job is never acked on failure, so exhausting the main queue's retries moves
 * it to the dead-letter queue, whose retry budget outlasts that window.
 * Malformed messages are dropped immediately.
 */
export async function handleRevocationBatch(
  batch: MessageBatch,
  revoker: Revoker,
  logger: Logger,
  now: () => number = Date.now,
): Promise<void> {
  await Promise.all(
    batch.messages.map(async (message) => {
      let job: RevocationJob;
      try {
        job = Revoker.parseJob(message.body);
      } catch (error) {
        logger.error("dropping malformed revocation message", {
          queue: batch.queue,
          message_id: message.id,
          error: String(error),
        });
        message.ack();
        return;
      }
      try {
        await revoker.revoke(job);
        message.ack();
        return;
      } catch (error) {
        const delaySeconds = revocationRetryDelaySeconds(job, message.attempts, now());
        if (delaySeconds === undefined) {
          logger.warn("giving up on revocation; the token has expired at GitHub", {
            queue: batch.queue,
            token_hash: job.token_hash,
            attempts: message.attempts,
            error: String(error),
          });
          message.ack();
          return;
        }
        logger.error("token revocation failed; will retry", {
          queue: batch.queue,
          token_hash: job.token_hash,
          attempts: message.attempts,
          retry_in_seconds: delaySeconds,
          error: String(error),
        });
        message.retry({ delaySeconds });
      }
    }),
  );
}
