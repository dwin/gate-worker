import { Revoker, type Logger, type RevocationJob, type RevocationStrategy } from "@gate/core";

/** Cloudflare Queues caps message delivery delay at 24 hours. */
const MAX_DELAY_SECONDS = 86_400;
const RETRY_DELAY_SECONDS = 30;

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

/** Queue consumer: revokes each token, retrying failures and dropping malformed messages. */
export async function handleRevocationBatch(
  batch: MessageBatch,
  revoker: Revoker,
  logger: Logger,
): Promise<void> {
  await Promise.all(
    batch.messages.map(async (message) => {
      let job: RevocationJob;
      try {
        job = Revoker.parseJob(message.body);
      } catch (error) {
        logger.error("dropping malformed revocation message", {
          message_id: message.id,
          error: String(error),
        });
        message.ack();
        return;
      }
      try {
        await revoker.revoke(job);
        message.ack();
      } catch (error) {
        logger.warn("token revocation failed; will retry", {
          token_hash: job.token_hash,
          attempt: message.attempts,
          error: String(error),
        });
        message.retry({ delaySeconds: RETRY_DELAY_SECONDS });
      }
    }),
  );
}
