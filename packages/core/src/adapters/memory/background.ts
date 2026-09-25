import type { Background, Logger } from "../../ports/index.ts";

/**
 * Runs deferred work without awaiting it. Suitable for long-lived processes
 * (Node, Bun). Serverless platforms that freeze after the response must supply
 * their own `Background` (Workers `waitUntil`, Vercel `waitUntil`).
 */
export class FireAndForgetBackground implements Background {
  readonly #logger: Logger;

  constructor(logger: Logger) {
    this.#logger = logger;
  }

  defer(task: () => Promise<void>): void {
    task().catch((error: unknown) => {
      this.#logger.error("background task failed", { error: String(error) });
    });
  }
}
