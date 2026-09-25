import type { AuditSink, Logger } from "../ports/index.ts";
import type { AuditEntry } from "./entry.ts";

/** Writes each audit entry as one structured log line, like upstream's console backend. */
export class LogAuditSink implements AuditSink {
  readonly name = "log";
  readonly #logger: Logger;

  constructor(logger: Logger) {
    this.#logger = logger;
  }

  write(entry: AuditEntry): Promise<void> {
    this.#logger.info("audit", { entry });
    return Promise.resolve();
  }
}
