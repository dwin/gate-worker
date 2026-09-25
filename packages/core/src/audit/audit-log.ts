import type { AuditSink, Background, Logger } from "../ports/index.ts";
import { auditEntryProblem, type AuditEntry } from "./entry.ts";

export interface AuditSinkRegistration {
  readonly sink: AuditSink;
  /** When true, a failed write of a granted entry fails the exchange (upstream semantics). */
  readonly required: boolean;
}

/**
 * Fans audit entries out to sinks. Granted entries are written before the
 * token is returned, and a failure in any required sink fails the request, so
 * no token is issued without a record. Denied entries are best-effort.
 */
export class AuditLog {
  readonly #sinks: readonly AuditSinkRegistration[];
  readonly #logger: Logger;

  constructor(sinks: readonly AuditSinkRegistration[], logger: Logger) {
    this.#sinks = sinks;
    this.#logger = logger;
  }

  async granted(entry: AuditEntry, background: Background): Promise<void> {
    const problem = auditEntryProblem(entry);
    if (problem) {
      throw new Error(`invalid audit entry: ${problem}`);
    }
    const optional = this.#sinks.filter((registration) => !registration.required);
    if (optional.length > 0) {
      background.defer(() => this.#writeAll(optional, entry));
    }
    await Promise.all(
      this.#sinks
        .filter((registration) => registration.required)
        .map((registration) => registration.sink.write(entry)),
    );
  }

  denied(entry: AuditEntry, background: Background): void {
    const problem = auditEntryProblem(entry);
    if (problem) {
      this.#logger.warn("audit log failed", { request_id: entry.request_id, error: problem });
      return;
    }
    background.defer(() => this.#writeAll(this.#sinks, entry));
  }

  async #writeAll(sinks: readonly AuditSinkRegistration[], entry: AuditEntry): Promise<void> {
    const results = await Promise.allSettled(
      sinks.map((registration) => registration.sink.write(entry)),
    );
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        this.#logger.warn("audit log failed", {
          request_id: entry.request_id,
          sink: sinks[index]?.sink.name,
          error: String(result.reason),
        });
      }
    });
  }
}
