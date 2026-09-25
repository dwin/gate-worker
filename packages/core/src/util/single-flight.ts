/**
 * Deduplicates concurrent calls that share a key: while a call for `key` is in
 * flight, later callers receive the same promise. Scope is one process or isolate.
 */
export class SingleFlight<T> {
  readonly #inflight = new Map<string, Promise<T>>();

  run(key: string, task: () => Promise<T>): Promise<T> {
    const existing = this.#inflight.get(key);
    if (existing) {
      return existing;
    }
    const promise = task().finally(() => {
      this.#inflight.delete(key);
    });
    this.#inflight.set(key, promise);
    return promise;
  }
}
