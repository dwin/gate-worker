import type { Cache, Clock } from "../../ports/index.ts";
import { systemClock } from "../../util/time.ts";

interface Entry<V> {
  value: V;
  expiresAt: number;
}

/**
 * Bounded in-process cache. When full, evicts the least recently inserted entry,
 * which matches upstream's "evict oldest fetched" behaviour for its caches.
 */
export class MemoryCache<V> implements Cache<V> {
  readonly #entries = new Map<string, Entry<V>>();
  readonly #maxEntries: number;
  readonly #clock: Clock;

  constructor(maxEntries: number, clock: Clock = systemClock) {
    this.#maxEntries = maxEntries;
    this.#clock = clock;
  }

  get(key: string): V | undefined {
    const entry = this.#entries.get(key);
    if (!entry) {
      return undefined;
    }
    if (this.#clock.now() >= entry.expiresAt) {
      this.#entries.delete(key);
      return undefined;
    }
    return entry.value;
  }

  set(key: string, value: V, ttlMs: number): void {
    this.#entries.delete(key);
    if (this.#entries.size >= this.#maxEntries) {
      const oldest = this.#entries.keys().next();
      if (!oldest.done) {
        this.#entries.delete(oldest.value);
      }
    }
    this.#entries.set(key, { value, expiresAt: this.#clock.now() + ttlMs });
  }

  delete(key: string): void {
    this.#entries.delete(key);
  }
}
