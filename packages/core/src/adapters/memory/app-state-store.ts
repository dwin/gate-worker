import type { AppStateStore, RateLimitState } from "../../ports/index.ts";
import { isFresherThan } from "../../selector/selector.ts";

/** In-process selector state, upstream's default `selector.type: memory`. */
export class MemoryAppStateStore implements AppStateStore {
  readonly #states = new Map<string, RateLimitState>();

  getAll(): Promise<ReadonlyMap<string, RateLimitState>> {
    return Promise.resolve(new Map(this.#states));
  }

  set(clientId: string, state: RateLimitState): Promise<void> {
    const existing = this.#states.get(clientId);
    if (!existing || isFresherThan(state, existing)) {
      this.#states.set(clientId, { ...state });
    }
    return Promise.resolve();
  }
}
