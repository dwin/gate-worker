import type { AppStateStore, Clock, RateLimitState } from "../ports/index.ts";
import { systemClock } from "../util/time.ts";

export interface GitHubApp {
  readonly clientId: string;
  readonly organization: string;
}

/** Retry-After bounds returned when every matching App is rate-limited. */
const DEFAULT_RETRY_SECONDS = 60;
const MIN_RETRY_SECONDS = 1;

/** Every App configured for the owner has exhausted its rate limit. */
export class AppsExhaustedError extends Error {
  override name = "AppsExhaustedError";
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super(`all GitHub Apps exhausted; retry after ${String(retryAfterSeconds)}s`);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/** No App is configured for the repository owner. */
export class NoMatchingAppError extends Error {
  override name = "NoMatchingAppError";
  constructor(owner: string) {
    super(`no GitHub App configured for organization: ${owner}`);
  }
}

/**
 * True when `candidate` is a newer observation than `existing`: a later reset
 * window, or the same window with fewer calls remaining. Matches upstream
 * `RateLimitState.IsFresherThan`.
 */
export function isFresherThan(candidate: RateLimitState, existing: RateLimitState): boolean {
  return (
    candidate.resetAt > existing.resetAt ||
    (candidate.resetAt === existing.resetAt && candidate.remaining < existing.remaining)
  );
}

/** Chooses the App with the most rate-limit headroom for a repository owner. */
export class AppSelector {
  readonly #apps: readonly GitHubApp[];
  readonly #store: AppStateStore;
  readonly #clock: Clock;
  readonly #random: () => number;

  constructor(
    apps: readonly GitHubApp[],
    store: AppStateStore,
    clock: Clock = systemClock,
    random: () => number = Math.random,
  ) {
    if (apps.length === 0) {
      throw new Error("apps cannot be empty");
    }
    this.#apps = [...apps];
    this.#store = store;
    this.#clock = clock;
    this.#random = random;
  }

  async select(repository: string): Promise<GitHubApp> {
    const owner = repository.split("/", 1)[0] ?? "";
    const matching = this.#apps.filter((app) => app.organization === owner);
    if (matching.length === 0) {
      throw new NoMatchingAppError(owner);
    }
    const states = await this.#store.getAll();
    const now = this.#clock.now();

    const candidates: { app: GitHubApp; remaining: number }[] = [];
    const observed: RateLimitState[] = [];
    for (const app of matching) {
      const state = states.get(app.clientId);
      if (state) {
        observed.push(state);
      }
      if (!state || now > state.resetAt) {
        candidates.push({ app, remaining: Number.POSITIVE_INFINITY });
      } else if (state.remaining > 0) {
        candidates.push({ app, remaining: state.remaining });
      }
    }

    if (candidates.length === 0) {
      throw new AppsExhaustedError(this.#retryAfter(observed, now));
    }
    const best = Math.max(...candidates.map((candidate) => candidate.remaining));
    const top = candidates.filter((candidate) => candidate.remaining === best);
    const chosen = top[Math.floor(this.#random() * top.length)] ?? top[0];
    if (!chosen) {
      throw new NoMatchingAppError(owner);
    }
    return chosen.app;
  }

  async recordUsage(clientId: string, remaining: number, resetAt: Date): Promise<void> {
    await this.#store.set(clientId, {
      remaining,
      resetAt: resetAt.getTime(),
      observedAt: this.#clock.now(),
    });
  }

  #retryAfter(states: readonly RateLimitState[], now: number): number {
    const pending = states.filter((state) => state.resetAt > now).map((state) => state.resetAt);
    if (pending.length === 0) {
      return DEFAULT_RETRY_SECONDS;
    }
    const seconds = Math.floor((Math.min(...pending) - now) / 1000);
    return Math.min(Math.max(seconds, MIN_RETRY_SECONDS), DEFAULT_RETRY_SECONDS);
  }
}
