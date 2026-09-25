/**
 * Ports: the interfaces through which the core reaches the outside world.
 *
 * The core never touches a platform API directly. Every entry point (Workers,
 * Node, Bun, Lambda, Vercel) supplies implementations of these interfaces.
 */
import type { AuditEntry } from "../audit/entry.ts";
import type { RevocationJob } from "../revocation/job.ts";

/** The subset of the WHATWG `fetch` signature the core relies on. */
export type FetchLike = (input: Request | string | URL, init?: RequestInit) => Promise<Response>;

/** Wall-clock source, in milliseconds since the Unix epoch. */
export interface Clock {
  now(): number;
}

/** Waits for `ms` milliseconds, rejecting early if `signal` aborts. */
export type Sleep = (ms: number, signal?: AbortSignal) => Promise<void>;

/** Resolves named secrets (GitHub App keys, origin header value, revocation keys). */
export interface SecretSource {
  get(name: string): Promise<string | undefined>;
}

/**
 * In-process key/value cache with per-entry expiry. Values may hold live
 * objects (compiled regexes, CryptoKeys), so implementations must not serialize.
 */
export interface Cache<V> {
  get(key: string): V | undefined;
  set(key: string, value: V, ttlMs: number): void;
  delete(key: string): void;
}

/** Last observed GitHub rate-limit state for one GitHub App. */
export interface RateLimitState {
  remaining: number;
  /** Epoch milliseconds at which the rate-limit window resets. */
  resetAt: number;
  /** Epoch milliseconds of the observation. */
  observedAt: number;
}

/** Stores rate-limit state per GitHub App client ID for the app selector. */
export interface AppStateStore {
  getAll(): Promise<ReadonlyMap<string, RateLimitState>>;
  /** Records `state`, ignoring it when an existing observation is fresher. */
  set(clientId: string, state: RateLimitState): Promise<void>;
}

/** Schedules revocation of an issued token once its capped TTL has elapsed. */
export interface RevocationScheduler {
  schedule(job: RevocationJob, delaySeconds: number): Promise<void>;
}

/** Persists audit entries. */
export interface AuditSink {
  readonly name: string;
  write(entry: AuditEntry): Promise<void>;
}

/** Runs work after the response has been sent (for example `ctx.waitUntil`). */
export interface Background {
  defer(task: () => Promise<void>): void;
}

export type LogLevel = "debug" | "info" | "warn" | "error";
export type LogAttributes = Readonly<Record<string, unknown>>;

/** Structured logger. Implementations emit one line per call. */
export interface Logger {
  debug(message: string, attributes?: LogAttributes): void;
  info(message: string, attributes?: LogAttributes): void;
  warn(message: string, attributes?: LogAttributes): void;
  error(message: string, attributes?: LogAttributes): void;
}
