import { SignJWT } from "jose";
import { MemoryCache } from "../adapters/memory/cache.ts";
import type { Permissions } from "../authorizer/permission-levels.ts";
import type { Cache, Clock, FetchLike, Sleep } from "../ports/index.ts";
import { base64Decode, utf8Decode } from "../util/encoding.ts";
import { SingleFlight } from "../util/single-flight.ts";
import { epochSeconds, systemClock, timerSleep } from "../util/time.ts";
import {
  FileNotFoundError,
  GitHubApiError,
  InstallationNotFoundError,
  RepositoryNotFoundError,
} from "./errors.ts";
import { DEFAULT_RETRY_POLICY, fetchWithRetry, type RetryPolicy } from "./retry.ts";

/** GitHub accepts App JWTs valid for at most 10 minutes. */
const APP_JWT_TTL_SECONDS = 600;
/** Backdates `iat` to tolerate clock drift between this service and GitHub. */
const APP_JWT_CLOCK_SKEW_SECONDS = 5;
/** Reuses a signed App JWT until this close to its expiry. */
const APP_JWT_REFRESH_MARGIN_SECONDS = 60;
const INSTALLATION_CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const INSTALLATION_CACHE_MAX_ENTRIES = 1000;
const TOKEN_CACHE_MAX_ENTRIES = 1000;
/** A cached contents token is not reused within this window of its expiry. */
const TOKEN_CACHE_EXPIRY_BUFFER_MS = 5 * 60 * 1000;

export interface GitHubAppClientOptions {
  readonly clientId: string;
  readonly privateKey: CryptoKey;
  readonly baseUrl: string;
  readonly fetch: FetchLike;
  readonly clock?: Clock;
  readonly sleep?: Sleep;
  readonly retry?: RetryPolicy;
  /** Overall budget for one logical call, including retries. Upstream: 30 s. */
  readonly timeoutMs?: number;
  /**
   * Pause after minting a contents token before first use, letting GitHub
   * replicate it. Upstream: 2 s, per GitHub Support guidance.
   */
  readonly tokenReadyDelayMs?: number;
}

export interface InstallationToken {
  readonly token: string;
  readonly expiresAt: Date;
}

export interface RateLimitInfo {
  readonly remaining: number;
  readonly resetAt: Date;
}

interface CachedToken {
  readonly token: string;
  readonly expiresAt: number;
}

function splitRepository(repository: string): [owner: string, repo: string] {
  const [owner, repo, extra] = repository.split("/");
  if (!owner || !repo || extra !== undefined) {
    throw new Error(`invalid repository format (expected owner/repo): ${repository}`);
  }
  return [owner, repo];
}

/** Stable cache key for a permission set. */
function permissionsKey(permissions: Permissions): string {
  return Object.keys(permissions)
    .sort()
    .map((name) => `${name}=${permissions[name] ?? ""}`)
    .join(",");
}

async function errorMessage(response: Response): Promise<string> {
  const text = await response.text().catch(() => "");
  try {
    const parsed = JSON.parse(text) as { message?: unknown };
    return typeof parsed.message === "string" ? parsed.message : text.slice(0, 200);
  } catch {
    return text.slice(0, 200);
  }
}

/**
 * Minimal GitHub App client: exactly the six endpoints GATE needs, with
 * upstream's retry, caching, and replication-delay behaviour.
 */
export class GitHubAppClient {
  readonly clientId: string;
  readonly #privateKey: CryptoKey;
  readonly #baseUrl: string;
  readonly #fetch: FetchLike;
  readonly #clock: Clock;
  readonly #sleep: Sleep;
  readonly #retry: RetryPolicy;
  readonly #timeoutMs: number;
  readonly #tokenReadyDelayMs: number;
  readonly #installations: Cache<number>;
  readonly #tokens: Cache<CachedToken>;
  readonly #installationFlight = new SingleFlight<number>();
  readonly #tokenFlight = new SingleFlight<string>();
  #appJwt: { value: string; expiresAt: number } | undefined;

  constructor(options: GitHubAppClientOptions) {
    this.clientId = options.clientId;
    this.#privateKey = options.privateKey;
    this.#baseUrl = options.baseUrl.replace(/\/+$/, "");
    this.#fetch = options.fetch;
    this.#clock = options.clock ?? systemClock;
    this.#sleep = options.sleep ?? timerSleep;
    this.#retry = options.retry ?? DEFAULT_RETRY_POLICY;
    this.#timeoutMs = options.timeoutMs ?? 30_000;
    this.#tokenReadyDelayMs = options.tokenReadyDelayMs ?? 2000;
    this.#installations = new MemoryCache(INSTALLATION_CACHE_MAX_ENTRIES, this.#clock);
    this.#tokens = new MemoryCache(TOKEN_CACHE_MAX_ENTRIES, this.#clock);
  }

  /** Mints an installation token scoped to one repository and permission set. */
  async requestToken(repository: string, permissions: Permissions): Promise<InstallationToken> {
    if (Object.keys(permissions).length === 0) {
      // GitHub treats an omitted permission set as "everything the App holds".
      throw new Error("refusing to mint a repository token without explicit permissions");
    }
    const [owner, repo] = splitRepository(repository);
    const installationId = await this.#installationId(owner);
    return this.#createInstallationToken(installationId, repo, permissions, repository);
  }

  /** Revokes an installation token. A 401 means it is already invalid and counts as success. */
  async revokeToken(token: string): Promise<void> {
    const response = await this.#call("DELETE", "/installation/token", `token ${token}`);
    if (response.status === 204 || response.status === 401 || response.ok) {
      await response.body?.cancel();
      return;
    }
    throw new GitHubApiError(response.status, await errorMessage(response));
  }

  /** Current core rate limit for the installation. `/rate_limit` does not consume quota. */
  async rateLimit(token: string): Promise<RateLimitInfo> {
    const response = await this.#call("GET", "/rate_limit", `token ${token}`);
    if (!response.ok) {
      throw new GitHubApiError(response.status, await errorMessage(response));
    }
    const body = (await response.json()) as {
      resources?: { core?: { remaining?: number; reset?: number } };
    };
    const core = body.resources?.core;
    return {
      remaining: core?.remaining ?? 0,
      resetAt: new Date((core?.reset ?? 0) * 1000),
    };
  }

  /** Fetches a file's UTF-8 content using a cached `contents: read` installation token. */
  async getContents(repository: string, path: string): Promise<string> {
    const [owner, repo] = splitRepository(repository);
    const encodedPath = path.split("/").map(encodeURIComponent).join("/");
    const location = `${repository}/${path}`;
    const permissions: Permissions = { contents: "read" };

    for (let attempt = 0; attempt < 2; attempt++) {
      // A second attempt mints a fresh token in case the cached one went stale.
      const token = await this.#contentsToken(owner, permissions, attempt > 0);
      const response = await this.#call(
        "GET",
        `/repos/${owner}/${repo}/contents/${encodedPath}`,
        `token ${token}`,
      );
      if (attempt === 0 && (response.status === 401 || response.status === 403)) {
        await response.body?.cancel();
        continue;
      }
      if (response.status === 404) {
        await response.body?.cancel();
        throw new FileNotFoundError(location);
      }
      if (!response.ok) {
        throw new GitHubApiError(response.status, await errorMessage(response));
      }
      const body = (await response.json()) as unknown;
      if (
        Array.isArray(body) ||
        typeof body !== "object" ||
        body === null ||
        (body as { type?: unknown }).type !== "file"
      ) {
        throw new FileNotFoundError(`${location} is a directory`);
      }
      const { content, encoding } = body as { content?: unknown; encoding?: unknown };
      if (encoding !== "base64" || typeof content !== "string") {
        throw new GitHubApiError(response.status, `unsupported content encoding for ${location}`);
      }
      return utf8Decode(base64Decode(content));
    }
    throw new GitHubApiError(401, `exhausted retries fetching ${location}`);
  }

  async #contentsToken(owner: string, permissions: Permissions, fresh: boolean): Promise<string> {
    const key = `${owner}|${permissionsKey(permissions)}`;
    if (fresh) {
      this.#tokens.delete(key);
    } else {
      const cached = this.#tokens.get(key);
      if (cached) {
        return cached.token;
      }
    }
    return this.#tokenFlight.run(key, async () => {
      const installationId = await this.#installationId(owner);
      const minted = await this.#createInstallationToken(
        installationId,
        undefined,
        permissions,
        owner,
      );
      if (this.#tokenReadyDelayMs > 0) {
        await this.#sleep(this.#tokenReadyDelayMs);
      }
      const expiresAt = minted.expiresAt.getTime();
      const ttlMs = expiresAt - TOKEN_CACHE_EXPIRY_BUFFER_MS - this.#clock.now();
      if (ttlMs > 0) {
        this.#tokens.set(key, { token: minted.token, expiresAt }, ttlMs);
      }
      return minted.token;
    });
  }

  async #installationId(owner: string): Promise<number> {
    const cached = this.#installations.get(owner);
    if (cached !== undefined) {
      return cached;
    }
    return this.#installationFlight.run(owner, async () => {
      const authorization = `Bearer ${await this.#appToken()}`;
      const encodedOwner = encodeURIComponent(owner);
      let response = await this.#call("GET", `/orgs/${encodedOwner}/installation`, authorization);
      if (response.status === 404) {
        await response.body?.cancel();
        response = await this.#call("GET", `/users/${encodedOwner}/installation`, authorization);
      }
      if (response.status === 404) {
        await response.body?.cancel();
        throw new InstallationNotFoundError(owner);
      }
      if (!response.ok) {
        throw new GitHubApiError(response.status, await errorMessage(response));
      }
      const { id } = (await response.json()) as { id?: unknown };
      if (typeof id !== "number") {
        throw new GitHubApiError(response.status, "installation response missing id");
      }
      this.#installations.set(owner, id, INSTALLATION_CACHE_TTL_MS);
      return id;
    });
  }

  async #createInstallationToken(
    installationId: number,
    repository: string | undefined,
    permissions: Permissions,
    subject: string,
  ): Promise<InstallationToken> {
    const body: { permissions?: Permissions; repositories?: string[] } = {};
    if (Object.keys(permissions).length > 0) {
      body.permissions = permissions;
    }
    if (repository !== undefined) {
      body.repositories = [repository];
    }
    const response = await this.#call(
      "POST",
      `/app/installations/${String(installationId)}/access_tokens`,
      `Bearer ${await this.#appToken()}`,
      JSON.stringify(body),
    );
    if (response.status === 404 || response.status === 422) {
      await response.body?.cancel();
      throw repository === undefined
        ? new InstallationNotFoundError(subject)
        : new RepositoryNotFoundError(subject);
    }
    if (!response.ok) {
      throw new GitHubApiError(response.status, await errorMessage(response));
    }
    const { token, expires_at: expiresAt } = (await response.json()) as {
      token?: unknown;
      expires_at?: unknown;
    };
    if (typeof token !== "string" || typeof expiresAt !== "string") {
      throw new GitHubApiError(
        response.status,
        "access token response missing token or expires_at",
      );
    }
    return { token, expiresAt: new Date(expiresAt) };
  }

  /** RS256 App JWT, reused until shortly before it expires. */
  async #appToken(): Promise<string> {
    const now = epochSeconds(this.#clock.now());
    if (this.#appJwt && this.#appJwt.expiresAt - APP_JWT_REFRESH_MARGIN_SECONDS > now) {
      return this.#appJwt.value;
    }
    const expiresAt = now + APP_JWT_TTL_SECONDS;
    const value = await new SignJWT({})
      .setProtectedHeader({ alg: "RS256", typ: "JWT" })
      .setIssuedAt(now - APP_JWT_CLOCK_SKEW_SECONDS)
      .setExpirationTime(expiresAt)
      .setIssuer(this.clientId)
      .sign(this.#privateKey);
    this.#appJwt = { value, expiresAt };
    return value;
  }

  #call(method: string, path: string, authorization: string, body?: string): Promise<Response> {
    const headers: Record<string, string> = {
      accept: "application/vnd.github+json",
      authorization,
      "user-agent": "gate-worker",
      "x-github-api-version": "2022-11-28",
    };
    const init: RequestInit & { body?: string } = {
      method,
      headers,
      signal: AbortSignal.timeout(this.#timeoutMs),
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      init.body = body;
    }
    return fetchWithRetry(this.#fetch, `${this.#baseUrl}${path}`, init, this.#retry, this.#sleep);
  }
}
