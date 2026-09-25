export const FAKE_GITHUB_API = "https://api.github.gate.test";
export const DEFAULT_INSTALLATION_ID = 123456;

interface Failure {
  status: number;
  message: string;
  retryAfter?: number;
}

interface TokenTemplate {
  value: string;
  permissions: Record<string, string>;
  expiresAt: Date;
}

export interface RecordedRequest {
  method: string;
  path: string;
  authorization: string | null;
  body: unknown;
}

/**
 * In-memory GitHub API covering the endpoints GATE calls. Port of upstream's
 * `test/integration/harness/github.go`, extended with the endpoints the client
 * actually uses (`/orgs/{org}/installation`, `/users/{user}/installation`,
 * `/rate_limit`, `DELETE /installation/token`).
 */
export class FakeGitHub {
  readonly baseUrl: string;
  readonly requests: RecordedRequest[] = [];
  readonly revokedTokens: string[] = [];
  readonly #policies = new Map<string, Map<string, string>>();
  readonly #installations = new Map<string, number>();
  readonly #tokens = new Map<number, TokenTemplate>();
  readonly #failures = new Map<string, Failure>();
  #latencyMs = 0;
  #tokenCounter = 0;
  #rateLimit = { remaining: 4999, reset: Math.floor(Date.now() / 1000) + 3600 };

  constructor(baseUrl: string = FAKE_GITHUB_API) {
    this.baseUrl = baseUrl;
  }

  get origin(): string {
    return new URL(this.baseUrl).origin;
  }

  /** Serves `content` at `path` (default `.github/trust-policy.yaml`) in `repository`. */
  setPolicy(repository: string, content: string, path = ".github/trust-policy.yaml"): void {
    const files = this.#policies.get(repository) ?? new Map<string, string>();
    files.set(path, content);
    this.#policies.set(repository, files);
  }

  /** Registers an installation for the repository's owner. */
  setInstallation(repository: string, id: number = DEFAULT_INSTALLATION_ID): void {
    this.#installations.set(repository.split("/")[0] ?? repository, id);
  }

  setToken(
    installationId: number,
    value: string,
    permissions: Record<string, string>,
    expiresAt: Date,
  ): void {
    this.#tokens.set(installationId, { value, permissions, expiresAt });
  }

  /** Every request whose path contains `pattern` fails with `status`. */
  setError(pattern: string, status: number, message: string, retryAfter?: number): void {
    this.#failures.set(
      pattern,
      retryAfter === undefined ? { status, message } : { status, message, retryAfter },
    );
  }

  setLatency(ms: number): void {
    this.#latencyMs = ms;
  }

  setRateLimit(remaining: number, reset: Date): void {
    this.#rateLimit = { remaining, reset: Math.floor(reset.getTime() / 1000) };
  }

  wasRequested(pathFragment: string, method?: string): boolean {
    return this.requests.some(
      (request) =>
        request.path.includes(pathFragment) && (method === undefined || request.method === method),
    );
  }

  count(pathFragment: string, method?: string): number {
    return this.requests.filter(
      (request) =>
        request.path.includes(pathFragment) && (method === undefined || request.method === method),
    ).length;
  }

  readonly handle = async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    const path = decodeURIComponent(url.pathname);
    const text =
      request.method === "GET" || request.method === "DELETE" ? "" : await request.text();
    this.requests.push({
      method: request.method,
      path,
      authorization: request.headers.get("authorization"),
      body: text ? (JSON.parse(text) as unknown) : undefined,
    });
    if (this.#latencyMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.#latencyMs));
    }
    for (const [pattern, failure] of this.#failures) {
      if (path.includes(pattern)) {
        const headers: Record<string, string> = {};
        if (failure.retryAfter !== undefined) headers["retry-after"] = String(failure.retryAfter);
        return Response.json({ message: failure.message }, { status: failure.status, headers });
      }
    }
    if (!request.headers.get("user-agent")) {
      return Response.json({ message: "User-Agent header required" }, { status: 403 });
    }

    const contents = /^\/repos\/([^/]+)\/([^/]+)\/contents\/(.+)$/.exec(path);
    if (contents && request.method === "GET") {
      return this.#contents(`${contents[1] ?? ""}/${contents[2] ?? ""}`, contents[3] ?? "");
    }
    const installation = /^\/(orgs|users)\/([^/]+)\/installation$/.exec(path);
    if (installation && request.method === "GET") {
      const id = this.#installations.get(installation[2] ?? "");
      return id === undefined
        ? Response.json({ message: "Not Found" }, { status: 404 })
        : Response.json({ id, account: { login: installation[2] } });
    }
    const accessTokens = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(path);
    if (accessTokens && request.method === "POST") {
      return this.#accessToken(Number(accessTokens[1]), text);
    }
    if (path === "/rate_limit" && request.method === "GET") {
      return Response.json({ resources: { core: this.#rateLimit } });
    }
    if (path === "/installation/token" && request.method === "DELETE") {
      const token = (request.headers.get("authorization") ?? "").replace(/^(token|Bearer) /, "");
      if (this.revokedTokens.includes(token)) {
        return Response.json({ message: "Bad credentials" }, { status: 401 });
      }
      this.revokedTokens.push(token);
      return new Response(null, { status: 204 });
    }
    return Response.json({ message: "Not Found" }, { status: 404 });
  };

  #contents(repository: string, filePath: string): Response {
    const content = this.#policies.get(repository)?.get(filePath);
    if (content === undefined) {
      return Response.json({ message: "Not Found" }, { status: 404 });
    }
    const bytes = new TextEncoder().encode(content);
    const base64 = btoa(String.fromCharCode(...bytes)).replace(/(.{60})/g, "$1\n");
    return Response.json({
      name: filePath.split("/").pop(),
      path: filePath,
      sha: "abc123",
      size: bytes.length,
      encoding: "base64",
      content: base64,
      type: "file",
    });
  }

  #accessToken(installationId: number, body: string): Response {
    const template = this.#tokens.get(installationId);
    const parsed = body ? (JSON.parse(body) as { permissions?: Record<string, string> }) : {};
    this.#tokenCounter++;
    return Response.json(
      {
        token:
          template?.value ??
          `ghs_test_token_${String(installationId)}_${String(this.#tokenCounter)}`,
        expires_at: (template?.expiresAt ?? new Date(Date.now() + 3600_000)).toISOString(),
        permissions: template?.permissions ?? parsed.permissions ?? { contents: "read" },
      },
      { status: 201 },
    );
  }
}
