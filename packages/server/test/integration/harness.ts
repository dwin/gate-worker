/**
 * Integration harness: the real Hono app and core, wired to a fake GitHub and a
 * fake OIDC provider through an injected fetch. Port of upstream's
 * test/integration/harness. Runs unchanged on Node (Vitest) and Bun (bun test).
 */
import {
  createLogger,
  validateCentralConfig,
  type ExchangeRequestBody,
  type RetryPolicy,
  type RevocationJob,
  type RevocationStrategy,
} from "@gate/core";
import {
  createFetchRouter,
  DEFAULT_REPOSITORY,
  FakeGitHub,
  FakeOidcProvider,
  generateAppKeyPem,
} from "@gate/testkit";
import { loadPolicyFixture } from "@gate/testkit/fixtures";
import { createApp } from "../../src/app.ts";
import { buildRuntime } from "../../src/runtime.ts";

export { DEFAULT_REPOSITORY };
const DEFAULT_POLICY = "contents_read_metadata_read.tpl.yaml";

const NO_WAIT: RetryPolicy = {
  maxAttempts: 4,
  initialBackoffMs: 0,
  maxBackoffMs: 0,
  multiplier: 2,
  jitterFraction: 0,
};

export interface ServerOptions {
  readonly requireExplicitPolicy?: boolean;
  readonly defaultTtl?: number;
  readonly maxTtl?: number;
  readonly maxPermissions?: Readonly<Record<string, string>>;
  readonly apps?: readonly { clientId: string; organization: string }[];
  readonly origin?: { headerName: string; value: string };
  readonly env?: Readonly<Record<string, string>>;
}

export interface ExchangeResult {
  readonly status: number;
  readonly headers: Headers;
  readonly body: Record<string, unknown>;
}

function randomKey(): string {
  return btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
}

export async function startServer(options: ServerOptions = {}) {
  const oidc = await FakeOidcProvider.create();
  const github = new FakeGitHub();
  const router = createFetchRouter({ [oidc.origin]: oidc.handle, [github.origin]: github.handle });
  const apps = options.apps ?? [{ clientId: "client-1", organization: "example-org" }];

  const env: Record<string, string> = { GATE_REVOCATION_KEYS: `k1:${randomKey()}`, ...options.env };
  for (const [index] of apps.entries()) {
    env[`GATE_APP_KEY_${String(index)}`] = (await generateAppKeyPem()).pem;
  }
  if (options.origin) {
    env["GATE_ORIGIN_HEADER_VALUE"] = options.origin.value;
  }

  const config = validateCentralConfig({
    oidc: { audience: oidc.issuer },
    policy: {
      trust_policy_path: ".github/trust-policy.yaml",
      default_token_ttl: options.defaultTtl ?? 3600,
      max_token_ttl: options.maxTtl ?? 7200,
      require_explicit_policy: options.requireExplicitPolicy ?? false,
      github_api_base_url: github.baseUrl,
      providers: [{ name: "github-actions", issuer: oidc.issuer }],
      max_permissions: options.maxPermissions ?? {
        contents: "write",
        metadata: "read",
        packages: "write",
        actions: "write",
        issues: "write",
        pull_requests: "write",
      },
    },
    origin: options.origin
      ? { enabled: true, header_name: options.origin.headerName }
      : { enabled: false },
    github_apps: apps.map((app, index) => ({
      client_id: app.clientId,
      organization: app.organization,
      private_key_secret: `GATE_APP_KEY_${String(index)}`,
    })),
  });

  const logs: string[] = [];
  const logger = createLogger({
    level: "debug",
    format: "json",
    writer: (_level, line) => logs.push(line),
  });
  const scheduled: { job: RevocationJob; delaySeconds: number }[] = [];
  const revocation: RevocationStrategy = {
    durable: true,
    create: () => ({
      schedule: (job, delaySeconds) => {
        scheduled.push({ job, delaySeconds });
        return Promise.resolve();
      },
    }),
  };
  const runtime = buildRuntime({
    config,
    env,
    fetch: router.fetch,
    revocation,
    gate: { logger, github: { retry: NO_WAIT, tokenReadyDelayMs: 0 } },
  });
  const tasks: Promise<void>[] = [];
  const app = createApp({
    getRuntime: () => runtime,
    background: () => ({ defer: (task) => tasks.push(task()) }),
    logger,
  });

  async function exchange(
    body: Partial<ExchangeRequestBody>,
    headers: Record<string, string> = {},
  ): Promise<ExchangeResult> {
    const response = await app.request("/api/v1/exchange", {
      method: "POST",
      headers: { "content-type": "application/json", ...headers },
      body: JSON.stringify(body),
    });
    return {
      status: response.status,
      headers: response.headers,
      body: (await response.json()) as Record<string, unknown>,
    };
  }

  return {
    app,
    oidc,
    github,
    router,
    logs,
    scheduled,
    runtime: () => runtime,
    setupPolicy(repository: string, fixture: string): void {
      github.setPolicy(repository, loadPolicyFixture(fixture, oidc.issuer));
      github.setInstallation(repository);
    },
    setupDefaultPolicy(): void {
      this.setupPolicy(DEFAULT_REPOSITORY, DEFAULT_POLICY);
    },
    exchange,
    async exchangeDefault(): Promise<ExchangeResult> {
      return exchange({ oidc_token: await oidc.token(), target_repository: DEFAULT_REPOSITORY });
    },
    /** Waits for background work (denied audit entries, rate-limit recording). */
    settle: () => Promise.all(tasks),
    logEntries: () => logs.map((line) => JSON.parse(line) as Record<string, unknown>),
  };
}

export type TestServer = Awaited<ReturnType<typeof startServer>>;
