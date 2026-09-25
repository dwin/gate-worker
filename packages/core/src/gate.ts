/**
 * Composition root: builds a ready-to-serve token exchange service from
 * validated configuration, resolved secrets, and platform adapters.
 */
import { MemoryAppStateStore } from "./adapters/memory/app-state-store.ts";
import { AuditLog, type AuditSinkRegistration } from "./audit/audit-log.ts";
import { LogAuditSink } from "./audit/log-sink.ts";
import { Authorizer } from "./authorizer/authorizer.ts";
import { PolicyLoader } from "./authorizer/policy-loader.ts";
import { ConfigError } from "./config/errors.ts";
import { importAppPrivateKey } from "./config/keys.ts";
import type { CentralConfig } from "./config/schema.ts";
import { GitHubAppClient } from "./github/client.ts";
import type { RetryPolicy } from "./github/retry.ts";
import { createLogger } from "./logging/logger.ts";
import { OidcValidator } from "./oidc/validator.ts";
import type {
  AppStateStore,
  Clock,
  FetchLike,
  Logger,
  RevocationScheduler,
  SecretSource,
  Sleep,
} from "./ports/index.ts";
import { Revoker } from "./revocation/revoker.ts";
import { TokenSealer } from "./revocation/sealer.ts";
import { AppSelector } from "./selector/selector.ts";
import { TokenExchangeService } from "./sts/service.ts";
import { systemClock, timerSleep } from "./util/time.ts";

/** How issued tokens get revoked when their capped TTL ends. */
export interface RevocationStrategy {
  /**
   * True when scheduled jobs leave the process (a queue or a store). Durable
   * strategies require the revocation key secret; in-process ones use an
   * ephemeral key when it is absent.
   */
  readonly durable: boolean;
  create(revoker: Revoker, logger: Logger): RevocationScheduler;
}

export interface GateOptions {
  readonly config: CentralConfig;
  readonly secrets: SecretSource;
  readonly fetch: FetchLike;
  readonly revocation: RevocationStrategy;
  readonly logger?: Logger;
  readonly clock?: Clock;
  readonly sleep?: Sleep;
  readonly appState?: AppStateStore;
  /** Defaults to one required `LogAuditSink`. */
  readonly auditSinks?: readonly AuditSinkRegistration[];
  readonly github?: {
    readonly retry?: RetryPolicy;
    readonly tokenReadyDelayMs?: number;
    readonly timeoutMs?: number;
  };
}

export interface Gate {
  readonly config: CentralConfig;
  readonly logger: Logger;
  readonly service: TokenExchangeService;
  readonly revoker: Revoker;
  readonly scheduler: RevocationScheduler;
}

export async function createGate(options: GateOptions): Promise<Gate> {
  const { config, secrets } = options;
  const clock = options.clock ?? systemClock;
  const sleep = options.sleep ?? timerSleep;
  const logger =
    options.logger ?? createLogger({ level: config.logger.level, format: config.logger.format });

  const problems: string[] = [];
  const clients = new Map<string, GitHubAppClient>();
  await Promise.all(
    config.github_apps.map(async (app, index) => {
      const label = `github_apps[${String(index)}].private_key_secret`;
      const pem = await secrets.get(app.private_key_secret);
      if (!pem) {
        problems.push(`${label}: secret "${app.private_key_secret}" is not set`);
        return;
      }
      try {
        const privateKey = await importAppPrivateKey(pem, `${label} (${app.private_key_secret})`);
        clients.set(
          app.client_id,
          new GitHubAppClient({
            clientId: app.client_id,
            privateKey,
            baseUrl: config.policy.github_api_base_url,
            fetch: options.fetch,
            clock,
            sleep,
            ...(options.github?.retry ? { retry: options.github.retry } : {}),
            ...(options.github?.tokenReadyDelayMs === undefined
              ? {}
              : { tokenReadyDelayMs: options.github.tokenReadyDelayMs }),
            ...(options.github?.timeoutMs === undefined
              ? {}
              : { timeoutMs: options.github.timeoutMs }),
          }),
        );
      } catch (error) {
        problems.push(...(error instanceof ConfigError ? error.issues : [String(error)]));
      }
    }),
  );

  const keySecretName = config.revocation.key_secret;
  const keySecret = await secrets.get(keySecretName);
  let sealer: TokenSealer | undefined;
  if (keySecret) {
    try {
      sealer = await TokenSealer.fromSecret(keySecret, `revocation.key_secret (${keySecretName})`);
    } catch (error) {
      problems.push(...(error instanceof ConfigError ? error.issues : [String(error)]));
    }
  } else if (options.revocation.durable) {
    problems.push(
      `revocation.key_secret: secret "${keySecretName}" is not set; it is required because issued tokens are held in a durable queue until revocation`,
    );
  } else {
    sealer = await TokenSealer.ephemeral();
  }

  if (problems.length > 0 || !sealer) {
    throw new ConfigError(problems);
  }

  const selector = new AppSelector(
    config.github_apps.map((app) => ({ clientId: app.client_id, organization: app.organization })),
    options.appState ?? new MemoryAppStateStore(),
    clock,
  );
  const loader = new PolicyLoader(config.policy.trust_policy_path, selector, clients, clock);
  const revoker = new Revoker(sealer, clients, logger);
  const scheduler = options.revocation.create(revoker, logger);
  const audit = new AuditLog(
    options.auditSinks ?? [{ sink: new LogAuditSink(logger), required: true }],
    logger,
  );

  const service = new TokenExchangeService({
    maxTtl: config.policy.max_token_ttl,
    oidc: new OidcValidator({
      audience: config.oidc.audience,
      issuers: config.policy.providers.map((provider) => provider.issuer),
      fetch: options.fetch,
      clock,
    }),
    authorizer: new Authorizer(config.policy, loader, clock),
    selector,
    clients,
    audit,
    sealer,
    scheduler,
    logger,
    clock,
  });

  return { config, logger, service, revoker, scheduler };
}
