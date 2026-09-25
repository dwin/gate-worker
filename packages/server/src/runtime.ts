import {
  applyEnvOverrides,
  ConfigError,
  createGate,
  createLogger,
  type CentralConfig,
  type FetchLike,
  type Gate,
  type GateOptions,
  type Logger,
  type RevocationStrategy,
  type SecretSource,
} from "@gate/core";

/** Everything a request needs, built once per process or isolate. */
export interface Runtime {
  readonly gate: Gate;
  readonly logger: Logger;
  /** Resolved origin-verification secret, present when `origin.enabled`. */
  readonly originSecret: string | undefined;
}

export interface RuntimeOptions {
  /** The build-time compiled central configuration. */
  readonly config: CentralConfig;
  /** Platform environment: Workers bindings, `process.env`, and so on. String values are read. */
  readonly env: Readonly<Record<string, unknown>>;
  readonly fetch: FetchLike;
  readonly revocation: RevocationStrategy;
  /** Defaults to reading secrets from `env`. */
  readonly secrets?: SecretSource;
  /** Advanced overrides, mainly for tests (retry timing, clock, audit sinks). */
  readonly gate?: Partial<Omit<GateOptions, "config" | "secrets" | "fetch" | "revocation">>;
}

/** Keeps only string values: Workers env mixes secrets and vars with binding objects. */
function stringEnv(env: Readonly<Record<string, unknown>>): Record<string, string | undefined> {
  const strings: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === "string") {
      strings[key] = value;
    }
  }
  return strings;
}

/** Secrets injected as environment variables (Worker secrets, Kubernetes secrets, Vercel env). */
function envSecrets(env: Readonly<Record<string, unknown>>): SecretSource {
  const strings = stringEnv(env);
  return { get: (name) => Promise.resolve(strings[name]) };
}

export async function buildRuntime(options: RuntimeOptions): Promise<Runtime> {
  const config = applyEnvOverrides(options.config, stringEnv(options.env));
  const logger =
    options.gate?.logger ??
    createLogger({ level: config.logger.level, format: config.logger.format });
  const secrets = options.secrets ?? envSecrets(options.env);

  let originSecret: string | undefined;
  if (config.origin.enabled) {
    originSecret = await secrets.get(config.origin.header_value_secret);
    if (!originSecret) {
      throw new ConfigError([
        `origin.header_value_secret: secret "${config.origin.header_value_secret}" is not set`,
      ]);
    }
  }

  const gate = await createGate({
    ...options.gate,
    config,
    secrets,
    fetch: options.fetch,
    revocation: options.revocation,
    logger,
  });
  logger.info("gate initialized", {
    apps: config.github_apps.length,
    providers: config.policy.providers.map((provider) => provider.issuer),
    origin_verification: config.origin.enabled,
  });
  return { gate, logger, originSecret };
}

/**
 * Builds the runtime once and shares it, retrying on the next call if
 * initialization failed (for example while a secret is being provisioned).
 */
export function memoizeRuntime(factory: () => Promise<Runtime>): () => Promise<Runtime> {
  let pending: Promise<Runtime> | undefined;
  return () => {
    pending ??= factory().catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
    return pending;
  };
}
