import { MemoryCache } from "../adapters/memory/cache.ts";
import type { GitHubAppClient } from "../github/client.ts";
import {
  FileNotFoundError,
  InstallationNotFoundError,
  RepositoryNotFoundError,
} from "../github/errors.ts";
import type { Cache, Clock } from "../ports/index.ts";
import type { AppSelector } from "../selector/selector.ts";
import { SingleFlight } from "../util/single-flight.ts";
import { systemClock } from "../util/time.ts";
import { parseTrustPolicy, type TrustPolicyFile } from "./trust-policy.ts";

const POLICY_CACHE_TTL_MS = 5 * 60 * 1000;
const POLICY_CACHE_MAX_ENTRIES = 500;

export class PolicyFileNotFoundError extends Error {
  override name = "PolicyFileNotFoundError";
}

export class RepositoryNotAccessibleError extends Error {
  override name = "RepositoryNotAccessibleError";
}

/** Tries `.yaml` then `.yml` unless the path already names one of them. */
export function extensionVariants(path: string): string[] {
  return /\.ya?ml$/.test(path) ? [path] : [`${path}.yaml`, `${path}.yml`];
}

/**
 * Loads trust policies from target repositories through the GitHub App that
 * serves the repository's owner. Parsed policies are cached for 5 minutes
 * (500 entries) and concurrent loads of the same file share one fetch.
 */
export class PolicyLoader {
  readonly #pathTemplate: string;
  readonly #selector: AppSelector;
  readonly #clients: ReadonlyMap<string, GitHubAppClient>;
  readonly #cache: Cache<TrustPolicyFile>;
  readonly #flight = new SingleFlight<TrustPolicyFile>();

  constructor(
    pathTemplate: string,
    selector: AppSelector,
    clients: ReadonlyMap<string, GitHubAppClient>,
    clock: Clock = systemClock,
  ) {
    this.#pathTemplate = pathTemplate;
    this.#selector = selector;
    this.#clients = clients;
    this.#cache = new MemoryCache(POLICY_CACHE_MAX_ENTRIES, clock);
  }

  async load(repository: string): Promise<TrustPolicyFile> {
    const owner = repository.split("/", 1)[0] ?? "";
    const path = this.#pathTemplate.replaceAll("{org}", owner);
    const key = `${repository}:${path}`;
    const cached = this.#cache.get(key);
    if (cached) {
      return cached;
    }
    return this.#flight.run(key, async () => {
      const file = await this.#fetch(repository, path);
      this.#cache.set(key, file, POLICY_CACHE_TTL_MS);
      return file;
    });
  }

  async #fetch(repository: string, path: string): Promise<TrustPolicyFile> {
    const app = await this.#selector.select(repository);
    const client = this.#clients.get(app.clientId);
    if (!client) {
      throw new Error(`no GitHub client for app ${app.clientId}`);
    }
    const paths = extensionVariants(path);
    for (const candidate of paths) {
      let content: string;
      try {
        content = await client.getContents(repository, candidate);
      } catch (error) {
        if (error instanceof FileNotFoundError) {
          continue;
        }
        if (
          error instanceof RepositoryNotFoundError ||
          error instanceof InstallationNotFoundError
        ) {
          throw new RepositoryNotAccessibleError(
            `repository not found or not accessible: ${repository}`,
            {
              cause: error,
            },
          );
        }
        throw error;
      }
      return parseTrustPolicy(content);
    }
    throw new PolicyFileNotFoundError(`trust policy file not found at ${paths.join(", ")}`);
  }
}
