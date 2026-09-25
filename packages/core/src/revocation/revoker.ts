import type { GitHubAppClient } from "../github/client.ts";
import type { Logger } from "../ports/index.ts";
import { revocationJobSchema, type RevocationJob } from "./job.ts";
import type { TokenSealer } from "./sealer.ts";

/** Opens sealed revocation jobs and revokes the tokens at GitHub. */
export class Revoker {
  readonly #sealer: TokenSealer;
  readonly #clients: ReadonlyMap<string, GitHubAppClient>;
  readonly #logger: Logger;

  constructor(sealer: TokenSealer, clients: ReadonlyMap<string, GitHubAppClient>, logger: Logger) {
    this.#sealer = sealer;
    this.#clients = clients;
    this.#logger = logger;
  }

  /** Validates an untrusted payload (for example a queue message body) as a job. */
  static parseJob(payload: unknown): RevocationJob {
    return revocationJobSchema.parse(payload);
  }

  async revoke(job: RevocationJob): Promise<void> {
    const token = await this.#sealer.open(job);
    // DELETE /installation/token authenticates with the token itself, so any
    // client can send it; prefer the App that minted the token.
    const client = this.#clients.get(job.github_client_id) ?? this.#clients.values().next().value;
    if (!client) {
      throw new Error("no GitHub client configured");
    }
    await client.revokeToken(token);
    this.#logger.info("token revoked", {
      token_hash: job.token_hash,
      github_client_id: job.github_client_id,
    });
  }
}
