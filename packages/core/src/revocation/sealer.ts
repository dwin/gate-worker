import { ConfigError } from "../config/errors.ts";
import {
  base64Decode,
  base64UrlDecode,
  base64UrlEncode,
  utf8Decode,
  utf8Encode,
} from "../util/encoding.ts";
import { hashToken } from "../util/hash.ts";
import type { RevocationJob } from "./job.ts";

const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,32}$/;
const IV_BYTES = 12;

export interface SealInput {
  readonly token: string;
  readonly tokenHash: string;
  readonly githubClientId: string;
  readonly expiresAt: number;
}

function additionalData(job: Omit<RevocationJob, "iv" | "ciphertext">): Uint8Array<ArrayBuffer> {
  return utf8Encode(
    [
      "gate/revocation",
      String(job.v),
      job.kid,
      job.token_hash,
      job.github_client_id,
      String(job.expires_at),
    ].join("|"),
  );
}

async function importKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

/**
 * Encrypts installation tokens that must be held until revocation.
 *
 * `DELETE /installation/token` authenticates with the token itself, so any
 * durable revocation design has to store it. Sealing keeps the token opaque to
 * anyone who can read the queue or store; the metadata stays readable for
 * operations but cannot be altered or swapped between jobs without detection.
 *
 * Keys come from one secret: comma-separated `kid:base64(32 bytes)` entries.
 * The first entry seals new jobs; every entry can open, which allows rotation.
 */
export class TokenSealer {
  readonly #current: string;
  readonly #keys: ReadonlyMap<string, CryptoKey>;

  private constructor(current: string, keys: ReadonlyMap<string, CryptoKey>) {
    this.#current = current;
    this.#keys = keys;
  }

  /** Parses `kid:base64key[,kid:base64key...]`. */
  static async fromSecret(value: string, label: string): Promise<TokenSealer> {
    const entries = value
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (entries.length === 0) {
      throw new ConfigError([`${label}: expected "kid:base64key[,kid:base64key...]"`]);
    }
    const keys = new Map<string, CryptoKey>();
    const problems: string[] = [];
    for (const entry of entries) {
      const separator = entry.indexOf(":");
      const kid = entry.slice(0, separator);
      if (separator <= 0 || !KEY_ID_PATTERN.test(kid)) {
        problems.push(
          `${label}: each entry must be "kid:base64key" with kid matching ${KEY_ID_PATTERN.source}`,
        );
        continue;
      }
      let raw: Uint8Array<ArrayBuffer>;
      try {
        raw = base64Decode(entry.slice(separator + 1));
      } catch {
        problems.push(`${label}: key "${kid}" is not valid base64`);
        continue;
      }
      if (raw.length !== 32) {
        problems.push(
          `${label}: key "${kid}" must be 32 bytes (AES-256), got ${String(raw.length)}`,
        );
        continue;
      }
      if (keys.has(kid)) {
        problems.push(`${label}: duplicate key id "${kid}"`);
        continue;
      }
      keys.set(kid, await importKey(raw));
    }
    const current = entries[0]?.split(":", 1)[0];
    if (problems.length > 0 || current === undefined) {
      throw new ConfigError(problems);
    }
    return new TokenSealer(current, keys);
  }

  /**
   * A random, non-extractable key that lives only in this process. Suitable
   * only when jobs never leave the process (the in-memory timer scheduler).
   */
  static async ephemeral(): Promise<TokenSealer> {
    // importKey (unlike generateKey) has the same return type in every runtime's typings.
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const key = await importKey(raw);
    raw.fill(0);
    return new TokenSealer("ephemeral", new Map([["ephemeral", key]]));
  }

  async seal(input: SealInput): Promise<RevocationJob> {
    const key = this.#keys.get(this.#current);
    if (!key) {
      throw new Error(`missing sealing key ${this.#current}`);
    }
    const metadata = {
      v: 1 as const,
      token_hash: input.tokenHash,
      github_client_id: input.githubClientId,
      expires_at: input.expiresAt,
      kid: this.#current,
    };
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: additionalData(metadata) },
      key,
      utf8Encode(input.token),
    );
    return {
      ...metadata,
      iv: base64UrlEncode(iv),
      ciphertext: base64UrlEncode(new Uint8Array(ciphertext)),
    };
  }

  /** Decrypts a job's token. Throws if the key is unknown or anything was altered. */
  async open(job: RevocationJob): Promise<string> {
    const key = this.#keys.get(job.kid);
    if (!key) {
      throw new Error(`unknown revocation key id: ${job.kid}`);
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlDecode(job.iv), additionalData: additionalData(job) },
      key,
      base64UrlDecode(job.ciphertext),
    );
    const token = utf8Decode(new Uint8Array(plaintext));
    if ((await hashToken(token)) !== job.token_hash) {
      throw new Error("revocation job token does not match its hash");
    }
    return token;
  }
}
