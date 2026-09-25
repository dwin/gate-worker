import type { ActionIO } from "./io.ts";

const LEVELS = new Set(["none", "read", "write"]);
const REPOSITORY = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

export interface ActionInputs {
  readonly endpoint: string;
  readonly repository: string;
  readonly policyName: string | undefined;
  readonly permissions: Readonly<Record<string, string>> | undefined;
  readonly ttl: number | undefined;
  readonly audience: string;
  readonly apiUrl: string;
  readonly originHeader: { readonly name: string; readonly value: string } | undefined;
  readonly revokeOnCompletion: boolean;
  readonly timeoutMs: number;
}

export class InputError extends Error {
  override name = "InputError";
}

/** Parses `key: level` lines (YAML-style) or a JSON object. */
export function parsePermissions(raw: string): Record<string, string> | undefined {
  const text = raw.trim();
  if (!text) {
    return undefined;
  }
  let entries: [string, unknown][];
  if (text.startsWith("{")) {
    try {
      entries = Object.entries(JSON.parse(text) as Record<string, unknown>);
    } catch {
      throw new InputError("permissions: invalid JSON");
    }
  } else {
    entries = text
      .split(/\r?\n/)
      .map((line) => line.replace(/#.*$/, "").trim())
      .filter(Boolean)
      .map((line) => {
        const match = /^([a-z_]+)\s*:\s*([a-z]+)$/.exec(line);
        if (!match?.[1] || !match[2]) {
          throw new InputError(`permissions: expected "name: level", got "${line}"`);
        }
        return [match[1], match[2]];
      });
  }
  const permissions: Record<string, string> = {};
  for (const [name, level] of entries) {
    if (typeof level !== "string" || !LEVELS.has(level)) {
      throw new InputError(`permissions: ${name} must be none, read, or write`);
    }
    permissions[name] = level;
  }
  return permissions;
}

function positiveInteger(name: string, raw: string): number | undefined {
  if (!raw.trim()) {
    return undefined;
  }
  if (!/^\d+$/.test(raw.trim()) || Number(raw) <= 0) {
    throw new InputError(`${name}: expected a positive integer, got "${raw}"`);
  }
  return Number(raw);
}

export function readInputs(io: ActionIO): ActionInputs {
  const endpoint = io.getInput("endpoint").trim().replace(/\/+$/, "");
  if (!/^https?:\/\//.test(endpoint)) {
    throw new InputError("endpoint: expected an http(s) URL");
  }
  if (
    endpoint.startsWith("http://") &&
    !/^http:\/\/(localhost|127\.0\.0\.1)(:|\/|$)/.test(endpoint)
  ) {
    throw new InputError("endpoint: must use https (tokens would cross the network in plaintext)");
  }
  const repository = io.getInput("repository").trim();
  if (!REPOSITORY.test(repository)) {
    throw new InputError(`repository: expected owner/repo, got "${repository}"`);
  }
  const originName = io.getInput("origin-header-name").trim();
  const originValue = io.getInput("origin-header-value");
  if (Boolean(originName) !== Boolean(originValue)) {
    throw new InputError("origin-header-name and origin-header-value must be set together");
  }
  const revoke = io.getInput("revoke-on-completion").trim().toLowerCase();
  if (!["", "true", "false"].includes(revoke)) {
    throw new InputError("revoke-on-completion: expected true or false");
  }
  return {
    endpoint,
    repository,
    policyName: io.getInput("policy-name").trim() || undefined,
    permissions: parsePermissions(io.getInput("permissions")),
    ttl: positiveInteger("ttl", io.getInput("ttl")),
    audience: io.getInput("audience").trim() || "gate",
    apiUrl: (io.getInput("api-url").trim() || "https://api.github.com").replace(/\/+$/, ""),
    originHeader: originName ? { name: originName, value: originValue } : undefined,
    revokeOnCompletion: revoke !== "false",
    timeoutMs: (positiveInteger("timeout", io.getInput("timeout")) ?? 60) * 1000,
  };
}
