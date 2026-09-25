import type { Permissions } from "../authorizer/permission-levels.ts";

export type AuditOutcome = "granted" | "denied";

/** One token-exchange attempt. Same fields as upstream `audit.AuditEntry`. */
export interface AuditEntry {
  readonly request_id: string;
  /** Unix seconds. */
  readonly timestamp: number;
  readonly caller: string;
  readonly claims?: Readonly<Record<string, string>>;
  readonly target_repository: string;
  readonly policy_name: string;
  readonly permissions?: Permissions;
  readonly outcome: AuditOutcome;
  readonly deny_reason?: string;
  readonly token_hash?: string;
  readonly ttl?: number;
  readonly github_client_id?: string;
}

/** Returns the first validation problem, using upstream's messages, or undefined. */
export function auditEntryProblem(entry: AuditEntry): string | undefined {
  if (!entry.request_id) return "request_id is required";
  if (!entry.timestamp) return "timestamp is required";
  if (!entry.caller) return "caller is required";
  if (!entry.target_repository) return "target_repository is required";
  if (entry.outcome === "denied") {
    return entry.deny_reason ? undefined : "deny_reason is required when outcome is denied";
  }
  if (!entry.token_hash) return "token_hash is required when outcome is granted";
  if (!entry.ttl || entry.ttl <= 0) return "ttl must be positive when outcome is granted";
  if (!entry.policy_name) return "policy_name is required when outcome is granted";
  if (!entry.github_client_id) return "github_client_id is required when outcome is granted";
  return undefined;
}
