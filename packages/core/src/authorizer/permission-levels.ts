export const PERMISSION_LEVELS = ["none", "read", "write"] as const;
export type PermissionLevel = (typeof PERMISSION_LEVELS)[number];
export type Permissions = Readonly<Record<string, PermissionLevel>>;

const LEVEL_RANK: Readonly<Record<PermissionLevel, number>> = { none: 0, read: 1, write: 2 };

export function isPermissionLevel(value: unknown): value is PermissionLevel {
  return typeof value === "string" && (PERMISSION_LEVELS as readonly string[]).includes(value);
}

/** True when `requested` is at or below `maximum` in the none < read < write order. */
export function isLevelAllowed(requested: PermissionLevel, maximum: PermissionLevel): boolean {
  return LEVEL_RANK[requested] <= LEVEL_RANK[maximum];
}
