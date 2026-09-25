export type Claims = Readonly<Record<string, unknown>>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Resolves a claim by name. A dotted name such as `app_metadata.preferences.theme`
 * walks nested objects, but a literal top-level key always wins so flat claims
 * containing dots are unaffected. Matches upstream `lookupClaim`.
 */
export function lookupClaim(claims: Claims, name: string): unknown {
  if (Object.hasOwn(claims, name)) {
    return claims[name];
  }
  let current: unknown = claims;
  for (const segment of name.split(".")) {
    if (!isRecord(current) || !Object.hasOwn(current, segment)) {
      return undefined;
    }
    current = current[segment];
  }
  return current;
}

/** Returns the claim only when it is present and a string, like upstream `claimString`. */
export function claimString(claims: Claims, name: string): string | undefined {
  const value = lookupClaim(claims, name);
  return typeof value === "string" ? value : undefined;
}
