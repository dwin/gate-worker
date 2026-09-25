import { RE2JS } from "re2js";

/**
 * A compiled RE2 pattern. RE2 guarantees linear-time matching, which matters
 * because trust-policy patterns are authored by repository owners. RE2 syntax
 * also matches upstream's Go `regexp`, so policies behave identically.
 */
export interface Pattern {
  readonly source: string;
  /** Unanchored search, like Go's `regexp.MatchString`. */
  test(value: string): boolean;
}

export function compilePattern(source: string): Pattern {
  const compiled = RE2JS.compile(source);
  return { source, test: (value) => compiled.test(value) };
}

/** Returns an error message when `source` is not a valid RE2 pattern. */
export function patternError(source: string): string | undefined {
  try {
    RE2JS.compile(source);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}
