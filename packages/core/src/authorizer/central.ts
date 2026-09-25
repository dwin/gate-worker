import type { ProviderConfig } from "../config/schema.ts";
import { compilePattern, type Pattern } from "../util/regex.ts";
import { claimString, type Claims } from "./claims.ts";
import { deny, DenialCode, type Denial } from "./denial.ts";

interface CompiledProvider {
  readonly config: ProviderConfig;
  readonly required: readonly (readonly [string, Pattern])[];
  readonly forbidden: readonly (readonly [string, Pattern])[];
}

const WEEKDAY_NAMES = [
  "Sunday",
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
] as const;

/** Hour windows are inclusive and may wrap past midnight (start > end). */
function isHourAllowed(hour: number, start: number, end: number): boolean {
  return start <= end ? hour >= start && hour <= end : hour >= start || hour <= end;
}

/**
 * Layer 1: organization-wide rules from the central config. Checks the issuer
 * allowlist, required and forbidden claim patterns, and UTC time windows.
 */
export class CentralPolicy {
  readonly #providers: ReadonlyMap<string, CompiledProvider>;

  constructor(providers: readonly ProviderConfig[]) {
    this.#providers = new Map(
      providers.map((config) => [
        config.issuer,
        {
          config,
          required: Object.entries(config.required_claims).map(
            ([claim, source]) => [claim, compilePattern(source)] as const,
          ),
          forbidden: Object.entries(config.forbidden_claims).map(
            ([claim, source]) => [claim, compilePattern(source)] as const,
          ),
        },
      ]),
    );
  }

  evaluate(issuer: string, claims: Claims, now: Date): Denial | undefined {
    const provider = this.#providers.get(issuer);
    if (!provider) {
      return deny(DenialCode.IssuerNotAllowed, "issuer not in allowed list", `issuer: ${issuer}`);
    }

    for (const [name, pattern] of provider.required) {
      const value = claimString(claims, name);
      if (value === undefined) {
        return deny(
          DenialCode.RequiredClaimMismatch,
          `required claim "${name}" not present or not a string`,
        );
      }
      if (!pattern.test(value)) {
        return deny(
          DenialCode.RequiredClaimMismatch,
          `required claim "${name}" does not match pattern`,
          `expected: ${pattern.source}, got: ${value}`,
        );
      }
    }

    for (const [name, pattern] of provider.forbidden) {
      const value = claimString(claims, name);
      if (value !== undefined && pattern.test(value)) {
        return deny(
          DenialCode.ForbiddenClaimMatched,
          `forbidden claim "${name}" matches pattern`,
          `pattern: ${pattern.source}, value: ${value}`,
        );
      }
    }

    const restrictions = provider.config.time_restrictions;
    if (restrictions) {
      const day = WEEKDAY_NAMES[now.getUTCDay()] ?? "";
      if (
        restrictions.allowed_days.length > 0 &&
        !restrictions.allowed_days.some((allowed) => allowed.toLowerCase() === day.toLowerCase())
      ) {
        return deny(DenialCode.TimeRestriction, "current day is not allowed", `current: ${day}`);
      }
      const hours = restrictions.allowed_hours;
      const hour = now.getUTCHours();
      if (hours && !isHourAllowed(hour, hours.start, hours.end)) {
        return deny(
          DenialCode.TimeRestriction,
          "current hour is not allowed",
          `allowed: ${String(hours.start)}-${String(hours.end)}, current: ${String(hour)} UTC`,
        );
      }
    }
    return undefined;
  }
}
