/**
 * Trust-policy file schema (version 1.0), authored by repository owners and
 * fetched at runtime. Validation rules and messages follow upstream
 * `internal/sts/authorizer/policy.go`. Every condition pattern is compiled with
 * RE2 during validation, so a stored policy can never hold an invalid regex.
 */
import { parse as parseYaml } from "yaml";
import { z } from "zod";
import { compilePattern, type Pattern } from "../util/regex.ts";
import { isPermissionLevel, type Permissions } from "./permission-levels.ts";

const requiredString = (message: string) =>
  z.string({ error: (issue) => (issue.input === undefined ? message : undefined) }).min(1, message);

const requiredArray = <T extends z.ZodType>(item: T, message: string) =>
  z
    .array(item, { error: (issue) => (issue.input === undefined ? message : undefined) })
    .min(1, message);

/** YAML is parsed with the failsafe schema, so integers arrive as strings. */
const integer = z
  .union([z.int(), z.string().regex(/^\d+$/, "must be a non-negative integer")])
  .transform(Number);

const conditionSchema = z
  .object({
    field: requiredString("field is required"),
    pattern: requiredString("pattern is required"),
  })
  .transform((condition, context) => {
    try {
      return { field: condition.field, pattern: compilePattern(condition.pattern) };
    } catch (error) {
      context.addIssue({
        code: "custom",
        path: ["pattern"],
        message: `invalid pattern ${JSON.stringify(condition.pattern)}: ${error instanceof Error ? error.message : String(error)}`,
      });
      return z.NEVER;
    }
  });

const ruleSchema = z.object({
  name: requiredString("name is required"),
  logic: z
    .string()
    .optional()
    .transform((logic, context) => {
      const normalized = logic === undefined || logic === "" ? "AND" : logic;
      if (normalized !== "AND" && normalized !== "OR") {
        context.addIssue({
          code: "custom",
          message: `logic must be AND or OR, got "${normalized}"`,
        });
        return z.NEVER;
      }
      return normalized;
    }),
  conditions: requiredArray(conditionSchema, "at least one condition is required"),
});

const permissionsSchema = z
  .record(z.string(), z.string(), {
    error: (issue) =>
      issue.input === undefined ? "at least one permission is required" : undefined,
  })
  .transform((permissions, context) => {
    const entries = Object.entries(permissions);
    if (entries.length === 0) {
      context.addIssue({ code: "custom", message: "at least one permission is required" });
      return z.NEVER;
    }
    for (const [permission, level] of entries) {
      if (!isPermissionLevel(level)) {
        context.addIssue({
          code: "custom",
          path: [permission],
          message: `permission "${permission}" has invalid level "${level}"`,
        });
      }
    }
    return permissions as Permissions;
  });

const trustPolicySchema = z.object({
  name: requiredString("name is required"),
  description: z.string().optional(),
  issuer: requiredString("issuer is required"),
  rules: requiredArray(ruleSchema, "at least one rule is required"),
  permissions: permissionsSchema,
  token_ttl: integer.optional(),
});

const trustPolicyFileSchema = z
  .object({
    version: z
      .string({ error: (issue) => (issue.input === undefined ? "version is required" : undefined) })
      .transform((version, context) => {
        if (version === "") {
          context.addIssue({ code: "custom", message: "version is required" });
          return z.NEVER;
        }
        if (version !== "1.0") {
          context.addIssue({
            code: "custom",
            message: `unsupported trust policy version: ${version} (expected 1.0)`,
          });
          return z.NEVER;
        }
        return "1.0" as const;
      }),
    trust_policies: requiredArray(trustPolicySchema, "at least one trust policy is required"),
  })
  .superRefine((file, context) => {
    const seen = new Set<string>();
    for (const policy of file.trust_policies) {
      if (seen.has(policy.name)) {
        context.addIssue({ code: "custom", message: `duplicate policy name: ${policy.name}` });
      }
      seen.add(policy.name);
    }
  });

export interface Condition {
  readonly field: string;
  readonly pattern: Pattern;
}

export interface PolicyRule {
  readonly name: string;
  readonly logic: "AND" | "OR";
  readonly conditions: readonly Condition[];
}

export interface TrustPolicy {
  readonly name: string;
  readonly description?: string | undefined;
  readonly issuer: string;
  readonly rules: readonly PolicyRule[];
  readonly permissions: Permissions;
  readonly token_ttl?: number | undefined;
}

export interface TrustPolicyFile {
  readonly version: "1.0";
  readonly trust_policies: readonly TrustPolicy[];
}

/** Raised when a trust-policy file cannot be parsed or fails validation. */
export class TrustPolicyError extends Error {
  readonly issues: readonly string[];

  constructor(issues: readonly string[]) {
    super(`invalid trust policy: ${issues.join("; ")}`);
    this.name = "TrustPolicyError";
    this.issues = issues;
  }
}

const PATH_LABELS: Readonly<Record<string, string>> = {
  trust_policies: "policy",
  rules: "rule",
  conditions: "condition",
};

function nameOf(node: unknown): string {
  if (node !== null && typeof node === "object" && "name" in node) {
    const { name } = node;
    return typeof name === "string" ? name : "";
  }
  return "";
}

/** Formats a zod path the way upstream wraps errors: `policy 0 (name): rule 1 (name): condition 0`. */
function describePath(raw: unknown, path: readonly PropertyKey[]): string[] {
  const parts: string[] = [];
  let node: unknown = raw;
  for (const [position, key] of path.entries()) {
    const container = node;
    node =
      container !== null && typeof container === "object"
        ? (container as Record<PropertyKey, unknown>)[key]
        : undefined;
    if (typeof key !== "number") {
      continue;
    }
    const previous = path[position - 1];
    const label = typeof previous === "string" ? PATH_LABELS[previous] : undefined;
    if (label === "condition") {
      parts.push(`${label} ${String(key)}`);
    } else if (label) {
      parts.push(`${label} ${String(key)} (${nameOf(node)})`);
    }
  }
  return parts;
}

/** Parses and validates a trust-policy YAML document. */
export function parseTrustPolicy(yamlText: string): TrustPolicyFile {
  let raw: unknown;
  try {
    // The failsafe schema keeps every scalar a string, as Go's yaml.v3 does when
    // decoding into string fields, so `version: 1.0` stays "1.0" rather than 1.
    raw = parseYaml(yamlText, { schema: "failsafe", uniqueKeys: true });
  } catch (error) {
    throw new TrustPolicyError([
      `parsing YAML: ${error instanceof Error ? error.message : String(error)}`,
    ]);
  }
  const result = trustPolicyFileSchema.safeParse(raw ?? {});
  if (!result.success) {
    throw new TrustPolicyError(
      result.error.issues.map((issue) =>
        [...describePath(raw, issue.path), issue.message].join(": "),
      ),
    );
  }
  return result.data;
}

/** JSON Schema for trust-policy files, so repositories can lint them in their own CI. */
export function trustPolicyJsonSchema(): Record<string, unknown> {
  return z.toJSONSchema(trustPolicyFileSchema, { io: "input", unrepresentable: "any" });
}
