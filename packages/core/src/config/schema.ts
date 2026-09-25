/**
 * Central configuration schema. Mirrors upstream `internal/config/*.go`
 * (same keys, defaults, and error messages) with these differences:
 *
 * - Secrets are never stored in the file. Fields ending in `_secret` name the
 *   secret that the runtime resolves (`private_key_secret` replaces upstream's
 *   `private_key_path`; `origin.header_value_secret` replaces `header_value`).
 * - Unknown keys are errors, so typos fail the build instead of being ignored.
 * - `server`, `aws_region`, `fips`, and `otel` are accepted and ignored.
 * - Only the log audit backend and the memory selector exist in this build.
 */
import { z } from "zod";
import { PERMISSION_LEVELS } from "../authorizer/permission-levels.ts";
import { patternError } from "../util/regex.ts";

const requiredString = (message: string) =>
  z.string({ error: (issue) => (issue.input === undefined ? message : undefined) }).min(1, message);

const permissionLevel = z.enum(PERMISSION_LEVELS, {
  error: (issue) =>
    `invalid permission level ${JSON.stringify(issue.input)} (must be none, read, or write)`,
});

const WEEKDAYS = [
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
] as const;

const hour = (message: string) => z.int(message).min(0, message).max(23, message);

/** A claim pattern: a plain RE2 string, or `{ pattern, description }` as in upstream's README. */
const claimPattern = z
  .union([z.string(), z.strictObject({ pattern: z.string(), description: z.string().optional() })])
  .transform((value) => (typeof value === "string" ? value : value.pattern));

const claimPatterns = z
  .record(z.string(), claimPattern)
  .default({})
  .superRefine((patterns, context) => {
    for (const [claim, pattern] of Object.entries(patterns)) {
      const problem = patternError(pattern);
      if (problem !== undefined) {
        context.addIssue({
          code: "custom",
          path: [claim],
          message: `invalid claim pattern for ${JSON.stringify(claim)}: ${problem}`,
        });
      }
    }
  });

const providerSchema = z.strictObject({
  issuer: requiredString("provider issuer is required"),
  name: requiredString("provider name is required"),
  required_claims: claimPatterns,
  forbidden_claims: claimPatterns,
  time_restrictions: z
    .strictObject({
      allowed_days: z.array(z.enum(WEEKDAYS, { error: "invalid allowed days" })).default([]),
      allowed_hours: z
        .strictObject({
          start: hour("start hour must be 0-23"),
          end: hour("end hour must be 0-23"),
        })
        .optional(),
    })
    .optional(),
});

const policySchema = z
  .strictObject({
    version: z.literal("1.0", { error: "invalid policy version" }).default("1.0"),
    trust_policy_path: requiredString("trust policy path is required"),
    default_token_ttl: z.int().positive("default token TTL must be positive").default(900),
    max_token_ttl: z.int().positive("max token TTL must be positive").default(3600),
    require_explicit_policy: z.boolean().default(false),
    github_api_base_url: z
      .url({ protocol: /^https?$/, error: "github_api_base_url must be an http(s) URL" })
      .default("https://api.github.com"),
    /** Accepted for upstream compatibility; unused, as upstream never reads it either. */
    github_raw_base_url: z.string().optional(),
    providers: z.array(providerSchema).min(1, "at least one provider is required"),
    max_permissions: z.record(z.string(), permissionLevel).default({}),
  })
  .superRefine((policy, context) => {
    if (policy.default_token_ttl > policy.max_token_ttl) {
      context.addIssue({
        code: "custom",
        path: ["default_token_ttl"],
        message: "default token TTL must be less than or equal to max token TTL",
      });
    }
    const seen = new Set<string>();
    policy.providers.forEach((provider, index) => {
      if (seen.has(provider.issuer)) {
        context.addIssue({
          code: "custom",
          path: ["providers", index, "issuer"],
          message: `duplicate provider issuer: ${provider.issuer}`,
        });
      }
      seen.add(provider.issuer);
    });
  });

const githubAppSchema = z
  .strictObject({
    client_id: requiredString("client_id is required"),
    organization: requiredString("organization is required"),
    private_key_secret: z.string().optional(),
    /** Upstream's field; rejected with a migration hint because secrets never live in config. */
    private_key_path: z.unknown().optional(),
  })
  .transform((app, context) => {
    if (app.private_key_path !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["private_key_path"],
        message:
          "private_key_path is not supported; store the PEM in a secret and name it with private_key_secret",
      });
      return z.NEVER;
    }
    if (!app.private_key_secret) {
      context.addIssue({
        code: "custom",
        path: ["private_key_secret"],
        message: "private_key_secret is required",
      });
      return z.NEVER;
    }
    return {
      client_id: app.client_id,
      organization: app.organization,
      private_key_secret: app.private_key_secret,
    };
  });

const originSchema = z
  .strictObject({
    enabled: z.boolean().default(false),
    header_name: z.string().optional(),
    header_value_secret: z.string().min(1).default("GATE_ORIGIN_HEADER_VALUE"),
    header_value: z.unknown().optional(),
  })
  .superRefine((origin, context) => {
    if (origin.header_value !== undefined) {
      context.addIssue({
        code: "custom",
        path: ["header_value"],
        message:
          "header_value must not be stored in config; put it in the secret named by header_value_secret",
      });
    }
    if (origin.enabled && !origin.header_name) {
      context.addIssue({
        code: "custom",
        path: ["header_name"],
        message: "origin header name is required",
      });
    }
  })
  .transform(({ header_value: _ignored, ...origin }) => origin);

const SUPPORTED_AUDIT_BACKENDS = ["", "log"];
const auditSchema = z
  .strictObject({ backend: z.string().default("log") })
  .superRefine((audit, context) => {
    if (!SUPPORTED_AUDIT_BACKENDS.includes(audit.backend)) {
      context.addIssue({
        code: "custom",
        path: ["backend"],
        message: `audit backend ${JSON.stringify(audit.backend)} is not supported in this build; use "log" (object-store sink is planned)`,
      });
    }
  });

const selectorSchema = z
  .strictObject({ type: z.string().default("memory") })
  .superRefine((selector, context) => {
    if (selector.type !== "memory") {
      context.addIssue({
        code: "custom",
        path: ["type"],
        message: `selector type ${JSON.stringify(selector.type)} is not supported in this build; use "memory"`,
      });
    }
  });

/** Top-level keys upstream supports that have no meaning on these runtimes. */
export const IGNORED_TOP_LEVEL_KEYS = ["server", "aws_region", "fips", "otel"] as const;

export const centralConfigSchema = z
  .strictObject({
    logger: z
      .strictObject({
        level: z.enum(["debug", "info", "warn", "error"]).default("info"),
        format: z.enum(["json", "text"]).default("json"),
      })
      .prefault({}),
    oidc: z
      .strictObject({ audience: requiredString("invalid OIDC audience").default("gate") })
      .prefault({}),
    policy: policySchema,
    origin: originSchema.prefault({}),
    audit: auditSchema.prefault({}),
    selector: selectorSchema.prefault({}),
    revocation: z
      .strictObject({ key_secret: z.string().min(1).default("GATE_REVOCATION_KEYS") })
      .prefault({}),
    github_apps: z
      .array(githubAppSchema)
      .min(1, "at least one GitHub app is required")
      .superRefine((apps, context) => {
        const seen = new Set<string>();
        apps.forEach((app, index) => {
          if (seen.has(app.client_id)) {
            context.addIssue({
              code: "custom",
              path: [index, "client_id"],
              message: `duplicate client_id: ${app.client_id}`,
            });
          }
          seen.add(app.client_id);
        });
      }),
    server: z.unknown().optional(),
    aws_region: z.unknown().optional(),
    fips: z.unknown().optional(),
    otel: z.unknown().optional(),
  })
  .transform(({ server: _s, aws_region: _a, fips: _f, otel: _o, ...config }) => config);

/** Validated, normalized central configuration. */
export type CentralConfig = z.output<typeof centralConfigSchema>;
export type ProviderConfig = CentralConfig["policy"]["providers"][number];
export type GitHubAppConfig = CentralConfig["github_apps"][number];
