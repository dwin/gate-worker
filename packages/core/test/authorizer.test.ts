import { describe, expect, it } from "vitest";
import {
  CentralPolicy,
  lookupClaim,
  matchAutomatic,
  matchExplicit,
  NON_REPOSITORY_PERMISSIONS,
  parseTrustPolicy,
  resolvePermissions,
  resolveTtl,
  type ProviderConfig,
  type TrustPolicy,
} from "../src/index.ts";

const ISSUER = "https://token.actions.githubusercontent.com";

const provider = (overrides: Partial<ProviderConfig> = {}): ProviderConfig => ({
  issuer: ISSUER,
  name: "GitHub Actions",
  required_claims: {},
  forbidden_claims: {},
  ...overrides,
});

describe("lookupClaim", () => {
  const claims = {
    repository: "a/b",
    "flat.key": "flat",
    app_metadata: { preferences: { theme: "dark" } },
    flat: { key: "nested" },
  };

  it("walks dotted paths into nested objects", () => {
    expect(lookupClaim(claims, "app_metadata.preferences.theme")).toBe("dark");
  });

  it("prefers a literal top-level key over path traversal", () => {
    expect(lookupClaim(claims, "flat.key")).toBe("flat");
  });

  it("returns undefined for missing paths and non-object segments", () => {
    expect(lookupClaim(claims, "app_metadata.missing.theme")).toBeUndefined();
    expect(lookupClaim(claims, "repository.length")).toBeUndefined();
  });
});

describe("CentralPolicy", () => {
  const monday10 = new Date("2026-09-21T10:00:00Z");

  it("denies issuers that are not configured", () => {
    expect(new CentralPolicy([provider()]).evaluate("https://evil.test", {}, monday10)?.code).toBe(
      "ISSUER_NOT_ALLOWED",
    );
  });

  it("enforces required claims", () => {
    const policy = new CentralPolicy([
      provider({ required_claims: { repository_owner: "^example-org$" } }),
    ]);
    expect(policy.evaluate(ISSUER, { repository_owner: "example-org" }, monday10)).toBeUndefined();
    expect(policy.evaluate(ISSUER, { repository_owner: "other" }, monday10)).toMatchObject({
      code: "REQUIRED_CLAIM_MISMATCH",
      details: "expected: ^example-org$, got: other",
    });
    expect(policy.evaluate(ISSUER, {}, monday10)?.message).toBe(
      'required claim "repository_owner" not present or not a string',
    );
  });

  it("enforces forbidden claims only when present", () => {
    const policy = new CentralPolicy([provider({ forbidden_claims: { actor: "^dependabot" } })]);
    expect(policy.evaluate(ISSUER, {}, monday10)).toBeUndefined();
    expect(policy.evaluate(ISSUER, { actor: "dependabot[bot]" }, monday10)?.code).toBe(
      "FORBIDDEN_CLAIM_MATCHED",
    );
  });

  it("enforces allowed days and hour windows in UTC, including overnight windows", () => {
    const weekdays = new CentralPolicy([
      provider({
        time_restrictions: {
          allowed_days: ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
          allowed_hours: { start: 22, end: 6 },
        },
      }),
    ]);
    expect(weekdays.evaluate(ISSUER, {}, new Date("2026-09-21T23:00:00Z"))).toBeUndefined();
    expect(weekdays.evaluate(ISSUER, {}, new Date("2026-09-21T05:59:00Z"))).toBeUndefined();
    expect(weekdays.evaluate(ISSUER, {}, monday10)?.message).toBe("current hour is not allowed");
    expect(weekdays.evaluate(ISSUER, {}, new Date("2026-09-20T23:00:00Z"))?.message).toBe(
      "current day is not allowed",
    );
  });
});

const policyFile = parseTrustPolicy(`version: "1.0"
trust_policies:
  - name: readonly
    issuer: ${ISSUER}
    rules:
      - name: main
        conditions:
          - { field: repository, pattern: "^example-org/example-repo$" }
          - { field: ref, pattern: "^refs/heads/main$" }
    permissions: { contents: read, metadata: read }
  - name: readwrite
    issuer: ${ISSUER}
    rules:
      - name: any-branch
        logic: OR
        conditions:
          - { field: ref, pattern: "^refs/heads/main$" }
          - { field: ref, pattern: "^refs/heads/release/" }
    permissions: { contents: write, issues: write, metadata: read }
    token_ttl: 600
`);
const [readonly, readwrite] = policyFile.trust_policies as [TrustPolicy, TrustPolicy];
const mainClaims = { repository: "example-org/example-repo", ref: "refs/heads/main" };

describe("policy matching", () => {
  it("automatic matching returns the first matching policy in file order", () => {
    expect(matchAutomatic(policyFile, ISSUER, mainClaims)).toMatchObject({
      ok: true,
      policy: { name: "readonly" },
    });
    expect(matchAutomatic(policyFile, ISSUER, { ref: "refs/heads/release/v1" })).toMatchObject({
      ok: true,
      policy: { name: "readwrite" },
    });
  });

  it("AND needs every condition, OR needs one", () => {
    expect(
      matchAutomatic(policyFile, ISSUER, {
        repository: "example-org/example-repo",
        ref: "refs/heads/x",
      }),
    ).toMatchObject({
      ok: false,
      denial: { code: "NO_RULES_MATCHED" },
    });
  });

  it("skips policies for other issuers", () => {
    expect(matchAutomatic(policyFile, "https://other.test", mainClaims)).toMatchObject({
      ok: false,
    });
  });

  it("explicit matching distinguishes missing policy, issuer mismatch, and rule mismatch", () => {
    expect(matchExplicit(policyFile, "readwrite", ISSUER, mainClaims)).toMatchObject({ ok: true });
    expect(matchExplicit(policyFile, "ReadWrite", ISSUER, mainClaims)).toMatchObject({
      denial: { code: "POLICY_NOT_FOUND" },
    });
    expect(matchExplicit(policyFile, "readwrite", "https://other.test", mainClaims)).toMatchObject({
      denial: { code: "ISSUER_NOT_ALLOWED" },
    });
    expect(matchExplicit(policyFile, "readonly", ISSUER, { ref: "refs/heads/main" })).toMatchObject(
      {
        denial: { code: "NO_RULES_MATCHED" },
      },
    );
  });
});

describe("resolvePermissions", () => {
  const max = {
    contents: "write",
    issues: "read",
    metadata: "read",
    administration: "none",
  } as const;

  it("uses the policy's grant when nothing is requested", () => {
    expect(resolvePermissions(undefined, readonly, max)).toEqual({
      ok: true,
      permissions: { contents: "read", metadata: "read" },
    });
  });

  it("allows downgrades and subsets", () => {
    expect(resolvePermissions({ contents: "read" }, readwrite, max)).toEqual({
      ok: true,
      permissions: { contents: "read" },
    });
  });

  it.each([
    [{ issues: "write" }, readonly, "PERMISSION_NOT_IN_POLICY"],
    [{ contents: "write" }, readonly, "PERMISSION_EXCEEDS_POLICY"],
    [{ contents: "admin" }, readwrite, "PERMISSION_EXCEEDS_POLICY"],
    [{ issues: "write" }, readwrite, "PERMISSION_EXCEEDS_ORG_MAX"],
    [{ members: "read" }, readonly, "NON_REPOSITORY_PERMISSION"],
  ] as const)("%o on %s is denied with %s", (requested, policy, code) => {
    expect(resolvePermissions(requested, policy, max)).toMatchObject({
      ok: false,
      denial: { code },
    });
  });

  it("treats max_permissions as an allowlist, with none as an explicit deny", () => {
    const policy = parseTrustPolicy(`version: "1.0"
trust_policies:
  - name: p
    issuer: ${ISSUER}
    rules: [{ name: r, conditions: [{ field: ref, pattern: "." }] }]
    permissions: { packages: read, administration: write }
`).trust_policies[0]!;
    expect(resolvePermissions({ packages: "read" }, policy, max)).toMatchObject({
      denial: { code: "PERMISSION_NOT_IN_MAX_PERMISSIONS" },
    });
    expect(resolvePermissions({ administration: "read" }, policy, max)).toMatchObject({
      denial: { code: "PERMISSION_DENIED" },
    });
  });

  it("rejects every organization, user, and enterprise permission", () => {
    for (const permission of NON_REPOSITORY_PERMISSIONS.keys()) {
      expect(resolvePermissions({ [permission]: "read" }, readonly, max)).toMatchObject({
        denial: { code: "NON_REPOSITORY_PERMISSION" },
      });
    }
    expect(NON_REPOSITORY_PERMISSIONS.size).toBe(27);
  });
});

describe("resolveTtl", () => {
  it("uses the default, caps by the policy, then by the maximum", () => {
    expect(resolveTtl(0, readonly, 900, 3600)).toBe(900);
    expect(resolveTtl(1800, readonly, 900, 3600)).toBe(1800);
    expect(resolveTtl(1800, readwrite, 900, 3600)).toBe(600);
    expect(resolveTtl(0, readonly, 900, 600)).toBe(600);
  });
});
