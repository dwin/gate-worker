import { readFileSync } from "node:fs";

const FIXTURES = new URL("../fixtures/policies/", import.meta.url);

/**
 * Loads an upstream trust-policy fixture, substituting `{{ISSUER_URL}}` as
 * upstream's `LoadTemplate` does.
 */
export function loadPolicyFixture(name: string, issuer?: string): string {
  const content = readFileSync(new URL(name, FIXTURES), "utf8");
  return issuer === undefined ? content : content.replaceAll("{{ISSUER_URL}}", issuer);
}
