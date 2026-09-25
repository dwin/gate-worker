import { hexEncode, utf8Encode } from "./encoding.ts";

/**
 * Returns the SHA-256 hex digest of `value` prefixed with `sha256:`, matching
 * upstream's `utils.HashString`. Used to reference tokens in logs and audit.
 */
export async function hashToken(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8Encode(value));
  return `sha256:${hexEncode(new Uint8Array(digest))}`;
}
