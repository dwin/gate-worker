import { z } from "zod";

/**
 * A pending revocation. The installation token itself is sealed with
 * AES-256-GCM; everything else is plaintext metadata bound into the
 * ciphertext as additional authenticated data.
 */
export const revocationJobSchema = z.strictObject({
  v: z.literal(1),
  /** `sha256:<hex>` of the token, for logs and audit correlation. */
  token_hash: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  github_client_id: z.string().min(1),
  /** Unix seconds at which the token's capped TTL ends. */
  expires_at: z.int().nonnegative(),
  kid: z.string().regex(/^[A-Za-z0-9_-]{1,32}$/),
  iv: z.string().min(1),
  ciphertext: z.string().min(1),
});

export type RevocationJob = z.infer<typeof revocationJobSchema>;
