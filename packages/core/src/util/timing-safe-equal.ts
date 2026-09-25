import { utf8Encode } from "./encoding.ts";

/**
 * Compares two strings in time independent of where they differ and of their
 * lengths. Both inputs are hashed first so the loop always runs over 32 bytes.
 * Portable replacement for the Workers-only `crypto.subtle.timingSafeEqual`.
 */
export async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const [digestA, digestB] = await Promise.all([
    crypto.subtle.digest("SHA-256", utf8Encode(a)),
    crypto.subtle.digest("SHA-256", utf8Encode(b)),
  ]);
  const bytesA = new Uint8Array(digestA);
  const bytesB = new Uint8Array(digestB);
  let difference = 0;
  for (let index = 0; index < bytesA.length; index++) {
    difference |= (bytesA[index] ?? 0) ^ (bytesB[index] ?? 0);
  }
  return difference === 0;
}
