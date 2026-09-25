import { base64Decode } from "../util/encoding.ts";
import { ConfigError } from "./errors.ts";

const PKCS1_TYPE = "RSA PRIVATE KEY";
const PKCS8_TYPE = "PRIVATE KEY";

/** DER prefix for PKCS#8 PrivateKeyInfo: version 0 and AlgorithmIdentifier rsaEncryption with NULL params. */
const PKCS8_RSA_PREFIX = new Uint8Array([
  0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
  0x05, 0x00,
]);

function derLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  for (let remaining = length; remaining > 0; remaining >>= 8) {
    bytes.unshift(remaining & 0xff);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function derElement(tag: number, content: Uint8Array): Uint8Array<ArrayBuffer> {
  const length = derLength(content.length);
  const out = new Uint8Array(1 + length.length + content.length);
  out[0] = tag;
  out.set(length, 1);
  out.set(content, 1 + length.length);
  return out;
}

/** Wraps a PKCS#1 RSAPrivateKey in a PKCS#8 PrivateKeyInfo so WebCrypto can import it. */
export function wrapPkcs1InPkcs8(pkcs1: Uint8Array): Uint8Array<ArrayBuffer> {
  const octetString = derElement(0x04, pkcs1);
  const body = new Uint8Array(PKCS8_RSA_PREFIX.length + octetString.length);
  body.set(PKCS8_RSA_PREFIX, 0);
  body.set(octetString, PKCS8_RSA_PREFIX.length);
  return derElement(0x30, body);
}

interface PemBlock {
  type: string;
  der: Uint8Array<ArrayBuffer>;
}

function decodePem(pem: string): PemBlock | undefined {
  // Secrets pasted into dashboards often carry literal "\n" sequences.
  const normalized = pem.includes("\\n") ? pem.replace(/\\n/g, "\n") : pem;
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(normalized);
  if (!match?.[1] || match[2] === undefined) {
    return undefined;
  }
  try {
    return { type: match[1], der: base64Decode(match[2]) };
  } catch {
    return undefined;
  }
}

/**
 * Imports a GitHub App private key for RS256 signing. Accepts PKCS#1
 * (`RSA PRIVATE KEY`, as GitHub downloads it) and PKCS#8 (`PRIVATE KEY`).
 */
export async function importAppPrivateKey(pem: string, label: string): Promise<CryptoKey> {
  const block = decodePem(pem);
  if (!block) {
    throw new ConfigError([`${label}: failed to decode PEM block`]);
  }
  if (block.type !== PKCS1_TYPE && block.type !== PKCS8_TYPE) {
    throw new ConfigError([
      `${label}: unexpected PEM block type: got "${block.type}", want "${PKCS1_TYPE}" or "${PKCS8_TYPE}"`,
    ]);
  }
  const pkcs8 = block.type === PKCS1_TYPE ? wrapPkcs1InPkcs8(block.der) : block.der;
  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch (error) {
    throw new ConfigError([`${label}: not a valid RSA private key (${String(error)})`]);
  }
}
