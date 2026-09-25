import { exportPKCS8, generateKeyPair } from "jose";

/** Generates an RSA-2048 key pair and returns the private key as PKCS#8 PEM, as tests store GitHub App keys. */
export async function generateAppKeyPem(): Promise<{ pem: string; publicKey: CryptoKey }> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  return { pem: await exportPKCS8(privateKey), publicKey };
}

/** Extracts the PKCS#1 RSAPrivateKey from a PKCS#8 PEM and re-encodes it as `RSA PRIVATE KEY`. */
export function pkcs8PemToPkcs1Pem(pkcs8Pem: string): string {
  const body = pkcs8Pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(body), (char) => char.charCodeAt(0));
  // PrivateKeyInfo ::= SEQUENCE { version, algorithm, OCTET STRING privateKey }
  let offset = 0;
  const readLength = (): number => {
    const first = der[offset++] ?? 0;
    if (first < 0x80) return first;
    let length = 0;
    for (let count = first & 0x7f; count > 0; count--)
      length = (length << 8) | (der[offset++] ?? 0);
    return length;
  };
  // Read each length before advancing: `offset += readLength()` would read the stale offset.
  const skip = (): void => {
    offset++; // tag
    const length = readLength();
    offset += length;
  };
  offset++; // outer SEQUENCE tag
  readLength();
  skip(); // version INTEGER
  skip(); // AlgorithmIdentifier SEQUENCE
  offset++; // OCTET STRING tag
  const length = readLength();
  const pkcs1 = der.slice(offset, offset + length);
  const base64 = btoa(String.fromCharCode(...pkcs1));
  const lines = base64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN RSA PRIVATE KEY-----\n${lines.join("\n")}\n-----END RSA PRIVATE KEY-----\n`;
}
