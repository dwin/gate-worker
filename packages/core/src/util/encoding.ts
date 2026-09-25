const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

/** UTF-8 bytes backed by a plain ArrayBuffer, as WebCrypto's BufferSource requires in every runtime's typings. */
export function utf8Encode(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(textEncoder.encode(value));
}

export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/** Decodes standard base64, tolerating embedded whitespace (as in GitHub's contents API and PEM). */
export function base64Decode(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value.replace(/\s+/g, ""));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function base64Encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

export function base64UrlEncode(bytes: Uint8Array): string {
  return base64Encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlDecode(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  return base64Decode(padded + "=".repeat((4 - (padded.length % 4)) % 4));
}

export function hexEncode(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
