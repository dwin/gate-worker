import { generateAppKeyPem, pkcs8PemToPkcs1Pem } from "@gate/testkit";
import { describe, expect, it } from "vitest";
import { ConfigError, importAppPrivateKey } from "../src/index.ts";

const data = new TextEncoder().encode("gate");
const sign = async (key: CryptoKey) =>
  new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data));

describe("importAppPrivateKey", () => {
  it("imports PKCS#1 (as GitHub downloads it) and PKCS#8 to the same key", async () => {
    const { pem, publicKey } = await generateAppKeyPem();
    const pkcs1 = pkcs8PemToPkcs1Pem(pem);
    expect(pkcs1).toContain("BEGIN RSA PRIVATE KEY");

    const fromPkcs8 = await importAppPrivateKey(pem, "test");
    const fromPkcs1 = await importAppPrivateKey(pkcs1, "test");
    // RSASSA-PKCS1-v1_5 is deterministic, so identical keys give identical signatures.
    expect(await sign(fromPkcs1)).toEqual(await sign(fromPkcs8));
    expect(
      await crypto.subtle.verify("RSASSA-PKCS1-v1_5", publicKey, await sign(fromPkcs1), data),
    ).toBe(true);
  });

  it("accepts PEMs whose newlines were pasted as literal \\n", async () => {
    const { pem } = await generateAppKeyPem();
    await expect(importAppPrivateKey(pem.replace(/\n/g, "\\n"), "test")).resolves.toBeDefined();
  });

  it("accepts a PEM pasted into a single-line field, with newlines removed or turned into spaces", async () => {
    const { pem } = await generateAppKeyPem();
    await expect(importAppPrivateKey(pem.replace(/\n/g, ""), "test")).resolves.toBeDefined();
    await expect(importAppPrivateKey(pem.replace(/\n/g, " "), "test")).resolves.toBeDefined();
  });

  it.each([
    ["garbage", "failed to decode PEM block"],
    [
      "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
      'unexpected PEM block type: got "PUBLIC KEY"',
    ],
    ["-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", "not a valid RSA private key"],
  ])("rejects %j", async (pem, message) => {
    const error = await importAppPrivateKey(pem, "label").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).issues[0]).toContain(message);
  });
});
