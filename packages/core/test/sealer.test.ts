import { describe, expect, it } from "vitest";
import { ConfigError, hashToken, TokenSealer, type RevocationJob } from "../src/index.ts";

const key = (byte: number) => btoa(String.fromCharCode(...new Uint8Array(32).fill(byte)));
const TOKEN = "ghs_example_installation_token";

async function sealed(sealer: TokenSealer): Promise<RevocationJob> {
  return sealer.seal({
    token: TOKEN,
    tokenHash: await hashToken(TOKEN),
    githubClientId: "Iv1.example",
    expiresAt: 1_900_000_000,
  });
}

describe("TokenSealer", () => {
  it("round-trips and never stores the token in plaintext", async () => {
    const sealer = await TokenSealer.fromSecret(`k1:${key(1)}`, "test");
    const job = await sealed(sealer);
    expect(JSON.stringify(job)).not.toContain(TOKEN);
    expect(job).toMatchObject({
      v: 1,
      kid: "k1",
      github_client_id: "Iv1.example",
      expires_at: 1_900_000_000,
    });
    expect(await sealer.open(job)).toBe(TOKEN);
  });

  it("uses a fresh IV for every seal", async () => {
    const sealer = await TokenSealer.fromSecret(`k1:${key(1)}`, "test");
    expect((await sealed(sealer)).iv).not.toBe((await sealed(sealer)).iv);
  });

  it("detects tampering with the ciphertext or the bound metadata", async () => {
    const sealer = await TokenSealer.fromSecret(`k1:${key(1)}`, "test");
    const job = await sealed(sealer);
    const flipped = job.ciphertext.startsWith("A")
      ? `B${job.ciphertext.slice(1)}`
      : `A${job.ciphertext.slice(1)}`;
    await expect(sealer.open({ ...job, ciphertext: flipped })).rejects.toThrow();
    await expect(sealer.open({ ...job, expires_at: job.expires_at + 1 })).rejects.toThrow();
    await expect(sealer.open({ ...job, github_client_id: "other" })).rejects.toThrow();
    await expect(sealer.open({ ...job, token_hash: await hashToken("other") })).rejects.toThrow();
  });

  it("supports rotation: seals with the first key, opens with any listed key", async () => {
    const old = await TokenSealer.fromSecret(`k1:${key(1)}`, "test");
    const rotated = await TokenSealer.fromSecret(`k2:${key(2)}, k1:${key(1)}`, "test");
    const oldJob = await sealed(old);
    expect(await rotated.open(oldJob)).toBe(TOKEN);
    expect((await sealed(rotated)).kid).toBe("k2");
    await expect(old.open(await sealed(rotated))).rejects.toThrow(/unknown revocation key id: k2/);
  });

  it("ephemeral sealers work in-process only", async () => {
    const a = await TokenSealer.ephemeral();
    const b = await TokenSealer.ephemeral();
    const job = await sealed(a);
    expect(await a.open(job)).toBe(TOKEN);
    await expect(b.open(job)).rejects.toThrow();
  });

  it.each([
    ["", "expected"],
    [`noseparator`, "kid:base64key"],
    [`bad kid!:${key(1)}`, "kid:base64key"],
    ["k1:***", "not valid base64"],
    [`k1:${btoa("short")}`, "must be 32 bytes"],
    [`k1:${key(1)},k1:${key(2)}`, 'duplicate key id "k1"'],
  ])("rejects key secret %j", async (value, message) => {
    const error = await TokenSealer.fromSecret(value, "label").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ConfigError);
    expect((error as ConfigError).issues.join("\n")).toContain(message);
  });
});
