import { describe, expect, it } from "vitest";
import { startServer } from "./harness.ts";

describe("revocation", () => {
  it("schedules a sealed revocation job at the capped TTL", async () => {
    const server = await startServer({ defaultTtl: 600 });
    server.setupDefaultPolicy();
    const got = await server.exchangeDefault();
    const token = got.body["token"] as string;

    expect(server.scheduled).toHaveLength(1);
    const [{ job, delaySeconds }] = server.scheduled as [(typeof server.scheduled)[number]];
    expect(delaySeconds).toBeGreaterThanOrEqual(599);
    expect(delaySeconds).toBeLessThanOrEqual(600);
    expect(job.github_client_id).toBe("client-1");
    expect(job.token_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(job)).not.toContain(token);
    expect(job.expires_at).toBe(Math.floor(Date.parse(got.body["expires_at"] as string) / 1000));
  });

  it("revokes the exact token when the job runs", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const token = (await server.exchangeDefault()).body["token"] as string;
    const runtime = await server.runtime();
    const job = server.scheduled[0]?.job;
    if (!job) throw new Error("no revocation job was scheduled");
    await runtime.gate.revoker.revoke(job);
    expect(server.github.revokedTokens).toEqual([token]);
  });

  it("refuses to start with a durable scheduler and no revocation key", async () => {
    const server = await startServer({ env: { GATE_REVOCATION_KEYS: "" } });
    await expect(server.runtime()).rejects.toThrow(/GATE_REVOCATION_KEYS" is not set/);
  });
});

describe("audit", () => {
  it("logs one audit line per granted exchange before responding", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchangeDefault();
    const audit = server.logEntries().filter((line) => line["msg"] === "audit");
    expect(audit).toHaveLength(1);
    expect(audit[0]?.["entry"]).toMatchObject({
      request_id: got.body["request_id"],
      outcome: "granted",
      caller: "repo:example-org/example-repo:ref:refs/heads/main",
      target_repository: "example-org/example-repo",
      policy_name: "default",
      permissions: { contents: "read", metadata: "read" },
      github_client_id: "client-1",
      ttl: 3600,
    });
    expect(JSON.stringify(server.logs)).not.toContain(got.body["token"] as string);
  });

  it("logs denied exchanges in the background with the deny reason", async () => {
    const server = await startServer();
    server.setupPolicy("example-org/example-repo", "no_match_other_repo.tpl.yaml");
    await server.exchangeDefault();
    await server.settle();
    const audit = server.logEntries().filter((line) => line["msg"] === "audit");
    expect(audit[0]?.["entry"]).toMatchObject({
      outcome: "denied",
      deny_reason: "NO_RULES_MATCHED",
    });
    expect(
      server
        .logEntries()
        .some((line) => line["msg"] === "token exchange denied" && line["level"] === "WARN"),
    ).toBe(true);
  });
});
