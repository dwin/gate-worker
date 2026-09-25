import { describe, expect, it } from "vitest";
import { startServer } from "./harness.ts";

describe("TestSuccess", () => {
  it("HappyPath", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchangeDefault();
    expect(got.status).toBe(200);
    expect(got.body["token"]).toMatch(/^ghs_/);
    expect(got.body["matched_policy"]).toBe("default");
    expect(got.body["request_id"]).toMatch(/^[0-9a-f-]{36}$/);
    expect(got.body["permissions"]).toEqual({ contents: "read", metadata: "read" });
  });

  it("MultiplePoliciesSecondMatches", async () => {
    const server = await startServer();
    server.setupPolicy("example-org/example-repo", "multi_policy_second_matches.tpl.yaml");
    const got = await server.exchangeDefault();
    expect(got.body["matched_policy"]).toBe("second-policy");
    expect((got.body["permissions"] as Record<string, string>)["contents"]).toBe("write");
  });
});
