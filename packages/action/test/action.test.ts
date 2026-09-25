import { describe, expect, it } from "vitest";
import { runExchange, STATE_API_URL, STATE_TOKEN } from "../src/exchange.ts";
import { parsePermissions } from "../src/inputs.ts";
import type { ActionIO } from "../src/io.ts";
import { runRevoke } from "../src/revoke.ts";

function fakeIO(inputs: Record<string, string>, state: Record<string, string> = {}) {
  const log: string[] = [];
  const outputs: Record<string, string> = {};
  const secrets: string[] = [];
  const saved: Record<string, string> = {};
  let failed: string | undefined;
  const io: ActionIO = {
    getInput: (name) => inputs[name] ?? "",
    getIDToken: (audience) => Promise.resolve(`oidc-for-${audience}`),
    setSecret: (value) => {
      secrets.push(value);
      log.push(`mask`);
    },
    setOutput: (name, value) => {
      outputs[name] = value;
      log.push(`output:${name}`);
    },
    saveState: (name, value) => {
      saved[name] = value;
    },
    getState: (name) => state[name] ?? "",
    setFailed: (message) => {
      failed = message;
    },
    info: (message) => log.push(`info:${message}`),
    warning: (message) => log.push(`warn:${message}`),
  };
  return { io, log, outputs, secrets, saved, failed: () => failed };
}

const BASE_INPUTS = {
  endpoint: "https://gate.example.com/",
  repository: "example-org/example-repo",
  audience: "",
  "api-url": "https://api.github.com",
  "revoke-on-completion": "true",
  timeout: "60",
};

const SUCCESS = {
  token: "ghs_secret",
  expires_at: "2026-09-25T10:00:00.000Z",
  matched_policy: "ci-read",
  permissions: { contents: "read" },
  request_id: "req-1",
};

function scriptedFetch(responses: (() => Response)[]) {
  const requests: { url: string; init: RequestInit | undefined }[] = [];
  return {
    requests,
    fetch: (url: string, init?: RequestInit) => {
      requests.push({ url, init });
      const next = responses.shift();
      return next ? Promise.resolve(next()) : Promise.reject(new Error("no response scripted"));
    },
  };
}

const noSleep = () => Promise.resolve();

describe("runExchange", () => {
  it("exchanges the OIDC token, masks the result before any output, and saves state for revocation", async () => {
    const fake = fakeIO({
      ...BASE_INPUTS,
      permissions: "contents: read\n# comment\nissues: write",
      ttl: "600",
      "policy-name": "ci-read",
    });
    const http = scriptedFetch([() => Response.json(SUCCESS)]);
    await runExchange(fake.io, http.fetch, noSleep);

    expect(fake.failed()).toBeUndefined();
    expect(http.requests[0]?.url).toBe("https://gate.example.com/api/v1/exchange");
    expect(JSON.parse(http.requests[0]?.init?.body as string)).toEqual({
      oidc_token: "oidc-for-gate",
      target_repository: "example-org/example-repo",
      policy_name: "ci-read",
      requested_permissions: { contents: "read", issues: "write" },
      requested_ttl: 600,
    });
    expect(fake.secrets).toEqual(["oidc-for-gate", "ghs_secret"]);
    expect(fake.log.indexOf("output:token")).toBeGreaterThan(fake.log.lastIndexOf("mask"));
    expect(fake.outputs).toMatchObject({
      token: "ghs_secret",
      "matched-policy": "ci-read",
      permissions: '{"contents":"read"}',
    });
    expect(fake.saved).toEqual({
      [STATE_TOKEN]: "ghs_secret",
      [STATE_API_URL]: "https://api.github.com",
    });
  });

  it("surfaces the error code and request ID of a denial without retrying", async () => {
    const fake = fakeIO(BASE_INPUTS);
    const http = scriptedFetch([
      () =>
        Response.json(
          {
            error_code: "NO_RULES_MATCHED",
            error: "no policy rules matched the request",
            request_id: "req-9",
          },
          { status: 403 },
        ),
    ]);
    await runExchange(fake.io, http.fetch, noSleep);
    expect(fake.failed()).toBe(
      "NO_RULES_MATCHED: no policy rules matched the request (HTTP 403, request_id req-9)",
    );
    expect(http.requests).toHaveLength(1);
  });

  it("retries 429 honoring Retry-After, and 5xx gateway errors", async () => {
    const fake = fakeIO(BASE_INPUTS);
    const waits: number[] = [];
    const http = scriptedFetch([
      () =>
        Response.json(
          { error_code: "RATE_LIMITED", error: "exhausted", request_id: "r" },
          { status: 429, headers: { "retry-after": "3" } },
        ),
      () => new Response("bad gateway", { status: 502 }),
      () => Response.json(SUCCESS),
    ]);
    await runExchange(fake.io, http.fetch, (ms) => {
      waits.push(ms);
      return Promise.resolve();
    });
    expect(fake.failed()).toBeUndefined();
    expect(waits).toEqual([3000, 4000]);
  });

  it("gives up when the timeout would be exceeded", async () => {
    const fake = fakeIO({ ...BASE_INPUTS, timeout: "5" });
    let clock = 0;
    const http = scriptedFetch([
      () => new Response("unavailable", { status: 503 }),
      () => new Response("unavailable", { status: 503 }),
    ]);
    await runExchange(
      fake.io,
      http.fetch,
      (ms) => {
        clock += ms;
        return Promise.resolve();
      },
      () => clock,
    );
    expect(fake.failed()).toMatch(/HTTP 503: unavailable; giving up after 2 attempt\(s\)/);
  });

  it("explains a missing id-token permission", async () => {
    const fake = fakeIO(BASE_INPUTS);
    fake.io.getIDToken = () =>
      Promise.reject(new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable"));
    await runExchange(fake.io, scriptedFetch([]).fetch, noSleep);
    expect(fake.failed()).toMatch(/permissions: id-token: write/);
  });

  it("sends the origin-verification header when configured", async () => {
    const fake = fakeIO({
      ...BASE_INPUTS,
      "origin-header-name": "X-Origin-Verify",
      "origin-header-value": "s3cret",
    });
    const http = scriptedFetch([() => Response.json(SUCCESS)]);
    await runExchange(fake.io, http.fetch, noSleep);
    expect((http.requests[0]?.init?.headers as Record<string, string>)["X-Origin-Verify"]).toBe(
      "s3cret",
    );
  });

  it.each([
    [{ endpoint: "http://gate.example.com" }, "must use https"],
    [{ "api-url": "http://github.example.com/api/v3" }, "api-url: must use https"],
    [{ "api-url": "github.example.com" }, "api-url: expected an http(s) URL"],
    [{ repository: "not-a-repo" }, "expected owner/repo"],
    [{ ttl: "-5" }, "positive integer"],
    [{ permissions: "contents: admin" }, "must be none, read, or write"],
    [{ "origin-header-name": "X" }, "must be set together"],
  ])("rejects invalid input %o", async (override, message) => {
    const fake = fakeIO({ ...BASE_INPUTS, ...override });
    await runExchange(fake.io, scriptedFetch([]).fetch, noSleep);
    expect(fake.failed()).toContain(message);
  });

  it("does not save state when revoke-on-completion is false", async () => {
    const fake = fakeIO({ ...BASE_INPUTS, "revoke-on-completion": "false" });
    await runExchange(fake.io, scriptedFetch([() => Response.json(SUCCESS)]).fetch, noSleep);
    expect(fake.saved).toEqual({});
  });
});

describe("parsePermissions", () => {
  it("accepts JSON objects", () => {
    expect(parsePermissions('{"contents":"write"}')).toEqual({ contents: "write" });
  });
});

describe("runRevoke", () => {
  it("revokes the saved token with DELETE /installation/token", async () => {
    const fake = fakeIO(
      {},
      { [STATE_TOKEN]: "ghs_secret", [STATE_API_URL]: "https://api.github.com" },
    );
    const http = scriptedFetch([() => new Response(null, { status: 204 })]);
    await runRevoke(fake.io, http.fetch);
    expect(http.requests[0]?.url).toBe("https://api.github.com/installation/token");
    expect(http.requests[0]?.init?.method).toBe("DELETE");
    expect((http.requests[0]?.init?.headers as Record<string, string>)["authorization"]).toBe(
      "Bearer ghs_secret",
    );
    expect(fake.log).toContain("info:Revoked the GATE token.");
  });

  it("does nothing without saved state and never fails the job", async () => {
    const empty = fakeIO({});
    await runRevoke(empty.io, scriptedFetch([]).fetch);
    expect(empty.failed()).toBeUndefined();

    const broken = fakeIO({}, { [STATE_TOKEN]: "t", [STATE_API_URL]: "https://api.github.com" });
    await runRevoke(broken.io, scriptedFetch([() => new Response("oops", { status: 500 })]).fetch);
    expect(broken.failed()).toBeUndefined();
    expect(broken.log.some((line) => line.startsWith("warn:"))).toBe(true);
  });
});
