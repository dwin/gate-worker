/**
 * Tests that run inside workerd: the deployed entry point via SELF, the full
 * exchange with Workers primitives (WebCrypto, waitUntil, the real queue
 * binding), and the queue consumer.
 */
import {
  createLogger,
  hashToken,
  validateCentralConfig,
  type RetryPolicy,
  type RevocationJob,
} from "@gate/core";
import { createFetchRouter, FakeGitHub, FakeOidcProvider, generateAppKeyPem } from "@gate/testkit";
import {
  createExecutionContext,
  createMessageBatch,
  getQueueResult,
  waitOnExecutionContext,
} from "cloudflare:test";
import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import policy from "../../../testkit/fixtures/policies/contents_read_metadata_read.tpl.yaml?raw";
import { createApp } from "../../src/app.ts";
import {
  handleRevocationBatch,
  queueRevocation,
} from "../../src/platforms/cloudflare/queue-revocation.ts";
import { buildRuntime } from "../../src/runtime.ts";

const NO_WAIT: RetryPolicy = {
  maxAttempts: 4,
  initialBackoffMs: 0,
  maxBackoffMs: 0,
  multiplier: 2,
  jitterFraction: 0,
};
const REPO = "example-org/example-repo";

describe("deployed entry point", () => {
  it("serves /health", async () => {
    const response = await exports.default.fetch("https://gate.test/health");
    expect(response.status).toBe(200);
    expect(response.headers.get("strict-transport-security")).toContain("max-age");
  });

  it("builds the runtime from compiled config and the deploy-button secrets, importing a PKCS#1 key", async () => {
    const response = await exports.default.fetch("https://gate.test/api/v1/info");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ fips_enabled: false });
  });

  it("rejects a malformed token without any outbound request", async () => {
    const response = await exports.default.fetch("https://gate.test/api/v1/exchange", {
      method: "POST",
      body: JSON.stringify({ oidc_token: "not-a-jwt", target_repository: REPO }),
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error_code: "INVALID_TOKEN" });
  });
});

async function workerHarness() {
  const oidc = await FakeOidcProvider.create();
  const github = new FakeGitHub();
  github.setPolicy(REPO, policy.replaceAll("{{ISSUER_URL}}", oidc.issuer));
  github.setInstallation(REPO);
  const router = createFetchRouter({ [oidc.origin]: oidc.handle, [github.origin]: github.handle });

  const sent: { job: RevocationJob; delaySeconds: number | undefined }[] = [];
  const queue = {
    send: async (job: RevocationJob, options?: QueueSendOptions) => {
      sent.push({ job, delaySeconds: options?.delaySeconds });
      await env.REVOKE.send(job, options);
    },
  } as unknown as Queue<RevocationJob>;

  const logs: string[] = [];
  const logger = createLogger({
    level: "debug",
    format: "json",
    writer: (_level, line) => logs.push(line),
  });
  const runtime = buildRuntime({
    config: validateCentralConfig({
      oidc: { audience: oidc.issuer },
      policy: {
        trust_policy_path: ".github/trust-policy.yaml",
        github_api_base_url: github.baseUrl,
        providers: [{ name: "test", issuer: oidc.issuer }],
        max_permissions: { contents: "write", metadata: "read" },
      },
      github_apps: [
        { client_id: "client-1", organization: "example-org", private_key_secret: "APP_KEY" },
      ],
    }),
    // Only what this harness needs: the Worker's own quick-setup secrets would override its config.
    env: {
      APP_KEY: (await generateAppKeyPem()).pem,
      GATE_REVOCATION_KEYS: env.GATE_REVOCATION_KEYS,
    },
    fetch: router.fetch,
    revocation: queueRevocation(queue),
    gate: { logger, github: { retry: NO_WAIT, tokenReadyDelayMs: 0 } },
  });
  const app = createApp({ getRuntime: () => runtime, logger });
  return { oidc, github, app, sent, logs, runtime: () => runtime };
}

describe("exchange inside workerd", () => {
  it("mints a token, enqueues a sealed revocation on the real queue binding, and uses waitUntil", async () => {
    const harness = await workerHarness();
    const ctx = createExecutionContext();
    const response = await harness.app.fetch(
      new Request("https://gate.test/api/v1/exchange", {
        method: "POST",
        body: JSON.stringify({
          oidc_token: await harness.oidc.token(),
          target_repository: REPO,
          requested_ttl: 600,
        }),
      }),
      env,
      ctx,
    );
    const body = await response.json<{ token: string }>();
    expect(response.status).toBe(200);
    expect(body.token).toMatch(/^ghs_/);

    expect(harness.sent).toHaveLength(1);
    const [{ job, delaySeconds }] = harness.sent as [(typeof harness.sent)[number]];
    expect(delaySeconds).toBeGreaterThanOrEqual(599);
    expect(JSON.stringify(job)).not.toContain(body.token);
    expect(job.token_hash).toBe(await hashToken(body.token));

    // Rate-limit recording runs in waitUntil after the response.
    await waitOnExecutionContext(ctx);
    expect(harness.github.wasRequested("/rate_limit")).toBe(true);
  });
});

describe("revocation queue consumer", () => {
  it("revokes sealed tokens, acks them, drops malformed messages, and retries failures", async () => {
    const harness = await workerHarness();
    const ctx = createExecutionContext();
    const response = await harness.app.fetch(
      new Request("https://gate.test/api/v1/exchange", {
        method: "POST",
        body: JSON.stringify({ oidc_token: await harness.oidc.token(), target_repository: REPO }),
      }),
      env,
      ctx,
    );
    const { token } = await response.json<{ token: string }>();
    await waitOnExecutionContext(ctx);
    const job = harness.sent[0]?.job;
    const runtime = await harness.runtime();

    const batch = createMessageBatch("gate-revoke", [
      { id: "good", timestamp: new Date(), attempts: 1, body: job },
      { id: "malformed", timestamp: new Date(), attempts: 1, body: { hello: "world" } },
      {
        id: "tampered",
        timestamp: new Date(),
        attempts: 1,
        body: { ...job, expires_at: (job?.expires_at ?? 0) + 1 },
      },
    ]);
    const consumerCtx = createExecutionContext();
    await handleRevocationBatch(batch, runtime.gate.revoker, runtime.logger);
    const result = await getQueueResult(batch, consumerCtx);

    expect(harness.github.revokedTokens).toEqual([token]);
    expect(result.explicitAcks.sort()).toEqual(["good", "malformed"]);
    expect(result.retryMessages.map((message) => message.msgId)).toEqual(["tampered"]);
    const retryLog = harness.logs
      .map((line) => JSON.parse(line) as Record<string, unknown>)
      .find((line) => line["msg"] === "token revocation failed; will retry");
    expect(retryLog).toMatchObject({ retry_in_seconds: 30, queue: "gate-revoke" });
  });

  it("keeps retrying while the token could be valid, then drops the job once it must have expired", async () => {
    const harness = await workerHarness();
    const ctx = createExecutionContext();
    await harness.app.fetch(
      new Request("https://gate.test/api/v1/exchange", {
        method: "POST",
        body: JSON.stringify({ oidc_token: await harness.oidc.token(), target_repository: REPO }),
      }),
      env,
      ctx,
    );
    await waitOnExecutionContext(ctx);
    const job = harness.sent[0]?.job;
    if (!job) throw new Error("no revocation job was sent");
    const runtime = await harness.runtime();
    harness.github.setError("/installation/token", 500, "GitHub is down");

    const late = createMessageBatch("gate-revoke-dlq", [
      { id: "within-window", timestamp: new Date(), attempts: 9, body: job },
    ]);
    await handleRevocationBatch(
      late,
      runtime.gate.revoker,
      runtime.logger,
      () => job.expires_at * 1000 + 60_000,
    );
    const retried = await getQueueResult(late, createExecutionContext());
    expect(retried.retryMessages.map((message) => message.msgId)).toEqual(["within-window"]);
    expect(harness.logs.some((line) => line.includes('"retry_in_seconds":300'))).toBe(true);

    const expired = createMessageBatch("gate-revoke-dlq", [
      { id: "past-window", timestamp: new Date(), attempts: 99, body: job },
    ]);
    await handleRevocationBatch(
      expired,
      runtime.gate.revoker,
      runtime.logger,
      () => (job.expires_at + 3600) * 1000,
    );
    const dropped = await getQueueResult(expired, createExecutionContext());
    expect(dropped.explicitAcks).toEqual(["past-window"]);
  });
});
