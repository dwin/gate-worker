import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createLogger,
  hashToken,
  revocationRetryDelaySeconds,
  TimerRevocationScheduler,
  type RevocationJob,
  type Revoker,
} from "../src/index.ts";

const NOW = 1_800_000_000_000;

async function jobExpiringAt(expiresAt: number): Promise<RevocationJob> {
  return {
    v: 1,
    token_hash: await hashToken("t"),
    github_client_id: "c",
    expires_at: expiresAt,
    kid: "k1",
    iv: "aXY",
    ciphertext: "Y3Q",
  };
}

describe("revocationRetryDelaySeconds", () => {
  it("backs off from 30 s to 5 min, never past the deadline, then gives up", async () => {
    const job = await jobExpiringAt(NOW / 1000);
    expect(
      [1, 2, 3, 4, 5, 9].map((attempt) => revocationRetryDelaySeconds(job, attempt, NOW)),
    ).toEqual([30, 60, 120, 240, 300, 300]);
    expect(revocationRetryDelaySeconds(job, 1, NOW + 3590_000)).toBe(10);
    expect(revocationRetryDelaySeconds(job, 1, NOW + 3600_000)).toBeUndefined();
  });
});

describe("TimerRevocationScheduler", () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: NOW });
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const logger = createLogger({ level: "error", format: "json", writer: () => undefined });

  it("retries a failed revocation until it succeeds", async () => {
    let calls = 0;
    const revoker = {
      revoke: () => (++calls < 3 ? Promise.reject(new Error("GitHub down")) : Promise.resolve()),
    } as unknown as Revoker;
    const scheduler = new TimerRevocationScheduler(revoker, logger, { now: () => Date.now() });
    await scheduler.schedule(await jobExpiringAt(NOW / 1000 + 600), 600);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(calls).toBe(1);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(calls).toBe(2);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(3);
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(calls).toBe(3);
  });

  it("stops retrying once the token must have expired, and after stop()", async () => {
    let calls = 0;
    const revoker = {
      revoke: () => {
        calls++;
        return Promise.reject(new Error("GitHub down"));
      },
    } as unknown as Revoker;
    const scheduler = new TimerRevocationScheduler(revoker, logger, { now: () => Date.now() });
    await scheduler.schedule(await jobExpiringAt(NOW / 1000), 0);
    await vi.advanceTimersByTimeAsync(2 * 3_600_000);
    const attemptsWithinWindow = calls;
    expect(attemptsWithinWindow).toBeGreaterThan(5);
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(calls).toBe(attemptsWithinWindow);

    const stopping = new TimerRevocationScheduler(revoker, logger, { now: () => Date.now() });
    calls = 0;
    await stopping.schedule(await jobExpiringAt(Date.now() / 1000 + 600), 0);
    await vi.advanceTimersByTimeAsync(0);
    expect(calls).toBe(1);
    stopping.stop();
    await vi.advanceTimersByTimeAsync(3_600_000);
    expect(calls).toBe(1);
  });
});
