import { describe, expect, it } from "vitest";
import {
  AppSelector,
  AppsExhaustedError,
  MemoryAppStateStore,
  NoMatchingAppError,
} from "../src/index.ts";

const NOW = 1_800_000_000_000;
const clock = { now: () => NOW };
const apps = [
  { clientId: "a", organization: "org" },
  { clientId: "b", organization: "org" },
  { clientId: "c", organization: "other" },
];

describe("AppSelector", () => {
  it("only considers Apps bound to the repository owner", async () => {
    const selector = new AppSelector(apps, new MemoryAppStateStore(), clock);
    expect((await selector.select("other/repo")).clientId).toBe("c");
    await expect(selector.select("nobody/repo")).rejects.toBeInstanceOf(NoMatchingAppError);
  });

  it("prefers the App with the most remaining quota", async () => {
    const store = new MemoryAppStateStore();
    const selector = new AppSelector(apps, store, clock);
    await selector.recordUsage("a", 10, new Date(NOW + 60_000));
    await selector.recordUsage("b", 500, new Date(NOW + 60_000));
    expect((await selector.select("org/repo")).clientId).toBe("b");
  });

  it("treats Apps with no state or an expired window as fully available", async () => {
    const store = new MemoryAppStateStore();
    const selector = new AppSelector(apps, store, clock, () => 0);
    await selector.recordUsage("a", 0, new Date(NOW - 1000));
    await selector.recordUsage("b", 4000, new Date(NOW + 60_000));
    expect((await selector.select("org/repo")).clientId).toBe("a");
  });

  it("treats an App as available again at the exact reset instant", async () => {
    const store = new MemoryAppStateStore();
    const selector = new AppSelector(apps, store, clock);
    await selector.recordUsage("a", 0, new Date(NOW));
    await selector.recordUsage("b", 0, new Date(NOW));
    expect((await selector.select("org/repo")).clientId).toMatch(/^[ab]$/);
  });

  it("reports Retry-After from the earliest reset when all Apps are exhausted", async () => {
    const store = new MemoryAppStateStore();
    const selector = new AppSelector(apps, store, clock);
    await selector.recordUsage("a", 0, new Date(NOW + 30_000));
    await selector.recordUsage("b", 0, new Date(NOW + 90_000));
    const error = await selector.select("org/repo").catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(AppsExhaustedError);
    expect((error as AppsExhaustedError).retryAfterSeconds).toBe(30);
  });

  it("ignores stale observations", async () => {
    const store = new MemoryAppStateStore();
    await store.set("a", { remaining: 100, resetAt: NOW + 60_000, observedAt: NOW });
    await store.set("a", { remaining: 200, resetAt: NOW + 60_000, observedAt: NOW + 1 });
    await store.set("a", { remaining: 300, resetAt: NOW + 30_000, observedAt: NOW + 2 });
    expect((await store.getAll()).get("a")?.remaining).toBe(100);
  });
});
