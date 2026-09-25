import type { Clock, Sleep } from "../ports/index.ts";

export const systemClock: Clock = { now: () => Date.now() };

export const timerSleep: Sleep = (ms, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason instanceof Error ? signal.reason : new Error("aborted"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(signal?.reason instanceof Error ? signal.reason : new Error("aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });

export function epochSeconds(ms: number): number {
  return Math.floor(ms / 1000);
}
