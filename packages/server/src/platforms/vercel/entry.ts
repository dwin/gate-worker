/**
 * Vercel entry. Not production-ready: functions may be frozen after the
 * response, so in-process revocation timers are best-effort. See "Platform
 * support" in the README.
 */
import process from "node:process";
import { timerRevocation } from "@gate/core";
import { handle } from "hono/vercel";
import { createApp } from "../../app.ts";
import { compiledConfig } from "../../config.generated.ts";
import { buildRuntime, memoizeRuntime } from "../../runtime.ts";

const getRuntime = memoizeRuntime(async () => {
  const runtime = await buildRuntime({
    config: compiledConfig,
    env: process.env,
    fetch,
    revocation: timerRevocation(),
  });
  runtime.logger.warn(
    "vercel entry uses best-effort in-process revocation; see 'Platform support' in the README",
  );
  return runtime;
});

export default handle(createApp({ getRuntime }));
