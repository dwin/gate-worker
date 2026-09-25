/**
 * AWS Lambda entry (API Gateway, ALB, or Function URL).
 *
 * Not production-ready: Lambda freezes between invocations, so in-process
 * revocation timers are best-effort, and Lambda's 4 KB environment limit rules
 * out GitHub App keys in env. Both need the adapters listed in PLAN.md.
 */
import process from "node:process";
import { timerRevocation } from "@gate/core";
import { handle } from "hono/aws-lambda";
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
  runtime.logger.warn("lambda entry uses best-effort in-process revocation; see PLAN.md");
  return runtime;
});

export const handler = handle(createApp({ getRuntime }));
