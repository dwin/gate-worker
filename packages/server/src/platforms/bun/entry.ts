/** Bun entry: `bun src/entry/bun.ts`. Long-lived, with in-process revocation timers. */
import process from "node:process";
import { timerRevocation } from "@gate/core";
import { createApp } from "../../app.ts";
import { compiledConfig } from "../../config.generated.ts";
import { buildRuntime, memoizeRuntime } from "../../runtime.ts";

const getRuntime = memoizeRuntime(() =>
  buildRuntime({ config: compiledConfig, env: process.env, fetch, revocation: timerRevocation() }),
);
await getRuntime();

export default {
  port: Number(process.env["PORT"] ?? process.env["GATE_SERVER_PORT"] ?? 8080),
  fetch: createApp({ getRuntime }).fetch,
};
