/** Node.js entry: a long-lived HTTP server with in-process revocation timers. */
import process from "node:process";
import { createLogger, timerRevocation } from "@gate/core";
import { serve } from "@hono/node-server";
import { createApp } from "../../app.ts";
import { compiledConfig } from "../../config.generated.ts";
import { buildRuntime, memoizeRuntime } from "../../runtime.ts";

const logger = createLogger({
  level: compiledConfig.logger.level,
  format: compiledConfig.logger.format,
});
const getRuntime = memoizeRuntime(() =>
  buildRuntime({
    config: compiledConfig,
    env: process.env,
    fetch,
    revocation: timerRevocation(),
    gate: { logger },
  }),
);

// Fail fast: a long-lived process should not start with bad secrets.
await getRuntime().catch((error: unknown) => {
  logger.error("startup failed", { error: error instanceof Error ? error.message : String(error) });
  process.exit(1);
});

const port = Number(process.env["PORT"] ?? process.env["GATE_SERVER_PORT"] ?? 8080);
const server = serve({ fetch: createApp({ getRuntime }).fetch, port }, (info) => {
  logger.info("listening", { port: info.port });
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    logger.info("received shutdown signal", { signal });
    server.close(() => process.exit(0));
  });
}
