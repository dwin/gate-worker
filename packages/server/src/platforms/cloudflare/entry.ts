/** Cloudflare Workers entry: HTTP via Hono, token revocation via a Queue consumer. */
import type { RevocationJob } from "@gate/core";
import { createApp } from "../../app.ts";
import { compiledConfig } from "../../config.generated.ts";
import { buildRuntime, memoizeRuntime, type Runtime } from "../../runtime.ts";
import { handleRevocationBatch, queueRevocation } from "./queue-revocation.ts";

interface Env {
  readonly REVOKE: Queue<RevocationJob>;
  readonly [binding: string]: unknown;
}

let getRuntime: (() => Promise<Runtime>) | undefined;

/** Built on first use because Worker bindings are only available inside handlers. */
function runtimeFor(env: Env): Promise<Runtime> {
  getRuntime ??= memoizeRuntime(() =>
    buildRuntime({
      config: compiledConfig,
      env,
      fetch: (input, init) => fetch(input, init),
      revocation: queueRevocation(env.REVOKE),
    }),
  );
  return getRuntime();
}

const app = createApp({ getRuntime: (context) => runtimeFor(context.env as Env) });

export default {
  fetch: app.fetch,
  async queue(batch, env) {
    const runtime = await runtimeFor(env);
    await handleRevocationBatch(batch, runtime.gate.revoker, runtime.logger);
  },
} satisfies ExportedHandler<Env, RevocationJob>;
