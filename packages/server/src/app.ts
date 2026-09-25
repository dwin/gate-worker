import { ConfigError, createLogger, ServiceErrorCode } from "@gate/core";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { HTTPException } from "hono/http-exception";
import { timeout } from "hono/timeout";
import { exchangeHandler } from "./http/exchange.ts";
import { normalizedPath, originVerify, requestId, securityHeaders } from "./http/middleware.ts";
import { errorBody, type AppEnv, type AppOptions } from "./http/types.ts";

/** Caps request bodies against payload-exhaustion attacks, as upstream does. */
const MAX_BODY_BYTES = 1 << 20;
/** Upstream `server.request_timeout` default. */
const REQUEST_TIMEOUT_MS = 30_000;

/**
 * The GATE HTTP API: `GET /health`, `GET /api/v1/info`, `POST /api/v1/exchange`.
 * Platform-neutral; each entry point supplies the runtime.
 */
export function createApp(options: AppOptions): Hono<AppEnv> {
  const app = new Hono<AppEnv>({ getPath: normalizedPath });
  const bootstrapLogger = options.logger ?? createLogger({ level: "info", format: "json" });

  app.use(securityHeaders);
  app.use(requestId);

  // Liveness only, like chi's Heartbeat: it does not require secrets or configuration.
  app.get("/health", (context) => context.text("."));

  app.use(
    bodyLimit({
      maxSize: MAX_BODY_BYTES,
      onError: (context) =>
        context.json(
          errorBody(
            ServiceErrorCode.InvalidRequest,
            "Invalid request",
            String(context.get("requestId")),
          ),
          400,
        ),
    }),
  );
  app.use(timeout(REQUEST_TIMEOUT_MS));

  const api = new Hono<AppEnv>();
  api.use(async (context, next) => {
    try {
      context.set("runtime", await options.getRuntime(context));
    } catch (error) {
      bootstrapLogger.error("runtime initialization failed", {
        request_id: context.get("requestId"),
        issues: error instanceof ConfigError ? error.issues : [String(error)],
      });
      return context.json(
        errorBody(
          ServiceErrorCode.InternalError,
          "Internal server error",
          context.get("requestId"),
        ),
        500,
      );
    }
    await next();
    return undefined;
  });
  api.use(originVerify);
  // No build of this service links a FIPS 140-3 validated module.
  api.get("/info", (context) => context.json({ fips_enabled: false }));
  api.post("/exchange", exchangeHandler(options));
  app.route("/api/v1", api);

  app.onError((error, context) => {
    if (error instanceof HTTPException) {
      return error.getResponse();
    }
    bootstrapLogger.error("unhandled error", {
      request_id: context.get("requestId"),
      error: String(error),
    });
    return context.json(
      errorBody(ServiceErrorCode.InternalError, "Internal server error", context.get("requestId")),
      500,
    );
  });

  return app;
}
