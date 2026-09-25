import {
  exchangeRequestBodySchema,
  FireAndForgetBackground,
  httpStatusFor,
  ServiceErrorCode,
  type Background,
  type Logger,
} from "@gate/core";
import type { Context } from "hono";
import { errorBody, type AppContext, type AppOptions } from "./types.ts";

/** Uses the platform's `waitUntil` when the request has an execution context. */
function defaultBackground(context: Context, logger: Logger): Background {
  let executionContext: { waitUntil(promise: Promise<unknown>): void } | undefined;
  try {
    executionContext = context.executionCtx;
  } catch {
    executionContext = undefined;
  }
  if (!executionContext) {
    return new FireAndForgetBackground(logger);
  }
  const context_ = executionContext;
  return {
    defer: (task) => {
      context_.waitUntil(
        task().catch((error: unknown) => {
          logger.error("background task failed", { error: String(error) });
        }),
      );
    },
  };
}

/** POST /api/v1/exchange */
export function exchangeHandler(options: AppOptions) {
  return async (context: AppContext): Promise<Response> => {
    const requestId = context.get("requestId");
    const { gate, logger } = context.get("runtime");

    let decoded: unknown;
    try {
      decoded = JSON.parse(await context.req.text());
    } catch (error) {
      logger.warn("request body decode failed", { request_id: requestId, error: String(error) });
      return context.json(
        errorBody(ServiceErrorCode.InvalidRequest, "Invalid request", requestId),
        400,
      );
    }
    const body = exchangeRequestBodySchema.safeParse(decoded);
    if (!body.success) {
      logger.warn("request body decode failed", {
        request_id: requestId,
        error: body.error.message,
      });
      return context.json(
        errorBody(ServiceErrorCode.InvalidRequest, "Invalid request", requestId),
        400,
      );
    }

    const background = (options.background ?? defaultBackground)(context, logger);
    const outcome = await gate.service.exchange(
      requestId,
      {
        oidcToken: body.data.oidc_token,
        targetRepository: body.data.target_repository,
        policyName: body.data.policy_name,
        requestedPermissions: body.data.requested_permissions,
        requestedTtl: body.data.requested_ttl,
      },
      background,
    );
    if (outcome.ok) {
      return context.json(outcome.response, 200);
    }
    const { code, message, retryAfterSeconds } = outcome.error;
    if (
      code === ServiceErrorCode.RateLimited &&
      retryAfterSeconds !== undefined &&
      retryAfterSeconds > 0
    ) {
      context.header("Retry-After", String(retryAfterSeconds));
    }
    return context.json(
      errorBody(code, message, outcome.error.requestId, retryAfterSeconds),
      httpStatusFor(code),
    );
  };
}
