import type { Background, ErrorCode, ErrorResponseBody, Logger } from "@gate/core";
import type { Context } from "hono";
import type { Runtime } from "../runtime.ts";

export interface AppEnv {
  Variables: {
    requestId: string;
    runtime: Runtime;
  };
}

export type AppContext = Context<AppEnv>;

export interface AppOptions {
  /** Returns the shared runtime; entries memoize it per process or isolate. */
  getRuntime(context: Context): Promise<Runtime>;
  /** Platform background work. Defaults to `waitUntil` when available, else fire-and-forget. */
  background?(context: Context, logger: Logger): Background;
  /** Logs failures that happen before a runtime exists. Defaults to JSON on the console. */
  logger?: Logger;
}

export function errorBody(
  code: ErrorCode,
  message: string,
  requestId: string,
  retryAfterSeconds?: number,
): ErrorResponseBody {
  return retryAfterSeconds === undefined
    ? { error_code: code, error: message, request_id: requestId }
    : {
        error_code: code,
        error: message,
        request_id: requestId,
        retry_after_seconds: retryAfterSeconds,
      };
}
