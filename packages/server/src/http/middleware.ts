import { timingSafeEqual } from "@gate/core";
import type { MiddlewareHandler } from "hono";
import type { AppEnv } from "./types.ts";

/** One year, as upstream sets it. */
const HSTS_MAX_AGE_SECONDS = 31_536_000;

/**
 * Upstream's OWASP header set, applied to every response. HSTS is sent only
 * when the request arrived over HTTPS (directly or via a proxy).
 */
export const securityHeaders: MiddlewareHandler<AppEnv> = async (context, next) => {
  await next();
  const headers = context.res.headers;
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("X-Frame-Options", "DENY");
  headers.set("X-XSS-Protection", "1; mode=block");
  headers.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  headers.set("Referrer-Policy", "no-referrer");
  const https =
    new URL(context.req.url).protocol === "https:" ||
    context.req.header("X-Forwarded-Proto") === "https";
  if (https) {
    headers.set(
      "Strict-Transport-Security",
      `max-age=${String(HSTS_MAX_AGE_SECONDS)}; includeSubDomains`,
    );
  }
};

/**
 * Assigns a server-generated request ID. Unlike chi's middleware this never
 * adopts a client-supplied `X-Request-Id`, because the ID keys audit entries.
 */
export const requestId: MiddlewareHandler<AppEnv> = async (context, next) => {
  const id = crypto.randomUUID();
  context.set("requestId", id);
  await next();
  context.res.headers.set("X-Request-Id", id);
};

/**
 * Rejects requests that did not come through the trusted proxy or CDN, by
 * comparing a shared-secret header in constant time. No-op when disabled.
 */
export const originVerify: MiddlewareHandler<AppEnv> = async (context, next) => {
  const { gate, originSecret, logger } = context.get("runtime");
  const origin = gate.config.origin;
  if (!origin.enabled || !origin.header_name || originSecret === undefined) {
    await next();
    return;
  }
  const presented = context.req.header(origin.header_name) ?? "";
  if (!presented || !(await timingSafeEqual(presented, originSecret))) {
    logger.warn("origin verification failed", {
      request_id: context.get("requestId"),
      header: origin.header_name,
      method: context.req.method,
      path: new URL(context.req.url).pathname,
    });
    return context.json(
      {
        error: "Forbidden",
        error_code: "ORIGIN_VERIFICATION_FAILED",
        request_id: context.get("requestId"),
      },
      403,
    );
  }
  await next();
  return undefined;
};

/** Canonical path for routing: collapses repeated slashes and strips trailing ones, like chi's CleanPath plus upstream's NormalizePath. */
export function normalizedPath(request: Request): string {
  const path = new URL(request.url).pathname.replace(/\/{2,}/g, "/");
  return path.length > 1 ? path.replace(/\/+$/, "") || "/" : path;
}
