const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Returns why `value` is unsafe to send credentials to or fetch trust material
 * from, or `undefined` when it is safe: it must parse as https (plain http only
 * for a loopback host, for local testing) with no credentials, query, or fragment.
 */
export function insecureUrlReason(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return "must be an absolute URL";
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return "must be an http(s) URL";
  }
  if (url.protocol === "http:" && !LOOPBACK_HOSTS.has(url.hostname)) {
    return "must use https (plain http is allowed only for localhost, 127.0.0.1, or [::1])";
  }
  if (url.username || url.password) {
    return "must not contain credentials";
  }
  if (url.search || url.hash) {
    return "must not contain a query or fragment";
  }
  return undefined;
}
