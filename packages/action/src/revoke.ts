import { STATE_API_URL, STATE_TOKEN } from "./exchange.ts";
import type { ActionIO, Fetch } from "./io.ts";

/**
 * Post step: revoke the token when the job ends, so it cannot outlive the job
 * even if the server's TTL is longer. Never fails the job.
 */
export async function runRevoke(io: ActionIO, fetchImpl: Fetch): Promise<void> {
  const token = io.getState(STATE_TOKEN);
  const apiUrl = io.getState(STATE_API_URL);
  if (!token || !apiUrl) {
    return;
  }
  io.setSecret(token);
  try {
    const response = await fetchImpl(`${apiUrl}/installation/token`, {
      method: "DELETE",
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "user-agent": "gate-action",
        "x-github-api-version": "2022-11-28",
      },
      signal: AbortSignal.timeout(10_000),
    });
    if (response.status === 204 || response.status === 401) {
      io.info("Revoked the GATE token.");
    } else {
      io.warning(
        `Could not revoke the GATE token: HTTP ${String(response.status)}. It expires on its own.`,
      );
    }
  } catch (error) {
    io.warning(`Could not revoke the GATE token: ${String(error)}. It expires on its own.`);
  }
}
