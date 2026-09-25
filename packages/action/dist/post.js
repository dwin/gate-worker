import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);
import {
  STATE_API_URL,
  STATE_TOKEN,
  coreIO
} from "./chunks/chunk-IVYFQS66.js";

// src/revoke.ts
async function runRevoke(io, fetchImpl) {
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
        "x-github-api-version": "2022-11-28"
      },
      signal: AbortSignal.timeout(1e4)
    });
    if (response.status === 204 || response.status === 401) {
      io.info("Revoked the GATE token.");
    } else {
      io.warning(
        `Could not revoke the GATE token: HTTP ${String(response.status)}. It expires on its own.`
      );
    }
  } catch (error) {
    io.warning(`Could not revoke the GATE token: ${String(error)}. It expires on its own.`);
  }
}

// src/post.ts
await runRevoke(coreIO, (input, init) => fetch(input, init));
