import type { RevocationJob } from "@gate/core";
import type * as mainModule from "../../src/platforms/cloudflare/entry.ts";

declare global {
  namespace Cloudflare {
    interface Env {
      REVOKE: Queue<RevocationJob>;
      REVOKE_DLQ: Queue<RevocationJob>;
      GATE_GITHUB_APP_CLIENT_ID: string;
      GATE_GITHUB_ORGANIZATION: string;
      GATE_GITHUB_APP_PRIVATE_KEY: string;
      GATE_REVOCATION_KEYS: string;
    }
    interface GlobalProps {
      mainModule: typeof mainModule;
    }
  }
}
