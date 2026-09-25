import type { RevocationJob } from "@gate/core";
import type * as mainModule from "../../src/platforms/cloudflare/entry.ts";

declare global {
  namespace Cloudflare {
    interface Env {
      REVOKE: Queue<RevocationJob>;
      GATE_APP_KEY_EXAMPLE_ORG: string;
      GATE_REVOCATION_KEYS: string;
    }
    interface GlobalProps {
      mainModule: typeof mainModule;
    }
  }
}
