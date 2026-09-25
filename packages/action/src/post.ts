import { coreIO } from "./core-io.ts";
import { runRevoke } from "./revoke.ts";

await runRevoke(coreIO, (input, init) => fetch(input, init));
