import { coreIO } from "./core-io.ts";
import { runExchange } from "./exchange.ts";
import { sleep } from "./io.ts";

await runExchange(coreIO, (input, init) => fetch(input, init), sleep);
