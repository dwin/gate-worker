import { createRequire } from 'node:module'; const require = createRequire(import.meta.url);
import {
  coreIO,
  runExchange
} from "./chunks/chunk-EP2PITPJ.js";

// src/io.ts
var sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// src/main.ts
await runExchange(coreIO, (input, init) => fetch(input, init), sleep);
