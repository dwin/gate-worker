import type { LogAttributes, Logger, LogLevel } from "../ports/index.ts";

const LEVEL_RANK: Readonly<Record<LogLevel, number>> = { debug: 0, info: 1, warn: 2, error: 3 };

export type LogFormat = "json" | "text";
export type LogWriter = (level: LogLevel, line: string) => void;

/** Writes to the console method matching the level, so platforms classify lines correctly. */
const consoleWriter: LogWriter = (level, line) => {
  /* eslint-disable no-console -- the console is the log transport on every target platform */
  switch (level) {
    case "debug":
      console.debug(line);
      break;
    case "info":
      console.info(line);
      break;
    case "warn":
      console.warn(line);
      break;
    case "error":
      console.error(line);
      break;
  }
  /* eslint-enable no-console */
};

function formatText(value: unknown): string {
  if (typeof value === "string") {
    return /[\s"=]/.test(value) ? JSON.stringify(value) : value;
  }
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") {
    return value.toString();
  }
  return value === undefined ? "undefined" : JSON.stringify(value);
}

/**
 * Structured logger emitting one line per call, shaped like Go's slog handlers
 * (`time`, `level`, `msg`, then attributes) so upstream log queries carry over.
 */
export function createLogger(options: {
  level: LogLevel;
  format: LogFormat;
  writer?: LogWriter;
  now?: () => number;
}): Logger {
  const writer = options.writer ?? consoleWriter;
  const now = options.now ?? Date.now;
  const threshold = LEVEL_RANK[options.level];

  const emit = (level: LogLevel, message: string, attributes: LogAttributes = {}): void => {
    if (LEVEL_RANK[level] < threshold) {
      return;
    }
    const time = new Date(now()).toISOString();
    const upper = level.toUpperCase();
    if (options.format === "json") {
      writer(level, JSON.stringify({ time, level: upper, msg: message, ...attributes }));
      return;
    }
    const pairs = Object.entries(attributes).map(([key, value]) => `${key}=${formatText(value)}`);
    writer(
      level,
      [`time=${time}`, `level=${upper}`, `msg=${formatText(message)}`, ...pairs].join(" "),
    );
  };

  return {
    debug: (message, attributes) => {
      emit("debug", message, attributes);
    },
    info: (message, attributes) => {
      emit("info", message, attributes);
    },
    warn: (message, attributes) => {
      emit("warn", message, attributes);
    },
    error: (message, attributes) => {
      emit("error", message, attributes);
    },
  };
}
