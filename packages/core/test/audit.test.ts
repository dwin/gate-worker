import { describe, expect, it } from "vitest";
import {
  AuditLog,
  auditEntryProblem,
  createLogger,
  LogAuditSink,
  type AuditEntry,
  type AuditSink,
  type Background,
} from "../src/index.ts";

const granted: AuditEntry = {
  request_id: "r1",
  timestamp: 1_800_000_000,
  caller: "repo:a/b:ref:refs/heads/main",
  target_repository: "a/b",
  policy_name: "default",
  permissions: { contents: "read" },
  outcome: "granted",
  token_hash: "sha256:abc",
  ttl: 900,
  github_client_id: "Iv1.test",
};

function collectingBackground() {
  const tasks: Promise<void>[] = [];
  const background: Background = { defer: (task) => tasks.push(task()) };
  return { background, settle: () => Promise.all(tasks) };
}

function memoryLogger() {
  const lines: string[] = [];
  return {
    lines,
    logger: createLogger({
      level: "debug",
      format: "json",
      writer: (_level, line) => lines.push(line),
    }),
  };
}

describe("auditEntryProblem", () => {
  it.each([
    [{ ...granted, request_id: "" }, "request_id is required"],
    [{ ...granted, token_hash: undefined }, "token_hash is required when outcome is granted"],
    [{ ...granted, ttl: 0 }, "ttl must be positive when outcome is granted"],
    [{ ...granted, outcome: "denied" as const }, "deny_reason is required when outcome is denied"],
  ])("reports upstream's validation message", (entry, message) => {
    expect(auditEntryProblem(entry as AuditEntry)).toBe(message);
  });
});

describe("AuditLog", () => {
  it("writes granted entries to the log synchronously", async () => {
    const { lines, logger } = memoryLogger();
    const { background } = collectingBackground();
    await new AuditLog([{ sink: new LogAuditSink(logger), required: true }], logger).granted(
      granted,
      background,
    );
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      level: "INFO",
      msg: "audit",
      entry: granted,
    });
  });

  it("fails the grant when a required sink fails", async () => {
    const { logger } = memoryLogger();
    const failing: AuditSink = {
      name: "broken",
      write: () => Promise.reject(new Error("disk full")),
    };
    const { background } = collectingBackground();
    await expect(
      new AuditLog([{ sink: failing, required: true }], logger).granted(granted, background),
    ).rejects.toThrow("disk full");
  });

  it("writes denied entries in the background and only warns on failure", async () => {
    const { lines, logger } = memoryLogger();
    const failing: AuditSink = {
      name: "broken",
      write: () => Promise.reject(new Error("disk full")),
    };
    const { background, settle } = collectingBackground();
    new AuditLog([{ sink: failing, required: true }], logger).denied(
      { ...granted, outcome: "denied", deny_reason: "NO_RULES_MATCHED" },
      background,
    );
    await settle();
    expect(JSON.parse(lines[0] ?? "{}")).toMatchObject({
      level: "WARN",
      msg: "audit log failed",
      sink: "broken",
    });
  });
});

describe("createLogger", () => {
  it("filters by level and supports text format", () => {
    const lines: string[] = [];
    const logger = createLogger({
      level: "warn",
      format: "text",
      writer: (_level, line) => lines.push(line),
      now: () => 0,
    });
    logger.info("hidden");
    logger.warn("shown", { repository: "a/b", note: "two words" });
    expect(lines).toEqual([
      'time=1970-01-01T00:00:00.000Z level=WARN msg=shown repository=a/b note="two words"',
    ]);
  });
});
