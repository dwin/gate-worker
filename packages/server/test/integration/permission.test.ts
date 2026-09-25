import { describe, expect, it } from "vitest";
import { DEFAULT_REPOSITORY, startServer } from "./harness.ts";

async function run(
  fixture: string,
  requested?: Record<string, string>,
  maxPermissions?: Record<string, string>,
) {
  const server = await startServer(maxPermissions ? { maxPermissions } : {});
  server.setupPolicy(DEFAULT_REPOSITORY, fixture);
  return server.exchange({
    oidc_token: await server.oidc.token(),
    target_repository: DEFAULT_REPOSITORY,
    ...(requested ? { requested_permissions: requested } : {}),
  });
}

const permissions = (got: { body: Record<string, unknown> }) =>
  got.body["permissions"] as Record<string, string>;

describe("TestPermission", () => {
  it("RequestNotInPolicy", async () => {
    expect((await run("contents_read.tpl.yaml", { issues: "write" })).body["error_code"]).toBe(
      "PERMISSION_NOT_IN_POLICY",
    );
  });

  it("RequestExceedsOrgMax", async () => {
    const got = await run("contents_write.tpl.yaml", undefined, {
      contents: "read",
      metadata: "read",
    });
    expect(got.body["error_code"]).toBe("PERMISSION_EXCEEDS_ORG_MAX");
    expect(got.status).toBe(403);
  });

  it("LevelRead", async () => {
    expect(permissions(await run("contents_read_metadata_read.tpl.yaml"))["contents"]).toBe("read");
  });

  it("LevelWrite", async () => {
    expect(permissions(await run("contents_write_metadata_read.tpl.yaml"))["contents"]).toBe(
      "write",
    );
  });

  it("RequestDowngrade", async () => {
    expect(
      permissions(await run("contents_write_metadata_read.tpl.yaml", { contents: "read" })),
    ).toEqual({ contents: "read" });
  });

  it("MultiplePermissions", async () => {
    const got = await run("multiple_permissions.tpl.yaml", {
      contents: "read",
      issues: "write",
      pull_requests: "read",
    });
    expect(permissions(got)).toEqual({ contents: "read", issues: "write", pull_requests: "read" });
  });

  it("RequestExceedsPolicyRejected", async () => {
    expect(
      (await run("contents_read_metadata_read.tpl.yaml", { contents: "write" })).body["error_code"],
    ).toBe("PERMISSION_EXCEEDS_POLICY");
  });

  it("EmptyPermissionsUsesPolicy", async () => {
    expect(permissions(await run("contents_write_metadata_read.tpl.yaml"))).toEqual({
      contents: "write",
      metadata: "read",
    });
  });

  it("MultiplePermissionsSomeExceedMax", async () => {
    const got = await run(
      "contents_write_packages_write_metadata_read.tpl.yaml",
      { contents: "read", packages: "write" },
      { contents: "read", metadata: "read", packages: "read" },
    );
    expect(got.body["error_code"]).toBe("PERMISSION_EXCEEDS_ORG_MAX");
  });

  it("MaxLevel", async () => {
    const got = await run("max_permission.tpl.yaml", undefined, {
      contents: "write",
      metadata: "read",
      repository_projects: "write",
    });
    expect(permissions(got)["repository_projects"]).toBe("write");
  });

  it("PartialPermissionSubset", async () => {
    expect(permissions(await run("multiple_permissions.tpl.yaml", { contents: "read" }))).toEqual({
      contents: "read",
    });
  });

  it("AllPolicyPermissionsGranted", async () => {
    expect(permissions(await run("multiple_permissions.tpl.yaml"))).toMatchObject({
      contents: "write",
      issues: "write",
      pull_requests: "write",
    });
  });

  it("NonRepositoryPermission (added)", async () => {
    expect((await run("contents_read.tpl.yaml", { members: "read" })).body["error_code"]).toBe(
      "NON_REPOSITORY_PERMISSION",
    );
  });

  it("the minted token carries exactly the effective permissions (added)", async () => {
    const server = await startServer();
    server.setupPolicy(DEFAULT_REPOSITORY, "multiple_permissions.tpl.yaml");
    await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: DEFAULT_REPOSITORY,
      requested_permissions: { issues: "read" },
    });
    const mint = server.github.requests
      .filter((request) => request.path.endsWith("/access_tokens"))
      .at(-1);
    expect(mint?.body).toEqual({ permissions: { issues: "read" }, repositories: ["example-repo"] });
  });
});
