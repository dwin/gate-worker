import { describe, expect, it } from "vitest";
import { startServer } from "./harness.ts";

describe("TestRepository", () => {
  it.each([
    ["InvalidFormat/no slash", "invalid"],
    ["InvalidFormat/empty repository", ""],
    ["MalformedPathsFail/too many slashes", "a/b/c"],
    ["MalformedPathsFail/only slash", "/"],
    ["MalformedPathsFail/missing owner", "/repo"],
    ["MalformedPathsFail/missing repo name", "owner/"],
  ])("%s", async (_name, repository) => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: repository,
    });
    expect(got.status).toBe(400);
    expect(got.body["error_code"]).toBe("INVALID_REQUEST");
  });

  it("CrossOrgAccessRequiresPolicy", async () => {
    const server = await startServer();
    server.setupDefaultPolicy();
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: "otherorg/otherrepo",
    });
    expect(got.body["error_code"]).toBe("POLICY_LOAD_FAILED");
  });

  it.each([
    ["hyphenated name", "example-org/my-repo"],
    ["underscored name", "example-org/my_repo"],
    ["dotted name", "example-org/my.repo"],
    ["complex name", "example-org/my-repo_v2.0"],
  ])("SpecialCharactersInName/%s", async (_name, repository) => {
    const server = await startServer();
    server.setupPolicy(repository, "contents_read_metadata_read.tpl.yaml");
    const got = await server.exchange({
      oidc_token: await server.oidc.token(),
      target_repository: repository,
    });
    expect(got.status).toBe(200);
  });
});
