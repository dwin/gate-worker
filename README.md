# gate-worker

A TypeScript port of [thomsonreuters/gate](https://github.com/thomsonreuters/gate)
(GitHub Authenticated Token Exchange). GATE is a Security Token Service: a
workload presents an OIDC token (for example from GitHub Actions) and receives a
short-lived GitHub App installation token scoped to one repository, governed by
a central policy and by a trust policy stored in the target repository.

Cloudflare Workers is the first-class target. The core is runtime-agnostic and
the same code runs on Node, Bun, AWS Lambda, and Vercel through small entry
points. A GitHub Action in this repository calls the service with one `uses:`
line.

The HTTP API, error codes, central configuration schema, and trust-policy
schema match upstream, so upstream's documentation for trust policies applies
unchanged. [PLAN.md](PLAN.md) explains the design, the decisions and rejected
alternatives, and where this port deliberately differs.

## Status

Proof of concept. The service, the action, and their tests are complete. The
end-to-end workflow against a real deployment is ready but has not run yet.

| Target              | Status                                                          |
| ------------------- | --------------------------------------------------------------- |
| Cloudflare Workers  | Supported. Revocation through a Cloudflare Queue.               |
| Node 22.18+ and Bun | Supported. Revocation through in-process timers, as upstream.   |
| AWS Lambda, Vercel  | Entry points build, but revocation is best-effort. See PLAN.md. |

## How it works

1. A workflow calls `POST /api/v1/exchange` with its OIDC token and a target repository.
2. The issuer is checked against the allowlist before any network request, then
   the token's signature, audience, and times are verified.
3. The central policy applies required and forbidden claim patterns and time windows.
4. The trust policy is fetched from the target repository, and its rules are
   matched against the token's claims.
5. Effective permissions are the intersection of the request, the trust policy,
   and the central `max_permissions` allowlist.
6. A GitHub App mints an installation token for that one repository.
7. The token's revocation is scheduled at the end of its TTL, sealed with
   AES-256-GCM, and the grant is audited before the token is returned.

## Deploy to Cloudflare Workers

Prerequisites: a Cloudflare account, and a GitHub App installed on your
organization with read access to repository contents plus every permission you
intend to grant.

1. Edit `packages/server/config.yaml`: your organization in `required_claims`
   and `github_apps`, your App's client ID, and `max_permissions`.
2. Create the queues and set the secrets:

   ```sh
   pnpm install
   cd packages/server
   npx wrangler queues create gate-revoke
   npx wrangler queues create gate-revoke-dlq
   npx wrangler secret put GATE_APP_KEY_EXAMPLE_ORG < path/to/app-private-key.pem
   echo "k1:$(openssl rand -base64 32)" | npx wrangler secret put GATE_REVOCATION_KEYS
   ```

3. Deploy. The build step validates `config.yaml` first and refuses to deploy an
   invalid configuration.

   ```sh
   npx wrangler deploy
   ```

The App key may be PKCS#1 (as GitHub downloads it) or PKCS#8. Name each key's
secret with `private_key_secret` in `config.yaml`.

To deploy from CI instead, set the repository variable `DEPLOY_ENABLED=true` and
the secrets `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`; the Deploy
workflow runs on every push to `main`.

## Run on Node or Bun

```sh
pnpm install && pnpm config:compile
export GATE_APP_KEY_EXAMPLE_ORG="$(cat path/to/app-private-key.pem)"
node packages/server/src/platforms/node/entry.ts   # or: bun packages/server/src/platforms/bun/entry.ts
```

`PORT` defaults to 8080. `GATE_REVOCATION_KEYS` is optional here, because
pending revocations never leave the process. `pnpm build` also produces
single-file bundles in `packages/server/dist/`.

## Use the GitHub Action

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: dwin/gate-worker@main
    id: gate
    with:
      endpoint: https://gate.example.workers.dev
      repository: my-org/other-repo
      permissions: |
        contents: read
        pull_requests: write
  - run: gh pr list --repo my-org/other-repo
    env:
      GH_TOKEN: ${{ steps.gate.outputs.token }}
```

The token is masked before it reaches any output. A post step revokes it when
the job ends, so it cannot outlive the job. Denials fail the step with the
server's error code and request ID. See [action.yml](action.yml) for every
input and output.

## Trust policies

Each target repository authorizes callers in `.github/gate/trust-policy.yaml`,
using upstream's format:

```yaml
version: "1.0"
trust_policies:
  - name: ci-read
    issuer: https://token.actions.githubusercontent.com
    rules:
      - name: main-branch
        logic: AND
        conditions:
          - field: repository
            pattern: "^my-org/my-repo$"
          - field: ref
            pattern: "^refs/heads/main$"
    permissions:
      contents: read
    token_ttl: 600
```

Patterns use RE2 syntax and match in linear time, as upstream's Go `regexp`
does. Protect this file with CODEOWNERS and branch rules: whoever can change it
controls who gets tokens for the repository (upstream threat model, section 5.1).

## Configuration

`packages/server/config.yaml` uses upstream's schema with these differences:

- Secrets are named, never stored. Use `private_key_secret` instead of
  `private_key_path`, and `origin.header_value_secret` instead of `header_value`.
- Unknown keys are errors.
- Only the log audit backend and the memory selector exist in this build.
- `revocation.key_secret` names the AES key secret (default `GATE_REVOCATION_KEYS`).

`GATE_LOGGER_LEVEL`, `GATE_OIDC_AUDIENCE`, `GATE_POLICY_DEFAULT_TOKEN_TTL` and
the other scalar `GATE_*` overrides work as upstream's do. Editors that support
`yaml-language-server` validate the file against `config.schema.json`.

## Development

```sh
pnpm install
pnpm check        # format, lint, typecheck, knip, and all tests
pnpm test:bun     # the integration suite on Bun
pnpm build        # Worker, Node, and Lambda bundles, and the action bundle
```

Tests never touch the network. Fakes for GitHub and the OIDC provider are
injected as `fetch`, and the integration suite ports upstream's test cases by
name. After changing the action, run `pnpm --filter @gate/action build` and
commit `packages/action/dist/`; CI fails if it is stale.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); this project
derives from GATE, which is Copyright 2026 Thomson Reuters under the same
license.
