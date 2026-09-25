# gate-worker

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/dwin/gate-worker)

GATE (GitHub Authenticated Token Exchange) on Cloudflare Workers. Workflows
exchange their OIDC token for a short-lived GitHub App token scoped to one
repository, instead of storing long-lived personal access tokens. Each target
repository decides who may get a token, and with what permissions, in a trust
policy file.

This is a TypeScript port of [thomsonreuters/gate](https://github.com/thomsonreuters/gate).
The HTTP API, error codes, configuration schema, and trust-policy format match
upstream. It runs on Cloudflare Workers first, and the same core also runs on
Node, Bun, AWS Lambda, and Vercel. A GitHub Action in this repository calls it
with one `uses:` line.

## Install with the Deploy to Cloudflare button

You need a Cloudflare account and a GitHub organization (or user account) where
you can create a GitHub App.

1. **Create a GitHub App** under your organization's settings, in Developer
   settings, GitHub Apps.
   - Disable the webhook.
   - Under Repository permissions, grant Contents: Read (GATE reads trust
     policies with it) and Metadata: Read. Add every permission you intend to
     hand out, for example Contents: Write or Pull requests: Write.
   - Create the App, note its **Client ID**, and generate a **private key**.
   - Install the App on the repositories GATE should issue tokens for.
2. **Click the button above.** Cloudflare copies this repository into your
   GitHub account, creates the two queues, and asks for four secrets:

   | Secret                        | Value                                                                                                |
   | ----------------------------- | ---------------------------------------------------------------------------------------------------- |
   | `GATE_GITHUB_APP_CLIENT_ID`   | The App's Client ID (starts with `Iv`).                                                              |
   | `GATE_GITHUB_ORGANIZATION`    | The organization or user the App is installed on. Only workflows from this owner can request tokens. |
   | `GATE_GITHUB_APP_PRIVATE_KEY` | The contents of the downloaded `.pem` file.                                                          |
   | `GATE_REVOCATION_KEYS`        | The output of `openssl rand -base64 32`.                                                             |

3. **Check the deployment.** `https://<worker>.workers.dev/health` returns `.`,
   and `/api/v1/info` returns `{"fips_enabled":false}`. If a secret is missing or
   malformed, API calls return `INTERNAL_ERROR` and the Worker's logs name the
   problem.
4. **Add a trust policy** to a repository (see [Trust policies](#trust-policies))
   and call GATE from a workflow (see [Use the GitHub Action](#use-the-github-action)).

The button works only while this repository is public. To change settings
later, edit `config.yaml` in your copy and redeploy (see [Configuration](#configuration)).

## Use the GitHub Action

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: dwin/gate-worker@main
    id: gate
    with:
      endpoint: https://gate.<your-subdomain>.workers.dev
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
server's error code and request ID. See [action.yml](action.yml) for every input
and output.

## Trust policies

Each target repository authorizes callers in `.github/gate/trust-policy.yaml`,
in upstream's format:

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

A request is granted only if the token's issuer is trusted, the central policy's
claim checks pass, a rule in the trust policy matches, and every requested
permission is allowed by both the trust policy and `max_permissions` in
`config.yaml`. Patterns use RE2 syntax and match in linear time, as upstream's
Go `regexp` does.

Protect this file with CODEOWNERS and branch rules. Whoever can change it
controls who gets tokens for the repository.

## Configuration

`config.yaml` holds the central policy: trusted issuers, required and forbidden
claims, `max_permissions`, token lifetimes, and the GitHub App. It is compiled
and validated at build time, and `wrangler deploy` refuses an invalid file.
Editors that support `yaml-language-server` validate it against
`config.schema.json` as you type.

After a button install, the App's client ID and organization come from the
secrets you entered. `GATE_GITHUB_ORGANIZATION` also sets the required
`repository_owner` claim for GitHub Actions. Everything else comes from
`config.yaml`. To change it, edit the file in your copy and redeploy with
`pnpm install && pnpm run deploy`, or push, if your copy builds with Workers
Builds.

Differences from upstream's configuration:

- Secrets are named, never stored. Use `private_key_secret` instead of
  `private_key_path`, and `origin.header_value_secret` instead of `header_value`.
- Unknown keys are errors.
- Only the log audit backend and the memory selector exist in this build.
- Scalar settings can be overridden with upstream's `GATE_*` variables, such as
  `GATE_LOGGER_LEVEL` or `GATE_POLICY_DEFAULT_TOKEN_TTL`.

For several GitHub Apps or organizations, list them all under `github_apps`,
each with its own `private_key_secret`, and do not set the two quick-setup
secrets.

## Deploy manually

```sh
pnpm install
cp .dev.vars.example .dev.vars   # fill in, then `pnpm dev` runs the Worker locally
npx wrangler secret put GATE_GITHUB_APP_CLIENT_ID    # repeat for each secret in .dev.vars.example
pnpm run deploy
```

`wrangler deploy` creates the queues if they do not exist. To deploy from CI,
set the repository variable `DEPLOY_ENABLED=true` and the secrets
`CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`. The Deploy workflow then
runs on every push to `main`.

## Platform support

| Target              | Status                                                                                                                                 |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Cloudflare Workers  | Supported. Tokens are revoked at the end of their TTL through a queue.                                                                 |
| Node 22.18+ and Bun | Supported. Revocation uses in-process timers, as upstream does.                                                                        |
| AWS Lambda, Vercel  | Entry points build, but revocation only runs while the instance stays warm, and Lambda's 4 KB environment limit rules out keys in env. |

To run on Node or Bun:

```sh
pnpm install && pnpm config:compile
export GATE_GITHUB_APP_CLIENT_ID=... GATE_GITHUB_ORGANIZATION=... GATE_GITHUB_APP_PRIVATE_KEY="$(cat app.pem)"
node packages/server/src/platforms/node/entry.ts   # or: bun packages/server/src/platforms/bun/entry.ts
```

## Security notes

- **Revocation.** GitHub App tokens always live one hour, so GATE revokes each
  token when its requested TTL ends. The token waits in the queue sealed with
  AES-256-GCM. Its metadata is authenticated, so jobs cannot be altered or
  swapped.
- **Key rotation.** `GATE_REVOCATION_KEYS` accepts `kid:key` entries separated
  by commas. The first entry seals new jobs, and every entry can open them. To
  rotate, prepend a new key and remove the old one an hour later.
- **Fail closed.** A token whose revocation cannot be scheduled, or whose audit
  record cannot be written, is revoked immediately and never returned.
- **Auditing.** Every exchange writes one structured audit line to Workers Logs,
  including the token's SHA-256 hash, never the token itself.
- **No FIPS.** None of these runtimes offers a FIPS 140-3 mode.

## Development

```sh
pnpm install
pnpm check        # format, lint, typecheck, knip, and all tests
pnpm test:bun     # the integration suite on Bun
pnpm build:all    # Worker, Node, and Lambda bundles, and the action bundle
```

The workspace has four packages: `core` (runtime-agnostic logic), `server` (Hono
app and platform entries), `action`, and `testkit` (fakes and upstream's
fixtures). Tests never touch the network, and the integration suite ports
upstream's test cases by name. After changing the action, run
`pnpm --filter @gate/action build` and commit `packages/action/dist/`; CI fails
if it is stale.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). This project
derives from GATE, Copyright 2026 Thomson Reuters, under the same license.
