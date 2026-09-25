# GATE on Cloudflare Workers: POC plan

Status: proposal, revision 3, 2026-09-25. Nothing here is built yet.

Upstream: [thomsonreuters/gate](https://github.com/thomsonreuters/gate) at commit
`958af7c` (2026-09-03, "Support nested claim paths in policy conditions").
Everything below about upstream behaviour was read from that commit's source,
not from the README alone.

Direction and decisions so far:

- Hono is the HTTP framework.
- Cloudflare Workers is the first-class target, but the code is structured so
  the same core deploys to Vercel, AWS Lambda, Bun, or Node with a thin entry
  file and a few adapters.
- Audit is logging first. The POC ships the log sink only; the optional
  object-store sink (one implementation for R2 and S3) is designed here and
  built after the POC.
- A GitHub Action ships in the same repository.
- License is Apache-2.0 (switched in this PR, with a NOTICE crediting upstream).
- GitHub Enterprise Server is out of scope for the POC. The config field and
  action input for it exist because they cost nothing.
- Central configuration is validated at build and deploy time, not on the
  first request.
- Dependencies are the latest stable releases at M0, with the two ceilings
  named in §4.10, and Renovate keeps them current.
- Code structure and linting follow the conventions in §4.9.

## 1. Recommendation in one paragraph

Rewrite the core of GATE in TypeScript as a runtime-agnostic package that
depends only on `fetch` and WebCrypto, expose it through a Hono app, and keep
every platform-specific concern (secrets, background work, delayed revocation,
optional caches) behind small interfaces with one adapter per platform. Keep
the public API, error codes, config schema, and trust-policy schema
byte-for-byte compatible with upstream so its docs and 44 test fixtures stay
valid. Compile the central config at build time so a bad config cannot deploy.
Portability is proven in CI by running the same integration suite on Node,
Bun, and workerd. The POC is done when a real GitHub Actions workflow uses the
bundled action to exchange its OIDC token at the deployed Worker, uses the
returned token, and sees it rejected after the TTL.

## 2. What GATE actually is (verified from source)

GATE is a Security Token Service. A workload presents an OIDC JWT; GATE returns
a short-lived GitHub App installation token scoped to one repository.

Request path in `internal/sts/sts.go`:

1. Validate request shape (`owner/repo`, TTL bounds).
2. Parse JWT unverified, read `iss`, reject unless `iss` is in the configured
   allowlist. Only then do OIDC discovery + JWKS fetch and verify signature,
   `aud`, `exp`, `nbf`, `iat`. The allowlist-before-network ordering is the SSRF
   guard (threat S2) and must be preserved.
3. Layer 1 (central policy): find provider by issuer, check `required_claims`
   regexes, `forbidden_claims` regexes, time restrictions (UTC day/hour window,
   overnight windows supported). Dotted claim names walk nested objects; a
   literal top-level key wins over path traversal.
4. Layer 2 (repository policy): fetch `.github/gate/trust-policy.yaml` from the
   target repo via the Contents API using a `contents:read` installation token
   minted by the App. `{org}` is substituted in the path; `.yaml`/`.yml` are
   both tried if no extension is given. Parse + validate (version must be
   `"1.0"`, unique names, at least one rule, regexes compile). Cached 5 min, max
   500 entries. If `policy_name` given: explicit match (issuer must match, rules
   must match). Else: first policy whose issuer matches and any rule matches.
   Rule logic is AND (default) or OR over conditions; a condition is
   `claim regex-matches pattern`.
5. Permissions: requested (or policy's if none requested) must each be
   repo-scoped (a hard-coded deny list of org/user/enterprise permissions),
   present in the policy, at or below the policy level, present in central
   `max_permissions` (allowlist), not `none`, and at or below the central
   level. Levels: `none < read < write`.
6. TTL: `requested || default_token_ttl`, capped by policy `token_ttl` if set,
   capped by `max_token_ttl`.
7. Select a GitHub App for the owner (apps are bound to one organization each;
   pick the one with the most remaining rate limit, random tie-break; if all
   exhausted return 429 with `Retry-After`).
8. Mint installation token: App JWT (RS256, `iat` backdated 5 s, `exp` 10 min)
   → find installation for org (fall back to user) → `POST
   /app/installations/{id}/access_tokens` with `repositories:[repo]` and
   `permissions`. Every GitHub call goes through a retrying transport: 4
   attempts, 2 s/4 s/8 s backoff capped at 10 s, retries on any 4xx/5xx or
   network error. A freshly minted contents token is also held 2 s before first
   use because GitHub replicates new tokens with a lag.
9. Query `/rate_limit` with the new token and record remaining/reset for the
   selector.
10. GitHub tokens always live 1 hour. GATE caps `expires_at` in the response to
    the effective TTL and records `(sha256(token), token, expiry)` in memory. A
    goroutine runs every minute and calls `DELETE /installation/token` for
    expired entries. This is what makes the short TTL real rather than
    cosmetic.
11. Audit: a granted exchange writes an audit entry synchronously and fails the
    request if the write fails. A denied exchange writes best-effort. Backends:
    console, PostgreSQL, DynamoDB.

Public surface to keep identical:

- `POST /api/v1/exchange`, `GET /api/v1/info`, `GET /health`.
- Request/response JSON shapes and every `error_code` string and HTTP status
  in `cmd/server/handlers/exchange.go` and `internal/sts/authorizer/errors.go`.
- Central config schema (`config.example.yaml`) and trust-policy schema v1.0.
- Security headers, 1 MB body cap, trailing-slash normalization, optional
  origin-verification header with constant-time compare.

Upstream does not ship a client or a GitHub Action. Its README shows raw
`curl`. The action in §6 is new scope.

## 3. Architecture: core, ports, adapters, entries

```
packages/core        pure TypeScript, no framework, no platform APIs
                     (needs only fetch + WebCrypto; runs on Node 24, Bun, workerd,
                      Vercel, Lambda without change)
        │
        │  ports (interfaces) defined here, implemented elsewhere:
        │    Fetch, Clock, SecretSource, Cache, AppStateStore,
        │    RevocationScheduler, AuditSink, Background, Logger
        ▼
packages/server      Hono app + middleware + HTTP handlers
   ├── adapters/     one folder per platform or backend
   │     memory/     Cache, AppStateStore, TimerRevocationScheduler (Node, Bun)
   │     cloudflare/ QueueRevocationScheduler, WaitUntilBackground
   │     node/       FireAndForgetBackground
   │     s3/         ObjectStoreAuditSink via aws4fetch          (post-POC)
   │     lambda/     CollectAndAwaitBackground                   (post-POC)
   └── entry/        cloudflare.ts, node.ts, bun.ts, lambda.ts, vercel.ts
                     each builds a Runtime {config, env, adapters} once and calls createApp()

packages/action      GitHub Action; imports request/response types from core
```

Rules that keep this honest:

- `packages/core` is fenced by ESLint (`eslint-plugin-boundaries`) so it
  cannot import `node:*`, `cloudflare:*`, `hono`, or any package outside its
  allowlist. If it compiles and lints, it is portable.
- Every outbound network call takes `fetch` from the `Runtime`, never the
  global. Tests inject a fake; production injects the platform's.
- The Hono app is created by `createApp(runtime)` and exported as a plain
  `app.fetch`. Entry files are 5 to 15 lines each.

### 3.1 Ports and their adapters

| Port | Used for | Portable default (in POC) | Workers adapter (in POC) | Other adapters (post-POC) |
|---|---|---|---|---|
| `Fetch` | OIDC discovery/JWKS, GitHub API, object store | platform `fetch` | same | same |
| `Clock` | time restrictions, TTL caps, JWT `iat`/`exp` | `Date.now` | same | same |
| `SecretSource` | GitHub App keys, origin header value | environment variables | same; Worker secrets appear as env bindings | Secrets Store binding; AWS Secrets Manager or SSM (Lambda's env limit is 4 KB total) |
| `Cache` | policy cache (5 min, 500), installation IDs (24 h, 1000), discovery docs | in-process `Map` with TTL and size cap, plus in-process promise dedupe (singleflight) | same (per isolate) | optional L2 on Workers Cache API or KV |
| `AppStateStore` | selector rate-limit state | in-process memory (upstream's own default) | same | Durable Object; Redis; DynamoDB |
| `RevocationScheduler` | revoke tokens at capped expiry | `TimerRevocationScheduler`: in-process timers, one sweep per minute, upstream parity; suits Node and Bun | `QueueRevocationScheduler`: Cloudflare Queue message with `delaySeconds = ttl`, consumer revokes | `SweepRevocationScheduler`: pending tokens in the object store, a cron-driven `/internal/revoke-sweep` on Vercel Cron or EventBridge Scheduler |
| `AuditSink` | see §4.6 | `LogAuditSink` (always on) | same | `ObjectStoreAuditSink` (R2/S3); R2-binding sink |
| `Background` | best-effort work after the response (denied audit, usage recording) | `FireAndForget` with error logging | `ctx.waitUntil` | Vercel: `waitUntil`; Lambda: collect and await before returning |
| `Logger` | one structured JSON line per exchange, same fields as upstream `logExchange` | `console.log(JSON)` | same; Workers Logs indexes JSON | CloudWatch and Vercel both parse JSON lines |

### 3.2 Compiled configuration

The central policy stays in upstream's YAML schema, but it is not parsed at
runtime. A build step compiles it:

```
packages/server/config.yaml
        │  scripts/compile-config.ts  (runs under plain `node`; see §4.9)
        │    1. parse YAML
        │    2. validate with the zod schema in @gate/core (same rules and
        │       messages as upstream internal/config/*.go)
        │    3. emit packages/server/src/config.generated.ts, a typed constant
        │    4. emit packages/server/config.schema.json for editors and CI
        ▼
   the bundle imports the typed constant; TypeScript checks every use
```

Where this runs:

- `pnpm config:check` in CI on every push.
- `wrangler.jsonc` `build.command` runs it before `wrangler dev` and
  `wrangler deploy`, so an invalid config cannot reach Cloudflare.
- The Node, Bun, Lambda, and Vercel build scripts run the same step.
- `config.yaml` carries a `# yaml-language-server: $schema=./config.schema.json`
  line so editors flag mistakes while typing.

What stays at runtime, and is validated at cold start against the same zod
schema: the handful of `GATE_*` environment overrides upstream supports (log
level, audience, and the like) and secret resolution through `SecretSource`.
Secrets are never in `config.yaml`; the file names the secret to resolve
(`github_apps[].private_key_secret` replaces upstream's `private_key_path`).
Keys may be PKCS#1 or PKCS#8 PEM; WebCrypto imports only PKCS#8, so PKCS#1 DER
is wrapped in the fixed PKCS#8 header at load time.

Three upstream fields are ignored with a warning at compile time (`server.*`,
`aws_region`, `fips.*`), and `audit.backend: sql|dynamodb` is rejected with a
message naming the supported sinks.

The same zod schema approach applies to trust policies, which are runtime
input from repositories: `@gate/core` exports the trust-policy schema and a
JSON Schema for it, so repository owners can lint `trust-policy.yaml` in their
own CI. Upstream's threat model recommends exactly that kind of status check
(§5.2, "required status checks with automated policy analysis"); a
`validate-policy` mode for the action is a cheap post-POC addition.

Rejected: parsing YAML at first request. It moves a configuration error from
the deploy log, where a human is watching, to a 500 in production.

Rejected: JSON in `wrangler.jsonc` `vars`. It abandons upstream's config
schema and does not work on the other platforms.

## 4. Design decisions and rejected alternatives

### 4.1 TypeScript rewrite, not Go→WASM

Rejected: compiling upstream with TinyGo or standard Go to WASM. The Go code
depends on `net/http` server semantics, goroutines with tickers, `os.ReadFile`,
Viper's filesystem search, and the AWS/Redis/GORM SDKs. None of that runs on
workerd, and none of it is portable to the other targets either. Stripping it
leaves the ~1,500-line core, which is faster to rewrite than to make WASM-clean.

### 4.2 Hono, and why it carries the portability

Hono 4.13 ships first-party adapters for Cloudflare Workers, Bun, AWS Lambda
(`handle` from `hono/aws-lambda`, covering API Gateway v1/v2, ALB, Function
URLs), Vercel (`handle` from `hono/vercel`), Deno, and Netlify, plus
`@hono/node-server` for Node. Its `env()` and `getRuntimeKey()` helpers from
`hono/adapter` read configuration the same way on each. Its built-in
`secure-headers`, `body-limit`, `request-id`, `timeout`, and `trailing-slash`
middlewares replace five of upstream's six custom middlewares; only origin
verification is written by hand, using a portable constant-time compare
rather than the Workers-only `crypto.subtle.timingSafeEqual`.

Rejected: a bare `fetch` handler. It would need a hand-rolled version of every
adapter Hono already maintains.

### 4.3 `re2js` instead of native `RegExp`

Trust policies are authored by repository owners (upstream trust boundary TB6,
semi-trusted). Upstream evaluates their patterns with Go's RE2 engine, which
guarantees linear time. Native JS `RegExp` backtracks, so a pattern like
`(a+)+$` becomes a CPU-exhaustion vector; on the Workers Free plan it trips
the 10 ms CPU cap. RE2 and ECMAScript regex syntax also differ (`(?P<n>)`,
`\z`, no lookaround in RE2, different Unicode class names), so native `RegExp`
would silently change which policies match. `re2js` 2.8.x is a pure-JS RE2
port that claims parity with Go's `regexp`, runs everywhere without WASM, and
is actively maintained. The fixture `complex_regex_patterns.tpl.yaml` is the
first test to run against it.

Rejected: native `RegExp` with a timeout. A running native regex cannot be
interrupted in JS.

### 4.4 Thin GitHub client instead of Octokit

GATE needs six GitHub endpoints: find org installation, find user
installation, create installation token, get contents, rate limit, revoke
token. Upstream's retry policy (retry every 4xx/5xx, 4 attempts, 2/4/8 s) is
deliberate and GitHub-support-informed; replicating it precisely is easier in a
150-line `fetch` wrapper than by configuring Octokit's retry plugin. Octokit
also requires PKCS#8 and does not convert PKCS#1 itself. The thin client takes
`fetch` from the `Runtime`, which is also how tests inject a fake GitHub.

### 4.5 Token revocation

Workers has no background goroutine, and neither do Lambda or Vercel. Rather
than pick one mechanism, revocation is a port with three adapters (§3.1). The
POC ships the in-process timer (exact upstream parity, used by Node and Bun and
by the Node-side integration tests) and the Cloudflare Queue adapter (delayed
message per issued token; max delay 24 h against upstream's default
`max_token_ttl` of 1 h; retries and a dead-letter queue come free; available on
the Free plan). The object-store sweep adapter for Lambda and Vercel is
designed but not built in the POC.

Trade-off stated plainly: any durable design stores the raw token until
expiry, because `DELETE /installation/token` authenticates with the token
itself. Upstream holds it in process memory. Queue storage is encrypted at
rest; that is the accepted residual.

### 4.6 Audit: log sink in the POC, object-store sink designed for later

`AuditLog` fans out to sinks. `LogAuditSink` is always on and writes one JSON
line per entry with upstream's `AuditEntry` fields and validation rules; on
Workers that lands in Workers Logs, on Lambda in CloudWatch, on Vercel in its
log drain. Upstream's blocking semantics are preserved from day one through
the sink interface: for a granted exchange every sink marked `required` is
awaited before the token is returned; for a denied exchange sinks run through
`Background`. With only the log sink present this is trivially satisfied, but
the shape is there so adding a sink changes no call sites.

Post-POC, `ObjectStoreAuditSink` targets the S3 API using `aws4fetch` (about
5 KB, `fetch` + WebCrypto only, supports session tokens). R2 exposes the same
API at `<account>.r2.cloudflarestorage.com` with `region: auto`, so one sink
covers R2, S3, MinIO, and anything else S3-compatible; on Lambda it picks up
the execution role's credentials from the standard environment variables.
Layout: one immutable object per entry at
`{prefix}{yyyy}/{mm}/{dd}/{hh}/{epoch_ms}-{request_id}.json`, written with
`If-None-Match: *` so the service's own credentials can never overwrite an
entry. That is a cheap partial answer to upstream's open threat T5 (no
write-once enforcement). S3 Object Lock closes it fully; R2's docs mention
conditional headers on `PutObject` only in passing, so that gets verified when
the sink is built. Config section, reserved now so the schema does not churn:

```yaml
audit:
  object_store:
    enabled: false
    endpoint: https://<account>.r2.cloudflarestorage.com
    region: auto
    bucket: gate-audit
    prefix: audit/
    required: true
    access_key_id_secret: GATE_AUDIT_ACCESS_KEY_ID
    secret_access_key_secret: GATE_AUDIT_SECRET_ACCESS_KEY
```

Rejected: the AWS SDK v3 S3 client (hundreds of KB, Node-centric, slow cold
start on Workers). Rejected: Analytics Engine for audit; it samples and has no
exact-row retrieval. Rejected: batching entries into JSONL objects; on
serverless there is nothing to batch within.

### 4.7 Observability without the OTel SDK

Rejected: `@microlabs/otel-cf-workers` (release candidate since 2024, last
published May 2025). Use the platform's log capture for the JSON lines above,
Workers Traces (beta, OTel-compatible export, billed from 2026-10-01) with the
same span names as upstream (`TokenExchange`, `ValidateOIDC`,
`EvaluatePolicy`, `SelectApp`, `MintInstallationToken`), and Analytics Engine
for the four counters. Rejected: pino or winston in core; both rely on Node
internals. The `Logger` port is a 40-line JSON writer.

### 4.8 Plan tier

Start on Workers Free. RS256 sign and verify are native WebCrypto and cost
low single-digit milliseconds; `re2js` matching is small; retry sleeps are
wall time, not CPU; no YAML is parsed at runtime except trust policies. The
10 ms CPU cap is probably enough but marginal. Expect to move to Paid
($5/month, 30 s default CPU) before load testing.

### 4.9 Code structure and linting

Structure:

- Hexagonal: `core` owns the domain and the port interfaces; `server` owns
  adapters and HTTP; `action` owns the runner integration. Dependencies point
  inward only, enforced by `eslint-plugin-boundaries`.
- Dependency injection through one `Runtime` object built once per process
  or isolate. No module-level mutable state except the explicitly named
  per-isolate caches, and those live behind the `Cache` port.
- Denials are values, not exceptions, exactly as upstream's `Result` and
  `DenialError`. Exceptions are reserved for programmer errors and transport
  failures, and every thrown error carries a code.
- Named exports only; `export default` appears only in entry files where the
  platform requires it.
- One reason to change per module; files stay under roughly 300 lines. The
  upstream package split (`oidc`, `authorizer`, `github`, `selector`, `audit`,
  `sts`) maps one-to-one to folders so a reviewer can diff against upstream.
- Package `exports` maps with no deep imports across packages.

TypeScript (latest 6.x; see §4.10): `strict`, `noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`, `noImplicitOverride`,
`noPropertyAccessFromIndexSignature`, `verbatimModuleSyntax`,
`isolatedModules`, `erasableSyntaxOnly`. The last one guarantees every source
file is runnable by Node 24's built-in type stripping, so the compile-config
script and any other tooling run under plain `node` with no `tsx` or
`ts-node`.

Linting and formatting:

- ESLint 10 flat config with `typescript-eslint` `strictTypeChecked` and
  `stylisticTypeChecked`. Type-aware rules are the point: `no-floating-promises`,
  `no-misused-promises`, `restrict-template-expressions`,
  `switch-exhaustiveness-check`, `no-unnecessary-condition`. `no-explicit-any`
  and `consistent-type-assertions` as errors.
- `eslint-plugin-import-x` for `no-cycle`, ordering, and `no-extraneous-dependencies`.
- `eslint-plugin-boundaries` for the package fences above.
- Prettier for formatting; ESLint does not format.
- `knip` for unused files, exports, and dependencies, run in CI.
- `lefthook` runs typecheck, lint, format check, and the config compile on
  pre-commit, mirroring upstream's `pre-commit` setup.
- EditorConfig copied from upstream.

Rejected: Biome. It is fast and would replace Prettier, but it has no
type-aware rules, and for a token-issuing service the type-aware promise and
exhaustiveness checks are the ones that catch real bugs.

### 4.10 Dependency policy

Latest stable at M0, then Renovate with minor and patch updates grouped
weekly, majors as individual PRs, lockfile maintenance on, and GitHub Actions
pinned by commit SHA as upstream does. pnpm catalogs hold one version per
dependency across the three packages so they cannot drift.

Two ceilings exist today and are recorded in the catalog with a comment:

- Vitest 4.x, because `@cloudflare/vitest-plugin` 1.2.6 and
  `@cloudflare/vitest-pool-workers` 0.22.0 both pin `^4.1.0`. Vitest 5.0.1 is
  out and unsupported there.
- TypeScript 6.x, because `typescript-eslint` 8.70.1 declares
  `typescript >=4.8.4 <6.1.0`. TypeScript 7.0.2 is the native compiler line;
  it is adopted the release `typescript-eslint` supports it, and nothing in
  the code changes for that.

## 5. Repository layout

pnpm workspaces, three packages.

```
gate-worker/
  action.yml                      # at the root so `uses: dwin/gate-worker@v1` works
  LICENSE, NOTICE                 # Apache-2.0; NOTICE credits upstream
  pnpm-workspace.yaml             # packages + catalog
  package.json                    # root scripts: build, test, typecheck, lint, config:check
  eslint.config.ts, .prettierrc, lefthook.yml, renovate.json, .editorconfig
  PLAN.md
  packages/
    core/                         # @gate/core
      src/
        config/                   # schema.ts (zod), overrides.ts, keys.ts (PKCS#1→PKCS#8)
        oidc/                     # validator.ts, discovery.ts
        authorizer/               # central.ts, policy.ts (zod), match.ts, permission.ts,
                                  # fetch.ts, claims.ts, errors.ts
        github/                   # client.ts, jwt.ts, errors.ts
        selector/                 # selector.ts
        audit/                    # entry.ts (+validate), log.ts, audit-log.ts (fan-out)
        sts/                      # service.ts, errors.ts (ExchangeError, code→status)
        ports/                    # one file per port
        util/                     # cache.ts, singleflight.ts, hash.ts, timing-safe-equal.ts
      test/
        fixtures/policies/        # upstream's 44 files, verbatim, Apache header kept
        harness/                  # oidc.ts (RSA keypair, discovery+JWKS), github.ts (fake)
        unit/
    server/                       # @gate/server
      config.yaml                 # central policy, upstream schema, $schema comment
      config.schema.json          # generated
      wrangler.jsonc              # build.command runs the config compile
      scripts/compile-config.ts   # YAML → validate → config.generated.ts + JSON Schema
      src/
        config.generated.ts       # generated, gitignored
        app.ts                    # createApp(runtime): Hono app
        http/                     # exchange.ts, info.ts, health.ts, origin-verify.ts
        runtime.ts                # Runtime type: config + env + adapters
        adapters/
          memory/                 # cache, app-state, timer-revocation
          cloudflare/             # queue-revocation.ts, background.ts
          node/                   # background.ts
        entry/
          cloudflare.ts           # export default { fetch, queue }
          node.ts                 # @hono/node-server
          bun.ts                  # export default { fetch: app.fetch }
          lambda.ts               # hono/aws-lambda handle()      (deploy post-POC)
          vercel.ts               # hono/vercel handle()          (deploy post-POC)
      test/
        integration/              # runs on Node and Bun via app.request()
        workers/                  # runs in workerd via @cloudflare/vitest-plugin
    action/                       # gate GitHub Action
      src/main.ts, post.ts, client.ts
      dist/                       # committed; CI fails if stale
      test/
  .github/workflows/
    checks.yml                    # matrix: node 24, bun; plus workerd suite; knip; action build check
    deploy.yml                    # config:check then wrangler deploy on main
    e2e.yml                       # uses the action against the dev deployment
```

`wrangler.jsonc` sketch:

```jsonc
{
  "name": "gate",
  "main": "src/entry/cloudflare.ts",
  "compatibility_date": "2026-09-01",
  "compatibility_flags": ["nodejs_compat"],
  "build": { "command": "pnpm config:compile" },
  "vars": { "GATE_LOGGER_LEVEL": "info" },
  "queues": {
    "producers": [{ "queue": "gate-revoke", "binding": "REVOKE" }],
    "consumers": [{ "queue": "gate-revoke", "max_retries": 5, "dead_letter_queue": "gate-revoke-dlq" }]
  },
  "observability": { "enabled": true, "traces": { "enabled": true } },
  "limits": { "cpu_ms": 30000 }
}
```

## 6. The GitHub Action

Purpose: replace the `curl` in upstream's README with

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: dwin/gate-worker@v1
    id: gate
    with:
      endpoint: https://gate.example.com
      repository: my-org/other-repo
      permissions: |
        contents: read
        pull_requests: write
  - run: gh api repos/my-org/other-repo/pulls
    env:
      GH_TOKEN: ${{ steps.gate.outputs.token }}
```

Design:

- JavaScript action, `runs.using: node24`. Node 20 was removed from GitHub
  runners on 2026-09-23, so `node24` is the only supported choice.
- Main step: `core.getIDToken(audience)` (requires `id-token: write`), `POST
  {endpoint}/api/v1/exchange`, `core.setSecret(token)` before setting any
  output, then outputs `token`, `expires-at`, `matched-policy`, `permissions`
  (JSON), `request-id`. Errors surface as `core.setFailed("<error_code>:
  <error> (request_id ...)")` so a denial is diagnosable from the job log
  without server access. Retries only on 429 (honouring `Retry-After`) and
  502/503/504, bounded by a `timeout` input.
- Post step (`revoke-on-completion`, default `true`): `DELETE
  {api-url}/installation/token` with the token, so the token dies at job end
  regardless of TTL. The token crosses to the post step through
  `core.saveState`, the same pattern `actions/checkout` uses for its auth
  token.
- Inputs: `endpoint` (required), `repository` (default `github.repository`),
  `policy-name`, `permissions` (multiline `key: level`), `ttl`, `audience`
  (default `gate`), `api-url` (default `github.api_url`), `origin-header-name`
  and `origin-header-value` (for deployments with origin verification; pass
  the value from a secret), `revoke-on-completion`, `timeout`.
- Types for the request, response, and error codes are imported from
  `@gate/core`, so the action cannot drift from the server.
- Bundled with esbuild into `dist/index.js` and `dist/post.js` (esbuild is
  already the bundler for the Node and Lambda server builds; `@vercel/ncc`
  would be a second tool doing the same job). `dist/` is committed because the
  runner executes it directly; CI rebuilds and fails on a diff.
- Tests: Vitest on Node with `@actions/core` mocked and `fetch` injected.
- Rejected: a composite shell action. It cannot guarantee output masking
  before the value hits a log, depends on `jq` being present, and gives worse
  error messages.
- Marketplace publication is optional and needs a unique name and branding
  block; the root `action.yml` works without it.

## 7. Milestones

Each milestone ends with green CI. "Done when" is the acceptance test.

### M0: Monorepo scaffold, tooling, three runtimes (1.5 days)

pnpm workspaces with a catalog; TypeScript 6.x with the flags in §4.9; ESLint
10 with `typescript-eslint`, `import-x`, `boundaries`; Prettier; `knip`;
`lefthook`; Renovate; Hono; Wrangler 4.x; `@cloudflare/vitest-plugin` 1.x with
Vitest 4.x; esbuild. `createApp()` with `/health` and `/api/v1/info`;
middleware chain; entries for Cloudflare, Node, Bun. The first commit that
adds tooling is the last commit allowed to have lint warnings.

Done when: CI starts the app on Node 24, on Bun, and in workerd, each serves
`/health` with the identical upstream security-header set, and lint,
typecheck, and `knip` are clean.

### M1: Compiled config and trust-policy schema (1.5 days)

zod schemas for the central config and the trust-policy file, porting the
rules and messages of `internal/config/*.go` and
`internal/sts/authorizer/policy.go`; the `GATE_*` override mapping; the
compile-config script with `build.command` and CI wiring; JSON Schema output;
the PKCS#1/PKCS#8 key loader. Copy upstream's fixtures.

Done when: `wrangler deploy --dry-run` fails on a `config.yaml` with a bad
TTL or an unknown permission level and passes on the example config; every
fixture upstream expects to fail (`missing_*`, `invalid_*`, `wrong_*`,
`duplicate_policy_names`, `empty_rules`) fails with the same message class,
`valid.yaml` passes; an in-test PKCS#1 key and its PKCS#8 form both import and
produce the same JWT signature.

### M2: Authorizer (1 day)

Port `authorizer.go`, `provider.go`, `match.go`, `permission.go`, dotted claim
lookup, with `re2js` for every pattern. Pure functions; the policy fetch is a
port so no GitHub is needed here.

Done when: unit tests cover upstream's `TestEvaluation_*`, `TestExplicit_*`,
`TestPermission_*`, `TestTTL_*`, `TestParsing_*` names using the `.tpl.yaml`
fixtures with `{{ISSUER_URL}}` substituted, the full `deniedPermissions` list
rejects with `NON_REPOSITORY_PERMISSION`, and a known catastrophic pattern
completes in bounded time.

### M3: OIDC validator (1 day)

`jose` discovery + JWKS + verify, allowlist first. Port
`internal/testutil/oidc.go` to a harness that generates an RSA keypair per run
and answers discovery and JWKS through the injected `fetch`.

Done when: upstream's 11 `TestOIDC_*` cases pass and the untrusted-issuer test
asserts the injected `fetch` was never called.

### M4: GitHub client, exchange service, HTTP handler (2 days)

Thin client with retry transport, caches, and a token-ready delay that tests
set to zero. Port `test/integration/harness/github.go` to a fake GitHub that
records calls, serves fixture policies at the configured path, and returns
401/403/404/422/5xx on demand. Wire `sts/service.ts` and the handler.

Done when: `TestSuccess_*`, `TestDiscovery_*`, `TestGitHub_*`,
`TestRepository_*` pass through `app.request()` on Node and Bun and through
`SELF.fetch` in workerd; every documented `error_code` is produced by at least
one test with its documented status; `TestDiscovery_ConcurrentRequests` shows
one policy fetch for N parallel requests.

### M5: Log audit, revocation, first deploy (1 day)

`LogAuditSink` and the fan-out with required/background semantics;
`TimerRevocationScheduler`; `QueueRevocationScheduler` and the queue consumer;
`Background` adapters. Deploy to a dev Worker with one GitHub App on one test
org.

Done when: a granted exchange in workerd produces exactly one audit log line
with the upstream field set before the response is returned; a denied exchange
produces its line through `waitUntil`; and a queue message is delivered after
the TTL and the fake GitHub records the revoke.

### M6: GitHub Action and end-to-end proof (1.5 days)

Build the action, commit `dist/`, add the root `action.yml`, and add
`e2e.yml` running against the dev deployment.

Done when: a workflow in a test repo with a trust policy uses the action,
receives a `ghs_` token, reads a file from the target repo with it, and after
the TTL the same token returns 401 from GitHub. That last assertion proves the
revocation path, the one piece no serverless platform inherits from upstream.

### Post-POC (listed so nothing is forgotten)

- `ObjectStoreAuditSink` (R2 and S3 through one S3-API implementation), then
  the R2-binding variant for Workers without API keys.
- Lambda and Vercel deployments: entries exist from M0; add the sweep
  revocation adapter, the Lambda `Background` adapter, and a Secrets Manager
  `SecretSource`. Lambda's 4 KB total env limit rules out keys in env there.
- `validate-policy` mode for the action, using the exported trust-policy JSON
  Schema, so repositories can gate policy changes with a status check.
- Durable Object `AppStateStore` for multiple Apps per org.
- Secrets Store binding on Workers.
- Analytics Engine metrics; traces export to the team's collector.
- Cloudflare Access service token or mTLS in front of `/api/v1/*`.
- GitHub Enterprise Server test matrix entry.
- Load test on the Paid tier.

Total POC estimate: about nine and a half working days for one engineer
familiar with Hono and Workers, plus GitHub App setup time.

## 8. Test strategy

Upstream's integration suite is the specification. Its fixtures are YAML and
language-neutral; its test names encode the behaviour matrix. Both are carried
across so a reviewer can diff the two suites by name.

- Fixtures copied verbatim under `packages/core/test/fixtures/policies/`,
  Apache-2.0 header retained.
- Fakes are injected as a `fetch` function, never installed globally. This is
  forced by the removal of `fetchMock` from `cloudflare:test` in
  `@cloudflare/vitest-pool-workers` 0.22 and is the better design regardless.
- The same integration suite runs three ways: `app.request()` on Node 24,
  `app.request()` on Bun, and `SELF.fetch` inside workerd. Passing on all three
  is the portability claim, made concrete.
- Workers-only tests cover the queue consumer
  (`createMessageBatch`/`getQueueResult`) and `waitUntil`
  (`waitOnExecutionContext`).
- One regex-parity test compiles every pattern in every fixture with `re2js`.
- Config tests feed known-bad YAML through the compile script and assert the
  exit code and message.
- Action tests mock `@actions/core` and inject `fetch`; `e2e.yml` is the only
  test that touches real GitHub.

## 9. Risks and resolved decisions

| Risk | Impact | Mitigation |
|---|---|---|
| `re2js` semantics diverge from Go `regexp` on some construct | Policy matches differ from upstream | Parity test over all fixture patterns; both are RE2 syntax |
| Free-plan 10 ms CPU cap | 5xx on cold start or large policies | Measure in M4; move to Paid |
| Worst case per exchange: 4 retries × up to 10 s + 2 s ready delay per GitHub call | Client timeouts during GitHub incidents | Same as upstream; action `timeout` input; consider lowering `MaxBackoff` |
| PKCS#1 key import | Deploy-time failure | Runtime wrapper, tested in M1 with a real PKCS#1 key |
| `typescript-eslint` lags TypeScript 7 | Cannot adopt TS 7 yet | Stay on 6.x; Renovate flags the unblock |
| Lambda env limit 4 KB total | Cannot hold an RSA key plus other vars | Secrets Manager `SecretSource` before any Lambda deploy |
| Raw token at rest in the queue | Residual per §4.5 | Accept for POC |
| In-process revocation on Node/Bun lost on restart | Some tokens live to GitHub's 1 h | Same as upstream; sweep adapter fixes it |
| Token in the action's `STATE_` env for the post step | Visible to later steps of the same job | Standard pattern (`actions/checkout`); documented |
| Workers Traces beta, billable 2026-10-01 | Cost surprise | Head sampling; logs are the primary signal |
| No FIPS on any of these runtimes | Blocks regulated deployments | Out of scope; state it in README |

Resolved:

1. License: Apache-2.0, switched in this PR with a NOTICE file.
2. Audit for the POC: log sink only.
3. GitHub Enterprise Server: out of scope for the POC.
4. Action reference form: root `action.yml`, `dist/` committed.
5. Single GitHub App in the POC with the memory selector.

Nothing else is blocking. Marketplace listing for the action can be decided
when M6 lands.

## Sources checked for platform facts

- Workers limits (CPU 10 ms free / 30 s default paid up to 5 min; 50 vs
  10,000 subrequests; 5 KB secrets; 128 MB): developers.cloudflare.com/workers/platform/limits/
- Queues limits (24 h max `delaySeconds`, 128 KB messages, Free plan
  supported): developers.cloudflare.com/queues/platform/limits/
- Workers Traces status (beta, OTel-compatible, billed from 2026-10-01):
  developers.cloudflare.com/workers/observability/traces/
- SQLite Durable Objects and alarms on the Free plan since 2025-04-07:
  developers.cloudflare.com/changelog/product/durable-objects/
- Secrets Store (open beta, `secrets_store_secrets` binding):
  developers.cloudflare.com/secrets-store/integrations/workers/
- WebCrypto RS256 and `timingSafeEqual` (Workers-only extension):
  developers.cloudflare.com/workers/runtime-apis/web-crypto/
- Wrangler `rules` (Text modules), `build.command`, queues, observability,
  `limits.cpu_ms`: developers.cloudflare.com/workers/wrangler/configuration/
- R2 S3 API extensions page references conditional headers on `PutObject`
  without specifying them: developers.cloudflare.com/r2/api/s3/extensions/
- Lambda: "The total size of all environment variables doesn't exceed 4 KB":
  docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html
- Node 20 removed from GitHub Actions runners 2026-09-23; `node24` required:
  github.blog/changelog/2026-09-23-node-20-is-no-longer-available-in-github-actions/
- `@actions/core` `getIDToken(audience)` and `setSecret`:
  github.com/actions/toolkit/blob/main/packages/core/README.md
- Hono 4.13.9 ships adapters `aws-lambda` (`handle`, `streamHandle`), `bun`,
  `cloudflare-workers`, `cloudflare-pages`, `deno`, `lambda-edge`, `netlify`,
  `service-worker`, `vercel` (`handle`); `hono/adapter` exports `env` and
  `getRuntimeKey` (verified from the published package).
- `@cloudflare/vitest-plugin` 1.2.6 and `@cloudflare/vitest-pool-workers`
  0.22.0 both pin `vitest ^4.1.0`; `cloudflare:test` exports `SELF`, `env`,
  queue and DO helpers, and no `fetchMock` (verified from the tarball).
- `typescript-eslint` 8.70.1 peer range `typescript >=4.8.4 <6.1.0`
  (verified from the registry).
- `universal-github-app-jwt` README: WebCrypto accepts PKCS#8 only.
- `re2js` 2.8.6: RE2 port, linear time, Go `regexp` parity claim.
- npm versions on 2026-09-25: wrangler 4.139.0, hono 4.13.9,
  @hono/node-server 2.1.1, jose 6.2.12, yaml 2.9.1, re2js 2.8.6, zod 4.6.5,
  aws4fetch 1.0.20, @actions/core 3.0.1, esbuild 0.28.2, pnpm 12.6.0, eslint
  10.11.0, typescript-eslint 8.70.1, eslint-plugin-import-x 4.17.1,
  eslint-plugin-boundaries 7.2.0, prettier 3.9.9, knip 6.38.0, lefthook
  2.1.14, typescript 6.0.3 (latest 6.x), vitest 5.0.1 (unsupported by the
  Cloudflare plugin), typescript 7.0.2 (unsupported by typescript-eslint).
