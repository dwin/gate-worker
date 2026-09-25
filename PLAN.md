# GATE on Cloudflare Workers: POC plan

Status: proposal, 2026-09-25. Nothing here is built yet.

Upstream: [thomsonreuters/gate](https://github.com/thomsonreuters/gate) at commit
`958af7c` (2026-09-03, "Support nested claim paths in policy conditions").
Everything below about upstream behaviour was read from that commit's source,
not from the README alone.

## 1. Recommendation in one paragraph

Rewrite the core of GATE in TypeScript on the Workers runtime rather than
compiling the Go code to WASM. The security-relevant core (OIDC validation,
two-layer authorizer, GitHub App client, app selector, audit contract) is about
1,500 lines of Go. The remaining ~18,000 lines are Go-server plumbing (Viper,
Cobra, chi, GORM, AWS SDK, OTel SDK, Helm, Terraform) that Workers replaces
with platform primitives. Keep the public API, error codes, config schema, and
trust-policy schema byte-for-byte compatible so upstream docs and fixtures stay
valid. Reuse upstream's 44 trust-policy YAML fixtures and its ~80 integration
test names as the parity checklist. The POC is done when a real GitHub Actions
workflow exchanges its OIDC token at the Worker and uses the returned
installation token against a real repository.

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

## 3. Go → Workers mapping

| Upstream component | Go implementation | Workers implementation | Notes |
|---|---|---|---|
| HTTP server, routing, middleware | chi + httpin + render, 6 custom middlewares | Hono 4.x with built-in `secure-headers`, `body-limit`, `request-id`, `timeout`, `trailing-slash` | Hono ships all six equivalents; no custom middleware needed except origin-verify |
| Config | Viper: YAML file + `GATE_*` env overrides | Central policy YAML imported as a Text module at build time, validated at first request with the same rules; secrets from Worker secrets | Keeps the upstream YAML schema verbatim. Env overrides become `vars` in `wrangler.jsonc` |
| GitHub App private key | PEM file on disk, PKCS#1 or PKCS#8 | Worker secret (5 KB limit; RSA-4096 PEM is ~3.2 KB) | WebCrypto imports PKCS#8 only. GitHub downloads PKCS#1. Wrap PKCS#1 DER in the fixed PKCS#8 header at runtime (~25 lines) so both formats work like upstream |
| OIDC validation | coreos/go-oidc + jwx | `jose` 6.x: `decodeJwt` (unverified, for `iss`), discovery doc via `fetch` + Cache API, `createRemoteJWKSet` + `jwtVerify` | Same allowlist-before-network order. JWKS cache is per-isolate; Cache API gives cross-request reuse per colo |
| Regex engine | Go `regexp` (RE2 syntax, linear time) | `re2js` 2.8.x | See §4.3. This is a security decision, not a preference |
| YAML | gopkg.in/yaml.v3 | `yaml` 2.x | |
| GitHub client | google/go-github + golang-jwt + retry transport | Thin `fetch` client, 5 endpoints, same retry/backoff policy, same 2 s token-ready delay | See §4.4 for why not Octokit |
| Installation-ID cache | in-memory, 24 h, 1000 entries | In-isolate `Map` L1 + Cache API L2 | |
| Contents-token cache | in-memory, 5 min expiry buffer | In-isolate `Map` only | Short-lived credential; do not persist beyond the isolate |
| Policy cache | in-memory, 5 min, 500 entries, singleflight | In-isolate `Map` + Cache API, in-isolate promise dedupe | |
| App selector state | memory / Redis / DynamoDB | POC: in-isolate memory (upstream's own default). Phase 2: one Durable Object holding per-app rate-limit state | DO gives the strongly consistent `IsFresherThan` write semantics upstream implements for Redis/DynamoDB |
| Token tracker + revocation loop | in-memory map + 1-minute goroutine | Cloudflare Queue with `delaySeconds = ttl`; consumer calls `DELETE /installation/token` | See §4.6 |
| Audit | console / Postgres / DynamoDB | POC: structured `console.log` to Workers Logs. Phase 2: D1 table with the upstream column set | Granted entries must be awaited before responding; denied entries go through `ctx.waitUntil`. Same semantics as upstream |
| Observability | OTel SDK, OTLP/gRPC | Workers Logs (GA) + Workers Traces (beta, OTel-compatible export) + Analytics Engine for the four counters | See §4.7 |
| FIPS 140-3 | Go crypto module | Not available | `/api/v1/info` returns `{"fips_enabled":false}`. Hard gap for FedRAMP-style deployments |
| Origin verification | shared-secret header | Same middleware, `crypto.subtle.timingSafeEqual` | Optional; on Cloudflare the stronger control is Access service tokens or mTLS |
| Timeouts | read/write/idle/request | `AbortSignal.timeout()` per subrequest, Hono `timeout()`, `limits.cpu_ms` | |
| Deployment | Docker, Helm, Terraform | `wrangler deploy`, GitHub Actions with `cloudflare/wrangler-action` | |

## 4. Design decisions and rejected alternatives

### 4.1 TypeScript rewrite, not Go→WASM

Rejected: compiling upstream with TinyGo or standard Go to WASM. The Go code
depends on `net/http` server semantics, goroutines with tickers, `os.ReadFile`,
Viper's filesystem search, and the AWS/Redis/GORM SDKs. None of that runs on
workerd. Stripping it leaves the ~1,500-line core, which is faster to rewrite
than to make WASM-clean, and the result would still be a larger, slower bundle
with an awkward JS shim for `fetch`. The rewrite also gets first-class access
to Cache API, Queues, Durable Objects, and D1.

### 4.2 Hono as the router

Rejected: bare `fetch` handler with a `switch`. Three routes barely need a
router, but upstream has six middlewares, and Hono provides equivalents for all
of them out of the box, plus a testable `app.request()` surface. Hono is the
de-facto standard on Workers and is tiny.

### 4.3 `re2js` instead of native `RegExp`

This matters more than it looks. Trust policies are authored by repository
owners (upstream trust boundary TB6, treated as semi-trusted). Upstream
evaluates their patterns with Go's RE2 engine, which guarantees linear time.
Native JS `RegExp` backtracks, so a policy pattern like `(a+)+$` becomes a
CPU-exhaustion vector against the Worker, and on the Free plan it trips the
10 ms CPU cap. Separately, RE2 and ECMAScript regex syntax differ (`(?P<n>)`,
`\z`, no lookaround in RE2, different Unicode class names). Using native
`RegExp` would silently change which policies match. `re2js` is a pure-JS port
of RE2 that claims parity with Go's `regexp`, runs on workerd without WASM, and
is actively maintained (v2.8.6, July 2026). The fixture
`complex_regex_patterns.tpl.yaml` is the first test to run against it.

Rejected: native `RegExp` with a timeout wrapper. There is no way to interrupt
a running native regex in JS.

### 4.4 Thin GitHub client instead of Octokit

GATE needs exactly five GitHub endpoints: find org installation, find user
installation, create installation token, get contents, rate limit, plus revoke
token. Upstream's retry policy (retry every 4xx/5xx, 4 attempts, 2/4/8 s) is
deliberate and GitHub-support-informed; replicating it precisely is easier with
a 150-line `fetch` wrapper than by configuring Octokit's plugin retry. Octokit
also needs a PKCS#8 key and does not do the PKCS#1 conversion itself. The thin
client takes `fetch` as a constructor argument, which is also how the tests
inject a fake GitHub (the Workers Vitest integration removed `fetchMock` in
0.22, so global mocking is no longer an option anyway).

### 4.5 Config: keep the upstream YAML schema

`config.yaml` is imported as a Text module (`rules: [{type: "Text", globs:
["**/*.yaml"]}]`) and parsed once per isolate. Validation ports
`internal/config/*.go` rule-for-rule so an upstream config file is valid here
too, with three fields ignored (`server.*`, `aws_region`, `fips.*`) and
`github_apps[].private_key_path` replaced by `private_key_secret`, the name of
the Worker secret holding the PEM. Runtime overrides that upstream took from
`GATE_*` env vars come from `vars` in `wrangler.jsonc`.

Rejected: storing config in KV. Adds a subrequest and eventual consistency to
every cold start for no benefit at POC scale; a config change should be a
deploy.

### 4.6 Token revocation via Queues

Workers has no background goroutine. Three options were considered:

- Cron Trigger every minute + D1 table of pending tokens. Works, but polls, and
  needs D1 before the POC otherwise needs it.
- Durable Object with an alarm. Strongly consistent, but a single DO becomes a
  serialization point for every issued token.
- Queue message per issued token with `delaySeconds = effective TTL`, consumer
  revokes. Max delay is 24 h; upstream's default `max_token_ttl` is 1 h. Retries
  and a dead-letter queue come free. Available on the Free plan.

Queues is the recommendation. Trade-off to state plainly: the raw token sits
in the queue at rest until delivery. Upstream holds it in process memory. Any
durable design must store the raw token because `DELETE /installation/token`
authenticates with the token itself. Cloudflare encrypts queue storage at rest;
that is the accepted residual for the POC. Note that the response `expires_at`
is capped to the TTL exactly as upstream does, so from the client's view the
contract is unchanged whether or not revocation succeeds.

### 4.7 Observability without the OTel SDK

Rejected: `@microlabs/otel-cf-workers`. It has been a release candidate since
2024 and last published May 2025. Not a foundation to build on.

Use Workers Logs for structured JSON (one line per exchange, same fields as
upstream's `logExchange`), Workers Traces (beta, `observability.traces.enabled`,
OTel-compatible, exportable to Honeycomb/Grafana/Axiom, billed from
2026-10-01) for spans named identically to upstream (`TokenExchange`,
`ValidateOIDC`, `EvaluatePolicy`, `SelectApp`, `MintInstallationToken`), and
Analytics Engine for the four counters/histogram. Analytics Engine is
appropriate for metrics; it is not appropriate for audit (see 4.8).

### 4.8 Audit: console first, D1 second, never Analytics Engine

Analytics Engine samples under load and has no exact-row retrieval; an audit
log that can drop rows is not an audit log. D1 gives the upstream schema
(`internal/db/migrations/postgres`) almost verbatim in SQLite. The POC ships
console audit, which is also upstream's default. D1 is the first post-POC
item, and the blocking-on-granted semantics are preserved from day one by
routing every write through an `AuditBackend` interface.

### 4.9 Plan tier

Start on Workers Free. RS256 sign and verify are native WebCrypto and cost
low single-digit milliseconds each; YAML and `re2js` parsing are small; retry
sleeps are wall time, not CPU. The 10 ms CPU cap is probably enough but
marginal. Expect to move to Paid ($5/month, 30 s default CPU, raisable) before
any load testing. Nothing in the design changes between tiers.

## 5. Proposed repository layout

```
gate-worker/
  wrangler.jsonc               # bindings, rules, triggers, observability, limits
  config.yaml                  # central policy (upstream schema)
  package.json                 # pnpm; scripts: dev, test, typecheck, lint, deploy
  tsconfig.json
  vitest.config.ts             # @cloudflare/vitest-plugin, configPath wrangler.jsonc
  src/
    index.ts                   # export default { fetch, queue }
    app.ts                     # Hono app, middleware chain, routes
    config/
      schema.ts                # types mirroring internal/config
      load.ts                  # parse YAML text module, validate, memoize per isolate
    oidc/
      validator.ts             # allowlist → discovery → JWKS → verify → Claims
      discovery.ts             # Cache-API-backed openid-configuration fetch
    authorizer/
      index.ts                 # authorize(): central then repository
      central.ts               # required/forbidden claims, time window
      policy.ts                # PolicyFile types + validate() (ports policy.go)
      match.ts                 # explicit/automatic match, rule evaluation
      permission.ts            # levels, denied-permission list, resolve()
      fetch.ts                 # policy fetch + cache + dedupe
      errors.ts                # DenialError + every ErrorCode string
      claims.ts                # lookupClaim with dotted paths
    github/
      client.ts                # thin fetch client, retry transport, caches
      jwt.ts                   # App JWT (RS256), PKCS#1→PKCS#8 wrapper
      errors.ts
    selector/
      selector.ts              # selectApp, recordUsage, retryAfter
      store.ts                 # Store interface; memory impl
    audit/
      types.ts                 # AuditEntry + validate()
      console.ts
    sts/
      service.ts               # exchange(): orchestrates everything
      errors.ts                # ExchangeError, code→HTTP status map
      revoke.ts                # queue producer + consumer
    http/
      exchange.ts              # handler
      info.ts, health.ts
      origin-verify.ts
    util/
      cache.ts                 # L1 Map + Cache API helper with TTL
      hash.ts                  # sha256 hex with "sha256:" prefix
      singleflight.ts
  test/
    fixtures/policies/         # upstream's 44 YAML files, verbatim, Apache header kept
    harness/
      oidc.ts                  # in-test RSA keypair, discovery+JWKS responder, signToken()
      github.ts                # fake GitHub: installations, tokens, contents, rate_limit
      server.ts                # builds the app with injected fetch + fixture config
    unit/                      # pure-function tests (authorizer, permission, config)
    integration/               # one file per upstream integration test file
  .github/workflows/
    checks.yml                 # typecheck, lint, test
    deploy.yml                 # wrangler-action on main
  PLAN.md
```

`wrangler.jsonc` sketch:

```jsonc
{
  "name": "gate",
  "main": "src/index.ts",
  "compatibility_date": "2026-09-01",
  "compatibility_flags": ["nodejs_compat"],
  "rules": [{ "type": "Text", "globs": ["**/*.yaml"], "fallthrough": false }],
  "vars": { "GATE_LOGGER_LEVEL": "info" },
  "queues": {
    "producers": [{ "queue": "gate-revoke", "binding": "REVOKE" }],
    "consumers": [{ "queue": "gate-revoke", "max_retries": 5, "dead_letter_queue": "gate-revoke-dlq" }]
  },
  "observability": { "enabled": true, "traces": { "enabled": true } },
  "limits": { "cpu_ms": 30000 }
}
```

Secrets: `wrangler secret put GATE_APP_<CLIENT_ID>_KEY` per app, and
`GATE_ORIGIN_HEADER_VALUE` if origin verification is on.

## 6. Milestones

Each milestone ends with green CI. "Done when" is the acceptance test.

### M0: Scaffold (½ day)

pnpm, TypeScript 5.x, Hono, Wrangler 4.x, `@cloudflare/vitest-plugin` 1.x with
Vitest 4.x (the plugin pins `^4.1.0`; Vitest 5 is out but unsupported), ESLint,
GitHub Actions `checks.yml`. Routes: `/health`, `/api/v1/info`. Middleware
chain: trailing-slash, request-id, secure-headers, body-limit 1 MB, timeout.

Done when: `wrangler dev` serves both routes with the upstream security
headers, and one Vitest test runs inside workerd via `SELF.fetch`.

### M1: Config and trust-policy schema (1 day)

Port `internal/config/{policy,oidc,origin,github_apps}.go` validation and
`internal/sts/authorizer/policy.go`. Copy upstream's fixture directory
verbatim.

Done when: every `*.yaml` fixture without a `.tpl` suffix that upstream expects
to fail (`missing_*`, `invalid_*`, `wrong_*`, `duplicate_policy_names`,
`empty_rules`) fails validation with the same message class, and `valid.yaml`
passes.

### M2: Authorizer (1 day)

Port `authorizer.go`, `provider.go`, `match.go`, `permission.go`, `claims`
lookup, with `re2js` for every pattern. Pure functions; no I/O. Policy fetch
is behind an interface so this milestone needs no GitHub.

Done when: unit tests cover the upstream test names under `TestEvaluation_*`,
`TestExplicit_*`, `TestPermission_*`, `TestTTL_*`, `TestParsing_*` using the
`.tpl.yaml` fixtures with `{{ISSUER_URL}}` substituted, and the full
`deniedPermissions` list rejects with `NON_REPOSITORY_PERMISSION`.

### M3: OIDC validator (1 day)

`jose` + discovery + Cache API. Port `internal/testutil/oidc.go` to a test
harness that generates an RSA keypair per run and answers discovery and JWKS
through the injected `fetch`.

Done when: `TestOIDC_*` (11 cases: valid, expired, not-yet-valid, future iat,
wrong audience, multiple audiences, untrusted issuer, malformed, missing
claims, missing subject succeeds, additional claims) pass, and the untrusted
issuer test asserts that the injected `fetch` was never called.

### M4: GitHub client, exchange service, handler (2 days)

Thin client with retry transport, PKCS#1/PKCS#8 import, installation and
contents-token caches, token-ready delay (configurable to 0 in tests). Port
`test/integration/harness/github.go` to a fake GitHub that records calls,
serves fixture policies at the configured path, and can be told to return
401/403/404/422/5xx on demand. Wire `sts/service.ts` and the handler.

Done when: `TestSuccess_*`, `TestDiscovery_*`, `TestGitHub_*`,
`TestRepository_*` pass end-to-end through `SELF.fetch`, every documented
`error_code` is produced by at least one test with the documented HTTP status,
and `TestDiscovery_ConcurrentRequests` shows one policy fetch for N parallel
requests to the same repo.

### M5: Revocation, audit, first real deploy (1 day)

Queue producer on grant, consumer calling revoke, DLQ. Console audit backend
with the upstream `AuditEntry.Validate()` rules. Deploy to a dev account with
one GitHub App installed on one test org.

Done when: a GitHub Actions workflow in a test repo with a trust policy runs
`curl -X POST https://<worker>/api/v1/exchange` with its `ACTIONS_ID_TOKEN`
(audience `gate`), receives a `ghs_` token, reads a file from the repo with it,
and after the TTL the same token returns 401. That last assertion proves the
revocation path, which is the one piece Workers could not inherit from
upstream.

### M6: Post-POC hardening (not in POC scope, listed so it is not forgotten)

- D1 audit backend with upstream's schema; granted writes awaited.
- Durable Object selector store for multiple Apps per org.
- Secrets Store binding (`secrets_store_secrets`, open beta) instead of
  per-Worker secrets, so keys are managed account-wide.
- Analytics Engine metrics; traces export to the team's collector.
- Cloudflare Access service-token or mTLS in front of `/api/v1/*`.
- GitHub Enterprise Server: `github_api_base_url` is already in the schema;
  test it.
- Load test on Paid tier; measure p99 including the 2 s token-ready delay.

Total POC estimate: about 7 working days for one engineer familiar with
Workers, plus GitHub App setup time.

## 7. Test strategy

Upstream's integration suite is the specification. Its fixtures are YAML and
language-neutral; its test names encode the behaviour matrix. The plan is to
carry both across so a reviewer can diff the two suites by name.

- Fixtures copied verbatim under `test/fixtures/policies/`, Apache-2.0 header
  retained.
- Fakes are injected as a `fetch` function, never installed globally. This is
  forced by the removal of `fetchMock` from `cloudflare:test` in
  `@cloudflare/vitest-pool-workers` 0.22 and is the better design regardless.
- Integration tests run inside workerd through `SELF.fetch` so Cache API,
  Queues (`createMessageBatch` / `getQueueResult`), and `waitUntil`
  (`waitOnExecutionContext`) behave as in production.
- One regex-parity test compiles every pattern in every fixture with `re2js`
  and asserts it compiles, and asserts that a known catastrophic-backtracking
  pattern completes in bounded time.

## 8. Risks and open questions

| Risk | Impact | Mitigation |
|---|---|---|
| `re2js` semantics diverge from Go `regexp` on some construct | Policy matches differ from upstream | Parity test over all fixture patterns; both engines are RE2-syntax, divergence should be zero |
| Free-plan 10 ms CPU cap | 5xx under cold start or large policy files | Measure in M4; move to Paid |
| Worst-case latency: 4 retries × up to 10 s + 2 s ready delay per GitHub call | Client timeouts on GitHub incidents | Same as upstream; document `--max-time` for clients; consider lowering `MaxBackoff` |
| PKCS#1 key import | Deploy-time failure | Runtime wrapper + a unit test with a real PKCS#1 fixture key generated in-test |
| 6 simultaneous outbound connections per request | None; the exchange path is sequential | |
| Raw token at rest in the queue | Residual per §4.6 | Accept for POC; revisit with DO + encryption if required |
| Secret size 5 KB per Worker secret | RSA-4096 PEM is ~3.2 KB, fits | Secrets Store later |
| No FIPS | Blocks regulated deployments | Out of scope; state it in README |
| Workers Traces is beta and becomes billable 2026-10-01 | Cost surprise | Head sampling; keep logs as the primary signal |

Decisions I need from you:

1. Licensing. This repo is MIT; upstream is Apache-2.0. A port that copies
   upstream fixtures verbatim and mirrors its logic should either be
   Apache-2.0 (my recommendation, removes all ambiguity) or carry a `NOTICE`
   file and keep the Apache header on every copied file.
2. Single GitHub App in the POC (memory selector, as above) or multi-App from
   the start (pulls the Durable Object into M4).
3. Console audit for the POC or D1 from the start (adds about a day).
4. Whether GitHub Enterprise Server is a target; it changes nothing in the
   design but adds a test matrix entry.

Absent answers I will proceed with Apache-2.0, single App, console audit, and
github.com only.

## Sources checked for platform facts

- Workers limits (CPU 10 ms free / 30 s default paid up to 5 min; 50 vs
  10,000 subrequests; 5 KB secrets; 128 MB): developers.cloudflare.com/workers/platform/limits/
- Queues limits (24 h max `delaySeconds`, 128 KB messages, Free plan
  supported): developers.cloudflare.com/queues/platform/limits/
- Workers Traces status (beta, OTel-compatible, billed from 2026-10-01):
  developers.cloudflare.com/workers/observability/traces/
- SQLite Durable Objects and alarms on the Free plan since 2025-04-07:
  developers.cloudflare.com/changelog/product/durable-objects/
- Secrets Store (open beta, `secrets_store_secrets` binding, `await
  env.X.get()`): developers.cloudflare.com/secrets-store/integrations/workers/
- WebCrypto RS256 sign/verify and `timingSafeEqual`:
  developers.cloudflare.com/workers/runtime-apis/web-crypto/
- Cron Triggers support `* * * * *`: developers.cloudflare.com/workers/configuration/cron-triggers/
- `@cloudflare/vitest-pool-workers` 0.22.0 and `@cloudflare/vitest-plugin`
  1.2.6 both pin `vitest ^4.1.0`; `cloudflare:test` 0.22 exports `SELF`, `env`,
  `createExecutionContext`, `waitOnExecutionContext`, queue and DO helpers, and
  no `fetchMock` (verified from the published tarball).
- `universal-github-app-jwt` README: WebCrypto accepts PKCS#8 only; PKCS#1
  must be converted.
- `re2js` 2.8.6 (github.com/le0pard/re2js): RE2 port, linear time, Go
  `regexp` parity claim.
- npm versions on 2026-09-25: wrangler 4.139.0, hono 4.13.9, jose 6.2.12,
  yaml 2.9.1, re2js 2.8.6, vitest 5.0.1 (unsupported by the CF plugin),
  typescript 7.0.2.
