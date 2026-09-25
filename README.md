# gate-worker

A TypeScript port of [thomsonreuters/gate](https://github.com/thomsonreuters/gate)
(GitHub Authenticated Token Exchange) built on Hono, with Cloudflare Workers as
the first-class target and a portable core that also runs on Node, Bun, AWS
Lambda, and Vercel.

GATE is a Security Token Service that exchanges OIDC tokens from trusted
identity providers (for example GitHub Actions) for short-lived, repository-scoped
GitHub App installation tokens, governed by a central policy and per-repository
trust policies.

This repository will contain three packages:

- `packages/core`: the runtime-agnostic exchange logic and ports.
- `packages/server`: the Hono app, platform adapters, and entry points.
- `packages/action`: a GitHub Action so workflows can call the service with
  one `uses:` line.

Audit is logging first, with optional object-store writing that targets the
S3 API and therefore works with both R2 and S3.

Status: planning. See [PLAN.md](PLAN.md) for the proof-of-concept plan, the
upstream behaviour it preserves, the port and adapter design, design decisions
with rejected alternatives, and milestones.

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE); this project
derives from GATE, which is Copyright 2026 Thomson Reuters under the same
license.
