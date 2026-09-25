# gate-worker

A port of [thomsonreuters/gate](https://github.com/thomsonreuters/gate)
(GitHub Authenticated Token Exchange) to Cloudflare Workers.

GATE is a Security Token Service that exchanges OIDC tokens from trusted
identity providers (for example GitHub Actions) for short-lived, repository-scoped
GitHub App installation tokens, governed by a central policy and per-repository
trust policies.

Status: planning. See [PLAN.md](PLAN.md) for the proof-of-concept plan,
the Go to Workers component mapping, design decisions, and milestones.
