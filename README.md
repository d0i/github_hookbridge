# GitHub Webhook Bridge for OpenClaw — v2

The bridge receives GitHub issue webhooks, verifies the GitHub HMAC signature, and coalesces events by issue before notifying OpenClaw. It never sends issue text, comment text, labels, or titles to the agent. The agent receives a canonical issue URL plus a set of event names, fetches current state with `gh`, and follows the private `AGENT.md` instructions.

## Production path

```text
GitHub -> exe.dev proxy -> nginx exact /hooks/github
       -> github-hookbridge (127.0.0.1:8003, ghbridge)
       -> SQLite issue window/outbox -> OpenClaw POST /hooks/agent
       -> main agent, isolated per-issue session
```

`/hooks/github` is the only public webhook route. The bridge verifies `X-Hub-Signature-256`, exact repository, supported event/action, and sender policy before aggregation. Raw request bodies are never logged or persisted.

## Supported activity

- `issues`: `opened`, `closed`, `reopened`, `labeled`, `unlabeled`
- `issue_comment`: `created` for Issues; comments attached to pull requests are ignored
- Other signed events/actions and GitHub's `ping` are acknowledged without starting an agent run
- Events from ignored senders (default: `d0i-agent`) are recorded as ignored and never enter an issue window; `GHB_IGNORED_SENDERS` overrides the default

In repository webhook settings, select **Issues** and **Issue comments**. The bridge applies the narrower action policy above.

The agent notification is deliberately minimal:

```text
[github-hookbridge:v2]
Issue: <canonical GitHub issue URL>
Observed events: issue_comment.created, issues.labeled

Fetch the current issue state and relevant comments with gh, then follow AGENT.md...
```

The URL is reconstructed from the repository allowlist and positive issue number; it is never copied from arbitrary webhook text. Issue content fetched later by the agent remains untrusted.

## Coalescing and storm circuit breaker

- A delivery UUID is idempotent for seven days.
- Events for the same canonical `owner/repo#number` are merged in a persistent SQLite window.
- A batch is sent only after the issue has been quiet for `GHB_QUIET_WINDOW`.
- If the storm deadline arrives before the quiet deadline, the pending batch is discarded and that issue key is quarantined. It is **not** flushed at the storm deadline.
- Events received during quarantine are discarded; they do not extend the deadline and are not replayed after expiry. A fresh event after expiry starts a new window.
- The expired quarantine marker is retained long enough to suppress requests that began during quarantine but waited on SQLite until after the deadline.
- The OpenClaw session key is stable per issue while each run stays isolated. OpenClaw serializes requests with the same logical session key, avoiding concurrent runs for one issue while allowing different issues to proceed independently.
- An ambiguous upstream transport failure or bridge restart during an OpenClaw admission is marked `uncertain`, not automatically replayed. This favors avoiding duplicate agent runs; an operator can inspect the gateway before manually requeueing.
- OpenClaw's replay key is sent in the JSON body, not an HTTP idempotency header, to prevent Go's HTTP transport from automatically replaying a POST on a reused connection.

Defaults are a 10-second quiet window, 60-second storm window, and 600-second quarantine. The decision is per issue; one noisy issue does not block others.

## Configuration

Secrets remain in protected files. Timing, dedupe policy, ignored senders, body limits, HTTP timeouts, retry delays, and retention are environment-configurable:

```text
GHB_QUIET_WINDOW=10s
GHB_STORM_WINDOW=60s
GHB_QUARANTINE_DURATION=600s
GHB_IGNORED_SENDERS=d0i-agent
GHB_WORKER_POLL_INTERVAL=250ms
GHB_FORWARD_TIMEOUT=25s
GHB_RETRY_DELAYS=5s,15s,45s
GHB_RECEIPT_RETENTION=168h
```

The code default for ignored senders is `d0i-agent`; explicitly set `GHB_IGNORED_SENDERS=` only if that filter should be disabled. The V2 schema is versioned; legacy V1 databases and unversioned V2 candidates are rejected, so configure a separate, fresh `GHB_DB_PATH`. See `DESIGN.md` for the state machine and the full configuration list. The production environment file is `/etc/default/github-hookbridge`.

OpenClaw hooks are restricted to `agentId: main` and accept only request session keys with the `github:issue:` prefix. The v2 marker is injected by the `github-hook-instructions` plugin, which loads the operator-maintained private `AGENT.md` as system context and blocks matching runs if that file cannot be read.

## Operations

```bash
sudo systemctl status github-hookbridge.service
sudo journalctl -u github-hookbridge.service -f
sudo sqlite3 /var/lib/github-hookbridge/deliveries-v2.sqlite3 '.tables'
```

The service listens on loopback at `127.0.0.1:8003`; nginx must retain the exact-match `/hooks/github` route. The bridge runs as the unprivileged `ghbridge` user with `dry_run=false` in production.

## Development

```bash
go test -race ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o github-hookbridge .
```

The pre-v2 implementation is preserved by the local `v1.0.0` tag. V2 is a breaking change to notification semantics and SQLite tables; production uses a new `deliveries-v2.sqlite3` file. The v1 database is kept separately and is not read or cleaned by v2; it may contain older v1 summaries/payload data.
