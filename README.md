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
- The OpenClaw session key is stable per issue while each run stays isolated. OpenClaw serializes requests with the same logical session key, avoiding concurrent runs for one issue. The bridge's SQLite writes/timer decisions are globally serialized; distinct issue sessions do not share agent context.
- An ambiguous upstream transport failure or bridge restart during an OpenClaw admission is marked `uncertain`, not automatically replayed. This favors avoiding duplicate agent runs; an operator can inspect the gateway before manually requeueing.
- OpenClaw's replay key is sent in the JSON body, not an HTTP idempotency header, to prevent Go's HTTP transport from automatically replaying a POST on a reused connection.

Defaults are a 10-second quiet window, 60-second storm window, and 600-second quarantine. The decision is per issue; one noisy issue does not block others.

**Deadline example:** with events at 0s and 8s, the last event's quiet deadline is 18s, so one batch is queued at about 18s. If events keep arriving every 9s, the quiet deadline keeps moving; at 60s the storm deadline arrives before quiet, so the batch is discarded and quarantine begins. A tie between quiet and storm deadlines favors quiet/flush.

The worker checks due windows every `GHB_WORKER_POLL_INTERVAL` (250ms by default), so a deadline decision is normally up to one poll late, plus database/queue contention. It compares the actual quiet and storm deadlines; if they tie, quiet wins. Timer processing and event acceptance share a state lock. `first_seen_ms`/`last_seen_ms` are set at the serialized acceptance point; `first_received_ms` preserves ingress time for quarantine filtering. This prevents a concurrent timer tick and SQLite write from applying contradictory ordering.

## Request and delivery timeouts

`GHB_HTTP_READ_HEADER_TIMEOUT`, `GHB_HTTP_READ_TIMEOUT`, `GHB_HTTP_WRITE_TIMEOUT`, and `GHB_HTTP_IDLE_TIMEOUT` configure the inbound Go HTTP server (defaults 10s, 15s, 15s, and 60s). Request bodies are capped by `GHB_MAX_BODY_BYTES` (1 MiB default). These are separate from the issue debounce/quarantine windows.

`GHB_FORWARD_TIMEOUT` (25s by default) limits the bridge's HTTP request to OpenClaw. It covers admission of the hook request, **not the model's full run time**; the bridge does not wait for agent completion. Known pre-admission failures (dial/DNS or non-2xx admission responses) use `GHB_RETRY_DELAYS` (5s, 15s, 45s; initial attempt plus three retries). A transport failure whose result is ambiguous, or a bridge restart while a job is in flight, marks the job `uncertain` and suppresses automatic replay. Check OpenClaw before manually requeueing an uncertain job.

The SQLite driver's busy timeout is fixed at 5s, the graceful HTTP shutdown deadline is fixed at 10s, and receipt/quarantine cleanup runs hourly. Receipts and quarantine intervals expire after `GHB_RECEIPT_RETENTION` (168h); sent/failed outbox rows use the same retention. `uncertain` rows are retained for operator review.

## Webhook response behavior

- `202`: accepted into the issue window, duplicate delivery, ignored sender, ignored event/action, ignored pull-request comment, or quarantined event.
- `400`: malformed headers/body or invalid event shape.
- `401`: missing/invalid HMAC signature.
- `403`: repository is not allowlisted.
- `413`: body exceeds the configured limit.
- `405`: non-POST method.
- `500`: SQLite/queue persistence failed; no success is acknowledged.

The bridge only returns success after recording an accepted/ignored delivery in SQLite. Ping and unsupported signed events are acknowledged without an agent run.

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
GHB_HTTP_READ_HEADER_TIMEOUT=10s
GHB_HTTP_READ_TIMEOUT=15s
GHB_HTTP_WRITE_TIMEOUT=15s
GHB_HTTP_IDLE_TIMEOUT=60s
```

The code default for ignored senders is `d0i-agent`; explicitly set `GHB_IGNORED_SENDERS=` only if that filter should be disabled. The V2 schema is versioned; legacy V1 databases and unversioned V2 candidates are rejected, so configure a separate, fresh `GHB_DB_PATH`. See `DESIGN.md` for the state machine and the full configuration list. The production environment file is `/etc/default/github-hookbridge`.

OpenClaw hooks are restricted to `agentId: main` and accept only request session keys with the `github:issue:` prefix. The v2 marker is injected by the `github-hook-instructions` plugin, which loads the operator-maintained private `AGENT.md` as system context and blocks matching runs if that file cannot be read.

## Operations

```bash
sudo systemctl status github-hookbridge.service
sudo journalctl -u github-hookbridge.service -f
sudo sqlite3 /var/lib/github-hookbridge/deliveries-v2.sqlite3 '.tables'
sudo sqlite3 -header -column /var/lib/github-hookbridge/deliveries-v2.sqlite3 \
  "SELECT state,COUNT(*) FROM issue_windows GROUP BY state;"
sudo sqlite3 -header -column /var/lib/github-hookbridge/deliveries-v2.sqlite3 \
  "SELECT status,COUNT(*) FROM notification_jobs GROUP BY status;"
sudo sqlite3 -header -column /var/lib/github-hookbridge/deliveries-v2.sqlite3 \
  "SELECT event_name,outcome,COUNT(*) FROM delivery_receipts GROUP BY event_name,outcome;"
sudo sqlite3 -header -column /var/lib/github-hookbridge/deliveries-v2.sqlite3 \
  "SELECT id,issue_key,attempts,last_error FROM notification_jobs WHERE status='uncertain';"
```

These diagnostics omit issue/comment text and the stored agent prompt.

The service listens on loopback at `127.0.0.1:8003`; nginx must retain the exact-match `/hooks/github` route. The bridge runs as the unprivileged `ghbridge` user with `dry_run=false` in production.

With `GHB_DRY_RUN=true`, signature/policy checks, SQLite coalescing, and quarantine still run, but due jobs are recorded as handled without calling OpenClaw. Dry-run logs only the batch ID and issue key; it does not log or persist the incoming payload or agent message.

## Development

```bash
go test -race ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o github-hookbridge .
```

The pre-v2 implementation is preserved by the local `v1.0.0` tag. V2 is a breaking change to notification semantics and SQLite tables; production uses a new `deliveries-v2.sqlite3` file. The v1 database is kept separately and is not read or cleaned by v2; it may contain older v1 summaries/payload data.
