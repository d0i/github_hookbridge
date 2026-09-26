# GitHub Hook Bridge v2 design

## Goal

Treat webhooks as invalidation hints, not as instructions or data to execute. OpenClaw should be woken once after a short burst for an issue, then read the current issue from GitHub using the authenticated `gh` CLI. No issue title, body, comment, label value, or raw webhook body is stored or forwarded by the bridge.

## Trusted ingress and normalization

1. Accept only `POST /hooks/github` with JSON and a bounded body.
2. Verify GitHub's HMAC-SHA256 signature over the exact raw bytes.
3. Deduplicate `X-GitHub-Delivery` in SQLite.
4. Accept only the configured repositories and these event/action pairs:
   - `issues.opened`, `issues.closed`, `issues.reopened`, `issues.labeled`, `issues.unlabeled`
   - `issue_comment.created`
5. Reject pull-request comments by checking the issue's `pull_request` field.
6. Normalize to an allowlisted repository, positive integer issue number, canonical URL, fixed event name, and `sender.login`. Never use a webhook-provided URL as a fetch target.
7. If `sender.login` case-insensitively matches `GHB_IGNORED_SENDERS`, record the delivery as ignored and do not modify any issue window. Production is configured with `d0i-agent`.

Unknown events/actions and `ping` are acknowledged but do not wake the agent. A disallowed repository remains a 403 policy rejection.

## Per-issue state machine

The key is the normalized `owner/repo#issue_number`. Each issue has at most one durable state row:

```text
IDLE --first accepted event--> COLLECTING
COLLECTING --quiet deadline first--> enqueue one URL+event batch, return to IDLE
COLLECTING --storm deadline first--> QUARANTINED until now+quarantine duration
QUARANTINED --incoming event--> increment suppression count, do not extend timer
QUARANTINED --expiry--> remove active window, retain interval tombstone
post-expiry event --> COLLECTING; late in-interval request --> remain suppressed
```

`quiet deadline = last_seen + quiet_window`; `storm deadline = first_seen + storm_window`. The acceptance timestamp is assigned only after HMAC/policy validation and while holding the same state lock used by the timer worker. This is the linearization point for ordering ingress against a deadline: if a timer wins the lock, a waiting event starts a new window; if the event wins, the timer sees it before deciding. If both deadlines are due when the worker runs, compare their actual deadline times: the earlier one wins; an exact tie favors quiet/flush. Thus a sustained stream never causes a flush at the storm threshold.

All state is persisted in SQLite so process restarts do not reset a storm timer or quarantine. Request handling only verifies, writes a compact row, and returns 202; a worker advances timers and sends the outbox. The outbox retries definite OpenClaw admission rejections with configurable backoff. Its replay key is carried in the JSON body, not an HTTP idempotency header that could cause Go's transport to replay a POST. A transport failure that may have occurred after admission, or a bridge restart during an in-flight request, becomes `uncertain` and is not automatically replayed. Webhook bodies are never written to logs or SQLite.

Quarantine is fixed-duration, not sliding: incoming events do not extend it. They are counted only for operational diagnosis. A separate interval-history table suppresses all webhooks first received during the noisy batch and quarantine, retaining that receive-time interval through the receipt-retention period. Thus a request received during quarantine but delayed on SQLite until after expiry is still suppressed—even if a fresh post-expiry window has already started. Accumulated events are discarded; only a new post-expiry event can begin a new window. Repeated storms can be observed and optionally escalated to an operator without waking the agent.

## Agent notification and current-state fetch

Each successful window produces a single v2 message containing:

- `[github-hookbridge:v2]` routing marker
- canonical issue URL
- sorted, deduplicated event names
- fixed instruction to fetch current state with `gh` and follow `AGENT.md`

No sender, body, title, label value, comment text, or full payload is included. The bridge derives the URL from the configured repository and issue number. The agent uses the fixed allowed repository, for example:

```bash
gh issue view 123 --repo d0is/00_HomeProject \
  --json title,body,state,labels,assignees,comments,updatedAt
```

All fetched GitHub content remains untrusted input. Existing `AGENT.md` rules determine whether an action is warranted.

The OpenClaw hook payload uses `sessionMode: isolated`, `deliver: false`, `agentId: main`, and a stable logical session key `github:issue:<repo>:<number>`. Gateway configuration enables request session keys but restricts their prefix to `github:issue:` (plus `hook:` for generated keys). This serializes runs for the same issue without reusing conversation context or announcing results into the main session; different issues remain independent.

## Sender loop suppression

The agent's GitHub writes use the dedicated `d0i-agent` account. The bridge excludes that exact login from aggregation, case-insensitively. This is a hard ingress filter, not merely an instruction in the system prompt. Human actions remain eligible because humans use a different account. The code default is `d0i-agent`; `GHB_IGNORED_SENDERS` is a comma-separated override and can be explicitly set empty to disable the filter.

## Configuration

All durations parse Go duration strings and must be positive (storm window must exceed quiet window):

| Variable | Default | Purpose |
|---|---:|---|
| `GHB_QUIET_WINDOW` | `10s` | Quiet period required to flush a batch |
| `GHB_STORM_WINDOW` | `60s` | Continuous activity threshold; trips quarantine, never flushes |
| `GHB_QUARANTINE_DURATION` | `600s` | Fixed per-issue suppression period |
| `GHB_WORKER_POLL_INTERVAL` | `250ms` | Timer/outbox worker cadence |
| `GHB_FORWARD_TIMEOUT` | `25s` | OpenClaw admission request deadline |
| `GHB_RETRY_DELAYS` | `5s,15s,45s` | Retry delays after the initial attempt |
| `GHB_RECEIPT_RETENTION` | `168h` | Delivery/outbox/tombstone cleanup retention |
| `GHB_HTTP_READ_HEADER_TIMEOUT` | `10s` | Incoming header timeout |
| `GHB_HTTP_READ_TIMEOUT` | `15s` | Incoming request timeout |
| `GHB_HTTP_WRITE_TIMEOUT` | `15s` | HTTP response timeout |
| `GHB_HTTP_IDLE_TIMEOUT` | `60s` | Keep-alive timeout |
| `GHB_MAX_BODY_BYTES` | `1048576` | Maximum webhook body |

`GHB_IGNORED_SENDERS` is a comma-separated login list; the default and production value is `d0i-agent`. Set it to an empty string only to disable sender suppression. `GHB_RETRY_DELAYS` may be changed to another comma-separated list of positive durations. The production values are in `/etc/default/github-hookbridge`.

If an OpenClaw admission has an ambiguous transport outcome, or the bridge restarts while a request is in flight, its outbox row becomes `uncertain` and is not automatically replayed. This prevents a bridge restart from waking the same agent twice; inspect the OpenClaw run before manually requeuing an uncertain batch.

## SQLite v2 tables

- `delivery_receipts`: delivery ID, timestamp, normalized repository/issue key, fixed event label, and disposition only.
- `issue_windows`: collecting/quarantined active state, timestamps, event-name set, and suppression counters.
- `issue_quarantines`: received-time suppression intervals retained through the receipt-retention period.
- `notification_jobs`: bounded URL/event prompt, retry/admission state (including `uncertain`), and batch idempotency key.

The v2 storage layout uses `PRAGMA user_version=3`; incompatible/unversioned v2 databases and databases containing the legacy `deliveries` table are rejected. Use a fresh, separate database path. The legacy v1 database is not read, written, or cleaned by v2; it may contain v1 summary/comment data. Raw webhook payloads and issue text are not stored in any v2 table.
