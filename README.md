# GitHub Webhook Bridge for OpenClaw

A small, security-focused HTTP bridge that receives GitHub webhook deliveries, verifies GitHub's HMAC signature, applies repository/event policy, and forwards approved events to an OpenClaw Generic HTTP Hook.

The bridge is intended to run locally on the VM. nginx exposes only the exact public endpoint `/hooks/github` and routes it directly to the bridge, bypassing the exe-auth gate for this machine-to-machine webhook. The bridge, not nginx, is responsible for authenticating GitHub.

## Status

This repository currently contains the design specification only. Implementation is planned in Go.

## Why a bridge is needed

OpenClaw Generic HTTP Hooks authenticate callers with an OpenClaw hook token. GitHub webhooks authenticate deliveries with an HMAC signature in `X-Hub-Signature-256`. These are different protocols, so GitHub should not be connected directly to an OpenClaw hook unless an intermediary translates and verifies the request.

The bridge will:

1. Accept the GitHub request with its raw body.
2. Verify `X-Hub-Signature-256` using the configured GitHub webhook secret.
3. Enforce repository and event policy.
4. Reject duplicate delivery IDs.
5. Convert the event into a bounded OpenClaw message.
6. Forward the message to OpenClaw over loopback using a separate OpenClaw hook token.

## Planned topology

```text
GitHub
  | HTTPS via exe.dev proxy
  v
nginx :80/:8000
  | exact location: /hooks/github
  v
GitHub Hook Bridge 127.0.0.1:8003
  | localhost HTTP, Authorization: Bearer <OpenClaw hook token>
  v
OpenClaw Gateway 127.0.0.1:8001
  | /hooks/agent or a named hook mapping
  v
OpenClaw agent
```

All paths other than the exact GitHub webhook path will continue to go through:

```text
nginx -> exe-auth-proxy :8002 -> OpenClaw :8001
```

## Goals

- Verify GitHub webhook authenticity before any OpenClaw call.
- Keep the public surface limited to one exact endpoint.
- Keep GitHub and OpenClaw credentials separate.
- Avoid exposing the OpenClaw Gateway port directly.
- Prevent arbitrary callers from selecting an OpenClaw agent or session.
- Provide bounded retries, timeouts, structured logs, and health checks.
- Make duplicate delivery handling explicit and testable.
- Keep the service small enough to audit and operate as a systemd service.

## Non-goals

- General-purpose workflow automation.
- Full GitHub API integration.
- Executing commands based directly on GitHub payload content.
- Treating issue/PR/comment text as trusted instructions.
- Replacing OpenClaw's authorization or agent/tool policy.
- Supporting arbitrary user-selected OpenClaw `agentId` or `sessionKey` values.

## Public HTTP contract

### `POST /hooks/github`

This is the only public webhook endpoint.

Required headers:

- `X-Hub-Signature-256: sha256=<hex digest>`
- `X-GitHub-Delivery: <delivery UUID>`
- `X-GitHub-Event: <event name>`
- `Content-Type: application/json`

Accepted request properties:

- HTTP method: `POST` only
- Content type: `application/json` (optional charset parameters may be accepted)
- Maximum body size: configurable, with a conservative default such as 1 MiB
- Valid UTF-8 JSON object

Response behavior:

- `202 Accepted`: signature and policy accepted; forwarding is queued or completed according to implementation mode
- `400 Bad Request`: malformed request, missing required header, invalid JSON, or unsupported content type
- `401 Unauthorized`: missing or invalid GitHub signature
- `403 Forbidden`: valid signature but repository/event/action is not allowed
- `409 Conflict`: duplicate delivery that was already accepted
- `413 Content Too Large`: body exceeds configured limit
- `405 Method Not Allowed`: method is not POST
- `502 Bad Gateway` or `503 Service Unavailable`: accepted delivery could not be forwarded and no durable queue is available

The exact status policy must be finalized before implementation, particularly whether an already-seen delivery is returned as `202` for GitHub retry friendliness or `409` for observability.

### `GET /healthz`

Local/service health endpoint. It must not expose secrets or configuration. It may report process health only.

The endpoint should be bound to loopback and need not be exposed through nginx.

### Optional `GET /readyz`

Reports whether the bridge can reach the configured OpenClaw upstream. This is useful for systemd/operator diagnostics but is not a GitHub endpoint.

## GitHub verification

The bridge must verify the signature against the exact raw request bytes:

```text
expected = HMAC-SHA256(github_webhook_secret, raw_request_body)
```

It must compare the received digest and expected digest using a constant-time comparison. It must not parse and re-serialize JSON before verification.

The bridge must reject:

- Missing `X-Hub-Signature-256`.
- Unsupported signature format.
- Non-`sha256` algorithms.
- Invalid hexadecimal digest.
- Signature mismatch.
- Missing delivery ID or event header.

The GitHub webhook secret must be loaded from an environment variable or root-readable secret file, never from the URL, source code, or a checked-in configuration file.

## Policy enforcement

The initial implementation should support explicit allowlists:

- `GITHUB_ALLOWED_REPOSITORIES`: exact `owner/name` values.
- `GITHUB_ALLOWED_EVENTS`: exact event names.
- `GITHUB_ALLOWED_ACTIONS`: optional per-event action allowlist.

At minimum, the bridge must validate the payload's `repository.full_name` against the repository allowlist. Header values alone are not sufficient for authorization.

The bridge should support an optional sender allowlist only if there is a clear operational need. Repository and event policy are the primary controls.

## OpenClaw forwarding

The bridge must use a dedicated OpenClaw hook token. It must never reuse:

- The OpenClaw Gateway control/UI token.
- The GitHub webhook secret.
- Any exe.dev authentication credential.

The upstream URL should default to a loopback address, for example:

```text
http://127.0.0.1:8001/hooks/agent
```

The forwarded request should use:

```http
Authorization: Bearer <dedicated OpenClaw hooks token>
Content-Type: application/json
```

The bridge must use a fixed configured OpenClaw `agentId` and a fixed session-key policy. Payload fields must not be allowed to override either value.

The bridge should send a deliberately bounded message, for example:

```json
{
  "name": "github",
  "event": "issues",
  "deliveryId": "...",
  "repository": "owner/repository",
  "action": "opened",
  "sender": "octocat",
  "summary": "Issue #123 opened: Example title",
  "payload": {
    "number": 123,
    "url": "https://github.com/owner/repository/issues/123"
  }
}
```

The full GitHub payload should not be forwarded by default. If full payload forwarding is required, it must be explicitly enabled and remain subject to size limits and prompt-injection handling.

## Reliability and duplicate handling

GitHub can retry deliveries. The bridge must use `X-GitHub-Delivery` as an idempotency key.

Initial implementation options:

1. SQLite-backed delivery table for durable deduplication.
2. Small local state file only if the service is explicitly best-effort.
3. In-memory cache is insufficient as the sole mechanism because restarts lose history.

Recommended initial design: SQLite with a bounded retention period, storing only:

- Delivery ID.
- Received timestamp.
- Event name.
- Repository.
- Processing status.
- Optional error classification.

Do not store full webhook payloads unless specifically required.

Forwarding behavior must define:

- Connect timeout.
- Request timeout.
- Maximum retry count.
- Backoff strategy.
- Whether retries can cause duplicate OpenClaw invocations.
- Whether accepted events survive a process restart.

For the first version, a synchronous forward with short bounded retries may be sufficient. A durable queue can be added if GitHub delivery volume or reliability requirements justify it.

## Security requirements

- Listen on `127.0.0.1` only.
- Expose only `/hooks/github` through nginx.
- Use an exact nginx location match, not a broad `/hooks` public prefix.
- Set request-body and header-size limits.
- Reject unexpected methods and content types.
- Do not log secrets, signatures, authorization headers, or complete payloads.
- Redact issue/comment/PR text from ordinary logs.
- Use constant-time signature comparison.
- Do not trust GitHub payload text as executable instructions.
- Do not allow payload-controlled URLs to be fetched by the bridge.
- Do not allow payload-controlled OpenClaw agent/session/tool selection.
- Use a separate Unix/systemd service user if practical.
- Keep the bridge's outbound network access limited to localhost if practical.
- Ensure the OpenClaw hook token is readable only by the service user.
- Rotate GitHub and OpenClaw hook secrets independently.
- Keep nginx, bridge, and OpenClaw logs free of credential material.

GitHub source IP filtering may be considered as defense in depth, but it must not replace HMAC verification because GitHub's published address ranges can change.

## Configuration proposal

The implementation should use environment variables or an `EnvironmentFile` managed by systemd. Proposed names:

```text
GHB_LISTEN_ADDR=127.0.0.1:8003
GHB_GITHUB_SECRET_FILE=/etc/github-hookbridge/github-webhook-secret
GHB_OPENCLAW_URL=http://127.0.0.1:8001/hooks/agent
GHB_OPENCLAW_TOKEN_FILE=/etc/github-hookbridge/openclaw-hooks-token
GHB_ALLOWED_REPOSITORIES=owner/repository
GHB_ALLOWED_EVENTS=issues,issue_comment,pull_request
GHB_ALLOWED_ACTIONS_FILE=/etc/github-hookbridge/actions.json
GHB_MAX_BODY_BYTES=1048576
GHB_FORWARD_TIMEOUT=5s
GHB_DB_PATH=/var/lib/github-hookbridge/deliveries.sqlite3
GHB_LOG_LEVEL=info
```

Secrets should preferably be supplied through protected files rather than inline environment values, because environment values can be exposed by diagnostics or process inspection.

## nginx integration plan

The nginx configuration should add an exact location before the catch-all location:

```nginx
location = /hooks/github {
    proxy_pass http://127.0.0.1:8003;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering on;
    proxy_read_timeout 10s;
    proxy_send_timeout 10s;
}
```

The existing catch-all location must continue to proxy to `127.0.0.1:8002`, preserving exe-auth for all other paths.

Before reload:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

The bridge must be running and listening before the nginx route is enabled.

## systemd integration plan

A user or system service will be added only after the implementation is tested. The service should:

- Start after networking and OpenClaw.
- Restart on failure with a bounded restart delay.
- Use a restricted service user where possible.
- Have a private writable state directory.
- Read secrets from protected files.
- Set a restrictive `UMask`.
- Use basic systemd hardening appropriate for the chosen deployment.

The deployment procedure must include a rollback path for both the systemd unit and nginx configuration.

## Testing plan

Unit tests:

- Valid GitHub signature.
- Missing signature.
- Wrong secret.
- Wrong algorithm.
- Malformed signature.
- Modified raw body.
- Missing delivery/event headers.
- Repository allow/deny behavior.
- Event/action allow/deny behavior.
- Duplicate delivery behavior.
- Body-size limit.
- OpenClaw timeout and error handling.
- Secret values absent from logs.

Integration tests:

- Start the bridge on loopback.
- Send a locally signed GitHub-style request.
- Verify the bridge forwards only approved events to a fake OpenClaw server.
- Verify nginx routes `/hooks/github` to the bridge.
- Verify ordinary paths still reach exe-auth.
- Verify unauthenticated browser access to ordinary paths remains protected.

Manual GitHub test:

- Configure a test repository webhook with a dedicated secret.
- Use GitHub's `ping` delivery and one selected event.
- Inspect delivery status and bridge logs.
- Test GitHub redelivery and confirm idempotency behavior.

## Implementation choice

Go is the recommended implementation language because this service is a small long-running HTTP daemon with:

- Strong standard-library support for HTTP, HMAC, constant-time comparison, JSON, and timeouts.
- A straightforward static binary deployment.
- Low memory use.
- Easy systemd integration.
- Good support for table-driven unit tests.

The first implementation should prefer the Go standard library and a small SQLite dependency only if durable deduplication is included.

## Open decisions before implementation

1. Which GitHub events and actions are required initially?
2. Which repository or repositories are allowed?
3. Should forwarding be synchronous or queued?
4. Should duplicate deliveries return `202` or `409`?
5. Is full payload forwarding required, or is a summarized message sufficient?
6. Should SQLite deduplication be included in version one?
7. Which OpenClaw hook endpoint and fixed agent/session policy should be used?
8. Should the bridge be a user service or a system service?
9. What retention period is acceptable for delivery IDs and operational logs?

Implementation should not begin until these choices are confirmed or sensible defaults are explicitly accepted.
