# GitHub Webhook Bridge for OpenClaw

A small, security-focused HTTP bridge that receives GitHub webhook deliveries, verifies GitHub's HMAC signature, applies repository/event policy, and forwards approved events to an OpenClaw Generic HTTP Hook.

The bridge is intended to run locally on the VM. nginx exposes only the exact public endpoint `/hooks/github` and routes it directly to the bridge, bypassing the exe-auth gate for this machine-to-machine webhook. The bridge, not nginx, is responsible for authenticating GitHub.

## Status

The Go bridge is deployed as a systemd service. For the configured repository, it accepts issue opened/closed/reopened/labeled/unlabeled events and issue-comment created events. Pull-request comments and other event actions are acknowledged but not forwarded.

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

- `202 Accepted`: signature and policy accepted; the delivery was queued or identified as a duplicate
- `400 Bad Request`: malformed request, missing required header, invalid JSON, or unsupported content type
- `401 Unauthorized`: missing or invalid GitHub signature
- `403 Forbidden`: valid signature but repository/event/action is not allowed
- `202 Accepted`: duplicate delivery; response body is `{"status":"ignored_duplicate"}`
- `413 Content Too Large`: body exceeds configured limit
- `405 Method Not Allowed`: method is not POST

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

The GitHub webhook secret must be loaded from a protected secret file, never from the URL, source code, or a checked-in configuration file.

## Policy enforcement

The bridge enforces an exact repository allowlist from `GHB_ALLOWED_REPOSITORIES` and a built-in event/action allowlist:

- `issues`: `opened`, `closed`, `reopened`, `labeled`, `unlabeled`
- `issue_comment`: `created` for issues only (pull-request comments are ignored)
- `pull_request`: `opened`, `closed`

The repository is validated from `repository.full_name` in the signed payload; the event header alone is not sufficient for authorization. Events/actions outside the allowlist are acknowledged with `202` and ignored, so selecting the broad Issues and Issue comments event categories in GitHub does not create failed deliveries for unrelated actions. GitHub's `ping` delivery is also acknowledged without starting an agent run.

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

The full GitHub payload is not forwarded. The bridge sends bounded issue metadata, the changed label name, and (for a new issue comment) up to 4,000 Unicode characters of comment text. The comment is explicitly marked as untrusted content; issue/comment text must never be treated as instructions.

## Reliability and duplicate handling

The bridge uses SQLite as both a durable delivery queue and the source of truth for idempotency.

When a valid, policy-approved webhook is received:

1. Verify the HMAC signature and payload policy.
2. Insert the delivery into SQLite with status `pending`.
3. Return `202 Accepted` immediately, targeting a sub-30ms local processing path.
4. Let a background goroutine claim and process pending deliveries.

The worker forwards approved summaries to OpenClaw with exponential backoff:

- Retry 1: 5 seconds.
- Retry 2: 15 seconds.
- Retry 3: 45 seconds.
- After the third retry: mark the delivery `failed`.

A duplicate `X-GitHub-Delivery` ID that already exists in SQLite returns:

```http
HTTP/1.1 202 Accepted
Content-Type: application/json
```

```json
{"status":"ignored_duplicate"}
```

It must not return `409 Conflict`, because that can cause confusing redelivery status in GitHub's delivery log.

The SQLite delivery record should include only bounded operational data:

- Delivery ID.
- Received timestamp.
- Event name.
- Repository.
- Action.
- Processing status.
- Attempt count.
- Next-attempt timestamp.
- Last error classification.
- Completed/failed timestamp.

Full GitHub payloads must not be stored or forwarded by default.
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

The implementation should use protected secret files, not inline environment values, for credentials. Proposed configuration:

```text
GHB_LISTEN_ADDR=127.0.0.1:8003
GHB_GITHUB_SECRET_FILE=/etc/github-hookbridge/github-webhook-secret
GHB_OPENCLAW_URL=http://127.0.0.1:8001/hooks/agent
GHB_OPENCLAW_TOKEN_FILE=/etc/github-hookbridge/openclaw-hooks-token
GHB_ALLOWED_REPOSITORIES=owner/repository
GHB_MAX_BODY_BYTES=1048576
GHB_FORWARD_TIMEOUT=5s
GHB_DB_PATH=/var/lib/github-hookbridge/deliveries.sqlite3
GHB_LOG_LEVEL=info
```

The event/action policy is fixed in the application configuration and must allow only:

- `issues`: `opened`, `closed`, `reopened`
- `issue_comment`: `created`
- `pull_request`: `opened`, `closed`

Secrets must be readable only by the `ghbridge` service user. They must never appear in the URL, source code, checked-in configuration, or ordinary logs.

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

A system service will be added after the implementation is tested. It will:

- Run as an unprivileged dedicated user named `ghbridge`.
- Start after networking and OpenClaw.
- Restart on failure with a bounded restart delay.
- Have a private writable state directory.
- Read secrets from protected files such as `/etc/github-hookbridge/github-webhook-secret` with `0600` permissions.
- Set a restrictive `UMask`.
- Use basic systemd hardening appropriate for the deployment.

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

The first implementation should use the pure-Go SQLite driver `modernc.org/sqlite` so the bridge remains a CGO-free static binary. SQLite is required in V1 for durable deduplication and the asynchronous task queue.

## Repository layout

- `main.go`: HTTP server, GitHub verification, SQLite queue, worker, and OpenClaw forwarding.
- `main_test.go`: signature, policy, deduplication, and forwarding tests.
- `deploy/github-hookbridge.service`: systemd system-service template.
- `deploy/nginx-hooks-github.conf`: exact nginx location for `/hooks/github`.

## Local development

Create protected development secret files and configure at least one allowed repository:

```bash
mkdir -p /tmp/github-hookbridge-secrets
umask 077
printf '%s\n' 'development-github-secret' > /tmp/github-hookbridge-secrets/github
printf '%s\n' 'development-openclaw-token' > /tmp/github-hookbridge-secrets/openclaw

GHB_GITHUB_SECRET_FILE=/tmp/github-hookbridge-secrets/github \\
GHB_OPENCLAW_TOKEN_FILE=/tmp/github-hookbridge-secrets/openclaw \\
GHB_ALLOWED_REPOSITORIES=owner/repo \\
GHB_DB_PATH=/tmp/github-hookbridge.sqlite3 \\
go run .
```

Build and test:

```bash
go test ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o github-hookbridge .
```

### GitHub setup and dry-run verification

The bridge is currently deployed in production mode. It verifies GitHub signatures, applies the repository/event policy, and forwards the trimmed payload to the OpenClaw Gateway. Set `GHB_DRY_RUN=true` only when performing a controlled pre-production inspection; dry-run does not call OpenClaw.

### Configure a repository webhook

1. Open the target repository on GitHub.
2. Go to **Settings** → **Webhooks** → **Add webhook**.
3. Set **Payload URL** to:

   ```text
   https://doi-agent-home.exe.xyz/hooks/github
   ```

4. Set **Content type** to `application/json`.
5. In **Secret**, enter the content of the protected VM file:

   ```text
   /etc/github-hookbridge/github-webhook-secret
   ```

   On the VM console, inspect it with:

   ```bash
   sudo cat /etc/github-hookbridge/github-webhook-secret
   ```

   Do not paste this secret into chat, Git, the URL, or a shell history file.

6. Leave **Enable SSL verification** enabled.
7. Select **Let me select individual events** and enable the events currently supported by the production design:

   - Issues
   - Issue comments
   - Pull requests

   The dry-run receiver also accepts GitHub's signed `ping` delivery, which GitHub sends when the webhook is created.
8. Leave **Active** enabled and click **Add webhook**.

GitHub's repository webhook creation flow is documented in [Creating webhooks](https://docs.github.com/en/webhooks/using-webhooks/creating-webhooks).

### Confirm delivery in GitHub

After saving the webhook:

1. Open the webhook again from **Settings** → **Webhooks**.
2. Open **Recent deliveries**.
3. Click a delivery GUID to inspect the request headers, request payload, timestamp, and response received from the bridge.
4. A successful dry-run delivery should have an HTTP `202` response and a body similar to:

   ```json
   {"status":"dry_run_logged"}
   ```

GitHub keeps recent delivery details for three days. Failed deliveries are not automatically redelivered; an administrator can use **Redeliver** from the delivery details page. See [Redelivering webhooks](https://docs.github.com/en/webhooks/testing-and-troubleshooting-webhooks/redelivering-webhooks).

### Inspect logs on the VM

Service lifecycle and error logs:

```bash
sudo systemctl status github-hookbridge.service
sudo journalctl -u github-hookbridge.service -f
```

The complete verified request bodies are stored as JSON Lines with mode `0600`:

```text
/var/lib/github-hookbridge/webhooks.jsonl
```

For supported production events, the exact trimmed JSON request that would be sent to OpenClaw is stored separately:

```text
/var/lib/github-hookbridge/openclaw.jsonl
```

Dry-run mode never sends this recorded request to OpenClaw.

Useful commands:

```bash
# Show the most recent received webhook
sudo tail -n 1 /var/lib/github-hookbridge/webhooks.jsonl | jq .

# Show the most recent trimmed OpenClaw request
sudo tail -n 1 /var/lib/github-hookbridge/openclaw.jsonl | jq .

# Follow newly received webhook bodies
sudo tail -f /var/lib/github-hookbridge/webhooks.jsonl | jq .

# Check the file permissions
sudo stat -c '%A %U:%G %n' /var/lib/github-hookbridge/webhooks.jsonl
```

The JSONL payload files described above are only written when `GHB_DRY_RUN=true`. In production mode, delivery history and retry state are retained in SQLite for seven days; full webhook payloads are not retained.


The following decisions are finalized for the initial implementation.


### Target events and actions

- `issues`: `opened`, `closed`, `reopened`
- `issue_comment`: `created`
- `pull_request`: `opened`, `closed`

All other events and actions are rejected.

### Allowed repositories

The payload field `repository.full_name` must match an exact allowlist configured through `GHB_ALLOWED_REPOSITORIES`, using values such as `owner/repo`.

### Forwarding architecture

Processing is fully asynchronous. After HMAC verification, policy validation, and insertion into SQLite with status `pending`, the bridge returns `202 Accepted` immediately. A background goroutine processes pending tasks and forwards them to OpenClaw.

Forwarding failures use exponential backoff at 5 seconds, 15 seconds, and 45 seconds, with a maximum of three retries. After the final failure, the delivery is marked `failed`.

### Duplicate deliveries

If a delivery ID already exists in SQLite, the bridge returns `202 Accepted` with:

```json
{"status":"ignored_duplicate"}
```

The bridge does not return `409 Conflict` for duplicates.

### Payload formatting

Summary mode is mandatory. Full raw GitHub payloads are never forwarded by default. The bridge emits only bounded structural data:

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

### Storage and dependencies

SQLite is required in V1 for durable deduplication and the asynchronous queue. The implementation will use the pure-Go `modernc.org/sqlite` driver to avoid CGO dependencies and produce a CGO-free static binary.

### OpenClaw upstream

The target endpoint is:

```text
http://127.0.0.1:8001/hooks/agent
```

The bridge uses a fixed configured `agentId`, such as `main`, and a dedicated OpenClaw hook token. Payloads cannot select an arbitrary agent or session.

### Service and deployment

The bridge will run as a systemd system service under the unprivileged dedicated user `ghbridge`. Secrets are read strictly from protected files, for example:

```text
/etc/github-hookbridge/github-webhook-secret
```

Secret files must have `0600` permissions and be readable only by the service account.

### Retention and maintenance

Delivery history and operational records are retained in SQLite for seven days. The daemon runs a daily cleanup routine. Full webhook payloads are not retained.

Implementation may now proceed against this specification.
