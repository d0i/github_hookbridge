package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testBridge(t *testing.T) *Bridge {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "deliveries.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Bridge{
		cfg: Config{
			GitHubSecret:        []byte("github-secret"),
			OpenClawToken:       "openclaw-token",
			OpenClawAgentID:     "main",
			AllowedRepositories: map[string]struct{}{"owner/repo": {}},
			MaxBodyBytes:        1 << 20,
			ForwardTimeout:      2 * time.Second,
		},
		db:     db,
		client: &http.Client{},
		log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func signedRequest(t *testing.T, bridge *Bridge, body []byte, delivery, event string) *httptest.ResponseRecorder {
	t.Helper()
	mac := hmac.New(sha256.New, bridge.cfg.GitHubSecret)
	_, _ = mac.Write(body)
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-GitHub-Delivery", delivery)
	req.Header.Set("X-GitHub-Event", event)
	rec := httptest.NewRecorder()
	bridge.handler(rec, req)
	return rec
}

func TestVerifySignature(t *testing.T) {
	body := []byte(`{"ok":true}`)
	mac := hmac.New(sha256.New, []byte("secret"))
	_, _ = mac.Write(body)
	valid := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !verifySignature(body, valid, []byte("secret")) {
		t.Fatal("valid signature rejected")
	}
	if verifySignature(body, valid, []byte("wrong")) {
		t.Fatal("invalid signature accepted")
	}
}

func TestWebhookQueuesAndDeduplicates(t *testing.T) {
	bridge := testBridge(t)
	body := []byte(`{"action":"opened","number":123,"repository":{"full_name":"owner/repo","html_url":"https://github.com/owner/repo"},"sender":{"login":"octocat"},"issue":{"number":123,"title":"Example","html_url":"https://github.com/owner/repo/issues/123"}}`)
	first := signedRequest(t, bridge, body, "delivery-1", "issues")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status = %d, want 202: %s", first.Code, first.Body.String())
	}
	second := signedRequest(t, bridge, body, "delivery-1", "issues")
	if second.Code != http.StatusAccepted || !bytes.Contains(second.Body.Bytes(), []byte("ignored_duplicate")) {
		t.Fatalf("duplicate response = %d %s", second.Code, second.Body.String())
	}
	var count int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM deliveries`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("delivery count = %d, want 1", count)
	}
}

func TestWebhookRejectsDisallowedAction(t *testing.T) {
	bridge := testBridge(t)
	body := []byte(`{"action":"edited","repository":{"full_name":"owner/repo"},"sender":{"login":"octocat"}}`)
	rec := signedRequest(t, bridge, body, "delivery-2", "issues")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestDryRunAcceptsAndLogsAnySignedEvent(t *testing.T) {
	bridge := testBridge(t)
	bridge.cfg.DryRun = true
	bridge.cfg.DryRunLogFile = filepath.Join(t.TempDir(), "webhooks.jsonl")
	body := []byte(`{"zen":"Keep it logically awesome.","repository":{"full_name":"owner/repo"}}`)
	rec := signedRequest(t, bridge, body, "ping-1", "ping")
	if rec.Code != http.StatusAccepted || !bytes.Contains(rec.Body.Bytes(), []byte("dry_run_logged")) {
		t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
	}
	logged, err := os.ReadFile(bridge.cfg.DryRunLogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(logged, body) {
		t.Fatalf("body not found in dry-run log: %s", logged)
	}
}
func TestDryRunRecordsTrimmedOpenClawPayload(t *testing.T) {
	bridge := testBridge(t)
	bridge.cfg.DryRun = true
	bridge.cfg.DryRunLogFile = filepath.Join(t.TempDir(), "webhooks.jsonl")
	bridge.cfg.DryRunOutboundLogFile = filepath.Join(t.TempDir(), "openclaw.jsonl")
	body := []byte(`{"action":"opened","number":123,"repository":{"full_name":"owner/repo"},"sender":{"login":"octocat"},"issue":{"number":123,"title":"Example","html_url":"https://github.com/owner/repo/issues/123"}}`)
	rec := signedRequest(t, bridge, body, "issues-1", "issues")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("response = %d %s", rec.Code, rec.Body.String())
	}
	outbound, err := os.ReadFile(bridge.cfg.DryRunOutboundLogFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"openclaw_request"`, `"agentId":"main"`, `"sessionMode":"isolated"`, `"repository":"owner/repo"`, `"action":"opened"`, `[github-hookbridge:v1]`} {
		if !bytes.Contains(outbound, []byte(want)) {
			t.Fatalf("outbound log missing %s: %s", want, outbound)
		}
	}
	if bytes.Contains(outbound, []byte(`"issue"`)) {
		t.Fatal("outbound log contains raw issue payload")
	}
}
func TestForwardUsesFixedOpenClawSettings(t *testing.T) {
	var got http.Request
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	bridge := testBridge(t)
	bridge.cfg.OpenClawURL = upstream.URL
	summary := githubSummary{Name: "github", Event: "issues", DeliveryID: "delivery-3", Repository: "owner/repo", Action: "opened", Sender: "octocat", Summary: "Example", Payload: map[string]any{"number": float64(1)}}
	payload, _ := json.Marshal(summary)
	if err := bridge.forward(context.Background(), delivery{ID: "delivery-3", Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if got.Header.Get("Authorization") != "Bearer openclaw-token" {
		t.Fatalf("authorization = %q", got.Header.Get("Authorization"))
	}
	if !bytes.Contains(gotBody, []byte(`[github-hookbridge:v1]\nExample`)) {
		t.Fatalf("GitHub hook marker missing: %s", gotBody)
	}
}
