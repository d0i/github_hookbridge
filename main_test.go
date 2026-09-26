package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		GitHubSecret:        []byte("github-secret"),
		OpenClawToken:       "openclaw-token",
		OpenClawAgentID:     "main",
		AllowedRepositories: map[string]string{"d0is/00_homeproject": "d0is/00_HomeProject", "owner/repo": "owner/repo"},
		IgnoredSenders:      map[string]struct{}{"d0i-agent": {}},
		QuietWindow:         10 * time.Second,
		StormWindow:         60 * time.Second,
		QuarantineDuration:  600 * time.Second,
		WorkerPollInterval:  250 * time.Millisecond,
		ForwardTimeout:      25 * time.Second,
		RetryDelays:         []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second},
		ReceiptRetention:    7 * 24 * time.Hour,
		MaxBodyBytes:        1 << 20,
	}
}

func testBridge(t *testing.T) *Bridge {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "bridge.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Bridge{
		cfg:    testConfig(),
		db:     db,
		client: &http.Client{Timeout: time.Second},
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

func TestWindowDefaults(t *testing.T) {
	for _, key := range []string{"GHB_QUIET_WINDOW", "GHB_STORM_WINDOW", "GHB_QUARANTINE_DURATION"} {
		t.Setenv(key, "")
	}
	quiet, err := durationEnv("GHB_QUIET_WINDOW", defaultQuietWindow)
	if err != nil || quiet != 10*time.Second {
		t.Fatalf("quiet default = %v, err=%v", quiet, err)
	}
	storm, err := durationEnv("GHB_STORM_WINDOW", defaultStormWindow)
	if err != nil || storm != 60*time.Second {
		t.Fatalf("storm default = %v, err=%v", storm, err)
	}
	quarantine, err := durationEnv("GHB_QUARANTINE_DURATION", defaultQuarantine)
	if err != nil || quarantine != 600*time.Second {
		t.Fatalf("quarantine default = %v, err=%v", quarantine, err)
	}
}

func TestDatabaseSchemaIsVersionedAndRejectsUnversionedV2Tables(t *testing.T) {
	freshPath := filepath.Join(t.TempDir(), "fresh.sqlite3")
	db, err := openDB(freshPath)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != currentSchemaVersion {
		t.Fatalf("schema version=%d err=%v", version, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	oldPath := filepath.Join(t.TempDir(), "unversioned.sqlite3")
	old, err := sql.Open("sqlite", oldPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`CREATE TABLE issue_windows(issue_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openDB(oldPath); err == nil || !strings.Contains(err.Error(), "unversioned v2 database") {
		t.Fatalf("unversioned v2 schema error=%v", err)
	}

	legacyPath := filepath.Join(t.TempDir(), "legacy.sqlite3")
	legacy, err := sql.Open("sqlite", legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE deliveries(id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openDB(legacyPath); err == nil || !strings.Contains(err.Error(), "legacy v1 database") {
		t.Fatalf("legacy v1 schema error=%v", err)
	}

	oldCandidatePath := filepath.Join(t.TempDir(), "old-v2.sqlite3")
	oldCandidate, err := sql.Open("sqlite", oldCandidatePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := oldCandidate.Exec(`PRAGMA user_version=2`); err != nil {
		t.Fatal(err)
	}
	if err := oldCandidate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openDB(oldCandidatePath); err == nil || !strings.Contains(err.Error(), "unsupported database schema version") {
		t.Fatalf("old v2 schema error=%v", err)
	}
}

func TestDialFailureIsSafeToRetryButPostConnectFailureIsAmbiguous(t *testing.T) {
	dialErr := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	if !definitelyPreAdmission(dialErr) {
		t.Fatal("dial failure should be safe to retry")
	}
	if definitelyPreAdmission(io.EOF) {
		t.Fatal("EOF after connecting must be treated as ambiguous")
	}
}

func TestLoadConfigTimingAndSenderOverrides(t *testing.T) {
	dir := t.TempDir()
	githubSecret := filepath.Join(dir, "github-secret")
	hookToken := filepath.Join(dir, "openclaw-token")
	if err := os.WriteFile(githubSecret, []byte("github-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hookToken, []byte("openclaw-token"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GHB_GITHUB_SECRET_FILE", githubSecret)
	t.Setenv("GHB_OPENCLAW_TOKEN_FILE", hookToken)
	t.Setenv("GHB_ALLOWED_REPOSITORIES", "d0is/00_HomeProject")
	t.Setenv("GHB_DB_PATH", "")
	t.Setenv("GHB_DRY_RUN", "false")
	t.Setenv("GHB_QUIET_WINDOW", "")
	t.Setenv("GHB_STORM_WINDOW", "")
	t.Setenv("GHB_QUARANTINE_DURATION", "")
	t.Setenv("GHB_IGNORED_SENDERS", " D0I-Agent, another-bot ")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QuietWindow != 10*time.Second || cfg.StormWindow != 60*time.Second || cfg.QuarantineDuration != 600*time.Second {
		t.Fatalf("unexpected defaults: quiet=%s storm=%s quarantine=%s", cfg.QuietWindow, cfg.StormWindow, cfg.QuarantineDuration)
	}
	if !isIgnoredSender(cfg.IgnoredSenders, "d0i-agent") || !isIgnoredSender(cfg.IgnoredSenders, "@ANOTHER-BOT") {
		t.Fatalf("sender overrides were not normalized: %#v", cfg.IgnoredSenders)
	}
	if filepath.Base(cfg.DBPath) != "deliveries-v2.sqlite3" {
		t.Fatalf("default database path=%q", cfg.DBPath)
	}

	t.Setenv("GHB_QUIET_WINDOW", "2s")
	t.Setenv("GHB_STORM_WINDOW", "5s")
	t.Setenv("GHB_QUARANTINE_DURATION", "30s")
	cfg, err = loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.QuietWindow != 2*time.Second || cfg.StormWindow != 5*time.Second || cfg.QuarantineDuration != 30*time.Second {
		t.Fatalf("unexpected overrides: quiet=%s storm=%s quarantine=%s", cfg.QuietWindow, cfg.StormWindow, cfg.QuarantineDuration)
	}
	t.Setenv("GHB_STORM_WINDOW", "1s")
	if _, err := loadConfig(); err == nil {
		t.Fatal("storm window shorter than quiet window should be rejected")
	}
}

func TestIgnoredSenderDefaultsToAgentAndCanBeExplicitlyCleared(t *testing.T) {
	old, existed := os.LookupEnv("GHB_IGNORED_SENDERS")
	if err := os.Unsetenv("GHB_IGNORED_SENDERS"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if existed {
			_ = os.Setenv("GHB_IGNORED_SENDERS", old)
		} else {
			_ = os.Unsetenv("GHB_IGNORED_SENDERS")
		}
	})
	if !isIgnoredSender(ignoredSendersFromEnv(), "D0I-Agent") {
		t.Fatal("d0i-agent must be ignored by default")
	}
	t.Setenv("GHB_IGNORED_SENDERS", "")
	if got := len(ignoredSendersFromEnv()); got != 0 {
		t.Fatalf("explicit empty ignored sender list has %d entries", got)
	}
}

func TestAllowedIssueEventActions(t *testing.T) {
	for _, test := range []struct {
		event  string
		action string
		want   bool
	}{
		{"issues", "opened", true},
		{"issues", "closed", true},
		{"issues", "reopened", true},
		{"issues", "labeled", true},
		{"issues", "unlabeled", true},
		{"issue_comment", "created", true},
		{"issues", "edited", false},
		{"issue_comment", "edited", false},
		{"pull_request", "opened", false},
	} {
		if got := isAllowedAction(test.event, test.action); got != test.want {
			t.Errorf("isAllowedAction(%q,%q)=%t, want %t", test.event, test.action, got, test.want)
		}
	}
}

func TestIssueEventsAreCoalescedAndOnlyNamesForwarded(t *testing.T) {
	bridge := testBridge(t)
	start := time.Unix(1_700_000_000, 0).UTC()
	for _, event := range []issueEvent{
		{DeliveryID: "d1", IssueKey: "owner/repo#12", Repository: "owner/repo", IssueNumber: 12, EventName: "issues.labeled", ReceivedAt: start},
		{DeliveryID: "d2", IssueKey: "owner/repo#12", Repository: "owner/repo", IssueNumber: 12, EventName: "issue_comment.created", ReceivedAt: start.Add(5 * time.Second)},
		{DeliveryID: "d3", IssueKey: "owner/repo#12", Repository: "owner/repo", IssueNumber: 12, EventName: "issues.labeled", ReceivedAt: start.Add(8 * time.Second)},
	} {
		if status, err := bridge.recordIssueEvent(context.Background(), event); err != nil || status != "aggregated" {
			t.Fatalf("record event: status=%q err=%v", status, err)
		}
	}
	if err := bridge.processDueWindows(context.Background(), start.Add(17*time.Second)); err != nil {
		t.Fatal(err)
	}
	var early int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM notification_jobs`).Scan(&early); err != nil || early != 0 {
		t.Fatalf("early notifications=%d err=%v", early, err)
	}
	if err := bridge.processDueWindows(context.Background(), start.Add(18*time.Second)); err != nil {
		t.Fatal(err)
	}
	var message string
	var count int
	if err := bridge.db.QueryRow(`SELECT message,COUNT(*) OVER() FROM notification_jobs`).Scan(&message, &count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("notification count = %d, want 1", count)
	}
	for _, want := range []string{"[github-hookbridge:v2]", "https://github.com/owner/repo/issues/12", "issues.labeled", "issue_comment.created", "AGENT.md"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message %q does not contain %q", message, want)
		}
	}
	for _, forbidden := range []string{"title", "comment body", "label name", "sender"} {
		if strings.Contains(strings.ToLower(message), forbidden) {
			t.Fatalf("message unexpectedly contains %q: %s", forbidden, message)
		}
	}
	var remaining int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM issue_windows`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("remaining issue windows=%d err=%v", remaining, err)
	}
}

func TestStormQuarantinesWithoutFlushingAndDropsUntilExpiry(t *testing.T) {
	bridge := testBridge(t)
	start := time.Unix(1_700_000_000, 0).UTC()
	for i := 0; i <= 6; i++ {
		acceptedAt := start.Add(time.Duration(i*9) * time.Second)
		receivedAt := acceptedAt
		if i == 0 {
			receivedAt = start.Add(-time.Millisecond)
		}
		event := issueEvent{
			DeliveryID: "storm-" + string(rune('a'+i)), IssueKey: "owner/repo#7",
			Repository: "owner/repo", IssueNumber: 7, EventName: "issues.labeled",
			ReceivedAt: receivedAt, AcceptedAt: acceptedAt,
		}
		if _, err := bridge.recordIssueEvent(context.Background(), event); err != nil {
			t.Fatal(err)
		}
	}
	stormAt := start.Add(60 * time.Second)
	if err := bridge.processDueWindows(context.Background(), stormAt); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM notification_jobs`).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 0 {
		t.Fatalf("storm flushed %d jobs; want none", jobs)
	}
	var state string
	var until int64
	var suppressed int64
	if err := bridge.db.QueryRow(`SELECT state,quarantine_until_ms,suppressed_count FROM issue_windows WHERE issue_key='owner/repo#7'`).Scan(&state, &until, &suppressed); err != nil {
		t.Fatal(err)
	}
	if state != "quarantined" || until != stormAt.Add(10*time.Minute).UnixMilli() {
		t.Fatalf("quarantine state=%s until=%d", state, until)
	}
	if suppressed != 7 {
		t.Fatalf("suppressed count=%d, want 7", suppressed)
	}
	var suppressionStart int64
	if err := bridge.db.QueryRow(`SELECT suppressed_from_ms FROM issue_quarantines WHERE issue_key='owner/repo#7'`).Scan(&suppressionStart); err != nil {
		t.Fatal(err)
	}
	if suppressionStart != start.Add(-time.Millisecond).UnixMilli() {
		t.Fatalf("quarantine start=%d, want first ingress %d", suppressionStart, start.Add(-time.Millisecond).UnixMilli())
	}
	status, err := bridge.recordIssueEvent(context.Background(), issueEvent{
		DeliveryID: "during-quarantine", IssueKey: "owner/repo#7", Repository: "owner/repo",
		IssueNumber: 7, EventName: "issue_comment.created", ReceivedAt: stormAt.Add(time.Minute),
	})
	if err != nil || status != "ignored_quarantine" {
		t.Fatalf("quarantined event status=%q err=%v", status, err)
	}
	var afterUntil int64
	if err := bridge.db.QueryRow(`SELECT quarantine_until_ms FROM issue_windows WHERE issue_key='owner/repo#7'`).Scan(&afterUntil); err != nil {
		t.Fatal(err)
	}
	if afterUntil != until {
		t.Fatalf("quarantine extended from %d to %d", until, afterUntil)
	}
	if err := bridge.processDueWindows(context.Background(), time.UnixMilli(until)); err != nil {
		t.Fatal(err)
	}
	var activeRows, quarantineRows int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM issue_windows WHERE issue_key='owner/repo#7'`).Scan(&activeRows); err != nil || activeRows != 0 {
		t.Fatalf("active quarantine rows=%d err=%v", activeRows, err)
	}
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM issue_quarantines WHERE issue_key='owner/repo#7'`).Scan(&quarantineRows); err != nil || quarantineRows != 1 {
		t.Fatalf("quarantine history rows=%d err=%v", quarantineRows, err)
	}
	status, err = bridge.recordIssueEvent(context.Background(), issueEvent{
		DeliveryID: "after-quarantine", IssueKey: "owner/repo#7", Repository: "owner/repo",
		IssueNumber: 7, EventName: "issues.reopened", ReceivedAt: time.UnixMilli(until),
	})
	if err != nil || status != "aggregated" {
		t.Fatalf("post-quarantine event status=%q err=%v", status, err)
	}
	late, err := bridge.recordIssueEvent(context.Background(), issueEvent{
		DeliveryID: "late-during-quarantine", IssueKey: "owner/repo#7", Repository: "owner/repo",
		IssueNumber: 7, EventName: "issues.labeled", ReceivedAt: time.UnixMilli(until - 1),
	})
	if err != nil || late != "ignored_quarantine" {
		t.Fatalf("delayed quarantine event status=%q err=%v", late, err)
	}
	if err := bridge.processDueWindows(context.Background(), time.UnixMilli(until).Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM notification_jobs`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("post-quarantine notification count=%d err=%v", jobs, err)
	}
	var message string
	if err := bridge.db.QueryRow(`SELECT message FROM notification_jobs`).Scan(&message); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(message, "issues.reopened") || strings.Contains(message, "issues.labeled") {
		t.Fatalf("late quarantined event leaked into post-quarantine batch: %q", message)
	}
}

func TestQuietDeadlineWinsWhenItEqualsStormDeadline(t *testing.T) {
	bridge := testBridge(t)
	start := time.Unix(1_700_000_000, 0).UTC()
	for i, seconds := range []int{0, 9, 18, 27, 36, 45, 50} {
		_, err := bridge.recordIssueEvent(context.Background(), issueEvent{
			DeliveryID: "equal-" + strconv.Itoa(i), IssueKey: "owner/repo#4",
			Repository: "owner/repo", IssueNumber: 4, EventName: "issues.opened",
			ReceivedAt: start.Add(time.Duration(seconds) * time.Second),
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := bridge.processDueWindows(context.Background(), start.Add(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	var jobs int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM notification_jobs`).Scan(&jobs); err != nil || jobs != 1 {
		t.Fatalf("notifications=%d err=%v; quiet/storm tie should flush once", jobs, err)
	}
}

func TestWebhookDedupeAndIgnoreAutomationSender(t *testing.T) {
	bridge := testBridge(t)
	body := []byte(`{"action":"created","repository":{"full_name":"d0is/00_HomeProject"},"issue":{"number":23},"sender":{"login":"D0I-Agent"},"comment":{"body":"not persisted"}}`)
	first := signedRequest(t, bridge, body, "delivery-bot", "issue_comment")
	if first.Code != http.StatusAccepted || !bytes.Contains(first.Body.Bytes(), []byte("ignored_sender")) {
		t.Fatalf("response = %d %s", first.Code, first.Body.String())
	}
	second := signedRequest(t, bridge, body, "delivery-bot", "issue_comment")
	if second.Code != http.StatusAccepted || !bytes.Contains(second.Body.Bytes(), []byte("ignored_duplicate")) {
		t.Fatalf("duplicate response = %d %s", second.Code, second.Body.String())
	}
	var windows, receipts int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM issue_windows`).Scan(&windows); err != nil {
		t.Fatal(err)
	}
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM delivery_receipts`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if windows != 0 || receipts != 1 {
		t.Fatalf("windows=%d receipts=%d; bot event must be receipt-only", windows, receipts)
	}
	var stored string
	if err := bridge.db.QueryRow(`SELECT event_name FROM delivery_receipts`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "issue_comment.created" {
		t.Fatalf("stored event=%q", stored)
	}
}

func TestWebhookIssueEventContainsNoPayloadTextInStorage(t *testing.T) {
	bridge := testBridge(t)
	body := []byte(`{"action":"created","repository":{"full_name":"owner/repo"},"issue":{"number":9,"title":"private title"},"sender":{"login":"human"},"comment":{"body":"private comment"}}`)
	rec := signedRequest(t, bridge, body, "delivery-comment", "issue_comment")
	if rec.Code != http.StatusAccepted || !bytes.Contains(rec.Body.Bytes(), []byte("aggregated")) {
		t.Fatalf("response=%d %s", rec.Code, rec.Body.String())
	}
	var eventJSON string
	if err := bridge.db.QueryRow(`SELECT events_json FROM issue_windows`).Scan(&eventJSON); err != nil {
		t.Fatal(err)
	}
	if eventJSON != `{"issue_comment.created":true}` {
		t.Fatalf("stored events=%s", eventJSON)
	}
	for _, forbidden := range []string{"private title", "private comment"} {
		var count int
		if err := bridge.db.QueryRow(`SELECT
			(SELECT COUNT(*) FROM delivery_receipts WHERE event_name LIKE '%' || ? || '%') +
			(SELECT COUNT(*) FROM issue_windows WHERE events_json LIKE '%' || ? || '%') +
			(SELECT COUNT(*) FROM notification_jobs WHERE message LIKE '%' || ? || '%')`, forbidden, forbidden, forbidden).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != 0 {
			t.Fatalf("payload text %q was persisted", forbidden)
		}
	}
}

func TestWebhookIgnoresPullRequestCommentsAndPing(t *testing.T) {
	bridge := testBridge(t)
	prComment := []byte(`{"action":"created","repository":{"full_name":"owner/repo"},"issue":{"number":3,"pull_request":{"url":"https://api.github.com/repos/owner/repo/pulls/3"}},"sender":{"login":"human"},"comment":{"body":"no"}}`)
	pr := signedRequest(t, bridge, prComment, "pr-comment", "issue_comment")
	if pr.Code != http.StatusAccepted || !bytes.Contains(pr.Body.Bytes(), []byte("ignored_pull_request")) {
		t.Fatalf("PR comment response=%d %s", pr.Code, pr.Body.String())
	}
	ping := signedRequest(t, bridge, []byte(`{"zen":"test"}`), "ping-1", "ping")
	if ping.Code != http.StatusAccepted || !bytes.Contains(ping.Body.Bytes(), []byte("ignored_event")) {
		t.Fatalf("ping response=%d %s", ping.Code, ping.Body.String())
	}
	var windows int
	if err := bridge.db.QueryRow(`SELECT COUNT(*) FROM issue_windows`).Scan(&windows); err != nil || windows != 0 {
		t.Fatalf("issue windows=%d err=%v", windows, err)
	}
}

func TestWebhookRejectsWrongRepositoryAndBadSignature(t *testing.T) {
	bridge := testBridge(t)
	body := []byte(`{"action":"opened","repository":{"full_name":"someone/else"},"issue":{"number":1},"sender":{"login":"human"}}`)
	rec := signedRequest(t, bridge, body, "wrong-repo", "issues")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("wrong repo status=%d, want 403", rec.Code)
	}
	req := httptest.NewRequest(http.MethodPost, "/hooks/github", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Hub-Signature-256", "sha256=deadbeef")
	req.Header.Set("X-GitHub-Delivery", "bad-signature")
	req.Header.Set("X-GitHub-Event", "issues")
	response := httptest.NewRecorder()
	bridge.handler(response, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("bad signature status=%d, want 401", response.Code)
	}
}

func TestForwardNotificationUsesIsolatedIssueSessionAndMinimalPrompt(t *testing.T) {
	var gotBody []byte
	var gotHeader http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	bridge := testBridge(t)
	bridge.cfg.OpenClawURL = upstream.URL
	job := notificationJob{
		ID: "batch-1", IssueKey: "d0is/00_homeproject#42", Repository: "d0is/00_HomeProject",
		IssueNumber: 42, Message: "[github-hookbridge:v2]\nIssue: https://github.com/d0is/00_HomeProject/issues/42\nObserved events: issues.labeled",
	}
	if err := bridge.forwardNotification(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	if gotHeader.Get("Authorization") != "Bearer openclaw-token" || gotHeader.Get("Idempotency-Key") != "" {
		t.Fatalf("unexpected headers: %#v", gotHeader)
	}
	var request map[string]any
	if err := json.Unmarshal(gotBody, &request); err != nil {
		t.Fatal(err)
	}
	if request["message"] != job.Message || request["sessionMode"] != "isolated" ||
		request["sessionKey"] != "github:issue:d0is/00_homeproject:42" || request["deliver"] != false ||
		request["idempotencyKey"] != "batch-1" {
		t.Fatalf("unexpected request: %#v", request)
	}
	for _, forbidden := range []string{"event", "repository", "action", "sender", "payload"} {
		if _, ok := request[forbidden]; ok {
			t.Fatalf("unexpected payload field %q: %#v", forbidden, request)
		}
	}
}

func TestTransportFailureBecomesUncertainInsteadOfAutomaticRetry(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer upstream.Close()
	bridge := testBridge(t)
	bridge.cfg.OpenClawURL = upstream.URL
	_, err := bridge.db.Exec(`INSERT INTO notification_jobs
		(id,issue_key,repository,issue_number,message,status,attempts,next_attempt_ms,created_at_ms,updated_at_ms)
		VALUES('ambiguous-1','owner/repo#5','owner/repo',5,'safe message','pending',0,?,?,?)`,
		time.Now().UnixMilli(), time.Now().UnixMilli(), time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	worked, err := bridge.processOneNotification(context.Background())
	if err != nil || !worked {
		t.Fatalf("worked=%t err=%v", worked, err)
	}
	var status string
	var attempts int
	if err := bridge.db.QueryRow(`SELECT status,attempts FROM notification_jobs WHERE id='ambiguous-1'`).Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "uncertain" || attempts != 1 {
		t.Fatalf("status=%q attempts=%d, want uncertain and one attempt", status, attempts)
	}
}

func TestProcessingNotificationBecomesUncertainOnRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.sqlite3")
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	_, err = db.Exec(`INSERT INTO notification_jobs
		(id,issue_key,repository,issue_number,message,status,attempts,next_attempt_ms,created_at_ms,updated_at_ms)
		VALUES('crashed-1','owner/repo#5','owner/repo',5,'safe message','processing',1,?,?,?)`,
		now, now, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	recovered, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	var status string
	if err := recovered.QueryRow(`SELECT status FROM notification_jobs WHERE id='crashed-1'`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "uncertain" {
		t.Fatalf("recovered status=%q, want uncertain", status)
	}
}

func TestRetryDelayParsing(t *testing.T) {
	got, err := retryDelaysEnv("GHB_RETRY_DELAYS", []time.Duration{time.Second})
	if err != nil || len(got) != 1 || got[0] != time.Second {
		t.Fatalf("default retries=%v err=%v", got, err)
	}
	t.Setenv("GHB_RETRY_DELAYS", "2s,7s")
	got, err = retryDelaysEnv("GHB_RETRY_DELAYS", nil)
	if err != nil || len(got) != 2 || got[0] != 2*time.Second || got[1] != 7*time.Second {
		t.Fatalf("parsed retries=%v err=%v", got, err)
	}
}
