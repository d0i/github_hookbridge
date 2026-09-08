package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	maxAttempts = 4 // initial attempt plus three retries
	maxBodySize = int64(1 << 20)
	retention   = 7 * 24 * time.Hour
)

type Config struct {
	ListenAddr            string
	GitHubSecret          []byte
	OpenClawURL           string
	OpenClawToken         string
	OpenClawAgentID       string
	AllowedRepositories   map[string]struct{}
	DBPath                string
	ForwardTimeout        time.Duration
	MaxBodyBytes          int64
	LogLevel              slog.Level
	DryRun                bool
	DryRunLogFile         string
	DryRunOutboundLogFile string
}

func loadConfig() (Config, error) {
	secretFile := envOr("GHB_GITHUB_SECRET_FILE", "")
	if secretFile == "" {
		return Config{}, errors.New("GHB_GITHUB_SECRET_FILE is required")
	}
	secret, err := readSecret(secretFile)
	if err != nil {
		return Config{}, fmt.Errorf("read GitHub secret: %w", err)
	}
	dryRun := strings.EqualFold(envOr("GHB_DRY_RUN", "false"), "true")
	var token []byte
	if tokenFile := envOr("GHB_OPENCLAW_TOKEN_FILE", ""); tokenFile != "" {
		token, err = readSecret(tokenFile)
		if err != nil {
			return Config{}, fmt.Errorf("read OpenClaw token: %w", err)
		}
	} else if !dryRun {
		return Config{}, errors.New("GHB_OPENCLAW_TOKEN_FILE is required unless GHB_DRY_RUN=true")
	}
	repos := make(map[string]struct{})
	for _, value := range strings.Split(os.Getenv("GHB_ALLOWED_REPOSITORIES"), ",") {
		value = strings.TrimSpace(value)
		if value != "" {
			repos[value] = struct{}{}
		}
	}
	if len(repos) == 0 && !dryRun {
		return Config{}, errors.New("GHB_ALLOWED_REPOSITORIES must contain at least one repository")
	}
	maxBytes := maxBodySize
	if value := os.Getenv("GHB_MAX_BODY_BYTES"); value != "" {
		maxBytes, err = strconv.ParseInt(value, 10, 64)
		if err != nil || maxBytes < 1 {
			return Config{}, errors.New("GHB_MAX_BODY_BYTES must be a positive integer")
		}
	}
	forwardTimeout := 5 * time.Second
	if value := os.Getenv("GHB_FORWARD_TIMEOUT"); value != "" {
		forwardTimeout, err = time.ParseDuration(value)
		if err != nil || forwardTimeout <= 0 {
			return Config{}, errors.New("GHB_FORWARD_TIMEOUT must be a positive duration")
		}
	}
	level := slog.LevelInfo
	if strings.EqualFold(os.Getenv("GHB_LOG_LEVEL"), "debug") {
		level = slog.LevelDebug
	}
	return Config{
		ListenAddr:            envOr("GHB_LISTEN_ADDR", "127.0.0.1:8003"),
		GitHubSecret:          secret,
		OpenClawURL:           envOr("GHB_OPENCLAW_URL", "http://127.0.0.1:8001/hooks/agent"),
		OpenClawToken:         string(token),
		OpenClawAgentID:       envOr("GHB_OPENCLAW_AGENT_ID", "main"),
		AllowedRepositories:   repos,
		DBPath:                envOr("GHB_DB_PATH", filepath.Join("data", "deliveries.sqlite3")),
		ForwardTimeout:        forwardTimeout,
		MaxBodyBytes:          maxBytes,
		LogLevel:              level,
		DryRun:                dryRun,
		DryRunLogFile:         envOr("GHB_DRY_RUN_LOG_FILE", "/var/log/github-hookbridge/webhooks.jsonl"),
		DryRunOutboundLogFile: envOr("GHB_DRY_RUN_OUTBOUND_LOG_FILE", "/var/log/github-hookbridge/openclaw.jsonl"),
	}, nil
}

func readSecret(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("secret path is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("secret file permissions are too broad: %04o", info.Mode().Perm())
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	value = []byte(strings.TrimSpace(string(value)))
	if len(value) == 0 {
		return nil, errors.New("secret file is empty")
	}
	return value, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

type Bridge struct {
	cfg    Config
	db     *sql.DB
	client *http.Client
	log    *slog.Logger
	logMu  sync.Mutex
}

type delivery struct {
	ID         string
	Event      string
	Repository string
	Action     string
	Summary    string
	Payload    []byte
	Attempts   int
}

func openDB(path string) (*sql.DB, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA journal_mode = WAL`,
		`CREATE TABLE IF NOT EXISTS deliveries (
			id TEXT PRIMARY KEY,
			event TEXT NOT NULL,
			repository TEXT NOT NULL,
			action TEXT NOT NULL,
			summary TEXT NOT NULL,
			payload_json TEXT NOT NULL,
			status TEXT NOT NULL CHECK(status IN ('pending','processing','completed','failed')),
			attempts INTEGER NOT NULL DEFAULT 0,
			next_attempt_at INTEGER NOT NULL,
			last_error TEXT NOT NULL DEFAULT '',
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL,
			completed_at INTEGER
		)`,
		`CREATE INDEX IF NOT EXISTS deliveries_queue_idx ON deliveries(status, next_attempt_at)`,
		`CREATE INDEX IF NOT EXISTS deliveries_created_idx ON deliveries(created_at)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	if _, err := db.Exec(`UPDATE deliveries SET status='pending', updated_at=? WHERE status='processing'`, time.Now().Unix()); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (b *Bridge) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if r.URL.Path == "/readyz" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		if err := b.db.PingContext(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	if r.URL.Path != "/hooks/github" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "content type must be application/json"})
		return
	}
	body, err := readLimitedBody(r.Body, b.cfg.MaxBodyBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request body too large"})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot read request body"})
		return
	}
	if !verifySignature(body, r.Header.Get("X-Hub-Signature-256"), b.cfg.GitHubSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid webhook signature"})
		return
	}
	deliveryID := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	event := strings.TrimSpace(r.Header.Get("X-GitHub-Event"))
	if deliveryID == "" || event == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing delivery or event header"})
		return
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if raw == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON object required"})
		return
	}
	if b.cfg.DryRun {
		status, err := b.recordDryRun(r.Context(), deliveryID, event, raw, body)
		if err != nil {
			b.log.Error("dry-run recording failed", "event", event, "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot record webhook"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
		return
	}
	summary, err := buildSummary(event, deliveryID, raw, b.cfg.AllowedRepositories)
	if err != nil {
		var policyErr *policyError
		if errors.As(err, &policyErr) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": policyErr.Error()})
			return
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	payloadJSON, err := json.Marshal(summary)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot encode summary"})
		return
	}
	status, err := b.enqueue(r.Context(), deliveryID, event, summary.Repository, summary.Action, summary.Summary, payloadJSON)
	if err != nil {
		b.log.Error("enqueue delivery failed", "event", event, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot queue delivery"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
}

type policyError struct{ message string }

func (e *policyError) Error() string { return e.message }

var allowedActions = map[string]map[string]struct{}{
	"issues":        {"opened": {}, "closed": {}, "reopened": {}},
	"issue_comment": {"created": {}},
	"pull_request":  {"opened": {}, "closed": {}},
}

type githubSummary struct {
	Name       string         `json:"name"`
	Event      string         `json:"event"`
	DeliveryID string         `json:"deliveryId"`
	Repository string         `json:"repository"`
	Action     string         `json:"action"`
	Sender     string         `json:"sender"`
	Summary    string         `json:"summary"`
	Payload    map[string]any `json:"payload"`
}

func buildSummary(event, deliveryID string, raw map[string]any, repos map[string]struct{}) (githubSummary, error) {
	actions, ok := allowedActions[event]
	if !ok {
		return githubSummary{}, &policyError{fmt.Sprintf("event %q is not allowed", event)}
	}
	action, ok := rawString(raw, "action")
	if !ok {
		return githubSummary{}, errors.New("payload action is required")
	}
	if _, ok := actions[action]; !ok {
		return githubSummary{}, &policyError{fmt.Sprintf("action %q is not allowed for event %q", action, event)}
	}
	repository, ok := nestedString(raw, "repository", "full_name")
	if !ok {
		return githubSummary{}, errors.New("payload repository.full_name is required")
	}
	if _, ok := repos[repository]; !ok {
		return githubSummary{}, &policyError{fmt.Sprintf("repository %q is not allowed", repository)}
	}
	sender, _ := nestedString(raw, "sender", "login")
	item := map[string]any{}
	if number, ok := raw["number"]; ok {
		item["number"] = number
	}
	if url, ok := rawString(raw, "html_url"); ok {
		item["url"] = url
	}
	title := ""
	if issue, ok := raw["issue"].(map[string]any); ok {
		if title, ok = rawString(issue, "title"); !ok {
			title = ""
		}
		copyItemFields(item, issue)
	}
	if pr, ok := raw["pull_request"].(map[string]any); ok {
		if title == "" {
			title, _ = rawString(pr, "title")
		}
		copyItemFields(item, pr)
	}
	if comment, ok := raw["comment"].(map[string]any); ok {
		copyItemFields(item, comment)
	}
	if title == "" {
		title, _ = rawString(raw, "title")
	}
	summaryText := fmt.Sprintf("GitHub %s #%v %s in %s", event, item["number"], action, repository)
	if title != "" {
		summaryText = fmt.Sprintf("GitHub %s #%v %s: %s", event, item["number"], action, truncate(title, 200))
	}
	return githubSummary{
		Name: "github", Event: event, DeliveryID: deliveryID, Repository: repository,
		Action: action, Sender: truncate(sender, 100), Summary: summaryText, Payload: item,
	}, nil
}

func copyItemFields(dst map[string]any, src map[string]any) {
	for _, key := range []string{"number", "html_url", "url"} {
		if value, ok := src[key]; ok {
			if key == "html_url" {
				dst["url"] = value
			} else {
				dst[key] = value
			}
		}
	}
}

func rawString(m map[string]any, key string) (string, bool) {
	value, ok := m[key].(string)
	return strings.TrimSpace(value), ok && strings.TrimSpace(value) != ""
}
func nestedString(m map[string]any, keys ...string) (string, bool) {
	current := m
	for _, key := range keys[:len(keys)-1] {
		next, ok := current[key].(map[string]any)
		if !ok {
			return "", false
		}
		current = next
	}
	return rawString(current, keys[len(keys)-1])
}
func truncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	return string(runes[:max]) + "…"
}

func (b *Bridge) recordDryRun(ctx context.Context, id, event string, raw map[string]any, body []byte) (string, error) {
	now := time.Now().Unix()
	repository, _ := nestedString(raw, "repository", "full_name")
	action, _ := rawString(raw, "action")
	result, err := b.db.ExecContext(ctx, `INSERT INTO deliveries
		(id,event,repository,action,summary,payload_json,status,attempts,next_attempt_at,created_at,updated_at,completed_at)
		VALUES(?,?,?,?,?,'{}','completed',0,?,?,?,?)`, id, event, repository, action, "dry-run", now, now, now, now)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			return "ignored_duplicate", nil
		}
		return "", err
	}
	if count, err := result.RowsAffected(); err != nil || count != 1 {
		return "", err
	}
	if err := b.appendDryRunLog(id, event, body); err != nil {
		return "", err
	}
	if summary, summaryErr := buildSummary(event, id, raw, b.cfg.AllowedRepositories); summaryErr == nil {
		outbound, outboundErr := b.buildOpenClawPayload(summary)
		if outboundErr != nil {
			return "", outboundErr
		}
		if err := b.appendDryRunOutboundLog(id, event, outbound); err != nil {
			return "", err
		}
	}
	return "dry_run_logged", nil
}

func (b *Bridge) appendDryRunLog(id, event string, body []byte) error {
	if dir := filepath.Dir(b.cfg.DryRunLogFile); dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}
	line := struct {
		ReceivedAt string          `json:"received_at"`
		DeliveryID string          `json:"delivery_id"`
		Event      string          `json:"event"`
		Body       json.RawMessage `json:"body"`
	}{time.Now().UTC().Format(time.RFC3339Nano), id, event, json.RawMessage(body)}
	encoded, err := json.Marshal(line)
	if err != nil {
		return err
	}
	b.logMu.Lock()
	defer b.logMu.Unlock()
	file, err := os.OpenFile(b.cfg.DryRunLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(encoded, '\n'))
	return err
}

func (b *Bridge) appendDryRunOutboundLog(id, event string, body []byte) error {
	if dir := filepath.Dir(b.cfg.DryRunOutboundLogFile); dir != "." {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return err
		}
	}
	line := struct {
		RecordedAt string          `json:"recorded_at"`
		DeliveryID string          `json:"delivery_id"`
		Event      string          `json:"event"`
		Request    json.RawMessage `json:"openclaw_request"`
	}{time.Now().UTC().Format(time.RFC3339Nano), id, event, json.RawMessage(body)}
	encoded, err := json.Marshal(line)
	if err != nil {
		return err
	}
	b.logMu.Lock()
	defer b.logMu.Unlock()
	file, err := os.OpenFile(b.cfg.DryRunOutboundLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(append(encoded, '\n'))
	return err
}

func (b *Bridge) enqueue(ctx context.Context, id, event, repo, action, summary string, payload []byte) (string, error) {
	now := time.Now().Unix()
	result, err := b.db.ExecContext(ctx, `INSERT INTO deliveries
		(id,event,repository,action,summary,payload_json,status,attempts,next_attempt_at,created_at,updated_at)
		VALUES(?,?,?,?,? ,?,'pending',0,?,?,?)`, id, event, repo, action, summary, string(payload), now, now, now)
	if err == nil {
		if _, err := result.RowsAffected(); err != nil {
			return "", err
		}
		return "queued", nil
	}
	if strings.Contains(strings.ToLower(err.Error()), "constraint") || strings.Contains(strings.ToLower(err.Error()), "unique") {
		return "ignored_duplicate", nil
	}
	return "", err
}

func (b *Bridge) worker(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	cleanupTicker := time.NewTicker(24 * time.Hour)
	defer cleanupTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for i := 0; i < 20; i++ {
				if err := b.processOne(ctx); err != nil {
					b.log.Error("worker error", "error", err)
					break
				}
			}
		case <-cleanupTicker.C:
			if err := b.cleanup(ctx); err != nil {
				b.log.Error("cleanup error", "error", err)
			}
		}
	}
}

func (b *Bridge) cleanup(ctx context.Context) error {
	cutoff := time.Now().Add(-retention).Unix()
	result, err := b.db.ExecContext(ctx, `DELETE FROM deliveries WHERE created_at < ?`, cutoff)
	if err != nil {
		return err
	}
	if count, err := result.RowsAffected(); err == nil && count > 0 {
		b.log.Info("old deliveries cleaned up", "count", count)
	}
	return nil
}

func (b *Bridge) processOne(ctx context.Context) error {
	d, ok, err := b.claim(ctx)
	if err != nil || !ok {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, b.cfg.ForwardTimeout)
	err = b.forward(requestCtx, d)
	cancel()
	if err == nil {
		_, err = b.db.ExecContext(ctx, `UPDATE deliveries SET status='completed', completed_at=?, updated_at=? WHERE id=?`, time.Now().Unix(), time.Now().Unix(), d.ID)
		return err
	}
	if d.Attempts >= maxAttempts {
		_, updateErr := b.db.ExecContext(ctx, `UPDATE deliveries SET status='failed', last_error=?, updated_at=? WHERE id=?`, truncate(err.Error(), 500), time.Now().Unix(), d.ID)
		if updateErr != nil {
			return updateErr
		}
		b.log.Error("delivery failed permanently", "delivery_id", d.ID, "error", err)
		return nil
	}
	backoff := []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}[d.Attempts-1]
	_, updateErr := b.db.ExecContext(ctx, `UPDATE deliveries SET status='failed', last_error=?, next_attempt_at=?, updated_at=? WHERE id=?`, truncate(err.Error(), 500), time.Now().Add(backoff).Unix(), time.Now().Unix(), d.ID)
	return updateErr
}

func (b *Bridge) claim(ctx context.Context) (delivery, bool, error) {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return delivery{}, false, err
	}
	defer tx.Rollback()
	var d delivery
	var payload string
	err = tx.QueryRowContext(ctx, `SELECT id,event,repository,action,summary,payload_json,attempts
		FROM deliveries
		WHERE (status='pending' OR (status='failed' AND attempts < ?)) AND next_attempt_at<=?
		ORDER BY next_attempt_at,created_at LIMIT 1`, maxAttempts, time.Now().Unix()).Scan(&d.ID, &d.Event, &d.Repository, &d.Action, &d.Summary, &payload, &d.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return delivery{}, false, nil
	}
	if err != nil {
		return delivery{}, false, err
	}
	d.Payload = []byte(payload)
	d.Attempts++
	result, err := tx.ExecContext(ctx, `UPDATE deliveries SET status='processing', attempts=?, updated_at=? WHERE id=? AND status IN ('pending','failed')`, d.Attempts, time.Now().Unix(), d.ID)
	if err != nil {
		return delivery{}, false, err
	}
	if count, _ := result.RowsAffected(); count != 1 {
		return delivery{}, false, nil
	}
	if err := tx.Commit(); err != nil {
		return delivery{}, false, err
	}
	return d, true, nil
}

func (b *Bridge) buildOpenClawPayload(summary githubSummary) ([]byte, error) {
	message := summary.Summary
	if summary.Sender != "" {
		message += " (by " + summary.Sender + ")"
	}
	request := map[string]any{
		"message":        message,
		"name":           "GitHub",
		"agentId":        b.cfg.OpenClawAgentID,
		"sessionMode":    "isolated",
		"idempotencyKey": summary.DeliveryID,
		"event":          summary.Event,
		"deliveryId":     summary.DeliveryID,
		"repository":     summary.Repository,
		"action":         summary.Action,
		"sender":         summary.Sender,
		"summary":        summary.Summary,
		"payload":        summary.Payload,
	}
	return json.Marshal(request)
}

func (b *Bridge) forward(ctx context.Context, d delivery) error {
	var summary githubSummary
	if err := json.Unmarshal(d.Payload, &summary); err != nil {
		return fmt.Errorf("decode queued summary: %w", err)
	}
	body, err := b.buildOpenClawPayload(summary)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.OpenClawURL, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+b.cfg.OpenClawToken)
	req.Header.Set("Idempotency-Key", d.ID)
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OpenClaw returned HTTP %d", resp.StatusCode)
	}
	return nil
}

var errBodyTooLarge = errors.New("body too large")

func readLimitedBody(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errBodyTooLarge
	}
	return body, nil
}
func verifySignature(body []byte, header string, secret []byte) bool {
	if !strings.HasPrefix(header, "sha256=") {
		return false
	}
	received, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil || len(received) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(body)
	expected := mac.Sum(nil)
	return subtle.ConstantTimeCompare(received, expected) == 1
}
func isJSONContentType(value string) bool {
	return strings.EqualFold(strings.TrimSpace(strings.Split(value, ";")[0]), "application/json")
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func methodNotAllowed(w http.ResponseWriter) {
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		slog.Error("configuration error", "error", err)
		os.Exit(1)
	}
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel})
	logger := slog.New(handler)
	db, err := openDB(cfg.DBPath)
	if err != nil {
		logger.Error("database error", "error", err)
		os.Exit(1)
	}
	defer db.Close()
	bridge := &Bridge{cfg: cfg, db: db, client: &http.Client{}, log: logger}
	server := &http.Server{Addr: cfg.ListenAddr, Handler: http.HandlerFunc(bridge.handler), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if !cfg.DryRun {
		go bridge.worker(ctx)
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Info("github webhook bridge listening", "addr", cfg.ListenAddr, "openclaw_url", cfg.OpenClawURL, "dry_run", cfg.DryRun)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
