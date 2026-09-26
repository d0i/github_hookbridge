package main

import (
	"bytes"
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
	bridgeVersion       = "2.0.0"
	defaultQuietWindow  = 10 * time.Second
	defaultStormWindow  = 60 * time.Second
	defaultQuarantine   = 600 * time.Second
	defaultPollInterval = 250 * time.Millisecond
	defaultForwardLimit = 25 * time.Second
	defaultMaxBody      = int64(1 << 20)
)

type Config struct {
	ListenAddr            string
	GitHubSecret          []byte
	OpenClawURL           string
	OpenClawToken         string
	OpenClawAgentID       string
	AllowedRepositories   map[string]string // lowercase full name -> configured spelling
	IgnoredSenders        map[string]struct{}
	DBPath                string
	QuietWindow           time.Duration
	StormWindow           time.Duration
	QuarantineDuration    time.Duration
	WorkerPollInterval    time.Duration
	ForwardTimeout        time.Duration
	RetryDelays           []time.Duration
	ReceiptRetention      time.Duration
	MaxBodyBytes          int64
	HTTPReadHeaderTimeout time.Duration
	HTTPReadTimeout       time.Duration
	HTTPWriteTimeout      time.Duration
	HTTPIdleTimeout       time.Duration
	LogLevel              slog.Level
	DryRun                bool
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

	repos := make(map[string]string)
	for _, value := range strings.Split(os.Getenv("GHB_ALLOWED_REPOSITORIES"), ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if !validRepository(value) {
			return Config{}, fmt.Errorf("invalid repository in GHB_ALLOWED_REPOSITORIES: %q", value)
		}
		repos[strings.ToLower(value)] = value
	}
	if len(repos) == 0 && !dryRun {
		return Config{}, errors.New("GHB_ALLOWED_REPOSITORIES must contain at least one owner/repository")
	}

	quiet, err := durationEnv("GHB_QUIET_WINDOW", defaultQuietWindow)
	if err != nil {
		return Config{}, err
	}
	storm, err := durationEnv("GHB_STORM_WINDOW", defaultStormWindow)
	if err != nil {
		return Config{}, err
	}
	quarantine, err := durationEnv("GHB_QUARANTINE_DURATION", defaultQuarantine)
	if err != nil {
		return Config{}, err
	}
	if storm <= quiet {
		return Config{}, errors.New("GHB_STORM_WINDOW must be longer than GHB_QUIET_WINDOW")
	}
	poll, err := durationEnv("GHB_WORKER_POLL_INTERVAL", defaultPollInterval)
	if err != nil {
		return Config{}, err
	}
	forwardTimeout, err := durationEnv("GHB_FORWARD_TIMEOUT", defaultForwardLimit)
	if err != nil {
		return Config{}, err
	}
	retries, err := retryDelaysEnv("GHB_RETRY_DELAYS", []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second})
	if err != nil {
		return Config{}, err
	}
	retention, err := durationEnv("GHB_RECEIPT_RETENTION", 7*24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	maxBytes := defaultMaxBody
	if value := os.Getenv("GHB_MAX_BODY_BYTES"); value != "" {
		maxBytes, err = strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || maxBytes < 1 {
			return Config{}, errors.New("GHB_MAX_BODY_BYTES must be a positive integer")
		}
	}

	readHeaderTimeout, err := durationEnv("GHB_HTTP_READ_HEADER_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	readTimeout, err := durationEnv("GHB_HTTP_READ_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	writeTimeout, err := durationEnv("GHB_HTTP_WRITE_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := durationEnv("GHB_HTTP_IDLE_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
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
		IgnoredSenders:        ignoredSendersFromEnv(),
		DBPath:                envOr("GHB_DB_PATH", filepath.Join("data", "deliveries-v2.sqlite3")),
		QuietWindow:           quiet,
		StormWindow:           storm,
		QuarantineDuration:    quarantine,
		WorkerPollInterval:    poll,
		ForwardTimeout:        forwardTimeout,
		RetryDelays:           retries,
		ReceiptRetention:      retention,
		MaxBodyBytes:          maxBytes,
		HTTPReadHeaderTimeout: readHeaderTimeout,
		HTTPReadTimeout:       readTimeout,
		HTTPWriteTimeout:      writeTimeout,
		HTTPIdleTimeout:       idleTimeout,
		LogLevel:              level,
		DryRun:                dryRun,
	}, nil
}

func ignoredSendersFromEnv() map[string]struct{} {
	value, configured := os.LookupEnv("GHB_IGNORED_SENDERS")
	if !configured {
		value = "d0i-agent"
	}
	ignored := make(map[string]struct{})
	for _, login := range strings.Split(value, ",") {
		login = normalizeLogin(login)
		if login != "" {
			ignored[login] = struct{}{}
		}
	}
	return ignored
}

func durationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < time.Millisecond {
		return 0, fmt.Errorf("%s must be a duration of at least 1ms", key)
	}
	return duration, nil
}

func retryDelaysEnv(key string, fallback []time.Duration) ([]time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	var delays []time.Duration
	for _, item := range strings.Split(value, ",") {
		delay, err := time.ParseDuration(strings.TrimSpace(item))
		if err != nil || delay < time.Millisecond {
			return nil, fmt.Errorf("%s must be comma-separated positive durations", key)
		}
		delays = append(delays, delay)
	}
	return delays, nil
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

func normalizeLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(login), "@")))
}

func validRepository(repository string) bool {
	parts := strings.Split(repository, "/")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || len(part) > 100 {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
				!(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
				return false
			}
		}
	}
	return true
}

func isIgnoredSender(ignored map[string]struct{}, login string) bool {
	_, ok := ignored[normalizeLogin(login)]
	return ok
}

type Bridge struct {
	cfg          Config
	db           *sql.DB
	client       *http.Client
	log          *slog.Logger
	issueStateMu sync.Mutex
}

type webhookPayload struct {
	Action     string `json:"action"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Issue struct {
		Number      int64           `json:"number"`
		PullRequest json.RawMessage `json:"pull_request"`
	} `json:"issue"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
}

type issueEvent struct {
	DeliveryID  string
	IssueKey    string
	Repository  string
	IssueNumber int64
	EventName   string
	ReceivedAt  time.Time
	AcceptedAt  time.Time
}

func (b *Bridge) handler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		if r.Method != http.MethodGet {
			methodNotAllowed(w)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": bridgeVersion})
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
	if deliveryID == "" || len(deliveryID) > 200 || event == "" || len(event) > 100 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing or invalid delivery/event header"})
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "JSON object required"})
		return
	}

	now := time.Now().UTC()
	if event == "ping" {
		status, err := b.recordReceiptOnly(r.Context(), deliveryID, "", "", "ping", "ignored_event", now)
		if err != nil {
			b.log.Error("record ping receipt failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot record delivery"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
		return
	}
	if event != "issues" && event != "issue_comment" {
		status, err := b.recordReceiptOnly(r.Context(), deliveryID, "", "", "ignored_event", "ignored_event", now)
		if err != nil {
			b.log.Error("record ignored event failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot record delivery"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
		return
	}

	var payload webhookPayload
	if err := json.Unmarshal(trimmed, &payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid GitHub event payload"})
		return
	}
	repoInput := strings.TrimSpace(payload.Repository.FullName)
	repository, allowed := b.cfg.AllowedRepositories[strings.ToLower(repoInput)]
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "repository is not allowed"})
		return
	}
	if payload.Issue.Number < 1 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload issue.number is required"})
		return
	}
	if payload.Sender.Login == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "payload sender.login is required"})
		return
	}
	if isPullRequestIssue(payload.Issue.PullRequest) {
		status, err := b.recordReceiptOnly(r.Context(), deliveryID, repository, issueKey(repository, payload.Issue.Number), "ignored_pull_request", "ignored_pull_request", now)
		if err != nil {
			b.log.Error("record ignored pull request event failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot record delivery"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
		return
	}

	action := strings.TrimSpace(payload.Action)
	if !isAllowedAction(event, action) {
		status, err := b.recordReceiptOnly(r.Context(), deliveryID, repository, issueKey(repository, payload.Issue.Number), "ignored_action", "ignored_action", now)
		if err != nil {
			b.log.Error("record ignored action failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot record delivery"})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
		return
	}

	key := issueKey(repository, payload.Issue.Number)
	eventName := event + "." + action
	if isIgnoredSender(b.cfg.IgnoredSenders, payload.Sender.Login) {
		status, err := b.recordReceiptOnly(r.Context(), deliveryID, repository, key, eventName, "ignored_sender", now)
		if err != nil {
			b.log.Error("record ignored sender event failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot record delivery"})
			return
		}
		if status != "ignored_duplicate" {
			b.log.Info("automation sender event ignored", "issue_key", key, "event", eventName)
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
		return
	}

	status, err := b.recordIssueEventLive(r.Context(), issueEvent{
		DeliveryID: deliveryID, IssueKey: key, Repository: repository,
		IssueNumber: payload.Issue.Number, EventName: eventName, ReceivedAt: now,
	})
	if err != nil {
		b.log.Error("record issue event failed", "issue_key", key, "event", eventName, "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot queue issue event"})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"status": status})
}

func isPullRequestIssue(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
}

func isAllowedAction(event, action string) bool {
	switch event {
	case "issues":
		switch action {
		case "opened", "closed", "reopened", "labeled", "unlabeled":
			return true
		}
	case "issue_comment":
		return action == "created"
	}
	return false
}

func issueKey(repository string, number int64) string {
	return strings.ToLower(repository) + "#" + strconv.FormatInt(number, 10)
}

func canonicalIssueURL(repository string, number int64) string {
	return "https://github.com/" + repository + "/issues/" + strconv.FormatInt(number, 10)
}

func (b *Bridge) recordReceiptOnly(ctx context.Context, id, repository, key, event, outcome string, received time.Time) (string, error) {
	result, err := b.db.ExecContext(ctx, `INSERT OR IGNORE INTO delivery_receipts
		(delivery_id,received_at_ms,repository,issue_key,event_name,outcome)
		VALUES(?,?,?,?,?,?)`, id, received.UnixMilli(), repository, key, event, outcome)
	if err != nil {
		return "", err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "ignored_duplicate", nil
	}
	return outcome, nil
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
	return subtle.ConstantTimeCompare(received, mac.Sum(nil)) == 1
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
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	db, err := openDB(cfg.DBPath)
	if err != nil {
		logger.Error("database error", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	bridge := &Bridge{cfg: cfg, db: db, client: &http.Client{Timeout: cfg.ForwardTimeout}, log: logger}
	server := &http.Server{
		Addr: cfg.ListenAddr, Handler: http.HandlerFunc(bridge.handler),
		ReadHeaderTimeout: cfg.HTTPReadHeaderTimeout, ReadTimeout: cfg.HTTPReadTimeout,
		WriteTimeout: cfg.HTTPWriteTimeout, IdleTimeout: cfg.HTTPIdleTimeout,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go bridge.worker(ctx)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	logger.Info("github webhook bridge listening", "version", bridgeVersion, "addr", cfg.ListenAddr,
		"openclaw_url", cfg.OpenClawURL, "dry_run", cfg.DryRun,
		"quiet_window", cfg.QuietWindow, "storm_window", cfg.StormWindow,
		"quarantine_duration", cfg.QuarantineDuration)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
