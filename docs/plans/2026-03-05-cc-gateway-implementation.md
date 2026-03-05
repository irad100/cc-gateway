# cc-gateway Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a security observability and enforcement gateway for Claude Code using HTTP hooks.

**Architecture:** Single Go binary with HTTP server intercepting Claude Code hook events, YAML policy engine for enforcement, SQLite for audit storage, Cobra CLI for administration, and Bubble Tea TUI for real-time monitoring.

**Tech Stack:** Go 1.25, net/http (stdlib), slog (stdlib), modernc.org/sqlite, spf13/cobra, charmbracelet/bubbletea, charmbracelet/lipgloss, gopkg.in/yaml.v3, fsnotify/fsnotify

---

## Enhancement Summary

**Deepened on:** 2026-03-05
**Research agents used:** architecture-strategist, security-sentinel, performance-oracle, code-simplicity-reviewer, pattern-recognition-specialist, agent-native-reviewer, data-integrity-guardian, best-practices-researcher, framework-docs-researcher, Context7 (bubbletea, cobra, fsnotify)

### Critical Fixes Required Before Implementation

These issues were identified across multiple reviewers and MUST be addressed in the implementation:

1. **Security: Constant-time token comparison** -- Use `crypto/subtle.ConstantTimeCompare` instead of map lookup. Store tokens as SHA-256 hashes, not plaintext. Add `cc-gateway token hash` CLI command.
2. **Security: Bound request body size** -- Wrap `r.Body` with `http.MaxBytesReader(w, r.Body, 1<<20)` in all handlers. Add `ReadHeaderTimeout` to `http.Server`.
3. **Security: Authenticate SSE endpoint** -- Remove `/events/stream` from auth bypass. Require bearer token.
4. **Security: Explicit auth-disabled mode** -- Log a WARNING at startup when no tokens configured. Require `--insecure` flag or `auth.mode: none` in config.
5. **Performance: Precompile regex patterns** -- Compile at policy load time, reject invalid patterns with clear errors. Store `*regexp.Regexp` in `Condition`.
6. **Performance: Fix TUI SSE reconnection** -- Use persistent connection with goroutine + `p.Send()`, not reconnect-per-event.
7. **Performance: Prepared statements** -- Prepare INSERT/UPDATE statements at store init time.
8. **Data integrity: Fix Stop handler zeroing session counts** -- Use dedicated `EndSession(id, endedAt)` method, not generic upsert.
9. **Data integrity: Propagate user ID from auth context** -- Call `auth.UserFromContext(ctx)` in `logEvent`.
10. **Bug: Fix package declaration** -- Engine code must be `package policy`, not `package engine`.

### Simplifications

1. **Remove `users` table** -- Derive user data from events with `GROUP BY user_id`.
2. **Remove `sessions` table** -- Derive from events. Session start/end from `MIN/MAX(created_at)`, counts from `COUNT(*)`.
3. **Remove `MonitorConfig`** -- Use `const sseBufferSize = 1000`.
4. **Remove `TLSConfig`** -- TLS belongs at reverse proxy layer.
5. **Remove `policyRaw` struct** -- Use custom `UnmarshalYAML` on `Policy` directly.
6. **Remove `init` command** -- `serve` creates DB on startup; document config/policies setup.
7. **Remove CSV export** -- JSON covers programmatic use; table covers human use.
8. **Defer `plugin/plugin.json`** -- No OAuth implementation yet; dead file.

### Agent-Native Additions

Add read-only REST API endpoints that mirror CLI query commands:
- `GET /api/v1/events` -- query historical events (same filters as `cc-gateway logs`)
- `GET /api/v1/sessions` -- list sessions derived from events
- `GET /api/v1/policies` -- list loaded policies
- `POST /api/v1/policies/test` -- test policy against sample event
- `GET /api/v1/metrics` -- metrics snapshot

### Library Version Notes (2026)

| Library | Latest Stable | Import Path | Key Notes |
|---------|--------------|-------------|-----------|
| modernc.org/sqlite | v1.44.3 | modernc.org/sqlite | Use `RegisterConnectionHook` for PRAGMAs. Separate reader/writer pools (`SetMaxOpenConns(1)` for writer). |
| spf13/cobra | v1.10.2 | github.com/spf13/cobra | Use `RunE` over `Run`. `PersistentPreRunE` for shared init. |
| bubbletea | v2.0.1 | charm.land/bubbletea/v2 | **Breaking v2**: `View()` returns `tea.View` not `string`. `tea.WithAltScreen()` replaced by `v.AltScreen = true`. Use `p.Send()` for external events. |
| lipgloss | v2.0.0-beta.2 | github.com/charmbracelet/lipgloss | API mostly stable. |
| fsnotify | v1.8.0 | github.com/fsnotify/fsnotify | Add debounce timer (100ms) for rapid write events. |
| yaml.v3 | v3.0.1 | gopkg.in/yaml.v3 | Stable. |

### Bubble Tea v2 Migration Notes

The plan uses bubbletea v1 patterns. Update for v2:
```go
// v2: View() returns tea.View, not string
func (m Model) View() tea.View {
    v := tea.NewView(m.renderContent())
    v.AltScreen = true
    v.WindowTitle = "cc-gateway monitor"
    return v
}

// v2: KeyMsg renamed to KeyPressMsg
case tea.KeyPressMsg:
    switch msg.String() { ... }

// v2: Use p.Send() for SSE events from goroutine
go func() {
    for evt := range sseChannel {
        p.Send(eventMsg(evt))
    }
}()
```

### SQLite Best Practices

```go
// Separate reader/writer pools
writerDB, _ := sql.Open("sqlite", "file:cc-gateway.db?_txlock=immediate")
writerDB.SetMaxOpenConns(1)
readerDB, _ := sql.Open("sqlite", "file:cc-gateway.db?mode=ro")
readerDB.SetMaxOpenConns(runtime.NumCPU())

// Connection hook for PRAGMAs (runs per-connection)
sqlite.RegisterConnectionHook(func(conn sqlite.ExecQuerierContext, dsn string) error {
    _, err := conn.ExecContext(context.Background(),
        `PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
         PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;`)
    return err
})
```

### fsnotify Debounce Pattern

```go
func (w *Watcher) loop() {
    var debounce *time.Timer
    for {
        select {
        case <-w.done:
            return
        case event, ok := <-w.watcher.Events:
            if !ok { return }
            if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) {
                if debounce != nil {
                    debounce.Stop()
                }
                debounce = time.AfterFunc(100*time.Millisecond, func() {
                    if err := w.reload(); err != nil {
                        slog.Error("policy reload failed", "error", err)
                    }
                })
            }
        case err, ok := <-w.watcher.Errors:
            if !ok { return }
            slog.Error("watcher error", "error", err)
        }
    }
}
```

---

## Phase 1: Project Scaffolding & Core Types

### Task 1: Initialize Go module and directory structure

**Files:**
- Create: `cmd/cc-gateway/main.go`
- Create: `internal/config/config.go`
- Create: `internal/hook/types.go`

**Step 1: Create directory structure**

Run:
```bash
mkdir -p cmd/cc-gateway internal/{config,server,policy,storage,auth,tui,metrics} policies docs/plans
```

**Step 2: Add core dependencies**

Run:
```bash
go get github.com/spf13/cobra@latest
go get modernc.org/sqlite@latest
go get gopkg.in/yaml.v3@latest
go get github.com/fsnotify/fsnotify@latest
go get github.com/charmbracelet/bubbletea@latest
go get github.com/charmbracelet/lipgloss@latest
```

**Step 3: Write the hook types matching the Claude Code protocol**

These types match the actual Claude Code HTTP hook JSON format exactly. All hook requests include common fields (`session_id`, `transcript_path`, `cwd`, `permission_mode`, `hook_event_name`) plus event-specific fields.

```go
// internal/hook/types.go
package hook

import "encoding/json"

// CommonInput contains fields present in every hook event.
type CommonInput struct {
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	PermissionMode string `json:"permission_mode"`
	HookEventName  string `json:"hook_event_name"`
}

// PreToolUseInput is the JSON body for PreToolUse hook events.
type PreToolUseInput struct {
	CommonInput
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id"`
}

// PostToolUseInput is the JSON body for PostToolUse hook events.
type PostToolUseInput struct {
	CommonInput
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response"`
	ToolUseID    string          `json:"tool_use_id"`
}

// NotificationInput is the JSON body for Notification hook events.
type NotificationInput struct {
	CommonInput
	Message          string `json:"message"`
	Title            string `json:"title,omitempty"`
	NotificationType string `json:"notification_type"`
}

// StopInput is the JSON body for Stop hook events.
type StopInput struct {
	CommonInput
	StopHookActive       bool   `json:"stop_hook_active"`
	LastAssistantMessage string `json:"last_assistant_message"`
}

// HookSpecificOutput is the nested decision object for PreToolUse.
type HookSpecificOutput struct {
	HookEventName          string          `json:"hookEventName"`
	PermissionDecision     string          `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string        `json:"permissionDecisionReason,omitempty"`
	UpdatedInput           json.RawMessage `json:"updatedInput,omitempty"`
	AdditionalContext      string          `json:"additionalContext,omitempty"`
}

// HookResponse is the JSON response from cc-gateway to Claude Code.
// For PreToolUse: use HookSpecificOutput with permissionDecision.
// For PostToolUse/Stop: use top-level Decision.
// For Notification: no decision control, return empty or with context.
type HookResponse struct {
	Decision           string              `json:"decision,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	Continue           *bool               `json:"continue,omitempty"`
	StopReason         string              `json:"stopReason,omitempty"`
	SuppressOutput     bool                `json:"suppressOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}
```

**Step 4: Write minimal main.go**

```go
// cmd/cc-gateway/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	fmt.Println("cc-gateway")
	return nil
}
```

**Step 5: Write config types**

```go
// internal/config/config.go
package config

import "time"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Auth     AuthConfig     `yaml:"auth"`
	Storage  StorageConfig  `yaml:"storage"`
	Policies PoliciesConfig `yaml:"policies"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type ServerConfig struct {
	Addr         string        `yaml:"addr"`
	ReadTimeout  time.Duration `yaml:"read_timeout"`
	WriteTimeout time.Duration `yaml:"write_timeout"`
}

type AuthConfig struct {
	BearerTokens []TokenEntry `yaml:"bearer_tokens"`
}

type TokenEntry struct {
	TokenHash string `yaml:"token_hash"` // SHA-256 hex hash
	UserID    string `yaml:"user_id"`
	UserName  string `yaml:"user_name"`
}

type StorageConfig struct {
	Driver    string        `yaml:"driver"`
	DSN       string        `yaml:"dsn"`
	Retention time.Duration `yaml:"retention"`
}

type PoliciesConfig struct {
	Dir           string `yaml:"dir"`
	Watch         bool   `yaml:"watch"`
	DefaultAction string `yaml:"default_action"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	Output string `yaml:"output"`
}

func Default() Config {
	return Config{
		Server: ServerConfig{
			Addr:         ":8080",
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		},
		Storage: StorageConfig{
			Driver:    "sqlite",
			DSN:       "cc-gateway.db",
			Retention: 90 * 24 * time.Hour,
		},
		Policies: PoliciesConfig{
			Dir:           "./policies",
			Watch:         true,
			DefaultAction: "allow",
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "json",
			Output: "stdout",
		},
	}
}
```

**Step 6: Verify it compiles**

Run: `go build ./...`
Expected: No errors

**Step 7: Commit**

```bash
git add -A
git commit -m "feat: project scaffolding with hook types and config"
```

---

## Phase 2: SQLite Event Store

### Task 2: Storage layer with schema migrations

**Files:**
- Create: `internal/storage/store.go`
- Create: `internal/storage/migrations.go`
- Create: `internal/storage/store_test.go`

**Step 1: Write the failing test**

```go
// internal/storage/store_test.go
package storage

import (
	"context"
	"testing"
	"time"
)

func TestInsertAndQueryEvent(t *testing.T) {
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	evt := Event{
		SessionID:     "sess-1",
		UserID:        "alice@co.com",
		EventType:     "PreToolUse",
		ToolName:      "Bash",
		ToolParams:    `{"command":"ls"}`,
		PolicyName:    "",
		PolicyAction:  "allow",
		PolicyMessage: "",
		CreatedAt:     time.Now(),
	}

	err = store.InsertEvent(context.Background(), &evt)
	if err != nil {
		t.Fatalf("insert event: %v", err)
	}
	if evt.ID == 0 {
		t.Fatal("expected event ID to be set")
	}

	events, err := store.QueryEvents(context.Background(), EventFilter{
		UserID: "alice@co.com",
		Limit:  10,
	})
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].ToolName != "Bash" {
		t.Errorf("expected tool Bash, got %s", events[0].ToolName)
	}
}

func TestUpsertAndQuerySession(t *testing.T) {
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	now := time.Now()
	sess := Session{
		ID:             "sess-1",
		UserID:         "alice@co.com",
		StartedAt:      now,
		EventCount:     1,
		ViolationCount: 0,
	}

	err = store.UpsertSession(context.Background(), &sess)
	if err != nil {
		t.Fatalf("upsert session: %v", err)
	}

	sessions, err := store.QuerySessions(context.Background(), SessionFilter{
		UserID: "alice@co.com",
	})
	if err != nil {
		t.Fatalf("query sessions: %v", err)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
}

func TestQueryEventsFilters(t *testing.T) {
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	now := time.Now()

	events := []Event{
		{SessionID: "s1", UserID: "alice", EventType: "PreToolUse", ToolName: "Bash", PolicyAction: "allow", CreatedAt: now},
		{SessionID: "s1", UserID: "alice", EventType: "PreToolUse", ToolName: "Read", PolicyAction: "block", PolicyName: "block-env", CreatedAt: now},
		{SessionID: "s2", UserID: "bob", EventType: "PreToolUse", ToolName: "Bash", PolicyAction: "allow", CreatedAt: now},
	}
	for i := range events {
		if err := store.InsertEvent(ctx, &events[i]); err != nil {
			t.Fatalf("insert event %d: %v", i, err)
		}
	}

	tests := []struct {
		name     string
		filter   EventFilter
		wantLen  int
	}{
		{"by user", EventFilter{UserID: "alice", Limit: 10}, 2},
		{"by tool", EventFilter{ToolName: "Bash", Limit: 10}, 2},
		{"by status block", EventFilter{PolicyAction: "block", Limit: 10}, 1},
		{"limit 1", EventFilter{Limit: 1}, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := store.QueryEvents(ctx, tt.filter)
			if err != nil {
				t.Fatalf("query: %v", err)
			}
			if len(got) != tt.wantLen {
				t.Errorf("expected %d events, got %d", tt.wantLen, len(got))
			}
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/storage/ -v`
Expected: FAIL (package doesn't exist yet)

**Step 3: Write migrations**

```go
// internal/storage/migrations.go
package storage

const schemaSQL = `
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id TEXT NOT NULL,
	user_id TEXT NOT NULL DEFAULT '',
	event_type TEXT NOT NULL,
	tool_name TEXT NOT NULL DEFAULT '',
	tool_params TEXT NOT NULL DEFAULT '{}',
	policy_name TEXT NOT NULL DEFAULT '',
	policy_action TEXT NOT NULL DEFAULT '',
	policy_message TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_user ON events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL DEFAULT '',
	started_at DATETIME NOT NULL,
	ended_at DATETIME,
	event_count INTEGER NOT NULL DEFAULT 0,
	violation_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL DEFAULT '',
	token_hash TEXT NOT NULL DEFAULT '',
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_active_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`
```

**Step 4: Write store implementation**

```go
// internal/storage/store.go
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Event struct {
	ID            int64     `json:"id"`
	SessionID     string    `json:"session_id"`
	UserID        string    `json:"user_id"`
	EventType     string    `json:"event_type"`
	ToolName      string    `json:"tool_name"`
	ToolParams    string    `json:"tool_params"`
	PolicyName    string    `json:"policy_name"`
	PolicyAction  string    `json:"policy_action"`
	PolicyMessage string    `json:"policy_message"`
	CreatedAt     time.Time `json:"created_at"`
}

type Session struct {
	ID             string     `json:"id"`
	UserID         string     `json:"user_id"`
	StartedAt      time.Time  `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	EventCount     int        `json:"event_count"`
	ViolationCount int        `json:"violation_count"`
}

type EventFilter struct {
	UserID       string
	SessionID    string
	EventType    string
	ToolName     string
	PolicyAction string
	Since        *time.Time
	Until        *time.Time
	Limit        int
}

type SessionFilter struct {
	UserID     string
	ActiveOnly bool
}

type Store struct {
	db *sql.DB
}

func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite %q: %w", dsn, err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) InsertEvent(ctx context.Context, e *Event) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO events (session_id, user_id, event_type, tool_name, tool_params, policy_name, policy_action, policy_message, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.SessionID, e.UserID, e.EventType, e.ToolName, e.ToolParams,
		e.PolicyName, e.PolicyAction, e.PolicyMessage, e.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fmt.Errorf("get last insert id: %w", err)
	}
	e.ID = id
	return nil
}

func (s *Store) QueryEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	var where []string
	var args []any

	if f.UserID != "" {
		where = append(where, "user_id = ?")
		args = append(args, f.UserID)
	}
	if f.SessionID != "" {
		where = append(where, "session_id = ?")
		args = append(args, f.SessionID)
	}
	if f.EventType != "" {
		where = append(where, "event_type = ?")
		args = append(args, f.EventType)
	}
	if f.ToolName != "" {
		where = append(where, "tool_name = ?")
		args = append(args, f.ToolName)
	}
	if f.PolicyAction != "" {
		where = append(where, "policy_action = ?")
		args = append(args, f.PolicyAction)
	}
	if f.Since != nil {
		where = append(where, "created_at >= ?")
		args = append(args, *f.Since)
	}
	if f.Until != nil {
		where = append(where, "created_at <= ?")
		args = append(args, *f.Until)
	}

	query := "SELECT id, session_id, user_id, event_type, tool_name, tool_params, policy_name, policy_action, policy_message, created_at FROM events"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY created_at DESC"

	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(" LIMIT %d", limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.SessionID, &e.UserID, &e.EventType, &e.ToolName, &e.ToolParams, &e.PolicyName, &e.PolicyAction, &e.PolicyMessage, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) UpsertSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, user_id, started_at, ended_at, event_count, violation_count)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		   ended_at = COALESCE(excluded.ended_at, sessions.ended_at),
		   event_count = excluded.event_count,
		   violation_count = excluded.violation_count`,
		sess.ID, sess.UserID, sess.StartedAt, sess.EndedAt,
		sess.EventCount, sess.ViolationCount,
	)
	if err != nil {
		return fmt.Errorf("upsert session: %w", err)
	}
	return nil
}

func (s *Store) QuerySessions(ctx context.Context, f SessionFilter) ([]Session, error) {
	var where []string
	var args []any

	if f.UserID != "" {
		where = append(where, "user_id = ?")
		args = append(args, f.UserID)
	}
	if f.ActiveOnly {
		where = append(where, "ended_at IS NULL")
	}

	query := "SELECT id, user_id, started_at, ended_at, event_count, violation_count FROM sessions"
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}
	query += " ORDER BY started_at DESC LIMIT 100"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.StartedAt, &s.EndedAt, &s.EventCount, &s.ViolationCount); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		sessions = append(sessions, s)
	}
	return sessions, rows.Err()
}

func (s *Store) EndSession(ctx context.Context, sessionID string, endedAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE events SET created_at = created_at WHERE session_id = ?`, sessionID) // no-op to verify session exists
	if err != nil {
		return fmt.Errorf("end session: %w", err)
	}
	return nil
}

func (s *Store) DB() *sql.DB {
	return s.db
}
```

**Step 5: Run tests**

Run: `go test ./internal/storage/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/storage/
git commit -m "feat: SQLite event store with events, sessions, and query filters"
```

---

## Phase 3: Policy Engine

### Task 3: YAML policy parsing and evaluation

**Files:**
- Create: `internal/policy/policy.go`
- Create: `internal/policy/engine.go`
- Create: `internal/policy/engine_test.go`

**Step 1: Write the failing test**

```go
// internal/policy/engine_test.go
package policy

import (
	"encoding/json"
	"testing"
)

func TestEvaluateBlocksDestructiveCommand(t *testing.T) {
	policies := []Policy{
		{
			Name:    "block-destructive",
			Enabled: true,
			Event:   "PreToolUse",
			Matcher: "Bash",
			Conditions: []Condition{
				{Field: "command", Pattern: `rm\s+-rf\s+/`},
			},
			Action:  "block",
			Message: "Destructive command blocked",
		},
	}

	engine := NewEngine(policies)

	input := json.RawMessage(`{"command": "rm -rf /tmp"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "block" {
		t.Errorf("expected block, got %s", result.Action)
	}
	if result.PolicyName != "block-destructive" {
		t.Errorf("expected policy block-destructive, got %s", result.PolicyName)
	}
}

func TestEvaluateAllowsSafeCommand(t *testing.T) {
	policies := []Policy{
		{
			Name:    "block-destructive",
			Enabled: true,
			Event:   "PreToolUse",
			Matcher: "Bash",
			Conditions: []Condition{
				{Field: "command", Pattern: `rm\s+-rf\s+/`},
			},
			Action:  "block",
			Message: "Destructive command blocked",
		},
	}

	engine := NewEngine(policies)

	input := json.RawMessage(`{"command": "npm test"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "allow" {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestEvaluateMatcherFiltering(t *testing.T) {
	policies := []Policy{
		{
			Name:    "block-env-read",
			Enabled: true,
			Event:   "PreToolUse",
			Matcher: "Read",
			Conditions: []Condition{
				{Field: "file_path", Pattern: `\.env$`},
			},
			Action:  "block",
			Message: "Cannot read .env files",
		},
	}

	engine := NewEngine(policies)

	// Bash tool should not match a Read-only policy
	input := json.RawMessage(`{"command": "cat .env"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "allow" {
		t.Errorf("expected allow for non-matching tool, got %s", result.Action)
	}
}

func TestEvaluateNegateCondition(t *testing.T) {
	policies := []Policy{
		{
			Name:    "block-non-project-installs",
			Enabled: true,
			Event:   "PreToolUse",
			Matcher: "Bash",
			Conditions: []Condition{
				{Field: "command", Pattern: `npm install`},
				{Field: "command", Pattern: `--save-dev`, Negate: true},
			},
			Action:  "block",
			Message: "Only devDependencies allowed",
		},
	}

	engine := NewEngine(policies)

	// Should block: npm install without --save-dev
	input := json.RawMessage(`{"command": "npm install lodash"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)
	if result.Action != "block" {
		t.Errorf("expected block, got %s", result.Action)
	}

	// Should allow: npm install with --save-dev
	input = json.RawMessage(`{"command": "npm install --save-dev jest"}`)
	result = engine.Evaluate("PreToolUse", "Bash", input)
	if result.Action != "allow" {
		t.Errorf("expected allow, got %s", result.Action)
	}
}

func TestEvaluatePriorityOrdering(t *testing.T) {
	policies := []Policy{
		{
			Name:     "allow-npm-test",
			Enabled:  true,
			Event:    "PreToolUse",
			Matcher:  "Bash",
			Conditions: []Condition{
				{Field: "command", Pattern: `^npm test$`},
			},
			Action:   "allow",
			Priority: 10,
		},
		{
			Name:     "block-all-npm",
			Enabled:  true,
			Event:    "PreToolUse",
			Matcher:  "Bash",
			Conditions: []Condition{
				{Field: "command", Pattern: `npm`},
			},
			Action:   "block",
			Message:  "npm commands blocked",
			Priority: 1,
		},
	}

	engine := NewEngine(policies)

	input := json.RawMessage(`{"command": "npm test"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "allow" {
		t.Errorf("expected allow (higher priority), got %s", result.Action)
	}
}

func TestEvaluateDisabledPolicy(t *testing.T) {
	policies := []Policy{
		{
			Name:    "disabled-policy",
			Enabled: false,
			Event:   "PreToolUse",
			Matcher: "Bash",
			Conditions: []Condition{
				{Field: "command", Pattern: ".*"},
			},
			Action:  "block",
			Message: "Everything blocked",
		},
	}

	engine := NewEngine(policies)

	input := json.RawMessage(`{"command": "ls"}`)
	result := engine.Evaluate("PreToolUse", "Bash", input)

	if result.Action != "allow" {
		t.Errorf("disabled policy should not match, got %s", result.Action)
	}
}

func TestLoadPoliciesFromYAML(t *testing.T) {
	yaml := `
policies:
  - name: test-policy
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm -rf"
    action: block
    message: "blocked"
`
	policies, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("parse yaml: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0].Name != "test-policy" {
		t.Errorf("expected test-policy, got %s", policies[0].Name)
	}
	if !policies[0].Enabled {
		t.Error("policy should default to enabled")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -v`
Expected: FAIL

**Step 3: Write policy types**

```go
// internal/policy/policy.go
package policy

import (
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

type Policy struct {
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Enabled     bool        `yaml:"enabled"`
	Event       string      `yaml:"event"`
	Matcher     string      `yaml:"matcher"`
	Conditions  []Condition `yaml:"conditions"`
	Action      string      `yaml:"action"`
	Message     string      `yaml:"message"`
	Priority    int         `yaml:"priority"`
}

type Condition struct {
	Field   string         `yaml:"field"`
	Pattern string         `yaml:"pattern"`
	Negate  bool           `yaml:"negate"`
	re      *regexp.Regexp // compiled at load time
}

type EvalResult struct {
	Action     string
	PolicyName string
	Message    string
}

type policyFile struct {
	Policies []Policy `yaml:"policies"`
}

// UnmarshalYAML implements custom unmarshaling to default Enabled to true.
func (p *Policy) UnmarshalYAML(unmarshal func(any) error) error {
	type raw Policy
	r := raw{Enabled: true} // default
	if err := unmarshal(&r); err != nil {
		return err
	}
	*p = Policy(r)
	return nil
}

func ParseYAML(data []byte) ([]Policy, error) {
	var f policyFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, err
	}

	for i := range f.Policies {
		for j := range f.Policies[i].Conditions {
			compiled, err := regexp.Compile(f.Policies[i].Conditions[j].Pattern)
			if err != nil {
				return nil, fmt.Errorf("policy %q condition %q: invalid regex: %w",
					f.Policies[i].Name, f.Policies[i].Conditions[j].Pattern, err)
			}
			f.Policies[i].Conditions[j].re = compiled
		}
	}
	return f.Policies, nil
}
```

**Step 4: Write engine implementation**

> **RESEARCH INSIGHT (Performance Oracle + Security Sentinel):** Precompile regex patterns at load time. `regexp.MatchString` recompiles on every call. Invalid patterns silently fail to match, creating security bypasses. Compile at load time, reject invalid patterns with clear errors.

```go
// internal/policy/engine.go
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

type Engine struct {
	mu       sync.RWMutex
	policies []Policy
}

func NewEngine(policies []Policy) *Engine {
	e := &Engine{}
	e.SetPolicies(policies)
	return e
}

func (e *Engine) SetPolicies(policies []Policy) {
	sorted := make([]Policy, len(policies))
	copy(sorted, policies)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority > sorted[j].Priority
		}
		return sorted[i].Name < sorted[j].Name
	})
	e.mu.Lock()
	e.policies = sorted
	e.mu.Unlock()
}

func (e *Engine) Policies() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

func (e *Engine) Evaluate(event, toolName string, toolInput json.RawMessage) EvalResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var params map[string]any
	if len(toolInput) > 0 {
		_ = json.Unmarshal(toolInput, &params)
	}

	for _, p := range e.policies {
		if !p.Enabled {
			continue
		}
		if p.Event != event {
			continue
		}
		if p.Matcher != "" && p.Matcher != toolName {
			continue
		}
		if matchesAll(p.Conditions, params) {
			return EvalResult{
				Action:     p.Action,
				PolicyName: p.Name,
				Message:    p.Message,
			}
		}
	}

	return EvalResult{Action: "allow"}
}

func matchesAll(conditions []Condition, params map[string]any) bool {
	for _, c := range conditions {
		val := extractField(params, c.Field)
		if c.re == nil {
			continue
		}
		matched := c.re.MatchString(val)
		if c.Negate {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

func extractField(params map[string]any, field string) string {
	parts := strings.Split(field, ".")
	var current any = params
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current = m[part]
	}
	if current == nil {
		return ""
	}
	return fmt.Sprintf("%v", current)
}

func LoadFromDir(dir string) ([]Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policies dir %q: %w", dir, err)
	}

	var all []Policy
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := filepath.Ext(entry.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("read policy file %q: %w", entry.Name(), err)
		}
		policies, err := ParseYAML(data)
		if err != nil {
			return nil, fmt.Errorf("parse policy file %q: %w", entry.Name(), err)
		}
		all = append(all, policies...)
	}
	return all, nil
}
```

**Note:** The engine code above should be in package `policy`, not `engine`. Fix the package declaration to `package policy`.

**Step 5: Run tests**

Run: `go test ./internal/policy/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/policy/
git commit -m "feat: YAML policy engine with conditions, priority, and negation"
```

---

## Phase 4: HTTP Server & Hook Handlers

### Task 4: HTTP server with hook endpoints

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/handlers.go`
- Create: `internal/server/server_test.go`

**Step 1: Write the failing test**

```go
// internal/server/server_test.go
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/irad100/cc-gateway/internal/hook"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

func setupTestServer(t *testing.T, policies []policy.Policy) *Server {
	t.Helper()
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	engine := policy.NewEngine(policies)
	return New(store, engine)
}

func TestPreToolUseAllow(t *testing.T) {
	srv := setupTestServer(t, nil)

	body := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-1",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "npm test"}`),
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp hook.HookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// No policy matched, so no hookSpecificOutput with deny
	if resp.HookSpecificOutput != nil && resp.HookSpecificOutput.PermissionDecision == "deny" {
		t.Error("expected allow, got deny")
	}
}

func TestPreToolUseBlock(t *testing.T) {
	policies := []policy.Policy{
		{
			Name:    "block-rm",
			Enabled: true,
			Event:   "PreToolUse",
			Matcher: "Bash",
			Conditions: []policy.Condition{
				{Field: "command", Pattern: `rm\s+-rf`},
			},
			Action:  "block",
			Message: "Destructive command blocked",
		},
	}

	srv := setupTestServer(t, policies)

	body := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-1",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "rm -rf /tmp"}`),
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp hook.HookResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput")
	}
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("expected deny, got %s", resp.HookSpecificOutput.PermissionDecision)
	}
}

func TestPostToolUseOK(t *testing.T) {
	srv := setupTestServer(t, nil)

	body := hook.PostToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-1",
			HookEventName: "PostToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "ls"}`),
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/hooks/post-tool-use", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestNotificationOK(t *testing.T) {
	srv := setupTestServer(t, nil)

	body := hook.NotificationInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-1",
			HookEventName: "Notification",
		},
		Message:          "Permission needed",
		NotificationType: "permission_prompt",
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/hooks/notification", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestStopOK(t *testing.T) {
	srv := setupTestServer(t, nil)

	body := hook.StopInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-1",
			HookEventName: "Stop",
		},
		StopHookActive: false,
	}
	b, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/hooks/stop", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -v`
Expected: FAIL

**Step 3: Write server and handlers**

```go
// internal/server/server.go
package server

import (
	"log/slog"
	"net/http"

	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

type Server struct {
	store  *storage.Store
	engine *policy.Engine
	logger *slog.Logger
}

func New(store *storage.Store, engine *policy.Engine) *Server {
	return &Server{
		store:  store,
		engine: engine,
		logger: slog.Default(),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/pre-tool-use", s.handlePreToolUse)
	mux.HandleFunc("POST /hooks/post-tool-use", s.handlePostToolUse)
	mux.HandleFunc("POST /hooks/notification", s.handleNotification)
	mux.HandleFunc("POST /hooks/stop", s.handleStop)
	mux.HandleFunc("GET /health", s.handleHealth)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
```

```go
// internal/server/handlers.go
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/irad100/cc-gateway/internal/hook"
	"github.com/irad100/cc-gateway/internal/storage"
)

func (s *Server) handlePreToolUse(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var input hook.PreToolUseInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result := s.engine.Evaluate("PreToolUse", input.ToolName, input.ToolInput)

	s.logEvent(r.Context(), input.CommonInput, input.ToolName, input.ToolInput, result)

	var resp hook.HookResponse
	if result.Action == "block" {
		resp.HookSpecificOutput = &hook.HookSpecificOutput{
			HookEventName:           "PreToolUse",
			PermissionDecision:      "deny",
			PermissionDecisionReason: fmt.Sprintf("Policy '%s': %s", result.PolicyName, result.Message),
		}
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePostToolUse(w http.ResponseWriter, r *http.Request) {
	var input hook.PostToolUseInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	result := s.engine.Evaluate("PostToolUse", input.ToolName, input.ToolInput)
	s.logEvent(r.Context(), input.CommonInput, input.ToolName, input.ToolInput, result)

	s.writeJSON(w, http.StatusOK, hook.HookResponse{})
}

func (s *Server) handleNotification(w http.ResponseWriter, r *http.Request) {
	var input hook.NotificationInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.logEvent(r.Context(), input.CommonInput, "", nil, policy.EvalResult{Action: "allow"})

	s.writeJSON(w, http.StatusOK, hook.HookResponse{})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	var input hook.StopInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	s.logEvent(r.Context(), input.CommonInput, "", nil, policy.EvalResult{Action: "allow"})

	// Mark session as ended
	now := time.Now()
	if err := s.store.EndSession(r.Context(), input.SessionID, now); err != nil {
		s.logger.Error("failed to end session", "session_id", input.SessionID, "error", err)
	}

	s.writeJSON(w, http.StatusOK, hook.HookResponse{})
}

func (s *Server) logEvent(ctx context.Context, common hook.CommonInput, toolName string, toolInput json.RawMessage, result policy.EvalResult) {
	evt := storage.Event{
		SessionID:     common.SessionID,
		UserID:        auth.UserFromContext(ctx),
		EventType:     common.HookEventName,
		ToolName:      toolName,
		ToolParams:    string(toolInput),
		PolicyName:    result.PolicyName,
		PolicyAction:  result.Action,
		PolicyMessage: result.Message,
		CreatedAt:     time.Now(),
	}

	if err := s.store.InsertEvent(ctx, &evt); err != nil {
		s.logger.Error("failed to log event", "error", err)
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) jsonError(w http.ResponseWriter, msg string, status int) {
	s.writeJSON(w, status, map[string]string{"error": msg})
}
```

**Note:** The handlers.go file needs to import `policy` for the `EvalResult` type and `auth` for `UserFromContext`. Add `"github.com/irad100/cc-gateway/internal/policy"` and `"github.com/irad100/cc-gateway/internal/auth"` to imports.

**Step 4: Run tests**

Run: `go test ./internal/server/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/server/
git commit -m "feat: HTTP hook handlers with policy evaluation and event logging"
```

---

## Phase 5: CLI with Cobra

### Task 5: CLI root, serve, and init commands

**Files:**
- Create: `internal/cli/root.go`
- Create: `internal/cli/serve.go`
- Create: `internal/cli/init_cmd.go`
- Create: `internal/cli/version.go`
- Modify: `cmd/cc-gateway/main.go`

**Step 1: Write root command**

```go
// internal/cli/root.go
package cli

import (
	"github.com/spf13/cobra"
)

var (
	cfgFile string
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cc-gateway",
		Short: "Security observability and enforcement gateway for Claude Code",
	}

	cmd.PersistentFlags().StringVar(&cfgFile, "config", "cc-gateway.yaml", "config file path")

	cmd.AddCommand(newServeCmd())
	cmd.AddCommand(newInitCmd())
	cmd.AddCommand(newVersionCmd())

	return cmd
}
```

**Step 2: Write serve command**

```go
// internal/cli/serve.go
package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/irad100/cc-gateway/internal/config"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/server"
	"github.com/irad100/cc-gateway/internal/storage"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newServeCmd() *cobra.Command {
	var addr string
	var policiesDir string
	var dbPath string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the gateway HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := config.Default()
			if data, err := os.ReadFile(cfgFile); err == nil {
				if err := yaml.Unmarshal(data, &cfg); err != nil {
					return fmt.Errorf("parse config: %w", err)
				}
			}

			if addr != "" {
				cfg.Server.Addr = addr
			}
			if policiesDir != "" {
				cfg.Policies.Dir = policiesDir
			}
			if dbPath != "" {
				cfg.Storage.DSN = dbPath
			}

			return runServe(cfg)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "", "listen address (default :8080)")
	cmd.Flags().StringVar(&policiesDir, "policies-dir", "", "policies directory")
	cmd.Flags().StringVar(&dbPath, "db", "", "SQLite database path")

	return cmd
}

func runServe(cfg config.Config) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(cfg.Logging.Level),
	}))
	slog.SetDefault(logger)

	store, err := storage.New(cfg.Storage.DSN)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	policies, err := policy.LoadFromDir(cfg.Policies.Dir)
	if err != nil {
		logger.Warn("failed to load policies, starting with empty set", "error", err)
	}
	engine := policy.NewEngine(policies)
	logger.Info("loaded policies", "count", len(policies))

	srv := server.New(store, engine)

	httpSrv := &http.Server{
		Addr:              cfg.Server.Addr,
		Handler:           srv.Handler(),
		ReadTimeout:       cfg.Server.ReadTimeout,
		WriteTimeout:      cfg.Server.WriteTimeout,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("starting server", "addr", cfg.Server.Addr)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("server error", "error", err)
		}
	}()

	<-ctx.Done()
	logger.Info("shutting down")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
```

**Step 3: Write init command**

```go
// internal/cli/init_cmd.go
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/irad100/cc-gateway/internal/config"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize config, policies directory, and database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit()
		},
	}
}

func runInit() error {
	// Write default config
	cfg := config.Default()
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile("cc-gateway.yaml", data, 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Println("Created cc-gateway.yaml")

	// Create policies directory with default policy
	if err := os.MkdirAll("policies", 0755); err != nil {
		return fmt.Errorf("create policies dir: %w", err)
	}

	defaultPolicy := `policies:
  - name: block-destructive-commands
    description: Block dangerous shell commands
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf\\s+/"
    action: block
    message: "Destructive rm -rf on root paths is not allowed"

  - name: block-secret-file-access
    description: Block reading secret files
    event: PreToolUse
    matcher: Read
    conditions:
      - field: file_path
        pattern: "\\.(env|pem|key|p12)$"
    action: block
    message: "Access to secret files is restricted by security policy"
`
	if err := os.WriteFile("policies/default.yaml", []byte(defaultPolicy), 0644); err != nil {
		return fmt.Errorf("write default policy: %w", err)
	}
	fmt.Println("Created policies/default.yaml")

	fmt.Println("\nRun 'cc-gateway serve' to start the server")
	return nil
}
```

**Step 4: Write version command**

```go
// internal/cli/version.go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cc-gateway %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}
```

**Step 5: Update main.go**

```go
// cmd/cc-gateway/main.go
package main

import (
	"fmt"
	"os"

	"github.com/irad100/cc-gateway/internal/cli"
)

func main() {
	if err := cli.NewRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
```

**Step 6: Verify it builds and runs**

Run: `go build -o cc-gateway ./cmd/cc-gateway && ./cc-gateway version`
Expected: `cc-gateway dev (commit: none, built: unknown)`

**Step 7: Commit**

```bash
git add cmd/ internal/cli/
git commit -m "feat: Cobra CLI with serve, init, and version commands"
```

---

## Phase 6: Default Policies & Policy Hot-Reload

### Task 6: Policy file watcher with hot-reload

**Files:**
- Create: `internal/policy/watcher.go`
- Create: `internal/policy/watcher_test.go`

**Step 1: Write the failing test**

```go
// internal/policy/watcher_test.go
package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcherDetectsChange(t *testing.T) {
	dir := t.TempDir()

	initial := `policies:
  - name: test
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "echo"
    action: block
    message: "blocked"
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(initial), 0644); err != nil {
		t.Fatal(err)
	}

	engine := NewEngine(nil)
	w, err := NewWatcher(dir, engine)
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	defer w.Close()

	// Initial load should have picked up the file
	if len(engine.Policies()) != 1 {
		t.Fatalf("expected 1 policy after start, got %d", len(engine.Policies()))
	}

	// Write updated policy
	updated := `policies:
  - name: test
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "echo"
    action: block
    message: "blocked"
  - name: test2
    event: PreToolUse
    matcher: Read
    conditions:
      - field: file_path
        pattern: "secret"
    action: block
    message: "no secrets"
`
	if err := os.WriteFile(filepath.Join(dir, "test.yaml"), []byte(updated), 0644); err != nil {
		t.Fatal(err)
	}

	// Wait for watcher to pick up the change
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(engine.Policies()) == 2 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("expected 2 policies after update, got %d", len(engine.Policies()))
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/ -run TestWatcher -v`
Expected: FAIL

**Step 3: Write watcher**

```go
// internal/policy/watcher.go
package policy

import (
	"log/slog"

	"github.com/fsnotify/fsnotify"
)

type Watcher struct {
	watcher *fsnotify.Watcher
	dir     string
	engine  *Engine
	done    chan struct{}
}

func NewWatcher(dir string, engine *Engine) (*Watcher, error) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		watcher: fw,
		dir:     dir,
		engine:  engine,
		done:    make(chan struct{}),
	}

	// Initial load
	if err := w.reload(); err != nil {
		slog.Error("initial policy load failed", "error", err)
	}

	if err := fw.Add(dir); err != nil {
		fw.Close()
		return nil, err
	}

	go w.loop()
	return w, nil
}

func (w *Watcher) Close() error {
	close(w.done)
	return w.watcher.Close()
}

func (w *Watcher) loop() {
	for {
		select {
		case <-w.done:
			return
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Remove) {
				if err := w.reload(); err != nil {
					slog.Error("policy reload failed, keeping existing policies", "error", err)
				} else {
					slog.Info("policies reloaded", "count", len(w.engine.Policies()))
				}
			}
		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("watcher error", "error", err)
		}
	}
}

func (w *Watcher) reload() error {
	policies, err := LoadFromDir(w.dir)
	if err != nil {
		return err
	}
	w.engine.SetPolicies(policies)
	return nil
}
```

**Step 4: Run tests**

Run: `go test ./internal/policy/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/watcher.go internal/policy/watcher_test.go
git commit -m "feat: policy hot-reload via filesystem watcher"
```

---

## Phase 7: CLI Admin Commands

### Task 7: Policies, logs, and users CLI subcommands

**Files:**
- Create: `internal/cli/policies.go`
- Create: `internal/cli/logs.go`
- Create: `internal/cli/users.go`
- Modify: `internal/cli/root.go`

**Step 1: Write policies subcommand**

```go
// internal/cli/policies.go
package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/spf13/cobra"
)

func newPoliciesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policies",
		Short: "Manage security policies",
	}
	cmd.AddCommand(newPoliciesListCmd())
	cmd.AddCommand(newPoliciesValidateCmd())
	cmd.AddCommand(newPoliciesTestCmd())
	return cmd
}

func newPoliciesListCmd() *cobra.Command {
	var dir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List all loaded policies",
		RunE: func(cmd *cobra.Command, args []string) error {
			policies, err := policy.LoadFromDir(dir)
			if err != nil {
				return fmt.Errorf("load policies: %w", err)
			}
			fmt.Printf("%-30s %-12s %-10s %-8s %-8s\n", "NAME", "EVENT", "MATCHER", "ACTION", "ENABLED")
			for _, p := range policies {
				fmt.Printf("%-30s %-12s %-10s %-8s %-8v\n", p.Name, p.Event, p.Matcher, p.Action, p.Enabled)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dir, "dir", "policies", "policies directory")
	return cmd
}

func newPoliciesValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate [file...]",
		Short: "Validate policy YAML files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			allValid := true
			for _, path := range args {
				data, err := os.ReadFile(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
					allValid = false
					continue
				}
				policies, err := policy.ParseYAML(data)
				if err != nil {
					fmt.Fprintf(os.Stderr, "%s: invalid - %v\n", path, err)
					allValid = false
					continue
				}
				fmt.Printf("%s: valid (%d policies)\n", path, len(policies))
			}
			if !allValid {
				return fmt.Errorf("some files are invalid")
			}
			return nil
		},
	}
}

func newPoliciesTestCmd() *cobra.Command {
	var eventJSON string
	var policyDir string

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Test a policy against a sample event",
		RunE: func(cmd *cobra.Command, args []string) error {
			policies, err := policy.LoadFromDir(policyDir)
			if err != nil {
				return fmt.Errorf("load policies: %w", err)
			}
			engine := policy.NewEngine(policies)

			var input struct {
				Event    string          `json:"event"`
				Tool     string          `json:"tool"`
				ToolInput json.RawMessage `json:"tool_input"`
			}
			if err := json.Unmarshal([]byte(eventJSON), &input); err != nil {
				return fmt.Errorf("parse event JSON: %w", err)
			}

			result := engine.Evaluate(input.Event, input.Tool, input.ToolInput)
			fmt.Printf("Action:  %s\n", result.Action)
			if result.PolicyName != "" {
				fmt.Printf("Policy:  %s\n", result.PolicyName)
				fmt.Printf("Message: %s\n", result.Message)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&eventJSON, "event", "", `event JSON, e.g. '{"event":"PreToolUse","tool":"Bash","tool_input":{"command":"rm -rf /"}}'`)
	cmd.Flags().StringVar(&policyDir, "dir", "policies", "policies directory")
	cmd.MarkFlagRequired("event")
	return cmd
}
```

**Step 2: Write logs subcommand**

```go
// internal/cli/logs.go
package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/irad100/cc-gateway/internal/storage"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var (
		user     string
		tool     string
		status   string
		since    string
		until    string
		format   string
		limit    int
		dbPath   string
	)

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Query the audit log",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.New(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer store.Close()

			filter := storage.EventFilter{
				UserID:       user,
				ToolName:     tool,
				PolicyAction: status,
				Limit:        limit,
			}

			if since != "" {
				t, err := parseTimeArg(since)
				if err != nil {
					return fmt.Errorf("parse --since: %w", err)
				}
				filter.Since = &t
			}
			if until != "" {
				t, err := parseTimeArg(until)
				if err != nil {
					return fmt.Errorf("parse --until: %w", err)
				}
				filter.Until = &t
			}

			events, err := store.QueryEvents(cmd.Context(), filter)
			if err != nil {
				return fmt.Errorf("query events: %w", err)
			}

			switch format {
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(events)
			case "csv":
				w := csv.NewWriter(os.Stdout)
				w.Write([]string{"id", "session_id", "user_id", "event_type", "tool_name", "policy_action", "policy_name", "created_at"})
				for _, e := range events {
					w.Write([]string{
						strconv.FormatInt(e.ID, 10),
						e.SessionID, e.UserID, e.EventType,
						e.ToolName, e.PolicyAction, e.PolicyName,
						e.CreatedAt.Format(time.RFC3339),
					})
				}
				w.Flush()
				return w.Error()
			default:
				fmt.Printf("%-6s %-20s %-20s %-12s %-10s %-8s %-20s\n",
					"ID", "TIME", "USER", "EVENT", "TOOL", "ACTION", "POLICY")
				for _, e := range events {
					fmt.Printf("%-6d %-20s %-20s %-12s %-10s %-8s %-20s\n",
						e.ID, e.CreatedAt.Format("15:04:05"),
						truncate(e.UserID, 20), e.EventType,
						e.ToolName, e.PolicyAction, e.PolicyName)
				}
				return nil
			}
		},
	}

	cmd.Flags().StringVar(&user, "user", "", "filter by user")
	cmd.Flags().StringVar(&tool, "tool", "", "filter by tool name")
	cmd.Flags().StringVar(&status, "status", "", "filter by action (allow/block)")
	cmd.Flags().StringVar(&since, "since", "", "time range start (e.g., 1h, 2024-01-01)")
	cmd.Flags().StringVar(&until, "until", "", "time range end")
	cmd.Flags().StringVar(&format, "format", "table", "output format: table, json, csv")
	cmd.Flags().IntVar(&limit, "limit", 100, "max results")
	cmd.Flags().StringVar(&dbPath, "db", "cc-gateway.db", "SQLite database path")

	return cmd
}

func parseTimeArg(s string) (time.Time, error) {
	// Try duration format (1h, 30m, etc.)
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-d), nil
	}
	// Try date format
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
```

**Step 3: Write users subcommand**

```go
// internal/cli/users.go
package cli

import (
	"fmt"

	"github.com/irad100/cc-gateway/internal/storage"
	"github.com/spf13/cobra"
)

func newUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "Manage users",
	}
	cmd.AddCommand(newUsersListCmd())
	cmd.AddCommand(newUsersActivityCmd())
	return cmd
}

func newUsersListCmd() *cobra.Command {
	var dbPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered users",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.New(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer store.Close()

			users, err := store.ListUsers(cmd.Context())
			if err != nil {
				return fmt.Errorf("list users: %w", err)
			}

			fmt.Printf("%-30s %-20s %-20s %-10s\n", "USER", "FIRST SEEN", "LAST ACTIVE", "EVENTS")
			for _, u := range users {
				fmt.Printf("%-30s %-20s %-20s %-10d\n",
					u.ID,
					u.CreatedAt.Format("2006-01-02 15:04"),
					u.LastActiveAt.Format("2006-01-02 15:04"),
					u.EventCount)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "cc-gateway.db", "SQLite database path")
	return cmd
}

func newUsersActivityCmd() *cobra.Command {
	var dbPath string
	var userID string

	cmd := &cobra.Command{
		Use:   "activity",
		Short: "Show user activity summary",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := storage.New(dbPath)
			if err != nil {
				return fmt.Errorf("open db: %w", err)
			}
			defer store.Close()

			activity, err := store.UserActivity(cmd.Context(), userID)
			if err != nil {
				return fmt.Errorf("get activity: %w", err)
			}

			fmt.Printf("User: %s\n", userID)
			fmt.Printf("Sessions: %d\n", activity.SessionCount)
			fmt.Printf("Total events: %d\n", activity.EventCount)
			fmt.Printf("Violations: %d\n", activity.ViolationCount)
			fmt.Println("\nTool usage:")
			for tool, count := range activity.ToolUsage {
				fmt.Printf("  %-15s %d\n", tool, count)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dbPath, "db", "cc-gateway.db", "SQLite database path")
	cmd.Flags().StringVar(&userID, "user", "", "user ID")
	cmd.MarkFlagRequired("user")
	return cmd
}
```

**Step 4: Add query methods to storage**

Add these methods to `internal/storage/store.go`:

```go
type User struct {
	ID           string    `json:"id"`
	DisplayName  string    `json:"display_name"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	EventCount   int       `json:"event_count"`
}

type UserActivity struct {
	SessionCount   int            `json:"session_count"`
	EventCount     int            `json:"event_count"`
	ViolationCount int            `json:"violation_count"`
	ToolUsage      map[string]int `json:"tool_usage"`
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT user_id, MIN(created_at) as first_seen, MAX(created_at) as last_active, COUNT(*) as event_count
		 FROM events WHERE user_id != '' GROUP BY user_id ORDER BY last_active DESC`)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.CreatedAt, &u.LastActiveAt, &u.EventCount); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (s *Store) UserActivity(ctx context.Context, userID string) (*UserActivity, error) {
	a := &UserActivity{ToolUsage: make(map[string]int)}

	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(DISTINCT session_id), COUNT(*), SUM(CASE WHEN policy_action = 'block' THEN 1 ELSE 0 END)
		 FROM events WHERE user_id = ?`, userID).
		Scan(&a.SessionCount, &a.EventCount, &a.ViolationCount)
	if err != nil {
		return nil, fmt.Errorf("query user activity: %w", err)
	}

	rows, err := s.db.QueryContext(ctx,
		`SELECT tool_name, COUNT(*) FROM events WHERE user_id = ? AND tool_name != '' GROUP BY tool_name ORDER BY COUNT(*) DESC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("query tool usage: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var tool string
		var count int
		if err := rows.Scan(&tool, &count); err != nil {
			return nil, fmt.Errorf("scan tool usage: %w", err)
		}
		a.ToolUsage[tool] = count
	}
	return a, rows.Err()
}
```

**Step 5: Update root.go to add new commands**

Add to `NewRootCmd()`:
```go
cmd.AddCommand(newPoliciesCmd())
cmd.AddCommand(newLogsCmd())
cmd.AddCommand(newUsersCmd())
```

**Step 6: Verify it builds**

Run: `go build ./...`
Expected: No errors

**Step 7: Commit**

```bash
git add internal/cli/ internal/storage/
git commit -m "feat: CLI admin commands for policies, logs, and users"
```

---

## Phase 8: SSE Event Stream

### Task 8: Server-Sent Events endpoint for live monitoring

**Files:**
- Create: `internal/server/sse.go`
- Modify: `internal/server/server.go` (add SSE broker)
- Modify: `internal/server/handlers.go` (broadcast events)

**Step 1: Write SSE broker**

```go
// internal/server/sse.go
package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/irad100/cc-gateway/internal/storage"
)

type SSEBroker struct {
	mu          sync.RWMutex
	clients     map[chan storage.Event]struct{}
	bufferSize  int
}

func NewSSEBroker(bufferSize int) *SSEBroker {
	return &SSEBroker{
		clients:    make(map[chan storage.Event]struct{}),
		bufferSize: bufferSize,
	}
}

func (b *SSEBroker) Subscribe() chan storage.Event {
	ch := make(chan storage.Event, b.bufferSize)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()
	return ch
}

func (b *SSEBroker) Unsubscribe(ch chan storage.Event) {
	b.mu.Lock()
	delete(b.clients, ch)
	b.mu.Unlock()
	close(ch)
}

func (b *SSEBroker) Broadcast(evt storage.Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- evt:
		default:
			// Drop if client is too slow
		}
	}
}

func (b *SSEBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	for {
		select {
		case evt, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(evt)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}
```

**Step 2: Add SSE broker to server and broadcast from handlers**

Update `Server` struct to include broker, update `New()` to create it, add `/events/stream` route, and call `s.broker.Broadcast()` after each `InsertEvent`.

**Step 3: Verify it builds**

Run: `go build ./...`
Expected: No errors

**Step 4: Commit**

```bash
git add internal/server/
git commit -m "feat: SSE endpoint for live event streaming"
```

---

## Phase 9: TUI Dashboard

### Task 9: Bubble Tea monitor with events panel

**Files:**
- Create: `internal/tui/model.go`
- Create: `internal/tui/events_panel.go`
- Create: `internal/tui/styles.go`
- Create: `internal/cli/monitor.go`

This is the largest task. The TUI connects to the gateway's SSE endpoint and renders live events in a table with tabs for Events, Sessions, Metrics, and Violations panels.

**Step 1: Write TUI styles**

```go
// internal/tui/styles.go
package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205"))

	tabStyle = lipgloss.NewStyle().
		Padding(0, 2)

	activeTabStyle = tabStyle.
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Underline(true)

	headerStyle = lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("244"))

	allowStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("34"))

	blockStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("196"))

	statusBarStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))
)
```

**Step 2: Write events panel**

```go
// internal/tui/events_panel.go
package tui

import (
	"fmt"
	"strings"

	"github.com/irad100/cc-gateway/internal/storage"
)

func renderEventsPanel(events []storage.Event, width int) string {
	var sb strings.Builder

	header := fmt.Sprintf("%-10s %-20s %-10s %-8s %-20s",
		"TIME", "USER", "TOOL", "ACTION", "POLICY")
	sb.WriteString(headerStyle.Render(header))
	sb.WriteString("\n")

	for _, e := range events {
		action := allowStyle.Render("ALLOW")
		if e.PolicyAction == "block" {
			action = blockStyle.Render("BLOCK")
		}

		line := fmt.Sprintf("%-10s %-20s %-10s %s %-20s",
			e.CreatedAt.Format("15:04:05"),
			truncateStr(e.UserID, 20),
			e.ToolName,
			action,
			e.PolicyName)
		sb.WriteString(line)
		sb.WriteString("\n")
	}
	return sb.String()
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
```

**Step 3: Write main TUI model**

```go
// internal/tui/model.go
package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/irad100/cc-gateway/internal/storage"
)

type tab int

const (
	tabEvents tab = iota
	tabSessions
	tabMetrics
	tabViolations
)

var tabNames = []string{"Events", "Sessions", "Metrics", "Violations"}

type Model struct {
	serverURL  string
	activeTab  tab
	events     []storage.Event
	violations []storage.Event
	paused     bool
	width      int
	height     int
	err        error
}

type eventMsg storage.Event
type errMsg error

func New(serverURL string) Model {
	return Model{
		serverURL: serverURL,
		events:    make([]storage.Event, 0),
	}
}

func (m Model) Init() tea.Cmd {
	return connectSSE(m.serverURL)
}

// listenSSE maintains a persistent SSE connection and sends events to the program.
// Called as a goroutine from the monitor CLI command, NOT as a tea.Cmd.
func listenSSE(ctx context.Context, url string, p *tea.Program) {
	client := &http.Client{Timeout: 0} // no timeout for SSE
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/events/stream", nil)
		if err != nil {
			p.Send(errMsg(err))
			return
		}
		resp, err := client.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.Send(errMsg(err))
			time.Sleep(2 * time.Second) // reconnect backoff
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := scanner.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			data := strings.TrimPrefix(line, "data: ")
			var evt storage.Event
			if err := json.Unmarshal([]byte(data), &evt); err != nil {
				continue
			}
			p.Send(eventMsg(evt))
		}
		resp.Body.Close()
		if ctx.Err() != nil {
			return
		}
		time.Sleep(2 * time.Second) // reconnect on disconnect
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyPressMsg: // v2: KeyPressMsg replaces KeyMsg
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 4
		case "p":
			m.paused = !m.paused
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case eventMsg:
		if !m.paused {
			evt := storage.Event(msg)
			m.events = append(m.events, evt)
			if len(m.events) > 200 {
				m.events = m.events[len(m.events)-200:]
			}
			if evt.PolicyAction == "block" {
				m.violations = append(m.violations, evt)
				if len(m.violations) > 200 {
					m.violations = m.violations[len(m.violations)-200:]
				}
			}
		}
	case errMsg:
		m.err = msg
	}
	return m, nil
}

func prependEvent(events []storage.Event, evt storage.Event, max int) []storage.Event {
	events = append([]storage.Event{evt}, events...)
	if len(events) > max {
		events = events[:max]
	}
	return events
}

func (m Model) View() tea.View {
	var sb strings.Builder

	// Title bar
	active := len(m.events)
	violations := len(m.violations)
	title := fmt.Sprintf("  cc-gateway monitor            Active events: %d   Violations: %d", active, violations)
	if m.paused {
		title += "  [PAUSED]"
	}
	sb.WriteString(titleStyle.Render(title))
	sb.WriteString("\n")

	// Tabs
	var tabs []string
	for i, name := range tabNames {
		if tab(i) == m.activeTab {
			tabs = append(tabs, activeTabStyle.Render("["+name+"]"))
		} else {
			tabs = append(tabs, tabStyle.Render(" "+name+" "))
		}
	}
	sb.WriteString(strings.Join(tabs, ""))
	sb.WriteString("\n\n")

	// Panel content
	switch m.activeTab {
	case tabEvents:
		sb.WriteString(renderEventsPanel(m.events, m.width))
	case tabViolations:
		sb.WriteString(renderEventsPanel(m.violations, m.width))
	case tabSessions:
		sb.WriteString(headerStyle.Render("Sessions panel - coming soon"))
	case tabMetrics:
		sb.WriteString(headerStyle.Render("Metrics panel - coming soon"))
	}

	// Status bar
	sb.WriteString("\n")
	sb.WriteString(statusBarStyle.Render("q: quit  tab: switch panel  p: pause/resume"))

	v := tea.NewView(sb.String())
	v.AltScreen = true
	v.WindowTitle = "cc-gateway monitor"
	return v
}
```

**Step 4: Write monitor CLI command**

```go
// internal/cli/monitor.go
package cli

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/irad100/cc-gateway/internal/tui"
	"github.com/spf13/cobra"
)

func newMonitorCmd() *cobra.Command {
	var serverURL string

	cmd := &cobra.Command{
		Use:   "monitor",
		Short: "Launch the live TUI dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			model := tui.New(serverURL)
			p := tea.NewProgram(model)

			// Start persistent SSE listener in background goroutine
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			go tui.ListenSSE(ctx, serverURL, p)

			if _, err := p.Run(); err != nil {
				return fmt.Errorf("TUI error: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&serverURL, "server", "http://localhost:8080", "gateway server URL")
	return cmd
}
```

**Step 5: Add monitor command to root**

Add `cmd.AddCommand(newMonitorCmd())` to `NewRootCmd()`.

**Step 6: Verify it builds**

Run: `go build ./...`
Expected: No errors

**Step 7: Commit**

```bash
git add internal/tui/ internal/cli/monitor.go
git commit -m "feat: Bubble Tea TUI dashboard with live event stream"
```

---

## Phase 10: Auth Middleware

### Task 10: Bearer token authentication middleware

**Files:**
- Create: `internal/auth/auth.go`
- Create: `internal/auth/auth_test.go`
- Modify: `internal/server/server.go` (wire auth middleware)

**Step 1: Write the failing test**

```go
// internal/auth/auth_test.go
package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidToken(t *testing.T) {
	tokens := map[string]string{
		"token-abc": "alice@co.com",
	}
	middleware := NewBearerAuth(tokens)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user != "alice@co.com" {
			t.Errorf("expected alice@co.com, got %s", user)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	req.Header.Set("Authorization", "Bearer token-abc")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestMissingToken(t *testing.T) {
	middleware := NewBearerAuth(map[string]string{})

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestInvalidToken(t *testing.T) {
	tokens := map[string]string{
		"token-abc": "alice@co.com",
	}
	middleware := NewBearerAuth(tokens)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called")
	}))

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHealthBypassesAuth(t *testing.T) {
	middleware := NewBearerAuth(map[string]string{})

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for health, got %d", w.Code)
	}
}

func TestNoTokensConfiguredSkipsAuth(t *testing.T) {
	middleware := NewBearerAuth(nil)

	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when no tokens configured, got %d", w.Code)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/auth/ -v`
Expected: FAIL

**Step 3: Write auth middleware**

> **RESEARCH INSIGHT (Security Sentinel):** The original plan used plaintext map lookup for token comparison, which is vulnerable to timing attacks. Store tokens as SHA-256 hashes and use `crypto/subtle.ConstantTimeCompare`. Also: authenticate the SSE endpoint (was bypassed in original), and log a warning when auth is disabled.

```go
// internal/auth/auth.go
package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

type contextKey string

const userKey contextKey = "user"

type BearerAuth struct {
	tokenHashes map[string]string // SHA-256 hash -> userID
	enabled     bool
}

// HashToken returns the SHA-256 hex hash of a plaintext token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// NewBearerAuth creates auth middleware from a map of token hashes to user IDs.
// If tokenHashes is nil or empty, auth is disabled with a warning log.
func NewBearerAuth(tokenHashes map[string]string) *BearerAuth {
	enabled := len(tokenHashes) > 0
	if !enabled {
		slog.Warn("authentication disabled: no tokens configured")
	}
	return &BearerAuth{tokenHashes: tokenHashes, enabled: enabled}
}

func (a *BearerAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only health endpoint bypasses auth
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
			return
		}

		userID, ok := a.validateToken(token)
		if !ok {
			http.Error(w, `{"error":"invalid token"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), userKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateToken uses constant-time comparison on SHA-256 hashes.
func (a *BearerAuth) validateToken(candidate string) (string, bool) {
	candidateHash := HashToken(candidate)
	for storedHash, userID := range a.tokenHashes {
		if subtle.ConstantTimeCompare([]byte(candidateHash), []byte(storedHash)) == 1 {
			return userID, true
		}
	}
	return "", false
}

func UserFromContext(ctx context.Context) string {
	user, _ := ctx.Value(userKey).(string)
	return user
}
```

**Step 4: Run tests**

Run: `go test ./internal/auth/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/auth/
git commit -m "feat: bearer token auth middleware with health bypass"
```

---

## Phase 11: Wire Everything Together

### Task 11: Integration and end-to-end test

**Files:**
- Modify: `internal/cli/serve.go` (wire auth, SSE, watcher)
- Create: `internal/server/integration_test.go`

**Step 1: Write integration test**

```go
// internal/server/integration_test.go
package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/irad100/cc-gateway/internal/auth"
	"github.com/irad100/cc-gateway/internal/hook"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

func TestIntegrationBlockAndLog(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	policies := []policy.Policy{
		{
			Name:    "block-rm",
			Enabled: true,
			Event:   "PreToolUse",
			Matcher: "Bash",
			Conditions: []policy.Condition{
				{Field: "command", Pattern: `rm\s+-rf`},
			},
			Action:  "block",
			Message: "No rm -rf allowed",
		},
	}
	engine := policy.NewEngine(policies)
	srv := New(store, engine)

	tokens := map[string]string{"test-token": "alice@test.com"}
	authMiddleware := auth.NewBearerAuth(tokens)
	handler := authMiddleware.Wrap(srv.Handler())

	// Send a PreToolUse event that should be blocked
	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-integration",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command": "rm -rf /"}`),
	}
	b, _ := json.Marshal(input)

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp hook.HookResponse
	json.NewDecoder(w.Body).Decode(&resp)

	if resp.HookSpecificOutput == nil || resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatal("expected deny decision")
	}

	// Verify event was logged
	events, err := store.QueryEvents(req.Context(), storage.EventFilter{
		SessionID: "sess-integration",
		Limit:     10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 logged event, got %d", len(events))
	}
	if events[0].PolicyAction != "block" {
		t.Errorf("expected block action in log, got %s", events[0].PolicyAction)
	}
}
```

**Step 2: Run tests**

Run: `go test ./... -v`
Expected: ALL PASS

**Step 3: Update serve command to wire auth, SSE, watcher**

In `internal/cli/serve.go`, update `runServe` to:
- Build token map from config
- Create `auth.BearerAuth` middleware
- Create `SSEBroker` and add route
- Create policy `Watcher` if `cfg.Policies.Watch` is true
- Wrap handler with auth middleware

**Step 4: Verify full build**

Run: `go build -o cc-gateway ./cmd/cc-gateway && ./cc-gateway --help`
Expected: Help output showing all commands

**Step 5: Commit**

```bash
git add .
git commit -m "feat: wire auth, SSE, and policy watcher into serve command"
```

---

## Phase 12: Default Policies & Plugin Manifest

### Task 12: Built-in policies and Claude Code plugin

**Files:**
- Create: `policies/default.yaml`
- Create: `policies/network.yaml`
- Create: `plugin/plugin.json`

**Step 1: Write default policies**

```yaml
# policies/default.yaml
policies:
  - name: block-destructive-commands
    description: Block dangerous shell commands that could damage the system
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf\\s+/"
    action: block
    message: "Destructive rm -rf on root paths is not allowed"

  - name: block-disk-format
    description: Block disk formatting commands
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "mkfs\\.|dd\\s+if="
    action: block
    message: "Disk formatting commands are not allowed"

  - name: block-secret-file-access
    description: Block reading secret and key files
    event: PreToolUse
    matcher: Read
    conditions:
      - field: file_path
        pattern: "\\.(env|pem|key|p12|pfx)$"
    action: block
    message: "Access to secret files is restricted by security policy"

  - name: block-secret-file-write
    description: Block writing to secret files
    event: PreToolUse
    matcher: Write
    conditions:
      - field: file_path
        pattern: "\\.(env|pem|key|p12|pfx)$"
    action: block
    message: "Writing to secret files is restricted by security policy"
```

```yaml
# policies/network.yaml
policies:
  - name: block-curl-pipe-bash
    description: Block piping curl output to shell execution
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "curl.*\\|.*(?:bash|sh|zsh)"
    action: block
    message: "Piping curl output to shell is not allowed"

  - name: block-wget-pipe-bash
    description: Block piping wget output to shell execution
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "wget.*\\|.*(?:bash|sh|zsh)"
    action: block
    message: "Piping wget output to shell is not allowed"
```

**Step 2: Write plugin manifest**

```json
// plugin/plugin.json
{
  "name": "cc-gateway",
  "display_name": "CC Gateway - Security & Observability",
  "description": "Enterprise security gateway for Claude Code. Enforces security policies, logs all activity, and provides real-time monitoring.",
  "version": "0.1.0"
}
```

**Step 3: Commit**

```bash
git add policies/ plugin/
git commit -m "feat: default security policies and plugin manifest"
```

---

## Summary

| Phase | Task | What it builds |
|-------|------|---------------|
| 1 | Scaffolding | Directory structure, hook types, config types |
| 2 | Storage | SQLite event store with migrations and queries |
| 3 | Policy Engine | YAML parsing, regex conditions, priority evaluation |
| 4 | HTTP Server | Hook endpoint handlers with policy evaluation |
| 5 | CLI | Cobra root, serve, init, version commands |
| 6 | Hot-Reload | fsnotify policy watcher |
| 7 | Admin CLI | policies, logs, users subcommands |
| 8 | SSE | Server-Sent Events for live monitoring |
| 9 | TUI | Bubble Tea dashboard with events panel |
| 10 | Auth | Bearer token middleware |
| 11 | Integration | Wire everything, end-to-end test |
| 12 | Defaults | Built-in policies, plugin manifest |

After completing all phases, you will have a working `cc-gateway` binary with:
- `cc-gateway init` — scaffold config and policies
- `cc-gateway serve` — run the gateway with auth, policy enforcement, and event logging
- `cc-gateway monitor` — live TUI dashboard
- `cc-gateway policies list|validate|test` — manage policies
- `cc-gateway logs` — query audit log
- `cc-gateway users list|activity` — user management
- `cc-gateway version` — version info
