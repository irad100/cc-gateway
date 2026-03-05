---
title: "feat: cc-gateway v2 — REST API, Metrics, Enhanced TUI, Richer Policies, Operational Features"
type: feat
status: active
date: 2026-03-05
origin: docs/brainstorms/2026-03-05-cc-gateway-v2-features-brainstorm.md
---

# feat: cc-gateway v2 — REST API, Metrics, Enhanced TUI, Richer Policies, Operational Features

## Overview

Extend cc-gateway with five parallel work streams: a REST API (`/api/v1/*`), a metrics aggregation package, an enhanced TUI with 4 panels and keyboard controls, richer policy engine capabilities (glob matchers, CommonInput conditions, PostToolUse evaluation), and operational features (retention pruning, init command, CSV export, configurable logging). All features build on existing infrastructure without architectural changes.

## Problem Statement

The v1 gateway has solid foundations but several spec'd features were deferred: the `internal/metrics/` package is empty, only 2 of 4 TUI panels exist, 5 config fields are unwired, tool matchers are exact-string only, PostToolUse events skip policy evaluation, and notification/stop content is discarded. There's no programmatic API for agents to query the gateway. (see brainstorm: docs/brainstorms/2026-03-05-cc-gateway-v2-features-brainstorm.md)

## Technical Approach

### Architecture

No new external dependencies. All features use existing packages (stdlib `net/http`, `modernc.org/sqlite`, `bubbletea`, `lipgloss`, `path`). The metrics package uses SQL aggregation against the existing `events` table. The REST API mounts on the existing mux with existing auth middleware. TUI panels use existing Bubble Tea v1 patterns.

### Implementation Phases

#### Phase 1: Metrics Package (`internal/metrics/`)
- [ ] Create `internal/metrics/metrics.go` with `Collector` struct taking `*sql.DB`
- [ ] `ToolUsage(ctx, window) -> []ToolStat{Name, Count}` — `SELECT tool_name, COUNT(*) FROM events WHERE created_at >= ? AND tool_name != '' GROUP BY tool_name ORDER BY COUNT(*) DESC`
- [ ] `ViolationsByPolicy(ctx, window) -> []PolicyStat{Name, Count}` — filter `policy_action = 'block'` GROUP BY policy_name
- [ ] `ViolationsByUser(ctx, window) -> []UserStat{UserID, Count}` — filter `policy_action = 'block'` GROUP BY user_id
- [ ] `SessionCount(ctx, window) -> int` — `COUNT(DISTINCT session_id)`
- [ ] `BlockedAllowedRatio(ctx, window) -> Ratio{Blocked, Allowed, Total}`
- [ ] `HourlyActivity(ctx, window) -> []HourStat{Hour, Count}` — `strftime('%H', created_at)` GROUP BY
- [ ] `Summary(ctx, window) -> MetricsSummary` — aggregates all above into one struct
- [ ] Time windows: `1h`, `24h`, `7d`, `30d` as `time.Duration` parameter
- [ ] Tests: `internal/metrics/metrics_test.go` with seeded events

#### Phase 2: REST API (`internal/server/api.go`)
- [ ] Create `internal/server/api.go` with handler methods on `*Server`
- [ ] `GET /api/v1/events` — wraps `store.QueryEvents` with query params: `user`, `tool`, `action`, `since`, `until`, `limit` (default 100), `offset` (default 0)
- [ ] `GET /api/v1/sessions` — `SELECT session_id, user_id, MIN(created_at), MAX(created_at), COUNT(*), SUM(CASE WHEN policy_action='block' THEN 1 ELSE 0 END) FROM events GROUP BY session_id ORDER BY MAX(created_at) DESC LIMIT ? OFFSET ?`
- [ ] `GET /api/v1/policies` — wraps `engine.Policies()`, returns JSON array
- [ ] `POST /api/v1/policies/test` — accepts `{"event","tool_name","tool_input"}`, calls `engine.Evaluate`, returns result
- [ ] `GET /api/v1/metrics` — accepts `?window=24h` (default), calls `metrics.Summary`
- [ ] Add `*metrics.Collector` field to `Server` struct
- [ ] Register routes in `New()`: `mux.HandleFunc("GET /api/v1/events", s.handleAPIEvents)` etc.
- [ ] Add pagination helpers: parse `limit`/`offset` from query params
- [ ] Add `Offset` field to `storage.EventFilter`
- [ ] Wire `Offset` into `QueryEvents` SQL: `LIMIT ? OFFSET ?`
- [ ] Tests: `internal/server/api_test.go` covering each endpoint
- [ ] Add sessions query method to store: `ListSessions(ctx, limit, offset) -> []Session`
- [ ] Add `Session` struct to storage: `SessionID, UserID, StartedAt, EndedAt, EventCount, ViolationCount`

#### Phase 3: Richer Policy Engine
- [ ] Change matcher from exact match to glob: replace `p.Matcher != toolName` with `!matchGlob(p.Matcher, toolName)` in `engine.go:67`
- [ ] Implement `matchGlob(pattern, name string) bool` using `path.Match` with fallback to exact match
- [ ] Extend `Evaluate` signature: `Evaluate(event, toolName string, toolInput json.RawMessage, meta EvalMeta) EvalResult`
- [ ] Add `EvalMeta` struct: `Cwd string`, `PermissionMode string`
- [ ] Support `cwd` and `permission_mode` as condition fields: check `meta.Cwd`/`meta.PermissionMode` when `c.Field` is `cwd` or `permission_mode` in `matchesAll`
- [ ] Wire `PoliciesConfig.DefaultAction` into `Engine`: add `defaultAction string` field, use in fallback
- [ ] Pass `defaultAction` from `NewEngine(policies, defaultAction)` in `serve.go`
- [ ] Update `handlePostToolUse` to call `engine.Evaluate` for logging (never returns block response)
- [ ] Store notification content: in `handleNotification`, marshal `{message, title, notification_type}` as `ToolParams`
- [ ] Store stop content: in `handleStop`, marshal `{reason, last_assistant_message}` as `ToolParams`
- [ ] Pass `EvalMeta{Cwd: input.Cwd, PermissionMode: input.PermissionMode}` from all handlers
- [ ] Update all existing tests, add glob matcher tests, condition field tests
- [ ] Update `policies test` CLI command to pass `EvalMeta`

#### Phase 4: Enhanced TUI
- [ ] Add Sessions panel (tab 3): query `/api/v1/sessions` on init, display `SESSION_ID USER STARTED DURATION EVENTS VIOLATIONS`
- [ ] Add Metrics panel (tab 4): query `/api/v1/metrics` on init, render summary stats and bar charts
- [ ] Change tab count from `% 2` to `% 4` in `Update`
- [ ] Add tabs `[3] Sessions` and `[4] Metrics` to header
- [ ] Add keyboard `3` and `4` for direct tab access
- [ ] Add `/` key: toggle filter text input at bottom, filter visible rows by substring match
- [ ] Add `p` key: toggle `paused bool` field, skip SSE events when paused, show "PAUSED" indicator
- [ ] Add `?` key: toggle help overlay with all keyboard shortcuts
- [ ] Add `Enter` key: show detail view for selected event (full JSON params)
- [ ] Add cursor/selection: `j`/`k` or `up`/`down` to move selection, highlight selected row
- [ ] Add `filterText string`, `filterActive bool`, `paused bool`, `showHelp bool`, `selectedIdx int` fields to Model
- [ ] Add `sessions []SessionRow` and `metricsSummary MetricsSummary` fields to Model
- [ ] Add `SessionRow` struct matching API response
- [ ] Render sessions table and metrics display functions
- [ ] Add periodic refresh for sessions/metrics panels (every 10s via `tea.Tick`)

#### Phase 5: Operational Features
- [ ] Event retention pruning: add `PruneOldEvents(ctx, before time.Time) (int64, error)` to store — `DELETE FROM events WHERE created_at < ?`
- [ ] Add `startRetentionPruner(ctx, store, retention, logger)` in `serve.go` — runs daily via `time.Ticker`, logs deleted count
- [ ] Wire retention config: only start pruner if `cfg.Storage.Retention > 0`
- [ ] `init` command: create default `cc-gateway.yaml`, `policies/` dir with default policies, log success
- [ ] Add `newInitCmd()` to `internal/cli/init.go`, register in `root.go`
- [ ] CSV export: add `format == "csv"` branch in `renderEvents` using `encoding/csv`
- [ ] Update logs command help text to list `table, json, csv` formats
- [ ] Configurable log format: support `LoggingConfig.Format` `"text"` → `slog.NewTextHandler` in `serve.go`
- [ ] Configurable log output: support `LoggingConfig.Output` `"stderr"` → `os.Stderr`, file path → `os.OpenFile`
- [ ] Remove dead `TokenEntry.UserName` field from config
- [ ] Tests for pruning, CSV output, init command

## System-Wide Impact

### Interaction Graph

- REST API handlers → `storage.QueryEvents` / `storage.ListSessions` / `metrics.Collector` / `policy.Engine`
- Policy engine `Evaluate` signature change → all 4 hook handlers must pass `EvalMeta`
- `handlePostToolUse` now calls `engine.Evaluate` → writes policy_name/policy_action to events table
- `handleNotification`/`handleStop` now marshal content into `tool_params` → richer SSE events → TUI shows more data
- Retention pruner → `storage.PruneOldEvents` → deletes rows from events table

### Error & Failure Propagation

- REST API errors return JSON `{"error": "message"}` with appropriate HTTP status codes
- Metrics queries that fail return 500 with error message
- Retention pruner logs errors but never crashes the server
- `init` command errors are returned to CLI

### State Lifecycle Risks

- Retention pruning deletes data permanently — logged with count for auditability
- No risk of orphaned state since sessions are derived queries, not separate tables

### API Surface Parity

- CLI `logs query` and `GET /api/v1/events` share the same `storage.QueryEvents`
- CLI `policies test` and `POST /api/v1/policies/test` share the same `engine.Evaluate`
- CLI `users list` and `GET /api/v1/sessions` provide different views but same underlying data

### Integration Test Scenarios

1. REST API with auth: `GET /api/v1/events` with valid token returns events, without token returns 401
2. Policy glob matcher: policy with `matcher: "Bash*"` matches tool `BashExec`
3. PostToolUse evaluation: PostToolUse event triggers policy logging but returns empty response
4. Notification content storage: notification event stores message in tool_params, queryable via API
5. Retention pruning: insert old events, run pruner, verify deleted

## Acceptance Criteria

### Functional Requirements

- [ ] `GET /api/v1/events` returns paginated events with filters
- [ ] `GET /api/v1/sessions` returns session summaries
- [ ] `GET /api/v1/policies` returns loaded policies
- [ ] `POST /api/v1/policies/test` evaluates sample events
- [ ] `GET /api/v1/metrics?window=24h` returns aggregated metrics
- [ ] Metrics package computes tool usage, violations, session count, hourly activity
- [ ] TUI has 4 panels: Events, Violations, Sessions, Metrics
- [ ] TUI supports `/` filter, `p` pause, `?` help, `Enter` detail, `j`/`k` navigation
- [ ] Policy matcher supports glob patterns (`*`, `?`)
- [ ] Policies can match on `cwd` and `permission_mode` fields
- [ ] PostToolUse events are evaluated by policy engine for logging
- [ ] Notification/stop events store content in tool_params
- [ ] `PoliciesConfig.DefaultAction` is wired to engine
- [ ] Event retention pruning runs daily when configured
- [ ] `cc-gateway init` creates config and policies
- [ ] `logs query --format csv` works
- [ ] `LoggingConfig.Format` and `LoggingConfig.Output` are respected
- [ ] Dead `TokenEntry.UserName` field removed

### Quality Gates

- [ ] All existing tests continue to pass
- [ ] New tests for metrics, API, policy glob, pruning, CSV, init
- [ ] `go vet ./...` clean
- [ ] `go build` succeeds

## Sources & References

### Origin

- **Brainstorm document:** [docs/brainstorms/2026-03-05-cc-gateway-v2-features-brainstorm.md](docs/brainstorms/2026-03-05-cc-gateway-v2-features-brainstorm.md) — Key decisions: SQL-based metrics (no separate storage), glob matchers via `path.Match`, sessions as derived queries not separate tables

### Internal References

- Existing server patterns: `internal/server/server.go:49-55` (route registration)
- Storage query patterns: `internal/storage/store.go:132-201` (QueryEvents with dynamic WHERE)
- Policy engine: `internal/policy/engine.go:53-80` (Evaluate method)
- TUI patterns: `internal/tui/tui.go:57-86` (Update method)
- Config defaults: `internal/config/config.go:47-70` (Default function)
- Hook types: `internal/hook/types.go` (CommonInput with Cwd/PermissionMode)
