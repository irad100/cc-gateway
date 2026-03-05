---
title: "cc-gateway v2: REST API, Metrics, Enhanced TUI, Richer Policies, and Operational Features"
date: 2026-03-05
status: complete
---

# cc-gateway v2 Features

## What We're Building

A comprehensive extension of cc-gateway across four areas:

1. **REST API + Metrics** — Agent-queryable HTTP API (`/api/v1/*`) and a metrics aggregation package for tool usage, violations, and session analytics
2. **Enhanced TUI** — Sessions and Metrics panels, keyboard filtering, drill-down, pause/resume, help overlay
3. **Richer Policies & Events** — Glob/regex tool matchers, conditions on `cwd`/`permission_mode`, PostToolUse evaluation, store notification/stop content, configurable default action
4. **Operational Features** — Event retention pruning, `init` command, CSV log export, configurable log format/output, wire up dead config fields

## Why This Approach

The v1 gateway has solid foundations (policy engine, SQLite store, SSE broker, TUI) but several spec'd features were deferred. The empty `internal/metrics/` package, 5 unwired config fields, and 2 missing TUI panels are clear gaps. Adding the REST API makes the gateway agent-native — other tools and agents can query it programmatically. These features build on existing infrastructure without architectural changes.

## Key Decisions

### REST API Design
- Mount under `/api/v1/` with JSON responses
- Endpoints: `GET /events`, `GET /sessions`, `GET /policies`, `POST /policies/test`, `GET /metrics`
- Reuse existing `storage.QueryEvents`, `storage.ListUsers` for data
- Auth middleware already wraps the mux, so API endpoints get auth for free
- Add pagination support (`?limit=N&offset=N`) for events endpoint

### Metrics Package
- SQL-based aggregation queries against the events table (no separate storage)
- Key metrics: tool usage frequency, violations by policy/user, session count, blocked/allowed ratio, hourly activity
- Expose via `/api/v1/metrics` endpoint and TUI Metrics panel
- Time-windowed queries (last 1h, 24h, 7d, 30d)

### Enhanced TUI
- Add Sessions panel (panel 3) and Metrics panel (panel 4)
- Sessions: group events by `session_id`, show duration/tool count/violation count
- Metrics: render bar charts and counters using lipgloss
- Keyboard: `/` toggle filter input, `Enter` drill into event/session detail, `p` pause SSE stream, `?` show help overlay
- Keep Bubble Tea v1 patterns (not v2)

### Richer Policy Engine
- Tool matcher supports glob patterns (`Bash*`, `*File*`) using `path.Match`
- New condition fields: `cwd`, `permission_mode` from `CommonInput`
- `handlePostToolUse` calls `engine.Evaluate` for logging (never blocks)
- Notification handler stores `Message`/`Title` in `ToolParams`
- Stop handler stores `Reason`/`LastAssistantMessage` in `ToolParams`
- Wire `PoliciesConfig.DefaultAction` into engine as fallback

### Operational Features
- Background goroutine in `serve.go` runs retention pruning daily using `StorageConfig.Retention`
- `init` command generates default `cc-gateway.yaml` and `policies/` directory
- `logs query --format csv` support
- `serve.go` respects `LoggingConfig.Format` (json/text) and `LoggingConfig.Output` (stdout/stderr/file)
- Remove dead `TokenEntry.UserName` field

### DB Schema
- Add `sessions` view or materialized query (not a new table) — derive from events grouped by `session_id`
- No schema migration needed for metrics (pure aggregation)
- Notification/stop content stored in existing `tool_params` TEXT column

## Open Questions

None — all decisions made based on SPEC.md patterns and existing code conventions.

## Scope

All features in a single plan, broken into parallelizable phases. Swarm agents handle independent work streams (REST API, metrics, TUI, policy engine, operational features can largely proceed in parallel).
