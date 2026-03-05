# cc-gateway Design Document

**Date:** 2026-03-05
**Status:** Approved

## Overview

cc-gateway is a security observability and enforcement gateway for companies whose employees use Claude Code. It intercepts Claude Code HTTP hook events to provide policy enforcement, audit logging, and real-time monitoring.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Deployment | Hybrid (self-hosted binary + optional cloud dashboard) | Keeps data on company network while enabling centralized management later |
| Enforcement | Block + Log | Clear security boundary — violations are blocked and logged with actionable messages |
| Auth | OAuth via Claude Plugin | Seamless developer experience — plugin installs hooks and handles authentication |
| Storage | SQLite | Zero-setup embedded database, single file, easy to back up and migrate |
| Hook events | All types (PreToolUse, PostToolUse, Notification, Stop) | Full visibility into Claude Code execution lifecycle |
| TUI | Admin CLI + live monitor | CLI for management, `cc-gateway monitor` for real-time dashboard |
| Policy format | YAML files | Human-readable, version-controllable, easy to review in PRs |

## Architecture

```
Developer's Claude Code
    |
    +-- PreToolUse ----> cc-gateway ----> Policy Engine ----> Allow / Block + Log
    +-- PostToolUse ---> cc-gateway ----> Log result + metrics
    +-- Notification --> cc-gateway ----> Log notification
    +-- Stop ----------> cc-gateway ----> Log session summary
                              |
                              v
                        SQLite (events, audit, metrics)
                              |
                              v
                        TUI Dashboard / CLI queries
```

## Components

### Gateway Server

HTTP server exposing endpoints for each hook type. Authenticates requests via OAuth bearer tokens. Returns hook responses (allow/block) per Claude Code HTTP hook protocol.

### Policy Engine

Evaluates YAML-based rules against incoming hook events. Each policy specifies an event type, tool matcher, conditions on fields, and an action (block/allow). Policies are loaded from disk and hot-reloaded on change.

### Event Store

SQLite database storing all hook events with full context: user identity, timestamp, tool name, arguments, policy decision, and session metadata. Supports querying by user, time range, tool, and policy outcome.

### OAuth Plugin

Claude Code plugin component that handles developer onboarding. Installs HTTP hooks pointing to the gateway server. Manages OAuth token lifecycle.

### Admin CLI

Subcommands: `serve`, `policies`, `logs`, `users`, `monitor`. Each provides management capabilities without requiring the TUI.

### Live TUI Monitor

Bubble Tea application launched via `cc-gateway monitor`. Displays real-time event stream, active sessions, violation counters, tool usage breakdown, and per-user activity.

## Policy Format

```yaml
policies:
  - name: block-destructive-commands
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf\\s+/"
    action: block
    message: "Destructive rm -rf on root paths is not allowed"

  - name: block-env-file-reads
    event: PreToolUse
    matcher: Read
    conditions:
      - field: file_path
        pattern: "\\.env$"
    action: block
    message: "Reading .env files is restricted by security policy"
```

## Key Features

1. Policy-based enforcement on tool calls
2. Full audit trail of all Claude Code activity
3. Real-time TUI monitoring dashboard
4. Per-user and per-project activity tracking
5. CLI administration and log querying
6. Hot-reloadable YAML policy configuration
7. OAuth-based developer onboarding via Claude plugin
8. Metrics: tool usage, violations, sessions, blocked/allowed ratios
