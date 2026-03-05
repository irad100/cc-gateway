# cc-gateway Specification

## 1. Purpose

cc-gateway is a security gateway that sits between Claude Code instances and the organization's security team. It intercepts all Claude Code hook events via HTTP hooks, enforces configurable security policies, maintains a complete audit trail, and provides real-time visibility through a TUI dashboard.

## 2. System Architecture

### 2.1 Components

```
+-------------------+     +-------------------+     +------------------+
|   Claude Code     |     |    cc-gateway     |     |     SQLite       |
|   (developer)     |---->|    HTTP Server    |---->|   Event Store    |
|                   |     |                   |     |                  |
|  Sends hook       |     | - Auth middleware |     | - Hook events    |
|  events via HTTP  |     | - Policy engine   |     | - Audit logs     |
|                   |     | - Event logging   |     | - User sessions  |
+-------------------+     | - Metrics agg     |     | - Metrics data   |
                          +-------------------+     +------------------+
                                   |
                          +--------+--------+
                          |                 |
                   +------+------+   +------+------+
                   |  Admin CLI  |   | TUI Monitor |
                   |             |   |             |
                   | - policies  |   | - Live feed |
                   | - logs      |   | - Sessions  |
                   | - users     |   | - Metrics   |
                   +-------------+   +-------------+
```

### 2.2 Deployment

Hybrid model:
- **Self-hosted gateway**: Single Go binary running on company infrastructure
- **Optional cloud dashboard**: Future component for multi-site management (out of scope for v1)

## 3. Hook Protocol

### 3.1 Supported Events

| Event | Endpoint | Purpose |
|-------|----------|---------|
| PreToolUse | `POST /hooks/pre-tool-use` | Evaluate policy before tool execution. Can block. |
| PostToolUse | `POST /hooks/post-tool-use` | Log tool execution result. Observability only. |
| Notification | `POST /hooks/notification` | Log Claude Code notifications. |
| Stop | `POST /hooks/stop` | Log session end. Finalize session metrics. |

### 3.2 Request Format

All hook requests are JSON POST bodies. Every event includes common fields plus event-specific fields.

**Common input fields (all events):**

| Field | Description |
|-------|-------------|
| `session_id` | Current session identifier |
| `transcript_path` | Path to conversation JSON |
| `cwd` | Current working directory |
| `permission_mode` | Permission mode: `default`, `plan`, `acceptEdits`, `dontAsk`, `bypassPermissions` |
| `hook_event_name` | Name of the event that fired |

**PreToolUse input:**
```json
{
  "session_id": "abc123",
  "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
  "cwd": "/home/user/my-project",
  "permission_mode": "default",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "npm test"
  },
  "tool_use_id": "toolu_01ABC123..."
}
```

**PostToolUse input:**
```json
{
  "session_id": "abc123",
  "hook_event_name": "PostToolUse",
  "tool_name": "Write",
  "tool_input": { "file_path": "/path/to/file.txt", "content": "..." },
  "tool_response": { "filePath": "/path/to/file.txt", "success": true },
  "tool_use_id": "toolu_01ABC123..."
}
```

**Notification input:**
```json
{
  "session_id": "abc123",
  "hook_event_name": "Notification",
  "message": "Claude needs your permission",
  "title": "Permission needed",
  "notification_type": "permission_prompt"
}
```

**Stop input:**
```json
{
  "session_id": "abc123",
  "hook_event_name": "Stop",
  "stop_hook_active": false,
  "last_assistant_message": "I've completed the task..."
}
```

### 3.3 Response Format

HTTP hooks return 2xx with a JSON body. Non-2xx responses and connection failures are non-blocking errors (execution continues).

**Allow (PreToolUse) — return empty JSON or omit hookSpecificOutput:**
```json
{}
```

**Block (PreToolUse) — use hookSpecificOutput with permissionDecision:**
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Policy 'block-destructive-commands': Destructive rm -rf on root paths is not allowed"
  }
}
```

**PostToolUse / Stop — use top-level decision to block:**
```json
{
  "decision": "block",
  "reason": "Explanation for blocking"
}
```

**Notification — no decision control, return empty:**
```json
{}
```

**Universal fields (all events):**

| Field | Default | Description |
|-------|---------|-------------|
| `continue` | `true` | If `false`, Claude stops processing entirely |
| `stopReason` | none | Message shown to user when `continue` is `false` |
| `suppressOutput` | `false` | If `true`, hides output from verbose mode |
| `systemMessage` | none | Warning message shown to the user |

### 3.4 Authentication

All requests must include a valid OAuth bearer token in the `Authorization` header. The gateway validates the token and maps it to a user identity.

Unauthenticated requests receive `401 Unauthorized`.
Requests with invalid/expired tokens receive `403 Forbidden`.

### 3.5 Timeout Handling

The gateway must respond within the timeout specified by the hook configuration (default 30s for tool use, 10s for notifications). If policy evaluation exceeds the timeout, the gateway defaults to **allow** to avoid blocking developer work, and logs a timeout warning.

## 4. Policy Engine

### 4.1 Policy Structure

```yaml
policies:
  - name: string            # Unique policy identifier
    description: string     # Human-readable description
    enabled: bool           # Toggle without removing (default: true)
    event: string           # Hook event type: PreToolUse | PostToolUse
    matcher: string         # Tool name to match (empty = all tools)
    conditions:             # All conditions must match (AND logic)
      - field: string       # Dot-path into tool params (e.g., "command", "file_path")
        pattern: string     # Regex pattern to match against field value
        negate: bool        # Invert match (default: false)
    action: string          # "block" or "allow"
    message: string         # Message shown to developer on block
    priority: int           # Higher priority policies evaluated first (default: 0)
```

### 4.2 Evaluation Rules

1. Policies are sorted by priority (descending), then by name (alphabetical)
2. For PreToolUse: first matching policy determines the outcome
3. If no policy matches, the default action is **allow**
4. All conditions within a policy use AND logic (all must match)
5. PostToolUse policies are evaluated for logging/metrics but cannot block

### 4.3 Hot Reload

The gateway watches the policies directory using filesystem notifications. When a policy file changes:

1. Parse and validate the new file
2. If valid, atomically swap the policy set
3. If invalid, log the error and keep the existing policies
4. Policy reload events are logged in the audit trail

### 4.4 Built-in Policies

cc-gateway ships with a default policy set that organizations can customize:

- `block-destructive-commands` — blocks `rm -rf /`, `mkfs`, `dd if=` on devices
- `block-secret-file-access` — blocks reading `.env`, `.pem`, `.key`, `.p12` files
- `block-network-exfiltration` — blocks `curl/wget` to non-allowlisted domains
- `block-package-install` — blocks `npm install`, `pip install` outside of project dirs
- `log-all-bash-commands` — allows but logs every Bash tool invocation

## 5. Event Store

### 5.1 Schema

**events table:**

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER PRIMARY KEY | Auto-increment ID |
| session_id | TEXT | Claude Code session ID |
| user_id | TEXT | Authenticated user identity |
| event_type | TEXT | PreToolUse, PostToolUse, Notification, Stop |
| tool_name | TEXT | Tool name (Bash, Read, Write, etc.) |
| tool_params | TEXT (JSON) | Tool parameters |
| policy_name | TEXT | Policy that matched (nullable) |
| policy_action | TEXT | allow, block (nullable) |
| policy_message | TEXT | Block message (nullable) |
| created_at | DATETIME | Event timestamp |

**sessions table:**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PRIMARY KEY | Claude Code session ID |
| user_id | TEXT | Authenticated user identity |
| started_at | DATETIME | First event timestamp |
| ended_at | DATETIME | Stop event timestamp (nullable) |
| event_count | INTEGER | Total events in session |
| violation_count | INTEGER | Total policy violations |

**users table:**

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT PRIMARY KEY | User identifier (email) |
| display_name | TEXT | Display name |
| oauth_token_hash | TEXT | Hashed OAuth token |
| created_at | DATETIME | First seen |
| last_active_at | DATETIME | Last event timestamp |

### 5.2 Retention

Events are retained indefinitely by default. Configurable retention period via `storage.retention` in config. A background goroutine prunes expired events daily.

### 5.3 Migrations

Schema migrations are embedded in the binary and run automatically on startup. Migration state tracked in a `schema_migrations` table.

## 6. TUI Dashboard

### 6.1 Monitor Mode (`cc-gateway monitor`)

Built with Bubble Tea and Lipgloss. Connects to the running gateway via a local Unix socket or HTTP SSE endpoint.

**Layout:**

```
+--------------------------------------------------------------+
|  cc-gateway monitor            Active: 12 users   3 violations|
+--------------------------------------------------------------+
| [Events]  [Sessions]  [Metrics]  [Violations]                |
+--------------------------------------------------------------+
|                                                               |
|  TIME       USER          TOOL     ACTION   POLICY            |
|  10:30:01   alice@co      Bash     ALLOW    -                 |
|  10:30:03   bob@co        Read     BLOCK    block-env-access  |
|  10:30:05   alice@co      Write    ALLOW    -                 |
|  10:30:07   charlie@co    Bash     ALLOW    -                 |
|  10:30:09   bob@co        Bash     BLOCK    block-destructive |
|  ...                                                          |
|                                                               |
+--------------------------------------------------------------+
| q: quit  tab: switch panel  /: filter  ?: help                |
+--------------------------------------------------------------+
```

**Panels:**

- **Events** — Real-time event stream with filtering by user, tool, action
- **Sessions** — Active sessions with user, duration, event count, violation count
- **Metrics** — Tool usage bar charts, violations over time, peak hours
- **Violations** — Violation-only feed with full context (command, file path, policy)

### 6.2 Keyboard Controls

| Key | Action |
|-----|--------|
| `Tab` | Switch between panels |
| `/` | Filter current panel |
| `Enter` | Drill into selected event/session |
| `q` | Quit |
| `?` | Help overlay |
| `p` | Pause/resume live feed |

## 7. Admin CLI

### 7.1 Commands

**`cc-gateway init`**
Initialize a new cc-gateway installation. Creates config file, policies directory with defaults, and empty database.

**`cc-gateway serve [flags]`**
Start the gateway HTTP server.

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | Listen address |
| `--config` | `cc-gateway.yaml` | Config file path |
| `--policies-dir` | `./policies` | Policies directory |
| `--db` | `cc-gateway.db` | SQLite database path |

**`cc-gateway policies list`**
List all loaded policies with name, event, matcher, action, and enabled status.

**`cc-gateway policies validate [file]`**
Validate policy YAML files. Reports errors without affecting the running server.

**`cc-gateway policies test --event <json> [--policy <name>]`**
Test a policy against a sample hook event. Shows which policy would match and what action would be taken.

**`cc-gateway logs [flags]`**
Query the audit log.

| Flag | Description |
|------|-------------|
| `--user` | Filter by user |
| `--tool` | Filter by tool name |
| `--status` | Filter by action (allow/block) |
| `--since` | Time range start (e.g., `1h`, `2024-01-01`) |
| `--until` | Time range end |
| `--format` | Output format: table, json, csv |
| `--limit` | Max results (default: 100) |

**`cc-gateway users list`**
List all registered users with last active time and event counts.

**`cc-gateway users activity --user <id>`**
Show detailed activity for a specific user: sessions, tool usage breakdown, violations.

**`cc-gateway monitor`**
Launch the live TUI dashboard (see section 6).

**`cc-gateway version`**
Print version, commit hash, and build date.

## 8. Configuration

### 8.1 Config File (`cc-gateway.yaml`)

```yaml
server:
  addr: ":8080"
  read_timeout: 30s
  write_timeout: 30s
  tls:
    cert: ""
    key: ""

auth:
  oauth:
    client_id: ""
    client_secret: ""
    issuer: ""
  token_ttl: 24h

storage:
  driver: sqlite
  dsn: "cc-gateway.db"
  retention: 90d

policies:
  dir: "./policies"
  watch: true
  default_action: allow

logging:
  level: info
  format: json
  output: stdout

monitor:
  transport: sse
  buffer_size: 1000
```

### 8.2 Environment Variables

All config values can be overridden via environment variables with the `CC_GATEWAY_` prefix:

- `CC_GATEWAY_SERVER_ADDR` — listen address
- `CC_GATEWAY_STORAGE_DSN` — database path
- `CC_GATEWAY_POLICIES_DIR` — policies directory
- `CC_GATEWAY_LOG_LEVEL` — log level

## 9. Claude Code Plugin

### 9.1 Plugin Manifest

The plugin is distributed as a Claude Code plugin that registers HTTP hooks pointing to the cc-gateway server.

```json
{
  "name": "cc-gateway",
  "display_name": "CC Gateway - Security & Observability",
  "description": "Enterprise security gateway for Claude Code",
  "oauth": {
    "authorization_url": "https://gateway.example.com/oauth/authorize",
    "token_url": "https://gateway.example.com/oauth/token",
    "scopes": ["hooks:write"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "http",
            "url": "{{gateway_url}}/hooks/pre-tool-use",
            "timeout": 30,
            "headers": {
              "Authorization": "Bearer {{oauth_token}}"
            }
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "http",
            "url": "{{gateway_url}}/hooks/post-tool-use",
            "timeout": 30,
            "headers": {
              "Authorization": "Bearer {{oauth_token}}"
            }
          }
        ]
      }
    ],
    "Notification": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "http",
            "url": "{{gateway_url}}/hooks/notification",
            "timeout": 10,
            "headers": {
              "Authorization": "Bearer {{oauth_token}}"
            }
          }
        ]
      }
    ],
    "Stop": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "http",
            "url": "{{gateway_url}}/hooks/stop",
            "timeout": 10,
            "headers": {
              "Authorization": "Bearer {{oauth_token}}"
            }
          }
        ]
      }
    ]
  }
}
```

### 9.2 Onboarding Flow

1. Admin configures cc-gateway with OAuth provider settings
2. Developer installs plugin: `claude plugin install cc-gateway`
3. Plugin triggers OAuth flow — developer authenticates with company credentials
4. Plugin writes hook configuration to developer's Claude Code settings
5. All subsequent Claude Code sessions send events to cc-gateway

## 10. Security Considerations

- All tokens stored as hashes, never plaintext
- TLS recommended for production deployments
- SQLite database should be on encrypted filesystem
- Policy files should be owned by root/admin with restricted permissions
- The gateway itself should run as a dedicated service user with minimal privileges
- Timeout-default-allow prevents the gateway from becoming a single point of failure

## 11. Implementation Phases

### Phase 1: Core Gateway
- HTTP server with all four hook endpoints
- Policy engine with YAML parsing and regex matching
- SQLite event store with schema migrations
- Bearer token authentication (static tokens)
- `cc-gateway serve` and `cc-gateway init` commands

### Phase 2: CLI and Policies
- Full CLI with `policies`, `logs`, `users` subcommands
- Built-in default policies
- Policy hot-reload via filesystem watcher
- Policy validation and testing commands

### Phase 3: TUI Dashboard
- Bubble Tea monitor with Events panel
- Sessions, Metrics, and Violations panels
- SSE endpoint for live event streaming
- Keyboard controls and filtering

### Phase 4: OAuth and Plugin
- OAuth provider integration
- Claude Code plugin manifest
- Token lifecycle management
- Developer onboarding flow

### Phase 5: Cloud Dashboard (Future)
- Web-based dashboard for multi-site management
- Centralized policy distribution
- Cross-gateway analytics
