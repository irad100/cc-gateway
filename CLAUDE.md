# cc-gateway

Security observability and enforcement gateway for Claude Code. Written in Go.

## Architecture

- **Gateway Server** (`internal/server/`) — HTTP endpoints for Claude Code hook events
- **Policy Engine** (`internal/policy/`) — YAML-based rule evaluation
- **Event Store** (`internal/storage/`) — SQLite audit log
- **Auth** (`internal/auth/`) — OAuth token management
- **TUI** (`internal/tui/`) — Bubble Tea real-time dashboard
- **Metrics** (`internal/metrics/`) — Usage aggregation and stats
- **CLI** (`cmd/cc-gateway/`) — Cobra-based CLI with subcommands

## Development

### Build and run

```bash
go build -o cc-gateway ./cmd/cc-gateway
go test ./...
```

### Key dependencies

- `github.com/spf13/cobra` — CLI framework
- `github.com/charmbracelet/bubbletea` — TUI framework
- `github.com/charmbracelet/lipgloss` — TUI styling
- `modernc.org/sqlite` — Pure Go SQLite driver (no CGO)
- `gopkg.in/yaml.v3` — YAML policy parsing
- `github.com/fsnotify/fsnotify` — Policy file hot-reload

### Conventions

- Standard Go project layout: `cmd/` for entrypoints, `internal/` for private packages
- Use `slog` (stdlib) for structured logging
- Errors wrap with `fmt.Errorf("context: %w", err)`
- HTTP handlers use stdlib `net/http`
- Tests colocated with source files (`*_test.go`)
- Table-driven tests preferred

### Hook endpoints

| Endpoint | Hook Type |
|----------|-----------|
| `POST /hooks/pre-tool-use` | PreToolUse |
| `POST /hooks/post-tool-use` | PostToolUse |
| `POST /hooks/notification` | Notification |
| `POST /hooks/stop` | Stop |

### Policy files

YAML files in `policies/` directory. Each policy has: name, event type, matcher (tool name), conditions (field + regex pattern), action (block/allow), and message.

### Database

SQLite at `cc-gateway.db`. Schema managed via embedded migrations in `internal/storage/migrations/`.
