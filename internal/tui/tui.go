package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxEvents = 200

// EventRow holds display data for a single event.
type EventRow struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	Tool   string `json:"tool"`
	Action string `json:"action"`
	Policy string `json:"policy"`
}

// SSEMsg delivers a parsed event from the SSE goroutine.
type SSEMsg EventRow

type errMsg error

// Model is the Bubble Tea model for the TUI dashboard.
type Model struct {
	events    []EventRow
	activeTab int
	width     int
	height    int
	serverURL string
	err       error
}

// New creates a Model targeting the given gateway server URL.
func New(serverURL string) Model {
	return Model{
		serverURL: serverURL,
		events:    make([]EventRow, 0, maxEvents),
	}
}

// Init satisfies tea.Model. No initial command needed.
func (m Model) Init() tea.Cmd {
	return nil
}

// Update handles messages and returns the updated model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % 2
		case "1":
			m.activeTab = 0
		case "2":
			m.activeTab = 1
		}

	case SSEMsg:
		m.events = append(m.events, EventRow(msg))
		if len(m.events) > maxEvents {
			m.events = m.events[len(m.events)-maxEvents:]
		}

	case errMsg:
		m.err = msg
	}

	return m, nil
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("62")).
			Padding(0, 1)

	inactiveTabStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("250")).
				Padding(0, 1)

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("12"))

	rowStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("252"))

	blockedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)
)

// View renders the TUI.
func (m Model) View() string {
	var b strings.Builder

	// Header
	title := titleStyle.Render(" cc-gateway ")
	tab0 := inactiveTabStyle.Render("[1] Events")
	tab1 := inactiveTabStyle.Render("[2] Violations")
	if m.activeTab == 0 {
		tab0 = activeTabStyle.Render("[1] Events")
	} else {
		tab1 = activeTabStyle.Render("[2] Violations")
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top, title, "  ", tab0, " ", tab1)
	b.WriteString(header)
	b.WriteString("\n\n")

	// Error banner
	if m.err != nil {
		b.WriteString(errorStyle.Render(fmt.Sprintf("  SSE error: %v", m.err)))
		b.WriteString("\n\n")
	}

	// Table
	rows := m.visibleRows()
	b.WriteString(renderTable(rows, m.height-6))

	// Footer
	b.WriteString("\n")
	b.WriteString(footerStyle.Render(
		"  q/ctrl+c quit | tab/1/2 switch panel",
	))

	return b.String()
}

func (m Model) visibleRows() []EventRow {
	if m.activeTab == 0 {
		return m.events
	}
	var blocked []EventRow
	for _, e := range m.events {
		if e.Action == "block" {
			blocked = append(blocked, e)
		}
	}
	return blocked
}

func renderTable(rows []EventRow, maxRows int) string {
	var b strings.Builder

	hdr := headerStyle.Render(fmt.Sprintf(
		"  %-12s %-16s %-24s %-10s %s",
		"TIME", "USER", "TOOL", "ACTION", "POLICY",
	))
	b.WriteString(hdr)
	b.WriteString("\n")

	start := 0
	if maxRows > 0 && len(rows) > maxRows {
		start = len(rows) - maxRows
	}

	for _, row := range rows[start:] {
		style := rowStyle
		if row.Action == "block" {
			style = blockedStyle
		}
		line := style.Render(fmt.Sprintf(
			"  %-12s %-16s %-24s %-10s %s",
			truncate(row.Time, 12),
			truncate(row.User, 16),
			truncate(row.Tool, 24),
			truncate(row.Action, 10),
			row.Policy,
		))
		b.WriteString(line)
		b.WriteString("\n")
	}

	if len(rows) == 0 {
		b.WriteString(footerStyle.Render("  (no events yet)"))
		b.WriteString("\n")
	}

	return b.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 1 {
		return s[:max]
	}
	return s[:max-1] + "\u2026"
}

// sseEventJSON mirrors the SSE event JSON structure from the server.
type sseEventJSON struct {
	ID   int64           `json:"id"`
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// sseDataPayload is the expected shape of sseEventJSON.Data.
type sseDataPayload struct {
	UserID       string `json:"user_id"`
	ToolName     string `json:"tool_name"`
	PolicyAction string `json:"policy_action"`
	PolicyName   string `json:"policy_name"`
	CreatedAt    string `json:"created_at"`
}

// ListenSSE connects to the gateway SSE endpoint, parses events,
// and sends them to the Bubble Tea program. It reconnects on error.
func ListenSSE(
	ctx context.Context,
	serverURL string,
	p *tea.Program,
) {
	url := strings.TrimRight(serverURL, "/") + "/events/stream"

	for {
		if err := streamSSE(ctx, url, p); err != nil {
			p.Send(errMsg(err))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

func streamSSE(
	ctx context.Context,
	url string,
	p *tea.Program,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d from %s", resp.StatusCode, url)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		raw := strings.TrimPrefix(line, "data: ")

		var ev sseEventJSON
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			slog.Warn("parse SSE event", "error", err, "raw", raw)
			continue
		}

		var payload sseDataPayload
		if err := json.Unmarshal(ev.Data, &payload); err != nil {
			slog.Warn("parse SSE data payload", "error", err)
			continue
		}

		ts := payload.CreatedAt
		if t, parseErr := time.Parse(time.RFC3339, ts); parseErr == nil {
			ts = t.Format("15:04:05")
		}

		p.Send(SSEMsg(EventRow{
			Time:   ts,
			User:   payload.UserID,
			Tool:   payload.ToolName,
			Action: payload.PolicyAction,
			Policy: payload.PolicyName,
		}))
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read SSE stream: %w", err)
	}
	return nil
}
