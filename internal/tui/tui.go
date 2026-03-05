package tui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	maxEvents = 200
	tabCount  = 4
)

// EventRow holds display data for a single event.
type EventRow struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	Tool   string `json:"tool"`
	Action string `json:"action"`
	Policy string `json:"policy"`
}

// SessionRow holds display data for a session.
type SessionRow struct {
	SessionID  string `json:"session_id"`
	User       string `json:"user_id"`
	StartedAt  string `json:"started_at"`
	Duration   string `json:"-"`
	Events     int    `json:"event_count"`
	Violations int    `json:"violation_count"`
}

// MetricsSummary holds aggregated metrics for display.
type MetricsSummary struct {
	ToolUsage          []stat `json:"tool_usage"`
	ViolationsByPolicy []stat `json:"violations_by_policy"`
	SessionCount       int    `json:"session_count"`
	BlockAllowRatio    ratio  `json:"block_allow_ratio"`
}

type stat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

type ratio struct {
	Blocked int `json:"blocked"`
	Allowed int `json:"allowed"`
	Total   int `json:"total"`
}

// Message types
type SSEMsg EventRow
type sessionsMsg []SessionRow
type metricsMsg MetricsSummary
type errMsg error

// Model is the Bubble Tea model for the TUI dashboard.
type Model struct {
	events     []EventRow
	sessions   []SessionRow
	metrics    MetricsSummary
	activeTab  int
	selectedIdx int
	width      int
	height     int
	serverURL  string
	err        error

	filterActive bool
	filterText   string
	paused       bool
	showHelp     bool
}

// New creates a Model targeting the given gateway server URL.
func New(serverURL string) Model {
	return Model{
		serverURL: serverURL,
		events:    make([]EventRow, 0, maxEvents),
	}
}

// Init returns nil — data fetching is driven by external goroutines.
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
		if m.filterActive {
			return m.updateFilter(msg)
		}
		if m.showHelp {
			m.showHelp = false
			return m, nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "tab":
			m.activeTab = (m.activeTab + 1) % tabCount
			m.selectedIdx = 0
		case "1":
			m.activeTab = 0
			m.selectedIdx = 0
		case "2":
			m.activeTab = 1
			m.selectedIdx = 0
		case "3":
			m.activeTab = 2
			m.selectedIdx = 0
		case "4":
			m.activeTab = 3
			m.selectedIdx = 0
		case "/":
			m.filterActive = true
		case "p":
			m.paused = !m.paused
		case "?":
			m.showHelp = true
		case "j", "down":
			m.selectedIdx++
		case "k", "up":
			if m.selectedIdx > 0 {
				m.selectedIdx--
			}
		}

	case SSEMsg:
		if !m.paused {
			m.events = append(m.events, EventRow(msg))
			if len(m.events) > maxEvents {
				m.events = m.events[len(m.events)-maxEvents:]
			}
		}

	case sessionsMsg:
		m.sessions = []SessionRow(msg)

	case metricsMsg:
		m.metrics = MetricsSummary(msg)

	case errMsg:
		m.err = msg
	}

	return m, nil
}

func (m Model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "enter", "esc":
		m.filterActive = false
	case "backspace":
		if len(m.filterText) > 0 {
			m.filterText = m.filterText[:len(m.filterText)-1]
		}
	case "ctrl+c":
		return m, tea.Quit
	default:
		if len(msg.String()) == 1 {
			m.filterText += msg.String()
		}
	}
	return m, nil
}

// Styles
var (
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

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("237"))

	blockedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	footerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196")).
			Bold(true)

	pausedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("214"))

	metricLabelStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("12"))

	metricValueStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("15"))

	barStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("62"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241")).
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2)
)

// View renders the TUI.
func (m Model) View() string {
	var b strings.Builder

	// Header
	title := activeTabStyle.Render(" cc-gateway ")
	tabs := []string{"[1] Events", "[2] Violations", "[3] Sessions", "[4] Metrics"}
	var renderedTabs []string
	for i, t := range tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, activeTabStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, inactiveTabStyle.Render(t))
		}
	}
	header := lipgloss.JoinHorizontal(lipgloss.Top,
		append([]string{title, "  "}, renderedTabs...)...,
	)
	if m.paused {
		header += "  " + pausedStyle.Render("PAUSED")
	}
	b.WriteString(header)
	b.WriteString("\n\n")

	// Error banner
	if m.err != nil {
		b.WriteString(errorStyle.Render(fmt.Sprintf("  SSE error: %v", m.err)))
		b.WriteString("\n\n")
	}

	// Help overlay
	if m.showHelp {
		b.WriteString(renderHelp())
		return b.String()
	}

	// Panel content
	contentHeight := m.height - 6
	switch m.activeTab {
	case 0:
		b.WriteString(m.renderEventsPanel(contentHeight, false))
	case 1:
		b.WriteString(m.renderEventsPanel(contentHeight, true))
	case 2:
		b.WriteString(m.renderSessionsPanel(contentHeight))
	case 3:
		b.WriteString(m.renderMetricsPanel(contentHeight))
	}

	// Footer
	b.WriteString("\n")
	footer := "  q quit | tab switch | / filter | p pause | ? help | j/k navigate"
	if m.filterActive {
		footer = fmt.Sprintf("  Filter: %s_  (Enter/Esc to close)", m.filterText)
	}
	b.WriteString(footerStyle.Render(footer))

	return b.String()
}

func (m Model) renderEventsPanel(maxRows int, violationsOnly bool) string {
	rows := m.filteredEvents(violationsOnly)
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

	for i, row := range rows[start:] {
		style := rowStyle
		if row.Action == "block" {
			style = blockedStyle
		}
		if i+start == m.selectedIdx {
			style = selectedStyle
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

func (m Model) filteredEvents(violationsOnly bool) []EventRow {
	var rows []EventRow
	for _, e := range m.events {
		if violationsOnly && e.Action != "block" {
			continue
		}
		if m.filterText != "" {
			combined := e.User + e.Tool + e.Action + e.Policy
			if !strings.Contains(
				strings.ToLower(combined),
				strings.ToLower(m.filterText),
			) {
				continue
			}
		}
		rows = append(rows, e)
	}
	return rows
}

func (m Model) renderSessionsPanel(maxRows int) string {
	var b strings.Builder

	hdr := headerStyle.Render(fmt.Sprintf(
		"  %-16s %-16s %-12s %-10s %-10s %s",
		"SESSION", "USER", "STARTED", "DURATION", "EVENTS", "VIOLATIONS",
	))
	b.WriteString(hdr)
	b.WriteString("\n")

	if len(m.sessions) == 0 {
		b.WriteString(footerStyle.Render("  (no sessions yet)"))
		b.WriteString("\n")
		return b.String()
	}

	start := 0
	if maxRows > 0 && len(m.sessions) > maxRows {
		start = len(m.sessions) - maxRows
	}

	for i, s := range m.sessions[start:] {
		style := rowStyle
		if s.Violations > 0 {
			style = blockedStyle
		}
		if i+start == m.selectedIdx {
			style = selectedStyle
		}
		line := style.Render(fmt.Sprintf(
			"  %-16s %-16s %-12s %-10s %-10d %d",
			truncate(s.SessionID, 16),
			truncate(s.User, 16),
			truncate(s.StartedAt, 12),
			truncate(s.Duration, 10),
			s.Events,
			s.Violations,
		))
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderMetricsPanel(_ int) string {
	var b strings.Builder
	ms := m.metrics

	// Summary stats
	b.WriteString(metricLabelStyle.Render("  Sessions: "))
	b.WriteString(metricValueStyle.Render(fmt.Sprintf("%d", ms.SessionCount)))
	b.WriteString("    ")
	b.WriteString(metricLabelStyle.Render("Blocked: "))
	b.WriteString(blockedStyle.Render(fmt.Sprintf("%d", ms.BlockAllowRatio.Blocked)))
	b.WriteString("    ")
	b.WriteString(metricLabelStyle.Render("Allowed: "))
	b.WriteString(metricValueStyle.Render(fmt.Sprintf("%d", ms.BlockAllowRatio.Allowed)))
	b.WriteString("    ")
	b.WriteString(metricLabelStyle.Render("Total: "))
	b.WriteString(metricValueStyle.Render(fmt.Sprintf("%d", ms.BlockAllowRatio.Total)))
	b.WriteString("\n\n")

	// Tool usage bar chart
	b.WriteString(metricLabelStyle.Render("  Tool Usage (24h)"))
	b.WriteString("\n")
	if len(ms.ToolUsage) == 0 {
		b.WriteString(footerStyle.Render("  (no data)"))
		b.WriteString("\n")
	} else {
		maxCount := 0
		for _, t := range ms.ToolUsage {
			if t.Count > maxCount {
				maxCount = t.Count
			}
		}
		for _, t := range ms.ToolUsage {
			barLen := 0
			if maxCount > 0 {
				barLen = (t.Count * 30) / maxCount
			}
			if barLen < 1 && t.Count > 0 {
				barLen = 1
			}
			bar := barStyle.Render(strings.Repeat("█", barLen))
			b.WriteString(fmt.Sprintf("  %-16s %s %d\n",
				truncate(t.Name, 16), bar, t.Count))
		}
	}
	b.WriteString("\n")

	// Violations by policy
	b.WriteString(metricLabelStyle.Render("  Violations by Policy"))
	b.WriteString("\n")
	if len(ms.ViolationsByPolicy) == 0 {
		b.WriteString(footerStyle.Render("  (none)"))
		b.WriteString("\n")
	} else {
		for _, v := range ms.ViolationsByPolicy {
			b.WriteString(blockedStyle.Render(fmt.Sprintf(
				"  %-32s %d\n", truncate(v.Name, 32), v.Count)))
		}
	}

	return b.String()
}

func renderHelp() string {
	help := `Keyboard Shortcuts

  tab        Switch between panels
  1-4        Jump to panel directly
  /          Toggle filter input
  p          Pause/resume live feed
  ?          Toggle this help
  j/k        Move selection up/down
  q/ctrl+c   Quit`
	return helpStyle.Render(help)
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
	token string,
	p *tea.Program,
) {
	url := strings.TrimRight(serverURL, "/") + "/events/stream"

	for {
		if err := streamSSE(ctx, url, token, p); err != nil {
			p.Send(errMsg(err))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
}

// FetchSessions queries the API for session data and sends it to the TUI.
func FetchSessions(
	ctx context.Context,
	serverURL string,
	token string,
	p *tea.Program,
) {
	url := strings.TrimRight(serverURL, "/") + "/api/v1/sessions?limit=50"
	fetchPeriodic(ctx, url, token, p, func(data []byte) tea.Msg {
		var sessions []SessionRow
		if err := json.Unmarshal(data, &sessions); err != nil {
			return errMsg(fmt.Errorf("parse sessions: %w", err))
		}
		return sessionsMsg(sessions)
	})
}

// FetchMetrics queries the API for metrics data and sends it to the TUI.
func FetchMetrics(
	ctx context.Context,
	serverURL string,
	token string,
	p *tea.Program,
) {
	url := strings.TrimRight(serverURL, "/") + "/api/v1/metrics?window=24h"
	fetchPeriodic(ctx, url, token, p, func(data []byte) tea.Msg {
		var ms MetricsSummary
		if err := json.Unmarshal(data, &ms); err != nil {
			return errMsg(fmt.Errorf("parse metrics: %w", err))
		}
		return metricsMsg(ms)
	})
}

func fetchPeriodic(
	ctx context.Context,
	url string,
	token string,
	p *tea.Program,
	parse func([]byte) tea.Msg,
) {
	for {
		data, err := httpGet(ctx, url, token)
		if err == nil {
			p.Send(parse(data))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Second):
		}
	}
}

func httpGet(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func streamSSE(
	ctx context.Context,
	url string,
	token string,
	p *tea.Program,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

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
