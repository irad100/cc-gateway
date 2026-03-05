package metrics

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

const createEventsTable = `
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
`

func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec(createEventsTable); err != nil {
		t.Fatalf("create table: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type testEvent struct {
	sessionID    string
	userID       string
	eventType    string
	toolName     string
	policyName   string
	policyAction string
	createdAt    time.Time
}

func insertEvents(t *testing.T, db *sql.DB, events []testEvent) {
	t.Helper()
	for _, e := range events {
		_, err := db.Exec(`
			INSERT INTO events (
				session_id, user_id, event_type, tool_name,
				policy_name, policy_action, created_at
			) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			e.sessionID, e.userID, e.eventType, e.toolName,
			e.policyName, e.policyAction, e.createdAt,
		)
		if err != nil {
			t.Fatalf("insert event: %v", err)
		}
	}
}

func TestToolUsage(t *testing.T) {
	db := setupTestDB(t)
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", toolName: "Bash", createdAt: now},
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", toolName: "Bash", createdAt: now},
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", toolName: "Read", createdAt: now},
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", toolName: "", createdAt: now},
		// Old event, should be excluded
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", toolName: "Write", createdAt: since.Add(-time.Hour)},
	})

	c := NewCollector(db)
	stats, err := c.ToolUsage(context.Background(), since)
	if err != nil {
		t.Fatalf("ToolUsage: %v", err)
	}

	if len(stats) != 2 {
		t.Fatalf("expected 2 tool stats, got %d", len(stats))
	}
	if stats[0].Name != "Bash" || stats[0].Count != 2 {
		t.Errorf("expected Bash:2, got %s:%d", stats[0].Name, stats[0].Count)
	}
	if stats[1].Name != "Read" || stats[1].Count != 1 {
		t.Errorf("expected Read:1, got %s:%d", stats[1].Name, stats[1].Count)
	}
}

func TestViolationsByPolicy(t *testing.T) {
	db := setupTestDB(t)
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", policyName: "no-rm", policyAction: "block", createdAt: now},
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", policyName: "no-rm", policyAction: "block", createdAt: now},
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", policyName: "no-curl", policyAction: "block", createdAt: now},
		// Allowed events should not appear
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", policyName: "audit", policyAction: "allow", createdAt: now},
		// Empty policy name excluded
		{sessionID: "s1", userID: "u1", eventType: "pre_tool_use", policyName: "", policyAction: "block", createdAt: now},
	})

	c := NewCollector(db)
	stats, err := c.ViolationsByPolicy(context.Background(), since)
	if err != nil {
		t.Fatalf("ViolationsByPolicy: %v", err)
	}

	if len(stats) != 2 {
		t.Fatalf("expected 2 policy stats, got %d", len(stats))
	}
	if stats[0].Name != "no-rm" || stats[0].Count != 2 {
		t.Errorf("expected no-rm:2, got %s:%d", stats[0].Name, stats[0].Count)
	}
	if stats[1].Name != "no-curl" || stats[1].Count != 1 {
		t.Errorf("expected no-curl:1, got %s:%d", stats[1].Name, stats[1].Count)
	}
}

func TestViolationsByUser(t *testing.T) {
	db := setupTestDB(t)
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", userID: "alice", eventType: "pre_tool_use", policyAction: "block", createdAt: now},
		{sessionID: "s1", userID: "alice", eventType: "pre_tool_use", policyAction: "block", createdAt: now},
		{sessionID: "s2", userID: "bob", eventType: "pre_tool_use", policyAction: "block", createdAt: now},
		// Allowed events excluded
		{sessionID: "s1", userID: "alice", eventType: "pre_tool_use", policyAction: "allow", createdAt: now},
		// Empty user excluded
		{sessionID: "s1", userID: "", eventType: "pre_tool_use", policyAction: "block", createdAt: now},
	})

	c := NewCollector(db)
	stats, err := c.ViolationsByUser(context.Background(), since)
	if err != nil {
		t.Fatalf("ViolationsByUser: %v", err)
	}

	if len(stats) != 2 {
		t.Fatalf("expected 2 user stats, got %d", len(stats))
	}
	if stats[0].UserID != "alice" || stats[0].Count != 2 {
		t.Errorf("expected alice:2, got %s:%d", stats[0].UserID, stats[0].Count)
	}
	if stats[1].UserID != "bob" || stats[1].Count != 1 {
		t.Errorf("expected bob:1, got %s:%d", stats[1].UserID, stats[1].Count)
	}
}

func TestSessionCount(t *testing.T) {
	db := setupTestDB(t)
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", eventType: "pre_tool_use", createdAt: now},
		{sessionID: "s1", eventType: "pre_tool_use", createdAt: now},
		{sessionID: "s2", eventType: "pre_tool_use", createdAt: now},
		{sessionID: "s3", eventType: "pre_tool_use", createdAt: now},
		// Old event excluded
		{sessionID: "s4", eventType: "pre_tool_use", createdAt: since.Add(-time.Hour)},
	})

	c := NewCollector(db)
	count, err := c.SessionCount(context.Background(), since)
	if err != nil {
		t.Fatalf("SessionCount: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 sessions, got %d", count)
	}
}

func TestBlockAllowRatio(t *testing.T) {
	db := setupTestDB(t)
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", eventType: "pre_tool_use", policyAction: "block", createdAt: now},
		{sessionID: "s1", eventType: "pre_tool_use", policyAction: "block", createdAt: now},
		{sessionID: "s1", eventType: "pre_tool_use", policyAction: "allow", createdAt: now},
		{sessionID: "s1", eventType: "pre_tool_use", policyAction: "", createdAt: now},
	})

	c := NewCollector(db)
	ratio, err := c.BlockAllowRatio(context.Background(), since)
	if err != nil {
		t.Fatalf("BlockAllowRatio: %v", err)
	}
	if ratio.Blocked != 2 {
		t.Errorf("expected 2 blocked, got %d", ratio.Blocked)
	}
	if ratio.Allowed != 2 {
		t.Errorf("expected 2 allowed, got %d", ratio.Allowed)
	}
	if ratio.Total != 4 {
		t.Errorf("expected 4 total, got %d", ratio.Total)
	}
}

func TestHourlyActivity(t *testing.T) {
	db := setupTestDB(t)
	since := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", eventType: "pre_tool_use", createdAt: time.Date(2026, 3, 5, 9, 0, 0, 0, time.UTC)},
		{sessionID: "s1", eventType: "pre_tool_use", createdAt: time.Date(2026, 3, 5, 9, 30, 0, 0, time.UTC)},
		{sessionID: "s1", eventType: "pre_tool_use", createdAt: time.Date(2026, 3, 5, 14, 0, 0, 0, time.UTC)},
	})

	c := NewCollector(db)
	stats, err := c.HourlyActivity(context.Background(), since)
	if err != nil {
		t.Fatalf("HourlyActivity: %v", err)
	}

	if len(stats) != 2 {
		t.Fatalf("expected 2 hour stats, got %d", len(stats))
	}
	if stats[0].Hour != 9 || stats[0].Count != 2 {
		t.Errorf("expected hour 9 count 2, got hour %d count %d", stats[0].Hour, stats[0].Count)
	}
	if stats[1].Hour != 14 || stats[1].Count != 1 {
		t.Errorf("expected hour 14 count 1, got hour %d count %d", stats[1].Hour, stats[1].Count)
	}
}

func TestSummary(t *testing.T) {
	db := setupTestDB(t)
	now := time.Date(2026, 3, 5, 10, 0, 0, 0, time.UTC)
	since := now.Add(-24 * time.Hour)

	insertEvents(t, db, []testEvent{
		{sessionID: "s1", userID: "alice", eventType: "pre_tool_use", toolName: "Bash", policyName: "no-rm", policyAction: "block", createdAt: now},
		{sessionID: "s2", userID: "bob", eventType: "pre_tool_use", toolName: "Read", policyAction: "allow", createdAt: now},
	})

	c := NewCollector(db)
	s, err := c.Summary(context.Background(), since)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}

	if len(s.ToolUsage) != 2 {
		t.Errorf("expected 2 tool stats, got %d", len(s.ToolUsage))
	}
	if len(s.ViolationsByPolicy) != 1 {
		t.Errorf("expected 1 policy violation, got %d", len(s.ViolationsByPolicy))
	}
	if len(s.ViolationsByUser) != 1 {
		t.Errorf("expected 1 user violation, got %d", len(s.ViolationsByUser))
	}
	if s.SessionCount != 2 {
		t.Errorf("expected 2 sessions, got %d", s.SessionCount)
	}
	if s.BlockAllowRatio.Blocked != 1 || s.BlockAllowRatio.Allowed != 1 {
		t.Errorf("expected 1:1 ratio, got %d:%d", s.BlockAllowRatio.Blocked, s.BlockAllowRatio.Allowed)
	}
	if len(s.HourlyActivity) != 1 {
		t.Errorf("expected 1 hour bucket, got %d", len(s.HourlyActivity))
	}
}

func TestEmptyDatabase(t *testing.T) {
	db := setupTestDB(t)
	since := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
	c := NewCollector(db)
	ctx := context.Background()

	tools, err := c.ToolUsage(ctx, since)
	if err != nil {
		t.Fatalf("ToolUsage on empty db: %v", err)
	}
	if len(tools) != 0 {
		t.Errorf("expected 0 tool stats, got %d", len(tools))
	}

	policies, err := c.ViolationsByPolicy(ctx, since)
	if err != nil {
		t.Fatalf("ViolationsByPolicy on empty db: %v", err)
	}
	if len(policies) != 0 {
		t.Errorf("expected 0 policy stats, got %d", len(policies))
	}

	users, err := c.ViolationsByUser(ctx, since)
	if err != nil {
		t.Fatalf("ViolationsByUser on empty db: %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected 0 user stats, got %d", len(users))
	}

	count, err := c.SessionCount(ctx, since)
	if err != nil {
		t.Fatalf("SessionCount on empty db: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sessions, got %d", count)
	}

	ratio, err := c.BlockAllowRatio(ctx, since)
	if err != nil {
		t.Fatalf("BlockAllowRatio on empty db: %v", err)
	}
	if ratio.Blocked != 0 || ratio.Allowed != 0 || ratio.Total != 0 {
		t.Errorf("expected all zeros, got %+v", ratio)
	}

	hourly, err := c.HourlyActivity(ctx, since)
	if err != nil {
		t.Fatalf("HourlyActivity on empty db: %v", err)
	}
	if len(hourly) != 0 {
		t.Errorf("expected 0 hour stats, got %d", len(hourly))
	}

	summary, err := c.Summary(ctx, since)
	if err != nil {
		t.Fatalf("Summary on empty db: %v", err)
	}
	if summary.SessionCount != 0 {
		t.Errorf("expected 0 sessions in summary, got %d", summary.SessionCount)
	}
}
