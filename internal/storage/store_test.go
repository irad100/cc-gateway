package storage

import (
	"context"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(":memory:")
	if err != nil {
		t.Fatalf("New(:memory:): %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestInsertAndQueryEvent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	ev := &Event{
		SessionID:     "sess-1",
		UserID:        "alice",
		EventType:     "PreToolUse",
		ToolName:      "Bash",
		ToolParams:    `{"command":"ls"}`,
		PolicyName:    "no-rm",
		PolicyAction:  "allow",
		PolicyMessage: "",
		CreatedAt:     now,
	}

	if err := store.InsertEvent(ctx, ev); err != nil {
		t.Fatalf("InsertEvent: %v", err)
	}
	if ev.ID == 0 {
		t.Fatal("expected non-zero ID after insert")
	}

	events, err := store.QueryEvents(ctx, EventFilter{UserID: "alice"})
	if err != nil {
		t.Fatalf("QueryEvents: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	got := events[0]
	if got.ID != ev.ID {
		t.Errorf("ID: got %d, want %d", got.ID, ev.ID)
	}
	if got.SessionID != "sess-1" {
		t.Errorf("SessionID: got %q, want %q", got.SessionID, "sess-1")
	}
	if got.UserID != "alice" {
		t.Errorf("UserID: got %q, want %q", got.UserID, "alice")
	}
	if got.EventType != "PreToolUse" {
		t.Errorf("EventType: got %q, want %q", got.EventType, "PreToolUse")
	}
	if got.ToolName != "Bash" {
		t.Errorf("ToolName: got %q, want %q", got.ToolName, "Bash")
	}
	if got.ToolParams != `{"command":"ls"}` {
		t.Errorf("ToolParams: got %q", got.ToolParams)
	}
	if got.PolicyName != "no-rm" {
		t.Errorf("PolicyName: got %q, want %q", got.PolicyName, "no-rm")
	}
	if got.PolicyAction != "allow" {
		t.Errorf("PolicyAction: got %q, want %q", got.PolicyAction, "allow")
	}
}

func TestQueryEventsFilters(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	events := []Event{
		{
			SessionID:    "s1",
			UserID:       "alice",
			EventType:    "PreToolUse",
			ToolName:     "Bash",
			PolicyAction: "allow",
			CreatedAt:    now,
		},
		{
			SessionID:    "s1",
			UserID:       "bob",
			EventType:    "PreToolUse",
			ToolName:     "Read",
			PolicyAction: "allow",
			CreatedAt:    now.Add(time.Second),
		},
		{
			SessionID:    "s2",
			UserID:       "alice",
			EventType:    "PreToolUse",
			ToolName:     "Bash",
			PolicyAction: "block",
			PolicyName:   "no-rm",
			CreatedAt:    now.Add(2 * time.Second),
		},
	}
	for i := range events {
		if err := store.InsertEvent(ctx, &events[i]); err != nil {
			t.Fatalf("InsertEvent[%d]: %v", i, err)
		}
	}

	t.Run("by_user", func(t *testing.T) {
		got, err := store.QueryEvents(ctx, EventFilter{UserID: "alice"})
		if err != nil {
			t.Fatalf("QueryEvents: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 events, got %d", len(got))
		}
	})

	t.Run("by_tool", func(t *testing.T) {
		got, err := store.QueryEvents(ctx, EventFilter{ToolName: "Read"})
		if err != nil {
			t.Fatalf("QueryEvents: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 event, got %d", len(got))
		}
		if got[0].UserID != "bob" {
			t.Errorf("expected bob, got %q", got[0].UserID)
		}
	})

	t.Run("by_status", func(t *testing.T) {
		got, err := store.QueryEvents(
			ctx, EventFilter{PolicyAction: "block"},
		)
		if err != nil {
			t.Fatalf("QueryEvents: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected 1 event, got %d", len(got))
		}
		if got[0].PolicyName != "no-rm" {
			t.Errorf("expected no-rm, got %q", got[0].PolicyName)
		}
	})

	t.Run("limit", func(t *testing.T) {
		got, err := store.QueryEvents(ctx, EventFilter{Limit: 2})
		if err != nil {
			t.Fatalf("QueryEvents: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("expected 2 events, got %d", len(got))
		}
	})
}
