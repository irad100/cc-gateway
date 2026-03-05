package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

func seedEvents(
	t *testing.T, store *storage.Store, count int,
	sessionID, userID, toolName, action string,
) {
	t.Helper()
	for range count {
		e := &storage.Event{
			SessionID:    sessionID,
			UserID:       userID,
			EventType:    "PreToolUse",
			ToolName:     toolName,
			PolicyAction: action,
		}
		if err := store.InsertEvent(context.Background(), e); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
}

func TestAPIEventsEmpty(t *testing.T) {
	s := setupTestServer(t, nil)

	rec := doRequest(t, s, http.MethodGet, "/api/v1/events", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var events []json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events, got %d", len(events))
	}
}

func TestAPIEventsFilterByUser(t *testing.T) {
	s := setupTestServer(t, nil)
	seedEvents(t, s.store, 3, "sess-a", "alice", "Read", "allow")
	seedEvents(t, s.store, 2, "sess-b", "bob", "Write", "allow")

	rec := doRequest(
		t, s, http.MethodGet, "/api/v1/events?user=alice", nil,
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var events []storage.Event
	if err := json.NewDecoder(rec.Body).Decode(&events); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(events) != 3 {
		t.Errorf("expected 3 events for alice, got %d", len(events))
	}
	for _, e := range events {
		if e.UserID != "alice" {
			t.Errorf("expected user alice, got %q", e.UserID)
		}
	}
}

func TestAPIEventsPagination(t *testing.T) {
	s := setupTestServer(t, nil)
	seedEvents(t, s.store, 10, "sess-p", "user1", "Read", "allow")

	rec := doRequest(
		t, s, http.MethodGet,
		"/api/v1/events?limit=5&offset=0", nil,
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var page1 []storage.Event
	if err := json.NewDecoder(rec.Body).Decode(&page1); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page1) != 5 {
		t.Errorf("expected 5 events, got %d", len(page1))
	}

	rec2 := doRequest(
		t, s, http.MethodGet,
		"/api/v1/events?limit=5&offset=5", nil,
	)
	var page2 []storage.Event
	if err := json.NewDecoder(rec2.Body).Decode(&page2); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(page2) != 5 {
		t.Errorf("expected 5 events on page 2, got %d", len(page2))
	}

	if len(page1) > 0 && len(page2) > 0 {
		if page1[0].ID == page2[0].ID {
			t.Error("page 1 and page 2 returned same first event")
		}
	}
}

func TestAPISessions(t *testing.T) {
	s := setupTestServer(t, nil)
	seedEvents(t, s.store, 3, "sess-x", "alice", "Read", "allow")
	seedEvents(t, s.store, 2, "sess-y", "bob", "Write", "block")

	rec := doRequest(
		t, s, http.MethodGet, "/api/v1/sessions", nil,
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var sessions []storage.Session
	if err := json.NewDecoder(rec.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}

	found := false
	for _, sess := range sessions {
		if sess.SessionID == "sess-y" {
			found = true
			if sess.ViolationCount != 2 {
				t.Errorf(
					"expected 2 violations for sess-y, got %d",
					sess.ViolationCount,
				)
			}
		}
	}
	if !found {
		t.Error("sess-y not found in sessions response")
	}
}

func TestAPIPolicies(t *testing.T) {
	policies, err := policy.ParseYAML([]byte(`
policies:
  - name: test-policy
    event: PreToolUse
    matcher: Bash
    conditions: []
    action: block
    message: "blocked"
    priority: 10
`))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	s := setupTestServer(t, policies)

	rec := doRequest(
		t, s, http.MethodGet, "/api/v1/policies", nil,
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(result))
	}
	if result[0]["name"] != "test-policy" {
		t.Errorf(
			"expected policy name test-policy, got %v",
			result[0]["name"],
		)
	}
}

func TestAPIPoliciesTest(t *testing.T) {
	policies, err := policy.ParseYAML([]byte(`
policies:
  - name: block-bash
    event: PreToolUse
    matcher: Bash
    conditions: []
    action: block
    message: "no bash"
    priority: 10
`))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	s := setupTestServer(t, policies)

	body := map[string]any{
		"event":      "PreToolUse",
		"tool_name":  "Bash",
		"tool_input": map[string]string{"command": "ls"},
	}
	rec := doRequest(
		t, s, http.MethodPost, "/api/v1/policies/test", body,
	)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if result["action"] != "block" {
		t.Errorf("expected action block, got %v", result["action"])
	}
	if result["message"] != "no bash" {
		t.Errorf("expected message 'no bash', got %v", result["message"])
	}
}

func TestAPIMetrics(t *testing.T) {
	s := setupTestServer(t, nil)

	rec := doRequest(
		t, s, http.MethodGet, "/api/v1/metrics?window=24h", nil,
	)
	if rec.Code != http.StatusOK {
		t.Fatalf(
			"expected 200, got %d: %s", rec.Code, rec.Body.String(),
		)
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if _, ok := result["session_count"]; !ok {
		t.Error("expected session_count in response")
	}
	if _, ok := result["block_allow_ratio"]; !ok {
		t.Error("expected block_allow_ratio in response")
	}
}
