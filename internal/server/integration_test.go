package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/irad100/cc-gateway/internal/auth"
	"github.com/irad100/cc-gateway/internal/config"
	"github.com/irad100/cc-gateway/internal/hook"
	"github.com/irad100/cc-gateway/internal/metrics"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

const testToken = "test-token-123"
const testUser = "testuser"

func blockRmRfPolicy(t *testing.T) []policy.Policy {
	t.Helper()
	policies, err := policy.ParseYAML([]byte(`
policies:
  - name: block-rm-rf
    event: PreToolUse
    matcher: Bash
    conditions:
      - field: command
        pattern: "rm\\s+-rf"
    action: block
    message: "rm -rf is blocked by policy"
    priority: 100
`))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}
	return policies
}

func setupIntegrationServer(
	t *testing.T, policies []policy.Policy,
) (*Server, *storage.Store) {
	t.Helper()

	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	engine := policy.NewEngine(policies, "allow")
	mc := metrics.NewCollector(store.DB())

	tokenHash := auth.HashToken(testToken)
	ba := auth.NewBearerAuth(map[string]string{
		tokenHash: testUser,
	})

	logger := slog.Default()
	cfg := config.Default().Server

	s := New(cfg, store, engine, mc, ba, logger)
	return s, store
}

func doAuthRequest(
	t *testing.T,
	s *Server,
	method, path, token string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()

	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode request body: %v", err)
		}
	}

	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestIntegrationPreToolUseAllowWithAuth(t *testing.T) {
	s, store := setupIntegrationServer(t, blockRmRfPolicy(t))

	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-allow-1",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"ls -la /tmp"}`),
	}

	rec := doAuthRequest(
		t, s, http.MethodPost, "/hooks/pre-tool-use", testToken, input,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp hook.HookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.HookSpecificOutput != nil {
		t.Errorf(
			"expected nil hookSpecificOutput for safe command, got %+v",
			resp.HookSpecificOutput,
		)
	}

	events, err := store.QueryEvents(
		context.Background(),
		storage.EventFilter{SessionID: "sess-allow-1"},
	)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].UserID != testUser {
		t.Errorf("expected user_id %q, got %q", testUser, events[0].UserID)
	}
	if events[0].PolicyAction != "allow" {
		t.Errorf(
			"expected policy_action allow, got %q",
			events[0].PolicyAction,
		)
	}
}

func TestIntegrationPreToolUseBlockWithAuth(t *testing.T) {
	s, store := setupIntegrationServer(t, blockRmRfPolicy(t))

	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-block-1",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"rm -rf /"}`),
	}

	rec := doAuthRequest(
		t, s, http.MethodPost, "/hooks/pre-tool-use", testToken, input,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp hook.HookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput for blocked command, got nil")
	}
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf(
			"expected deny, got %q",
			resp.HookSpecificOutput.PermissionDecision,
		)
	}
	if resp.HookSpecificOutput.PermissionDecisionReason != "rm -rf is blocked by policy" {
		t.Errorf(
			"expected blocked message, got %q",
			resp.HookSpecificOutput.PermissionDecisionReason,
		)
	}

	events, err := store.QueryEvents(
		context.Background(),
		storage.EventFilter{SessionID: "sess-block-1"},
	)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].PolicyAction != "block" {
		t.Errorf(
			"expected policy_action block, got %q",
			events[0].PolicyAction,
		)
	}
	if events[0].PolicyName != "block-rm-rf" {
		t.Errorf(
			"expected policy_name block-rm-rf, got %q",
			events[0].PolicyName,
		)
	}
}

func TestIntegrationAuthRequired(t *testing.T) {
	s, _ := setupIntegrationServer(t, blockRmRfPolicy(t))

	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-noauth",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/x"}`),
	}

	// No token: expect 401
	rec := doAuthRequest(
		t, s, http.MethodPost, "/hooks/pre-tool-use", "", input,
	)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}

	// Invalid token: expect 403
	rec = doAuthRequest(
		t, s, http.MethodPost, "/hooks/pre-tool-use", "wrong-token", input,
	)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationPostToolUse(t *testing.T) {
	s, store := setupIntegrationServer(t, nil)

	input := hook.PostToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-post-1",
			HookEventName: "PostToolUse",
		},
		ToolName:     "Read",
		ToolInput:    json.RawMessage(`{"file_path":"/tmp/test.txt"}`),
		ToolResponse: json.RawMessage(`{"content":"hello world"}`),
	}

	rec := doAuthRequest(
		t, s, http.MethodPost, "/hooks/post-tool-use", testToken, input,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	events, err := store.QueryEvents(
		context.Background(),
		storage.EventFilter{SessionID: "sess-post-1"},
	)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != "PostToolUse" {
		t.Errorf(
			"expected event_type PostToolUse, got %q",
			events[0].EventType,
		)
	}
	if events[0].UserID != testUser {
		t.Errorf("expected user_id %q, got %q", testUser, events[0].UserID)
	}
}

func TestIntegrationNotification(t *testing.T) {
	s, store := setupIntegrationServer(t, nil)

	input := hook.NotificationInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-notify-1",
			HookEventName: "Notification",
		},
		Message:          "Task completed",
		NotificationType: "info",
	}

	rec := doAuthRequest(
		t, s, http.MethodPost, "/hooks/notification", testToken, input,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	events, err := store.QueryEvents(
		context.Background(),
		storage.EventFilter{SessionID: "sess-notify-1"},
	)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != "Notification" {
		t.Errorf(
			"expected event_type Notification, got %q",
			events[0].EventType,
		)
	}
}

func TestIntegrationStop(t *testing.T) {
	s, store := setupIntegrationServer(t, nil)

	input := hook.StopInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-stop-1",
			HookEventName: "Stop",
		},
		StopHookActive:       true,
		LastAssistantMessage: "Done with the task",
	}

	rec := doAuthRequest(
		t, s, http.MethodPost, "/hooks/stop", testToken, input,
	)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	events, err := store.QueryEvents(
		context.Background(),
		storage.EventFilter{SessionID: "sess-stop-1"},
	)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].EventType != "Stop" {
		t.Errorf(
			"expected event_type Stop, got %q", events[0].EventType,
		)
	}
}

func TestIntegrationSSEStream(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	policies := blockRmRfPolicy(t)
	engine := policy.NewEngine(policies, "allow")
	mc := metrics.NewCollector(store.DB())

	tokenHash := auth.HashToken(testToken)
	ba := auth.NewBearerAuth(map[string]string{
		tokenHash: testUser,
	})

	logger := slog.Default()
	cfg := config.Default().Server
	s := New(cfg, store, engine, mc, ba, logger)

	ts := httptest.NewServer(s.http.Handler)
	t.Cleanup(ts.Close)

	// Connect SSE client
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, ts.URL+"/events/stream", nil,
	)
	if err != nil {
		t.Fatalf("create SSE request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)

	sseResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	t.Cleanup(func() { sseResp.Body.Close() })

	if sseResp.StatusCode != http.StatusOK {
		t.Fatalf("SSE expected 200, got %d", sseResp.StatusCode)
	}

	// Read initial ": connected" comment
	scanner := bufio.NewScanner(sseResp.Body)
	if !scanner.Scan() {
		t.Fatal("expected initial connected line from SSE")
	}

	// Send a PreToolUse event to trigger SSE broadcast
	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-sse-1",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/test.txt"}`),
	}

	body, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("marshal input: %v", err)
	}

	hookReq, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		ts.URL+"/hooks/pre-tool-use",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("create hook request: %v", err)
	}
	hookReq.Header.Set("Content-Type", "application/json")
	hookReq.Header.Set("Authorization", "Bearer "+testToken)

	hookResp, err := http.DefaultClient.Do(hookReq)
	if err != nil {
		t.Fatalf("send hook request: %v", err)
	}
	hookResp.Body.Close()

	if hookResp.StatusCode != http.StatusOK {
		t.Fatalf("hook expected 200, got %d", hookResp.StatusCode)
	}

	// Read SSE event lines: "id: N", "data: {...}", ""
	var dataLine string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("SSE scanner error: %v", err)
	}
	if dataLine == "" {
		t.Fatal("did not receive SSE data line")
	}

	var sseEvent SSEEvent
	if err := json.Unmarshal([]byte(dataLine), &sseEvent); err != nil {
		t.Fatalf("unmarshal SSE event: %v", err)
	}
	if sseEvent.Type != "PreToolUse" {
		t.Errorf("expected SSE type PreToolUse, got %q", sseEvent.Type)
	}
}
