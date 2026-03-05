package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/irad100/cc-gateway/internal/auth"
	"github.com/irad100/cc-gateway/internal/config"
	"github.com/irad100/cc-gateway/internal/hook"
	"github.com/irad100/cc-gateway/internal/metrics"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

func setupTestServer(t *testing.T, policies []policy.Policy) *Server {
	t.Helper()

	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	engine := policy.NewEngine(policies, "allow")
	mc := metrics.NewCollector(store.DB())
	ba := auth.NewBearerAuth(map[string]string{})
	logger := slog.Default()
	cfg := config.Default().Server

	return New(cfg, store, engine, mc, ba, logger)
}

func doRequest(
	t *testing.T, s *Server, method, path string, body any,
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
	rec := httptest.NewRecorder()
	s.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestPreToolUseAllow(t *testing.T) {
	s := setupTestServer(t, nil)

	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-1",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Read",
		ToolInput: json.RawMessage(`{"file_path":"/tmp/test.txt"}`),
	}

	rec := doRequest(t, s, http.MethodPost, "/hooks/pre-tool-use", input)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp hook.HookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.HookSpecificOutput != nil {
		t.Errorf(
			"expected nil hookSpecificOutput, got %+v",
			resp.HookSpecificOutput,
		)
	}
}

func TestPreToolUseBlock(t *testing.T) {
	blockPolicy, err := policy.ParseYAML([]byte(`
policies:
  - name: block-bash
    event: PreToolUse
    matcher: Bash
    conditions: []
    action: block
    message: "Bash is not allowed"
    priority: 100
`))
	if err != nil {
		t.Fatalf("parse policy: %v", err)
	}

	s := setupTestServer(t, blockPolicy)

	input := hook.PreToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-2",
			HookEventName: "PreToolUse",
		},
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"rm -rf /"}`),
	}

	rec := doRequest(t, s, http.MethodPost, "/hooks/pre-tool-use", input)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp hook.HookResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.HookSpecificOutput == nil {
		t.Fatal("expected hookSpecificOutput, got nil")
	}
	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf(
			"expected deny, got %q",
			resp.HookSpecificOutput.PermissionDecision,
		)
	}
	if resp.HookSpecificOutput.PermissionDecisionReason != "Bash is not allowed" {
		t.Errorf(
			"expected reason %q, got %q",
			"Bash is not allowed",
			resp.HookSpecificOutput.PermissionDecisionReason,
		)
	}
}

func TestPostToolUse(t *testing.T) {
	s := setupTestServer(t, nil)

	input := hook.PostToolUseInput{
		CommonInput: hook.CommonInput{
			SessionID:     "sess-3",
			HookEventName: "PostToolUse",
		},
		ToolName:     "Read",
		ToolInput:    json.RawMessage(`{}`),
		ToolResponse: json.RawMessage(`{"content":"hello"}`),
	}

	rec := doRequest(t, s, http.MethodPost, "/hooks/post-tool-use", input)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHealth(t *testing.T) {
	s := setupTestServer(t, nil)

	rec := doRequest(t, s, http.MethodGet, "/health", nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %q", resp["status"])
	}
}
