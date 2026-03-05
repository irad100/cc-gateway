package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/irad100/cc-gateway/internal/auth"
	"github.com/irad100/cc-gateway/internal/config"
	"github.com/irad100/cc-gateway/internal/hook"
	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

const maxBodySize = 1 << 20 // 1 MiB

// Server is the HTTP server for cc-gateway hook endpoints.
type Server struct {
	http   *http.Server
	engine *policy.Engine
	store  *storage.Store
	auth   *auth.BearerAuth
	logger *slog.Logger
}

// New creates a Server with routes, auth middleware, and timeouts.
func New(
	cfg config.ServerConfig,
	store *storage.Store,
	engine *policy.Engine,
	ba *auth.BearerAuth,
	logger *slog.Logger,
) *Server {
	s := &Server{
		engine: engine,
		store:  store,
		auth:   ba,
		logger: logger,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /hooks/pre-tool-use", s.handlePreToolUse)
	mux.HandleFunc("POST /hooks/post-tool-use", s.handlePostToolUse)
	mux.HandleFunc("POST /hooks/notification", s.handleNotification)
	mux.HandleFunc("POST /hooks/stop", s.handleStop)
	mux.HandleFunc("GET /health", s.handleHealth)

	s.http = &http.Server{
		Addr:              cfg.Addr,
		Handler:           ba.Wrap(mux),
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return s
}

// Start begins listening. Returns nil on graceful shutdown.
func (s *Server) Start() error {
	s.logger.Info("server starting", "addr", s.http.Addr)
	err := s.http.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown gracefully drains connections.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func (s *Server) handlePreToolUse(w http.ResponseWriter, r *http.Request) {
	var input hook.PreToolUseInput
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	result := s.engine.Evaluate("PreToolUse", input.ToolName, input.ToolInput)

	s.logEvent(r.Context(), input.CommonInput, input.ToolName,
		string(input.ToolInput), result)

	resp := hook.HookResponse{}
	if result.Action == "block" {
		resp.HookSpecificOutput = &hook.HookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: result.Message,
		}
	}

	respondJSON(w, http.StatusOK, resp)
}

func (s *Server) handlePostToolUse(w http.ResponseWriter, r *http.Request) {
	var input hook.PostToolUseInput
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	s.logEvent(r.Context(), input.CommonInput, input.ToolName,
		string(input.ToolInput), policy.EvalResult{Action: "allow"})

	respondJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleNotification(w http.ResponseWriter, r *http.Request) {
	var input hook.NotificationInput
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	s.logEvent(r.Context(), input.CommonInput, "",
		"", policy.EvalResult{Action: "allow"})

	respondJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleStop(w http.ResponseWriter, r *http.Request) {
	var input hook.StopInput
	if err := decodeJSON(r, &input); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	s.logEvent(r.Context(), input.CommonInput, "",
		"", policy.EvalResult{Action: "allow"})

	respondJSON(w, http.StatusOK, struct{}{})
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) logEvent(
	ctx context.Context,
	common hook.CommonInput,
	toolName, toolParams string,
	result policy.EvalResult,
) {
	userID := auth.UserFromContext(ctx)

	event := &storage.Event{
		SessionID:     common.SessionID,
		UserID:        userID,
		EventType:     common.HookEventName,
		ToolName:      toolName,
		ToolParams:    toolParams,
		PolicyName:    result.PolicyName,
		PolicyAction:  result.Action,
		PolicyMessage: result.Message,
	}

	if err := s.store.InsertEvent(ctx, event); err != nil {
		s.logger.Error("failed to insert event",
			"error", err,
			"event_type", common.HookEventName,
		)
	}

	s.logger.Info("hook event",
		"event_type", common.HookEventName,
		"tool", toolName,
		"user", userID,
		"action", result.Action,
	)
}

func decodeJSON(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, maxBodySize)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("decode request body: %w", err)
	}
	return nil
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}
