package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/irad100/cc-gateway/internal/policy"
	"github.com/irad100/cc-gateway/internal/storage"
)

func queryInt(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return defaultVal
	}
	return v
}

func (s *Server) handleAPIEvents(
	w http.ResponseWriter, r *http.Request,
) {
	q := r.URL.Query()

	f := storage.EventFilter{
		UserID:       q.Get("user"),
		ToolName:     q.Get("tool"),
		PolicyAction: q.Get("action"),
		Limit:        queryInt(r, "limit", 100),
		Offset:       queryInt(r, "offset", 0),
	}

	if since := q.Get("since"); since != "" {
		d, err := time.ParseDuration(since)
		if err == nil {
			t := time.Now().Add(-d)
			f.Since = &t
		}
	}
	if until := q.Get("until"); until != "" {
		d, err := time.ParseDuration(until)
		if err == nil {
			t := time.Now().Add(-d)
			f.Until = &t
		}
	}

	events, err := s.store.QueryEvents(r.Context(), f)
	if err != nil {
		s.logger.Error("api: query events", "error", err)
		respondJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "failed to query events"})
		return
	}
	if events == nil {
		events = []storage.Event{}
	}
	respondJSON(w, http.StatusOK, events)
}

func (s *Server) handleAPISessions(
	w http.ResponseWriter, r *http.Request,
) {
	limit := queryInt(r, "limit", 50)
	offset := queryInt(r, "offset", 0)

	sessions, err := s.store.ListSessions(r.Context(), limit, offset)
	if err != nil {
		s.logger.Error("api: list sessions", "error", err)
		respondJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "failed to list sessions"})
		return
	}
	if sessions == nil {
		sessions = []storage.Session{}
	}
	respondJSON(w, http.StatusOK, sessions)
}

func (s *Server) handleAPIPolicies(
	w http.ResponseWriter, _ *http.Request,
) {
	policies := s.engine.Policies()
	respondJSON(w, http.StatusOK, policies)
}

func (s *Server) handleAPIPoliciesTest(
	w http.ResponseWriter, r *http.Request,
) {
	var req struct {
		Event     string          `json:"event"`
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		respondJSON(w, http.StatusBadRequest,
			map[string]string{"error": "invalid request body"})
		return
	}

	result := s.engine.Evaluate(
		req.Event, req.ToolName, req.ToolInput, policy.EvalMeta{},
	)
	respondJSON(w, http.StatusOK, result)
}

func (s *Server) handleAPIMetrics(
	w http.ResponseWriter, r *http.Request,
) {
	if s.metrics == nil {
		respondJSON(w, http.StatusNotImplemented,
			map[string]string{"error": "metrics not configured"})
		return
	}

	windowStr := r.URL.Query().Get("window")
	if windowStr == "" {
		windowStr = "24h"
	}
	window, err := time.ParseDuration(windowStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest,
			map[string]string{"error": "invalid window duration"})
		return
	}

	since := time.Now().Add(-window)
	summary, err := s.metrics.Summary(r.Context(), since)
	if err != nil {
		s.logger.Error("api: metrics summary", "error", err)
		respondJSON(w, http.StatusInternalServerError,
			map[string]string{"error": "failed to compute metrics"})
		return
	}
	respondJSON(w, http.StatusOK, summary)
}
