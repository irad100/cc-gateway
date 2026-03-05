package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestValidToken(t *testing.T) {
	hash := HashToken("token-abc")
	tokens := map[string]string{hash: "alice"}
	mw := NewBearerAuth(tokens)

	var gotUser string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser = UserFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	req.Header.Set("Authorization", "Bearer token-abc")
	rec := httptest.NewRecorder()

	mw.Wrap(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if gotUser != "alice" {
		t.Fatalf("expected user 'alice', got %q", gotUser)
	}
}

func TestMissingToken(t *testing.T) {
	hash := HashToken("token-abc")
	tokens := map[string]string{hash: "alice"}
	mw := NewBearerAuth(tokens)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	rec := httptest.NewRecorder()

	mw.Wrap(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func TestInvalidToken(t *testing.T) {
	hash := HashToken("token-abc")
	tokens := map[string]string{hash: "alice"}
	mw := NewBearerAuth(tokens)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()

	mw.Wrap(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestHealthBypassesAuth(t *testing.T) {
	hash := HashToken("token-abc")
	tokens := map[string]string{hash: "alice"}
	mw := NewBearerAuth(tokens)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	mw.Wrap(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestNoTokensConfiguredSkipsAuth(t *testing.T) {
	mw := NewBearerAuth(nil)

	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/hooks/pre-tool-use", nil)
	rec := httptest.NewRecorder()

	mw.Wrap(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
