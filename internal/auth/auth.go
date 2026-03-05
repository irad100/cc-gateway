package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
)

type contextKey string

const userKey contextKey = "user"

// BearerAuth validates Bearer tokens against stored SHA-256 hashes.
type BearerAuth struct {
	tokenHashes map[string]string // SHA-256 hash -> userID
	enabled     bool
}

// HashToken returns the SHA-256 hex hash of a plaintext token.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// NewBearerAuth creates auth middleware from token hashes to user IDs.
// Logs warning when no tokens configured (auth disabled).
func NewBearerAuth(tokenHashes map[string]string) *BearerAuth {
	enabled := len(tokenHashes) > 0
	if !enabled {
		slog.Warn("authentication disabled: no tokens configured")
	}
	return &BearerAuth{tokenHashes: tokenHashes, enabled: enabled}
}

// Wrap returns an HTTP handler that enforces bearer token auth.
// The /health endpoint always bypasses authentication.
func (a *BearerAuth) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(
				w,
				`{"error":"missing authorization header"}`,
				http.StatusUnauthorized,
			)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			http.Error(
				w,
				`{"error":"invalid authorization format"}`,
				http.StatusUnauthorized,
			)
			return
		}

		userID, ok := a.validateToken(token)
		if !ok {
			http.Error(
				w,
				`{"error":"invalid token"}`,
				http.StatusForbidden,
			)
			return
		}

		ctx := context.WithValue(r.Context(), userKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateToken uses constant-time comparison on SHA-256 hashes.
func (a *BearerAuth) validateToken(candidate string) (string, bool) {
	candidateHash := HashToken(candidate)
	for storedHash, userID := range a.tokenHashes {
		if subtle.ConstantTimeCompare(
			[]byte(candidateHash),
			[]byte(storedHash),
		) == 1 {
			return userID, true
		}
	}
	return "", false
}

// UserFromContext extracts the authenticated user ID from the request context.
func UserFromContext(ctx context.Context) string {
	user, _ := ctx.Value(userKey).(string)
	return user
}
