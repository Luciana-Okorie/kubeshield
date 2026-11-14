package middleware

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
	"github.com/luciana-okorie/kubeshield/internal/auth"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// bearer returns the presented token if it is well formed and has the wanted prefix.
// Rejecting the wrong kind of token here avoids a database lookup for obvious junk.
func bearer(r *http.Request, prefix string) (string, bool) {
	tok, ok := auth.BearerToken(r)
	if !ok || !strings.HasPrefix(tok, prefix) {
		return "", false
	}
	return tok, true
}

// Authenticate requires a valid user session token. Every failure is the same 401,
// so a client cannot tell an unknown token from an expired or revoked one.
func Authenticate(store storage.Store, logger *slog.Logger, now func() time.Time) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := bearer(r, auth.UserTokenPrefix)
			if !ok {
				httpx.Unauthorized(w)
				return
			}
			user, err := store.UserBySession(r.Context(), auth.HashToken(tok), now())
			switch {
			case err == nil:
				next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), user)))
			case errors.Is(err, storage.ErrNotFound):
				httpx.Unauthorized(w)
			default:
				httpx.StoreError(w, r, logger, err)
			}
		})
	}
}

// AuthenticateAgent requires a valid agent token and records its use.
func AuthenticateAgent(store storage.Store, logger *slog.Logger, now func() time.Time) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok, ok := bearer(r, auth.AgentTokenPrefix)
			if !ok {
				httpx.Unauthorized(w)
				return
			}
			id, err := store.AuthenticateAgent(r.Context(), auth.HashToken(tok), now())
			switch {
			case err == nil:
				next.ServeHTTP(w, r.WithContext(auth.WithAgent(r.Context(), id)))
			case errors.Is(err, storage.ErrNotFound):
				httpx.Unauthorized(w)
			default:
				httpx.StoreError(w, r, logger, err)
			}
		})
	}
}
