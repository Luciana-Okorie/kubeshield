package handlers

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/luciana-okorie/kubeshield/internal/api/clientip"
	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// pathID returns the named path value if it is a well-formed ID. Otherwise it
// writes a 404 (an ID that cannot exist is simply not found) and returns false.
func pathID(w http.ResponseWriter, r *http.Request, name string) (string, bool) {
	id := r.PathValue(name)
	if !storage.IsValidID(id) {
		httpx.NotFound(w)
		return "", false
	}
	return id, true
}

// noStore keeps responses that carry a secret out of browser and proxy caches.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}

// audit records a sensitive action. It is best effort: the action has already happened,
// so a failed audit write is logged loudly rather than turned into an error for the caller.
// Metadata must never contain secrets.
func audit(ctx context.Context, store storage.Store, logger *slog.Logger, r *http.Request, e storage.AuditEntry) {
	if e.Metadata == nil {
		e.Metadata = map[string]any{}
	}
	e.IP = clientip.FromRequest(r)
	if err := store.AppendAudit(ctx, e); err != nil {
		logger.Error("audit write failed", slog.String("action", e.Action), slog.Any("error", err))
	}
}
