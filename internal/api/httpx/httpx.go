// Package httpx holds the JSON request/response helpers shared by middleware and handlers,
// so every error leaves the API in the same shape: {"error":{"code","message","field"}}.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// MaxBodyBytes bounds request bodies so a client cannot make the server buffer unbounded input.
const MaxBodyBytes = 1 << 20 // 1 MiB

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

// JSON writes v with the given status.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes the standard error body.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// Unauthorized writes a 401 with the challenge header clients expect.
func Unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kubeshield"`)
	Error(w, http.StatusUnauthorized, "unauthorized", "authentication required")
}

// NotFound writes the 404 used for missing resources and for resources the caller may not know exist.
func NotFound(w http.ResponseWriter) {
	Error(w, http.StatusNotFound, "not_found", "resource not found")
}

// Forbidden writes a 403 for an authenticated caller whose role is too low.
func Forbidden(w http.ResponseWriter) {
	Error(w, http.StatusForbidden, "forbidden", "your role does not allow this action")
}

// DecodeJSON reads exactly one JSON object into dst. On failure it writes the
// error response itself and returns false.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			Error(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large")
			return false
		}
		Error(w, http.StatusBadRequest, "invalid_json", "request body must be a single valid JSON object with known fields")
		return false
	}
	// Reject trailing content such as a second JSON value.
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		Error(w, http.StatusBadRequest, "invalid_json", "request body must contain exactly one JSON object")
		return false
	}
	return true
}

// StoreError maps a storage error to an HTTP response. Anything unrecognised is
// logged in full but reported to the client as an opaque 500.
func StoreError(w http.ResponseWriter, r *http.Request, logger *slog.Logger, err error) {
	var ve *storage.ValidationError
	switch {
	case errors.As(err, &ve):
		JSON(w, http.StatusUnprocessableEntity, errorBody{Error: errorDetail{
			Code: "validation_failed", Message: ve.Message, Field: ve.Field,
		}})
	case errors.Is(err, storage.ErrNotFound):
		NotFound(w)
	case errors.Is(err, storage.ErrConflict):
		Error(w, http.StatusConflict, "conflict", "a resource with that name already exists")
	case errors.Is(err, storage.ErrLastOwner):
		Error(w, http.StatusConflict, "last_owner", "an organization must keep at least one owner")
	case errors.Is(err, storage.ErrSignupClosed):
		Error(w, http.StatusForbidden, "signup_disabled", "signup is closed on this server")
	default:
		logger.Error("store error", slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Any("error", err))
		Error(w, http.StatusInternalServerError, "internal", "internal server error")
	}
}

// List wraps list results so the response can grow (pagination) without breaking clients.
type List[T any] struct {
	Items []T `json:"items"`
}

// Items builds a List, encoding a nil slice as [] rather than null.
func Items[T any](items []T) List[T] {
	if items == nil {
		items = []T{}
	}
	return List[T]{Items: items}
}
