// Package observability holds logging (and, later, metrics and tracing) setup.
package observability

import (
	"io"
	"log/slog"
)

// NewLogger returns a structured logger. Production emits JSON for log
// aggregators; every other environment emits human-readable key=value text.
func NewLogger(env string, level slog.Level, w io.Writer) *slog.Logger {
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	if env == "production" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	return slog.New(h).With("service", "kubeshield-api")
}
