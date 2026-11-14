package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// runSessionJanitor deletes sessions that expired (or were revoked) more than grace ago,
// once at startup and then every interval, until ctx is cancelled. A failed pass is logged
// and retried next time; it never affects serving requests.
func runSessionJanitor(ctx context.Context, store storage.Store, logger *slog.Logger, interval, grace time.Duration, now func() time.Time) {
	purge := func() {
		n, err := store.DeleteExpiredSessions(ctx, now().Add(-grace))
		switch {
		case ctx.Err() != nil:
		case err != nil:
			logger.Error("session cleanup failed", "error", err)
		case n > 0:
			logger.Info("expired sessions removed", "count", n)
		}
	}
	purge()

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			purge()
		}
	}
}
