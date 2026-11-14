package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// runScanRecovery returns abandoned jobs to the queue after the agent's bounded scan window.
func runScanRecovery(ctx context.Context, store storage.Store, logger *slog.Logger, interval, lease time.Duration, now func() time.Time) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			count, err := store.RequeueStaleScanJobs(ctx, now().Add(-lease))
			if err != nil {
				logger.Error("scan recovery failed", "error", err)
				continue
			}
			if count > 0 {
				logger.Warn("requeued stale scan jobs", "count", count)
			}
		}
	}
}
