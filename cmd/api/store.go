package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/config"
	"github.com/luciana-okorie/kubeshield/internal/storage"
	"github.com/luciana-okorie/kubeshield/internal/storage/memory"
	"github.com/luciana-okorie/kubeshield/internal/storage/postgres"
)

// pgxDriverName is the database/sql driver name registered by pgx's stdlib package.
// The registration lives in driver_pgx.go behind the "pgx" build tag so the project
// still builds before the driver has been downloaded (go get github.com/jackc/pgx/v5).
const pgxDriverName = "pgx"

// openStore returns the configured storage backend and a function that releases it.
// With no database URL it falls back to the in-memory store.
func openStore(ctx context.Context, cfg config.Config, logger *slog.Logger) (storage.Store, func(), error) {
	if cfg.DatabaseURL == "" {
		logger.Warn("no DATABASE_URL set: using the in-memory store, data is lost on restart")
		return memory.New(), func() {}, nil
	}

	db, err := sql.Open(pgxDriverName, cfg.DatabaseURL)
	if err != nil {
		// Deliberately not including the URL: it contains the password.
		return nil, nil, fmt.Errorf("open database (is the binary built with -tags pgx after `go get github.com/jackc/pgx/v5`?): %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("connect to database: %w", err)
	}

	if cfg.AutoMigrate {
		logger.Info("applying database migrations")
		if err := postgres.Migrate(ctx, db); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
	}

	logger.Info("using PostgreSQL store")
	return postgres.New(db), func() { _ = db.Close() }, nil
}
