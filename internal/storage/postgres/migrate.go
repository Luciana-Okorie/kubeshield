package postgres

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"
)

// The .down.sql files are embedded too so tests can check every migration has one;
// Migrate itself only ever applies .up.sql files.
//
//go:embed migrations/*.sql
var migrationFS embed.FS

// migrateLockID is an arbitrary constant key for pg_advisory_lock, so two API
// instances starting at once cannot apply the same migration twice.
const migrateLockID int64 = 0x4b53_4d49_4752 // "KSMIGR"

type migration struct {
	version int64
	name    string
	sql     string
}

// loadMigrations returns the embedded up-migrations ordered by version.
func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}

	var out []migration
	seen := map[int64]string{}
	for _, e := range entries {
		file := e.Name()
		if !strings.HasSuffix(file, ".up.sql") {
			continue
		}
		prefix, name, ok := strings.Cut(strings.TrimSuffix(file, ".up.sql"), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q: want <version>_<name>.up.sql", file)
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q: version %q is not a positive number", file, prefix)
		}
		if prev, dup := seen[version]; dup {
			return nil, fmt.Errorf("migrations %q and %q share version %d", prev, file, version)
		}
		seen[version] = file

		body, err := migrationFS.ReadFile(path.Join("migrations", file))
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", file, err)
		}
		out = append(out, migration{version: version, name: name, sql: string(body)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

// Migrate applies any embedded migrations that have not run yet. Each one runs in
// its own transaction together with its schema_migrations row, so a failure leaves
// the database at the last good version.
func Migrate(ctx context.Context, db *sql.DB) error {
	migrations, err := loadMigrations()
	if err != nil {
		return err
	}

	// Advisory locks belong to a session, so hold one connection for the whole run.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, migrateLockID); err != nil {
		return fmt.Errorf("migrate: take advisory lock: %w", err)
	}
	defer func() {
		// Use a fresh context so the lock is released even if ctx was cancelled.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrateLockID)
	}()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    bigint      PRIMARY KEY,
		name       text        NOT NULL,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, conn)
	if err != nil {
		return err
	}

	for _, m := range migrations {
		if applied[m.version] {
			continue
		}
		if err := apply(ctx, conn, m); err != nil {
			return fmt.Errorf("migrate: apply %06d_%s: %w", m.version, m.name, err)
		}
	}
	return nil
}

func appliedVersions(ctx context.Context, conn *sql.Conn) (map[int64]bool, error) {
	rows, err := conn.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: read schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := map[int64]bool{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("migrate: read schema_migrations: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func apply(ctx context.Context, conn *sql.Conn, m migration) error {
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op after a successful Commit

	// No arguments, so the driver may send the whole file as one multi-statement query.
	if _, err := tx.ExecContext(ctx, m.sql); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`, m.version, m.name); err != nil {
		return err
	}
	return tx.Commit()
}
