package postgres

import (
	"fmt"
	"strings"
	"testing"
)

func TestLoadMigrations(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(ms) == 0 {
		t.Fatal("no migrations embedded")
	}
	for i, m := range ms {
		if want := int64(i + 1); m.version != want {
			t.Errorf("migration %d has version %d; versions must be contiguous from 1", i, m.version)
		}
		if m.name == "" || strings.TrimSpace(m.sql) == "" {
			t.Errorf("migration %d (%s) has an empty name or body", m.version, m.name)
		}
	}
}

func TestEveryMigrationHasADownMigration(t *testing.T) {
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		file := fmt.Sprintf("migrations/%06d_%s.down.sql", m.version, m.name)
		body, err := migrationFS.ReadFile(file)
		if err != nil {
			t.Errorf("missing %s: %v", file, err)
			continue
		}
		if strings.TrimSpace(string(body)) == "" {
			t.Errorf("%s is empty", file)
		}
	}
}

func TestMigrationsAreNotDestructiveOnUp(t *testing.T) {
	// Up-migrations must never drop data. A reviewer should have to add an
	// explicit exception here, which makes the change visible.
	ms, _ := loadMigrations()
	for _, m := range ms {
		upper := strings.ToUpper(m.sql)
		for _, bad := range []string{"DROP TABLE", "DROP COLUMN", "TRUNCATE TABLE", "DELETE FROM"} {
			if strings.Contains(upper, bad) {
				t.Errorf("migration %06d_%s contains %q", m.version, m.name, bad)
			}
		}
	}
}
