package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// pgErr stands in for a driver error (pgx's *pgconn.PgError has the same SQLState method).
type pgErr struct{ code string }

func (e pgErr) Error() string    { return "pg error " + e.code }
func (e pgErr) SQLState() string { return e.code }

func TestMapError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error // nil means "wrapped original"
	}{
		{"no rows", sql.ErrNoRows, storage.ErrNotFound},
		{"unique violation", pgErr{"23505"}, storage.ErrConflict},
		{"foreign key violation", pgErr{"23503"}, storage.ErrNotFound},
		{"invalid uuid text", pgErr{"22P02"}, storage.ErrNotFound},
		{"wrapped unique violation", fmt.Errorf("driver: %w", pgErr{"23505"}), storage.ErrConflict},
		{"serialization failure is not remapped", pgErr{"40001"}, nil},
		{"plain error is not remapped", errors.New("boom"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mapError("op", tc.err)
			if tc.want != nil {
				if !errors.Is(got, tc.want) {
					t.Errorf("mapError = %v, want %v", got, tc.want)
				}
				return
			}
			if errors.Is(got, storage.ErrNotFound) || errors.Is(got, storage.ErrConflict) {
				t.Errorf("mapError = %v, want an unclassified error", got)
			}
			if !strings.HasPrefix(got.Error(), "op: ") || !errors.Is(got, tc.err) {
				t.Errorf("mapError = %v, want %q wrapped with op context", got, tc.err)
			}
		})
	}
}

// fakeRow feeds fixed values into Scan, handling only the destination types the store uses.
// A nil value leaves nullable destinations invalid (SQL NULL).
type fakeRow struct{ vals []any }

func (r fakeRow) Scan(dest ...any) error {
	if len(dest) != len(r.vals) {
		return fmt.Errorf("scan: %d destinations for %d values", len(dest), len(r.vals))
	}
	for i, d := range dest {
		switch p := d.(type) {
		case *string:
			*p = r.vals[i].(string)
		case *storage.Role:
			*p = storage.Role(r.vals[i].(string))
		case *int64:
			*p = r.vals[i].(int64)
		case *time.Time:
			*p = r.vals[i].(time.Time)
		case *[]byte:
			if v, ok := r.vals[i].(string); ok {
				*p = []byte(v)
			}
		case *sql.NullString:
			if v, ok := r.vals[i].(string); ok {
				*p = sql.NullString{String: v, Valid: true}
			}
		case *sql.NullTime:
			if v, ok := r.vals[i].(time.Time); ok {
				*p = sql.NullTime{Time: v, Valid: true}
			}
		default:
			return fmt.Errorf("scan: unsupported destination %T", d)
		}
	}
	return nil
}

var lagos = time.FixedZone("WAT", 3600)

func TestScanClusterHandlesNullsAndUTC(t *testing.T) {
	created := time.Date(2026, 11, 5, 22, 0, 0, 0, lagos)
	seen := time.Date(2026, 11, 5, 22, 30, 0, 0, lagos)

	t.Run("nullable columns present", func(t *testing.T) {
		c, err := scanCluster(fakeRow{[]any{"c1", "o1", "prod", "gke", "v1.35.9-gke.1505000", "connected", seen, created, created}})
		if err != nil {
			t.Fatal(err)
		}
		if c.KubernetesVersion == nil || *c.KubernetesVersion != "v1.35.9-gke.1505000" {
			t.Errorf("KubernetesVersion = %v", c.KubernetesVersion)
		}
		if c.LastSeenAt == nil || c.LastSeenAt.Location() != time.UTC || c.LastSeenAt.Hour() != 21 {
			t.Errorf("LastSeenAt = %v, want 21:30 UTC", c.LastSeenAt)
		}
		if c.CreatedAt.Location() != time.UTC {
			t.Errorf("CreatedAt location = %v, want UTC", c.CreatedAt.Location())
		}
	})

	t.Run("nullable columns absent", func(t *testing.T) {
		c, err := scanCluster(fakeRow{[]any{"c1", "o1", "prod", "gke", nil, "pending", nil, created, created}})
		if err != nil {
			t.Fatal(err)
		}
		if c.KubernetesVersion != nil || c.LastSeenAt != nil {
			t.Errorf("want nil pointers for NULL columns, got %v / %v", c.KubernetesVersion, c.LastSeenAt)
		}
	})
}

func TestScanScanJobHandlesNulls(t *testing.T) {
	created := time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC)

	queued, err := scanScanJob(fakeRow{[]any{"s1", "o1", "c1", "queued", "u1", nil, created, nil, nil}})
	if err != nil {
		t.Fatal(err)
	}
	if queued.RequestedBy == nil || *queued.RequestedBy != "u1" {
		t.Errorf("RequestedBy = %v, want u1", queued.RequestedBy)
	}
	if queued.Error != nil || queued.StartedAt != nil || queued.FinishedAt != nil {
		t.Errorf("queued scan = %+v, want nil error/started/finished", queued)
	}

	orphan, _ := scanScanJob(fakeRow{[]any{"s3", "o1", "c1", "queued", nil, nil, created, nil, nil}})
	if orphan.RequestedBy != nil {
		t.Errorf("RequestedBy = %v, want nil when the requesting user was deleted", orphan.RequestedBy)
	}

	failed, err := scanScanJob(fakeRow{[]any{"s2", "o1", "c1", "failed", nil, "agent unreachable", created, created, created}})
	if err != nil {
		t.Fatal(err)
	}
	if failed.Error == nil || *failed.Error != "agent unreachable" || failed.StartedAt == nil || failed.FinishedAt == nil {
		t.Errorf("failed scan = %+v", failed)
	}
}

func TestScanUser(t *testing.T) {
	created := time.Date(2026, 11, 5, 22, 0, 0, 0, lagos)

	u, err := scanUser(fakeRow{[]any{"u1", "a@b.com", "A", "pbkdf2-sha256$1$x$y", nil, created}})
	if err != nil {
		t.Fatal(err)
	}
	if u.PasswordHash != "pbkdf2-sha256$1$x$y" || u.DisabledAt != nil || u.CreatedAt.Location() != time.UTC {
		t.Errorf("user = %+v", u)
	}

	noPassword, _ := scanUser(fakeRow{[]any{"u2", "c@d.com", "C", nil, created, created}})
	if noPassword.PasswordHash != "" {
		t.Errorf("NULL password_hash = %q, want empty so no password can ever match", noPassword.PasswordHash)
	}
	if noPassword.DisabledAt == nil || noPassword.DisabledAt.Location() != time.UTC {
		t.Errorf("DisabledAt = %v, want a UTC time", noPassword.DisabledAt)
	}
}

func TestScanOrganizationAndMembership(t *testing.T) {
	now := time.Date(2026, 11, 5, 21, 0, 0, 0, time.UTC)

	o, err := scanOrganization(fakeRow{[]any{"o1", "Acme", "acme", now, now}})
	if err != nil || o.ID != "o1" || o.Slug != "acme" {
		t.Errorf("organization = %+v, %v", o, err)
	}

	m, err := scanMembership(fakeRow{[]any{"o1", "u1", "admin", now}})
	if err != nil || m.Role != storage.RoleAdmin || m.UserID != "u1" {
		t.Errorf("membership = %+v, %v", m, err)
	}

	om, err := scanOrgMembership(fakeRow{[]any{"o1", "Acme", "acme", now, now, "viewer"}})
	if err != nil || om.ID != "o1" || om.Role != storage.RoleViewer {
		t.Errorf("org membership = %+v, %v", om, err)
	}
}

func TestScanMember(t *testing.T) {
	created := time.Date(2026, 11, 5, 22, 0, 0, 0, lagos)
	m, err := scanMember(fakeRow{[]any{"u1", "a@b.com", "Ada", "member", created}})
	if err != nil {
		t.Fatal(err)
	}
	if m.UserID != "u1" || m.Email != "a@b.com" || m.DisplayName != "Ada" || m.Role != storage.RoleMember || m.CreatedAt.Location() != time.UTC {
		t.Errorf("member = %+v", m)
	}
}

func TestScanAgent(t *testing.T) {
	created := time.Date(2026, 11, 5, 22, 0, 0, 0, lagos)

	fresh, err := scanAgent(fakeRow{[]any{"a1", "c1", "ksa_Ab3dE9", created, nil, nil}})
	if err != nil || fresh.LastUsedAt != nil || fresh.RevokedAt != nil || fresh.TokenPrefix != "ksa_Ab3dE9" {
		t.Errorf("fresh = %+v, %v", fresh, err)
	}
	used, _ := scanAgent(fakeRow{[]any{"a2", "c1", "ksa_x", created, created, created}})
	if used.LastUsedAt == nil || used.RevokedAt == nil || used.RevokedAt.Location() != time.UTC {
		t.Errorf("used = %+v", used)
	}
}

func TestScanAudit(t *testing.T) {
	created := time.Date(2026, 11, 5, 22, 0, 0, 0, lagos)

	full, err := scanAudit(fakeRow{[]any{int64(7), "o1", "u1", "user", "cluster.created", "cluster", "c1", `{"name":"prod"}`, "203.0.113.9", created}})
	if err != nil {
		t.Fatal(err)
	}
	if full.ID != 7 || full.OrganizationID == nil || *full.OrganizationID != "o1" || full.ActorUserID == nil {
		t.Errorf("entry = %+v", full)
	}
	if full.Metadata["name"] != "prod" || full.IP != "203.0.113.9" || full.TargetType != "cluster" || full.CreatedAt.Location() != time.UTC {
		t.Errorf("entry = %+v", full)
	}

	sparse, err := scanAudit(fakeRow{[]any{int64(8), nil, nil, "system", "startup", nil, nil, nil, nil, created}})
	if err != nil {
		t.Fatal(err)
	}
	if sparse.OrganizationID != nil || sparse.ActorUserID != nil || sparse.TargetType != "" || sparse.IP != "" {
		t.Errorf("sparse entry = %+v, want NULLs as nil/empty", sparse)
	}
	if sparse.Metadata == nil {
		t.Error("Metadata must be an empty map, not nil, so it encodes as {}")
	}

	if _, err := scanAudit(fakeRow{[]any{int64(9), nil, nil, "system", "x", nil, nil, "{not json", nil, created}}); err == nil {
		t.Error("corrupt metadata JSON was accepted")
	}
}

func TestNullHelpers(t *testing.T) {
	if got := nullString(""); got.Valid {
		t.Errorf("nullString(\"\") = %+v, want NULL", got)
	}
	if got := nullString("x"); !got.Valid || got.String != "x" {
		t.Errorf("nullString(\"x\") = %+v", got)
	}
	if got := nullStringPtr(nil); got.Valid {
		t.Errorf("nullStringPtr(nil) = %+v, want NULL", got)
	}
	s := "v"
	if got := nullStringPtr(&s); !got.Valid || got.String != "v" {
		t.Errorf("nullStringPtr(&v) = %+v", got)
	}
}

func TestStoreValidatesBeforeTouchingTheDatabase(t *testing.T) {
	// A nil *sql.DB would panic on use, so reaching the validation error proves no query was attempted.
	s := New(nil)
	ctx := context.Background()

	var ve *storage.ValidationError
	check := func(name string, err error) {
		t.Helper()
		if !errors.As(err, &ve) {
			t.Errorf("%s error = %v, want *ValidationError", name, err)
		}
	}

	_, _, err := s.CreateAccount(ctx, storage.NewAccount{Email: "nope"})
	check("CreateAccount", err)

	_, err = s.CreateOrganizationFor(ctx, "u1", storage.NewOrganization{Name: "", Slug: "x"})
	check("CreateOrganizationFor", err)

	_, err = s.CreateCluster(ctx, "o1", storage.NewCluster{Name: "prod", Provider: "nope"})
	check("CreateCluster", err)

	_, err = s.AddMember(ctx, "o1", "u1", "boss")
	check("AddMember", err)
	check("SetMemberRole", s.SetMemberRole(ctx, "o1", "u1", "boss"))

	check("AppendAudit", s.AppendAudit(ctx, storage.AuditEntry{ActorType: "robot", Action: "x"}))
	check("AppendAudit bad ip", s.AppendAudit(ctx, storage.AuditEntry{ActorType: storage.ActorSystem, Action: "x", IP: "not-an-ip"}))
}
