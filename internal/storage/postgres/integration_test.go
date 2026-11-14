//go:build integration

// Integration tests against a real PostgreSQL. They need the pgx driver, so they are
// excluded from the normal build. To run them:
//
//	go get github.com/jackc/pgx/v5 && go mod tidy
//	docker compose up -d postgres
//	KUBESHIELD_TEST_DATABASE_URL="postgres://kubeshield:kubeshield_dev_only@127.0.0.1:5460/kubeshield?sslmode=disable" \
//	    go test -tags "integration" ./internal/storage/postgres/
//
// The tests create and drop their own schema, so point them at a throwaway database.
package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	url := os.Getenv("KUBESHIELD_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("KUBESHIELD_TEST_DATABASE_URL not set")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Start from an empty public schema so Migrate is exercised from scratch.
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	return db
}

func TestMigrateIsIdempotent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("first Migrate: %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("second Migrate: %v", err)
	}

	ms, _ := loadMigrations()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(ms) {
		t.Errorf("schema_migrations has %d rows, want %d", n, len(ms))
	}
}

func hash32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestStoreAgainstRealPostgres(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := New(db)
	now := time.Now().UTC()
	const missing = "00000000-0000-4000-8000-000000000000"

	account := func(email, slug string) (storage.User, storage.Organization) {
		t.Helper()
		u, o, err := s.CreateAccount(ctx, storage.NewAccount{
			Email: email, DisplayName: "Test", PasswordHash: "pbkdf2-sha256$1$AAAAAAAAAAA$AAAA",
			OrgName: "Org " + slug, OrgSlug: slug,
		})
		if err != nil {
			t.Fatalf("CreateAccount(%s): %v", email, err)
		}
		return u, o
	}

	alice, acme := account("alice@example.com", "acme")
	bob, beta := account("bob@example.com", "beta")

	t.Run("accounts", func(t *testing.T) {
		if alice.PasswordHash == "" || alice.DisabledAt != nil {
			t.Errorf("alice = %+v", alice)
		}
		if _, _, err := s.CreateAccount(ctx, storage.NewAccount{Email: "alice@example.com", DisplayName: "Dup", PasswordHash: "x", OrgName: "D", OrgSlug: "dup-1"}); !errors.Is(err, storage.ErrConflict) {
			t.Errorf("duplicate email error = %v, want ErrConflict", err)
		}
		// A failed signup must roll back completely: no half-created user left behind.
		if _, _, err := s.CreateAccount(ctx, storage.NewAccount{Email: "carol@example.com", DisplayName: "C", PasswordHash: "x", OrgName: "C", OrgSlug: "acme"}); !errors.Is(err, storage.ErrConflict) {
			t.Errorf("duplicate slug error = %v, want ErrConflict", err)
		}
		if _, err := s.GetUserByEmail(ctx, "carol@example.com"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("user from failed signup exists (err = %v); the transaction did not roll back", err)
		}
		got, err := s.GetUserByEmail(ctx, "alice@example.com")
		if err != nil || got.ID != alice.ID {
			t.Errorf("GetUserByEmail = %+v, %v", got, err)
		}
		if n, err := s.CountUsers(ctx); err != nil || n != 2 {
			t.Errorf("CountUsers = %d, %v; want 2", n, err)
		}
	})

	t.Run("membership", func(t *testing.T) {
		m, err := s.GetMembership(ctx, acme.ID, alice.ID)
		if err != nil || m.Role != storage.RoleOwner {
			t.Errorf("alice in acme = %+v, %v; want owner", m, err)
		}
		if _, err := s.GetMembership(ctx, acme.ID, bob.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("bob in acme error = %v, want ErrNotFound", err)
		}
		second, err := s.CreateOrganizationFor(ctx, alice.ID, storage.NewOrganization{Name: "Second", Slug: "second"})
		if err != nil {
			t.Fatal(err)
		}
		orgs, err := s.ListOrganizationsFor(ctx, alice.ID)
		if err != nil || len(orgs) != 2 || orgs[0].ID != acme.ID || orgs[1].ID != second.ID || orgs[1].Role != storage.RoleOwner {
			t.Errorf("alice's organizations = %+v, %v; want acme then second, both owner", orgs, err)
		}
		if orgs, _ := s.ListOrganizationsFor(ctx, bob.ID); len(orgs) != 1 || orgs[0].ID != beta.ID {
			t.Errorf("bob's organizations = %+v, want only beta", orgs)
		}
		if _, err := s.CreateOrganizationFor(ctx, alice.ID, storage.NewOrganization{Name: "Dup", Slug: "second"}); !errors.Is(err, storage.ErrConflict) {
			t.Errorf("duplicate slug error = %v, want ErrConflict", err)
		}
		if _, err := s.GetOrganization(ctx, "not-a-uuid"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetOrganization(bad id) error = %v, want ErrNotFound", err)
		}
	})

	t.Run("sessions", func(t *testing.T) {
		h := hash32(1)
		if err := s.CreateSession(ctx, alice.ID, h, now.Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if u, err := s.UserBySession(ctx, h, now); err != nil || u.ID != alice.ID {
			t.Errorf("live session = %+v, %v", u, err)
		}
		if _, err := s.UserBySession(ctx, h, now.Add(2*time.Hour)); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("expired session error = %v, want ErrNotFound", err)
		}
		if _, err := s.UserBySession(ctx, hash32(9), now); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("unknown session error = %v, want ErrNotFound", err)
		}
		if err := s.RevokeSession(ctx, h); err != nil {
			t.Fatal(err)
		}
		if err := s.RevokeSession(ctx, h); err != nil {
			t.Errorf("second revoke = %v, want idempotent", err)
		}
		if _, err := s.UserBySession(ctx, h, now); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("revoked session error = %v, want ErrNotFound", err)
		}
		if err := s.CreateSession(ctx, alice.ID, []byte("short"), now.Add(time.Hour)); err == nil {
			t.Error("a token hash of the wrong length was accepted")
		}
		if err := s.CreateSession(ctx, alice.ID, hash32(2), now.Add(-time.Hour)); err == nil {
			t.Error("a session that is already expired was accepted")
		}

		// Purge: keep a live session, drop one expired shortly after creation.
		live, soon := hash32(3), hash32(4)
		_ = s.CreateSession(ctx, alice.ID, live, now.Add(time.Hour))
		_ = s.CreateSession(ctx, alice.ID, soon, now.Add(time.Second))
		if n, err := s.DeleteExpiredSessions(ctx, now.Add(time.Minute)); err != nil || n < 1 {
			t.Errorf("DeleteExpiredSessions = %d, %v; want at least the expired one", n, err)
		}
		if _, err := s.UserBySession(ctx, live, now); err != nil {
			t.Errorf("purge removed a live session: %v", err)
		}
	})

	t.Run("members", func(t *testing.T) {
		// bob joins acme as a viewer
		m, err := s.AddMember(ctx, acme.ID, bob.ID, storage.RoleViewer)
		if err != nil || m.Role != storage.RoleViewer {
			t.Fatalf("AddMember = %+v, %v", m, err)
		}
		if _, err := s.AddMember(ctx, acme.ID, bob.ID, storage.RoleAdmin); !errors.Is(err, storage.ErrConflict) {
			t.Errorf("duplicate AddMember error = %v, want ErrConflict", err)
		}
		if _, err := s.AddMember(ctx, acme.ID, missing, storage.RoleViewer); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("AddMember missing user error = %v, want ErrNotFound", err)
		}
		if _, err := s.AddMember(ctx, missing, bob.ID, storage.RoleViewer); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("AddMember missing org error = %v, want ErrNotFound", err)
		}
		list, err := s.ListMembers(ctx, acme.ID)
		if err != nil || len(list) != 2 || list[0].UserID != alice.ID || list[1].Email != "bob@example.com" || list[1].Role != storage.RoleViewer {
			t.Errorf("ListMembers = %+v, %v; want alice then bob(viewer)", list, err)
		}
		if _, err := s.ListMembers(ctx, missing); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("ListMembers(missing) error = %v, want ErrNotFound", err)
		}

		// alice is the only owner of acme
		if err := s.SetMemberRole(ctx, acme.ID, alice.ID, storage.RoleAdmin); !errors.Is(err, storage.ErrLastOwner) {
			t.Errorf("demoting the last owner error = %v, want ErrLastOwner", err)
		}
		if err := s.RemoveMember(ctx, acme.ID, alice.ID); !errors.Is(err, storage.ErrLastOwner) {
			t.Errorf("removing the last owner error = %v, want ErrLastOwner", err)
		}
		if err := s.SetMemberRole(ctx, acme.ID, missing, storage.RoleViewer); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("role of a non-member error = %v, want ErrNotFound", err)
		}
		if err := s.SetMemberRole(ctx, acme.ID, bob.ID, storage.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if err := s.SetMemberRole(ctx, acme.ID, alice.ID, storage.RoleMember); err != nil {
			t.Errorf("stepping down with a second owner present: %v", err)
		}
		if err := s.RemoveMember(ctx, acme.ID, bob.ID); !errors.Is(err, storage.ErrLastOwner) {
			t.Errorf("removing the now-last owner error = %v, want ErrLastOwner", err)
		}
		// restore alice as owner and remove bob again so later subtests see the original state
		if err := s.SetMemberRole(ctx, acme.ID, alice.ID, storage.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if err := s.RemoveMember(ctx, acme.ID, bob.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := s.GetMembership(ctx, acme.ID, bob.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("removed member still found: %v", err)
		}
	})

	t.Run("bootstrap guard", func(t *testing.T) {
		_, _, err := s.CreateAccount(ctx, storage.NewAccount{Email: "late@example.com", DisplayName: "L", PasswordHash: "x", OrgName: "Late", OrgSlug: "late", OnlyIfNoUsers: true})
		if !errors.Is(err, storage.ErrSignupClosed) {
			t.Errorf("bootstrap signup with users present error = %v, want ErrSignupClosed", err)
		}
		if _, err := s.GetUserByEmail(ctx, "late@example.com"); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("refused bootstrap signup left a user behind: %v", err)
		}
	})

	cluster, err := s.CreateCluster(ctx, acme.ID, storage.NewCluster{Name: "prod", Provider: storage.ProviderGKE})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}

	t.Run("clusters and tenant isolation", func(t *testing.T) {
		if cluster.Status != storage.ClusterPending || cluster.KubernetesVersion != nil || cluster.LastSeenAt != nil {
			t.Errorf("cluster = %+v, want pending with NULL version and last_seen_at", cluster)
		}
		if _, err := s.CreateCluster(ctx, acme.ID, storage.NewCluster{Name: "prod", Provider: storage.ProviderGKE}); !errors.Is(err, storage.ErrConflict) {
			t.Errorf("duplicate cluster error = %v, want ErrConflict", err)
		}
		if _, err := s.CreateCluster(ctx, beta.ID, storage.NewCluster{Name: "prod", Provider: storage.ProviderGKE}); err != nil {
			t.Errorf("same name in another organization: %v", err)
		}
		if _, err := s.CreateCluster(ctx, missing, storage.NewCluster{Name: "x", Provider: storage.ProviderGKE}); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("cluster in missing organization error = %v, want ErrNotFound", err)
		}
		if _, err := s.GetCluster(ctx, beta.ID, cluster.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetCluster across organizations error = %v, want ErrNotFound", err)
		}
		if cl, _ := s.ListClusters(ctx, beta.ID); len(cl) != 1 || cl[0].ID == cluster.ID {
			t.Errorf("beta's clusters = %+v, want only its own", cl)
		}
	})

	t.Run("scans", func(t *testing.T) {
		if _, err := s.CreateScanJob(ctx, beta.ID, cluster.ID, bob.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("CreateScanJob across organizations error = %v, want ErrNotFound", err)
		}
		first, err := s.CreateScanJob(ctx, acme.ID, cluster.ID, alice.ID)
		if err != nil {
			t.Fatalf("CreateScanJob: %v", err)
		}
		second, _ := s.CreateScanJob(ctx, acme.ID, cluster.ID, alice.ID)
		if first.Status != storage.ScanQueued || first.StartedAt != nil || first.Error != nil {
			t.Errorf("scan = %+v, want queued with NULL started_at and error", first)
		}
		if first.RequestedBy == nil || *first.RequestedBy != alice.ID {
			t.Errorf("requested_by = %v, want %s", first.RequestedBy, alice.ID)
		}
		jobs, err := s.ListScanJobs(ctx, acme.ID, cluster.ID)
		if err != nil || len(jobs) != 2 || jobs[0].ID != second.ID {
			t.Errorf("ListScanJobs = %+v, %v; want two, newest first", jobs, err)
		}
		if _, err := s.GetScanJob(ctx, beta.ID, first.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("GetScanJob across organizations error = %v, want ErrNotFound", err)
		}
	})

	t.Run("agent credentials", func(t *testing.T) {
		h := hash32(0xAB)
		cred, err := s.CreateAgentCredential(ctx, acme.ID, cluster.ID, "ksa_abcdef", h)
		if err != nil {
			t.Fatalf("CreateAgentCredential: %v", err)
		}
		if cred.TokenPrefix != "ksa_abcdef" || cred.RevokedAt != nil || cred.LastUsedAt != nil {
			t.Errorf("credential = %+v", cred)
		}
		if _, err := s.CreateAgentCredential(ctx, beta.ID, cluster.ID, "ksa_zzzzzz", hash32(0xCD)); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("credential for another organization's cluster error = %v, want ErrNotFound", err)
		}
		if _, err := s.CreateAgentCredential(ctx, acme.ID, cluster.ID, "ksa_dupdup", h); !errors.Is(err, storage.ErrConflict) {
			t.Errorf("duplicate token hash error = %v, want ErrConflict", err)
		}

		id, err := s.AuthenticateAgent(ctx, h, now)
		if err != nil || id.ClusterID != cluster.ID || id.OrganizationID != acme.ID || id.CredentialID != cred.ID {
			t.Errorf("AuthenticateAgent = %+v, %v", id, err)
		}
		if _, err := s.AuthenticateAgent(ctx, hash32(0xEE), now); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("unknown token error = %v, want ErrNotFound", err)
		}

		if err := s.RevokeAgentCredential(ctx, beta.ID, cluster.ID, cred.ID); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("revoke from another organization error = %v, want ErrNotFound", err)
		}
		if _, err := s.AuthenticateAgent(ctx, h, now); err != nil {
			t.Errorf("a refused revoke still disabled the token: %v", err)
		}
		for i := 0; i < 2; i++ { // idempotent
			if err := s.RevokeAgentCredential(ctx, acme.ID, cluster.ID, cred.ID); err != nil {
				t.Fatalf("revoke #%d: %v", i+1, err)
			}
		}
		if _, err := s.AuthenticateAgent(ctx, h, now); !errors.Is(err, storage.ErrNotFound) {
			t.Errorf("revoked token error = %v, want ErrNotFound", err)
		}
		list, err := s.ListAgentCredentials(ctx, acme.ID, cluster.ID)
		if err != nil || len(list) != 1 || list[0].RevokedAt == nil || list[0].LastUsedAt == nil {
			t.Errorf("ListAgentCredentials = %+v, %v; want one revoked, used credential", list, err)
		}
		if list, _ := s.ListAgentCredentials(ctx, beta.ID, cluster.ID); len(list) != 0 {
			t.Errorf("beta sees acme's credentials: %+v", list)
		}
	})

	t.Run("audit log", func(t *testing.T) {
		org, user := acme.ID, alice.ID
		entries := []storage.AuditEntry{
			{OrganizationID: &org, ActorUserID: &user, ActorType: storage.ActorUser, Action: "cluster.created", TargetType: "cluster", TargetID: cluster.ID, Metadata: map[string]any{"name": "prod"}, IP: "203.0.113.9"},
			{OrganizationID: &org, ActorType: storage.ActorSystem, Action: "scan.expired", Metadata: map[string]any{}},
			{ActorUserID: &user, ActorType: storage.ActorUser, Action: "auth.login", Metadata: map[string]any{}, IP: "2001:db8::1"}, // no organization
		}
		for _, e := range entries {
			if err := s.AppendAudit(ctx, e); err != nil {
				t.Fatalf("AppendAudit(%s): %v", e.Action, err)
			}
		}
		if err := s.AppendAudit(ctx, storage.AuditEntry{ActorType: "robot", Action: "x"}); err == nil {
			t.Error("invalid audit entry accepted")
		}
		got, err := s.ListAudit(ctx, acme.ID)
		if err != nil || len(got) != 2 || got[0].Action != "scan.expired" || got[1].Action != "cluster.created" {
			t.Fatalf("ListAudit = %+v, %v; want two entries, newest first, without the org-less login", got, err)
		}
		if got[1].Metadata["name"] != "prod" || got[1].IP != "203.0.113.9" || got[1].TargetID != cluster.ID {
			t.Errorf("entry did not round-trip: %+v", got[1])
		}
		if other, _ := s.ListAudit(ctx, beta.ID); len(other) != 0 {
			t.Errorf("beta sees acme's audit log: %+v", other)
		}
		// The table is append-only at the database level.
		if _, err := db.ExecContext(ctx, `UPDATE audit_logs SET action = 'tampered'`); err == nil {
			t.Error("UPDATE on audit_logs succeeded")
		}
		if _, err := db.ExecContext(ctx, `DELETE FROM audit_logs`); err == nil {
			t.Error("DELETE on audit_logs succeeded")
		}
	})
}

// Two simultaneous first signups on a closed server: exactly one account may be created.
func TestBootstrapSignupRace(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := New(db)

	const n = 10
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.CreateAccount(ctx, storage.NewAccount{
				Email: fmt.Sprintf("u%d@example.com", i), DisplayName: "U", PasswordHash: "x",
				OrgName: "O", OrgSlug: fmt.Sprintf("org-%d", i), OnlyIfNoUsers: true,
			})
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	ok, closed := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, storage.ErrSignupClosed):
			closed++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 || closed != n-1 {
		t.Errorf("created=%d closed=%d, want exactly 1 and %d", ok, closed, n-1)
	}
	if c, _ := s.CountUsers(ctx); c != 1 {
		t.Errorf("CountUsers = %d, want 1", c)
	}
}

// Two owners demoting each other at the same instant must not leave the organization ownerless.
func TestLastOwnerRace(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	if err := Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := New(db)

	a, org, err := s.CreateAccount(ctx, storage.NewAccount{Email: "a@example.com", DisplayName: "A", PasswordHash: "x", OrgName: "O", OrgSlug: "race"})
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.CreateAccount(ctx, storage.NewAccount{Email: "b@example.com", DisplayName: "B", PasswordHash: "x", OrgName: "P", OrgSlug: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMember(ctx, org.ID, b.ID, storage.RoleOwner); err != nil {
		t.Fatal(err)
	}

	for round := 0; round < 20; round++ {
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, id := range []string{a.ID, b.ID} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				results <- s.SetMemberRole(ctx, org.ID, id, storage.RoleViewer)
			}(id)
		}
		wg.Wait()
		close(results)
		ok, last := 0, 0
		for err := range results {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, storage.ErrLastOwner):
				last++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
		if ok != 1 || last != 1 {
			t.Fatalf("round %d: succeeded=%d refused=%d, want exactly one of each", round, ok, last)
		}
		members, _ := s.ListMembers(ctx, org.ID)
		owners := 0
		for _, m := range members {
			if m.Role == storage.RoleOwner {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("round %d: %d owners remain, want 1", round, owners)
		}
		// reset: make both owners again for the next round
		for _, id := range []string{a.ID, b.ID} {
			if err := s.SetMemberRole(ctx, org.ID, id, storage.RoleOwner); err != nil {
				t.Fatal(err)
			}
		}
	}
}
