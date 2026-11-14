package memory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

var ctx = context.Background()

// account creates a user who owns a fresh organization with the given slug.
func account(t *testing.T, s *Store, slug string) (storage.User, storage.Organization) {
	t.Helper()
	u, o, err := s.CreateAccount(ctx, storage.NewAccount{
		Email: slug + "@example.com", DisplayName: slug, PasswordHash: "hash", OrgName: slug, OrgSlug: slug,
	})
	if err != nil {
		t.Fatalf("CreateAccount(%s): %v", slug, err)
	}
	return u, o
}

func mustCluster(t *testing.T, s *Store, orgID, name string) storage.Cluster {
	t.Helper()
	c, err := s.CreateCluster(ctx, orgID, storage.NewCluster{Name: name, Provider: storage.ProviderGKE})
	if err != nil {
		t.Fatalf("CreateCluster(%s): %v", name, err)
	}
	return c
}

func hash(b byte) []byte {
	h := make([]byte, 32)
	h[0] = b
	return h
}

func TestNewIDIsValidAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		id := newID()
		if !storage.IsValidID(id) {
			t.Fatalf("newID() = %q, not a valid ID", id)
		}
		if seen[id] {
			t.Fatalf("newID() repeated %q", id)
		}
		seen[id] = true
	}
}

func TestCreateAccount(t *testing.T) {
	s := New()
	user, org := account(t, s, "acme")

	m, err := s.GetMembership(ctx, org.ID, user.ID)
	if err != nil || m.Role != storage.RoleOwner {
		t.Errorf("membership = %+v, %v; want owner", m, err)
	}

	got, err := s.GetUserByEmail(ctx, "  ACME@Example.com ")
	if err != nil || got.ID != user.ID || got.PasswordHash != "hash" {
		t.Errorf("GetUserByEmail = %+v, %v", got, err)
	}
	if _, err := s.GetUserByEmail(ctx, "nobody@example.com"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown email error = %v, want ErrNotFound", err)
	}

	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Errorf("CountUsers = %d, want 1", n)
	}
}

func TestCreateAccountConflictsAndValidation(t *testing.T) {
	s := New()
	account(t, s, "acme")

	base := storage.NewAccount{Email: "new@example.com", DisplayName: "N", PasswordHash: "h", OrgName: "New", OrgSlug: "new"}

	dupEmail := base
	dupEmail.Email = "ACME@example.com" // same address, different case
	if _, _, err := s.CreateAccount(ctx, dupEmail); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate email error = %v, want ErrConflict", err)
	}

	dupSlug := base
	dupSlug.OrgSlug = "acme"
	if _, _, err := s.CreateAccount(ctx, dupSlug); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate slug error = %v, want ErrConflict", err)
	}

	bad := base
	bad.Email = "nope"
	var ve *storage.ValidationError
	if _, _, err := s.CreateAccount(ctx, bad); !errors.As(err, &ve) {
		t.Errorf("invalid email error = %v, want *ValidationError", err)
	}

	// A failed signup must not leave a half-created user behind.
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Errorf("CountUsers = %d after failed signups, want 1", n)
	}
}

func TestOrganizationsAndMembership(t *testing.T) {
	s := New()
	alice, acme := account(t, s, "acme")
	bob, beta := account(t, s, "beta")

	second, err := s.CreateOrganizationFor(ctx, alice.ID, storage.NewOrganization{Name: "Second", Slug: "second"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateOrganizationFor(ctx, alice.ID, storage.NewOrganization{Name: "Dup", Slug: "beta"}); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate slug error = %v, want ErrConflict", err)
	}
	if _, err := s.CreateOrganizationFor(ctx, newID(), storage.NewOrganization{Name: "X", Slug: "x"}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown user error = %v, want ErrNotFound", err)
	}

	mine, _ := s.ListOrganizationsFor(ctx, alice.ID)
	if len(mine) != 2 || mine[0].ID != acme.ID || mine[1].ID != second.ID || mine[0].Role != storage.RoleOwner {
		t.Errorf("alice's organizations = %+v, want acme then second, as owner", mine)
	}
	theirs, _ := s.ListOrganizationsFor(ctx, bob.ID)
	if len(theirs) != 1 || theirs[0].ID != beta.ID {
		t.Errorf("bob's organizations = %+v, want only beta", theirs)
	}

	if _, err := s.GetMembership(ctx, beta.ID, alice.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("non-member error = %v, want ErrNotFound", err)
	}
	if _, err := s.GetOrganization(ctx, newID()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("missing organization error = %v, want ErrNotFound", err)
	}
}

func TestSessions(t *testing.T) {
	s := New()
	user, _ := account(t, s, "acme")
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

	if err := s.CreateSession(ctx, user.ID, hash(1), now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateSession(ctx, user.ID, hash(1), now.Add(time.Hour)); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate token hash error = %v, want ErrConflict", err)
	}
	if err := s.CreateSession(ctx, newID(), hash(2), now.Add(time.Hour)); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("session for unknown user error = %v, want ErrNotFound", err)
	}

	if got, err := s.UserBySession(ctx, hash(1), now); err != nil || got.ID != user.ID {
		t.Errorf("live session = %+v, %v", got, err)
	}
	if _, err := s.UserBySession(ctx, hash(9), now); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown token error = %v, want ErrNotFound", err)
	}

	// Expiry is exclusive: valid strictly before expires_at.
	if _, err := s.UserBySession(ctx, hash(1), now.Add(time.Hour-time.Nanosecond)); err != nil {
		t.Errorf("session just before expiry rejected: %v", err)
	}
	if _, err := s.UserBySession(ctx, hash(1), now.Add(time.Hour)); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("session at expiry error = %v, want ErrNotFound", err)
	}

	if err := s.RevokeSession(ctx, hash(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserBySession(ctx, hash(1), now); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("revoked session error = %v, want ErrNotFound", err)
	}
	if err := s.RevokeSession(ctx, hash(1)); err != nil {
		t.Errorf("second revoke = %v, want nil (idempotent)", err)
	}
	if err := s.RevokeSession(ctx, hash(77)); err != nil {
		t.Errorf("revoking unknown session = %v, want nil", err)
	}
}

func TestDisabledUserSessionsStopWorking(t *testing.T) {
	s := New()
	user, _ := account(t, s, "acme")
	now := time.Now()
	_ = s.CreateSession(ctx, user.ID, hash(1), now.Add(time.Hour))

	s.users[0].DisabledAt = &now // same package: flip the flag directly

	if _, err := s.UserBySession(ctx, hash(1), now); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("disabled user's session error = %v, want ErrNotFound", err)
	}
}

func TestClustersAreScopedToTheirOrganization(t *testing.T) {
	s := New()
	_, acme := account(t, s, "acme")
	_, beta := account(t, s, "beta")

	prod := mustCluster(t, s, acme.ID, "prod")
	mustCluster(t, s, beta.ID, "prod") // same name in another organization is fine

	if _, err := s.CreateCluster(ctx, acme.ID, storage.NewCluster{Name: "prod", Provider: storage.ProviderGKE}); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate cluster name error = %v, want ErrConflict", err)
	}
	if _, err := s.CreateCluster(ctx, newID(), storage.NewCluster{Name: "x", Provider: storage.ProviderGKE}); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("cluster in missing organization error = %v, want ErrNotFound", err)
	}
	if prod.Status != storage.ClusterPending {
		t.Errorf("new cluster status = %q, want pending", prod.Status)
	}

	if _, err := s.GetCluster(ctx, acme.ID, prod.ID); err != nil {
		t.Errorf("GetCluster in own organization: %v", err)
	}
	if _, err := s.GetCluster(ctx, beta.ID, prod.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetCluster across organizations error = %v, want ErrNotFound", err)
	}

	list, _ := s.ListClusters(ctx, acme.ID)
	if len(list) != 1 || list[0].ID != prod.ID {
		t.Errorf("ListClusters(acme) = %+v, want only acme's cluster", list)
	}
}

func TestScanJobs(t *testing.T) {
	s := New()
	alice, acme := account(t, s, "acme")
	_, beta := account(t, s, "beta")
	prod := mustCluster(t, s, acme.ID, "prod")

	first, err := s.CreateScanJob(ctx, acme.ID, prod.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := s.CreateScanJob(ctx, acme.ID, prod.ID, alice.ID)
	if first.Status != storage.ScanQueued || first.StartedAt != nil || first.FinishedAt != nil {
		t.Errorf("new scan = %+v, want queued with no timestamps", first)
	}
	if first.RequestedBy == nil || *first.RequestedBy != alice.ID {
		t.Errorf("RequestedBy = %v, want %s", first.RequestedBy, alice.ID)
	}

	if _, err := s.CreateScanJob(ctx, beta.ID, prod.ID, alice.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("scan on another organization's cluster error = %v, want ErrNotFound", err)
	}
	if _, err := s.GetScanJob(ctx, beta.ID, first.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("GetScanJob across organizations error = %v, want ErrNotFound", err)
	}
	if got, err := s.GetScanJob(ctx, acme.ID, first.ID); err != nil || got.ID != first.ID {
		t.Errorf("GetScanJob = %+v, %v", got, err)
	}

	list, _ := s.ListScanJobs(ctx, acme.ID, prod.ID)
	if len(list) != 2 || list[0].ID != second.ID || list[1].ID != first.ID {
		t.Errorf("ListScanJobs = %+v, want newest first", list)
	}
	if other, _ := s.ListScanJobs(ctx, beta.ID, prod.ID); len(other) != 0 {
		t.Errorf("ListScanJobs across organizations = %+v, want empty", other)
	}
}

func TestListsAreCapped(t *testing.T) {
	s := New()
	_, acme := account(t, s, "acme")
	prod := mustCluster(t, s, acme.ID, "prod")
	for range storage.ListLimit + 5 {
		if _, err := s.CreateScanJob(ctx, acme.ID, prod.ID, ""); err != nil {
			t.Fatal(err)
		}
	}
	list, _ := s.ListScanJobs(ctx, acme.ID, prod.ID)
	if len(list) != storage.ListLimit {
		t.Errorf("len = %d, want %d", len(list), storage.ListLimit)
	}
}

func TestAgentCredentials(t *testing.T) {
	s := New()
	_, acme := account(t, s, "acme")
	_, beta := account(t, s, "beta")
	prod := mustCluster(t, s, acme.ID, "prod")
	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

	cred, err := s.CreateAgentCredential(ctx, acme.ID, prod.ID, "ksa_Ab3dE9", hash(5))
	if err != nil {
		t.Fatal(err)
	}
	if cred.TokenPrefix != "ksa_Ab3dE9" || cred.RevokedAt != nil || cred.LastUsedAt != nil {
		t.Errorf("credential = %+v", cred)
	}
	if _, err := s.CreateAgentCredential(ctx, acme.ID, prod.ID, "ksa_x", hash(5)); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate token hash error = %v, want ErrConflict", err)
	}
	if _, err := s.CreateAgentCredential(ctx, beta.ID, prod.ID, "ksa_x", hash(6)); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("credential for another organization's cluster error = %v, want ErrNotFound", err)
	}

	id, err := s.AuthenticateAgent(ctx, hash(5), now)
	if err != nil || id.ClusterID != prod.ID || id.OrganizationID != acme.ID || id.CredentialID != cred.ID {
		t.Errorf("AuthenticateAgent = %+v, %v", id, err)
	}
	if _, err := s.AuthenticateAgent(ctx, hash(99), now); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("unknown agent token error = %v, want ErrNotFound", err)
	}

	listed, _ := s.ListAgentCredentials(ctx, acme.ID, prod.ID)
	if len(listed) != 1 || listed[0].LastUsedAt == nil || !listed[0].LastUsedAt.Equal(now) {
		t.Errorf("listed = %+v, want last_used_at = %v", listed, now)
	}
	if other, _ := s.ListAgentCredentials(ctx, beta.ID, prod.ID); len(other) != 0 {
		t.Errorf("another organization lists credentials: %+v", other)
	}

	// Another organization cannot revoke it.
	if err := s.RevokeAgentCredential(ctx, beta.ID, prod.ID, cred.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("cross-tenant revoke error = %v, want ErrNotFound", err)
	}
	if _, err := s.AuthenticateAgent(ctx, hash(5), now); err != nil {
		t.Errorf("token stopped working after a failed cross-tenant revoke: %v", err)
	}

	if err := s.RevokeAgentCredential(ctx, acme.ID, prod.ID, cred.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAgent(ctx, hash(5), now); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("revoked token still authenticates: %v", err)
	}
	if err := s.RevokeAgentCredential(ctx, acme.ID, prod.ID, cred.ID); err != nil {
		t.Errorf("second revoke = %v, want nil (idempotent)", err)
	}
	if err := s.RevokeAgentCredential(ctx, acme.ID, prod.ID, newID()); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("revoking unknown credential error = %v, want ErrNotFound", err)
	}
}

func TestAudit(t *testing.T) {
	s := New()
	alice, acme := account(t, s, "acme")
	_, beta := account(t, s, "beta")

	entry := func(org, action string, meta map[string]any) storage.AuditEntry {
		return storage.AuditEntry{OrganizationID: &org, ActorUserID: &alice.ID, ActorType: storage.ActorUser, Action: action, Metadata: meta}
	}

	meta := map[string]any{"name": "prod"}
	if err := s.AppendAudit(ctx, entry(acme.ID, "cluster.created", meta)); err != nil {
		t.Fatal(err)
	}
	_ = s.AppendAudit(ctx, entry(acme.ID, "scan.requested", nil))
	_ = s.AppendAudit(ctx, entry(beta.ID, "cluster.created", nil))
	meta["name"] = "mutated after append"

	list, _ := s.ListAudit(ctx, acme.ID)
	if len(list) != 2 || list[0].Action != "scan.requested" || list[1].Action != "cluster.created" {
		t.Fatalf("ListAudit = %+v, want two entries, newest first", list)
	}
	if list[1].Metadata["name"] != "prod" {
		t.Errorf("stored metadata changed after the caller mutated its map: %v", list[1].Metadata)
	}
	if list[0].Metadata == nil {
		t.Error("nil metadata should come back as an empty map")
	}
	if list[0].ID <= list[1].ID || list[0].CreatedAt.IsZero() {
		t.Errorf("IDs/timestamps not assigned in order: %+v", list)
	}
	if other, _ := s.ListAudit(ctx, beta.ID); len(other) != 1 {
		t.Errorf("beta sees %d entries, want only its own 1", len(other))
	}

	for name, bad := range map[string]storage.AuditEntry{
		"unknown actor type": {ActorType: "robot", Action: "x"},
		"blank action":       {ActorType: storage.ActorSystem, Action: "  "},
	} {
		if err := s.AppendAudit(ctx, bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestMembers(t *testing.T) {
	ctx := context.Background()
	s := New()
	owner, org, _ := s.CreateAccount(ctx, storage.NewAccount{Email: "o@example.com", DisplayName: "O", PasswordHash: "h", OrgName: "Org", OrgSlug: "org"})
	other, _, _ := s.CreateAccount(ctx, storage.NewAccount{Email: "x@example.com", DisplayName: "X", PasswordHash: "h", OrgName: "Other", OrgSlug: "other"})

	if _, err := s.AddMember(ctx, org.ID, other.ID, "boss"); err == nil {
		t.Error("invalid role accepted")
	}
	if _, err := s.AddMember(ctx, org.ID, "missing", storage.RoleViewer); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("missing user: %v", err)
	}
	if _, err := s.AddMember(ctx, "missing", other.ID, storage.RoleViewer); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("missing org: %v", err)
	}
	if _, err := s.AddMember(ctx, org.ID, other.ID, storage.RoleViewer); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddMember(ctx, org.ID, other.ID, storage.RoleAdmin); !errors.Is(err, storage.ErrConflict) {
		t.Errorf("duplicate: %v", err)
	}
	list, err := s.ListMembers(ctx, org.ID)
	if err != nil || len(list) != 2 || list[0].UserID != owner.ID || list[1].Email != "x@example.com" {
		t.Errorf("ListMembers = %+v, %v", list, err)
	}
	if _, err := s.ListMembers(ctx, "missing"); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("ListMembers(missing) = %v", err)
	}

	if err := s.SetMemberRole(ctx, org.ID, owner.ID, storage.RoleViewer); !errors.Is(err, storage.ErrLastOwner) {
		t.Errorf("demoting the last owner: %v", err)
	}
	if err := s.RemoveMember(ctx, org.ID, owner.ID); !errors.Is(err, storage.ErrLastOwner) {
		t.Errorf("removing the last owner: %v", err)
	}
	if err := s.SetMemberRole(ctx, org.ID, "nobody", storage.RoleViewer); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("role of non-member: %v", err)
	}
	if err := s.SetMemberRole(ctx, org.ID, other.ID, storage.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMemberRole(ctx, org.ID, owner.ID, storage.RoleMember); err != nil {
		t.Errorf("stepping down with a second owner present: %v", err)
	}
	if err := s.RemoveMember(ctx, org.ID, other.ID); !errors.Is(err, storage.ErrLastOwner) {
		t.Errorf("removing the now-last owner: %v", err)
	}
	if err := s.RemoveMember(ctx, org.ID, owner.ID); err != nil {
		t.Errorf("removing a non-owner: %v", err)
	}
	if _, err := s.GetMembership(ctx, org.ID, owner.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("removed member still found: %v", err)
	}
}

func TestOnlyIfNoUsers(t *testing.T) {
	ctx := context.Background()
	s := New()
	in := func(email, slug string) storage.NewAccount {
		return storage.NewAccount{Email: email, DisplayName: "U", PasswordHash: "h", OrgName: "O", OrgSlug: slug, OnlyIfNoUsers: true}
	}
	if _, _, err := s.CreateAccount(ctx, in("a@example.com", "a-org")); err != nil {
		t.Fatalf("first account: %v", err)
	}
	if _, _, err := s.CreateAccount(ctx, in("b@example.com", "b-org")); !errors.Is(err, storage.ErrSignupClosed) {
		t.Errorf("second account error = %v, want ErrSignupClosed", err)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Errorf("CountUsers = %d, want 1", n)
	}
}

func TestDeleteExpiredSessions(t *testing.T) {
	ctx := context.Background()
	s := New()
	u, _, _ := s.CreateAccount(ctx, storage.NewAccount{Email: "o@example.com", DisplayName: "O", PasswordHash: "h", OrgName: "Org", OrgSlug: "org"})
	now := time.Now().UTC()
	hash := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

	_ = s.CreateSession(ctx, u.ID, hash(1), now.Add(-2*time.Hour)) // expired
	_ = s.CreateSession(ctx, u.ID, hash(2), now.Add(time.Hour))    // live
	_ = s.CreateSession(ctx, u.ID, hash(3), now.Add(time.Hour))    // live, then revoked
	_ = s.RevokeSession(ctx, hash(3))

	if n, err := s.DeleteExpiredSessions(ctx, now.Add(-time.Hour)); err != nil || n != 1 {
		t.Errorf("first purge = %d, %v; want only the expired session", n, err)
	}
	if _, err := s.UserBySession(ctx, hash(2), now); err != nil {
		t.Errorf("a live session was purged: %v", err)
	}
	// Once the revocation is older than the cutoff, the revoked session goes too, the live one stays.
	if n, err := s.DeleteExpiredSessions(ctx, now.Add(time.Minute)); err != nil || n != 1 {
		t.Errorf("second purge = %d, %v; want the revoked session", n, err)
	}
	if _, err := s.UserBySession(ctx, hash(2), now); err != nil {
		t.Errorf("a live session was purged: %v", err)
	}
}

func TestScanCompletionAndStaleRecovery(t *testing.T) {
	s := New()
	alice, org := account(t, s, "scan-recovery")
	cluster := mustCluster(t, s, org.ID, "kind")
	job, err := s.CreateScanJob(ctx, org.ID, cluster.ID, alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimNextScanJob(ctx, org.ID, cluster.ID)
	if err != nil || claimed.Status != storage.ScanRunning {
		t.Fatalf("claim = %+v, %v", claimed, err)
	}
	count, err := s.RequeueStaleScanJobs(ctx, time.Now().UTC().Add(time.Minute))
	if err != nil || count != 1 {
		t.Fatalf("requeue = %d, %v; want 1", count, err)
	}
	reloaded, err := s.GetScanJob(ctx, org.ID, job.ID)
	if err != nil || reloaded.Status != storage.ScanQueued || reloaded.StartedAt != nil {
		t.Fatalf("reloaded job = %+v, %v", reloaded, err)
	}
	claimed, err = s.ClaimNextScanJob(ctx, org.ID, cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	findings := json.RawMessage(`[]`)
	summary := json.RawMessage(`{"cluster_id":"` + cluster.ID + `","nodes":1,"pods":0}`)
	if err := s.CompleteScanJob(ctx, org.ID, cluster.ID, job.ID, findings, summary); err != nil {
		t.Fatal(err)
	}
	reloaded, err = s.GetScanJob(ctx, org.ID, job.ID)
	if err != nil || reloaded.Status != storage.ScanSucceeded || reloaded.FinishedAt == nil {
		t.Fatalf("completed job = %+v, %v", reloaded, err)
	}
	result, err := s.GetScanResult(ctx, org.ID, job.ID)
	if err != nil || string(result.Findings) != "[]" {
		t.Fatalf("result = %+v, %v", result, err)
	}
}
