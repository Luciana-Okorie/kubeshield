// Package memory is an in-process storage.Store. It backs the tests and lets the
// API run without a database; nothing it holds survives a restart.
package memory

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

type session struct {
	userID    string
	expiresAt time.Time
	revokedAt *time.Time
}

type agentRecord struct {
	cred storage.AgentCredential
	hash string
	org  string
}

// Store implements storage.Store with slices and maps guarded by one mutex.
// Lookups are linear, which is fine at test and development scale.
type Store struct {
	mu        sync.RWMutex
	users     []storage.User
	orgs      []storage.Organization
	members   []storage.Membership
	clusters  []storage.Cluster
	scans     []storage.ScanJob
	results   map[string]storage.ScanResult
	sessions  map[string]session // keyed by string(token hash)
	agents    []agentRecord
	audit     []storage.AuditEntry
	nextAudit int64
}

var _ storage.Store = (*Store)(nil)

// New returns an empty Store.
func New() *Store {
	return &Store{sessions: map[string]session{}, results: map[string]storage.ScanResult{}, nextAudit: 1}
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("memory store: crypto/rand failed: %v", err))
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func ptr[T any](v T) *T { return &v }

// --- accounts and tenancy ---------------------------------------------------

func (s *Store) CreateAccount(_ context.Context, in storage.NewAccount) (storage.User, storage.Organization, error) {
	if err := in.Validate(); err != nil {
		return storage.User{}, storage.Organization{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if in.OnlyIfNoUsers && len(s.users) > 0 {
		return storage.User{}, storage.Organization{}, storage.ErrSignupClosed
	}
	for _, u := range s.users {
		if u.Email == in.Email {
			return storage.User{}, storage.Organization{}, storage.ErrConflict
		}
	}
	if s.slugTaken(in.OrgSlug) {
		return storage.User{}, storage.Organization{}, storage.ErrConflict
	}

	now := time.Now().UTC()
	user := storage.User{ID: newID(), Email: in.Email, DisplayName: in.DisplayName, PasswordHash: in.PasswordHash, CreatedAt: now}
	s.users = append(s.users, user)
	org := s.addOrg(user.ID, in.OrgName, in.OrgSlug, now)
	return user, org, nil
}

func (s *Store) CreateOrganizationFor(_ context.Context, userID string, in storage.NewOrganization) (storage.Organization, error) {
	if err := in.Validate(); err != nil {
		return storage.Organization{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.userExists(userID) {
		return storage.Organization{}, storage.ErrNotFound
	}
	if s.slugTaken(in.Slug) {
		return storage.Organization{}, storage.ErrConflict
	}
	return s.addOrg(userID, in.Name, in.Slug, time.Now().UTC()), nil
}

// addOrg appends an organization and its owner membership. Caller holds s.mu.
func (s *Store) addOrg(ownerID, name, slug string, now time.Time) storage.Organization {
	org := storage.Organization{ID: newID(), Name: name, Slug: slug, CreatedAt: now, UpdatedAt: now}
	s.orgs = append(s.orgs, org)
	s.members = append(s.members, storage.Membership{OrganizationID: org.ID, UserID: ownerID, Role: storage.RoleOwner, CreatedAt: now})
	return org
}

func (s *Store) slugTaken(slug string) bool {
	for _, o := range s.orgs {
		if o.Slug == slug {
			return true
		}
	}
	return false
}

func (s *Store) userExists(id string) bool {
	for _, u := range s.users {
		if u.ID == id {
			return true
		}
	}
	return false
}

func (s *Store) GetOrganization(_ context.Context, id string) (storage.Organization, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.org(id)
}

func (s *Store) org(id string) (storage.Organization, error) {
	for _, o := range s.orgs {
		if o.ID == id {
			return o, nil
		}
	}
	return storage.Organization{}, storage.ErrNotFound
}

func (s *Store) ListOrganizationsFor(_ context.Context, userID string) ([]storage.OrgMembership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []storage.OrgMembership
	for _, o := range s.orgs { // s.orgs is in creation order, matching the SQL ORDER BY
		for _, m := range s.members {
			if m.OrganizationID == o.ID && m.UserID == userID && len(out) < storage.ListLimit {
				out = append(out, storage.OrgMembership{Organization: o, Role: m.Role})
			}
		}
	}
	return out, nil
}

func (s *Store) GetMembership(_ context.Context, orgID, userID string) (storage.Membership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, m := range s.members {
		if m.OrganizationID == orgID && m.UserID == userID {
			return m, nil
		}
	}
	return storage.Membership{}, storage.ErrNotFound
}

func (s *Store) CountUsers(context.Context) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users), nil
}

func (s *Store) GetUserByEmail(_ context.Context, email string) (storage.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if u.Email == email {
			return u, nil
		}
	}
	return storage.User{}, storage.ErrNotFound
}

// --- sessions ---------------------------------------------------------------

func (s *Store) CreateSession(_ context.Context, userID string, tokenHash []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.userExists(userID) {
		return storage.ErrNotFound
	}
	if _, dup := s.sessions[string(tokenHash)]; dup {
		return storage.ErrConflict
	}
	s.sessions[string(tokenHash)] = session{userID: userID, expiresAt: expiresAt}
	return nil
}

func (s *Store) UserBySession(_ context.Context, tokenHash []byte, now time.Time) (storage.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sess, ok := s.sessions[string(tokenHash)]
	if !ok || sess.revokedAt != nil || !sess.expiresAt.After(now) {
		return storage.User{}, storage.ErrNotFound
	}
	for _, u := range s.users {
		if u.ID == sess.userID && u.DisabledAt == nil {
			return u, nil
		}
	}
	return storage.User{}, storage.ErrNotFound
}

func (s *Store) RevokeSession(_ context.Context, tokenHash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sess, ok := s.sessions[string(tokenHash)]; ok && sess.revokedAt == nil {
		sess.revokedAt = ptr(time.Now().UTC())
		s.sessions[string(tokenHash)] = sess
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var n int64
	for k, sess := range s.sessions {
		if sess.expiresAt.Before(before) || (sess.revokedAt != nil && sess.revokedAt.Before(before)) {
			delete(s.sessions, k)
			n++
		}
	}
	return n, nil
}

// --- clusters ---------------------------------------------------------------

func (s *Store) CreateCluster(_ context.Context, orgID string, in storage.NewCluster) (storage.Cluster, error) {
	if err := in.Validate(); err != nil {
		return storage.Cluster{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.org(orgID); err != nil {
		return storage.Cluster{}, err
	}
	for _, c := range s.clusters {
		if c.OrganizationID == orgID && c.Name == in.Name {
			return storage.Cluster{}, storage.ErrConflict
		}
	}
	now := time.Now().UTC()
	cluster := storage.Cluster{
		ID: newID(), OrganizationID: orgID, Name: in.Name, Provider: in.Provider,
		Status: storage.ClusterPending, CreatedAt: now, UpdatedAt: now,
	}
	s.clusters = append(s.clusters, cluster)
	return cluster, nil
}

func (s *Store) GetCluster(_ context.Context, orgID, clusterID string) (storage.Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cluster(orgID, clusterID)
}

func (s *Store) cluster(orgID, clusterID string) (storage.Cluster, error) {
	for _, c := range s.clusters {
		if c.ID == clusterID && c.OrganizationID == orgID {
			return c, nil
		}
	}
	return storage.Cluster{}, storage.ErrNotFound
}

func (s *Store) ListClusters(_ context.Context, orgID string) ([]storage.Cluster, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []storage.Cluster
	for _, c := range s.clusters {
		if c.OrganizationID == orgID && len(out) < storage.ListLimit {
			out = append(out, c)
		}
	}
	return out, nil
}

// --- scans ------------------------------------------------------------------

func (s *Store) CreateScanJob(_ context.Context, orgID, clusterID, requestedBy string) (storage.ScanJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.cluster(orgID, clusterID); err != nil {
		return storage.ScanJob{}, err
	}
	job := storage.ScanJob{
		ID: newID(), OrganizationID: orgID, ClusterID: clusterID,
		Status: storage.ScanQueued, CreatedAt: time.Now().UTC(),
	}
	if requestedBy != "" {
		job.RequestedBy = ptr(requestedBy)
	}
	s.scans = append(s.scans, job)
	return job, nil
}

func (s *Store) ClaimNextScanJob(_ context.Context, orgID, clusterID string) (storage.ScanJob, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.cluster(orgID, clusterID); err != nil {
		return storage.ScanJob{}, err
	}
	for i := range s.scans {
		job := &s.scans[i]
		if job.OrganizationID == orgID && job.ClusterID == clusterID && job.Status == storage.ScanQueued {
			now := time.Now().UTC()
			job.Status = storage.ScanRunning
			job.StartedAt = &now
			return *job, nil
		}
	}
	return storage.ScanJob{}, storage.ErrNoWork
}

func (s *Store) CompleteScanJob(_ context.Context, orgID, clusterID, scanID string, findings, summary json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.scans {
		j := &s.scans[i]
		if j.ID == scanID && j.OrganizationID == orgID && j.ClusterID == clusterID && j.Status == storage.ScanRunning {
			now := time.Now().UTC()
			j.Status, j.FinishedAt, j.Error = storage.ScanSucceeded, &now, nil
			s.results[scanID] = storage.ScanResult{ScanJobID: scanID, Findings: append(json.RawMessage(nil), findings...), Summary: append(json.RawMessage(nil), summary...), CreatedAt: now}
			for k := range s.clusters {
				if s.clusters[k].ID == clusterID && s.clusters[k].OrganizationID == orgID {
					s.clusters[k].Status = storage.ClusterConnected
					s.clusters[k].LastSeenAt = &now
				}
			}
			return nil
		}
	}
	return storage.ErrNotFound
}

func (s *Store) FailScanJob(_ context.Context, orgID, clusterID, scanID, message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.scans {
		j := &s.scans[i]
		if j.ID == scanID && j.OrganizationID == orgID && j.ClusterID == clusterID && j.Status == storage.ScanRunning {
			now := time.Now().UTC()
			j.Status, j.FinishedAt, j.Error = storage.ScanFailed, &now, ptr(message)
			return nil
		}
	}
	return storage.ErrNotFound
}

func (s *Store) GetScanResult(_ context.Context, orgID, scanID string) (storage.ScanResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, j := range s.scans {
		if j.ID == scanID && j.OrganizationID == orgID {
			r, ok := s.results[scanID]
			if !ok {
				return storage.ScanResult{}, storage.ErrNotFound
			}
			return r, nil
		}
	}
	return storage.ScanResult{}, storage.ErrNotFound
}

func (s *Store) RequeueStaleScanJobs(_ context.Context, before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var count int64
	for i := range s.scans {
		j := &s.scans[i]
		if j.Status == storage.ScanRunning && j.StartedAt != nil && j.StartedAt.Before(before) {
			j.Status = storage.ScanQueued
			j.StartedAt = nil
			j.Error = nil
			count++
		}
	}
	return count, nil
}

func (s *Store) GetScanJob(_ context.Context, orgID, scanID string) (storage.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, j := range s.scans {
		if j.ID == scanID && j.OrganizationID == orgID {
			return j, nil
		}
	}
	return storage.ScanJob{}, storage.ErrNotFound
}

func (s *Store) ListScanJobs(_ context.Context, orgID, clusterID string) ([]storage.ScanJob, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []storage.ScanJob
	// Walk backwards so the newest scan comes first, matching the SQL ordering.
	for i := len(s.scans) - 1; i >= 0 && len(out) < storage.ListLimit; i-- {
		j := s.scans[i]
		if j.OrganizationID == orgID && j.ClusterID == clusterID {
			out = append(out, j)
		}
	}
	return out, nil
}

// --- agent credentials ------------------------------------------------------

func (s *Store) CreateAgentCredential(_ context.Context, orgID, clusterID, tokenPrefix string, tokenHash []byte) (storage.AgentCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.cluster(orgID, clusterID); err != nil {
		return storage.AgentCredential{}, err
	}
	for _, a := range s.agents {
		if a.hash == string(tokenHash) {
			return storage.AgentCredential{}, storage.ErrConflict
		}
	}
	cred := storage.AgentCredential{ID: newID(), ClusterID: clusterID, TokenPrefix: tokenPrefix, CreatedAt: time.Now().UTC()}
	s.agents = append(s.agents, agentRecord{cred: cred, hash: string(tokenHash), org: orgID})
	return cred, nil
}

func (s *Store) ListAgentCredentials(_ context.Context, orgID, clusterID string) ([]storage.AgentCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []storage.AgentCredential
	for i := len(s.agents) - 1; i >= 0 && len(out) < storage.ListLimit; i-- {
		a := s.agents[i]
		if a.org == orgID && a.cred.ClusterID == clusterID {
			out = append(out, a.cred)
		}
	}
	return out, nil
}

func (s *Store) RevokeAgentCredential(_ context.Context, orgID, clusterID, credentialID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, a := range s.agents {
		if a.cred.ID == credentialID && a.cred.ClusterID == clusterID && a.org == orgID {
			if a.cred.RevokedAt == nil {
				s.agents[i].cred.RevokedAt = ptr(time.Now().UTC())
			}
			return nil
		}
	}
	return storage.ErrNotFound
}

func (s *Store) AuthenticateAgent(_ context.Context, tokenHash []byte, now time.Time) (storage.AgentIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, a := range s.agents {
		if a.hash == string(tokenHash) && a.cred.RevokedAt == nil {
			s.agents[i].cred.LastUsedAt = ptr(now.UTC())
			return storage.AgentIdentity{CredentialID: a.cred.ID, ClusterID: a.cred.ClusterID, OrganizationID: a.org}, nil
		}
	}
	return storage.AgentIdentity{}, storage.ErrNotFound
}

// --- audit log --------------------------------------------------------------

func (s *Store) AppendAudit(_ context.Context, e storage.AuditEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e.ID = s.nextAudit
	s.nextAudit++
	e.CreatedAt = time.Now().UTC()
	e.Metadata = cloneMetadata(e.Metadata)
	s.audit = append(s.audit, e)
	return nil
}

func (s *Store) ListAudit(_ context.Context, orgID string) ([]storage.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var out []storage.AuditEntry
	for i := len(s.audit) - 1; i >= 0 && len(out) < storage.ListLimit; i-- {
		e := s.audit[i]
		if e.OrganizationID != nil && *e.OrganizationID == orgID {
			e.Metadata = cloneMetadata(e.Metadata)
			out = append(out, e)
		}
	}
	return out, nil
}

// cloneMetadata returns a non-nil copy so callers can neither alias nor mutate stored entries.
func cloneMetadata(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return maps.Clone(m)
}
