// Package postgres implements storage.Store on PostgreSQL using database/sql.
//
// It is driver-agnostic: the caller registers a driver (the project uses
// github.com/jackc/pgx/v5/stdlib) and passes in an open *sql.DB.
package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// Store implements storage.Store.
type Store struct {
	db *sql.DB
}

var _ storage.Store = (*Store)(nil)

// New returns a Store that uses db.
func New(db *sql.DB) *Store { return &Store{db: db} }

const (
	orgColumns     = `id, name, slug, created_at, updated_at`
	userColumns    = `id, email, display_name, password_hash, disabled_at, created_at`
	clusterColumns = `id, organization_id, name, provider, kubernetes_version, status, last_seen_at, created_at, updated_at`
	scanColumns    = `id, organization_id, cluster_id, status, requested_by, error, created_at, started_at, finished_at`
	agentColumns   = `id, cluster_id, token_prefix, created_at, last_used_at, revoked_at`
	auditColumns   = `id, organization_id, actor_user_id, actor_type, action, target_type, target_id, metadata, host(ip), created_at`
)

// Every query on tenant-owned data scopes by organization_id.
const (
	qInsertOrganization = `INSERT INTO organizations (name, slug) VALUES ($1, $2) RETURNING ` + orgColumns
	qGetOrganization    = `SELECT ` + orgColumns + ` FROM organizations WHERE id = $1`

	qInsertUser     = `INSERT INTO users (email, display_name, password_hash) VALUES ($1, $2, $3) RETURNING ` + userColumns
	qInsertOwner    = `INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')`
	qGetMembership  = `SELECT organization_id, user_id, role, created_at FROM memberships WHERE organization_id = $1 AND user_id = $2`
	qListOrgsFor    = `SELECT o.id, o.name, o.slug, o.created_at, o.updated_at, m.role FROM memberships m JOIN organizations o ON o.id = m.organization_id WHERE m.user_id = $1 ORDER BY o.created_at, o.id LIMIT $2`
	qCountUsers     = `SELECT count(*) FROM users`
	qBootstrapLock  = `SELECT pg_advisory_xact_lock($1)`
	qGetUserByEmail = `SELECT ` + userColumns + ` FROM users WHERE email = $1`
	qListMembers    = `SELECT m.user_id, u.email, u.display_name, m.role, m.created_at FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.organization_id = $1 ORDER BY m.created_at, m.user_id LIMIT $2`
	qInsertMember   = `INSERT INTO memberships (organization_id, user_id, role) VALUES ($1, $2, $3) RETURNING organization_id, user_id, role, created_at`
	qUpdateRole     = `UPDATE memberships SET role = $3 WHERE organization_id = $1 AND user_id = $2`
	qDeleteMember   = `DELETE FROM memberships WHERE organization_id = $1 AND user_id = $2`
	qCountOwners    = `SELECT count(*) FROM memberships WHERE organization_id = $1 AND role = 'owner'`
	// Serialises membership changes per organization, so two owners cannot demote each other at once.
	qLockOrg       = `SELECT id FROM organizations WHERE id = $1 FOR UPDATE`
	qInsertSession = `INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`
	qUserBySession = `SELECT u.id, u.email, u.display_name, u.password_hash, u.disabled_at, u.created_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > $2 AND u.disabled_at IS NULL`
	qRevokeSession = `UPDATE sessions SET revoked_at = now() WHERE token_hash = $1 AND revoked_at IS NULL`
	qPurgeSessions = `DELETE FROM sessions WHERE expires_at < $1 OR revoked_at < $1`

	qInsertCluster = `INSERT INTO clusters (organization_id, name, provider) VALUES ($1, $2, $3) RETURNING ` + clusterColumns
	qGetCluster    = `SELECT ` + clusterColumns + ` FROM clusters WHERE id = $1 AND organization_id = $2`
	qListClusters  = `SELECT ` + clusterColumns + ` FROM clusters WHERE organization_id = $1 ORDER BY created_at, id LIMIT $2`

	qInsertScanJob    = `INSERT INTO scan_jobs (organization_id, cluster_id, requested_by) VALUES ($1, $2, $3) RETURNING ` + scanColumns
	qGetScanJob       = `SELECT ` + scanColumns + ` FROM scan_jobs WHERE id = $1 AND organization_id = $2`
	qListScanJobs     = `SELECT ` + scanColumns + ` FROM scan_jobs WHERE cluster_id = $1 AND organization_id = $2 ORDER BY created_at DESC, id LIMIT $3`
	qClaimNextScanJob = `UPDATE scan_jobs SET status = 'running', started_at = now() WHERE id = (SELECT sj.id FROM scan_jobs sj WHERE sj.cluster_id = $1 AND sj.organization_id = $2 AND sj.status = 'queued' ORDER BY sj.created_at, sj.id FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING ` + scanColumns

	// The INSERT ... SELECT only produces a row when the cluster belongs to the organization.
	qInsertAgent = `INSERT INTO agent_credentials (cluster_id, token_prefix, token_hash) SELECT id, $3, $4 FROM clusters WHERE id = $1 AND organization_id = $2 RETURNING ` + agentColumns
	qListAgents  = `SELECT ac.id, ac.cluster_id, ac.token_prefix, ac.created_at, ac.last_used_at, ac.revoked_at FROM agent_credentials ac JOIN clusters c ON c.id = ac.cluster_id WHERE ac.cluster_id = $1 AND c.organization_id = $2 ORDER BY ac.created_at DESC, ac.id LIMIT $3`
	// COALESCE keeps the original revocation time, which makes revoking idempotent.
	qRevokeAgent = `UPDATE agent_credentials ac SET revoked_at = COALESCE(ac.revoked_at, now()) FROM clusters c WHERE ac.id = $1 AND ac.cluster_id = $2 AND c.id = ac.cluster_id AND c.organization_id = $3 RETURNING ac.id`
	qAuthAgent   = `UPDATE agent_credentials ac SET last_used_at = $2 FROM clusters c WHERE ac.token_hash = $1 AND ac.revoked_at IS NULL AND c.id = ac.cluster_id RETURNING ac.id, c.id, c.organization_id`

	qInsertAudit = `INSERT INTO audit_logs (organization_id, actor_user_id, actor_type, action, target_type, target_id, metadata, ip) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::inet)`
	qListAudit   = `SELECT ` + auditColumns + ` FROM audit_logs WHERE organization_id = $1 ORDER BY id DESC LIMIT $2`
)

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func utc(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	u := t.Time.UTC()
	return &u
}

func strPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	return &s.String
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

func nullStringPtr(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return nullString(*s)
}

func scanOrganization(r rowScanner) (storage.Organization, error) {
	var o storage.Organization
	if err := r.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
		return storage.Organization{}, err
	}
	o.CreatedAt, o.UpdatedAt = o.CreatedAt.UTC(), o.UpdatedAt.UTC()
	return o, nil
}

func scanOrgMembership(r rowScanner) (storage.OrgMembership, error) {
	var m storage.OrgMembership
	if err := r.Scan(&m.ID, &m.Name, &m.Slug, &m.CreatedAt, &m.UpdatedAt, &m.Role); err != nil {
		return storage.OrgMembership{}, err
	}
	m.CreatedAt, m.UpdatedAt = m.CreatedAt.UTC(), m.UpdatedAt.UTC()
	return m, nil
}

func scanUser(r rowScanner) (storage.User, error) {
	var (
		u        storage.User
		hash     sql.NullString
		disabled sql.NullTime
	)
	if err := r.Scan(&u.ID, &u.Email, &u.DisplayName, &hash, &disabled, &u.CreatedAt); err != nil {
		return storage.User{}, err
	}
	u.PasswordHash = hash.String // empty when NULL: no password set, so no password can match
	u.DisabledAt = utc(disabled)
	u.CreatedAt = u.CreatedAt.UTC()
	return u, nil
}

func scanMembership(r rowScanner) (storage.Membership, error) {
	var m storage.Membership
	if err := r.Scan(&m.OrganizationID, &m.UserID, &m.Role, &m.CreatedAt); err != nil {
		return storage.Membership{}, err
	}
	m.CreatedAt = m.CreatedAt.UTC()
	return m, nil
}

func scanCluster(r rowScanner) (storage.Cluster, error) {
	var (
		c        storage.Cluster
		version  sql.NullString
		lastSeen sql.NullTime
	)
	if err := r.Scan(&c.ID, &c.OrganizationID, &c.Name, &c.Provider, &version, &c.Status, &lastSeen, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return storage.Cluster{}, err
	}
	c.KubernetesVersion = strPtr(version)
	c.LastSeenAt = utc(lastSeen)
	c.CreatedAt, c.UpdatedAt = c.CreatedAt.UTC(), c.UpdatedAt.UTC()
	return c, nil
}

func scanScanJob(r rowScanner) (storage.ScanJob, error) {
	var (
		j           storage.ScanJob
		requestedBy sql.NullString
		errText     sql.NullString
		started     sql.NullTime
		finished    sql.NullTime
	)
	if err := r.Scan(&j.ID, &j.OrganizationID, &j.ClusterID, &j.Status, &requestedBy, &errText, &j.CreatedAt, &started, &finished); err != nil {
		return storage.ScanJob{}, err
	}
	j.RequestedBy = strPtr(requestedBy)
	j.Error = strPtr(errText)
	j.StartedAt = utc(started)
	j.FinishedAt = utc(finished)
	j.CreatedAt = j.CreatedAt.UTC()
	return j, nil
}

func scanAgent(r rowScanner) (storage.AgentCredential, error) {
	var (
		a        storage.AgentCredential
		lastUsed sql.NullTime
		revoked  sql.NullTime
	)
	if err := r.Scan(&a.ID, &a.ClusterID, &a.TokenPrefix, &a.CreatedAt, &lastUsed, &revoked); err != nil {
		return storage.AgentCredential{}, err
	}
	a.LastUsedAt = utc(lastUsed)
	a.RevokedAt = utc(revoked)
	a.CreatedAt = a.CreatedAt.UTC()
	return a, nil
}

func scanAudit(r rowScanner) (storage.AuditEntry, error) {
	var (
		e                      storage.AuditEntry
		org, actor, tType, tID sql.NullString
		ip                     sql.NullString
		metadata               []byte
	)
	if err := r.Scan(&e.ID, &org, &actor, &e.ActorType, &e.Action, &tType, &tID, &metadata, &ip, &e.CreatedAt); err != nil {
		return storage.AuditEntry{}, err
	}
	e.OrganizationID = strPtr(org)
	e.ActorUserID = strPtr(actor)
	e.TargetType, e.TargetID, e.IP = tType.String, tID.String, ip.String
	e.CreatedAt = e.CreatedAt.UTC()
	e.Metadata = map[string]any{}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &e.Metadata); err != nil {
			return storage.AuditEntry{}, fmt.Errorf("decode audit metadata: %w", err)
		}
	}
	return e, nil
}

// bootstrapLockKey is an arbitrary constant for pg_advisory_xact_lock. It differs from the
// migration lock's key so the two never block each other.
const bootstrapLockKey int64 = 0x4b53_0002

func scanMember(r rowScanner) (storage.Member, error) {
	var m storage.Member
	if err := r.Scan(&m.UserID, &m.Email, &m.DisplayName, &m.Role, &m.CreatedAt); err != nil {
		return storage.Member{}, err
	}
	m.CreatedAt = m.CreatedAt.UTC()
	return m, nil
}

// mapError turns database errors into the storage package's sentinels.
// SQLSTATE codes are read through an interface so this file needs no driver import;
// pgx's *pgconn.PgError provides SQLState().
func mapError(op string, err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ErrNotFound
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		switch pgErr.SQLState() {
		case "23505": // unique_violation
			return storage.ErrConflict
		case "23503": // foreign_key_violation: the parent organization, cluster or user does not exist (or is another tenant's)
			return storage.ErrNotFound
		case "22P02": // invalid_text_representation: not a UUID, so it cannot exist
			return storage.ErrNotFound
		}
	}
	return fmt.Errorf("%s: %w", op, err)
}

// inTx runs fn in a transaction, committing only if fn returns nil.
func (s *Store) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once committed
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// --- accounts and tenancy ---------------------------------------------------

func (s *Store) CreateAccount(ctx context.Context, in storage.NewAccount) (storage.User, storage.Organization, error) {
	if err := in.Validate(); err != nil {
		return storage.User{}, storage.Organization{}, err
	}
	var (
		user storage.User
		org  storage.Organization
	)
	err := s.inTx(ctx, func(tx *sql.Tx) (err error) {
		if in.OnlyIfNoUsers {
			// The lock is held until commit, so a concurrent bootstrap signup waits here and
			// then sees the first account.
			if _, err = tx.ExecContext(ctx, qBootstrapLock, bootstrapLockKey); err != nil {
				return err
			}
			var n int
			if err = tx.QueryRowContext(ctx, qCountUsers).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return storage.ErrSignupClosed
			}
		}
		if user, err = scanUser(tx.QueryRowContext(ctx, qInsertUser, in.Email, in.DisplayName, in.PasswordHash)); err != nil {
			return err
		}
		if org, err = scanOrganization(tx.QueryRowContext(ctx, qInsertOrganization, in.OrgName, in.OrgSlug)); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, qInsertOwner, org.ID, user.ID)
		return err
	})
	if err != nil {
		if errors.Is(err, storage.ErrSignupClosed) {
			return storage.User{}, storage.Organization{}, err
		}
		return storage.User{}, storage.Organization{}, mapError("create account", err)
	}
	return user, org, nil
}

func (s *Store) CreateOrganizationFor(ctx context.Context, userID string, in storage.NewOrganization) (storage.Organization, error) {
	if err := in.Validate(); err != nil {
		return storage.Organization{}, err
	}
	var org storage.Organization
	err := s.inTx(ctx, func(tx *sql.Tx) (err error) {
		if org, err = scanOrganization(tx.QueryRowContext(ctx, qInsertOrganization, in.Name, in.Slug)); err != nil {
			return err
		}
		// A missing user fails the membership foreign key, which rolls the organization back too.
		_, err = tx.ExecContext(ctx, qInsertOwner, org.ID, userID)
		return err
	})
	if err != nil {
		return storage.Organization{}, mapError("create organization", err)
	}
	return org, nil
}

func (s *Store) GetOrganization(ctx context.Context, id string) (storage.Organization, error) {
	o, err := scanOrganization(s.db.QueryRowContext(ctx, qGetOrganization, id))
	if err != nil {
		return storage.Organization{}, mapError("get organization", err)
	}
	return o, nil
}

func (s *Store) ListOrganizationsFor(ctx context.Context, userID string) ([]storage.OrgMembership, error) {
	return queryList(ctx, s.db, "list organizations", scanOrgMembership, qListOrgsFor, userID, storage.ListLimit)
}

func (s *Store) GetMembership(ctx context.Context, orgID, userID string) (storage.Membership, error) {
	m, err := scanMembership(s.db.QueryRowContext(ctx, qGetMembership, orgID, userID))
	if err != nil {
		return storage.Membership{}, mapError("get membership", err)
	}
	return m, nil
}

func (s *Store) ListMembers(ctx context.Context, orgID string) ([]storage.Member, error) {
	if _, err := s.GetOrganization(ctx, orgID); err != nil {
		return nil, err
	}
	return queryList(ctx, s.db, "list members", scanMember, qListMembers, orgID, storage.ListLimit)
}

func (s *Store) AddMember(ctx context.Context, orgID, userID string, role storage.Role) (storage.Membership, error) {
	if !role.Valid() {
		return storage.Membership{}, &storage.ValidationError{Field: "role", Message: "must be owner, admin, member or viewer"}
	}
	m, err := scanMembership(s.db.QueryRowContext(ctx, qInsertMember, orgID, userID, string(role)))
	if err != nil {
		return storage.Membership{}, mapError("add member", err)
	}
	return m, nil
}

func (s *Store) SetMemberRole(ctx context.Context, orgID, userID string, role storage.Role) error {
	if !role.Valid() {
		return &storage.ValidationError{Field: "role", Message: "must be owner, admin, member or viewer"}
	}
	return s.changeMembership(ctx, "set member role", orgID, userID, role != storage.RoleOwner, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, qUpdateRole, orgID, userID, string(role))
		return err
	})
}

func (s *Store) RemoveMember(ctx context.Context, orgID, userID string) error {
	return s.changeMembership(ctx, "remove member", orgID, userID, true, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, qDeleteMember, orgID, userID)
		return err
	})
}

// changeMembership runs a role change or removal under a lock on the organization row.
// If the member is currently an owner and losesOwnership is true, it refuses to remove the last one.
func (s *Store) changeMembership(ctx context.Context, op, orgID, userID string, losesOwnership bool, apply func(tx *sql.Tx) error) error {
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var locked string
		if err := tx.QueryRowContext(ctx, qLockOrg, orgID).Scan(&locked); err != nil {
			return err
		}
		current, err := scanMembership(tx.QueryRowContext(ctx, qGetMembership, orgID, userID))
		if err != nil {
			return err
		}
		if current.Role == storage.RoleOwner && losesOwnership {
			var owners int
			if err := tx.QueryRowContext(ctx, qCountOwners, orgID).Scan(&owners); err != nil {
				return err
			}
			if owners <= 1 {
				return storage.ErrLastOwner
			}
		}
		return apply(tx)
	})
	if errors.Is(err, storage.ErrLastOwner) {
		return err
	}
	if err != nil {
		return mapError(op, err)
	}
	return nil
}

func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, qCountUsers).Scan(&n); err != nil {
		return 0, mapError("count users", err)
	}
	return n, nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (storage.User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	u, err := scanUser(s.db.QueryRowContext(ctx, qGetUserByEmail, email))
	if err != nil {
		return storage.User{}, mapError("get user", err)
	}
	return u, nil
}

// --- sessions ---------------------------------------------------------------

func (s *Store) CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time) error {
	if _, err := s.db.ExecContext(ctx, qInsertSession, userID, tokenHash, expiresAt); err != nil {
		return mapError("create session", err)
	}
	return nil
}

func (s *Store) UserBySession(ctx context.Context, tokenHash []byte, now time.Time) (storage.User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, qUserBySession, tokenHash, now))
	if err != nil {
		return storage.User{}, mapError("find session", err)
	}
	return u, nil
}

func (s *Store) RevokeSession(ctx context.Context, tokenHash []byte) error {
	if _, err := s.db.ExecContext(ctx, qRevokeSession, tokenHash); err != nil {
		return mapError("revoke session", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, qPurgeSessions, before)
	if err != nil {
		return 0, mapError("purge sessions", err)
	}
	return res.RowsAffected()
}

// --- clusters ---------------------------------------------------------------

func (s *Store) CreateCluster(ctx context.Context, orgID string, in storage.NewCluster) (storage.Cluster, error) {
	if err := in.Validate(); err != nil {
		return storage.Cluster{}, err
	}
	c, err := scanCluster(s.db.QueryRowContext(ctx, qInsertCluster, orgID, in.Name, in.Provider))
	if err != nil {
		return storage.Cluster{}, mapError("create cluster", err)
	}
	return c, nil
}

func (s *Store) GetCluster(ctx context.Context, orgID, clusterID string) (storage.Cluster, error) {
	c, err := scanCluster(s.db.QueryRowContext(ctx, qGetCluster, clusterID, orgID))
	if err != nil {
		return storage.Cluster{}, mapError("get cluster", err)
	}
	return c, nil
}

func (s *Store) ListClusters(ctx context.Context, orgID string) ([]storage.Cluster, error) {
	return queryList(ctx, s.db, "list clusters", scanCluster, qListClusters, orgID, storage.ListLimit)
}

// --- scans ------------------------------------------------------------------

func (s *Store) CreateScanJob(ctx context.Context, orgID, clusterID, requestedBy string) (storage.ScanJob, error) {
	j, err := scanScanJob(s.db.QueryRowContext(ctx, qInsertScanJob, orgID, clusterID, nullString(requestedBy)))
	if err != nil {
		return storage.ScanJob{}, mapError("create scan job", err)
	}
	return j, nil
}

func (s *Store) ClaimNextScanJob(ctx context.Context, orgID, clusterID string) (storage.ScanJob, error) {
	j, err := scanScanJob(s.db.QueryRowContext(ctx, qClaimNextScanJob, clusterID, orgID))
	if errors.Is(err, sql.ErrNoRows) {
		return storage.ScanJob{}, storage.ErrNoWork
	}
	if err != nil {
		return storage.ScanJob{}, mapError("claim next scan job", err)
	}
	return j, nil
}

func (s *Store) CompleteScanJob(ctx context.Context, orgID, clusterID, scanID string, findings, summary json.RawMessage) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `INSERT INTO scan_results (scan_job_id, organization_id, cluster_id, findings, summary) SELECT id, organization_id, cluster_id, $4::jsonb, $5::jsonb FROM scan_jobs WHERE id=$1 AND organization_id=$2 AND cluster_id=$3 AND status='running' ON CONFLICT (scan_job_id) DO NOTHING`, scanID, orgID, clusterID, string(findings), string(summary))
	if err != nil {
		return mapError("save scan results", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return storage.ErrNotFound
	}
	res, err = tx.ExecContext(ctx, `UPDATE scan_jobs SET status='succeeded', finished_at=now(), error=NULL WHERE id=$1 AND organization_id=$2 AND cluster_id=$3 AND status='running'`, scanID, orgID, clusterID)
	if err != nil {
		return mapError("complete scan job", err)
	}
	n, _ = res.RowsAffected()
	if n != 1 {
		return storage.ErrNotFound
	}
	if _, err = tx.ExecContext(ctx, `UPDATE clusters SET status='connected', last_seen_at=now() WHERE id=$1 AND organization_id=$2`, clusterID, orgID); err != nil {
		return mapError("update cluster heartbeat", err)
	}
	if err := tx.Commit(); err != nil {
		return mapError("commit scan result", err)
	}
	return nil
}

func (s *Store) FailScanJob(ctx context.Context, orgID, clusterID, scanID, message string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE scan_jobs SET status='failed', error=$4, finished_at=now() WHERE id=$1 AND organization_id=$2 AND cluster_id=$3 AND status='running'`, scanID, orgID, clusterID, message)
	if err != nil {
		return mapError("fail scan job", err)
	}
	n, _ := res.RowsAffected()
	if n != 1 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *Store) RequeueStaleScanJobs(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE scan_jobs SET status='queued', started_at=NULL, error=NULL WHERE status='running' AND started_at < $1`, before)
	if err != nil {
		return 0, mapError("requeue stale scan jobs", err)
	}
	return res.RowsAffected()
}

func (s *Store) GetScanResult(ctx context.Context, orgID, scanID string) (storage.ScanResult, error) {
	var r storage.ScanResult
	var findings, summary []byte
	err := s.db.QueryRowContext(ctx, `SELECT scan_job_id, findings, summary, created_at FROM scan_results WHERE scan_job_id=$1 AND organization_id=$2`, scanID, orgID).Scan(&r.ScanJobID, &findings, &summary, &r.CreatedAt)
	if err != nil {
		return storage.ScanResult{}, mapError("get scan result", err)
	}
	r.Findings, r.Summary, r.CreatedAt = findings, summary, r.CreatedAt.UTC()
	return r, nil
}

func (s *Store) GetScanJob(ctx context.Context, orgID, scanID string) (storage.ScanJob, error) {
	j, err := scanScanJob(s.db.QueryRowContext(ctx, qGetScanJob, scanID, orgID))
	if err != nil {
		return storage.ScanJob{}, mapError("get scan job", err)
	}
	return j, nil
}

func (s *Store) ListScanJobs(ctx context.Context, orgID, clusterID string) ([]storage.ScanJob, error) {
	return queryList(ctx, s.db, "list scan jobs", scanScanJob, qListScanJobs, clusterID, orgID, storage.ListLimit)
}

// --- agent credentials ------------------------------------------------------

func (s *Store) CreateAgentCredential(ctx context.Context, orgID, clusterID, tokenPrefix string, tokenHash []byte) (storage.AgentCredential, error) {
	a, err := scanAgent(s.db.QueryRowContext(ctx, qInsertAgent, clusterID, orgID, tokenPrefix, tokenHash))
	if err != nil {
		return storage.AgentCredential{}, mapError("create agent credential", err)
	}
	return a, nil
}

func (s *Store) ListAgentCredentials(ctx context.Context, orgID, clusterID string) ([]storage.AgentCredential, error) {
	return queryList(ctx, s.db, "list agent credentials", scanAgent, qListAgents, clusterID, orgID, storage.ListLimit)
}

func (s *Store) RevokeAgentCredential(ctx context.Context, orgID, clusterID, credentialID string) error {
	var id string
	if err := s.db.QueryRowContext(ctx, qRevokeAgent, credentialID, clusterID, orgID).Scan(&id); err != nil {
		return mapError("revoke agent credential", err)
	}
	return nil
}

func (s *Store) AuthenticateAgent(ctx context.Context, tokenHash []byte, now time.Time) (storage.AgentIdentity, error) {
	var id storage.AgentIdentity
	if err := s.db.QueryRowContext(ctx, qAuthAgent, tokenHash, now).Scan(&id.CredentialID, &id.ClusterID, &id.OrganizationID); err != nil {
		return storage.AgentIdentity{}, mapError("authenticate agent", err)
	}
	return id, nil
}

// --- audit log --------------------------------------------------------------

func (s *Store) AppendAudit(ctx context.Context, e storage.AuditEntry) error {
	if err := e.Validate(); err != nil {
		return err
	}
	meta := e.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("encode audit metadata: %w", err)
	}
	_, err = s.db.ExecContext(ctx, qInsertAudit,
		nullStringPtr(e.OrganizationID), nullStringPtr(e.ActorUserID), e.ActorType, e.Action,
		nullString(e.TargetType), nullString(e.TargetID), string(body), nullString(e.IP))
	if err != nil {
		return mapError("append audit", err)
	}
	return nil
}

func (s *Store) ListAudit(ctx context.Context, orgID string) ([]storage.AuditEntry, error) {
	return queryList(ctx, s.db, "list audit", scanAudit, qListAudit, orgID, storage.ListLimit)
}

func queryList[T any](ctx context.Context, db *sql.DB, op string, scan func(rowScanner) (T, error), query string, args ...any) ([]T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, mapError(op, err)
	}
	defer rows.Close()

	var out []T
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, mapError(op, err)
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(op, err)
	}
	return out, nil
}
