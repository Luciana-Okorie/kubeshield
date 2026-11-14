// Package storage defines KubeShield's domain records and the Store interface
// that persistence backends (in-memory for tests, PostgreSQL for real use) implement.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// ListLimit caps how many rows any list call returns. Pagination comes later.
const ListLimit = 100

var (
	// ErrNotFound means the record does not exist, or belongs to a different organization.
	// The two are deliberately indistinguishable so IDs cannot be probed across tenants.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a uniqueness rule was violated (duplicate slug, duplicate cluster name).
	ErrConflict = errors.New("already exists")
	// ErrLastOwner means the change would leave an organization with no owner.
	ErrLastOwner = errors.New("organization must keep at least one owner")
	// ErrSignupClosed means a bootstrap-only signup lost the race: an account already exists.
	ErrSignupClosed = errors.New("signup is closed")
	// ErrNoWork means an agent has no queued scan jobs for its cluster.
	ErrNoWork = errors.New("no queued scan jobs")
)

// ValidationError describes input that is well-formed JSON but not acceptable.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return e.Field + ": " + e.Message }

// Cluster providers. Provider matters for advisory matching: a GKE bulletin only applies to "gke".
const (
	ProviderGKE         = "gke"
	ProviderEKS         = "eks"
	ProviderAKS         = "aks"
	ProviderKind        = "kind"
	ProviderSelfManaged = "self_managed"
	ProviderUnknown     = "unknown"
)

var providers = []string{ProviderGKE, ProviderEKS, ProviderAKS, ProviderKind, ProviderSelfManaged, ProviderUnknown}

// Cluster connection states.
const (
	ClusterPending      = "pending"
	ClusterConnected    = "connected"
	ClusterDisconnected = "disconnected"
)

// Scan job states.
const (
	ScanQueued    = "queued"
	ScanRunning   = "running"
	ScanSucceeded = "succeeded"
	ScanFailed    = "failed"
	ScanCanceled  = "canceled"
)

var (
	slugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	idRE   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// IsValidID reports whether s is a canonical lowercase UUID, the form every ID takes.
func IsValidID(s string) bool { return idRE.MatchString(s) }

// Organization is a tenant. Every cluster, scan and finding belongs to exactly one.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NewOrganization is the input for creating an Organization.
type NewOrganization struct {
	Name string
	Slug string
}

// Validate trims the name in place and checks every field.
func (n *NewOrganization) Validate() error {
	name, err := validName("name", n.Name)
	if err != nil {
		return err
	}
	n.Name = name
	if !slugRE.MatchString(n.Slug) {
		return &ValidationError{"slug", "must be 1-63 characters: lowercase letters, digits and hyphens, starting and ending with a letter or digit"}
	}
	return nil
}

// Cluster is a registered Kubernetes cluster.
type Cluster struct {
	ID                string     `json:"id"`
	OrganizationID    string     `json:"organization_id"`
	Name              string     `json:"name"`
	Provider          string     `json:"provider"`
	KubernetesVersion *string    `json:"kubernetes_version"`
	Status            string     `json:"status"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// NewCluster is the input for registering a Cluster.
type NewCluster struct {
	Name     string
	Provider string
}

// Validate trims the name in place and checks every field.
func (n *NewCluster) Validate() error {
	name, err := validName("name", n.Name)
	if err != nil {
		return err
	}
	n.Name = name
	for _, p := range providers {
		if n.Provider == p {
			return nil
		}
	}
	return &ValidationError{"provider", fmt.Sprintf("must be one of: %s", strings.Join(providers, ", "))}
}

// ScanJob is one request to scan a cluster, and its outcome.
type ScanResult struct {
	ScanJobID string          `json:"scan_job_id"`
	Findings  json.RawMessage `json:"findings"`
	Summary   json.RawMessage `json:"summary"`
	CreatedAt time.Time       `json:"created_at"`
}

type ScanJob struct {
	ID             string     `json:"id"`
	OrganizationID string     `json:"organization_id"`
	ClusterID      string     `json:"cluster_id"`
	Status         string     `json:"status"`
	RequestedBy    *string    `json:"requested_by"`
	Error          *string    `json:"error"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
}

func validName(field, v string) (string, error) {
	v = strings.TrimSpace(v)
	if n := utf8.RuneCountInString(v); n < 1 || n > 120 {
		return "", &ValidationError{field, "must be between 1 and 120 characters"}
	}
	return v, nil
}

// Store is everything the API needs from persistence. Every method that takes an
// organization ID scopes its query to that organization, so a record from another
// tenant is reported as ErrNotFound rather than returned.
type Store interface {
	// Accounts and tenancy.

	// CreateAccount creates a user, a new organization and the user's owner membership
	// in one transaction. ErrConflict means the email or organization slug is taken.
	CreateAccount(ctx context.Context, in NewAccount) (User, Organization, error)
	// CreateOrganizationFor creates an organization owned by an existing user.
	CreateOrganizationFor(ctx context.Context, userID string, in NewOrganization) (Organization, error)
	GetOrganization(ctx context.Context, id string) (Organization, error)
	// ListOrganizationsFor returns the organizations a user belongs to, with their role in each.
	ListOrganizationsFor(ctx context.Context, userID string) ([]OrgMembership, error)
	// GetMembership returns ErrNotFound when the user is not a member of the organization.
	GetMembership(ctx context.Context, orgID, userID string) (Membership, error)
	// ListMembers returns everyone in the organization with their role, oldest first.
	ListMembers(ctx context.Context, orgID string) ([]Member, error)
	// AddMember gives an existing user a role. ErrNotFound if the organization or user is missing,
	// ErrConflict if they are already a member.
	AddMember(ctx context.Context, orgID, userID string, role Role) (Membership, error)
	// SetMemberRole changes a member's role. ErrNotFound if they are not a member,
	// ErrLastOwner if it would leave the organization without an owner.
	SetMemberRole(ctx context.Context, orgID, userID string, role Role) error
	// RemoveMember removes a member. Same errors as SetMemberRole.
	RemoveMember(ctx context.Context, orgID, userID string) error
	CountUsers(ctx context.Context) (int, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)

	// Sessions. Tokens are passed as SHA-256 hashes; the store never sees a secret.

	CreateSession(ctx context.Context, userID string, tokenHash []byte, expiresAt time.Time) error
	// UserBySession returns the user for a live session: not revoked, not expired at
	// now, and the user not disabled. Anything else is ErrNotFound.
	UserBySession(ctx context.Context, tokenHash []byte, now time.Time) (User, error)
	// RevokeSession is idempotent: revoking an unknown or already revoked session is not an error.
	RevokeSession(ctx context.Context, tokenHash []byte) error
	// DeleteExpiredSessions removes sessions that expired, or were revoked, before the cutoff.
	DeleteExpiredSessions(ctx context.Context, before time.Time) (int64, error)

	// Clusters and scans.

	CreateCluster(ctx context.Context, orgID string, in NewCluster) (Cluster, error)
	GetCluster(ctx context.Context, orgID, clusterID string) (Cluster, error)
	ListClusters(ctx context.Context, orgID string) ([]Cluster, error)

	// CreateScanJob queues a scan for a cluster of the given organization, recording who asked.
	CreateScanJob(ctx context.Context, orgID, clusterID, requestedBy string) (ScanJob, error)
	// ClaimNextScanJob atomically claims the oldest queued job for the authenticated agent cluster.
	ClaimNextScanJob(ctx context.Context, orgID, clusterID string) (ScanJob, error)
	// CompleteScanJob stores the agent result and atomically marks the running job succeeded.
	CompleteScanJob(ctx context.Context, orgID, clusterID, scanID string, findings, summary json.RawMessage) error
	// FailScanJob marks a running job failed with a bounded diagnostic.
	FailScanJob(ctx context.Context, orgID, clusterID, scanID, message string) error
	GetScanResult(ctx context.Context, orgID, scanID string) (ScanResult, error)
	// RequeueStaleScanJobs returns abandoned running jobs to queued after their execution lease expires.
	RequeueStaleScanJobs(ctx context.Context, before time.Time) (int64, error)
	GetScanJob(ctx context.Context, orgID, scanID string) (ScanJob, error)
	// ListScanJobs returns a cluster's scans, newest first.
	ListScanJobs(ctx context.Context, orgID, clusterID string) ([]ScanJob, error)

	// Agent credentials. Tokens are passed as SHA-256 hashes.

	CreateAgentCredential(ctx context.Context, orgID, clusterID, tokenPrefix string, tokenHash []byte) (AgentCredential, error)
	ListAgentCredentials(ctx context.Context, orgID, clusterID string) ([]AgentCredential, error)
	// RevokeAgentCredential is idempotent for an existing credential.
	RevokeAgentCredential(ctx context.Context, orgID, clusterID, credentialID string) error
	// AuthenticateAgent resolves a live (unrevoked) agent token and records its use at now.
	AuthenticateAgent(ctx context.Context, tokenHash []byte, now time.Time) (AgentIdentity, error)

	// Audit log.

	AppendAudit(ctx context.Context, e AuditEntry) error
	// ListAudit returns an organization's audit entries, newest first.
	ListAudit(ctx context.Context, orgID string) ([]AuditEntry, error)
}
