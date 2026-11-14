package storage

import (
	"net"
	"net/mail"
	"strings"
	"time"
)

// maxEmailLength is the practical limit from RFC 5321.
const maxEmailLength = 254

// User is a person who can sign in.
type User struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	// PasswordHash never leaves the server: it has no JSON representation.
	PasswordHash string     `json:"-"`
	DisabledAt   *time.Time `json:"-"`
	CreatedAt    time.Time  `json:"created_at"`
}

// NewAccount is the input for signing up: a user plus the organization they will own.
// PasswordHash must already be hashed; the store never sees a plaintext password.
type NewAccount struct {
	Email        string
	DisplayName  string
	PasswordHash string
	OrgName      string
	OrgSlug      string

	// OnlyIfNoUsers makes creation atomic with "no accounts exist yet", so two simultaneous
	// bootstrap signups cannot both succeed. The store returns ErrSignupClosed if it loses.
	OnlyIfNoUsers bool
}

// Validate normalises Email (trimmed, lowercased) and DisplayName in place and checks every field.
func (n *NewAccount) Validate() error {
	email, err := NormalizeEmail(n.Email)
	if err != nil {
		return err
	}
	n.Email = email

	name, err := validName("display_name", n.DisplayName)
	if err != nil {
		return err
	}
	n.DisplayName = name

	if n.PasswordHash == "" {
		return &ValidationError{"password", "is required"}
	}

	org := NewOrganization{Name: n.OrgName, Slug: n.OrgSlug}
	if err := org.Validate(); err != nil {
		if ve, ok := err.(*ValidationError); ok {
			ve.Field = "organization_" + ve.Field
		}
		return err
	}
	n.OrgName = org.Name
	return nil
}

// NormalizeEmail trims and lowercases an address and checks it is a plain
// "local@domain" address (no display name, no angle brackets).
func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	if email == "" || len(email) > maxEmailLength {
		return "", &ValidationError{"email", "must be a valid email address"}
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", &ValidationError{"email", "must be a valid email address"}
	}
	return email, nil
}

// Membership ties a user to an organization with a role.
type Membership struct {
	OrganizationID string    `json:"organization_id"`
	UserID         string    `json:"user_id"`
	Role           Role      `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
}

// Member is a person in an organization, as listed to the people who manage it.
type Member struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Role        Role      `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

// OrgMembership is an organization as seen by one of its members.
type OrgMembership struct {
	Organization
	Role Role `json:"role"`
}

// AgentCredential is the stored, non-secret side of an agent token.
type AgentCredential struct {
	ID          string     `json:"id"`
	ClusterID   string     `json:"cluster_id"`
	TokenPrefix string     `json:"token_prefix"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
}

// AgentIdentity is who an authenticated agent token speaks for.
type AgentIdentity struct {
	CredentialID   string
	ClusterID      string
	OrganizationID string
}

// Actor types recorded in the audit log.
const (
	ActorUser   = "user"
	ActorAgent  = "agent"
	ActorSystem = "system"
)

// Validate checks the fields the audit_logs table constrains.
func (e AuditEntry) Validate() error {
	switch e.ActorType {
	case ActorUser, ActorAgent, ActorSystem:
	default:
		return &ValidationError{"actor_type", "must be user, agent or system"}
	}
	if strings.TrimSpace(e.Action) == "" {
		return &ValidationError{"action", "is required"}
	}
	if e.IP != "" && net.ParseIP(e.IP) == nil {
		return &ValidationError{"ip", "must be an IP address"}
	}
	return nil
}

// AuditEntry is one append-only record of a sensitive action.
// Metadata must never contain secrets (passwords, tokens, hashes).
type AuditEntry struct {
	ID             int64          `json:"id"`
	OrganizationID *string        `json:"organization_id"`
	ActorUserID    *string        `json:"actor_user_id"`
	ActorType      string         `json:"actor_type"`
	Action         string         `json:"action"`
	TargetType     string         `json:"target_type,omitempty"`
	TargetID       string         `json:"target_id,omitempty"`
	Metadata       map[string]any `json:"metadata"`
	IP             string         `json:"ip,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}
