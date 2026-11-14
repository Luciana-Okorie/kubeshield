package memory

import (
	"context"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

func (s *Store) ListMembers(_ context.Context, orgID string) ([]storage.Member, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if _, err := s.org(orgID); err != nil {
		return nil, err
	}
	var out []storage.Member
	for _, m := range s.members {
		if m.OrganizationID != orgID {
			continue
		}
		for _, u := range s.users {
			if u.ID == m.UserID {
				out = append(out, storage.Member{UserID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Role: m.Role, CreatedAt: m.CreatedAt})
			}
		}
		if len(out) == storage.ListLimit {
			break
		}
	}
	return out, nil
}

func (s *Store) AddMember(_ context.Context, orgID, userID string, role storage.Role) (storage.Membership, error) {
	if !role.Valid() {
		return storage.Membership{}, &storage.ValidationError{Field: "role", Message: "must be owner, admin, member or viewer"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.org(orgID); err != nil || !s.userExists(userID) {
		return storage.Membership{}, storage.ErrNotFound
	}
	if s.memberIndex(orgID, userID) >= 0 {
		return storage.Membership{}, storage.ErrConflict
	}
	m := storage.Membership{OrganizationID: orgID, UserID: userID, Role: role, CreatedAt: time.Now().UTC()}
	s.members = append(s.members, m)
	return m, nil
}

func (s *Store) SetMemberRole(_ context.Context, orgID, userID string, role storage.Role) error {
	if !role.Valid() {
		return &storage.ValidationError{Field: "role", Message: "must be owner, admin, member or viewer"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	i := s.memberIndex(orgID, userID)
	if i < 0 {
		return storage.ErrNotFound
	}
	if s.members[i].Role == storage.RoleOwner && role != storage.RoleOwner && s.ownerCount(orgID) <= 1 {
		return storage.ErrLastOwner
	}
	s.members[i].Role = role
	return nil
}

func (s *Store) RemoveMember(_ context.Context, orgID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	i := s.memberIndex(orgID, userID)
	if i < 0 {
		return storage.ErrNotFound
	}
	if s.members[i].Role == storage.RoleOwner && s.ownerCount(orgID) <= 1 {
		return storage.ErrLastOwner
	}
	s.members = append(s.members[:i], s.members[i+1:]...)
	return nil
}

// memberIndex returns the position of the membership, or -1. Caller holds s.mu.
func (s *Store) memberIndex(orgID, userID string) int {
	for i, m := range s.members {
		if m.OrganizationID == orgID && m.UserID == userID {
			return i
		}
	}
	return -1
}

func (s *Store) ownerCount(orgID string) int {
	n := 0
	for _, m := range s.members {
		if m.OrganizationID == orgID && m.Role == storage.RoleOwner {
			n++
		}
	}
	return n
}

// AllAudit returns every audit entry, including ones that belong to no organization.
// It is outside storage.Store: it exists so tests can verify that login events were
// recorded even though the API does not serve them.
func (s *Store) AllAudit(context.Context) ([]storage.AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]storage.AuditEntry(nil), s.audit...), nil
}
