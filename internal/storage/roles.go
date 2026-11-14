package storage

// Role is a user's standing within one organization.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleAdmin  Role = "admin"
	RoleMember Role = "member"
	RoleViewer Role = "viewer"
)

// Permission is something a role may be allowed to do inside an organization.
type Permission int

const (
	// PermRead allows viewing the organization's clusters, scans and findings.
	PermRead Permission = iota + 1
	// PermScan allows requesting scans.
	PermScan
	// PermManage allows registering clusters, managing agent tokens and reading the audit log.
	PermManage
)

// Valid reports whether r is one of the defined roles.
func (r Role) Valid() bool {
	switch r {
	case RoleOwner, RoleAdmin, RoleMember, RoleViewer:
		return true
	}
	return false
}

// Can reports whether the role grants permission p. Unknown roles and unknown
// permissions grant nothing.
func (r Role) Can(p Permission) bool {
	switch p {
	case PermRead:
		return r.Valid()
	case PermScan:
		return r == RoleOwner || r == RoleAdmin || r == RoleMember
	case PermManage:
		return r == RoleOwner || r == RoleAdmin
	}
	return false
}

// CanAssign reports whether someone holding role r may give another person the role
// "to", or take away the role "from" (pass an empty "from" when adding a new member).
//
// Owners may do anything. Admins may only handle members and viewers: they cannot create
// owners or admins, and cannot touch existing ones, which stops an admin escalating
// themselves or a friend to full control. Members and viewers manage nobody.
func (r Role) CanAssign(from, to Role) bool {
	switch r {
	case RoleOwner:
		return to.Valid() && (from == "" || from.Valid())
	case RoleAdmin:
		low := func(x Role) bool { return x == RoleMember || x == RoleViewer }
		return low(to) && (from == "" || low(from))
	}
	return false
}
