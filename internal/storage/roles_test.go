package storage

import "testing"

func TestRoleCan(t *testing.T) {
	tests := []struct {
		role               Role
		read, scan, manage bool
	}{
		{RoleOwner, true, true, true},
		{RoleAdmin, true, true, true},
		{RoleMember, true, true, false},
		{RoleViewer, true, false, false},
		{Role(""), false, false, false},
		{Role("root"), false, false, false},
		{Role("OWNER"), false, false, false}, // roles are case-sensitive
	}
	for _, tc := range tests {
		t.Run(string(tc.role), func(t *testing.T) {
			if got := tc.role.Can(PermRead); got != tc.read {
				t.Errorf("Can(read) = %v, want %v", got, tc.read)
			}
			if got := tc.role.Can(PermScan); got != tc.scan {
				t.Errorf("Can(scan) = %v, want %v", got, tc.scan)
			}
			if got := tc.role.Can(PermManage); got != tc.manage {
				t.Errorf("Can(manage) = %v, want %v", got, tc.manage)
			}
		})
	}
}

func TestUnknownPermissionGrantsNothing(t *testing.T) {
	for _, r := range []Role{RoleOwner, RoleAdmin, RoleMember, RoleViewer} {
		if r.Can(Permission(0)) || r.Can(Permission(99)) {
			t.Errorf("%s was granted an undefined permission", r)
		}
	}
}

func TestCanAssign(t *testing.T) {
	const none = Role("")
	tests := []struct {
		actor, from, to Role
		want            bool
	}{
		// owners can do anything valid
		{RoleOwner, none, RoleOwner, true},
		{RoleOwner, RoleAdmin, RoleViewer, true},
		{RoleOwner, RoleOwner, RoleMember, true},
		{RoleOwner, none, Role("root"), false},
		{RoleOwner, Role("root"), RoleViewer, false},
		// admins handle only members and viewers
		{RoleAdmin, none, RoleMember, true},
		{RoleAdmin, none, RoleViewer, true},
		{RoleAdmin, RoleMember, RoleViewer, true},
		{RoleAdmin, none, RoleAdmin, false},
		{RoleAdmin, none, RoleOwner, false},
		{RoleAdmin, RoleMember, RoleAdmin, false}, // no promoting anyone to admin
		{RoleAdmin, RoleAdmin, RoleMember, false}, // no demoting another admin
		{RoleAdmin, RoleOwner, RoleViewer, false}, // no touching owners
		// everyone else manages nobody
		{RoleMember, none, RoleViewer, false},
		{RoleViewer, none, RoleViewer, false},
		{Role("root"), none, RoleViewer, false},
	}
	for _, tc := range tests {
		if got := tc.actor.CanAssign(tc.from, tc.to); got != tc.want {
			t.Errorf("%q.CanAssign(%q -> %q) = %v, want %v", tc.actor, tc.from, tc.to, got, tc.want)
		}
	}
}
