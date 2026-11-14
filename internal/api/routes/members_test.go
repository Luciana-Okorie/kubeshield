package routes

import (
	"net/http"
	"strings"
	"sync"
	"testing"
)

func membersPath(a account) string { return "/v1/organizations/" + a.OrgID + "/members" }

func TestOwnerManagesMembers(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("owner@example.com", "acme")
	bob := h.signup("bob@example.com", "bob-co") // an existing account, in his own org

	// Bob cannot see Acme at all yet.
	h.want(h.do("GET", "/v1/organizations/"+owner.OrgID, bob.Token, nil), http.StatusNotFound)

	added := h.want(h.do("POST", membersPath(owner), owner.Token, map[string]string{"email": " BOB@example.com ", "role": "viewer"}), http.StatusCreated)
	if added.JSON["role"] != "viewer" || added.JSON["email"] != "bob@example.com" || added.JSON["user_id"] != bob.UserID {
		t.Errorf("added = %v", added.JSON)
	}
	if strings.Contains(added.Body, "pbkdf2") {
		t.Error("response leaks a password hash")
	}

	// Now Bob can read Acme but nothing else.
	h.want(h.do("GET", "/v1/organizations/"+owner.OrgID, bob.Token, nil), http.StatusOK)
	h.want(h.do("GET", membersPath(owner), bob.Token, nil), http.StatusForbidden)
	h.want(h.do("POST", "/v1/organizations/"+owner.OrgID+"/clusters", bob.Token, map[string]string{"name": "x", "provider": "kind"}), http.StatusForbidden)

	list := h.want(h.do("GET", membersPath(owner), owner.Token, nil), http.StatusOK).JSON["items"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["role"] != "owner" || list[1].(map[string]any)["email"] != "bob@example.com" {
		t.Errorf("members = %v, want owner then bob", list)
	}

	// Promote, then the new role takes effect immediately.
	h.want(h.do("PATCH", membersPath(owner)+"/"+bob.UserID, owner.Token, map[string]string{"role": "member"}), http.StatusOK)
	h.want(h.do("POST", "/v1/organizations/"+owner.OrgID+"/clusters/"+h.cluster(owner, "prod")+"/scans", bob.Token, nil), http.StatusCreated)

	// Removal revokes access at once, even though Bob's session is still valid.
	h.want(h.do("DELETE", membersPath(owner)+"/"+bob.UserID, owner.Token, nil), http.StatusNoContent)
	h.want(h.do("GET", "/v1/organizations/"+owner.OrgID, bob.Token, nil), http.StatusNotFound)
	h.want(h.do("GET", "/v1/me", bob.Token, nil), http.StatusOK)
	h.want(h.do("DELETE", membersPath(owner)+"/"+bob.UserID, owner.Token, nil), http.StatusNotFound) // already gone
}

func TestMemberInputValidation(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("owner@example.com", "acme")
	h.signup("bob@example.com", "bob-co")

	tests := []struct {
		name string
		body any
		want int
	}{
		{"unknown account", map[string]string{"email": "ghost@example.com", "role": "viewer"}, http.StatusNotFound},
		{"bad email", map[string]string{"email": "nope", "role": "viewer"}, http.StatusUnprocessableEntity},
		{"bad role", map[string]string{"email": "bob@example.com", "role": "god"}, http.StatusUnprocessableEntity},
		{"empty role", map[string]string{"email": "bob@example.com"}, http.StatusUnprocessableEntity},
		{"unknown field", `{"email":"bob@example.com","role":"viewer","user_id":"x"}`, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h.want(h.do("POST", membersPath(owner), owner.Token, tc.body), tc.want)
		})
	}
	h.want(h.do("POST", membersPath(owner), owner.Token, map[string]string{"email": "bob@example.com", "role": "viewer"}), http.StatusCreated)
	h.want(h.do("POST", membersPath(owner), owner.Token, map[string]string{"email": "bob@example.com", "role": "admin"}), http.StatusConflict)
	// The owner adding themselves again is also a conflict, not a silent role change.
	h.want(h.do("POST", membersPath(owner), owner.Token, map[string]string{"email": "owner@example.com", "role": "viewer"}), http.StatusConflict)
}

// An admin must never be able to gain, grant or touch owner-level power.
func TestAdminCannotEscalate(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("owner@example.com", "acme")
	admin := h.member(owner, "admin@example.com", "admin-co", "admin")
	admin2 := h.member(owner, "admin2@example.com", "admin2-co", "admin")
	member := h.member(owner, "member@example.com", "member-co", "member")
	friend := h.signup("friend@example.com", "friend-co")

	base := membersPath(owner)

	// Allowed: handling members and viewers.
	h.want(h.do("POST", base, admin.Token, map[string]string{"email": "friend@example.com", "role": "viewer"}), http.StatusCreated)
	h.want(h.do("PATCH", base+"/"+friend.UserID, admin.Token, map[string]string{"role": "member"}), http.StatusOK)
	h.want(h.do("PATCH", base+"/"+member.UserID, admin.Token, map[string]string{"role": "viewer"}), http.StatusOK)

	forbidden := []struct {
		name, method, path string
		body               any
	}{
		{"add an owner", "POST", base, map[string]string{"email": "friend@example.com", "role": "owner"}},
		{"add an admin", "POST", base, map[string]string{"email": "friend@example.com", "role": "admin"}},
		{"promote a member to admin", "PATCH", base + "/" + member.UserID, map[string]string{"role": "admin"}},
		{"promote self to owner", "PATCH", base + "/" + admin.UserID, map[string]string{"role": "owner"}},
		{"promote a friend to owner", "PATCH", base + "/" + friend.UserID, map[string]string{"role": "owner"}},
		{"demote an owner", "PATCH", base + "/" + owner.UserID, map[string]string{"role": "viewer"}},
		{"demote another admin", "PATCH", base + "/" + admin2.UserID, map[string]string{"role": "viewer"}},
		{"remove an owner", "DELETE", base + "/" + owner.UserID, nil},
		{"remove another admin", "DELETE", base + "/" + admin2.UserID, nil},
	}
	for _, tc := range forbidden {
		if r := h.do(tc.method, tc.path, admin.Token, tc.body); r.Status != http.StatusForbidden {
			t.Errorf("admin tried to %s: %d, want 403 (%s)", tc.name, r.Status, r.Body)
		}
	}

	// Admin may remove a member.
	h.want(h.do("DELETE", base+"/"+friend.UserID, admin.Token, nil), http.StatusNoContent)

	// And none of the refused attempts changed anything.
	roles := map[string]string{}
	for _, it := range h.want(h.do("GET", base, owner.Token, nil), http.StatusOK).JSON["items"].([]any) {
		m := it.(map[string]any)
		roles[m["email"].(string)] = m["role"].(string)
	}
	want := map[string]string{"owner@example.com": "owner", "admin@example.com": "admin", "admin2@example.com": "admin", "member@example.com": "viewer"}
	for email, role := range want {
		if roles[email] != role {
			t.Errorf("%s is %q, want %q", email, roles[email], role)
		}
	}
	if len(roles) != len(want) {
		t.Errorf("members = %v", roles)
	}

	// Members and viewers manage nobody.
	for _, who := range []account{member, h.member(owner, "viewer@example.com", "viewer-co", "viewer")} {
		h.want(h.do("POST", base, who.Token, map[string]string{"email": "friend@example.com", "role": "viewer"}), http.StatusForbidden)
		h.want(h.do("PATCH", base+"/"+admin.UserID, who.Token, map[string]string{"role": "viewer"}), http.StatusForbidden)
		h.want(h.do("DELETE", base+"/"+admin.UserID, who.Token, nil), http.StatusForbidden)
	}
}

func TestOrganizationAlwaysKeepsAnOwner(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("owner@example.com", "acme")
	base := membersPath(owner)

	for _, tc := range []struct{ name, method string }{{"demote", "PATCH"}, {"remove", "DELETE"}} {
		var body any
		if tc.method == "PATCH" {
			body = map[string]string{"role": "viewer"}
		}
		r := h.want(h.do(tc.method, base+"/"+owner.UserID, owner.Token, body), http.StatusConflict)
		if r.JSON["error"].(map[string]any)["code"] != "last_owner" {
			t.Errorf("sole owner %s: %v, want last_owner", tc.name, r.JSON)
		}
	}
	// "Changing" the sole owner to owner is harmless.
	h.want(h.do("PATCH", base+"/"+owner.UserID, owner.Token, map[string]string{"role": "owner"}), http.StatusOK)

	// With a second owner, the first may step down, and then the second is the last.
	second := h.member(owner, "second@example.com", "second-co", "owner")
	h.want(h.do("PATCH", base+"/"+owner.UserID, owner.Token, map[string]string{"role": "admin"}), http.StatusOK)
	h.want(h.do("DELETE", base+"/"+second.UserID, second.Token, nil), http.StatusConflict)
	h.want(h.do("DELETE", base+"/"+second.UserID, owner.Token, nil), http.StatusForbidden) // owner is now only an admin
}

func TestMembersAreTenantScoped(t *testing.T) {
	h := newHarness(t)
	alice := h.signup("alice@example.com", "alice-co")
	bob := h.signup("bob@example.com", "bob-co")
	carol := h.signup("carol@example.com", "carol-co")
	h.want(h.do("POST", membersPath(alice), alice.Token, map[string]string{"email": "carol@example.com", "role": "viewer"}), http.StatusCreated)

	// Bob, an outsider, learns nothing about Alice's membership.
	for _, tc := range []struct {
		method, path string
		body         any
	}{
		{"GET", membersPath(alice), nil},
		{"POST", membersPath(alice), map[string]string{"email": "bob@example.com", "role": "owner"}},
		{"PATCH", membersPath(alice) + "/" + carol.UserID, map[string]string{"role": "owner"}},
		{"DELETE", membersPath(alice) + "/" + carol.UserID, nil},
	} {
		if r := h.do(tc.method, tc.path, bob.Token, tc.body); r.Status != http.StatusNotFound {
			t.Errorf("bob %s %s = %d, want 404", tc.method, tc.path, r.Status)
		}
	}
	// Using his own org with Alice's member's ID reveals nothing either.
	h.want(h.do("PATCH", membersPath(bob)+"/"+carol.UserID, bob.Token, map[string]string{"role": "viewer"}), http.StatusNotFound)
	h.want(h.do("DELETE", membersPath(bob)+"/"+carol.UserID, bob.Token, nil), http.StatusNotFound)

	// Carol is still a viewer in Alice's org.
	list := h.want(h.do("GET", membersPath(alice), alice.Token, nil), http.StatusOK).JSON["items"].([]any)
	if len(list) != 2 {
		t.Errorf("alice's members = %v, want 2", list)
	}
}

func TestMemberChangesAreAudited(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("owner@example.com", "acme")
	bob := h.signup("bob@example.com", "bob-co")
	h.want(h.do("POST", membersPath(owner), owner.Token, map[string]string{"email": "bob@example.com", "role": "viewer"}), http.StatusCreated)
	h.want(h.do("PATCH", membersPath(owner)+"/"+bob.UserID, owner.Token, map[string]string{"role": "member"}), http.StatusOK)
	h.want(h.do("DELETE", membersPath(owner)+"/"+bob.UserID, owner.Token, nil), http.StatusNoContent)

	r := h.want(h.do("GET", "/v1/organizations/"+owner.OrgID+"/audit-logs", owner.Token, nil), http.StatusOK)
	var got []string
	for _, it := range r.JSON["items"].([]any) {
		got = append(got, it.(map[string]any)["action"].(string))
	}
	want := "member.removed,member.role_changed,member.added,account.created"
	if strings.Join(got, ",") != want {
		t.Errorf("actions = %v, want %s", got, want)
	}
	if !strings.Contains(r.Body, `"from":"viewer"`) || !strings.Contains(r.Body, `"to":"member"`) {
		t.Errorf("role change not recorded with before/after: %s", r.Body)
	}
	if strings.Contains(r.Body, "bob@example.com") {
		t.Error("audit log stores the added person's email; it should reference only the user ID")
	}
}

// Two people racing to be the first account on a closed server: exactly one wins.
func TestClosedSignupBootstrapIsAtomic(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.AllowSignup = false })
	const n = 12
	var wg sync.WaitGroup
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			email := "user" + string(rune('a'+i)) + "@example.com"
			slug := "org-" + string(rune('a'+i))
			codes <- h.do("POST", "/v1/auth/signup", "", map[string]string{
				"email": email, "display_name": "U", "password": testPassword, "organization_name": "O", "organization_slug": slug,
			}).Status
		}(i)
	}
	wg.Wait()
	close(codes)
	created, forbidden := 0, 0
	for c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusForbidden:
			forbidden++
		default:
			t.Errorf("unexpected status %d", c)
		}
	}
	if created != 1 || forbidden != n-1 {
		t.Errorf("created=%d forbidden=%d, want exactly 1 and %d", created, forbidden, n-1)
	}
}
