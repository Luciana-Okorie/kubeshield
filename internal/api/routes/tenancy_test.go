package routes

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// Bob is signed in and valid, but nothing in Alice's organization may be visible or
// changeable to him, and every refusal must look exactly like "does not exist".
func TestTenantIsolation(t *testing.T) {
	h := newHarness(t)
	alice := h.signup("alice@example.com", "alice-co")
	bob := h.signup("bob@example.com", "bob-co")

	aOrg := "/v1/organizations/" + alice.OrgID
	aCluster := h.cluster(alice, "alice-prod")
	scan := h.want(h.do("POST", aOrg+"/clusters/"+aCluster+"/scans", alice.Token, nil), http.StatusCreated)
	scanID := str(h, scan.JSON, "id")
	tok := h.want(h.do("POST", aOrg+"/clusters/"+aCluster+"/agent-tokens", alice.Token, nil), http.StatusCreated)
	tokID := str(h, tok.JSON, "id")

	missing := h.do("GET", "/v1/organizations/22222222-2222-4222-8222-222222222222", bob.Token, nil)

	denied := []struct{ method, path string }{
		{"GET", aOrg},
		{"GET", aOrg + "/audit-logs"},
		{"GET", aOrg + "/clusters"},
		{"POST", aOrg + "/clusters"},
		{"GET", aOrg + "/clusters/" + aCluster},
		{"GET", aOrg + "/clusters/" + aCluster + "/scans"},
		{"POST", aOrg + "/clusters/" + aCluster + "/scans"},
		{"GET", aOrg + "/scans/" + scanID},
		{"GET", aOrg + "/clusters/" + aCluster + "/agent-tokens"},
		{"POST", aOrg + "/clusters/" + aCluster + "/agent-tokens"},
		{"DELETE", aOrg + "/clusters/" + aCluster + "/agent-tokens/" + tokID},
	}
	for _, d := range denied {
		var body any
		if d.method == "POST" && strings.HasSuffix(d.path, "/clusters") {
			body = map[string]string{"name": "evil", "provider": "kind"}
		}
		r := h.do(d.method, d.path, bob.Token, body)
		if r.Status != http.StatusNotFound {
			t.Errorf("bob %s %s = %d, want 404 (%s)", d.method, d.path, r.Status, r.Body)
		}
		if r.Body != missing.Body {
			t.Errorf("bob %s %s body %q differs from a truly missing org %q: tenants could probe for IDs", d.method, d.path, r.Body, missing.Body)
		}
	}

	// Using Bob's own org ID with Alice's cluster or scan must not leak them either.
	bOrg := "/v1/organizations/" + bob.OrgID
	for _, p := range []string{
		bOrg + "/clusters/" + aCluster,
		bOrg + "/clusters/" + aCluster + "/scans",
		bOrg + "/clusters/" + aCluster + "/agent-tokens",
		bOrg + "/scans/" + scanID,
	} {
		if got := h.do("GET", p, bob.Token, nil).Status; got != http.StatusNotFound {
			t.Errorf("bob GET %s = %d, want 404", p, got)
		}
	}
	h.want(h.do("POST", bOrg+"/clusters/"+aCluster+"/scans", bob.Token, nil), http.StatusNotFound)
	h.want(h.do("POST", bOrg+"/clusters/"+aCluster+"/agent-tokens", bob.Token, nil), http.StatusNotFound)
	h.want(h.do("DELETE", bOrg+"/clusters/"+aCluster+"/agent-tokens/"+tokID, bob.Token, nil), http.StatusNotFound)

	// Bob's listings contain only Bob's data.
	orgs := h.want(h.do("GET", "/v1/organizations", bob.Token, nil), http.StatusOK).JSON["items"].([]any)
	if len(orgs) != 1 || orgs[0].(map[string]any)["id"] != bob.OrgID {
		t.Errorf("bob's organizations = %v, want only his own", orgs)
	}
	if cl := h.want(h.do("GET", bOrg+"/clusters", bob.Token, nil), http.StatusOK).JSON["items"].([]any); len(cl) != 0 {
		t.Errorf("bob sees clusters %v", cl)
	}

	// None of Bob's attempts changed Alice's data, and Alice's token still works.
	if cl := h.want(h.do("GET", aOrg+"/clusters", alice.Token, nil), http.StatusOK).JSON["items"].([]any); len(cl) != 1 {
		t.Errorf("alice has %d clusters, want 1", len(cl))
	}
	if sc := h.want(h.do("GET", aOrg+"/clusters/"+aCluster+"/scans", alice.Token, nil), http.StatusOK).JSON["items"].([]any); len(sc) != 1 {
		t.Errorf("alice has %d scans, want 1", len(sc))
	}
	toks := h.want(h.do("GET", aOrg+"/clusters/"+aCluster+"/agent-tokens", alice.Token, nil), http.StatusOK).JSON["items"].([]any)
	if len(toks) != 1 || toks[0].(map[string]any)["revoked_at"] != nil {
		t.Errorf("alice's agent tokens = %v, want one unrevoked", toks)
	}
	h.want(h.do("GET", "/v1/agent/whoami", str(h, tok.JSON, "token"), nil), http.StatusOK)
}

// The same cluster name is allowed in different organizations.
func TestClusterNamesAreScopedPerOrganization(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "a-co")
	b := h.signup("b@example.com", "b-co")
	h.cluster(a, "prod")
	h.cluster(b, "prod")
	h.want(h.do("POST", "/v1/organizations/"+a.OrgID+"/clusters", a.Token, map[string]string{"name": "prod", "provider": "kind"}), http.StatusConflict)
}

func TestRoleEnforcement(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("owner@example.com", "acme")
	admin := h.member(owner, "admin@example.com", "admin-own", storage.RoleAdmin)
	member := h.member(owner, "member@example.com", "member-own", storage.RoleMember)
	viewer := h.member(owner, "viewer@example.com", "viewer-own", storage.RoleViewer)

	org := "/v1/organizations/" + owner.OrgID
	cluster := h.cluster(owner, "prod")
	cl := org + "/clusters/" + cluster
	tokID := str(h, h.want(h.do("POST", cl+"/agent-tokens", owner.Token, nil), http.StatusCreated).JSON, "id")

	// action -> minimum status per role. 0 means "success of any 2xx kind".
	type action struct {
		name, method, path string
		body               any
		ok                 map[string]bool // roles that may do it
	}
	newCluster := func(n string) any { return map[string]string{"name": n, "provider": "kind"} }
	actions := []action{
		{"read org", "GET", org, nil, map[string]bool{"owner": true, "admin": true, "member": true, "viewer": true}},
		{"list clusters", "GET", org + "/clusters", nil, map[string]bool{"owner": true, "admin": true, "member": true, "viewer": true}},
		{"get cluster", "GET", cl, nil, map[string]bool{"owner": true, "admin": true, "member": true, "viewer": true}},
		{"list scans", "GET", cl + "/scans", nil, map[string]bool{"owner": true, "admin": true, "member": true, "viewer": true}},
		{"request scan", "POST", cl + "/scans", nil, map[string]bool{"owner": true, "admin": true, "member": true}},
		{"create cluster", "POST", org + "/clusters", "NEW", map[string]bool{"owner": true, "admin": true}},
		{"create agent token", "POST", cl + "/agent-tokens", nil, map[string]bool{"owner": true, "admin": true}},
		{"list agent tokens", "GET", cl + "/agent-tokens", nil, map[string]bool{"owner": true, "admin": true}},
		{"read audit log", "GET", org + "/audit-logs", nil, map[string]bool{"owner": true, "admin": true}},
	}
	users := map[string]account{"owner": owner, "admin": admin, "member": member, "viewer": viewer}

	n := 0
	for _, a := range actions {
		for role, u := range users {
			body := a.body
			if body == "NEW" {
				n++
				body = newCluster(fmt.Sprintf("c-%d", n))
			}
			r := h.do(a.method, a.path, u.Token, body)
			if a.ok[role] {
				if r.Status < 200 || r.Status > 299 {
					t.Errorf("%s as %s = %d, want success (%s)", a.name, role, r.Status, r.Body)
				}
			} else if r.Status != http.StatusForbidden {
				t.Errorf("%s as %s = %d, want 403 (%s)", a.name, role, r.Status, r.Body)
			}
		}
	}

	// Revoking a token needs manage rights as well.
	h.want(h.do("DELETE", cl+"/agent-tokens/"+tokID, viewer.Token, nil), http.StatusForbidden)
	h.want(h.do("DELETE", cl+"/agent-tokens/"+tokID, member.Token, nil), http.StatusForbidden)
	h.want(h.do("DELETE", cl+"/agent-tokens/"+tokID, admin.Token, nil), http.StatusNoContent)

	// A forbidden attempt must not have had any effect: the token is still usable until the admin revoked it above,
	// and the viewer never created clusters or scans.
	scans := h.want(h.do("GET", cl+"/scans", owner.Token, nil), http.StatusOK).JSON["items"].([]any)
	if len(scans) != 3 { // owner, admin, member each queued one; the viewer's was refused
		t.Errorf("scans = %d, want 3", len(scans))
	}
}

func TestScanRecordsWhoRequestedIt(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	c := h.cluster(a, "prod")
	r := h.want(h.do("POST", "/v1/organizations/"+a.OrgID+"/clusters/"+c+"/scans", a.Token, nil), http.StatusCreated)
	if r.JSON["requested_by"] != a.UserID || r.JSON["status"] != "queued" {
		t.Errorf("scan = %v, want queued and requested_by %s", r.JSON, a.UserID)
	}
	if !strings.HasPrefix(r.Header.Get("Location"), "/v1/organizations/"+a.OrgID+"/scans/") {
		t.Errorf("Location = %q", r.Header.Get("Location"))
	}
}

func TestCreateAdditionalOrganization(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	r := h.want(h.do("POST", "/v1/organizations", a.Token, map[string]string{"name": "Second", "slug": "second"}), http.StatusCreated)
	if r.JSON["role"] != "owner" {
		t.Errorf("creator role = %v, want owner", r.JSON["role"])
	}
	h.want(h.do("POST", "/v1/organizations", a.Token, map[string]string{"name": "Dup", "slug": "second"}), http.StatusConflict)
	orgs := h.want(h.do("GET", "/v1/organizations", a.Token, nil), http.StatusOK).JSON["items"].([]any)
	if len(orgs) != 2 {
		t.Errorf("organizations = %d, want 2", len(orgs))
	}
}
