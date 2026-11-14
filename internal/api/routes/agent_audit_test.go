package routes

import (
	"net/http"
	"strings"
	"testing"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

func TestAgentTokenLifecycle(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	cluster := h.cluster(a, "prod")
	base := "/v1/organizations/" + a.OrgID + "/clusters/" + cluster + "/agent-tokens"

	created := h.want(h.do("POST", base, a.Token, nil), http.StatusCreated)
	agentToken := str(h, created.JSON, "token")
	credID := str(h, created.JSON, "id")
	if !strings.HasPrefix(agentToken, "ksa_") {
		t.Errorf("agent token = %q, want ksa_ prefix", agentToken)
	}
	if created.Header.Get("Cache-Control") != "no-store" {
		t.Error("agent token response is cacheable")
	}
	if prefix := str(h, created.JSON, "token_prefix"); !strings.HasPrefix(agentToken, prefix) || prefix == agentToken {
		t.Errorf("token_prefix = %q must be a short non-secret prefix of the token", prefix)
	}

	// The secret is shown once: listing returns metadata only.
	list := h.want(h.do("GET", base, a.Token, nil), http.StatusOK)
	if strings.Contains(list.Body, agentToken) || strings.Contains(list.Body, `"token":`) || strings.Contains(list.Body, "token_hash") {
		t.Errorf("list leaks the token or its hash: %s", list.Body)
	}

	// The agent can identify itself, and only with an agent token.
	who := h.want(h.do("GET", "/v1/agent/whoami", agentToken, nil), http.StatusOK)
	if who.JSON["cluster_id"] != cluster || who.JSON["organization_id"] != a.OrgID {
		t.Errorf("whoami = %v, want cluster %s in org %s", who.JSON, cluster, a.OrgID)
	}
	items := h.want(h.do("GET", base, a.Token, nil), http.StatusOK).JSON["items"].([]any)
	if items[0].(map[string]any)["last_used_at"] == nil {
		t.Error("last_used_at not recorded after the agent authenticated")
	}

	// Token kinds are not interchangeable.
	h.want(h.do("GET", "/v1/agent/whoami", a.Token, nil), http.StatusUnauthorized)
	h.want(h.do("GET", "/v1/me", agentToken, nil), http.StatusUnauthorized)
	h.want(h.do("GET", "/v1/organizations/"+a.OrgID+"/clusters", agentToken, nil), http.StatusUnauthorized)

	// Revoke; revoking again is fine; the agent is locked out immediately.
	h.want(h.do("DELETE", base+"/"+credID, a.Token, nil), http.StatusNoContent)
	h.want(h.do("DELETE", base+"/"+credID, a.Token, nil), http.StatusNoContent)
	h.want(h.do("GET", "/v1/agent/whoami", agentToken, nil), http.StatusUnauthorized)

	// Unknown credential or wrong cluster is a 404.
	h.want(h.do("DELETE", base+"/33333333-3333-4333-8333-333333333333", a.Token, nil), http.StatusNotFound)
	other := h.cluster(a, "staging")
	h.want(h.do("DELETE", "/v1/organizations/"+a.OrgID+"/clusters/"+other+"/agent-tokens/"+credID, a.Token, nil), http.StatusNotFound)

	// Two tokens are different, and each cluster's token speaks only for its own cluster.
	t2 := str(h, h.want(h.do("POST", base, a.Token, nil), http.StatusCreated).JSON, "token")
	t3 := str(h, h.want(h.do("POST", "/v1/organizations/"+a.OrgID+"/clusters/"+other+"/agent-tokens", a.Token, nil), http.StatusCreated).JSON, "token")
	if t2 == t3 || t2 == agentToken {
		t.Error("token reuse")
	}
	if got := h.want(h.do("GET", "/v1/agent/whoami", t3, nil), http.StatusOK).JSON["cluster_id"]; got != other {
		t.Errorf("second token speaks for %v, want %s", got, other)
	}
}

func TestAgentTokenForUnknownClusterIs404(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	h.want(h.do("POST", "/v1/organizations/"+a.OrgID+"/clusters/44444444-4444-4444-8444-444444444444/agent-tokens", a.Token, nil), http.StatusNotFound)
	h.want(h.do("GET", "/v1/organizations/"+a.OrgID+"/clusters/44444444-4444-4444-8444-444444444444/agent-tokens", a.Token, nil), http.StatusNotFound)
}

func TestAuditLog(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	cluster := h.cluster(a, "prod")
	base := "/v1/organizations/" + a.OrgID + "/clusters/" + cluster
	h.want(h.do("POST", base+"/scans", a.Token, nil), http.StatusCreated)
	created := h.want(h.do("POST", base+"/agent-tokens", a.Token, nil), http.StatusCreated)
	agentToken := str(h, created.JSON, "token")
	h.want(h.do("DELETE", base+"/agent-tokens/"+str(h, created.JSON, "id"), a.Token, nil), http.StatusNoContent)

	r := h.want(h.do("GET", "/v1/organizations/"+a.OrgID+"/audit-logs", a.Token, nil), http.StatusOK)
	var actions []string
	for _, it := range r.JSON["items"].([]any) {
		e := it.(map[string]any)
		actions = append(actions, e["action"].(string))
		if e["actor_user_id"] != a.UserID || e["actor_type"] != "user" {
			t.Errorf("entry %v: want actor %s", e, a.UserID)
		}
	}
	// Newest first. account.created came from signup, before the cluster was made.
	want := []string{"agent_token.revoked", "agent_token.created", "scan.requested", "cluster.created", "account.created"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Errorf("actions = %v, want %v", actions, want)
	}

	// The audit log must never contain a credential of any kind.
	for name, secret := range map[string]string{
		"password": testPassword, "session token": a.Token, "agent token": agentToken,
		"hash scheme": "pbkdf2", "token hash field": "token_hash",
	} {
		if strings.Contains(r.Body, secret) {
			t.Errorf("audit log contains the %s", name)
		}
	}
}

func TestLoginsAreAudited(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": a.Email, "password": "wrong password!!"}), http.StatusUnauthorized)
	h.want(h.do("POST", "/v1/auth/logout", a.Token, nil), http.StatusNoContent)

	// These events belong to a person, not an organization, so they are not in an org's log...
	login := h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": a.Email, "password": testPassword}), http.StatusOK)
	r := h.want(h.do("GET", "/v1/organizations/"+a.OrgID+"/audit-logs", str(h, login.JSON, "token"), nil), http.StatusOK)
	if strings.Contains(r.Body, "auth.login") {
		t.Errorf("per-person auth events leaked into the organization audit log: %s", r.Body)
	}
	// ...but they were written, so they can be reviewed by an operator.
	got := map[string]int{}
	for _, e := range h.auditEntries(a.UserID) {
		got[e.Action]++
	}
	if got["auth.login"] != 2 || got["auth.login_failed"] != 1 || got["auth.logout"] != 1 {
		t.Errorf("auth audit counts = %v, want login=2 login_failed=1 logout=1", got)
	}
}

func TestAgentClaimsOnlyItsClusterScanJobs(t *testing.T) {
	h := newHarness(t)
	a := h.signup("claim@example.com", "claim-org")
	clusterID := h.cluster(a, "agent-cluster")
	base := "/v1/organizations/" + a.OrgID + "/clusters/" + clusterID
	agentToken := str(h, h.want(h.do("POST", base+"/agent-tokens", a.Token, nil), http.StatusCreated).JSON, "token")
	queued := h.want(h.do("POST", base+"/scans", a.Token, nil), http.StatusCreated)
	scanID := str(h, queued.JSON, "id")

	claimed := h.want(h.do("GET", "/v1/agent/scans/next", agentToken, nil), http.StatusOK)
	if claimed.JSON["id"] != scanID || claimed.JSON["status"] != storage.ScanRunning {
		t.Fatalf("claimed job = %v, want scan %s running", claimed.JSON, scanID)
	}
	if claimed.JSON["started_at"] == nil {
		t.Fatal("claimed job has no started_at")
	}
	h.want(h.do("GET", "/v1/agent/scans/next", agentToken, nil), http.StatusNoContent)
	// A user session is not an agent credential.
	h.want(h.do("GET", "/v1/agent/scans/next", a.Token, nil), http.StatusUnauthorized)
}
