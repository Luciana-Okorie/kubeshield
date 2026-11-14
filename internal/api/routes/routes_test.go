package routes

import (
	"net/http"
	"strings"
	"testing"
)

func TestBasicRouting(t *testing.T) {
	h := newHarness(t)
	tests := []struct {
		name, method, path string
		want               int
	}{
		{"healthz GET", "GET", "/healthz", http.StatusOK},
		{"healthz HEAD", "HEAD", "/healthz", http.StatusOK},
		{"healthz POST rejected", "POST", "/healthz", http.StatusMethodNotAllowed},
		{"unknown path", "GET", "/nope", http.StatusNotFound},
		{"login GET rejected", "GET", "/v1/auth/login", http.StatusMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.do(tc.method, tc.path, "", nil).Status; got != tc.want {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// Every route except health, signup and login must refuse an anonymous caller.
func TestProtectedRoutesRequireAuthentication(t *testing.T) {
	h := newHarness(t)
	const id = "11111111-1111-4111-8111-111111111111"
	org := "/v1/organizations/" + id
	routes := []struct{ method, path string }{
		{"POST", "/v1/auth/logout"},
		{"GET", "/v1/me"},
		{"POST", "/v1/organizations"},
		{"GET", "/v1/organizations"},
		{"GET", org},
		{"GET", org + "/audit-logs"},
		{"POST", org + "/clusters"},
		{"GET", org + "/clusters"},
		{"GET", org + "/clusters/" + id},
		{"POST", org + "/clusters/" + id + "/scans"},
		{"GET", org + "/clusters/" + id + "/scans"},
		{"GET", org + "/scans/" + id},
		{"POST", org + "/clusters/" + id + "/agent-tokens"},
		{"GET", org + "/clusters/" + id + "/agent-tokens"},
		{"DELETE", org + "/clusters/" + id + "/agent-tokens/" + id},
		{"GET", "/v1/agent/whoami"},
	}
	bad := map[string]string{
		"no header":      "",
		"garbage":        "nonsense",
		"wrong prefix":   "xyz_" + strings.Repeat("a", 43),
		"unknown ksu":    "ksu_" + strings.Repeat("a", 43),
		"unknown ksa":    "ksa_" + strings.Repeat("a", 43),
		"empty ksu body": "ksu_",
	}
	for _, rt := range routes {
		for name, tok := range bad {
			r := h.do(rt.method, rt.path, tok, nil)
			if r.Status != http.StatusUnauthorized {
				t.Errorf("%s %s with %s = %d, want 401", rt.method, rt.path, name, r.Status)
			}
			if r.Header.Get("WWW-Authenticate") == "" {
				t.Errorf("%s %s with %s: 401 without WWW-Authenticate", rt.method, rt.path, name)
			}
		}
	}
}

func TestMalformedIDsAre404(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	for _, p := range []string{
		"/v1/organizations/not-a-uuid",
		"/v1/organizations/" + a.OrgID + "/clusters/not-a-uuid",
		"/v1/organizations/" + a.OrgID + "/scans/%27%20OR%201=1--",
	} {
		if got := h.do("GET", p, a.Token, nil).Status; got != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, got)
		}
	}
}

func TestRequestBodyValidation(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	path := "/v1/organizations/" + a.OrgID + "/clusters"

	tests := []struct {
		name string
		body any
		want int
	}{
		{"unknown field", `{"name":"x","provider":"kind","admin":true}`, http.StatusBadRequest},
		{"not json", `hello`, http.StatusBadRequest},
		{"two objects", `{"name":"x","provider":"kind"}{"name":"y"}`, http.StatusBadRequest},
		{"bad provider", map[string]string{"name": "x", "provider": "alibaba"}, http.StatusUnprocessableEntity},
		{"empty name", map[string]string{"name": " ", "provider": "kind"}, http.StatusUnprocessableEntity},
		{"too large", `{"name":"` + strings.Repeat("a", 2<<20) + `"}`, http.StatusRequestEntityTooLarge},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.do("POST", path, a.Token, tc.body).Status; got != tc.want {
				t.Errorf("status = %d, want %d", got, tc.want)
			}
		})
	}
}
