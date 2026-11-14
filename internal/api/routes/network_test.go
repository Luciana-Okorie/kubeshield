package routes

import (
	"net/http"
	"net/netip"
	"testing"
	"time"
)

// httptest connects from 127.0.0.1, so that is the "proxy" in these tests.
func trustLoopback(o *Options) {
	o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
}

func loginAttempt(h *harness, forwardedFor string) resp {
	hdr := map[string]string{}
	if forwardedFor != "" {
		hdr["X-Forwarded-For"] = forwardedFor
	}
	return h.doWith("POST", "/v1/auth/login", "", map[string]string{"email": "x@example.com", "password": "wrong password here"}, hdr)
}

func TestForgedForwardedForDoesNotEvadeRateLimit(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.AuthPerMinute, o.AuthBurst = 6, 2 }) // no trusted proxies
	h.want(loginAttempt(h, "1.1.1.1"), http.StatusUnauthorized)
	h.want(loginAttempt(h, "2.2.2.2"), http.StatusUnauthorized)
	h.want(loginAttempt(h, "3.3.3.3"), http.StatusTooManyRequests) // a new "address" bought nothing
}

func TestTrustedProxyGivesEachClientItsOwnLimit(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.AuthPerMinute, o.AuthBurst = 6, 2 }, trustLoopback)
	for i := 0; i < 2; i++ {
		h.want(loginAttempt(h, "198.51.100.1"), http.StatusUnauthorized)
	}
	h.want(loginAttempt(h, "198.51.100.1"), http.StatusTooManyRequests)
	// A different real client behind the same proxy is unaffected...
	h.want(loginAttempt(h, "198.51.100.2"), http.StatusUnauthorized)
	// ...and cannot shake off its own limit by forging entries on the left.
	h.want(loginAttempt(h, "9.9.9.9, 198.51.100.1"), http.StatusTooManyRequests)
	h.clock.Advance(11 * time.Second)
	h.want(loginAttempt(h, "198.51.100.1"), http.StatusUnauthorized)
}

func TestAuditRecordsTheResolvedClientAddress(t *testing.T) {
	ip := func(h *harness, forwarded string) string {
		a := h.signup("a@example.com", "alpha")
		h.doWith("POST", "/v1/auth/login", "", map[string]string{"email": a.Email, "password": "wrong password here"},
			map[string]string{"X-Forwarded-For": forwarded})
		for _, e := range h.auditEntries(a.UserID) {
			if e.Action == "auth.login_failed" {
				return e.IP
			}
		}
		t.Fatal("no auth.login_failed entry")
		return ""
	}
	if got := ip(newHarness(t), "203.0.113.50"); got != "127.0.0.1" {
		t.Errorf("untrusted: audit IP = %q, want the TCP peer 127.0.0.1 (a forged header must not reach the audit log)", got)
	}
	if got := ip(newHarness(t, trustLoopback), "203.0.113.50"); got != "203.0.113.50" {
		t.Errorf("trusted proxy: audit IP = %q, want 203.0.113.50", got)
	}
}

func TestResponsesCarrySecurityHeaders(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.HSTS = true })
	a := h.signup("a@example.com", "alpha")
	for _, r := range []resp{
		h.do("GET", "/healthz", "", nil),
		h.do("GET", "/v1/me", a.Token, nil),
		h.do("GET", "/v1/me", "", nil),      // 401
		h.do("GET", "/v1/nowhere", "", nil), // 404 from the mux
	} {
		if r.Header.Get("X-Content-Type-Options") != "nosniff" || r.Header.Get("Cache-Control") != "no-store" ||
			r.Header.Get("Strict-Transport-Security") == "" || r.Header.Get("Content-Security-Policy") == "" {
			t.Errorf("status %d missing security headers: %v", r.Status, r.Header)
		}
	}
}
