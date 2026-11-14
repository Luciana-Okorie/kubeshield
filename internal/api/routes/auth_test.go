package routes

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignupLoginMeLogout(t *testing.T) {
	h := newHarness(t)

	r := h.want(h.do("POST", "/v1/auth/signup", "", map[string]string{
		"email": "  Ada@Example.COM ", "display_name": "Ada", "password": testPassword,
		"organization_name": "Analytical", "organization_slug": "analytical",
	}), http.StatusCreated)
	if got := r.JSON["user"].(map[string]any)["email"]; got != "ada@example.com" {
		t.Errorf("email = %v, want normalised ada@example.com", got)
	}
	for _, secret := range []string{testPassword, "pbkdf2", "password_hash", "PasswordHash"} {
		if strings.Contains(r.Body, secret) {
			t.Errorf("signup response leaks %q: %s", secret, r.Body)
		}
	}

	login := h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": "ADA@example.com", "password": testPassword}), http.StatusOK)
	token := str(h, login.JSON, "token")
	if !strings.HasPrefix(token, "ksu_") || len(token) < 40 {
		t.Errorf("token = %q, want a ksu_ token with 256 bits of entropy", token)
	}
	if login.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("login Cache-Control = %q, want no-store", login.Header.Get("Cache-Control"))
	}
	if strings.Contains(login.Body, "pbkdf2") {
		t.Error("login response leaks the password hash")
	}

	me := h.want(h.do("GET", "/v1/me", token, nil), http.StatusOK)
	orgs := me.JSON["organizations"].([]any)
	if len(orgs) != 1 || orgs[0].(map[string]any)["role"] != "owner" || orgs[0].(map[string]any)["slug"] != "analytical" {
		t.Errorf("organizations = %v, want one owned org", orgs)
	}

	h.want(h.do("POST", "/v1/auth/logout", token, nil), http.StatusNoContent)
	h.want(h.do("GET", "/v1/me", token, nil), http.StatusUnauthorized)
	h.want(h.do("POST", "/v1/auth/logout", token, nil), http.StatusUnauthorized) // already revoked
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	h := newHarness(t)
	h.signup("real@example.com", "real")

	wrongPassword := h.do("POST", "/v1/auth/login", "", map[string]string{"email": "real@example.com", "password": "not the password"})
	unknownUser := h.do("POST", "/v1/auth/login", "", map[string]string{"email": "ghost@example.com", "password": testPassword})
	badEmail := h.do("POST", "/v1/auth/login", "", map[string]string{"email": "Name <x@example.com>", "password": testPassword})
	emptyBoth := h.do("POST", "/v1/auth/login", "", map[string]string{})

	for name, r := range map[string]resp{"wrong password": wrongPassword, "unknown user": unknownUser, "malformed email": badEmail, "empty": emptyBoth} {
		if r.Status != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, r.Status)
		}
		if r.Body != wrongPassword.Body {
			t.Errorf("%s: body %q differs from wrong-password body %q, which would let a caller enumerate accounts", name, r.Body, wrongPassword.Body)
		}
	}
}

func TestSignupValidationAndConflicts(t *testing.T) {
	h := newHarness(t)
	h.signup("taken@example.com", "taken")

	valid := func(mut func(m map[string]string)) map[string]string {
		m := map[string]string{
			"email": "new@example.com", "display_name": "New", "password": testPassword,
			"organization_name": "New Org", "organization_slug": "new-org",
		}
		mut(m)
		return m
	}
	tests := []struct {
		name  string
		body  map[string]string
		want  int
		field string
	}{
		{"short password", valid(func(m map[string]string) { m["password"] = "short" }), 422, "password"},
		{"bad email", valid(func(m map[string]string) { m["email"] = "nope" }), 422, "email"},
		{"empty display name", valid(func(m map[string]string) { m["display_name"] = "" }), 422, "display_name"},
		{"bad slug", valid(func(m map[string]string) { m["organization_slug"] = "Not A Slug" }), 422, "organization_slug"},
		{"duplicate email", valid(func(m map[string]string) { m["email"] = "TAKEN@example.com" }), 409, ""},
		{"duplicate slug", valid(func(m map[string]string) { m["organization_slug"] = "taken" }), 409, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := h.do("POST", "/v1/auth/signup", "", tc.body)
			if r.Status != tc.want {
				t.Fatalf("status = %d, want %d (%s)", r.Status, tc.want, r.Body)
			}
			if tc.field != "" && r.JSON["error"].(map[string]any)["field"] != tc.field {
				t.Errorf("field = %v, want %s", r.JSON["error"], tc.field)
			}
			if strings.Contains(r.Body, testPassword) {
				t.Error("error response echoes the password")
			}
		})
	}
}

func TestSignupClosedAllowsOnlyTheBootstrapAccount(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.AllowSignup = false })
	body := func(email, slug string) map[string]string {
		return map[string]string{"email": email, "display_name": "X", "password": testPassword, "organization_name": "O", "organization_slug": slug}
	}
	h.want(h.do("POST", "/v1/auth/signup", "", body("first@example.com", "first")), http.StatusCreated)
	r := h.want(h.do("POST", "/v1/auth/signup", "", body("second@example.com", "second")), http.StatusForbidden)
	if r.JSON["error"].(map[string]any)["code"] != "signup_disabled" {
		t.Errorf("error = %v", r.JSON)
	}
}

func TestSessionExpiry(t *testing.T) {
	h := newHarness(t) // session TTL is one hour
	a := h.signup("a@example.com", "alpha")

	h.clock.Advance(59 * time.Minute)
	h.want(h.do("GET", "/v1/me", a.Token, nil), http.StatusOK)

	h.clock.Advance(2 * time.Minute)
	h.want(h.do("GET", "/v1/me", a.Token, nil), http.StatusUnauthorized)

	// Logging in again gives a fresh, working session.
	login := h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": a.Email, "password": testPassword}), http.StatusOK)
	h.want(h.do("GET", "/v1/me", str(h, login.JSON, "token"), nil), http.StatusOK)
}

func TestEachLoginIsAnIndependentSession(t *testing.T) {
	h := newHarness(t)
	a := h.signup("a@example.com", "alpha")
	second := h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": a.Email, "password": testPassword}), http.StatusOK)
	t2 := str(h, second.JSON, "token")
	if t2 == a.Token {
		t.Fatal("two logins produced the same token")
	}
	h.want(h.do("POST", "/v1/auth/logout", a.Token, nil), http.StatusNoContent)
	h.want(h.do("GET", "/v1/me", t2, nil), http.StatusOK) // logging out one session leaves the other
}

func TestAuthRateLimiting(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.AuthPerMinute, o.AuthBurst = 6, 3 }) // 1 per 10s, burst 3
	attempt := func() resp {
		return h.do("POST", "/v1/auth/login", "", map[string]string{"email": "x@example.com", "password": "wrong password here"})
	}
	for i := 0; i < 3; i++ {
		h.want(attempt(), http.StatusUnauthorized)
	}
	r := h.want(attempt(), http.StatusTooManyRequests)
	if r.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	// A correct password does not bypass the limit either.
	h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": "x@example.com", "password": testPassword}), http.StatusTooManyRequests)

	h.clock.Advance(11 * time.Second)
	h.want(attempt(), http.StatusUnauthorized) // one token refilled
	h.want(attempt(), http.StatusTooManyRequests)
}
