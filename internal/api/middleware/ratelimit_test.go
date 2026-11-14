package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestRateLimiterBurstThenRefill(t *testing.T) {
	c := &clock{t: time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)}
	l := NewRateLimiter(60, 3, c.now) // 1 token per second, burst 3

	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatalf("request %d refused inside the burst", i+1)
		}
	}
	ok, wait := l.allow("a")
	if ok {
		t.Fatal("4th request allowed; burst is 3")
	}
	if wait <= 0 || wait > time.Second {
		t.Errorf("retryAfter = %v, want within (0, 1s]", wait)
	}

	c.advance(1100 * time.Millisecond)
	if ok, _ := l.allow("a"); !ok {
		t.Error("refused after a token should have refilled")
	}
	if ok, _ := l.allow("a"); ok {
		t.Error("allowed twice after refilling only one token")
	}

	c.advance(time.Hour)
	for i := 0; i < 3; i++ {
		if ok, _ := l.allow("a"); !ok {
			t.Fatal("bucket did not refill to the burst size after a long idle")
		}
	}
	if ok, _ := l.allow("a"); ok {
		t.Error("refill exceeded the burst size")
	}
}

func TestRateLimiterClientsAreIndependent(t *testing.T) {
	c := &clock{t: time.Now()}
	l := NewRateLimiter(1, 1, c.now)
	if ok, _ := l.allow("a"); !ok {
		t.Fatal("first client refused")
	}
	if ok, _ := l.allow("a"); ok {
		t.Fatal("first client not limited")
	}
	if ok, _ := l.allow("b"); !ok {
		t.Error("second client was limited by the first client's traffic")
	}
}

func TestClientKey(t *testing.T) {
	tests := []struct{ in, want string }{
		{"203.0.113.9:51000", "203.0.113.9"},
		{"[::ffff:203.0.113.9]:51000", "203.0.113.9"},
		{"[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:443", "2001:db8:1:2::"},
		{"[2001:db8:1:2:1111:2222:3333:4444]:80", "2001:db8:1:2::"}, // same /64, same key
		{"[2001:db8:1:3::1]:80", "2001:db8:1:3::"},
		{"not-an-address", "not-an-address"},
	}
	for _, tc := range tests {
		if got := clientKey(tc.in); got != tc.want {
			t.Errorf("clientKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestRateLimiterSweepForgetsIdleClientsAndStaysBounded(t *testing.T) {
	c := &clock{t: time.Now()}
	l := NewRateLimiter(60, 2, c.now)

	for i := 0; i < 50; i++ {
		l.allow("client-" + strconv.Itoa(i))
	}
	if got := len(l.buckets); got != 50 {
		t.Fatalf("tracked = %d, want 50", got)
	}
	c.advance(10 * time.Minute) // everyone is fully refilled and forgettable
	l.allow("trigger")
	if got := len(l.buckets); got > 2 {
		t.Errorf("tracked after sweep = %d, want idle clients dropped", got)
	}

	// A flood of distinct clients must not grow the map without bound.
	for i := 0; i < maxTrackedClients+500; i++ {
		l.allow("flood-" + strconv.Itoa(i))
	}
	if got := len(l.buckets); got > maxTrackedClients {
		t.Errorf("tracked = %d, want at most %d", got, maxTrackedClients)
	}
}

func TestRateLimitMiddleware429(t *testing.T) {
	c := &clock{t: time.Now()}
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		NewRateLimiter(6, 1, c.now).Middleware()) // 1 token per 10s

	do := func(forwardedFor string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "198.51.100.7:4000"
		if forwardedFor != "" {
			req.Header.Set("X-Forwarded-For", forwardedFor)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := do(""); rec.Code != http.StatusNoContent {
		t.Fatalf("first request = %d", rec.Code)
	}
	// Spoofing X-Forwarded-For must not buy a fresh bucket.
	rec := do("192.0.2.200")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "10" {
		t.Errorf("Retry-After = %q, want 10", got)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if body := rec.Body.String(); body == "" || !strings.Contains(body, `"rate_limited"`) {
		t.Errorf("body = %q, want the standard error shape with code rate_limited", body)
	}
}
