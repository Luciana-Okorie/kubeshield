package clientip

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func req(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestParseTrusted(t *testing.T) {
	got, err := ParseTrusted(" 10.0.0.0/8, 192.0.2.7 ,2001:db8::/32,, ::ffff:198.51.100.1 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || got[0].String() != "10.0.0.0/8" || got[1].String() != "192.0.2.7/32" || got[3].String() != "198.51.100.1/32" {
		t.Errorf("parsed = %v", got)
	}
	if got, err := ParseTrusted(""); err != nil || got != nil {
		t.Errorf("empty list = %v, %v", got, err)
	}
	for _, bad := range []string{"nope", "10.0.0.0/33", "10.0.0.1, banana"} {
		if _, err := ParseTrusted(bad); err == nil {
			t.Errorf("ParseTrusted(%q) accepted", bad)
		}
	}
}

func TestResolve(t *testing.T) {
	trusted, _ := ParseTrusted("10.0.0.0/8, 35.191.0.0/16")
	tests := []struct {
		name string
		r    *http.Request
		tr   bool
		want string
	}{
		{"direct client, no proxies trusted", req("203.0.113.5:4000"), false, "203.0.113.5"},
		{"forged header from an untrusted peer is ignored", req("203.0.113.5:4000", "1.2.3.4"), true, "203.0.113.5"},
		{"trusted proxy reports the client", req("10.0.0.2:80", "198.51.100.9"), true, "198.51.100.9"},
		{"trusted proxy chain", req("10.0.0.2:80", "198.51.100.9, 35.191.1.1"), true, "198.51.100.9"},
		{"client-forged left entries are ignored", req("10.0.0.2:80", "1.2.3.4, 198.51.100.9"), true, "198.51.100.9"},
		{"header split over several lines", req("10.0.0.2:80", "1.2.3.4", "198.51.100.9"), true, "198.51.100.9"},
		{"trusted peer, no header", req("10.0.0.2:80"), true, "10.0.0.2"},
		{"trusted peer, only proxies in header", req("10.0.0.2:80", "10.1.1.1, 35.191.2.2"), true, "10.0.0.2"},
		{"garbage in header is not guessed at", req("10.0.0.2:80", "1.2.3.4, not-an-ip"), true, "10.0.0.2"},
		{"trusted proxy but trust list empty", req("10.0.0.2:80", "198.51.100.9"), false, "10.0.0.2"},
		{"ipv6 client", req("[2001:db8::1]:443"), true, "2001:db8::1"},
		{"ipv4-mapped peer", req("[::ffff:203.0.113.5]:4000"), true, "203.0.113.5"},
		{"unparseable peer", req("garbage"), true, ""},
	}
	for _, tc := range tests {
		tr := trusted
		if !tc.tr {
			tr = nil
		}
		if got := Resolve(tc.r, tr); got != tc.want {
			t.Errorf("%s: Resolve = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestMiddlewareAndFromRequest(t *testing.T) {
	trusted, _ := ParseTrusted("10.0.0.0/8")
	var seen string
	h := Middleware(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { seen = FromRequest(r) }))
	h.ServeHTTP(httptest.NewRecorder(), req("10.0.0.2:80", "198.51.100.9"))
	if seen != "198.51.100.9" {
		t.Errorf("through middleware = %q", seen)
	}
	// Without the middleware, only the peer is believed.
	if got := FromRequest(req("203.0.113.5:1", "1.2.3.4")); got != "203.0.113.5" {
		t.Errorf("without middleware = %q", got)
	}
}
