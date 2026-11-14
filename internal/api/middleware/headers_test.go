package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSecurityHeaders(t *testing.T) {
	for _, hsts := range []bool{false, true} {
		h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }), SecurityHeaders(hsts))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		for k, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"Cache-Control":          "no-store",
			"Referrer-Policy":        "no-referrer",
		} {
			if got := rec.Header().Get(k); got != want {
				t.Errorf("hsts=%v %s = %q, want %q", hsts, k, got, want)
			}
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Error("no Content-Security-Policy")
		}
		if got := rec.Header().Get("Strict-Transport-Security") != ""; got != hsts {
			t.Errorf("HSTS present = %v, want %v", got, hsts)
		}
	}
}
