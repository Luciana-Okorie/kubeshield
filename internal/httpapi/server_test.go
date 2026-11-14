package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyAuth(t *testing.T) {
	handler := apiKeyAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), "secret")
	for _, tc := range []struct {
		name, path, auth string
		want             int
	}{
		{"health", "/healthz", "", 204},
		{"missing", "/api/v1/findings", "", 401},
		{"invalid", "/api/v1/findings", "Bearer wrong", 401},
		{"valid", "/api/v1/findings", "Bearer secret", 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.path, nil)
			r.Header.Set("Authorization", tc.auth)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
		})
	}
}
