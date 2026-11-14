package middleware

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luciana-okorie/kubeshield/internal/api/clientip"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestRecoverReturns500AndLogs(t *testing.T) {
	var buf bytes.Buffer
	h := Recover(testLogger(&buf))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "internal server error") {
		t.Errorf("body = %q", rec.Body.String())
	}
	if !strings.Contains(buf.String(), "panic recovered") || !strings.Contains(buf.String(), "boom") {
		t.Errorf("panic not logged: %q", buf.String())
	}
}

func TestRecoverPassesThroughNormalResponses(t *testing.T) {
	h := Recover(testLogger(&bytes.Buffer{}))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want 418", rec.Code)
	}
}

func TestLoggingRecordsRequest(t *testing.T) {
	var buf bytes.Buffer
	h := Logging(testLogger(&buf))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/missing", nil))

	out := buf.String()
	for _, want := range []string{"method=GET", "path=/missing", "status=404"} {
		if !strings.Contains(out, want) {
			t.Errorf("log %q missing %q", out, want)
		}
	}
}

func TestLoggingDefaultsTo200(t *testing.T) {
	var buf bytes.Buffer
	h := Logging(testLogger(&buf))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if !strings.Contains(buf.String(), "status=200") {
		t.Errorf("log %q missing status=200", buf.String())
	}
}

func TestChainOrderFirstIsOutermost(t *testing.T) {
	var order []string
	mk := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		order = append(order, "handler")
	}), mk("a"), mk("b"))

	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if got := strings.Join(order, ","); got != "a,b,handler" {
		t.Errorf("order = %s, want a,b,handler", got)
	}
}

func TestLoggingRecordsTheResolvedClientAddress(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	trusted, _ := clientip.ParseTrusted("10.0.0.0/8")

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		clientip.Middleware(trusted), Logging(logger))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.RemoteAddr = "10.0.0.2:5000"
	req.Header.Set("X-Forwarded-For", "198.51.100.9")
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if !strings.Contains(out, "client_ip=198.51.100.9") || !strings.Contains(out, "remote_addr=10.0.0.2:5000") {
		t.Errorf("log line = %q, want both the proxy (remote_addr) and the client (client_ip)", out)
	}
}
