package routes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/storage"
	"github.com/luciana-okorie/kubeshield/internal/storage/memory"
)

const testPassword = "correct horse battery staple"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	t     *testing.T
	srv   *httptest.Server
	store *memory.Store
	clock *fakeClock
}

// resp is a decoded response. Body keeps the raw bytes for "must not contain" checks.
type resp struct {
	Status int
	Header http.Header
	JSON   map[string]any
	Body   string
}

// newHarness starts the API over real HTTP with a fast password hash, a fake clock,
// open signup and rate limits high enough to stay out of the way unless a test lowers them.
func newHarness(t *testing.T, mutate ...func(*Options)) *harness {
	t.Helper()
	clock := &fakeClock{t: time.Date(2026, 11, 6, 9, 0, 0, 0, time.UTC)}
	opts := Options{
		AllowSignup: true, SessionTTL: time.Hour, Now: clock.Now, PasswordIterations: 1000,
		AuthPerMinute: 6000, AuthBurst: 1000, APIPerMinute: 60000, APIBurst: 10000,
	}
	for _, m := range mutate {
		m(&opts)
	}
	store := memory.New()
	srv := httptest.NewServer(New(slog.New(slog.NewTextHandler(io.Discard, nil)), "test", store, opts))
	t.Cleanup(srv.Close)
	return &harness{t: t, srv: srv, store: store, clock: clock}
}

func (h *harness) do(method, path, token string, body any) resp {
	h.t.Helper()
	return h.doWith(method, path, token, body, nil)
}

func (h *harness) doWith(method, path, token string, body any, headers map[string]string) resp {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = bytes.NewBufferString(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			h.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		h.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{Status: res.StatusCode, Header: res.Header, Body: string(raw)}
	_ = json.Unmarshal(raw, &out.JSON)
	return out
}

func (h *harness) want(r resp, status int) resp {
	h.t.Helper()
	if r.Status != status {
		h.t.Fatalf("status = %d, want %d (body: %s)", r.Status, status, r.Body)
	}
	return r
}

func str(h *harness, m map[string]any, key string) string {
	h.t.Helper()
	v, ok := m[key].(string)
	if !ok {
		h.t.Fatalf("field %q missing or not a string in %v", key, m)
	}
	return v
}

// account is a signed-up, logged-in user with the organization they own.
type account struct {
	Token, UserID, Email, OrgID string
}

func (h *harness) signup(email, slug string) account {
	h.t.Helper()
	r := h.want(h.do("POST", "/v1/auth/signup", "", map[string]string{
		"email": email, "display_name": "Test User", "password": testPassword,
		"organization_name": "Org " + slug, "organization_slug": slug,
	}), http.StatusCreated)
	user := r.JSON["user"].(map[string]any)
	org := r.JSON["organization"].(map[string]any)
	login := h.want(h.do("POST", "/v1/auth/login", "", map[string]string{"email": email, "password": testPassword}), http.StatusOK)
	return account{Token: str(h, login.JSON, "token"), UserID: str(h, user, "id"), Email: email, OrgID: str(h, org, "id")}
}

func (h *harness) cluster(a account, name string) string {
	h.t.Helper()
	r := h.want(h.do("POST", "/v1/organizations/"+a.OrgID+"/clusters", a.Token,
		map[string]string{"name": name, "provider": "kind"}), http.StatusCreated)
	return str(h, r.JSON, "id")
}

// member signs up a fresh user and gives them a role in owner's organization.
func (h *harness) member(owner account, email, slug string, role storage.Role) account {
	h.t.Helper()
	a := h.signup(email, slug)
	if _, err := h.store.AddMember(context.Background(), owner.OrgID, a.UserID, role); err != nil {
		h.t.Fatal(err)
	}
	return a
}

// auditEntries returns the org-less audit entries (login, logout...) written for a user.
// They are not reachable through the API; this reads them straight from the store.
func (h *harness) auditEntries(userID string) []storage.AuditEntry {
	h.t.Helper()
	all, err := h.store.AllAudit(context.Background())
	if err != nil {
		h.t.Fatal(err)
	}
	var out []storage.AuditEntry
	for _, e := range all {
		if e.OrganizationID == nil && e.ActorUserID != nil && *e.ActorUserID == userID {
			out = append(out, e)
		}
	}
	return out
}
