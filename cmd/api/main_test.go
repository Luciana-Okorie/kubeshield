package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/config"
	"github.com/luciana-okorie/kubeshield/internal/storage"
	"github.com/luciana-okorie/kubeshield/internal/storage/memory"
)

func TestIsLoopback(t *testing.T) {
	tests := map[string]bool{
		"127.0.0.1:8110":   true,
		"[::1]:8110":       true,
		"localhost:8110":   true,
		"127.1.2.3:80":     true,
		"0.0.0.0:8110":     false,
		":8110":            false,
		"[::]:8110":        false,
		"192.168.1.5:8110": false,
		"example.com:443":  false,
		"garbage":          false,
	}
	for addr, want := range tests {
		if got := isLoopback(addr); got != want {
			t.Errorf("isLoopback(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestSessionJanitor(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	store := memory.New()
	user, _, err := store.CreateAccount(ctx, storage.NewAccount{Email: "a@example.com", DisplayName: "A", PasswordHash: "h", OrgName: "O", OrgSlug: "o-org"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old, live := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	if err := store.CreateSession(ctx, user.ID, old, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(ctx, user.ID, live, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		runSessionJanitor(ctx, store, slog.New(slog.NewTextHandler(io.Discard, nil)), 5*time.Millisecond, 24*time.Hour, time.Now)
		close(done)
	}()

	// The run at startup removes the long-expired session; the live one survives.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if n, _ := store.DeleteExpiredSessions(ctx, now.Add(-24*time.Hour)); n == 0 {
			break // nothing left for us to delete: the janitor already did
		}
		if time.Now().After(deadline) {
			t.Fatal("janitor did not remove the expired session")
		}
	}
	if _, err := store.UserBySession(ctx, live, now); err != nil {
		t.Errorf("live session was removed: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("janitor did not stop when its context was cancelled")
	}
}

// A store that fails must not stop the janitor.
type failingStore struct {
	storage.Store
	calls chan struct{}
}

func (f failingStore) DeleteExpiredSessions(context.Context, time.Time) (int64, error) {
	f.calls <- struct{}{}
	return 0, errors.New("database is down")
}

func TestSessionJanitorSurvivesErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := failingStore{calls: make(chan struct{}, 100)}
	go runSessionJanitor(ctx, f, slog.New(slog.NewTextHandler(io.Discard, nil)), 5*time.Millisecond, time.Hour, time.Now)
	for i := 0; i < 3; i++ {
		select {
		case <-f.calls:
		case <-time.After(2 * time.Second):
			t.Fatalf("janitor stopped after %d passes", i)
		}
	}
}

// Every setting that changes behaviour must actually reach the router.
func TestRouteOptionsCarryEveryConfigSetting(t *testing.T) {
	env := map[string]string{
		config.EnvSessionTTL:   "90m",
		config.EnvAllowSignup:  "true",
		config.EnvTLSCertFile:  "c.pem",
		config.EnvTLSKeyFile:   "k.pem",
		config.EnvTrustedProxy: "10.0.0.0/8, 192.0.2.1",
	}
	cfg, err := config.Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	o := routeOptions(cfg)
	if o.SessionTTL != 90*time.Minute || !o.AllowSignup || !o.HSTS || len(o.TrustedProxies) != 2 {
		t.Errorf("options = %+v; a config setting was dropped on the way to the router", o)
	}

	cfg, _ = config.Load(func(string) string { return "" })
	if o := routeOptions(cfg); o.HSTS || o.AllowSignup || len(o.TrustedProxies) != 0 {
		t.Errorf("defaults leaked into options: %+v", o)
	}
}
