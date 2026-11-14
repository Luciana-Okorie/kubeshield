// Package routes wires URL patterns to handlers and middleware.
package routes

import (
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/api/clientip"
	"github.com/luciana-okorie/kubeshield/internal/api/handlers"
	"github.com/luciana-okorie/kubeshield/internal/api/middleware"
	"github.com/luciana-okorie/kubeshield/internal/auth"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// Options configures the API. The zero value is safe: closed signup, 12h sessions,
// production password cost, the real clock and default rate limits.
type Options struct {
	SessionTTL  time.Duration
	AllowSignup bool

	// TrustedProxies are the proxies whose X-Forwarded-For header is believed. Empty means
	// none: the client is the TCP peer.
	TrustedProxies []netip.Prefix
	// HSTS adds Strict-Transport-Security. Set it only when this server terminates TLS.
	HSTS bool

	// Now is the clock for session expiry and rate limiting. Tests inject a fake.
	Now func() time.Time
	// PasswordIterations overrides PBKDF2 cost. Only tests should set it (to keep them fast).
	PasswordIterations int

	// Requests per minute per client. Login and signup get the strict limit because
	// they are the endpoints an attacker hammers to guess passwords.
	AuthPerMinute, AuthBurst int
	APIPerMinute, APIBurst   int
}

func (o *Options) defaults() {
	if o.SessionTTL <= 0 {
		o.SessionTTL = 12 * time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.AuthPerMinute <= 0 {
		o.AuthPerMinute = 10
	}
	if o.AuthBurst <= 0 {
		o.AuthBurst = 5
	}
	if o.APIPerMinute <= 0 {
		o.APIPerMinute = 600
	}
	if o.APIBurst <= 0 {
		o.APIBurst = 100
	}
}

// New builds the API's root handler.
func New(logger *slog.Logger, version string, store storage.Store, opts Options) http.Handler {
	opts.defaults()

	mux := http.NewServeMux()
	authH := handlers.NewAuth(store, logger, handlers.AuthOptions{
		Hasher:      auth.NewPasswordHasher(opts.PasswordIterations),
		SessionTTL:  opts.SessionTTL,
		AllowSignup: opts.AllowSignup,
		Now:         opts.Now,
	})
	res := handlers.NewResources(store, logger)

	strict := middleware.NewRateLimiter(opts.AuthPerMinute, opts.AuthBurst, opts.Now).Middleware()
	general := middleware.NewRateLimiter(opts.APIPerMinute, opts.APIBurst, opts.Now).Middleware()
	userAuth := middleware.Authenticate(store, logger, opts.Now)
	agentAuth := middleware.AuthenticateAgent(store, logger, opts.Now)

	// protect puts a handler behind the general rate limit and user authentication.
	// The limiter runs first so unauthenticated floods are cut off before any database lookup.
	protect := func(h http.HandlerFunc) http.Handler {
		return middleware.Chain(h, general, userAuth)
	}

	// Method-qualified patterns (Go 1.22+): other methods get an automatic 405.
	mux.Handle("GET /healthz", handlers.NewHealth(version))

	// Public, strictly rate limited.
	mux.Handle("POST /v1/auth/signup", middleware.Chain(http.HandlerFunc(authH.Signup), strict))
	mux.Handle("POST /v1/auth/login", middleware.Chain(http.HandlerFunc(authH.Login), strict))

	// User session.
	mux.Handle("POST /v1/auth/logout", protect(authH.Logout))
	mux.Handle("GET /v1/me", protect(authH.Me))

	// Organizations: membership and role are checked inside each handler.
	mux.Handle("POST /v1/organizations", protect(res.CreateOrganization))
	mux.Handle("GET /v1/organizations", protect(res.ListOrganizations))
	mux.Handle("GET /v1/organizations/{orgID}", protect(res.GetOrganization))
	mux.Handle("GET /v1/organizations/{orgID}/audit-logs", protect(res.ListAudit))

	mux.Handle("GET /v1/organizations/{orgID}/members", protect(res.ListMembers))
	mux.Handle("POST /v1/organizations/{orgID}/members", protect(res.AddMember))
	mux.Handle("PATCH /v1/organizations/{orgID}/members/{userID}", protect(res.SetMemberRole))
	mux.Handle("DELETE /v1/organizations/{orgID}/members/{userID}", protect(res.RemoveMember))

	mux.Handle("POST /v1/organizations/{orgID}/clusters", protect(res.CreateCluster))
	mux.Handle("GET /v1/organizations/{orgID}/clusters", protect(res.ListClusters))
	mux.Handle("GET /v1/organizations/{orgID}/clusters/{clusterID}", protect(res.GetCluster))

	mux.Handle("POST /v1/organizations/{orgID}/clusters/{clusterID}/scans", protect(res.CreateScan))
	mux.Handle("GET /v1/organizations/{orgID}/clusters/{clusterID}/scans", protect(res.ListScans))
	mux.Handle("GET /v1/organizations/{orgID}/scans/{scanID}", protect(res.GetScan))
	mux.Handle("GET /v1/organizations/{orgID}/scans/{scanID}/results", protect(res.GetScanResult))

	mux.Handle("POST /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens", protect(res.CreateAgentToken))
	mux.Handle("GET /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens", protect(res.ListAgentTokens))
	mux.Handle("DELETE /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens/{tokenID}", protect(res.RevokeAgentToken))

	// Agent side: authenticated by agent token, not by user session.
	mux.Handle("GET /v1/agent/whoami", middleware.Chain(http.HandlerFunc(res.AgentWhoAmI), general, agentAuth))
	mux.Handle("GET /v1/agent/scans/next", middleware.Chain(http.HandlerFunc(res.AgentNextScan), general, agentAuth))
	mux.Handle("POST /v1/agent/scans/{scanID}/results", middleware.Chain(http.HandlerFunc(res.AgentSubmitScanResult), general, agentAuth))
	mux.Handle("POST /v1/agent/scans/{scanID}/failure", middleware.Chain(http.HandlerFunc(res.AgentFailScan), general, agentAuth))

	// First is outermost. The client address is resolved first so logging can record it, and
	// logging comes before recovery so requests that panic are still logged with their 500.
	return middleware.Chain(mux,
		clientip.Middleware(opts.TrustedProxies),
		middleware.Logging(logger),
		middleware.Recover(logger),
		middleware.SecurityHeaders(opts.HSTS),
	)
}
