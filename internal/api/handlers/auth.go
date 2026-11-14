package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
	"github.com/luciana-okorie/kubeshield/internal/auth"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// Auth serves signup, login, logout and the current-user endpoint.
type Auth struct {
	store       storage.Store
	logger      *slog.Logger
	hasher      *auth.PasswordHasher
	sessionTTL  time.Duration
	allowSignup bool
	now         func() time.Time
}

// AuthOptions configures the auth handlers.
type AuthOptions struct {
	Hasher      *auth.PasswordHasher
	SessionTTL  time.Duration
	AllowSignup bool
	Now         func() time.Time
}

// NewAuth returns the auth handler set.
func NewAuth(store storage.Store, logger *slog.Logger, o AuthOptions) *Auth {
	return &Auth{store: store, logger: logger, hasher: o.Hasher, sessionTTL: o.SessionTTL, allowSignup: o.AllowSignup, now: o.Now}
}

type signupRequest struct {
	Email            string `json:"email"`
	DisplayName      string `json:"display_name"`
	Password         string `json:"password"`
	OrganizationName string `json:"organization_name"`
	OrganizationSlug string `json:"organization_slug"`
}

// Signup handles POST /v1/auth/signup. It creates a user and the organization they own.
// It does not log the user in; the client calls login next.
func (a *Auth) Signup(w http.ResponseWriter, r *http.Request) {
	// Cheap gate first: when signup is closed, only the very first account is allowed.
	if !a.allowSignup {
		n, err := a.store.CountUsers(r.Context())
		if err != nil {
			httpx.StoreError(w, r, a.logger, err)
			return
		}
		if n > 0 {
			httpx.Error(w, http.StatusForbidden, "signup_disabled", "signup is closed on this server")
			return
		}
	}

	var req signupRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if err := auth.ValidatePassword(req.Password); err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}
	in := storage.NewAccount{
		Email: req.Email, DisplayName: req.DisplayName, PasswordHash: "-",
		OrgName: req.OrganizationName, OrgSlug: req.OrganizationSlug,
		// When signup is closed the store re-checks "no accounts exist" atomically with the
		// insert, so two simultaneous first signups cannot both win.
		OnlyIfNoUsers: !a.allowSignup,
	}
	// Validate everything before paying for a password hash.
	if err := in.Validate(); err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}
	hash, err := a.hasher.Hash(req.Password)
	if err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}
	in.PasswordHash = hash

	user, org, err := a.store.CreateAccount(r.Context(), in)
	if errors.Is(err, storage.ErrConflict) {
		httpx.Error(w, http.StatusConflict, "conflict", "email or organization slug is already in use")
		return
	}
	if err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}

	audit(r.Context(), a.store, a.logger, r, storage.AuditEntry{
		OrganizationID: &org.ID, ActorUserID: &user.ID, ActorType: storage.ActorUser,
		Action: "account.created", TargetType: "organization", TargetID: org.ID,
	})
	httpx.JSON(w, http.StatusCreated, struct {
		User         storage.User         `json:"user"`
		Organization storage.Organization `json:"organization"`
	}{user, org})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// invalidCredentials is the single answer for every login failure, so the response
// never says whether the email exists, the password was wrong or the account is disabled.
func invalidCredentials(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="kubeshield"`)
	httpx.Error(w, http.StatusUnauthorized, "invalid_credentials", "invalid email or password")
}

// Login handles POST /v1/auth/login and returns a session token shown only this once.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}

	email, err := storage.NormalizeEmail(req.Email)
	if err != nil {
		a.hasher.BurnTime(req.Password)
		invalidCredentials(w)
		return
	}
	user, err := a.store.GetUserByEmail(r.Context(), email)
	if errors.Is(err, storage.ErrNotFound) {
		a.hasher.BurnTime(req.Password) // same cost as a real check
		invalidCredentials(w)
		return
	}
	if err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}

	if !auth.VerifyPassword(user.PasswordHash, req.Password) || user.DisabledAt != nil {
		audit(r.Context(), a.store, a.logger, r, storage.AuditEntry{
			ActorUserID: &user.ID, ActorType: storage.ActorUser, Action: "auth.login_failed",
		})
		invalidCredentials(w)
		return
	}

	tok, err := auth.NewToken(auth.UserTokenPrefix)
	if err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}
	expires := a.now().UTC().Add(a.sessionTTL)
	if err := a.store.CreateSession(r.Context(), user.ID, tok.Hash, expires); err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}

	audit(r.Context(), a.store, a.logger, r, storage.AuditEntry{
		ActorUserID: &user.ID, ActorType: storage.ActorUser, Action: "auth.login",
	})
	noStore(w)
	httpx.JSON(w, http.StatusOK, struct {
		Token     string       `json:"token"`
		ExpiresAt time.Time    `json:"expires_at"`
		User      storage.User `json:"user"`
	}{tok.Secret, expires, user})
}

// Logout handles POST /v1/auth/logout and revokes the session that made the request.
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	tok, hasTok := auth.BearerToken(r)
	if !ok || !hasTok {
		httpx.Unauthorized(w)
		return
	}
	if err := a.store.RevokeSession(r.Context(), auth.HashToken(tok)); err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}
	audit(r.Context(), a.store, a.logger, r, storage.AuditEntry{
		ActorUserID: &user.ID, ActorType: storage.ActorUser, Action: "auth.logout",
	})
	w.WriteHeader(http.StatusNoContent)
}

// Me handles GET /v1/me.
func (a *Auth) Me(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	orgs, err := a.store.ListOrganizationsFor(r.Context(), user.ID)
	if err != nil {
		httpx.StoreError(w, r, a.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, struct {
		User          storage.User            `json:"user"`
		Organizations []storage.OrgMembership `json:"organizations"`
	}{user, httpx.Items(orgs).Items})
}
