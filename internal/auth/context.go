package auth

import (
	"context"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

type userKey struct{}

// WithUser returns a context carrying the authenticated user.
func WithUser(ctx context.Context, u storage.User) context.Context {
	return context.WithValue(ctx, userKey{}, u)
}

// UserFrom returns the authenticated user, if the request passed authentication.
func UserFrom(ctx context.Context) (storage.User, bool) {
	u, ok := ctx.Value(userKey{}).(storage.User)
	return u, ok
}

type agentKey struct{}

// WithAgent returns a context carrying the authenticated agent identity.
func WithAgent(ctx context.Context, a storage.AgentIdentity) context.Context {
	return context.WithValue(ctx, agentKey{}, a)
}

// AgentFrom returns the authenticated agent, if the request passed agent authentication.
func AgentFrom(ctx context.Context) (storage.AgentIdentity, bool) {
	a, ok := ctx.Value(agentKey{}).(storage.AgentIdentity)
	return a, ok
}
