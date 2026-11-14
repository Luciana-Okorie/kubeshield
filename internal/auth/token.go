package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// Token prefixes. They make a leaked token recognisable (and greppable by secret
// scanners) and let the server reject the wrong kind of token without a database lookup.
const (
	UserTokenPrefix  = "ksu_"
	AgentTokenPrefix = "ksa_"

	tokenRandomBytes = 32 // 256 bits
	displayChars     = 6
)

// Token is a freshly generated bearer token. Secret is shown to its owner exactly
// once; only Hash is stored. Because the secret is 256 bits of randomness, a plain
// SHA-256 is enough to store it safely (unlike a password, it cannot be guessed).
type Token struct {
	Secret  string // "ksu_<43 chars>"; give to the client, never store or log
	Hash    []byte // SHA-256 of Secret, 32 bytes; this is what the database holds
	Display string // short non-secret label such as "ksa_Ab3dE9", safe to show in a UI
}

// NewToken generates a token with the given prefix.
func NewToken(prefix string) (Token, error) {
	raw := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, fmt.Errorf("generate token: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	secret := prefix + body
	return Token{
		Secret:  secret,
		Hash:    HashToken(secret),
		Display: prefix + body[:displayChars],
	}, nil
}

// HashToken returns the SHA-256 digest used to look a presented token up.
func HashToken(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// BearerToken extracts the token from an "Authorization: Bearer <token>" header.
func BearerToken(r *http.Request) (string, bool) {
	const scheme = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(scheme) || !strings.EqualFold(h[:len(scheme)], scheme) {
		return "", false
	}
	token := strings.TrimSpace(h[len(scheme):])
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", false
	}
	return token, true
}
