// Package auth holds password hashing, token handling and request-context helpers.
// It uses only the Go standard library.
package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

const (
	// DefaultPasswordIterations follows OWASP's guidance for PBKDF2-HMAC-SHA256 (600,000).
	DefaultPasswordIterations = 600_000

	// maxPasswordIterations bounds the work Verify will do for an encoded hash, so a
	// corrupt or hostile stored value cannot turn a login attempt into a CPU stall.
	maxPasswordIterations = 10_000_000

	saltBytes  = 16
	keyBytes   = 32
	hashScheme = "pbkdf2-sha256"

	MinPasswordLength = 12
	MaxPasswordLength = 128
)

var b64 = base64.RawStdEncoding

// ValidatePassword enforces length only. Length is what protects a password;
// composition rules mostly push people toward predictable substitutions.
func ValidatePassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < MinPasswordLength || n > MaxPasswordLength {
		return &storage.ValidationError{
			Field:   "password",
			Message: fmt.Sprintf("must be between %d and %d characters", MinPasswordLength, MaxPasswordLength),
		}
	}
	return nil
}

// PasswordHasher hashes passwords with PBKDF2-HMAC-SHA256 and a random salt per password.
// Encoded form: pbkdf2-sha256$<iterations>$<salt>$<key>, so the cost can be raised later
// while old hashes keep verifying.
type PasswordHasher struct {
	iterations int
	dummy      func() string
}

// NewPasswordHasher returns a hasher using the given iteration count.
// Zero or negative means DefaultPasswordIterations. Production code should pass 0.
func NewPasswordHasher(iterations int) *PasswordHasher {
	if iterations <= 0 {
		iterations = DefaultPasswordIterations
	}
	h := &PasswordHasher{iterations: iterations}
	h.dummy = sync.OnceValue(func() string {
		encoded, err := h.Hash("kubeshield-timing-equaliser")
		if err != nil {
			panic(fmt.Sprintf("auth: cannot build timing hash: %v", err))
		}
		return encoded
	})
	return h
}

// Hash returns the encoded hash of password.
func (h *PasswordHasher) Hash(password string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, h.iterations, keyBytes)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	return fmt.Sprintf("%s$%d$%s$%s", hashScheme, h.iterations, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// BurnTime spends about as long as a real verification. Call it when a login names
// an account that does not exist, so response time does not reveal which emails are registered.
func (h *PasswordHasher) BurnTime(password string) {
	VerifyPassword(h.dummy(), password)
}

// VerifyPassword reports whether password matches the encoded hash. Malformed
// input returns false rather than an error or a panic.
func VerifyPassword(encoded, password string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != hashScheme {
		return false
	}
	iterations, err := strconv.Atoi(parts[1])
	if err != nil || iterations < 1 || iterations > maxPasswordIterations {
		return false
	}
	salt, err := b64.DecodeString(parts[2])
	if err != nil || len(salt) < 8 {
		return false
	}
	want, err := b64.DecodeString(parts[3])
	if err != nil || len(want) < 16 {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}
