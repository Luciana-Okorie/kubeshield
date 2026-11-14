package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// A low iteration count keeps the suite fast; the encoded hash records it, so
// VerifyPassword exercises exactly the same code path as production.
func fastHasher() *PasswordHasher { return NewPasswordHasher(1000) }

func TestHashAndVerify(t *testing.T) {
	h := fastHasher()
	encoded, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(encoded, "pbkdf2-sha256$1000$") {
		t.Errorf("encoded = %q, want scheme and iteration prefix", encoded)
	}
	if !VerifyPassword(encoded, "correct horse battery staple") {
		t.Error("correct password rejected")
	}
	for _, wrong := range []string{"", "correct horse battery stapl", "Correct horse battery staple", "correct horse battery staple "} {
		if VerifyPassword(encoded, wrong) {
			t.Errorf("wrong password %q accepted", wrong)
		}
	}
}

func TestHashesAreSalted(t *testing.T) {
	h := fastHasher()
	a, _ := h.Hash("same password here")
	b, _ := h.Hash("same password here")
	if a == b {
		t.Error("two hashes of the same password are identical; salt is not random")
	}
	if !VerifyPassword(a, "same password here") || !VerifyPassword(b, "same password here") {
		t.Error("salted hashes failed to verify")
	}
}

func TestDefaultIterations(t *testing.T) {
	if got := NewPasswordHasher(0).iterations; got != DefaultPasswordIterations {
		t.Errorf("iterations = %d, want %d", got, DefaultPasswordIterations)
	}
	if got := NewPasswordHasher(-5).iterations; got != DefaultPasswordIterations {
		t.Errorf("iterations = %d for negative input, want default", got)
	}
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	good, _ := fastHasher().Hash("some password long enough")
	parts := strings.Split(good, "$")

	bad := map[string]string{
		"empty":               "",
		"plaintext":           "some password long enough",
		"too few parts":       "pbkdf2-sha256$1000$abc",
		"too many parts":      good + "$extra",
		"wrong scheme":        "md5$1000$" + parts[2] + "$" + parts[3],
		"zero iterations":     "pbkdf2-sha256$0$" + parts[2] + "$" + parts[3],
		"negative iterations": "pbkdf2-sha256$-1$" + parts[2] + "$" + parts[3],
		"text iterations":     "pbkdf2-sha256$many$" + parts[2] + "$" + parts[3],
		"absurd iterations":   "pbkdf2-sha256$10000001$" + parts[2] + "$" + parts[3],
		"bad salt encoding":   "pbkdf2-sha256$1000$!!!$" + parts[3],
		"short salt":          "pbkdf2-sha256$1000$AAAA$" + parts[3],
		"bad key encoding":    "pbkdf2-sha256$1000$" + parts[2] + "$!!!",
		"short key":           "pbkdf2-sha256$1000$" + parts[2] + "$AAAA",
	}
	for name, encoded := range bad {
		t.Run(name, func(t *testing.T) {
			if VerifyPassword(encoded, "some password long enough") {
				t.Errorf("malformed hash %q verified", encoded)
			}
		})
	}
}

func TestBurnTimeDoesNotPanic(t *testing.T) {
	h := fastHasher()
	h.BurnTime("anything")
	h.BurnTime("") // second call reuses the cached dummy hash
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"exactly minimum", strings.Repeat("a", MinPasswordLength), true},
		{"one short", strings.Repeat("a", MinPasswordLength-1), false},
		{"exactly maximum", strings.Repeat("a", MaxPasswordLength), true},
		{"one over", strings.Repeat("a", MaxPasswordLength+1), false},
		{"empty", "", false},
		{"counts characters not bytes", strings.Repeat("é", MinPasswordLength), true},
		{"passphrase with spaces", "correct horse battery", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePassword(tc.pw)
			if tc.ok != (err == nil) {
				t.Fatalf("ValidatePassword err = %v, want ok=%v", err, tc.ok)
			}
			if err != nil {
				var ve *storage.ValidationError
				if !errors.As(err, &ve) || ve.Field != "password" {
					t.Errorf("error = %v, want *ValidationError on field password", err)
				}
			}
		})
	}
}
