package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewToken(t *testing.T) {
	tok, err := NewToken(UserTokenPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok.Secret, "ksu_") {
		t.Errorf("Secret = %q, want ksu_ prefix", tok.Secret)
	}
	if len(tok.Secret) != len("ksu_")+43 { // 32 bytes in unpadded base64url
		t.Errorf("len(Secret) = %d, want %d", len(tok.Secret), len("ksu_")+43)
	}
	if len(tok.Hash) != 32 || !bytes.Equal(tok.Hash, HashToken(tok.Secret)) {
		t.Errorf("Hash is not the SHA-256 of the secret")
	}
	if !strings.HasPrefix(tok.Secret, tok.Display) || len(tok.Display) != len("ksu_")+displayChars {
		t.Errorf("Display = %q, want the first %d characters of the secret", tok.Display, len("ksu_")+displayChars)
	}
	if tok.Display == tok.Secret {
		t.Error("Display must not reveal the whole secret")
	}
}

func TestTokensAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 200 {
		tok, _ := NewToken(AgentTokenPrefix)
		if seen[tok.Secret] {
			t.Fatalf("duplicate token %q", tok.Secret)
		}
		seen[tok.Secret] = true
	}
}

func TestHashTokenIsDeterministicAndSensitive(t *testing.T) {
	if !bytes.Equal(HashToken("ksu_abc"), HashToken("ksu_abc")) {
		t.Error("same input produced different hashes")
	}
	if bytes.Equal(HashToken("ksu_abc"), HashToken("ksu_abd")) {
		t.Error("different inputs produced the same hash")
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   string
		ok     bool
	}{
		{"valid", "Bearer ksu_abc", "ksu_abc", true},
		{"scheme is case-insensitive", "bearer ksu_abc", "ksu_abc", true},
		{"missing header", "", "", false},
		{"wrong scheme", "Basic dXNlcjpwYXNz", "", false},
		{"scheme only", "Bearer", "", false},
		{"scheme and space only", "Bearer ", "", false},
		{"empty token after spaces", "Bearer    ", "", false},
		{"two tokens", "Bearer a b", "", false},
		{"no space after scheme", "Bearerksu_abc", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				r.Header.Set("Authorization", tc.header)
			}
			got, ok := BearerToken(r)
			if ok != tc.ok || got != tc.want {
				t.Errorf("BearerToken(%q) = %q, %v; want %q, %v", tc.header, got, ok, tc.want, tc.ok)
			}
		})
	}
}
