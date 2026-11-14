package storage

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeEmail(t *testing.T) {
	valid := map[string]string{
		"a@b.com":                  "a@b.com",
		"  Luciana@Example.COM  ":  "luciana@example.com",
		"first.last+tag@sub.d.org": "first.last+tag@sub.d.org",
	}
	for in, want := range valid {
		got, err := NormalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; want %q", in, got, err, want)
		}
	}

	invalid := []string{
		"", "   ", "plain", "@b.com", "a@", "a b@c.com",
		"Name <a@b.com>",                    // display names are not accepted
		"<a@b.com>",                         // angle brackets
		"a@b.com, c@d.com",                  // two addresses
		strings.Repeat("a", 250) + "@b.com", // over 254 characters
	}
	for _, in := range invalid {
		_, err := NormalizeEmail(in)
		var ve *ValidationError
		if !errors.As(err, &ve) || ve.Field != "email" {
			t.Errorf("NormalizeEmail(%q) error = %v, want *ValidationError on email", in, err)
		}
	}
}

func TestNewAccountValidate(t *testing.T) {
	ok := NewAccount{Email: "A@B.com", DisplayName: "  Luciana ", PasswordHash: "hash", OrgName: " Acme ", OrgSlug: "acme"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid account rejected: %v", err)
	}
	if ok.Email != "a@b.com" || ok.DisplayName != "Luciana" || ok.OrgName != "Acme" {
		t.Errorf("not normalised in place: %+v", ok)
	}

	tests := []struct {
		name      string
		mutate    func(*NewAccount)
		wantField string
	}{
		{"bad email", func(n *NewAccount) { n.Email = "nope" }, "email"},
		{"blank display name", func(n *NewAccount) { n.DisplayName = " " }, "display_name"},
		{"missing password hash", func(n *NewAccount) { n.PasswordHash = "" }, "password"},
		{"blank organization name", func(n *NewAccount) { n.OrgName = "" }, "organization_name"},
		{"bad organization slug", func(n *NewAccount) { n.OrgSlug = "Bad Slug" }, "organization_slug"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := NewAccount{Email: "a@b.com", DisplayName: "L", PasswordHash: "h", OrgName: "Acme", OrgSlug: "acme"}
			tc.mutate(&in)
			assertValidation(t, in.Validate(), tc.wantField)
		})
	}
}
