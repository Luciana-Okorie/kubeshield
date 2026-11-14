package storage

import (
	"errors"
	"strings"
	"testing"
)

func TestNewOrganizationValidate(t *testing.T) {
	tests := []struct {
		name      string
		in        NewOrganization
		wantField string // empty means valid
	}{
		{"valid", NewOrganization{Name: "Acme", Slug: "acme"}, ""},
		{"valid with hyphen and digits", NewOrganization{Name: "Acme 2", Slug: "acme-2"}, ""},
		{"single character slug", NewOrganization{Name: "A", Slug: "a"}, ""},
		{"blank name", NewOrganization{Name: "   ", Slug: "acme"}, "name"},
		{"name too long", NewOrganization{Name: strings.Repeat("x", 121), Slug: "acme"}, "name"},
		{"uppercase slug", NewOrganization{Name: "Acme", Slug: "Acme"}, "slug"},
		{"slug with space", NewOrganization{Name: "Acme", Slug: "ac me"}, "slug"},
		{"slug starts with hyphen", NewOrganization{Name: "Acme", Slug: "-acme"}, "slug"},
		{"slug ends with hyphen", NewOrganization{Name: "Acme", Slug: "acme-"}, "slug"},
		{"slug too long", NewOrganization{Name: "Acme", Slug: strings.Repeat("a", 64)}, "slug"},
		{"empty slug", NewOrganization{Name: "Acme", Slug: ""}, "slug"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertValidation(t, tc.in.Validate(), tc.wantField)
		})
	}
}

func TestNewOrganizationValidateTrimsName(t *testing.T) {
	in := NewOrganization{Name: "  Acme  ", Slug: "acme"}
	if err := in.Validate(); err != nil {
		t.Fatal(err)
	}
	if in.Name != "Acme" {
		t.Errorf("Name = %q, want trimmed", in.Name)
	}
}

func TestNewClusterValidate(t *testing.T) {
	tests := []struct {
		name      string
		in        NewCluster
		wantField string
	}{
		{"valid gke", NewCluster{Name: "prod", Provider: ProviderGKE}, ""},
		{"valid kind", NewCluster{Name: "local", Provider: ProviderKind}, ""},
		{"blank name", NewCluster{Name: "", Provider: ProviderGKE}, "name"},
		{"unknown provider", NewCluster{Name: "prod", Provider: "digitalocean"}, "provider"},
		{"wrong case provider", NewCluster{Name: "prod", Provider: "GKE"}, "provider"},
		{"empty provider", NewCluster{Name: "prod"}, "provider"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertValidation(t, tc.in.Validate(), tc.wantField)
		})
	}
}

func TestIsValidID(t *testing.T) {
	valid := []string{
		"123e4567-e89b-42d3-a456-426614174000",
		"00000000-0000-0000-0000-0000000000a1",
	}
	invalid := []string{
		"", "nope", "123E4567-E89B-42D3-A456-426614174000", // uppercase is not canonical
		"123e4567-e89b-42d3-a456-42661417400",   // one char short
		"123e4567e89b42d3a456426614174000",      // no hyphens
		"123e4567-e89b-42d3-a456-426614174000x", // trailing junk
	}
	for _, s := range valid {
		if !IsValidID(s) {
			t.Errorf("IsValidID(%q) = false, want true", s)
		}
	}
	for _, s := range invalid {
		if IsValidID(s) {
			t.Errorf("IsValidID(%q) = true, want false", s)
		}
	}
}

func assertValidation(t *testing.T, err error, wantField string) {
	t.Helper()
	if wantField == "" {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error = %v, want *ValidationError", err)
	}
	if ve.Field != wantField {
		t.Errorf("Field = %q, want %q", ve.Field, wantField)
	}
}
