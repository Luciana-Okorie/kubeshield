package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Env != "development" {
		t.Errorf("Env = %q, want development", cfg.Env)
	}
	if cfg.HTTPAddr != "127.0.0.1:8110" {
		t.Errorf("HTTPAddr = %q, want 127.0.0.1:8110 (loopback only until auth exists)", cfg.HTTPAddr)
	}
	if cfg.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel = %v, want info", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 10*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 10s", cfg.ShutdownTimeout)
	}
	if cfg.DatabaseURL != "" || cfg.AutoMigrate {
		t.Errorf("database defaults = %q / %v, want empty / false", cfg.DatabaseURL, cfg.AutoMigrate)
	}
}

func TestLoadOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{
		EnvName:         "Production",
		EnvHTTPAddr:     "0.0.0.0:9000",
		EnvLogLevel:     "debug",
		EnvShutdownWait: "3s",
		EnvDatabaseURL:  "postgres://u:p@db:5432/ks",
		EnvAutoMigrate:  "true",
	}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Env != "production" || cfg.HTTPAddr != "0.0.0.0:9000" {
		t.Errorf("unexpected cfg: %+v", cfg)
	}
	if cfg.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel = %v, want debug", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 3*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 3s", cfg.ShutdownTimeout)
	}
	if cfg.DatabaseURL != "postgres://u:p@db:5432/ks" || !cfg.AutoMigrate {
		t.Errorf("database settings = %q / %v", cfg.DatabaseURL, cfg.AutoMigrate)
	}
}

func TestLoadBlankValuesFallBackToDefaults(t *testing.T) {
	cfg, err := Load(env(map[string]string{EnvHTTPAddr: "   "}))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.HTTPAddr != DefaultHTTPAddr {
		t.Errorf("HTTPAddr = %q, want default", cfg.HTTPAddr)
	}
}

func TestLoadInvalid(t *testing.T) {
	tests := map[string]map[string]string{
		"bad env":                  {EnvName: "staging"},
		"bad log level":            {EnvLogLevel: "loud"},
		"bad timeout":              {EnvShutdownWait: "soon"},
		"zero timeout":             {EnvShutdownWait: "0s"},
		"negative timeout":         {EnvShutdownWait: "-5s"},
		"bad auto migrate":         {EnvAutoMigrate: "maybe"},
		"auto migrate without url": {EnvAutoMigrate: "true"},
		"bad session ttl":          {EnvSessionTTL: "tomorrow"},
		"session ttl too short":    {EnvSessionTTL: "10s"},
		"session ttl too long":     {EnvSessionTTL: "9999h"},
		"bad allow signup":         {EnvAllowSignup: "sure"},
		"cert without key":         {EnvTLSCertFile: "cert.pem"},
		"key without cert":         {EnvTLSKeyFile: "key.pem"},
		"bad trusted proxy":        {EnvTrustedProxy: "10.0.0.0/8, banana"},
	}
	for name, vars := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Load(env(vars)); err == nil {
				t.Fatal("Load() error = nil, want error")
			}
		})
	}
}

func TestLoadErrorsNeverContainTheDatabaseURL(t *testing.T) {
	const secret = "s3cret-password"
	_, err := Load(env(map[string]string{
		EnvDatabaseURL: "postgres://u:" + secret + "@db/ks",
		EnvLogLevel:    "loud", // force an error while the URL is set
	}))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaks the database password: %v", err)
	}
}

func TestLoadSessionAndSignup(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 12*time.Hour {
		t.Errorf("SessionTTL = %v, want 12h default", cfg.SessionTTL)
	}
	if cfg.AllowSignup {
		t.Error("AllowSignup defaults to true; it must default to closed")
	}

	cfg, err = Load(env(map[string]string{EnvSessionTTL: "90m", EnvAllowSignup: "true"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SessionTTL != 90*time.Minute || !cfg.AllowSignup {
		t.Errorf("got ttl=%v signup=%v, want 90m and true", cfg.SessionTTL, cfg.AllowSignup)
	}
}

func TestLoadTLSAndProxies(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSEnabled() || len(cfg.TrustedProxies) != 0 {
		t.Errorf("defaults: tls=%v proxies=%v, want off and none", cfg.TLSEnabled(), cfg.TrustedProxies)
	}

	cfg, err = Load(env(map[string]string{
		EnvTLSCertFile: "cert.pem", EnvTLSKeyFile: "key.pem", EnvTrustedProxy: "10.0.0.0/8, 35.191.0.0/16",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.TLSEnabled() || cfg.TLSCertFile != "cert.pem" || cfg.TLSKeyFile != "key.pem" || len(cfg.TrustedProxies) != 2 {
		t.Errorf("cfg = %+v", cfg)
	}
}
