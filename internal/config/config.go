// Package config loads and validates KubeShield runtime configuration.
package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"
)

const (
	EnvName          = "KUBESHIELD_ENV"
	EnvHTTPAddr      = "HTTP_ADDR"
	EnvLogLevel      = "LOG_LEVEL"
	EnvShutdownWait  = "SHUTDOWN_TIMEOUT"
	EnvDatabaseURL   = "DATABASE_URL"
	EnvAutoMigrate   = "AUTO_MIGRATE"
	EnvSessionTTL    = "SESSION_TTL"
	EnvAllowSignup   = "ALLOW_SIGNUP"
	EnvTLSCertFile   = "TLS_CERT_FILE"
	EnvTLSKeyFile    = "TLS_KEY_FILE"
	EnvTrustedProxy  = "TRUSTED_PROXIES"
	EnvKubeconfig    = "KUBECONFIG"
	EnvScanInterval  = "SCAN_INTERVAL"
	EnvScanClusterID = "SCAN_CLUSTER_ID"
	EnvAPIKey        = "API_KEY"
	DefaultHTTPAddr  = "127.0.0.1:8110"
)

type Config struct {
	Env             string
	HTTPAddr        string
	LogLevel        slog.Level
	ShutdownTimeout time.Duration
	DatabaseURL     string
	AutoMigrate     bool
	SessionTTL      time.Duration
	AllowSignup     bool
	TLSCertFile     string
	TLSKeyFile      string
	TrustedProxies  []netip.Prefix

	// Legacy scanner settings remain available to cmd/kubeshield-api.
	Kubeconfig    string
	ScanInterval  time.Duration
	ScanClusterID string
	APIKey        string
}

func (c Config) TLSEnabled() bool { return c.TLSCertFile != "" && c.TLSKeyFile != "" }

// Load reads configuration from getenv. Passing os.Getenv keeps loading testable.
func Load(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	get := func(key, fallback string) string {
		if value := strings.TrimSpace(getenv(key)); value != "" {
			return value
		}
		return fallback
	}

	cfg := Config{
		Env:             strings.ToLower(get(EnvName, "development")),
		HTTPAddr:        get(EnvHTTPAddr, DefaultHTTPAddr),
		LogLevel:        slog.LevelInfo,
		ShutdownTimeout: 10 * time.Second,
		DatabaseURL:     strings.TrimSpace(getenv(EnvDatabaseURL)),
		SessionTTL:      12 * time.Hour,
		AllowSignup:     false, // account creation is opt-in
		TLSCertFile:     strings.TrimSpace(getenv(EnvTLSCertFile)),
		TLSKeyFile:      strings.TrimSpace(getenv(EnvTLSKeyFile)),
		Kubeconfig:      strings.TrimSpace(getenv(EnvKubeconfig)),
		ScanClusterID:   strings.TrimSpace(getenv(EnvScanClusterID)),
		APIKey:          strings.TrimSpace(getenv(EnvAPIKey)),
		ScanInterval:    60 * time.Second,
	}

	if cfg.Env != "development" && cfg.Env != "test" && cfg.Env != "production" {
		return Config{}, fmt.Errorf("invalid %s: expected development, test, or production", EnvName)
	}
	switch strings.ToLower(get(EnvLogLevel, "info")) {
	case "debug":
		cfg.LogLevel = slog.LevelDebug
	case "info":
		cfg.LogLevel = slog.LevelInfo
	case "warn", "warning":
		cfg.LogLevel = slog.LevelWarn
	case "error":
		cfg.LogLevel = slog.LevelError
	default:
		return Config{}, fmt.Errorf("invalid %s", EnvLogLevel)
	}

	if value := strings.TrimSpace(getenv(EnvShutdownWait)); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return Config{}, fmt.Errorf("invalid %s", EnvShutdownWait)
		}
		cfg.ShutdownTimeout = duration
	}
	if value := strings.TrimSpace(getenv(EnvSessionTTL)); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration < time.Minute || duration > 30*24*time.Hour {
			return Config{}, fmt.Errorf("invalid %s", EnvSessionTTL)
		}
		cfg.SessionTTL = duration
	}
	if value := strings.TrimSpace(getenv(EnvScanInterval)); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return Config{}, fmt.Errorf("invalid %s", EnvScanInterval)
		}
		cfg.ScanInterval = duration
	}
	if value := strings.TrimSpace(getenv(EnvAutoMigrate)); value != "" {
		parsed, err := parseBool(value)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s", EnvAutoMigrate)
		}
		cfg.AutoMigrate = parsed
	}
	if cfg.AutoMigrate && cfg.DatabaseURL == "" {
		return Config{}, fmt.Errorf("%s requires %s", EnvAutoMigrate, EnvDatabaseURL)
	}
	if value := strings.TrimSpace(getenv(EnvAllowSignup)); value != "" {
		parsed, err := parseBool(value)
		if err != nil {
			return Config{}, fmt.Errorf("invalid %s", EnvAllowSignup)
		}
		cfg.AllowSignup = parsed
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, fmt.Errorf("TLS certificate and key must be configured together")
	}

	if value := strings.TrimSpace(getenv(EnvTrustedProxy)); value != "" {
		for _, raw := range strings.Split(value, ",") {
			item := strings.TrimSpace(raw)
			if item == "" {
				return Config{}, fmt.Errorf("invalid trusted proxy prefix")
			}
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				addr, addrErr := netip.ParseAddr(item)
				if addrErr != nil {
					return Config{}, fmt.Errorf("invalid trusted proxy prefix")
				}
				prefix = netip.PrefixFrom(addr, addr.BitLen())
			}
			cfg.TrustedProxies = append(cfg.TrustedProxies, prefix.Masked())
		}
	}
	return cfg, nil
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean")
	}
}
