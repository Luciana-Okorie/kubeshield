// Command api runs the KubeShield central API server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/api/routes"
	"github.com/luciana-okorie/kubeshield/internal/config"
	"github.com/luciana-okorie/kubeshield/internal/observability"
)

// version is overridden at build time: -ldflags "-X main.version=v0.1.0".
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "kubeshield-api:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := observability.NewLogger(cfg.Env, cfg.LogLevel, os.Stdout)

	// Cancelled on Ctrl+C or SIGTERM (what Kubernetes sends when stopping a pod).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, closeStore, err := openStore(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer closeStore()

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           routes.New(logger, version, store, routeOptions(cfg)),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if cfg.TLSEnabled() {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if !cfg.TLSEnabled() && !isLoopback(cfg.HTTPAddr) {
		logger.Warn("listening beyond loopback without TLS: tokens and passwords will cross the network in clear text unless a TLS-terminating proxy sits in front",
			"addr", cfg.HTTPAddr)
	}

	// Expired and long-revoked sessions are refused anyway; this just stops the table growing.
	go runSessionJanitor(ctx, store, logger, time.Hour, 24*time.Hour, time.Now)
	go runScanRecovery(ctx, store, logger, time.Minute, 20*time.Minute, time.Now)

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("server starting", "addr", cfg.HTTPAddr, "env", cfg.Env, "version", version,
			"tls", cfg.TLSEnabled(), "signup_open", cfg.AllowSignup, "session_ttl", cfg.SessionTTL.String(),
			"trusted_proxies", len(cfg.TrustedProxies))
		if cfg.TLSEnabled() {
			serveErr <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
			return
		}
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		// ListenAndServe only returns on failure here (e.g. port already in use).
		return fmt.Errorf("server failed: %w", err)
	case <-ctx.Done():
		logger.Info("shutdown signal received", "timeout", cfg.ShutdownTimeout.String())
	}

	// Stop accepting new connections and let in-flight requests finish.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("server: %w", err)
	}

	logger.Info("server stopped cleanly")
	return nil
}

// routeOptions maps runtime configuration onto the API's options. Kept separate so a test
// can check that every setting actually reaches the router.
func routeOptions(cfg config.Config) routes.Options {
	return routes.Options{
		SessionTTL:     cfg.SessionTTL,
		AllowSignup:    cfg.AllowSignup,
		TrustedProxies: cfg.TrustedProxies,
		HSTS:           cfg.TLSEnabled(),
	}
}

// isLoopback reports whether addr (host:port) only accepts connections from this machine.
// An empty host (":8110") listens on every interface.
func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
