package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/config"
	"github.com/luciana-okorie/kubeshield/internal/httpapi"
	"github.com/luciana-okorie/kubeshield/internal/kube"
	"github.com/luciana-okorie/kubeshield/internal/store"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatalf("load configuration: %v", err)
	}
	ctx := context.Background()

	repo, err := store.NewPostgres(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer repo.Close()

	kubeScanner, err := kube.NewScanner(cfg.Kubeconfig)
	var scanner kube.Scanner = kubeScanner
	if err != nil {
		log.Printf("Kubernetes scanner unavailable at startup: %v", err)
		scanner = kube.NewUnavailableScanner(err)
	}

	ctxDone := make(chan struct{})
	api := httpapi.New(repo, scanner)
	if cfg.ScanClusterID != "" {
		go func() {
			ticker := time.NewTicker(cfg.ScanInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctxDone:
					return
				case <-ticker.C:
					scanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					findings, _, err := scanner.Scan(scanCtx, cfg.ScanClusterID)
					if err != nil {
						log.Printf("scheduled scan failed: %v", err)
					} else {
						fingerprints := make([]string, 0, len(findings))
						persistOK := true
						for _, f := range findings {
							fingerprints = append(fingerprints, f.Fingerprint)
							if _, err := repo.UpsertFinding(scanCtx, f); err != nil {
								persistOK = false
								log.Printf("persist finding: %v", err)
							}
						}
						if persistOK {
							if _, err := repo.CompleteScan(scanCtx, cfg.ScanClusterID, fingerprints); err != nil {
								log.Printf("complete scan lifecycle: %v", err)
							}
							log.Printf("scheduled scan completed: %d findings", len(findings))
						} else {
							log.Printf("scheduled scan persisted incompletely; skipped auto-resolution")
						}
					}
					cancel()
				}
			}
		}()
	}
	server := &http.Server{
		Addr: cfg.HTTPAddr, Handler: api.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("KubeShield API listening on %s", cfg.HTTPAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	close(ctxDone)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown: %v", err)
	}
}
