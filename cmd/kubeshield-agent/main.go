// Command kubeshield-agent connects one Kubernetes cluster to the KubeShield API.
// Run one agent per registered cluster; the agent token is scoped to that cluster.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/domain"
	"github.com/luciana-okorie/kubeshield/internal/kube"
)

type scanJob struct {
	ID             string `json:"id"`
	ClusterID      string `json:"cluster_id"`
	OrganizationID string `json:"organization_id"`
}
type agent struct {
	baseURL, token string
	client         *http.Client
	scanner        kube.Scanner
}

func main() {
	if err := run(); err != nil {
		log.Printf("kubeshield-agent: %v", err)
		os.Exit(1)
	}
}
func run() error {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("KUBESHIELD_API_URL")), "/")
	token := strings.TrimSpace(os.Getenv("KUBESHIELD_AGENT_TOKEN"))
	if base == "" || token == "" {
		return errors.New("KUBESHIELD_API_URL and KUBESHIELD_AGENT_TOKEN are required")
	}
	u, parseErr := url.Parse(base)
	if parseErr != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"))) {
		return errors.New("KUBESHIELD_API_URL must use HTTPS except for localhost development")
	}
	poll := 5 * time.Second
	if v := os.Getenv("KUBESHIELD_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Second {
			return errors.New("KUBESHIELD_POLL_INTERVAL must be at least 1s")
		}
		poll = d
	}
	scanner, err := kube.NewScanner(os.Getenv("KUBECONFIG"))
	if err != nil {
		return fmt.Errorf("initialize Kubernetes scanner: %w", err)
	}
	a := &agent{baseURL: base, token: token, client: &http.Client{Timeout: 2 * time.Minute}, scanner: scanner}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if _, err := a.request(ctx, http.MethodGet, "/v1/agent/whoami", nil, nil); err != nil {
		return fmt.Errorf("agent authentication check: %w", err)
	}
	log.Printf("agent connected; polling every %s", poll)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()
	for {
		if err := a.processOne(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("agent cycle: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
func (a *agent) processOne(ctx context.Context) error {
	var job scanJob
	resp, err := a.request(ctx, http.MethodGet, "/v1/agent/scans/next", nil, &job)
	if err != nil {
		return err
	}
	if resp == http.StatusNoContent {
		return nil
	}
	if job.ID == "" || job.ClusterID == "" {
		return errors.New("API returned an invalid scan job")
	}
	log.Printf("running scan %s for cluster %s", job.ID, job.ClusterID)
	scanCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	findings, summary, scanErr := a.scanner.Scan(scanCtx, job.ClusterID)
	if scanErr != nil {
		payload := map[string]string{"error": scanErr.Error()}
		_, err = a.request(ctx, http.MethodPost, "/v1/agent/scans/"+job.ID+"/failure", payload, nil)
		return err
	}
	payload := struct {
		Findings []domain.Finding   `json:"findings"`
		Summary  domain.ScanSummary `json:"summary"`
	}{findings, summary}
	_, err = a.request(ctx, http.MethodPost, "/v1/agent/scans/"+job.ID+"/results", payload, nil)
	if err == nil {
		log.Printf("scan %s completed: %d findings across %d pods", job.ID, len(findings), summary.Pods)
	}
	return err
}
func (a *agent) request(ctx context.Context, method, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+a.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("API %s %s returned %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode API response: %w", err)
		}
	}
	return resp.StatusCode, nil
}
