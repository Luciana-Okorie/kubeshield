package httpapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/domain"
	"github.com/luciana-okorie/kubeshield/internal/kube"
	"github.com/luciana-okorie/kubeshield/internal/store"
)

type Server struct {
	repo    store.Repository
	scanner kube.Scanner
}

func New(repo store.Repository, scanner kube.Scanner) *Server {
	return &Server{repo: repo, scanner: scanner}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /api/v1/findings", s.findings)
	mux.HandleFunc("PATCH /api/v1/findings/{findingID}/status", s.updateFindingStatus)
	mux.HandleFunc("POST /api/v1/clusters/{clusterID}/scan", s.scan)
	return requestIDAndLogging(apiKeyAuth(mux, os.Getenv("API_KEY")))
}
func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]string{"status": "ok"})
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.repo.Health(ctx); err != nil {
		writeError(w, 503, "database unavailable")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready"})
}
func (s *Server) findings(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.repo.ListFindings(r.Context(), r.URL.Query().Get("cluster_id"), r.URL.Query().Get("status"), limit)
	if err != nil {
		writeError(w, 500, "could not list findings")
		return
	}
	if items == nil {
		items = []domain.Finding{}
	}
	writeJSON(w, 200, map[string]any{"items": items, "count": len(items)})
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request) {
	clusterID := r.PathValue("clusterID")
	if clusterID == "" {
		writeError(w, 400, "clusterID is required")
		return
	}
	findings, summary, err := s.scanner.Scan(r.Context(), clusterID)
	if err != nil {
		writeError(w, 502, err.Error())
		return
	}
	created := 0
	fingerprints := make([]string, 0, len(findings))
	for _, f := range findings {
		fingerprints = append(fingerprints, f.Fingerprint)
		ok, err := s.repo.UpsertFinding(r.Context(), f)
		if err != nil {
			writeError(w, 500, "could not persist scan findings")
			return
		}
		if ok {
			created++
		}
	}
	resolved, err := s.repo.CompleteScan(r.Context(), clusterID, fingerprints)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not complete finding lifecycle for scan")
		return
	}
	summary.FindingsCreated = created

	persistedFindings, err := s.repo.ListFindings(
		r.Context(),
		clusterID,
		"open",
		500,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to retrieve persisted findings")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"summary":           summary,
		"findings":          persistedFindings,
		"resolved_findings": resolved,
	})
}

func (s *Server) updateFindingStatus(w http.ResponseWriter, r *http.Request) {
	findingID := r.PathValue("findingID")
	if findingID == "" {
		writeError(w, http.StatusBadRequest, "finding ID is required")
		return
	}

	var request struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if request.Status != "open" && request.Status != "acknowledged" && request.Status != "resolved" {
		writeError(w, http.StatusBadRequest, "invalid status")
		return
	}

	updated, err := s.repo.UpdateFindingStatus(r.Context(), findingID, request.Status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not update finding")
		return
	}
	if !updated {
		writeError(w, http.StatusNotFound, "finding not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "finding status updated",
		"status":  request.Status,
		"id":      findingID,
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// apiKeyAuth protects the findings and scan endpoints. Health probes remain public.
// API_KEY is required for all non-health endpoints; this is a single-operator MVP control.
func apiKeyAuth(next http.Handler, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if key == "" {
			writeError(w, http.StatusServiceUnavailable, "API_KEY is not configured")
			return
		}
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if len(token) != len(key) || subtle.ConstantTimeCompare([]byte(token), []byte(key)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}
