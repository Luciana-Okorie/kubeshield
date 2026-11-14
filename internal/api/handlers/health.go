// Package handlers contains the HTTP handlers for the KubeShield API.
package handlers

import (
	"encoding/json"
	"net/http"
)

// HealthResponse is the body returned by the health endpoint.
type HealthResponse struct {
	Status  string `json:"status"`
	Service string `json:"service"`
	Version string `json:"version"`
}

// Health reports that the process is up and able to serve HTTP.
// It is a liveness check only: it deliberately checks no dependencies, so a
// database outage will not make Kubernetes restart a healthy API process.
type Health struct {
	version string
}

// NewHealth returns a Health handler that reports the given build version.
func NewHealth(version string) *Health {
	return &Health{version: version}
}

func (h *Health) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(HealthResponse{
		Status:  "ok",
		Service: "kubeshield-api",
		Version: h.version,
	})
}
