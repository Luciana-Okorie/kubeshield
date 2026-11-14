package handlers

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/luciana-okorie/kubeshield/internal/domain"
	"net/http"

	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
	"github.com/luciana-okorie/kubeshield/internal/auth"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// CreateAgentToken handles POST /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens.
// The token is returned once, here; the server keeps only its hash.
func (h *Resources) CreateAgentToken(w http.ResponseWriter, r *http.Request) {
	user, orgID, ok := h.authorize(w, r, storage.PermManage)
	if !ok {
		return
	}
	clusterID, ok := pathID(w, r, "clusterID")
	if !ok {
		return
	}
	tok, err := auth.NewToken(auth.AgentTokenPrefix)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	cred, err := h.store.CreateAgentCredential(r.Context(), orgID, clusterID, tok.Display, tok.Hash)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	// The audit entry names the credential and its public prefix, never the token.
	audit(r.Context(), h.store, h.logger, r, userAudit(user, orgID, "agent_token.created", "agent_token", cred.ID,
		map[string]any{"cluster_id": clusterID, "token_prefix": cred.TokenPrefix}))
	noStore(w)
	httpx.JSON(w, http.StatusCreated, struct {
		storage.AgentCredential
		Token string `json:"token"`
	}{cred, tok.Secret})
}

// ListAgentTokens handles GET /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens.
// It shows prefixes and usage only; secrets cannot be recovered.
func (h *Resources) ListAgentTokens(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermManage)
	if !ok {
		return
	}
	clusterID, ok := pathID(w, r, "clusterID")
	if !ok {
		return
	}
	if _, err := h.store.GetCluster(r.Context(), orgID, clusterID); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	creds, err := h.store.ListAgentCredentials(r.Context(), orgID, clusterID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Items(creds))
}

// RevokeAgentToken handles DELETE /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens/{tokenID}.
func (h *Resources) RevokeAgentToken(w http.ResponseWriter, r *http.Request) {
	user, orgID, ok := h.authorize(w, r, storage.PermManage)
	if !ok {
		return
	}
	clusterID, ok := pathID(w, r, "clusterID")
	if !ok {
		return
	}
	tokenID, ok := pathID(w, r, "tokenID")
	if !ok {
		return
	}
	if err := h.store.RevokeAgentCredential(r.Context(), orgID, clusterID, tokenID); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(user, orgID, "agent_token.revoked", "agent_token", tokenID,
		map[string]any{"cluster_id": clusterID}))
	w.WriteHeader(http.StatusNoContent)
}

// AgentWhoAmI handles GET /v1/agent/whoami. It lets an agent confirm its token works and
// which cluster it speaks for, and is the first endpoint behind agent authentication.
func (h *Resources) AgentWhoAmI(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.AgentFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	httpx.JSON(w, http.StatusOK, struct {
		ClusterID      string `json:"cluster_id"`
		OrganizationID string `json:"organization_id"`
	}{id.ClusterID, id.OrganizationID})
}

// AgentNextScan atomically claims the oldest queued scan for the cluster represented by
// the agent token. A 204 response means there is currently no work for this cluster.
func (h *Resources) AgentNextScan(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.AgentFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	job, err := h.store.ClaimNextScanJob(r.Context(), id.OrganizationID, id.ClusterID)
	if errors.Is(err, storage.ErrNoWork) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	noStore(w)
	httpx.JSON(w, http.StatusOK, job)
}

type agentScanResultRequest struct {
	Findings []domain.Finding   `json:"findings"`
	Summary  domain.ScanSummary `json:"summary"`
}

// AgentSubmitScanResult accepts the result of the scan currently claimed by this agent.
func (h *Resources) AgentSubmitScanResult(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.AgentFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	scanID, ok := pathID(w, r, "scanID")
	if !ok {
		return
	}
	var req agentScanResultRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if req.Summary.ClusterID != id.ClusterID {
		httpx.Error(w, http.StatusUnprocessableEntity, "cluster_mismatch", "summary cluster_id does not match authenticated agent")
		return
	}
	for _, f := range req.Findings {
		if f.ClusterID != id.ClusterID || strings.TrimSpace(f.Fingerprint) == "" || strings.TrimSpace(f.Title) == "" {
			httpx.Error(w, http.StatusUnprocessableEntity, "invalid_finding", "every finding must belong to this cluster and include fingerprint and title")
			return
		}
	}
	if req.Summary.ScannedAt.IsZero() {
		req.Summary.ScannedAt = time.Now().UTC()
	}
	req.Summary.FindingsCreated = len(req.Findings)
	if req.Findings == nil {
		req.Findings = []domain.Finding{}
	}
	findings, err := json.Marshal(req.Findings)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_result", "findings could not be encoded")
		return
	}
	summary, err := json.Marshal(req.Summary)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_result", "summary could not be encoded")
		return
	}
	if err := h.store.CompleteScanJob(r.Context(), id.OrganizationID, id.ClusterID, scanID, findings, summary); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// AgentFailScan marks the currently running scan failed. Error details are bounded and never expose secrets.
func (h *Resources) AgentFailScan(w http.ResponseWriter, r *http.Request) {
	id, ok := auth.AgentFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	scanID, ok := pathID(w, r, "scanID")
	if !ok {
		return
	}
	var req struct {
		Error string `json:"error"`
	}
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	message := strings.TrimSpace(req.Error)
	if message == "" {
		message = "scan failed"
	}
	if len(message) > 1000 {
		runes := []rune(message)
		message = string(runes[:1000])
	}
	if err := h.store.FailScanJob(r.Context(), id.OrganizationID, id.ClusterID, scanID, message); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetScanResult returns results only to members of the owning organization.
func (h *Resources) GetScanResult(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermRead)
	if !ok {
		return
	}
	scanID, ok := pathID(w, r, "scanID")
	if !ok {
		return
	}
	result, err := h.store.GetScanResult(r.Context(), orgID, scanID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	var findings any
	var summary any
	if err := json.Unmarshal(result.Findings, &findings); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	if err := json.Unmarshal(result.Summary, &summary); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"scan_job_id": result.ScanJobID, "findings": findings, "summary": summary, "created_at": result.CreatedAt})
}
