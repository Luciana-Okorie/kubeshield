package routes

import (
	"net/http"
	"testing"
	"time"
)

func TestAgentScanExecutionRoundTrip(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("scan-owner@example.com", "scan-owner")
	clusterID := h.cluster(owner, "local-kind")
	tokenResp := h.want(h.do("POST", "/v1/organizations/"+owner.OrgID+"/clusters/"+clusterID+"/agent-tokens", owner.Token, nil), http.StatusCreated)
	agentToken := str(h, tokenResp.JSON, "token")
	scan := h.want(h.do("POST", "/v1/organizations/"+owner.OrgID+"/clusters/"+clusterID+"/scans", owner.Token, nil), http.StatusCreated)
	scanID := str(h, scan.JSON, "id")

	claimed := h.want(h.do("GET", "/v1/agent/scans/next", agentToken, nil), http.StatusOK)
	if str(h, claimed.JSON, "id") != scanID || str(h, claimed.JSON, "status") != "running" {
		t.Fatalf("unexpected claimed scan: %s", claimed.Body)
	}

	payload := map[string]any{
		"findings": []any{map[string]any{"cluster_id": clusterID, "fingerprint": "abc123", "title": "Pod is not ready", "severity": "high"}},
		"summary":  map[string]any{"cluster_id": clusterID, "nodes": 1, "pods": 2, "unhealthy_pods": 1, "restarting_pods": 0, "scanned_at": time.Now().UTC()},
	}
	h.want(h.do("POST", "/v1/agent/scans/"+scanID+"/results", agentToken, payload), http.StatusNoContent)
	status := h.want(h.do("GET", "/v1/organizations/"+owner.OrgID+"/scans/"+scanID, owner.Token, nil), http.StatusOK)
	if str(h, status.JSON, "status") != "succeeded" {
		t.Fatalf("scan status = %v", status.JSON["status"])
	}
	result := h.want(h.do("GET", "/v1/organizations/"+owner.OrgID+"/scans/"+scanID+"/results", owner.Token, nil), http.StatusOK)
	if result.JSON["findings"] == nil || result.JSON["summary"] == nil {
		t.Fatalf("missing scan result payload: %s", result.Body)
	}
}

func TestAgentCannotSubmitResultsForAnotherCluster(t *testing.T) {
	h := newHarness(t)
	owner := h.signup("scan-a@example.com", "scan-a")
	clusterID := h.cluster(owner, "cluster-a")
	tokenResp := h.want(h.do("POST", "/v1/organizations/"+owner.OrgID+"/clusters/"+clusterID+"/agent-tokens", owner.Token, nil), http.StatusCreated)
	agentToken := str(h, tokenResp.JSON, "token")
	scan := h.want(h.do("POST", "/v1/organizations/"+owner.OrgID+"/clusters/"+clusterID+"/scans", owner.Token, nil), http.StatusCreated)
	scanID := str(h, scan.JSON, "id")
	h.want(h.do("GET", "/v1/agent/scans/next", agentToken, nil), http.StatusOK)
	payload := map[string]any{"findings": []any{}, "summary": map[string]any{"cluster_id": "22222222-2222-4222-8222-222222222222"}}
	h.want(h.do("POST", "/v1/agent/scans/"+scanID+"/results", agentToken, payload), http.StatusUnprocessableEntity)
}
