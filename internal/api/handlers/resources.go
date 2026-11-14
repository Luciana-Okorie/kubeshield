package handlers

import (
	"log/slog"
	"net/http"

	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
	"github.com/luciana-okorie/kubeshield/internal/auth"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// Resources serves the organization, cluster, scan, agent-token and audit endpoints.
// Every route here sits behind the Authenticate middleware, and every handler that
// takes an {orgID} checks the caller's membership and role before touching data.
type Resources struct {
	store  storage.Store
	logger *slog.Logger
}

// NewResources returns the handler set backed by store.
func NewResources(store storage.Store, logger *slog.Logger) *Resources {
	return &Resources{store: store, logger: logger}
}

// authorize resolves the {orgID} in the path and checks the caller may do perm in it.
//
//   - Not a member (or the organization does not exist): 404, so tenants cannot probe each other's IDs.
//   - A member whose role is too low: 403.
//
// On failure it has already written the response.
func (h *Resources) authorize(w http.ResponseWriter, r *http.Request, perm storage.Permission) (user storage.User, orgID string, ok bool) {
	user, orgID, _, ok = h.authorizeRole(w, r, perm)
	return user, orgID, ok
}

// authorizeRole is authorize that also returns the caller's role, for handlers whose rules
// depend on it (who may change whose role).
func (h *Resources) authorizeRole(w http.ResponseWriter, r *http.Request, perm storage.Permission) (user storage.User, orgID string, role storage.Role, ok bool) {
	user, authed := auth.UserFrom(r.Context())
	if !authed {
		httpx.Unauthorized(w)
		return user, "", "", false
	}
	orgID, ok = pathID(w, r, "orgID")
	if !ok {
		return user, "", "", false
	}
	m, err := h.store.GetMembership(r.Context(), orgID, user.ID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err) // ErrNotFound -> 404
		return user, "", "", false
	}
	if !m.Role.Can(perm) {
		httpx.Forbidden(w)
		return user, "", "", false
	}
	return user, orgID, m.Role, true
}

func userAudit(user storage.User, orgID, action, targetType, targetID string, meta map[string]any) storage.AuditEntry {
	return storage.AuditEntry{
		OrganizationID: &orgID, ActorUserID: &user.ID, ActorType: storage.ActorUser,
		Action: action, TargetType: targetType, TargetID: targetID, Metadata: meta,
	}
}

type createOrganizationRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// CreateOrganization handles POST /v1/organizations. The caller becomes its owner.
func (h *Resources) CreateOrganization(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	var req createOrganizationRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	org, err := h.store.CreateOrganizationFor(r.Context(), user.ID, storage.NewOrganization{Name: req.Name, Slug: req.Slug})
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(user, org.ID, "organization.created", "organization", org.ID, nil))
	w.Header().Set("Location", "/v1/organizations/"+org.ID)
	httpx.JSON(w, http.StatusCreated, storage.OrgMembership{Organization: org, Role: storage.RoleOwner})
}

// ListOrganizations handles GET /v1/organizations: only the caller's own organizations.
func (h *Resources) ListOrganizations(w http.ResponseWriter, r *http.Request) {
	user, ok := auth.UserFrom(r.Context())
	if !ok {
		httpx.Unauthorized(w)
		return
	}
	orgs, err := h.store.ListOrganizationsFor(r.Context(), user.ID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Items(orgs))
}

// GetOrganization handles GET /v1/organizations/{orgID}.
func (h *Resources) GetOrganization(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermRead)
	if !ok {
		return
	}
	org, err := h.store.GetOrganization(r.Context(), orgID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, org)
}

type createClusterRequest struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
}

// CreateCluster handles POST /v1/organizations/{orgID}/clusters.
func (h *Resources) CreateCluster(w http.ResponseWriter, r *http.Request) {
	user, orgID, ok := h.authorize(w, r, storage.PermManage)
	if !ok {
		return
	}
	var req createClusterRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	cluster, err := h.store.CreateCluster(r.Context(), orgID, storage.NewCluster{Name: req.Name, Provider: req.Provider})
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(user, orgID, "cluster.created", "cluster", cluster.ID,
		map[string]any{"name": cluster.Name, "provider": cluster.Provider}))
	w.Header().Set("Location", "/v1/organizations/"+orgID+"/clusters/"+cluster.ID)
	httpx.JSON(w, http.StatusCreated, cluster)
}

// ListClusters handles GET /v1/organizations/{orgID}/clusters.
func (h *Resources) ListClusters(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermRead)
	if !ok {
		return
	}
	clusters, err := h.store.ListClusters(r.Context(), orgID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Items(clusters))
}

// GetCluster handles GET /v1/organizations/{orgID}/clusters/{clusterID}.
func (h *Resources) GetCluster(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermRead)
	if !ok {
		return
	}
	clusterID, ok := pathID(w, r, "clusterID")
	if !ok {
		return
	}
	cluster, err := h.store.GetCluster(r.Context(), orgID, clusterID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, cluster)
}

// CreateScan handles POST /v1/organizations/{orgID}/clusters/{clusterID}/scans.
// It only queues the scan; nothing executes it until the scan-execution phase.
func (h *Resources) CreateScan(w http.ResponseWriter, r *http.Request) {
	user, orgID, ok := h.authorize(w, r, storage.PermScan)
	if !ok {
		return
	}
	clusterID, ok := pathID(w, r, "clusterID")
	if !ok {
		return
	}
	job, err := h.store.CreateScanJob(r.Context(), orgID, clusterID, user.ID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(user, orgID, "scan.requested", "scan", job.ID,
		map[string]any{"cluster_id": clusterID}))
	w.Header().Set("Location", "/v1/organizations/"+orgID+"/scans/"+job.ID)
	httpx.JSON(w, http.StatusCreated, job)
}

// ListScans handles GET /v1/organizations/{orgID}/clusters/{clusterID}/scans.
func (h *Resources) ListScans(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermRead)
	if !ok {
		return
	}
	clusterID, ok := pathID(w, r, "clusterID")
	if !ok {
		return
	}
	// An unknown (or other tenant's) cluster is a 404, not an empty list.
	if _, err := h.store.GetCluster(r.Context(), orgID, clusterID); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	jobs, err := h.store.ListScanJobs(r.Context(), orgID, clusterID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Items(jobs))
}

// GetScan handles GET /v1/organizations/{orgID}/scans/{scanID}.
func (h *Resources) GetScan(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermRead)
	if !ok {
		return
	}
	scanID, ok := pathID(w, r, "scanID")
	if !ok {
		return
	}
	job, err := h.store.GetScanJob(r.Context(), orgID, scanID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, job)
}

// ListAudit handles GET /v1/organizations/{orgID}/audit-logs. Owners and admins only.
func (h *Resources) ListAudit(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermManage)
	if !ok {
		return
	}
	entries, err := h.store.ListAudit(r.Context(), orgID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Items(entries))
}
