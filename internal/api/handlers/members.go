package handlers

import (
	"errors"
	"net/http"

	"github.com/luciana-okorie/kubeshield/internal/api/httpx"
	"github.com/luciana-okorie/kubeshield/internal/storage"
)

// Membership rules, enforced here and in storage.Role.CanAssign:
//
//   - Only owners and admins can see or change membership.
//   - Owners can assign any role. Admins can only add, change and remove members and
//     viewers, so an admin can never create an owner or touch one.
//   - An organization always keeps at least one owner (enforced atomically in the store).
//
// Adding takes the email of an account that already exists. There is no email invitation
// yet, so an admin who knows an address can learn whether it is registered (404 vs 201).

type addMemberRequest struct {
	Email string       `json:"email"`
	Role  storage.Role `json:"role"`
}

type setRoleRequest struct {
	Role storage.Role `json:"role"`
}

func roleError(w http.ResponseWriter) {
	httpx.JSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{
		"code": "validation_failed", "message": "must be owner, admin, member or viewer", "field": "role",
	}})
}

// ListMembers handles GET /v1/organizations/{orgID}/members.
func (h *Resources) ListMembers(w http.ResponseWriter, r *http.Request) {
	_, orgID, ok := h.authorize(w, r, storage.PermManage)
	if !ok {
		return
	}
	members, err := h.store.ListMembers(r.Context(), orgID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	httpx.JSON(w, http.StatusOK, httpx.Items(members))
}

// AddMember handles POST /v1/organizations/{orgID}/members.
func (h *Resources) AddMember(w http.ResponseWriter, r *http.Request) {
	actor, orgID, actorRole, ok := h.authorizeRole(w, r, storage.PermManage)
	if !ok {
		return
	}
	var req addMemberRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !req.Role.Valid() {
		roleError(w)
		return
	}
	email, err := storage.NormalizeEmail(req.Email)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	if !actorRole.CanAssign("", req.Role) {
		httpx.Forbidden(w)
		return
	}

	target, err := h.store.GetUserByEmail(r.Context(), email)
	if err != nil || target.DisabledAt != nil {
		if err == nil || errors.Is(err, storage.ErrNotFound) {
			httpx.NotFound(w) // unknown and disabled accounts look the same
			return
		}
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	m, err := h.store.AddMember(r.Context(), orgID, target.ID, req.Role)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(actor, orgID, "member.added", "user", target.ID,
		map[string]any{"role": string(req.Role)}))
	httpx.JSON(w, http.StatusCreated, storage.Member{
		UserID: target.ID, Email: target.Email, DisplayName: target.DisplayName, Role: m.Role, CreatedAt: m.CreatedAt,
	})
}

// SetMemberRole handles PATCH /v1/organizations/{orgID}/members/{userID}.
func (h *Resources) SetMemberRole(w http.ResponseWriter, r *http.Request) {
	actor, orgID, actorRole, ok := h.authorizeRole(w, r, storage.PermManage)
	if !ok {
		return
	}
	targetID, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	var req setRoleRequest
	if !httpx.DecodeJSON(w, r, &req) {
		return
	}
	if !req.Role.Valid() {
		roleError(w)
		return
	}
	current, err := h.store.GetMembership(r.Context(), orgID, targetID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err) // not a member -> 404
		return
	}
	if !actorRole.CanAssign(current.Role, req.Role) {
		httpx.Forbidden(w)
		return
	}
	if err := h.store.SetMemberRole(r.Context(), orgID, targetID, req.Role); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(actor, orgID, "member.role_changed", "user", targetID,
		map[string]any{"from": string(current.Role), "to": string(req.Role)}))
	current.Role = req.Role
	httpx.JSON(w, http.StatusOK, current)
}

// RemoveMember handles DELETE /v1/organizations/{orgID}/members/{userID}.
func (h *Resources) RemoveMember(w http.ResponseWriter, r *http.Request) {
	actor, orgID, actorRole, ok := h.authorizeRole(w, r, storage.PermManage)
	if !ok {
		return
	}
	targetID, ok := pathID(w, r, "userID")
	if !ok {
		return
	}
	current, err := h.store.GetMembership(r.Context(), orgID, targetID)
	if err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	if !actorRole.CanAssign(current.Role, current.Role) {
		httpx.Forbidden(w)
		return
	}
	if err := h.store.RemoveMember(r.Context(), orgID, targetID); err != nil {
		httpx.StoreError(w, r, h.logger, err)
		return
	}
	audit(r.Context(), h.store, h.logger, r, userAudit(actor, orgID, "member.removed", "user", targetID,
		map[string]any{"role": string(current.Role)}))
	w.WriteHeader(http.StatusNoContent)
}
