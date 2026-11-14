# Scanner API contract

The scanner API is the earlier single-operator service launched with `go run ./cmd/kubeshield-api`. It is separate from the multi-tenant platform API launched with `go run ./cmd/api`.

All scanner routes except health probes require `Authorization: Bearer $API_KEY`.

## GET /healthz
Liveness probe. Does not require authentication.

## GET /readyz
Checks database connectivity. Does not require authentication.

## GET /api/v1/findings
Optional query parameters:
- `cluster_id`: logical cluster identifier.
- `status`: `open`, `acknowledged` or `resolved`.
- `limit`: defaults to 100; maximum 500.

## POST /api/v1/clusters/{clusterID}/scan
Runs a read-only scan using the Kubernetes context configured for the scanner process. Persists findings, reopens matching findings detected again, and resolves active findings that were not present in this successful scan.

The response contains `summary`, current open `findings`, and `resolved_findings` (the number automatically resolved during reconciliation).

## PATCH /api/v1/findings/{findingID}/status
Request body:
```json
{"status":"acknowledged"}
```

Allowed statuses: `open`, `acknowledged`, `resolved`.

This scanner API is an internal prototype contract. It is not yet bound to the multi-tenant organization's cluster ownership model.

## Multi-tenant platform agent routes

These routes belong to the primary API (`go run ./cmd/api`), not the legacy scanner API described above. They require a cluster-scoped agent token unless marked as user-facing.

- `GET /v1/agent/whoami` — validate agent and return its cluster/organization identity.
- `GET /v1/agent/scans/next` — atomically claim the next queued job for that agent's cluster; returns 204 when idle.
- `POST /v1/agent/scans/{scanID}/results` — submit `{ "findings": [], "summary": {} }` and complete the running job.
- `POST /v1/agent/scans/{scanID}/failure` — submit `{ "error": "..." }` and fail the running job.
- `GET /v1/organizations/{orgID}/scans/{scanID}/results` — retrieve persisted findings and summary with organization read permission.

See [Scan execution integration](SCAN-EXECUTION-INTEGRATION.md) for agent configuration and the full workflow.
