# KubeShield local verification record — 14 November 2026

## Environment

- Windows PowerShell
- Docker Desktop / Docker Compose
- PostgreSQL 16 (`postgres:16-alpine`)
- Primary API executable: `go run ./cmd/api`
- Local API address: `127.0.0.1:8110`
- Runtime environment: development

## Verified successfully

| Area | Check | Observed result |
|---|---|---|
| Database | `docker compose ps` | PostgreSQL container healthy; host port 5460 mapped to container port 5432 |
| API startup | API logs | Migrations applied; PostgreSQL store selected; server started |
| Health | `GET /healthz` | `status=ok`, service `kubeshield-api`, version `dev` |
| Signup | `POST /v1/auth/signup` | Test user and organization created |
| Login | `POST /v1/auth/login` | Session token returned |
| Authentication | `GET /v1/me` | Authenticated user details returned |
| Tenancy | `GET /v1/organizations` | Organization returned with caller role `owner` |
| Cluster registration | `POST /v1/organizations/{orgID}/clusters` | Cluster created with provider `kind` |
| Cluster retrieval | `GET /v1/organizations/{orgID}/clusters/{clusterID}` | Persisted cluster returned |
| Scan request | `POST /v1/organizations/{orgID}/clusters/{clusterID}/scans` | Scan job created with status `queued` |
| Scan retrieval | `GET /v1/organizations/{orgID}/scans/{scanID}` | Job returned; still `queued`; no start or finish timestamp |

## Important distinction

The primary platform scan endpoint currently queues a job; it does not execute it. The source comment in `internal/api/handlers/resources.go` states this explicitly. The primary API startup in `cmd/api/main.go` does not initialize a scan worker.

The existing read-only Kubernetes scanner lives in `internal/kube/scanner.go`, but it is not yet wired to the primary platform's per-cluster credentials, scan-job lifecycle, or organization-scoped finding storage.

**Verified:** API, PostgreSQL-backed persistence, authentication, organization access, cluster registration/retrieval, scan-job queuing/retrieval.

**Not yet verified/implemented:** execution of a queued scan through the primary API, persistence of its findings/summary in the multi-tenant platform, and a completed/failed scan lifecycle.

## Next milestone

Implement and test the full worker pipeline: secure per-cluster Kubernetes credentials, atomic job claiming, running/completed/failed transitions, bounded execution and cancellation, organization-scoped finding/summary persistence, and end-to-end verification against the local `kind` cluster. Do not manually change job status to simulate execution.
