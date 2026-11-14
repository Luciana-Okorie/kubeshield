# KubeShield handoff — 14 November 2026

## Changes prepared in this handoff

- Standardized the Go module path as `github.com/luciana-okorie/kubeshield` across both API implementations.
- Reconciled the runtime configuration package with the configuration contract already exercised by `internal/config/config_test.go`, while retaining settings needed by the earlier scanner API.
- Registered the pgx `database/sql` driver in the normal build so the primary API can open its configured PostgreSQL store without a special build tag.
- Removed the local `.env` file from the handoff package. Use `.env.example` to create a fresh local file and generate a new scanner API key.
- Updated the Makefile, Dockerfile and CI workflow to identify `cmd/api` as the primary platform API while continuing to build the earlier scanner API.
- Rewrote the README and implementation-status document to distinguish the two API stages and avoid claiming that scanner-to-tenant integration is complete.

## Verification performed here

- `gofmt` was run across the Go source tree.
- `go test ./internal/config` passed.
- `go test ./...` could not complete because this environment has no network access to download the Go modules (pgx and Kubernetes client-go dependencies). Therefore, a full compile/test pass is **not claimed**.

## Required local checks before submission/demo

1. Keep your existing local `.env` file when updating the source. If it does not exist, create it from `.env.example`. Because the earlier key appeared in a screenshot, rotate it once before a public demo; do not regenerate it for each ZIP handoff.
2. Run `go mod download` while online, then `go test ./...`, `go vet ./...`, `go build ./cmd/api`, and `go build ./cmd/kubeshield-api`.
3. Start PostgreSQL with `docker compose up -d --wait postgres` and start the primary API with `go run ./cmd/api`.
4. Test signup/login, organization creation, membership roles, cluster registration, agent token creation/revocation and audit log access using `api/requests.http` as a starting point (extend requests as needed).
5. Test the earlier scanner API separately against a disposable `kind` cluster. Its legacy schema is defined in `migrations/001_init.sql`; do not apply that legacy schema to the primary platform database, whose migrations are embedded under `internal/storage/postgres/migrations`.
6. Do not claim that the primary platform API already runs Kubernetes scans. Scanner-to-platform ingestion, background workers, dashboard, notifications, deployment hardening and end-to-end cluster verification remain outstanding.

## Current architectural boundary

`cmd/api` is the primary multi-tenant platform API. `cmd/kubeshield-api` is the earlier single-operator scanner/findings API. They are separate executables with separate data models and database schema histories. Integrating the scanner into organization-scoped clusters is the next major engineering task.

## Additional scanner work prepared in this handoff

- Expanded read-only checks to include Pending Pods, CrashLoopBackOff, image-pull failures, Deployment availability, StatefulSet readiness and missing CPU/memory limits.
- Added successful-scan reconciliation: active findings not seen in the latest successful scan are marked resolved. A repeated fingerprint is reopened by the existing upsert behavior. The scheduled scanner skips reconciliation if any finding persistence operation fails.
- Updated scanner API documentation and implementation-status notes.
- Added a fake-client scanner test for Pending Pod, ImagePullBackOff and unavailable Deployment findings.
- Added `scripts/package.ps1` to create a source ZIP without `.env` or `.git`.

## API key continuity

Keep the developer's `.env` file in the local project directory. It is intentionally excluded from source ZIPs and Git. Preserve that file when extracting updated source over the project; do not recreate the key for every handoff. Rotate it only if exposed or lost. The packaging script excludes `.env` so it cannot accidentally be sent.

## Verification limitation

`gofmt` completed and `go test ./internal/config` passed. Full Go tests could not run here because the environment cannot reach `proxy.golang.org` to download Kubernetes and PostgreSQL modules. Run `go test ./...` locally while online before treating the new scanner checks as verified.


## Local verification update — 14 November 2026

The developer extracted this handoff on Windows and completed the following checks against the primary API (`cmd/api`) using Docker Desktop, PowerShell, and PostgreSQL 16:

- Docker Compose started `postgres:16-alpine`; `docker compose ps` reported the container healthy.
- The API applied its database migrations and logged that it was using the PostgreSQL store.
- The API started locally at `127.0.0.1:8110` with version `dev`.
- `GET /healthz` returned `status: ok`, `service: kubeshield-api`, `version: dev`.
- `POST /v1/auth/signup` successfully created a test user and organization.
- `POST /v1/auth/login` returned a session token.
- `GET /v1/me` succeeded with that bearer token.
- `GET /v1/organizations` returned the created organization with the caller's role `owner`.
- `POST /v1/organizations/{orgID}/clusters` successfully registered a cluster using the accepted request fields `name` and `provider` (provider `kind`).
- `GET /v1/organizations/{orgID}/clusters/{clusterID}` successfully retrieved the cluster.
- `POST /v1/organizations/{orgID}/clusters/{clusterID}/scans` created a scan job with status `queued`.
- `GET /v1/organizations/{orgID}/scans/{scanID}` retrieved the same job; its status remained `queued`, with `started_at` and `finished_at` both null.

No passwords, bearer tokens, or `.env` values are included in this handoff. The test account and organization are local development data in the developer's PostgreSQL database.

## Scan-execution integration finding — confirmed locally

The primary API's scan endpoint currently creates a persisted scan-job record only. The handler comment in `internal/api/handlers/resources.go` explicitly states that it queues the scan and that execution is not part of this phase. The developer inspected `cmd/api/main.go`; its startup path opens the store, starts the HTTP server and session janitor, but does not initialize a scan worker.

The existing Kubernetes scanner is in `internal/kube/scanner.go`:

- `kube.Scanner` exposes `Scan(context.Context, string) ([]domain.Finding, domain.ScanSummary, error)`.
- `NewScanner(kubeconfig string)` builds a Kubernetes client using a kubeconfig path (or in-cluster configuration fallback).
- `KubernetesScanner.Scan` performs read-only Kubernetes API inspection and produces findings plus a summary.

The primary platform `storage.Store` interface currently supports `CreateScanJob`, `GetScanJob`, and `ListScanJobs`. It does not currently expose job claiming/lease operations, scan status transitions, or persistence of the `internal/domain.Finding` and `domain.ScanSummary` results. The current `domain` package has finding and summary models, but those are not yet integrated with the primary platform's organization-scoped storage model.

Therefore, the successful scan API test verifies **job queuing and retrieval only**. It does not verify that Kubernetes resources were scanned. Do not report the primary multi-tenant scan workflow as complete.

## Recommended next engineering work

Implement this as a deliberate integration milestone rather than changing scan status manually:

1. Define a secure per-cluster connection/credential model. The existing scanner's single kubeconfig constructor is not sufficient to select credentials independently for each registered tenant cluster.
2. Extend the primary storage model and PostgreSQL migrations for organization-scoped findings, scan summaries, and safe job claiming/status transitions. Preserve tenant isolation in every query.
3. Implement a worker with bounded concurrency, context cancellation, timeouts, retry/failure handling, and a safe strategy for stale jobs.
4. Connect the worker to the existing read-only scanner through a per-cluster Kubernetes client/configuration.
5. Persist scan start/end times, terminal status, error details, summary, and findings transactionally or with clearly defined partial-failure behavior.
6. Add tests for job claiming, worker success/failure, tenant isolation, duplicate execution prevention, credential selection, and scan-result persistence.
7. Verify end-to-end against the local `kind` cluster and only then claim that the primary platform performs real scans.

Do not implement a fake `running`/`succeeded` transition just to make the API response look complete.

## Scan execution integration update — implementation prepared

The source now includes the first end-to-end agent execution path (not yet locally verified):

- `GET /v1/agent/scans/next` atomically claims the oldest queued job for the authenticated agent's exact organization and cluster.
- `cmd/kubeshield-agent` authenticates with a cluster-scoped agent token, polls for jobs, runs the existing read-only `internal/kube.Scanner` using that agent process's kubeconfig/in-cluster identity, and submits results or failure.
- `POST /v1/agent/scans/{scanID}/results` validates that the result summary and every finding belong to the authenticated agent's cluster.
- `POST /v1/agent/scans/{scanID}/failure` records a bounded failure diagnostic.
- Migration `000006_scan_results` stores findings and summary JSONB with relational organization/cluster/scan foreign keys.
- Result persistence and transition to `succeeded` happen in one PostgreSQL transaction. A successful scan also marks the cluster connected and updates `last_seen_at`.
- `GET /v1/organizations/{orgID}/scans/{scanID}/results` returns the result only to a member with read permission.
- The in-memory store and route tests cover the agent claim/result round trip and cluster mismatch rejection.
- Scanner findings now populate `detected_at` and `status` rather than returning zero timestamps/empty status.
- Read-only RBAC now includes Pods, Nodes, Deployments and StatefulSets, matching the resources the scanner actually lists.

### Run the local agent

After the updated API is running and migration 000006 has been applied, create an agent token for the registered cluster via the existing `POST /v1/organizations/{orgID}/clusters/{clusterID}/agent-tokens` endpoint. The token is returned once. In a separate PowerShell terminal:

```powershell
$env:KUBESHIELD_API_URL = "http://127.0.0.1:8110"
$env:KUBESHIELD_AGENT_TOKEN = "<agent-token>"
# Optional: $env:KUBECONFIG = "$HOME\.kube\config"
go run ./cmd/kubeshield-agent
```

The agent requires HTTPS for non-localhost API URLs. It polls every 5 seconds by default (`KUBESHIELD_POLL_INTERVAL` can override, minimum 1 second). Run one agent per registered cluster. Do not commit the token. The local agent uses the kubeconfig of the machine on which it runs; it does not fetch or store customer kubeconfigs on the central API.

### Remaining production hardening

- Recover stale `running` jobs when an agent crashes after claiming work (lease/heartbeat/requeue policy).
- Add PostgreSQL-backed concurrency and full integration tests against Docker PostgreSQL and kind.
- Consider normalizing individual scanner findings into the advisory-oriented `findings` table after the rule taxonomy is reconciled. Current results are stored as a JSONB scan-result envelope to preserve the scanner's existing domain model without incorrectly mapping categories.
- Report Kubernetes server version during agent check-in; it remains null currently.
- Add deployment packaging and agent installation/rotation runbooks.

### Verification status of this update

`gofmt` completed for the modified Go files. A Go test run was attempted but could not download uncached modules because this environment cannot resolve/reach `proxy.golang.org`; therefore compilation and tests are **not claimed as passing**. Run `go test ./...` from the Windows project directory while online before relying on this implementation. The earlier locally verified health, authentication, organization, cluster and scan-queue checks remain valid for the previously installed source; they do not verify this new agent pipeline.
