# Implemented vs planned

KubeShield contains a multi-tenant platform API (`cmd/api`) and a separate single-operator Kubernetes scanner API (`cmd/kubeshield-api`). They are not yet one integrated multi-tenant scan workflow.

## Implemented in the primary platform API (`cmd/api`)

- Signup/login, password hashing, session authentication, logout and current-user endpoint.
- Organization creation/listing and membership management with role checks.
- Organization-scoped cluster registration and retrieval.
- Scan-job record creation/listing and scan record retrieval.
- Agent token creation/listing/revocation and authenticated agent identity endpoint.
- Audit logging, PostgreSQL storage and embedded migrations.
- Request logging/recovery, security headers, rate limiting, trusted-proxy-aware client IP handling and graceful shutdown.

## Implemented in the scanner API (`cmd/kubeshield-api`)

- Read-only Pod and Node inspection using Kubernetes `client-go`.
- Pod readiness, pending Pods, restart counts, CrashLoopBackOff and image-pull failure detection.
- Privileged containers, missing non-root enforcement and privilege-escalation checks.
- Missing CPU/memory requests and limits.
- Deployment and StatefulSet availability checks.
- PostgreSQL finding persistence, filtering and status updates.
- Finding deduplication by stable fingerprint; a later detection reopens an acknowledged/resolved finding.
- Successful-scan reconciliation: findings absent from a successful scan are automatically marked resolved. Failed or incompletely persisted scans do not trigger auto-resolution.
- On-demand and interval-based scans for one configured cluster.
- Bearer API-key protection for scanner/findings routes; health probes are exempt.
- Read-only RBAC example and disposable unhealthy-Pod demo fixture.

## Partially implemented / requires local verification

- Build and runtime verification of both APIs, PostgreSQL migrations and Docker Compose on the target machine.
- End-to-end Kubernetes testing against a disposable `kind` cluster.
- Primary platform scan-job and agent primitives are not yet connected to scanner execution or organization-scoped finding ingestion.
- Per-cluster credential onboarding and tenant-bound scanner identity require integration work.

## Still planned

- Integrate scanner execution and findings ingestion into organization-owned clusters in `cmd/api`.
- Background worker leasing, distributed scheduling and retry policies.
- Notifications, alert routing, severity policies and finding suppression.
- Prometheus metrics, Grafana dashboards and broader OpenTelemetry coverage.
- Web dashboard, cluster overview, workload inventory, finding details and trend views.
- Helm deployment, production secret-management integration, full TLS deployment, end-to-end/load tests and independent security review.

## Release caveat

KubeShield is an engineering prototype. Do not claim complete multi-tenant scanning, automated remediation or production readiness until the integration and deployment work above is implemented and tested.


## Local verification update (14 November 2026)

The primary API was exercised locally on Windows with PostgreSQL 16 running in Docker Compose. The developer verified API startup and migrations, `/healthz`, signup, login, `/v1/me`, organization listing, cluster registration/retrieval, and scan-job creation/retrieval. The scan job remained `queued`; `started_at` and `finished_at` remained null. This confirms the platform API and persistence path for scan requests, not execution of scans.

The scan handler explicitly documents that it only queues jobs. The primary API startup does not initialize a scan worker. The existing `internal/kube` scanner is a separate read-only scanner component and has not yet been connected to the primary platform's organization-scoped cluster credentials, job lifecycle, or findings persistence. See `HANDOFF-NOTES.md` for the verified workflow and recommended integration sequence.
