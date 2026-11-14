# KubeShield

KubeShield is a Kubernetes reliability and security posture platform. It is being developed to help platform engineers and DevOps teams inspect Kubernetes workloads, identify selected reliability and security risks, retain findings, and manage cluster access through an authenticated API.

**Project status:** active engineering prototype. The repository currently contains a newer multi-tenant platform API and an earlier single-operator scanner API. They are separate entry points; the scanner has not yet been wired into the multi-tenant platform workflow. Runtime behavior must be verified in the target environment before describing the project as production-ready.

## What is in the repository

### Primary platform API — `cmd/api`

- User signup/login and session-based authentication.
- Organization creation and membership management.
- Role-aware organization operations and tenant-scoped data access.
- Cluster registration and scan-job records.
- Agent token issuance/revocation and agent identity endpoint.
- Audit logging, security headers, rate limiting and graceful shutdown.
- PostgreSQL storage with embedded, versioned migrations; in-memory storage for local API tests.

The primary API currently exposes `GET /healthz`, authentication endpoints under `/v1/auth`, organization and cluster endpoints under `/v1/organizations`, and `GET /v1/agent/whoami`. The presence of scan-job and agent records does not mean a complete scan worker or scanner-to-platform ingestion pipeline is finished.

### Earlier scanner API — `cmd/kubeshield-api`

- Read-only Kubernetes inspection using `client-go` and local kubeconfig/in-cluster configuration.
- Pod and Node inspection with selected readiness, restart, privilege, non-root, privilege-escalation and resource-request checks.
- PostgreSQL persistence and findings endpoints.
- Optional interval-based scanning for a configured cluster.
- Successful-scan reconciliation automatically resolves findings no longer detected; repeat detections reopen findings.
- Deployment/StatefulSet availability, Pending Pod, CrashLoopBackOff, image-pull failure and resource-limit checks.
- Bearer API-key protection for scanner/findings routes.

This is an earlier single-operator workflow. It is retained as a working area for scanner development and is not yet integrated with organization-scoped cluster registration in the primary API.

## Technology

Go 1.23+, Kubernetes `client-go`, PostgreSQL, Docker Compose, REST/JSON, and GitHub Actions. Tests use in-memory storage and HTTP test servers where applicable.

## Local setup

Prerequisites: Go 1.23+, Docker Desktop (or Docker Engine with Compose), and PowerShell on Windows or a POSIX shell.

1. Copy `.env.example` to `.env` once and set a cryptographically secure scanner `API_KEY`. Keep this local `.env` file between project ZIP exchanges; you do not need to generate a new key every time you send or receive source code. Never include `.env` in a ZIP you share or commit it to Git. If the `.env` file is lost or the key is exposed, rotate it.
2. Start the local database:

```bash
docker compose up -d --wait postgres
```

The root Compose file binds PostgreSQL to `127.0.0.1:5460` with disposable local-development credentials. Do not reuse these credentials outside local development.

3. Load environment variables from `.env` into your shell. On PowerShell:

```powershell
Get-Content .env | Where-Object { $_ -match '^[A-Za-z_][A-Za-z0-9_]*=' -and $_ -notmatch '^\s*#' } | ForEach-Object { $name, $value = $_ -split '=', 2; Set-Item -Path "Env:$name" -Value $value }
```

4. Run the primary platform API:

```bash
go test ./...
go run ./cmd/api
```

The primary API listens on `127.0.0.1:8110` by default. Signup is closed by default; set `ALLOW_SIGNUP=true` only for a local development session when you need to create the first account. PostgreSQL migrations are applied when `AUTO_MIGRATE=true` and `DATABASE_URL` is configured.

### Run the earlier scanner API

The scanner API uses the same `.env` values for `DATABASE_URL`, `KUBECONFIG`, `SCAN_CLUSTER_ID`, `SCAN_INTERVAL`, and `API_KEY`. Its API address is configured with `HTTP_ADDR`; use a separate terminal and a separate port if running both APIs at once.

```bash
go run ./cmd/kubeshield-api
```

Use a disposable development cluster such as `kind`. Grant only the read permissions in `deploy/rbac.yaml`. The scanner is designed to inspect resources, not modify them.

## Useful commands

```bash
make test          # run all Go tests
go vet ./...        # static analysis
go build ./cmd/api  # build primary API
go build ./cmd/kubeshield-api  # build scanner API
```

## Security notes

- `.env` is local-only and excluded from version control. The checked-in `.env.example` contains placeholders and disposable local settings only.
- Keep the scanner API key private. Rotate any key that has appeared in a screenshot, chat, ZIP archive or repository.
- Do not expose either API publicly without TLS, deployment-specific secret management and a security review.
- The scanner should use read-only Kubernetes RBAC. Do not mount a developer's personal kubeconfig into a public container.
- The primary platform API has session authentication and organization-aware authorization, but this prototype still needs production deployment hardening and end-to-end verification.

## Documentation

See `docs/ARCHITECTURE.md`, `docs/API.md`, `docs/SECURITY.md`, `docs/security-model.md`, `docs/IMPLEMENTED-VS-PLANNED.md`, and `docs/DEMO.md` for design details and current limitations.

## Run a cluster agent

The central API queues scans; a cluster-scoped agent executes them using the read-only Kubernetes scanner and submits findings back to the platform. Run one agent per registered cluster. See [Scan execution integration](docs/SCAN-EXECUTION-INTEGRATION.md) for the full API contract and setup.

For local development, after creating an agent token for the cluster, set `KUBESHIELD_API_URL` and `KUBESHIELD_AGENT_TOKEN`, then run `go run ./cmd/kubeshield-agent`. The agent uses `KUBECONFIG` when set, otherwise the default kubeconfig/in-cluster configuration.
