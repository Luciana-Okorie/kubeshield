# Scan execution integration

## End-to-end flow

1. A user creates a scan through `POST /v1/organizations/{orgID}/clusters/{clusterID}/scans`.
2. The API stores the job as `queued`.
3. A cluster-scoped agent authenticates with its agent token and polls `GET /v1/agent/scans/next`.
4. PostgreSQL atomically claims the oldest queued job for that agent's organization and cluster (`FOR UPDATE SKIP LOCKED`); the job becomes `running`.
5. The agent invokes the existing read-only `internal/kube.Scanner` against its configured Kubernetes context.
6. The agent posts findings and summary to `POST /v1/agent/scans/{scanID}/results`.
7. The API verifies that every finding and the summary belong to the authenticated agent's cluster, persists the result payload, marks the job `succeeded`, and updates the cluster's `last_seen_at`/`connected` state in one transaction.
8. If scanning fails, the agent posts a bounded diagnostic to `POST /v1/agent/scans/{scanID}/failure`; the job becomes `failed`.
9. Organization members with read permission retrieve results through `GET /v1/organizations/{orgID}/scans/{scanID}/results`.

## Agent configuration

Run one agent process per registered cluster. The agent token is cluster-scoped and is shown only once when created.

Required environment variables:

- `KUBESHIELD_API_URL`: platform API base URL, e.g. `http://127.0.0.1:8110` for local development. Use HTTPS for remote deployments.
- `KUBESHIELD_AGENT_TOKEN`: the secret returned by the platform's agent-token creation endpoint.
- `KUBECONFIG`: optional path to the kubeconfig for this cluster. If omitted, client-go uses the default kubeconfig or in-cluster service-account configuration.
- `KUBESHIELD_POLL_INTERVAL`: optional polling interval, default `5s`, minimum `1s`.

Example PowerShell session for a local kind cluster:

```powershell
$env:KUBESHIELD_API_URL = "http://127.0.0.1:8110"
$env:KUBESHIELD_AGENT_TOKEN = "<paste-token-once-created>"
# Optional: $env:KUBECONFIG = "$HOME\.kube\config"
go run ./cmd/kubeshield-agent
```

Do not commit agent tokens or put them in source control. For remote agents, terminate TLS at the API or a trusted reverse proxy.

## API contract

- `GET /v1/agent/whoami` — validates the agent credential and returns its organization/cluster identity.
- `GET /v1/agent/scans/next` — returns the next claimed scan as JSON, or `204 No Content` when idle.
- `POST /v1/agent/scans/{scanID}/results` — submits `{ "findings": [...], "summary": {...} }`; succeeds with `204`.
- `POST /v1/agent/scans/{scanID}/failure` — submits `{ "error": "..." }`; succeeds with `204`.
- `GET /v1/organizations/{orgID}/scans/{scanID}/results` — returns persisted findings and summary to an organization member.

All agent endpoints require an agent token. The token, not a client-supplied organization or cluster ID, determines tenant scope.

## Persistence model

Migration `000006_scan_results` stores one JSONB result envelope per scan job, with relational organization/cluster foreign keys. This preserves the existing scanner's finding and summary model without incorrectly mapping its rule categories into the separate advisory-oriented `findings` schema. A later reporting migration can normalize individual scanner findings once the product's finding taxonomy is finalized.

## Current limitations to address before production

- Stale `running` jobs need lease/heartbeat recovery for agents that crash after claiming work.
- Agent installation, rotation and revocation need operational runbooks.
- Add PostgreSQL-backed concurrency and full kind-cluster integration tests in CI.
- Configure a least-privilege read-only Kubernetes RBAC role; the scanner reads Pods, Nodes, Deployments and StatefulSets.
- The current scanner does not yet report Kubernetes server version; cluster version remains null.
