# Architecture

## Logical flow

Kubernetes API (read-only)
    -> KubeShield scanner
    -> rule evaluation
    -> finding fingerprint/deduplication
    -> PostgreSQL
    -> HTTP API
    -> future web dashboard and alert adapters

## Components

### API
Exposes health, readiness, findings and an explicit scan endpoint. HTTP handlers validate inputs and return JSON.

### Kubernetes scanner
Uses client-go to list Nodes and Pods. The first rule set detects:
- Pods not in Running/Ready state
- Container restart counts at or above the configured threshold (currently 3)
- Privileged containers
- Containers without an explicit `runAsNonRoot: true`

### Rule engine (initial)
Rules are currently implemented in the scanner for clarity. A future milestone will extract versioned rule definitions, severity configuration, suppression and policy tests.

### Persistence
PostgreSQL stores findings with a stable fingerprint so repeat scans do not create duplicate open findings.

## Important design limitations

- The current API process uses one configured kubeconfig context.
- The `clusterID` in the route is a logical label, not an authenticated cluster identity.
- No authentication or authorization exists yet.
- No background scan scheduler exists yet.
- The current API is not safe to expose to the public internet.
