# Product Roadmap

## Milestone 1 — Working scanner foundation
- [x] Go API foundation
- [x] PostgreSQL finding persistence
- [x] Kubernetes Pod/Node inspection
- [x] Initial reliability and security checks
- [x] Findings listing API
- [x] Dockerfile and CI workflow

## Milestone 2 — Production-quality detection
- [ ] Extract rule engine from scanner
- [ ] Add unit tests for every rule
- [ ] Add Deployment/StatefulSet availability checks
- [ ] Add image pull failures and CrashLoopBackOff detection
- [ ] Add resource request/limit and pending-Pod checks
- [ ] Add rule severity configuration and suppression
- [ ] Add scan history and cluster inventory

## Milestone 3 — Secure cluster onboarding
- [ ] Authentication and role-based authorization
- [ ] Per-cluster identity and credential model
- [ ] Least-privilege Kubernetes RBAC manifests
- [ ] Tenant isolation and audit trail
- [ ] Secret encryption and rotation strategy

## Milestone 4 — Continuous operations
- [ ] Background scan scheduler
- [ ] Event-driven observation
- [ ] Alert policies and notification adapters
- [ ] Incident lifecycle and acknowledgement
- [ ] API pagination and filtering
- [ ] OpenTelemetry traces, logs and metrics

## Milestone 5 — Product experience
- [ ] Web dashboard
- [ ] Cluster overview and workload inventory
- [ ] Findings detail and remediation guidance
- [ ] Trend charts and scan comparisons
- [ ] User management and audit views

## Milestone 6 — Deployment and hardening
- [ ] Helm chart
- [ ] Prometheus ServiceMonitor
- [ ] Grafana dashboard
- [ ] Trivy image scanning
- [ ] TLS, rate limits and security headers
- [ ] Load, resilience and failure-injection tests
- [ ] Deployment runbooks and threat model
