# Beyond Tech Terms: KubeShield teaching series

## Long-form YouTube lessons
1. Why Kubernetes reliability is harder than checking whether a Pod exists (problem and architecture).
2. Building a read-only Kubernetes scanner in Go (client-go, kubeconfig, RBAC).
3. Detecting failing Pods and unsafe container configuration (live disposable-cluster demo).
4. Turning scanner observations into deduplicated PostgreSQL findings (fingerprints and schema).
5. Building an API safely: bearer tokens, readiness probes and operational limits.
6. Adding scheduled scans and explaining why a single-process ticker is not a distributed scheduler.
7. Hardening the system: multi-cluster identity, incidents, metrics and next milestones.

## Instagram Reels (20–45 seconds each)
- A Pod can be Running and still be unready — show readiness status.
- What a CrashLoopBackOff actually looks like — show `kubectl get pods`.
- Why a monitoring service should not have write access — show the RBAC YAML.
- One security setting that gives a container too much power — show privileged=true in the disposable demo.
- Why a unique fingerprint matters — explain repeated scans vs duplicated alerts.
- Why a green health endpoint does not mean a database is reachable — contrast /healthz and /readyz.

Record actual terminal output; don't present planned features as built. Each video: hook, one observable demo, simple explanation, takeaway.
