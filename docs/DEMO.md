# Reproducible KubeShield demo

1. Create a local Kubernetes cluster using kind or minikube and ensure `kubectl get pods -A` works.
2. Start PostgreSQL: `docker compose -f deploy/docker-compose.yml up -d`.
3. Apply `migrations/001_init.sql` (the Compose PostgreSQL initialization does this on a fresh volume).
4. Set `API_KEY` to a long random secret, `KUBECONFIG` to your cluster config path, and `SCAN_CLUSTER_ID=local-demo`.
5. Start the API: `go run ./cmd/kubeshield-api`.
6. Apply the intentionally unsafe fixture: `kubectl apply -f deploy/demo-unhealthy.yaml`.
7. Run `curl -X POST -H "Authorization: Bearer $API_KEY" http://localhost:8080/api/v1/clusters/local-demo/scan`.
8. Query `curl -H "Authorization: Bearer $API_KEY" 'http://localhost:8080/api/v1/findings?cluster_id=local-demo'`.
9. Clean up: `kubectl delete namespace kubeshield-demo`.

The fixture intentionally crashes and runs privileged; **only deploy it in a disposable local cluster**. This demo does not validate multi-cluster identity or production security.
