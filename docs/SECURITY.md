# Security Notes

## Current safety posture
- Scanner performs Kubernetes list operations only.
- No automated remediation is implemented.
- API has no authentication/authorization yet.
- The configured kubeconfig may grant more access than required if the operator uses an admin context.

## Required before production
1. Create a dedicated Kubernetes ServiceAccount with only the required get/list/watch permissions for resources being inspected.
2. Add authentication and role-based authorization to the API.
3. Bind each cluster identity to an authenticated tenant and prevent caller-controlled cluster labels from selecting credentials.
4. Protect credentials with a secrets manager and rotation.
5. Enable TLS, request limits, audit logging and security headers.
6. Add database least-privilege credentials, backups and migration management.
7. Review findings for false positives and document rule rationale.
8. Conduct threat modelling and security testing.

Never mount an administrator kubeconfig into a publicly reachable API deployment.
