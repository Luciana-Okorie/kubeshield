# Database design

PostgreSQL 16. Migrations live in `internal/storage/postgres/migrations/` as numbered `.up.sql` / `.down.sql` pairs, are embedded in the binary, and are applied by `postgres.Migrate` (or at startup with `KUBESHIELD_AUTO_MIGRATE=true`).

## Entities

```
organizations 1──* memberships *──1 users 1──* sessions
organizations 1──* clusters 1──* agent_credentials
clusters      1──* scan_jobs 1──* findings
advisories    1──* findings        (vulnerability findings only)
audit_logs                         (no foreign keys, by design)
```

| Table | Purpose |
| --- | --- |
| `organizations` | Tenants. Everything below belongs to exactly one. |
| `users`, `memberships` | People and their role (`owner`, `admin`, `member`, `viewer`) in each organization. |
| `sessions` | One row per login. Stores only a SHA-256 hash of the session token, with expiry and revocation time. |
| `clusters` | Registered clusters. `provider` decides whether a provider-specific advisory (such as a GKE bulletin) can apply. |
| `agent_credentials` | One row per agent token. Stores only a SHA-256 hash, never the token. |
| `advisories` | Verified advisories, one row per (source, source id), with the source's own severity and score. |
| `scan_jobs` | A request to scan a cluster, with its lifecycle. |
| `findings` | One finding per issue per scan, with evidence and remediation. |
| `audit_logs` | Append-only record of sensitive actions. |

The API exposes accounts, sessions, organizations, clusters, scan jobs, agent tokens and the audit log. `advisories` and `findings` exist so later phases do not need to reshape the core.

## Decisions worth knowing

**Tenant isolation is enforced by the database, not just the queries.**
`scan_jobs` and `findings` carry `organization_id` and reference `clusters (id, organization_id)` through a composite foreign key. A scan cannot be attached to another organization's cluster even if application code has a bug. Every API query also filters by organization, and a cross-tenant ID returns the same 404 as a missing one.

**Lifecycle rules are CHECK constraints.**
A `queued` scan has no timestamps, a `running` scan has `started_at`, a finished scan has `finished_at`, and `error` is only allowed on `failed`. A vulnerability finding must have a `detection_status`; a configuration or network finding must not.

**Advisory status is separate from remediation status.**
`detection_status` (`vulnerable`, `patched`, `patch_pending`, `unknown`, `not_affected`) says what the scanner concluded. `remediation_status` (`open`, `in_progress`, `resolved`, `risk_accepted`) says what the team has done about it.

**One advisory row per source.**
Sources can disagree. Google rated GCP-2026-078 Medium while third-party trackers scored its CVE 9.8, so the severity and score belong to the (source, source id) row, not to the CVE.

**Findings have a fingerprint.**
A stable hash of cluster, rule and resource, unique per scan. It lets Phase 6 recognise the same issue across scans, so it can report what is new, fixed or unchanged.

**The audit log cannot be edited.**
Triggers reject `UPDATE`, `DELETE` and `TRUNCATE`. It has no foreign keys, so history survives deleting the organization or user it describes. A superuser can still disable the triggers; stronger protection (a separate role with insert-only rights) is future hardening.

**Secrets are never stored.**
Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes (`users.password_hash`). Session and agent tokens are 256 random bits and are stored as SHA-256 hashes, so a database leak does not hand out working credentials. `sessions.token_hash` and `agent_credentials.token_hash` are checked to be exactly 32 bytes.

**Audit entries can belong to no organization.**
`audit_logs.organization_id` is nullable. Sign-in and sign-out describe a person, not a tenant, so they are written with no organization and are not served by the per-organization audit endpoint.

**IDs and time.**
UUID primary keys (`gen_random_uuid()`, built in since PostgreSQL 13). All timestamps are `timestamptz`, returned as UTC. `updated_at` is maintained by a trigger.

## Testing the schema

`scripts/schema-check.sql` runs inside one rolled-back transaction and asserts that each constraint rejects bad data with the expected SQLSTATE: duplicate slugs, cross-tenant scans and findings, lifecycle violations, the append-only audit log, the `updated_at` trigger, and cascade deletes.

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/schema-check.sql
```

Each check prints `ok: ...`; a failure aborts with `FAIL: ...`. Removing a constraint makes the matching check fail, so the script does test what it claims.

## Not yet covered

- No pagination: lists return at most 100 rows.
- Expired and long-revoked `sessions` rows are deleted hourly by the API (`DeleteExpiredSessions`).
- Membership changes lock the organization's row (`SELECT ... FOR UPDATE`) so the last-owner rule holds under concurrency, and bootstrap signup takes a transaction-scoped advisory lock (`pg_advisory_xact_lock`) so only one first account can be created.
- No row-level security. Isolation relies on the composite keys above plus filtered queries.
- No retention policy for `scan_jobs`, `findings` or `audit_logs`.
- Rollback files (`.down.sql`) drop data by design. They are for development only; production fixes go forward as a new migration.
