# Security model

What the API protects, how, and what it does not protect yet. Everything marked **tested** has an automated test that fails if the protection is removed; the test names are in the right-hand column.

## Principles

- **Read-only product.** KubeShield recommends fixes and never changes a cluster it scans.
- **Least privilege.** Roles grant the minimum, agents get a per-cluster token that can do almost nothing, and the agent's Kubernetes access is read-only (Phase 3).
- **No secret is stored in a recoverable form.** Passwords and tokens are hashed; tokens are shown once.
- **Refusals reveal nothing.** A caller outside an organization, an unknown token and an expired token all get the same answers as "does not exist".

## Identities

| Identity | Credential | Lifetime | Accepted on |
| --- | --- | --- | --- |
| User | Password at login, then a `ksu_` session token | Session TTL (default 12h, max 30d), revocable by logout | Everything except `/v1/agent/*` |
| Agent | `ksa_` token, one or more per cluster | Until revoked | `/v1/agent/*` only |

Tokens are 256 random bits from `crypto/rand`, so a fast hash is enough to store them. The database holds only the SHA-256. The prefix makes a leaked token recognisable to secret scanners and lets the server reject the wrong kind without a database lookup.

Passwords use PBKDF2-HMAC-SHA256 with 600,000 iterations and a random salt per password (the OWASP-recommended cost for that algorithm), from Go's standard library. The cost is part of the stored string, so it can be raised later while old hashes keep working. Length is the only password rule (12 to 128 characters).

## Authorization

Roles per organization: `owner`, `admin`, `member`, `viewer`.

| Permission | Granted to | Used for |
| --- | --- | --- |
| read | all roles | Organization, clusters, scans |
| scan | owner, admin, member | Queue a scan |
| manage | owner, admin | Create clusters, agent tokens, read the audit log, manage members |

Managing members has an extra rule on top of `manage` (`Role.CanAssign`): owners can assign any role, admins can only add, change and remove **members and viewers**. An admin therefore cannot create an owner or admin, cannot promote themselves, and cannot touch an existing owner or admin. An organization always keeps at least one owner; the store enforces that under a row lock so two owners cannot demote each other at the same moment.

Order of checks on any `/v1/organizations/{orgID}/...` request: authenticated (401) -> ID well formed (404) -> member of the organization (404) -> role allows it (403) -> then the data is touched. Tenant isolation is also enforced below the API: scans and findings reference `clusters (id, organization_id)` through a composite foreign key, and every store query filters by organization.

## Threats and defenses

| Threat | Defense | Test |
| --- | --- | --- |
| Anonymous access | Every route except health, signup and login requires a valid token | `TestProtectedRoutesRequireAuthentication` |
| One tenant reading or changing another's data | Membership check; composite keys; org-filtered queries; identical 404 | `TestTenantIsolation` |
| Privilege escalation inside an organization | Role check on every mutating route | `TestRoleEnforcement` |
| An admin making themselves or a friend an owner, or demoting an owner | `Role.CanAssign`: admins handle only members and viewers | `TestAdminCannotEscalate`, `TestCanAssign` |
| An organization left with no owner (also by two owners demoting each other at once) | Check under a lock on the organization row | `TestOrganizationAlwaysKeepsAnOwner`, `TestLastOwnerRace` (needs Postgres, see below) |
| A removed member keeping access | Access is checked against membership on every request, not stored in the session | `TestOwnerManagesMembers` |
| Two simultaneous first signups on a closed server | "No accounts yet" is re-checked atomically with the insert (advisory lock) | `TestClosedSignupBootstrapIsAtomic`, `TestBootstrapSignupRace` (Postgres) |
| Password guessing | Strict per-client rate limit on login and signup; PBKDF2 cost | `TestAuthRateLimiting`, rate limiter tests |
| Account enumeration through login | One response for every failure; a dummy hash is computed for unknown emails so timing matches | `TestLoginFailuresAreIndistinguishable` |
| Stolen database | Only hashes stored; no recoverable password or token | schema constraints, `TestSignupLoginMeLogout` (no hash in responses) |
| Stolen session token | Expiry, logout revokes it, disabled users are refused | `TestSessionExpiry`, `TestEachLoginIsAnIndependentSession`, `TestDisabledUserSessionsStopWorking` |
| Leaked agent token | Revocation takes effect immediately; scoped to one cluster; useless on user endpoints | `TestAgentTokenLifecycle` |
| Secrets leaking through logs or audit | Audit metadata is built from non-secret fields; request bodies are never logged | `TestAuditLog` (scans the log for password and tokens); real-binary log check |
| Audit tampering | `audit_logs` rejects UPDATE, DELETE and TRUNCATE at the database | `scripts/schema-check.sql` |
| Oversized or malformed bodies | 1 MiB limit, single JSON object, unknown fields rejected | `TestRequestBodyValidation` |
| Spoofed client address to dodge rate limits or forge the audit IP | The client is the TCP peer. `X-Forwarded-For` is believed only from proxies the operator listed, read from the right, so entries a client wrote are ignored | `TestForgedForwardedForDoesNotEvadeRateLimit`, `TestTrustedProxyGivesEachClientItsOwnLimit`, `TestAuditRecordsTheResolvedClientAddress`, `clientip` tests |
| Memory exhaustion through many client addresses | Rate limiter tracks at most 10,000 clients | `TestRateLimiterSweepForgetsIdleClientsAndStaysBounded` |
| Tokens or data cached, sniffed or framed by a browser or proxy | `Cache-Control: no-store`, `nosniff` and a locked-down CSP on every response; HSTS when the server terminates TLS | `TestResponsesCarrySecurityHeaders`, `TestSecurityHeaders` |
| Traffic read on the network | Optional built-in TLS (1.2 or newer), or terminate TLS in front; a warning is logged when listening beyond loopback without TLS | real-binary TLS check (see README) |
| Sessions piling up forever | A janitor removes sessions expired or revoked more than a day ago | `TestSessionJanitor`, `TestDeleteExpiredSessions` |

## Audit log

Recorded: account creation, login, failed login (for existing accounts), logout, organization creation, cluster creation, scan requests, agent token creation and revocation. Each entry has the actor, action, target, client IP and a small metadata object. Entries are append-only in the database.

Writing the audit entry happens after the action succeeds and is **best effort**: if the write fails, the failure is logged at error level and the request still succeeds. This favors availability; a deployment that must fail closed would wrap action and audit write in one transaction.

## Operating it safely

- **Transport.** Either set `KUBESHIELD_TLS_CERT_FILE` and `KUBESHIELD_TLS_KEY_FILE`, or run behind a proxy or ingress that terminates TLS. Without one of them, do not bind beyond loopback.
- **Behind a proxy**, set `KUBESHIELD_TRUSTED_PROXIES` to the proxy's address range (for example the load balancer's CIDR). Without it every client looks like the proxy and shares one rate limit. Listing a range that clients can reach directly lets them forge their address, so keep it to the proxy only.
- **Signup** stays closed unless `KUBESHIELD_ALLOW_SIGNUP=true`. Closed means exactly one account can ever be created this way; everyone else is added by an owner or admin.
- **Agent tokens** go into a Kubernetes Secret, never into source control or an image. Revoke on suspicion; revocation is immediate.

## Known gaps

These are real and deliberate for this phase. None is hidden by the tests.

1. **Adding a member needs an existing account.** There is no email invitation, so a manager can learn whether an address is registered (404 versus 201), and a person must sign up (or be the first account) before being added. Signup itself also reveals taken emails and slugs (409). Login does not.
2. **No account lockout, password reset, email verification, MFA or session listing.** Rate limiting is the only brake on guessing. Removing a person from an organization does not end their sessions elsewhere.
3. **Members cannot leave an organization themselves.** Only an owner or admin can remove them.
4. **Audit writes are best effort.** If the write fails the action still succeeds and the failure is logged at error level. A deployment that must fail closed would wrap action and audit write in one transaction.
5. **A database superuser can disable the audit triggers.** An insert-only database role is future hardening.
6. **The agent endpoint is a stub.** `/v1/agent/whoami` proves agent authentication works; inventory upload arrives with the agent.
7. **The Go to PostgreSQL path has been verified in pieces, not end to end.** The SQL was run against PostgreSQL 16 (including a real two-session last-owner race with and without the lock), the scan code is unit tested, and the full store is tested in memory. The integration tests that drive the real store through pgx (`internal/storage/postgres/integration_test.go`) compile but have not been run, because the driver could not be downloaded where this was built. Run them once before trusting the PostgreSQL path (README, "Run with PostgreSQL").
8. **CI has not run.** The workflow is written and its database steps were simulated locally, but nothing has executed it on GitHub yet.
