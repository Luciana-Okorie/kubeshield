-- Asserts that the schema's constraints actually reject bad data.
-- Run against a migrated database; everything happens in one transaction that is rolled back.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f scripts/schema-check.sql
--
-- Any failed expectation aborts with an error starting "FAIL:".

\pset tuples_only on
BEGIN;

-- expect_error(stmt, sqlstate, label): runs stmt and requires it to fail with exactly that SQLSTATE
-- (use 'none' to require success). Returns a line like "ok: <label>".
CREATE FUNCTION pg_temp.expect_error(stmt text, expected text, label text) RETURNS text
LANGUAGE plpgsql AS $$
DECLARE
    got text;
BEGIN
    BEGIN
        EXECUTE stmt;
        got := 'none';
    EXCEPTION WHEN OTHERS THEN
        got := SQLSTATE;
    END;
    IF got <> expected THEN
        RAISE EXCEPTION 'FAIL: % (expected SQLSTATE %, got %)', label, expected, got;
    END IF;
    RETURN 'ok: ' || label;
END;
$$;

-- Fixtures: two organizations, each with a cluster called "prod".
INSERT INTO organizations (id, name, slug) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'Acme', 'acme'),
    ('00000000-0000-0000-0000-0000000000b2', 'Beta', 'beta');

INSERT INTO clusters (id, organization_id, name, provider) VALUES
    ('00000000-0000-0000-0000-00000000c001', '00000000-0000-0000-0000-0000000000a1', 'prod', 'gke'),
    ('00000000-0000-0000-0000-00000000c002', '00000000-0000-0000-0000-0000000000b2', 'prod', 'gke');

INSERT INTO scan_jobs (id, organization_id, cluster_id) VALUES
    ('00000000-0000-0000-0000-00000000d001', '00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001');

-- Organizations ---------------------------------------------------------------
SELECT pg_temp.expect_error($q$INSERT INTO organizations (name, slug) VALUES ('Dup', 'acme')$q$,
    '23505', 'duplicate organization slug is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO organizations (name, slug) VALUES ('Bad', 'Bad Slug')$q$,
    '23514', 'malformed slug is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO organizations (name, slug) VALUES ('   ', 'blank-name')$q$,
    '23514', 'blank organization name is rejected');

-- Users -----------------------------------------------------------------------
SELECT pg_temp.expect_error($q$INSERT INTO users (email, display_name) VALUES ('Mixed@Case.com', 'X')$q$,
    '23514', 'non-lowercase email is rejected');

-- Clusters --------------------------------------------------------------------
SELECT pg_temp.expect_error($q$INSERT INTO clusters (organization_id, name, provider) VALUES ('00000000-0000-0000-0000-0000000000a1', 'prod', 'gke')$q$,
    '23505', 'duplicate cluster name within an organization is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO clusters (organization_id, name, provider) VALUES ('00000000-0000-0000-0000-0000000000a1', 'x', 'digitalocean')$q$,
    '23514', 'unknown provider is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO clusters (organization_id, name, provider) VALUES ('00000000-0000-0000-0000-0000000000ff', 'x', 'gke')$q$,
    '23503', 'cluster for a missing organization is rejected');

-- Agent credentials -----------------------------------------------------------
SELECT pg_temp.expect_error($q$INSERT INTO agent_credentials (cluster_id, token_prefix, token_hash) VALUES ('00000000-0000-0000-0000-00000000c001', 'ks_abcd', '\x00'::bytea)$q$,
    '23514', 'token hash that is not 32 bytes is rejected');

-- Sessions --------------------------------------------------------------------
INSERT INTO users (id, email, display_name) VALUES ('00000000-0000-0000-0000-00000000e001', 'u@example.com', 'U');

SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('00000000-0000-0000-0000-00000000e001', '\x00'::bytea, now() + interval '1 hour')$q$,
    '23514', 'session token hash that is not 32 bytes is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('00000000-0000-0000-0000-00000000e001', decode(repeat('ab', 32), 'hex'), now() - interval '1 hour')$q$,
    '23514', 'session that expires before it is created is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('00000000-0000-0000-0000-0000000000ff', decode(repeat('ab', 32), 'hex'), now() + interval '1 hour')$q$,
    '23503', 'session for a missing user is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('00000000-0000-0000-0000-00000000e001', decode(repeat('ab', 32), 'hex'), now() + interval '1 hour')$q$,
    'none', 'valid session is accepted');
SELECT pg_temp.expect_error($q$INSERT INTO sessions (user_id, token_hash, expires_at) VALUES ('00000000-0000-0000-0000-00000000e001', decode(repeat('ab', 32), 'hex'), now() + interval '1 hour')$q$,
    '23505', 'duplicate session token hash is rejected');

-- Scan jobs: organization isolation and lifecycle -----------------------------
SELECT pg_temp.expect_error($q$INSERT INTO scan_jobs (organization_id, cluster_id) VALUES ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-00000000c001')$q$,
    '23503', 'scan cannot pair one organization with another organization''s cluster');
SELECT pg_temp.expect_error($q$INSERT INTO scan_jobs (organization_id, cluster_id, status) VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', 'running')$q$,
    '23514', 'running scan without started_at is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO scan_jobs (organization_id, cluster_id, status, finished_at) VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', 'succeeded', now())$q$,
    'none', 'succeeded scan with finished_at is accepted');
SELECT pg_temp.expect_error($q$INSERT INTO scan_jobs (organization_id, cluster_id, status, error) VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', 'queued', 'oops')$q$,
    '23514', 'error text on a non-failed scan is rejected');

-- Findings --------------------------------------------------------------------
SELECT pg_temp.expect_error($q$INSERT INTO findings (organization_id, cluster_id, scan_job_id, kind, rule_id, fingerprint, resource_type, resource_name, severity, description, remediation, detected_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', '00000000-0000-0000-0000-00000000d001', 'vulnerability', 'GCP-2026-078', 'fp1', 'Node', 'node-1', 'high', 'd', 'r', now())$q$,
    '23514', 'vulnerability finding without detection_status is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO findings (organization_id, cluster_id, scan_job_id, kind, rule_id, fingerprint, resource_type, resource_name, severity, detection_status, description, remediation, detected_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', '00000000-0000-0000-0000-00000000d001', 'configuration', 'K8S-PRIV-001', 'fp2', 'Pod', 'p', 'high', 'vulnerable', 'd', 'r', now())$q$,
    '23514', 'configuration finding with a detection_status is rejected');
SELECT pg_temp.expect_error($q$INSERT INTO findings (organization_id, cluster_id, scan_job_id, kind, rule_id, fingerprint, resource_type, resource_name, severity, description, remediation, detected_at)
    VALUES ('00000000-0000-0000-0000-0000000000b2', '00000000-0000-0000-0000-00000000c002', '00000000-0000-0000-0000-00000000d001', 'configuration', 'K8S-PRIV-001', 'fp3', 'Pod', 'p', 'high', 'd', 'r', now())$q$,
    '23503', 'finding cannot reference another organization''s scan');
SELECT pg_temp.expect_error($q$INSERT INTO findings (organization_id, cluster_id, scan_job_id, kind, rule_id, fingerprint, resource_type, resource_name, severity, description, remediation, detected_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', '00000000-0000-0000-0000-00000000d001', 'configuration', 'K8S-PRIV-001', 'fp4', 'Pod', 'p', 'high', 'd', 'r', now())$q$,
    'none', 'valid configuration finding is accepted');
SELECT pg_temp.expect_error($q$INSERT INTO findings (organization_id, cluster_id, scan_job_id, kind, rule_id, fingerprint, resource_type, resource_name, severity, description, remediation, detected_at)
    VALUES ('00000000-0000-0000-0000-0000000000a1', '00000000-0000-0000-0000-00000000c001', '00000000-0000-0000-0000-00000000d001', 'configuration', 'K8S-PRIV-001', 'fp4', 'Pod', 'p', 'high', 'd', 'r', now())$q$,
    '23505', 'same fingerprint twice in one scan is rejected');

-- Audit log is append-only ----------------------------------------------------
INSERT INTO audit_logs (organization_id, actor_type, action) VALUES ('00000000-0000-0000-0000-0000000000a1', 'system', 'schema_check');
SELECT pg_temp.expect_error($q$UPDATE audit_logs SET action = 'tampered'$q$, '23001', 'audit log UPDATE is rejected');
SELECT pg_temp.expect_error($q$DELETE FROM audit_logs$q$, '23001', 'audit log DELETE is rejected');
SELECT pg_temp.expect_error($q$TRUNCATE audit_logs$q$, '23001', 'audit log TRUNCATE is rejected');

-- updated_at trigger ----------------------------------------------------------
DO $$
DECLARE
    before_ts timestamptz;
    after_ts  timestamptz;
BEGIN
    SELECT updated_at INTO before_ts FROM organizations WHERE slug = 'acme';
    PERFORM pg_sleep(0.02);
    UPDATE organizations SET name = 'Acme Inc' WHERE slug = 'acme';
    SELECT updated_at INTO after_ts FROM organizations WHERE slug = 'acme';
    IF after_ts <= before_ts THEN
        RAISE EXCEPTION 'FAIL: updated_at did not advance on UPDATE';
    END IF;
    RAISE NOTICE 'ok: updated_at advances on UPDATE';
END;
$$;

-- Deleting an organization removes everything beneath it ----------------------
DO $$
DECLARE
    leftover int;
BEGIN
    DELETE FROM organizations WHERE slug = 'acme';
    SELECT (SELECT count(*) FROM clusters  WHERE organization_id = '00000000-0000-0000-0000-0000000000a1')
         + (SELECT count(*) FROM scan_jobs WHERE organization_id = '00000000-0000-0000-0000-0000000000a1')
         + (SELECT count(*) FROM findings  WHERE organization_id = '00000000-0000-0000-0000-0000000000a1')
    INTO leftover;
    IF leftover <> 0 THEN
        RAISE EXCEPTION 'FAIL: % rows survived deleting the organization', leftover;
    END IF;
    RAISE NOTICE 'ok: deleting an organization cascades to clusters, scans and findings';
END;
$$;

-- Deleting a user removes their sessions --------------------------------------
DO $$
DECLARE
    leftover int;
BEGIN
    DELETE FROM users WHERE id = '00000000-0000-0000-0000-00000000e001';
    SELECT count(*) INTO leftover FROM sessions WHERE user_id = '00000000-0000-0000-0000-00000000e001';
    IF leftover <> 0 THEN
        RAISE EXCEPTION 'FAIL: % sessions survived deleting the user', leftover;
    END IF;
    RAISE NOTICE 'ok: deleting a user cascades to their sessions';
END;
$$;

ROLLBACK;
