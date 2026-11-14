-- Advisories, scan jobs and findings.

CREATE TABLE advisories (
    id           uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    source       text         NOT NULL CHECK (source IN ('google_gke', 'kubernetes', 'nvd', 'github')),
    -- The source's own identifier, e.g. 'GCP-2026-078'.
    source_id    text         NOT NULL,
    cve_ids      text[]       NOT NULL DEFAULT '{}',
    title        text         NOT NULL,
    -- Severity and score exactly as this source rates them. Different sources can disagree
    -- (Google rated GCP-2026-078 Medium while trackers scored the CVE 9.8), so one row per source.
    severity     text         CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    cvss_score   numeric(3,1) CHECK (cvss_score BETWEEN 0 AND 10),
    published_at timestamptz  NOT NULL,
    retrieved_at timestamptz  NOT NULL,
    source_url   text         NOT NULL,
    -- Affected products, version ranges and fixed versions, as the source states them.
    affected     jsonb        NOT NULL DEFAULT '[]'::jsonb,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    updated_at   timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT advisories_source_key UNIQUE (source, source_id)
);

CREATE INDEX advisories_cve_ids_idx ON advisories USING gin (cve_ids);

CREATE TRIGGER advisories_set_updated_at
    BEFORE UPDATE ON advisories
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE scan_jobs (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid        NOT NULL,
    cluster_id      uuid        NOT NULL,
    status          text        NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    requested_by    uuid        REFERENCES users (id) ON DELETE SET NULL,
    error           text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    -- The composite key makes it impossible to attach a scan to a cluster of a different organization.
    CONSTRAINT scan_jobs_cluster_fk FOREIGN KEY (cluster_id, organization_id)
        REFERENCES clusters (id, organization_id) ON DELETE CASCADE,
    CONSTRAINT scan_jobs_id_org_key UNIQUE (id, organization_id),
    CONSTRAINT scan_jobs_timing_check CHECK (
           (status = 'queued'  AND started_at IS NULL     AND finished_at IS NULL)
        OR (status = 'running' AND started_at IS NOT NULL AND finished_at IS NULL)
        OR (status IN ('succeeded', 'failed', 'canceled') AND finished_at IS NOT NULL)
    ),
    CONSTRAINT scan_jobs_error_check CHECK (error IS NULL OR status = 'failed')
);

CREATE INDEX scan_jobs_cluster_created_idx ON scan_jobs (cluster_id, created_at DESC);
-- Lets a worker find queued work without scanning history.
CREATE INDEX scan_jobs_queued_idx ON scan_jobs (created_at) WHERE status = 'queued';

CREATE TABLE findings (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    uuid        NOT NULL,
    cluster_id         uuid        NOT NULL,
    scan_job_id        uuid        NOT NULL,
    kind               text        NOT NULL CHECK (kind IN ('vulnerability', 'configuration', 'network')),
    -- Identifies the check that produced this: an advisory id like 'GCP-2026-078' or a rule like 'K8S-PRIV-001'.
    rule_id            text        NOT NULL,
    advisory_id        uuid        REFERENCES advisories (id) ON DELETE RESTRICT,
    -- Stable hash of (cluster, rule, resource) so the same issue can be recognised across scans.
    fingerprint        text        NOT NULL,
    resource_type      text        NOT NULL,
    resource_namespace text,
    resource_name      text        NOT NULL,
    severity           text        NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'informational')),
    -- Only meaningful for vulnerability findings; see findings_kind_detection_status_check.
    detection_status   text        CHECK (detection_status IN ('vulnerable', 'patched', 'patch_pending', 'unknown', 'not_affected')),
    remediation_status text        NOT NULL DEFAULT 'open' CHECK (remediation_status IN ('open', 'in_progress', 'resolved', 'risk_accepted')),
    description        text        NOT NULL,
    evidence           jsonb       NOT NULL DEFAULT '{}'::jsonb,
    affected_version   text,
    remediation        text        NOT NULL,
    source_url         text,
    detected_at        timestamptz NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT findings_scan_fk FOREIGN KEY (scan_job_id, organization_id)
        REFERENCES scan_jobs (id, organization_id) ON DELETE CASCADE,
    CONSTRAINT findings_cluster_fk FOREIGN KEY (cluster_id, organization_id)
        REFERENCES clusters (id, organization_id) ON DELETE CASCADE,
    CONSTRAINT findings_scan_fingerprint_key UNIQUE (scan_job_id, fingerprint),
    CONSTRAINT findings_kind_detection_status_check CHECK ((kind = 'vulnerability') = (detection_status IS NOT NULL))
);

CREATE INDEX findings_cluster_severity_idx ON findings (cluster_id, severity);
CREATE INDEX findings_org_severity_idx ON findings (organization_id, severity);

CREATE TRIGGER findings_set_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
