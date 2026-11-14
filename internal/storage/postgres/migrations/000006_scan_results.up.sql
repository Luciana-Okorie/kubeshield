-- Persist the scanner's normalized domain payload for each completed scan.
CREATE TABLE scan_results (
    scan_job_id uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    findings jsonb NOT NULL DEFAULT '[]'::jsonb,
    summary jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT scan_results_job_fk FOREIGN KEY (scan_job_id, organization_id)
        REFERENCES scan_jobs (id, organization_id) ON DELETE CASCADE,
    CONSTRAINT scan_results_cluster_fk FOREIGN KEY (cluster_id, organization_id)
        REFERENCES clusters (id, organization_id) ON DELETE CASCADE
);
