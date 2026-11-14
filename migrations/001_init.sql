CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS clusters (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    context_name TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id TEXT NOT NULL,
    namespace TEXT NOT NULL DEFAULT '',
    resource TEXT NOT NULL,
    resource_name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('reliability','security','capacity')),
    severity TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    fingerprint TEXT NOT NULL UNIQUE,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved'))
);

CREATE INDEX IF NOT EXISTS idx_findings_cluster_status ON findings(cluster_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_detected_at ON findings(detected_at DESC);
