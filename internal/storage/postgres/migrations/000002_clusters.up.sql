-- Registered clusters and the credentials their agents use.

CREATE TABLE clusters (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id    uuid        NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    name               text        NOT NULL CHECK (char_length(btrim(name)) BETWEEN 1 AND 120),
    -- Matters for advisory matching: a GKE bulletin only applies to provider = 'gke'.
    provider           text        NOT NULL CHECK (provider IN ('gke', 'eks', 'aks', 'kind', 'self_managed', 'unknown')),
    kubernetes_version text,
    status             text        NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'connected', 'disconnected')),
    last_seen_at       timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT clusters_org_name_key UNIQUE (organization_id, name),
    -- Lets child tables prove a row belongs to the same organization as its cluster (see scan_jobs, findings).
    CONSTRAINT clusters_id_org_key UNIQUE (id, organization_id)
);

CREATE TRIGGER clusters_set_updated_at
    BEFORE UPDATE ON clusters
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE agent_credentials (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_id   uuid        NOT NULL REFERENCES clusters (id) ON DELETE CASCADE,
    -- Short, non-secret prefix so people can tell tokens apart in the UI.
    token_prefix text        NOT NULL,
    -- SHA-256 of the secret token. The token itself is shown once and never stored.
    token_hash   bytea       NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz,
    CONSTRAINT agent_credentials_token_hash_key UNIQUE (token_hash)
);

CREATE INDEX agent_credentials_cluster_id_idx ON agent_credentials (cluster_id);
