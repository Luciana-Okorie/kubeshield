-- Append-only audit trail for sensitive actions.

CREATE TABLE audit_logs (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- Deliberately no foreign keys on the two ids below: the audit history must
    -- outlive the organization or user it describes.
    organization_id uuid,
    actor_user_id   uuid,
    actor_type      text        NOT NULL CHECK (actor_type IN ('user', 'agent', 'system')),
    action          text        NOT NULL,
    target_type     text,
    target_id       text,
    metadata        jsonb       NOT NULL DEFAULT '{}'::jsonb,
    ip              inet,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_logs_org_created_idx ON audit_logs (organization_id, created_at DESC);

CREATE FUNCTION audit_logs_reject_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only' USING ERRCODE = 'restrict_violation';
END;
$$;

CREATE TRIGGER audit_logs_no_update_delete
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_change();

CREATE TRIGGER audit_logs_no_truncate
    BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_reject_change();
