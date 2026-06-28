-- Platform audit event foundation.
-- Events store redacted actor/action/resource evidence for sensitive platform
-- operations. Raw credentials, session tokens, and provider tokens do not belong
-- in this table.

CREATE TABLE IF NOT EXISTS platform_audit_events (
    audit_event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    actor_principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    actor_kind TEXT NOT NULL,
    action_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    reason TEXT,
    redaction TEXT NOT NULL,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (audit_event_id LIKE 'audit_%'),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (actor_principal_id LIKE 'usr_%' OR actor_principal_id LIKE 'svc_%' OR actor_principal_id LIKE 'sys_%'),
    CHECK (actor_kind IN ('user', 'service_account', 'system')),
    CHECK (action_id <> ''),
    CHECK (resource_kind <> ''),
    CHECK (resource_id <> ''),
    CHECK (event_type <> ''),
    CHECK (reason IS NULL OR reason <> ''),
    CHECK (redaction <> '')
);

CREATE INDEX IF NOT EXISTS platform_audit_events_tenant_created_idx
    ON platform_audit_events (tenant_id, created_at DESC, audit_event_id);

CREATE INDEX IF NOT EXISTS platform_audit_events_resource_idx
    ON platform_audit_events (tenant_id, resource_kind, resource_id, created_at DESC);
