CREATE TABLE IF NOT EXISTS gateway_maintenance_windows (
    maintenance_window_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    name TEXT NOT NULL,
    reason TEXT NOT NULL,
    starts_at TIMESTAMPTZ NOT NULL,
    ends_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (maintenance_window_id LIKE 'mw_%'),
    CHECK (starts_at < ends_at),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_maintenance_windows_scope_idx
    ON gateway_maintenance_windows (tenant_id, organization_id, project_id, starts_at, ends_at)
    WHERE status <> 'deleted';

CREATE INDEX IF NOT EXISTS gateway_maintenance_windows_active_idx
    ON gateway_maintenance_windows (tenant_id, starts_at, ends_at)
    WHERE status = 'active';

ALTER TABLE gateway_maintenance_windows
    ADD CONSTRAINT gateway_maintenance_windows_tenant_project_fk
    FOREIGN KEY (tenant_id, organization_id, project_id)
    REFERENCES gateway_projects (tenant_id, organization_id, project_id);
