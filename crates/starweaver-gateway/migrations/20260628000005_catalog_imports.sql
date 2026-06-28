CREATE TABLE IF NOT EXISTS gateway_catalog_imports (
    catalog_import_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    import_mode TEXT NOT NULL,
    import_document JSONB NOT NULL,
    document_checksum TEXT NOT NULL,
    resource_count BIGINT NOT NULL,
    validation_id TEXT NOT NULL REFERENCES gateway_validation_diagnostics (validation_id),
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (catalog_import_id LIKE 'cimp_%'),
    CHECK (import_mode = 'draft'),
    CHECK (document_checksum LIKE 'sha256:%'),
    CHECK (resource_count > 0),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_catalog_imports_scope_time_idx
    ON gateway_catalog_imports (tenant_id, organization_id, project_id, created_at DESC)
    WHERE status <> 'deleted';

CREATE INDEX IF NOT EXISTS gateway_catalog_imports_checksum_idx
    ON gateway_catalog_imports (tenant_id, document_checksum, created_at DESC)
    WHERE status <> 'deleted';

ALTER TABLE gateway_catalog_imports
    ADD CONSTRAINT gateway_catalog_imports_tenant_project_fk
    FOREIGN KEY (tenant_id, organization_id, project_id)
    REFERENCES gateway_projects (tenant_id, organization_id, project_id);
