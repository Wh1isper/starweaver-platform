-- Platform organization invitation lifecycle.
-- Raw invitation tokens are never stored; only domain-separated token hashes
-- are persisted for preview and accept lookup.

CREATE TABLE IF NOT EXISTS platform_organization_invitations (
    invitation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    invited_email TEXT,
    invited_principal_id TEXT REFERENCES platform_principals (principal_id),
    invitation_token_hash TEXT NOT NULL UNIQUE,
    role_id TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_by TEXT NOT NULL REFERENCES platform_principals (principal_id),
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (invitation_id LIKE 'inv_%'),
    CHECK (project_id IS NULL OR project_id LIKE 'prj_%'),
    CHECK (
        (invited_email IS NOT NULL AND invited_principal_id IS NULL)
        OR (invited_email IS NULL AND invited_principal_id IS NOT NULL)
    ),
    CHECK (invited_email IS NULL OR invited_email = lower(btrim(invited_email))),
    CHECK (invited_email IS NULL OR position('@' IN invited_email) > 1),
    CHECK (role_id <> ''),
    CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    CHECK (status <> 'accepted' OR accepted_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS platform_org_invitations_org_status_idx
    ON platform_organization_invitations (tenant_id, organization_id, status, created_at DESC);

CREATE INDEX IF NOT EXISTS platform_org_invitations_principal_idx
    ON platform_organization_invitations (tenant_id, invited_principal_id, status)
    WHERE invited_principal_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS platform_org_invitations_email_idx
    ON platform_organization_invitations (tenant_id, invited_email, status)
    WHERE invited_email IS NOT NULL;
