-- Platform secret references and OIDC token endpoint auth method.
-- Raw secret values are not stored in this schema. Environment-backed refs keep
-- only safe locator metadata, display masks, and fingerprints.

CREATE TABLE IF NOT EXISTS platform_secret_refs (
    secret_ref_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    purpose TEXT NOT NULL,
    backend_kind TEXT NOT NULL,
    backend_locator TEXT NOT NULL,
    display_mask TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (secret_ref_id LIKE 'sec_%'),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (backend_kind IN ('environment')),
    CHECK (status IN ('active', 'rotating', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_secret_refs_tenant_idx
    ON platform_secret_refs (tenant_id, organization_id, project_id)
    WHERE status IN ('active', 'rotating');

ALTER TABLE platform_identity_providers
    ADD COLUMN IF NOT EXISTS token_endpoint_auth_method TEXT NOT NULL DEFAULT 'none';

ALTER TABLE platform_identity_providers
    DROP CONSTRAINT IF EXISTS platform_identity_providers_oidc_token_auth_method_check;

ALTER TABLE platform_identity_providers
    ADD CONSTRAINT platform_identity_providers_oidc_token_auth_method_check
    CHECK (
        provider_kind <> 'oidc'
        OR (
            token_endpoint_auth_method IN (
                'none',
                'client_secret_basic',
                'client_secret_post'
            )
            AND (
                (client_secret_ref IS NULL AND token_endpoint_auth_method = 'none')
                OR (
                    client_secret_ref IS NOT NULL
                    AND token_endpoint_auth_method IN (
                        'client_secret_basic',
                        'client_secret_post'
                    )
                )
            )
        )
    );

ALTER TABLE platform_identity_providers
    DROP CONSTRAINT IF EXISTS platform_identity_providers_client_secret_ref_fkey;

ALTER TABLE platform_identity_providers
    ADD CONSTRAINT platform_identity_providers_client_secret_ref_fkey
    FOREIGN KEY (client_secret_ref)
    REFERENCES platform_secret_refs (secret_ref_id);
