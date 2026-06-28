-- Durable platform OIDC login-attempt storage.
-- Raw OAuth state, OIDC nonce, and PKCE verifier material must not be stored.
-- Callback lookup uses domain-separated hashes produced by the platform service.

CREATE TABLE IF NOT EXISTS platform_oidc_login_attempts (
    oidc_login_attempt_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    identity_provider_id TEXT NOT NULL REFERENCES platform_identity_providers (identity_provider_id),
    state_hash TEXT NOT NULL UNIQUE,
    nonce_hash TEXT NOT NULL,
    pkce_verifier_hash TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (oidc_login_attempt_id LIKE 'ola_%'),
    CHECK (length(state_hash) = 64 AND state_hash ~ '^[0-9a-f]{64}$'),
    CHECK (length(nonce_hash) = 64 AND nonce_hash ~ '^[0-9a-f]{64}$'),
    CHECK (length(pkce_verifier_hash) = 64 AND pkce_verifier_hash ~ '^[0-9a-f]{64}$'),
    CHECK (redirect_uri LIKE 'https://%'),
    CHECK (status IN ('active', 'consumed', 'expired', 'abandoned')),
    CHECK (status <> 'consumed' OR consumed_at IS NOT NULL),
    CHECK (status = 'consumed' OR consumed_at IS NULL)
);

CREATE INDEX IF NOT EXISTS platform_oidc_login_attempts_provider_status_idx
    ON platform_oidc_login_attempts (tenant_id, identity_provider_id, status, expires_at);

CREATE INDEX IF NOT EXISTS platform_oidc_login_attempts_expiry_idx
    ON platform_oidc_login_attempts (status, expires_at)
    WHERE status = 'active';
