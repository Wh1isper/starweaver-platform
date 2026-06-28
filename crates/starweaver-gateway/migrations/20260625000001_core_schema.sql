-- Core gateway schema foundation.
-- This migration establishes durable ownership and evidence tables before
-- runtime behavior depends on them. Later migrations should be additive.

CREATE TABLE IF NOT EXISTS gateway_tenants (
    tenant_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (tenant_id LIKE 'ten_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_organizations (
    organization_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (organization_id LIKE 'org_%'),
    CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_projects (
    project_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES gateway_organizations (organization_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (project_id LIKE 'prj_%'),
    CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_principals (
    principal_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    principal_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (principal_id LIKE 'usr_%' OR principal_id LIKE 'svc_%' OR principal_id LIKE 'sys_%'),
    CHECK (principal_kind IN ('user', 'service_account', 'internal_service', 'system')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_users (
    user_id TEXT PRIMARY KEY REFERENCES gateway_principals (principal_id),
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    default_organization_id TEXT REFERENCES gateway_organizations (organization_id),
    default_project_id TEXT REFERENCES gateway_projects (project_id),
    primary_email TEXT,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (user_id LIKE 'usr_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_service_accounts (
    service_account_id TEXT PRIMARY KEY REFERENCES gateway_principals (principal_id),
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (service_account_id LIKE 'svc_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_organization_memberships (
    organization_member_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES gateway_organizations (organization_id),
    principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    membership_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (organization_id, principal_id),
    CHECK (organization_member_id LIKE 'om_%'),
    CHECK (membership_kind IN ('user', 'service_account')),
    CHECK (status IN ('active', 'suspended', 'removed'))
);

CREATE INDEX IF NOT EXISTS gateway_org_members_principal_scope_idx
    ON gateway_organization_memberships (tenant_id, principal_id, organization_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_project_memberships (
    project_member_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES gateway_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES gateway_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    organization_member_id TEXT REFERENCES gateway_organization_memberships (organization_member_id),
    membership_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (project_id, principal_id),
    CHECK (project_member_id LIKE 'pm_%'),
    CHECK (membership_kind IN ('user', 'service_account')),
    CHECK (status IN ('active', 'suspended', 'removed'))
);

CREATE INDEX IF NOT EXISTS gateway_project_members_principal_scope_idx
    ON gateway_project_memberships (tenant_id, organization_id, principal_id, project_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_external_identities (
    external_identity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    login_provider_id TEXT,
    provider_kind TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    email TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, login_provider_id, provider_kind, provider_subject),
    CHECK (external_identity_id LIKE 'xid_%'),
    CHECK (provider_kind IN ('github_oauth_app', 'oidc')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_external_identities_principal_idx
    ON gateway_external_identities (tenant_id, principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_role_bindings (
    role_binding_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    role_id TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (role_binding_id LIKE 'rb_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_role_bindings_principal_scope_idx
    ON gateway_role_bindings (tenant_id, organization_id, project_id, principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_action_grants (
    action_grant_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    action_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (action_grant_id LIKE 'ag_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_action_grants_principal_action_idx
    ON gateway_action_grants (tenant_id, organization_id, project_id, principal_id, action_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_api_keys (
    api_key_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    owner_principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    hash_version INTEGER NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    allowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_request_id TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (api_key_id LIKE 'ak_%'),
    CHECK (status IN ('active', 'disabled', 'expired', 'rotating', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_api_keys_prefix_idx
    ON gateway_api_keys (key_prefix)
    WHERE status IN ('active', 'rotating');

CREATE INDEX IF NOT EXISTS gateway_api_keys_owner_scope_idx
    ON gateway_api_keys (tenant_id, owner_principal_id, organization_id, project_id)
    WHERE status IN ('active', 'rotating');

CREATE TABLE IF NOT EXISTS gateway_secret_refs (
    secret_ref_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    purpose TEXT NOT NULL,
    backend_kind TEXT NOT NULL,
    backend_locator_ciphertext TEXT NOT NULL,
    display_mask TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (secret_ref_id LIKE 'sec_%'),
    CHECK (status IN ('active', 'disabled', 'rotating', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_provider_endpoints (
    provider_endpoint_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    provider_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    protocol_families JSONB NOT NULL,
    upstream_base_url TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (provider_endpoint_id LIKE 'pep_%'),
    CHECK (status IN ('active', 'disabled', 'draining', 'degraded', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_upstream_credentials (
    upstream_credential_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    provider_endpoint_id TEXT NOT NULL REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    credential_kind TEXT NOT NULL,
    secret_ref_id TEXT NOT NULL REFERENCES gateway_secret_refs (secret_ref_id),
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (upstream_credential_id LIKE 'upc_%'),
    CHECK (status IN ('active', 'disabled', 'rotating', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_codex_oauth_connections (
    codex_oauth_connection_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    provider_endpoint_id TEXT NOT NULL REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    upstream_credential_id TEXT REFERENCES gateway_upstream_credentials (upstream_credential_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (codex_oauth_connection_id LIKE 'coc_%'),
    CHECK (status IN (
        'unauthenticated',
        'login_pending',
        'active',
        'expired',
        'error',
        'disabled'
    ))
);

CREATE TABLE IF NOT EXISTS gateway_codex_oauth_sessions (
    codex_oauth_session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    codex_oauth_connection_id TEXT NOT NULL REFERENCES gateway_codex_oauth_connections (codex_oauth_connection_id),
    upstream_credential_id TEXT NOT NULL REFERENCES gateway_upstream_credentials (upstream_credential_id),
    token_secret_ref_id TEXT NOT NULL REFERENCES gateway_secret_refs (secret_ref_id),
    token_expires_at TIMESTAMPTZ,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (codex_oauth_session_id LIKE 'cos_%'),
    CHECK (status IN ('login_pending', 'active', 'revoked', 'expired', 'error'))
);

CREATE TABLE IF NOT EXISTS gateway_codex_oauth_refresh_status (
    codex_oauth_refresh_status_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    codex_oauth_connection_id TEXT NOT NULL REFERENCES gateway_codex_oauth_connections (codex_oauth_connection_id),
    upstream_credential_id TEXT REFERENCES gateway_upstream_credentials (upstream_credential_id),
    status TEXT NOT NULL,
    last_refresh_at TIMESTAMPTZ,
    next_refresh_at TIMESTAMPTZ,
    token_expires_at TIMESTAMPTZ,
    last_error TEXT,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (codex_oauth_refresh_status_id LIKE 'cofr_%'),
    CHECK (status IN (
        'unauthenticated',
        'login_pending',
        'active',
        'expired',
        'error',
        'disabled'
    ))
);

CREATE TABLE IF NOT EXISTS gateway_provider_grants (
    provider_grant_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    principal_id TEXT REFERENCES gateway_principals (principal_id),
    provider_endpoint_id TEXT NOT NULL REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    model_target_id TEXT,
    action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (provider_grant_id LIKE 'pg_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_provider_grants_scope_idx
    ON gateway_provider_grants (tenant_id, organization_id, project_id, principal_id, provider_endpoint_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_pricing_skus (
    pricing_sku_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    provider_endpoint_id TEXT REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    model_target_id TEXT,
    currency_code TEXT NOT NULL,
    pricing_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (pricing_sku_id LIKE 'sku_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_model_targets (
    model_target_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    provider_endpoint_id TEXT NOT NULL REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    upstream_credential_id TEXT REFERENCES gateway_upstream_credentials (upstream_credential_id),
    protocol_family TEXT NOT NULL,
    upstream_model_id TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (model_target_id LIKE 'mt_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_model_aliases (
    model_alias_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    alias_name TEXT NOT NULL,
    protocol_family TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (model_alias_id LIKE 'ma_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE UNIQUE INDEX IF NOT EXISTS gateway_model_aliases_scope_alias_idx
    ON gateway_model_aliases (
        tenant_id,
        COALESCE(organization_id, ''),
        COALESCE(project_id, ''),
        alias_name
    )
    WHERE status != 'deleted';

CREATE TABLE IF NOT EXISTS gateway_routing_groups (
    routing_group_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (routing_group_id LIKE 'rg_%'),
    CHECK (status IN ('active', 'disabled', 'draining', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_routing_group_targets (
    routing_group_target_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    routing_group_id TEXT NOT NULL REFERENCES gateway_routing_groups (routing_group_id),
    model_target_id TEXT NOT NULL REFERENCES gateway_model_targets (model_target_id),
    weight INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (routing_group_id, model_target_id),
    CHECK (routing_group_target_id LIKE 'rgt_%'),
    CHECK (weight > 0),
    CHECK (status IN ('active', 'disabled', 'draining', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_route_policies (
    route_policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    model_alias_id TEXT NOT NULL REFERENCES gateway_model_aliases (model_alias_id),
    routing_group_id TEXT NOT NULL REFERENCES gateway_routing_groups (routing_group_id),
    policy_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (route_policy_id LIKE 'rp_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_route_rules (
    route_rule_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    route_policy_id TEXT NOT NULL REFERENCES gateway_route_policies (route_policy_id),
    routing_group_id TEXT NOT NULL REFERENCES gateway_routing_groups (routing_group_id),
    rule_order INTEGER NOT NULL,
    match_document JSONB NOT NULL,
    action_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (route_policy_id, rule_order),
    CHECK (route_rule_id LIKE 'rr_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_route_decisions (
    route_decision_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    principal_id TEXT REFERENCES gateway_principals (principal_id),
    api_key_id TEXT REFERENCES gateway_api_keys (api_key_id),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    request_id TEXT NOT NULL,
    protocol_family TEXT NOT NULL,
    config_snapshot_id TEXT,
    config_version BIGINT,
    model_alias_id TEXT REFERENCES gateway_model_aliases (model_alias_id),
    alias_name TEXT NOT NULL,
    route_policy_id TEXT REFERENCES gateway_route_policies (route_policy_id),
    routing_group_id TEXT REFERENCES gateway_routing_groups (routing_group_id),
    model_target_id TEXT REFERENCES gateway_model_targets (model_target_id),
    provider_endpoint_id TEXT REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    upstream_credential_id TEXT REFERENCES gateway_upstream_credentials (upstream_credential_id),
    filtered_summary JSONB NOT NULL DEFAULT '[]'::jsonb,
    decision_status TEXT NOT NULL,
    reason TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    CHECK (route_decision_id LIKE 'rd_%'),
    CHECK (decision_status IN ('started', 'selected', 'blocked', 'no_route', 'completed', 'failed'))
);

CREATE INDEX IF NOT EXISTS gateway_route_decisions_scope_time_idx
    ON gateway_route_decisions (tenant_id, organization_id, project_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS gateway_route_decisions_request_idx
    ON gateway_route_decisions (tenant_id, request_id);

CREATE TABLE IF NOT EXISTS gateway_route_attempt_events (
    route_attempt_event_id TEXT PRIMARY KEY,
    route_decision_id TEXT NOT NULL REFERENCES gateway_route_decisions (route_decision_id),
    attempt_index INTEGER NOT NULL,
    routing_group_id TEXT NOT NULL REFERENCES gateway_routing_groups (routing_group_id),
    model_target_id TEXT NOT NULL REFERENCES gateway_model_targets (model_target_id),
    provider_endpoint_id TEXT NOT NULL REFERENCES gateway_provider_endpoints (provider_endpoint_id),
    status TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    CHECK (route_attempt_event_id LIKE 'rae_%'),
    CHECK (attempt_index >= 0),
    CHECK (status IN ('started', 'completed', 'failed', 'client_disconnected'))
);

CREATE INDEX IF NOT EXISTS gateway_route_attempts_decision_idx
    ON gateway_route_attempt_events (route_decision_id, attempt_index);

CREATE TABLE IF NOT EXISTS gateway_config_snapshots (
    config_snapshot_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    version BIGINT NOT NULL,
    checksum TEXT NOT NULL,
    status TEXT NOT NULL,
    diagnostics JSONB NOT NULL DEFAULT '[]'::jsonb,
    snapshot_document JSONB NOT NULL DEFAULT '{}'::jsonb,
    schema_version INTEGER NOT NULL DEFAULT 1,
    compiled_at TIMESTAMPTZ NOT NULL,
    published_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    UNIQUE (tenant_id, version),
    CHECK (config_snapshot_id LIKE 'cfg_%'),
    CHECK (status IN ('pending', 'published', 'rejected', 'rolled_back'))
);

CREATE TABLE IF NOT EXISTS gateway_config_invalidation_events (
    config_invalidation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    config_snapshot_id TEXT NOT NULL REFERENCES gateway_config_snapshots (config_snapshot_id),
    version BIGINT NOT NULL,
    checksum TEXT NOT NULL,
    published_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, version),
    CHECK (config_invalidation_id LIKE 'cfginv_%')
);

CREATE INDEX IF NOT EXISTS gateway_config_invalidations_tenant_version_idx
    ON gateway_config_invalidation_events (tenant_id, version DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS gateway_config_publications (
    tenant_id TEXT PRIMARY KEY REFERENCES gateway_tenants (tenant_id),
    config_snapshot_id TEXT NOT NULL REFERENCES gateway_config_snapshots (config_snapshot_id),
    version BIGINT NOT NULL,
    checksum TEXT NOT NULL,
    config_invalidation_id TEXT NOT NULL REFERENCES gateway_config_invalidation_events (config_invalidation_id),
    published_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS gateway_config_worker_reloads (
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    worker_id TEXT NOT NULL,
    config_snapshot_id TEXT NOT NULL REFERENCES gateway_config_snapshots (config_snapshot_id),
    loaded_version BIGINT NOT NULL,
    checksum TEXT NOT NULL,
    last_known_good_snapshot_id TEXT NOT NULL REFERENCES gateway_config_snapshots (config_snapshot_id),
    last_known_good_version BIGINT NOT NULL,
    reload_source TEXT NOT NULL,
    status TEXT NOT NULL,
    missed_invalidation_count INTEGER NOT NULL DEFAULT 0,
    publication_lag_ms BIGINT NOT NULL DEFAULT 0,
    reloaded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, worker_id),
    CHECK (reload_source IN ('invalidation', 'polling')),
    CHECK (status IN ('loaded', 'failed')),
    CHECK (missed_invalidation_count >= 0),
    CHECK (publication_lag_ms >= 0)
);

CREATE INDEX IF NOT EXISTS gateway_config_worker_reloads_tenant_status_idx
    ON gateway_config_worker_reloads (tenant_id, status, loaded_version DESC, reloaded_at DESC);

CREATE TABLE IF NOT EXISTS gateway_validation_diagnostics (
    validation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    resource_kind TEXT NOT NULL,
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    valid BOOLEAN NOT NULL,
    errors JSONB NOT NULL DEFAULT '[]'::jsonb,
    warnings JSONB NOT NULL DEFAULT '[]'::jsonb,
    affected_resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    publication_plan JSONB,
    route_simulation JSONB,
    budget_simulation JSONB,
    created_by TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (validation_id LIKE 'vdiag_%'),
    CHECK (jsonb_typeof(errors) = 'array'),
    CHECK (jsonb_typeof(warnings) = 'array'),
    CHECK (jsonb_typeof(affected_resources) = 'array')
);

CREATE INDEX IF NOT EXISTS gateway_validation_diagnostics_scope_time_idx
    ON gateway_validation_diagnostics (
        tenant_id,
        resource_kind,
        scope_kind,
        valid,
        created_at DESC
    );

CREATE TABLE IF NOT EXISTS gateway_usage_events (
    usage_event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    principal_id TEXT REFERENCES gateway_principals (principal_id),
    project_member_id TEXT REFERENCES gateway_project_memberships (project_member_id),
    service_account_id TEXT REFERENCES gateway_service_accounts (service_account_id),
    api_key_id TEXT REFERENCES gateway_api_keys (api_key_id),
    request_id TEXT NOT NULL,
    protocol_family TEXT NOT NULL,
    route_decision_id TEXT REFERENCES gateway_route_decisions (route_decision_id),
    model_alias_id TEXT,
    model_target_id TEXT,
    route_policy_id TEXT REFERENCES gateway_route_policies (route_policy_id),
    routing_group_id TEXT REFERENCES gateway_routing_groups (routing_group_id),
    provider_endpoint_id TEXT,
    upstream_credential_id TEXT,
    usage_confidence TEXT NOT NULL,
    latency_ms INTEGER,
    time_to_first_token_ms INTEGER,
    status TEXT NOT NULL,
    usage_payload JSONB NOT NULL,
    cost_payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, request_id)
);

CREATE INDEX IF NOT EXISTS gateway_usage_scope_time_idx
    ON gateway_usage_events (tenant_id, organization_id, project_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS gateway_usage_member_time_idx
    ON gateway_usage_events (tenant_id, project_member_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS gateway_ledger_buckets (
    ledger_bucket_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    principal_id TEXT REFERENCES gateway_principals (principal_id),
    project_member_id TEXT REFERENCES gateway_project_memberships (project_member_id),
    service_account_id TEXT REFERENCES gateway_service_accounts (service_account_id),
    api_key_id TEXT REFERENCES gateway_api_keys (api_key_id),
    model_alias_id TEXT,
    model_target_id TEXT,
    provider_endpoint_id TEXT,
    upstream_credential_id TEXT,
    route_policy_id TEXT REFERENCES gateway_route_policies (route_policy_id),
    routing_group_id TEXT REFERENCES gateway_routing_groups (routing_group_id),
    protocol_family TEXT,
    status TEXT,
    usage_confidence TEXT,
    bucket_kind TEXT NOT NULL,
    bucket_start TIMESTAMPTZ NOT NULL,
    currency_code TEXT NOT NULL,
    input_tokens BIGINT NOT NULL DEFAULT 0,
    output_tokens BIGINT NOT NULL DEFAULT 0,
    reasoning_tokens BIGINT NOT NULL DEFAULT 0,
    media_units BIGINT NOT NULL DEFAULT 0,
    request_count BIGINT NOT NULL DEFAULT 0,
    success_count BIGINT NOT NULL DEFAULT 0,
    error_count BIGINT NOT NULL DEFAULT 0,
    blocked_count BIGINT NOT NULL DEFAULT 0,
    usage_missing_count BIGINT NOT NULL DEFAULT 0,
    usage_estimated_count BIGINT NOT NULL DEFAULT 0,
    estimated_cost_micros BIGINT NOT NULL DEFAULT 0,
    latency_ms_sum BIGINT NOT NULL DEFAULT 0,
    latency_sample_count BIGINT NOT NULL DEFAULT 0,
    ttft_ms_sum BIGINT NOT NULL DEFAULT 0,
    ttft_sample_count BIGINT NOT NULL DEFAULT 0,
    pricing_version TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, organization_id, project_id, principal_id, project_member_id, service_account_id, api_key_id, model_alias_id, model_target_id, provider_endpoint_id, upstream_credential_id, route_policy_id, routing_group_id, protocol_family, status, usage_confidence, bucket_kind, bucket_start),
    CHECK (ledger_bucket_id LIKE 'lb_%'),
    CHECK (bucket_kind IN ('event', 'minute', 'hour', 'day', 'month'))
);

CREATE INDEX IF NOT EXISTS gateway_ledger_buckets_scope_time_idx
    ON gateway_ledger_buckets (tenant_id, organization_id, project_id, bucket_kind, bucket_start DESC);

CREATE INDEX IF NOT EXISTS gateway_ledger_buckets_member_time_idx
    ON gateway_ledger_buckets (tenant_id, project_member_id, bucket_kind, bucket_start DESC);

CREATE TABLE IF NOT EXISTS gateway_budget_policies (
    budget_policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    currency_code TEXT NOT NULL,
    policy_document JSONB NOT NULL,
    stale_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (budget_policy_id LIKE 'bp_%'),
    CHECK (scope_kind IN ('tenant', 'organization', 'project', 'project_member', 'api_key', 'service_account', 'model_alias', 'model_target')),
    CHECK (stale_mode IN ('fail_closed', 'fail_limited', 'fail_open')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_budget_policies_scope_idx
    ON gateway_budget_policies (tenant_id, organization_id, project_id, scope_kind, scope_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_quota_policies (
    quota_policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    counter_kind TEXT NOT NULL,
    limit_value BIGINT NOT NULL,
    burst_limit BIGINT,
    window_kind TEXT NOT NULL,
    increment_source TEXT NOT NULL,
    loss_behavior TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (quota_policy_id LIKE 'qp_%'),
    CHECK (scope_kind IN ('tenant', 'organization', 'project', 'credential', 'alias', 'endpoint', 'protocol_family')),
    CHECK (counter_kind IN ('request_rate', 'token_estimate_rate', 'token_actual_rate', 'concurrent_request', 'concurrent_stream', 'stream_duration', 'request_body_bytes')),
    CHECK (limit_value > 0),
    CHECK (burst_limit IS NULL OR burst_limit > 0),
    CHECK (window_kind IN ('fixed', 'sliding', 'ledger_bucket', 'request_lifetime', 'stream_lifetime')),
    CHECK (increment_source IN ('accepted_preflight_request', 'request_estimate', 'terminal_usage_event', 'preflight_acquire', 'stream_start', 'request_body_bytes')),
    CHECK (loss_behavior IN ('fail_closed', 'fail_limited', 'fail_open')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_quota_policies_scope_idx
    ON gateway_quota_policies (tenant_id, organization_id, project_id, scope_kind, scope_id)
    WHERE status = 'active';

CREATE UNIQUE INDEX IF NOT EXISTS gateway_quota_policies_active_shape_idx
    ON gateway_quota_policies (tenant_id, scope_kind, scope_id, counter_kind, window_kind)
    WHERE status != 'deleted';

CREATE TABLE IF NOT EXISTS gateway_rate_limit_policies (
    rate_limit_policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    scope_kind TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    window_kind TEXT NOT NULL,
    limit_document JSONB NOT NULL,
    cache_loss_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (rate_limit_policy_id LIKE 'rlp_%'),
    CHECK (scope_kind IN ('tenant', 'organization', 'project', 'project_member', 'api_key', 'service_account', 'model_alias', 'model_target')),
    CHECK (window_kind IN ('second', 'minute', 'hour', 'day')),
    CHECK (cache_loss_mode IN ('fail_closed', 'fail_limited', 'fail_open')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_rate_limit_policies_scope_idx
    ON gateway_rate_limit_policies (tenant_id, organization_id, project_id, scope_kind, scope_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_audit_events (
    audit_event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    action_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    event_payload JSONB NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    CHECK (decision IN ('allowed', 'denied', 'failed'))
);

CREATE INDEX IF NOT EXISTS gateway_audit_scope_time_idx
    ON gateway_audit_events (tenant_id, organization_id, project_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS gateway_audit_actor_time_idx
    ON gateway_audit_events (tenant_id, actor_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS gateway_authz_decision_events (
    authz_decision_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    action_id TEXT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    policy_snapshot_id TEXT REFERENCES gateway_config_snapshots (config_snapshot_id),
    request_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    CHECK (authz_decision_id LIKE 'azd_%'),
    CHECK (decision IN ('allowed', 'denied'))
);

CREATE INDEX IF NOT EXISTS gateway_authz_decision_scope_time_idx
    ON gateway_authz_decision_events (tenant_id, organization_id, project_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS gateway_auth_sessions (
    auth_session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    principal_id TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    active_organization_id TEXT REFERENCES gateway_organizations (organization_id),
    active_project_id TEXT REFERENCES gateway_projects (project_id),
    session_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (auth_session_id LIKE 'sess_%'),
    CHECK (status IN ('active', 'revoked', 'expired'))
);

CREATE TABLE IF NOT EXISTS gateway_login_providers (
    login_provider_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    provider_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    config_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (login_provider_id LIKE 'lp_%'),
    CHECK (provider_kind IN ('github_oauth_app', 'oidc')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_login_attempts (
    login_attempt_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    login_provider_id TEXT NOT NULL REFERENCES gateway_login_providers (login_provider_id),
    provider_kind TEXT NOT NULL,
    state_hash TEXT NOT NULL UNIQUE,
    nonce_hash TEXT,
    code_verifier_hash TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (login_attempt_id LIKE 'lat_%'),
    CHECK (provider_kind IN ('github_oauth_app', 'oidc')),
    CHECK (state_hash LIKE 'sha256:%'),
    CHECK (nonce_hash IS NULL OR nonce_hash LIKE 'sha256:%'),
    CHECK (code_verifier_hash LIKE 'sha256:%'),
    CHECK (status IN ('pending', 'consumed', 'expired'))
);

CREATE INDEX IF NOT EXISTS gateway_login_attempts_provider_status_idx
    ON gateway_login_attempts (tenant_id, login_provider_id, status, expires_at);

CREATE TABLE IF NOT EXISTS gateway_dashboard_configs (
    dashboard_config_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    config_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (dashboard_config_id LIKE 'dbc_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_otel_export_configs (
    otel_export_config_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    endpoint_url TEXT NOT NULL,
    protocol TEXT NOT NULL,
    header_refs JSONB NOT NULL DEFAULT '[]'::jsonb,
    signal_config JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (otel_export_config_id LIKE 'otel_%'),
    CHECK (endpoint_url LIKE 'https://%'),
    CHECK (protocol IN ('otlp_http', 'otlp_grpc')),
    CHECK (COALESCE(jsonb_typeof(header_refs) = 'array', false)),
    CHECK (COALESCE(jsonb_typeof(signal_config->'enabled_signals') = 'array', false)),
    CHECK (COALESCE((signal_config->'enabled_signals') ? 'metrics', false)),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_otel_export_configs_scope_idx
    ON gateway_otel_export_configs (tenant_id, organization_id, project_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS gateway_otel_exporter_health (
    otel_exporter_health_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    otel_export_config_id TEXT NOT NULL REFERENCES gateway_otel_export_configs (otel_export_config_id),
    worker_id TEXT NOT NULL,
    status TEXT NOT NULL,
    failure_count BIGINT NOT NULL DEFAULT 0,
    dropped_metric_count BIGINT NOT NULL DEFAULT 0,
    exported_metric_count BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    last_attempted_at TIMESTAMPTZ NOT NULL,
    last_successful_export_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, otel_export_config_id),
    CHECK (otel_exporter_health_id LIKE 'otelh_%'),
    CHECK (status IN ('succeeded', 'retryable_failed', 'disabled')),
    CHECK (failure_count >= 0),
    CHECK (dropped_metric_count >= 0),
    CHECK (exported_metric_count >= 0)
);

CREATE INDEX IF NOT EXISTS gateway_otel_exporter_health_scope_status_idx
    ON gateway_otel_exporter_health (tenant_id, status, last_attempted_at DESC);

CREATE TABLE IF NOT EXISTS gateway_redaction_policies (
    redaction_policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    policy_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (redaction_policy_id LIKE 'redp_%'),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_debug_capture_policies (
    debug_capture_policy_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    capture_document JSONB NOT NULL,
    retention_seconds INTEGER NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (debug_capture_policy_id LIKE 'dcp_%'),
    CHECK (retention_seconds > 0),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS gateway_debug_capture_records (
    debug_capture_record_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    request_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    debug_capture_policy_id TEXT REFERENCES gateway_debug_capture_policies (debug_capture_policy_id),
    storage_ref_id TEXT REFERENCES gateway_secret_refs (secret_ref_id),
    metadata_document JSONB NOT NULL,
    status TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    retention_expires_at TIMESTAMPTZ NOT NULL,
    CHECK (debug_capture_record_id LIKE 'dcr_%'),
    CHECK (status IN ('captured', 'redacted', 'purged'))
);

CREATE INDEX IF NOT EXISTS gateway_debug_capture_records_scope_time_idx
    ON gateway_debug_capture_records (tenant_id, organization_id, project_id, captured_at DESC);

CREATE TABLE IF NOT EXISTS gateway_notification_sinks (
    notification_sink_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    sink_kind TEXT NOT NULL,
    endpoint_config JSONB NOT NULL,
    signing_secret_ref_id TEXT REFERENCES gateway_secret_refs (secret_ref_id),
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (notification_sink_id LIKE 'ns_%'),
    CHECK (sink_kind IN ('webhook', 'object_export', 'pubsub', 'stdout', 'disabled')),
    CHECK (status IN ('active', 'disabled', 'degraded', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_notification_sinks_scope_idx
    ON gateway_notification_sinks (tenant_id, organization_id, project_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS gateway_notification_subscriptions (
    notification_subscription_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    notification_sink_id TEXT NOT NULL REFERENCES gateway_notification_sinks (notification_sink_id),
    event_family TEXT NOT NULL,
    filter_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (notification_subscription_id LIKE 'nsub_%'),
    CHECK (event_family IN ('usage', 'budget', 'quota', 'routing', 'provider_health', 'credential', 'admin', 'delivery')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS gateway_notification_subscriptions_sink_idx
    ON gateway_notification_subscriptions (notification_sink_id, status, event_family);

CREATE TABLE IF NOT EXISTS gateway_notification_outbox_events (
    notification_outbox_event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    notification_subscription_id TEXT REFERENCES gateway_notification_subscriptions (notification_subscription_id),
    notification_sink_id TEXT REFERENCES gateway_notification_sinks (notification_sink_id),
    event_kind TEXT NOT NULL,
    dedupe_key TEXT NOT NULL,
    payload_document JSONB NOT NULL,
    status TEXT NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, dedupe_key),
    CHECK (notification_outbox_event_id LIKE 'nob_%'),
    CHECK (attempt_count >= 0),
    CHECK (status IN ('pending', 'delivering', 'delivered', 'retryable_failed', 'permanent_failed', 'dead_lettered'))
);

CREATE INDEX IF NOT EXISTS gateway_notification_outbox_status_idx
    ON gateway_notification_outbox_events (status, next_attempt_at, created_at);

CREATE TABLE IF NOT EXISTS gateway_notification_delivery_attempts (
    notification_delivery_attempt_id TEXT PRIMARY KEY,
    notification_outbox_event_id TEXT NOT NULL REFERENCES gateway_notification_outbox_events (notification_outbox_event_id),
    notification_sink_id TEXT REFERENCES gateway_notification_sinks (notification_sink_id),
    attempt_index INTEGER NOT NULL,
    status TEXT NOT NULL,
    response_status INTEGER,
    error_message TEXT,
    request_body_sha256 TEXT,
    signing_secret_ref_id TEXT REFERENCES gateway_secret_refs (secret_ref_id),
    signature_sha256 TEXT,
    delivery_headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    attempted_at TIMESTAMPTZ NOT NULL,
    CHECK (notification_delivery_attempt_id LIKE 'nda_%'),
    CHECK (attempt_index >= 0),
    CHECK (request_body_sha256 IS NULL OR request_body_sha256 LIKE 'sha256:%'),
    CHECK (signature_sha256 IS NULL OR signature_sha256 LIKE 'sha256:%'),
    CHECK (status IN ('started', 'succeeded', 'retryable_failed', 'permanent_failed', 'dead_lettered'))
);

CREATE INDEX IF NOT EXISTS gateway_notification_delivery_attempts_event_idx
    ON gateway_notification_delivery_attempts (notification_outbox_event_id, attempt_index);

CREATE TABLE IF NOT EXISTS gateway_export_jobs (
    export_job_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    export_kind TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    query_document JSONB NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    CHECK (export_job_id LIKE 'exj_%'),
    CHECK (export_kind IN ('usage', 'audit')),
    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'expired'))
);

CREATE INDEX IF NOT EXISTS gateway_export_jobs_scope_status_idx
    ON gateway_export_jobs (tenant_id, organization_id, project_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS gateway_export_manifests (
    export_manifest_id TEXT PRIMARY KEY,
    export_job_id TEXT NOT NULL REFERENCES gateway_export_jobs (export_job_id),
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    object_ref TEXT NOT NULL,
    record_count BIGINT NOT NULL DEFAULT 0,
    byte_count BIGINT NOT NULL DEFAULT 0,
    checksum TEXT NOT NULL,
    manifest_document JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (export_manifest_id LIKE 'exm_%'),
    CHECK (record_count >= 0),
    CHECK (byte_count >= 0)
);

CREATE TABLE IF NOT EXISTS gateway_emergency_operations (
    emergency_operation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    operation_kind TEXT NOT NULL,
    target_resource_kind TEXT NOT NULL,
    target_resource_id TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES gateway_principals (principal_id),
    reason TEXT NOT NULL,
    status TEXT NOT NULL,
    operator_alert_document JSONB NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (emergency_operation_id LIKE 'emop_%'),
    CHECK (operation_kind IN ('disable_upstream_credential', 'disable_provider_endpoint', 'drain_routing_group', 'freeze_config')),
    CHECK (target_resource_kind IN ('UpstreamCredential', 'ProviderEndpoint', 'RoutingGroup', 'Config')),
    CHECK (status IN ('applied', 'expired', 'reverted', 'failed')),
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS gateway_emergency_operations_scope_status_idx
    ON gateway_emergency_operations (tenant_id, operation_kind, status, expires_at DESC, created_at DESC);

CREATE TABLE IF NOT EXISTS gateway_invitations (
    invitation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    organization_id TEXT REFERENCES gateway_organizations (organization_id),
    project_id TEXT REFERENCES gateway_projects (project_id),
    invited_email TEXT,
    invited_principal_id TEXT REFERENCES gateway_principals (principal_id),
    invitation_token_hash TEXT NOT NULL,
    role_id TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (invitation_id LIKE 'inv_%'),
    CHECK (status IN ('pending', 'accepted', 'revoked', 'expired'))
);

CREATE TABLE IF NOT EXISTS gateway_idempotency_keys (
    idempotency_key_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES gateway_tenants (tenant_id),
    scope_key TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_record JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, scope_key)
);

ALTER TABLE gateway_organizations
    ADD CONSTRAINT gateway_organizations_tenant_org_key
    UNIQUE (tenant_id, organization_id);

ALTER TABLE gateway_projects
    ADD CONSTRAINT gateway_projects_tenant_project_key
    UNIQUE (tenant_id, project_id),
    ADD CONSTRAINT gateway_projects_tenant_org_project_key
    UNIQUE (tenant_id, organization_id, project_id),
    ADD CONSTRAINT gateway_projects_tenant_org_fk
    FOREIGN KEY (tenant_id, organization_id)
    REFERENCES gateway_organizations (tenant_id, organization_id);

ALTER TABLE gateway_principals
    ADD CONSTRAINT gateway_principals_tenant_principal_key
    UNIQUE (tenant_id, principal_id);

ALTER TABLE gateway_organization_memberships
    ADD CONSTRAINT gateway_org_members_tenant_org_member_key
    UNIQUE (tenant_id, organization_id, organization_member_id),
    ADD CONSTRAINT gateway_org_members_tenant_org_fk
    FOREIGN KEY (tenant_id, organization_id)
    REFERENCES gateway_organizations (tenant_id, organization_id),
    ADD CONSTRAINT gateway_org_members_tenant_principal_fk
    FOREIGN KEY (tenant_id, principal_id)
    REFERENCES gateway_principals (tenant_id, principal_id);

ALTER TABLE gateway_project_memberships
    ADD CONSTRAINT gateway_project_members_tenant_project_member_key
    UNIQUE (tenant_id, organization_id, project_id, project_member_id),
    ADD CONSTRAINT gateway_project_members_tenant_project_fk
    FOREIGN KEY (tenant_id, organization_id, project_id)
    REFERENCES gateway_projects (tenant_id, organization_id, project_id),
    ADD CONSTRAINT gateway_project_members_tenant_principal_fk
    FOREIGN KEY (tenant_id, principal_id)
    REFERENCES gateway_principals (tenant_id, principal_id),
    ADD CONSTRAINT gateway_project_members_tenant_org_member_fk
    FOREIGN KEY (tenant_id, organization_id, organization_member_id)
    REFERENCES gateway_organization_memberships (tenant_id, organization_id, organization_member_id);

ALTER TABLE gateway_api_keys
    ADD CONSTRAINT gateway_api_keys_tenant_owner_fk
    FOREIGN KEY (tenant_id, owner_principal_id)
    REFERENCES gateway_principals (tenant_id, principal_id),
    ADD CONSTRAINT gateway_api_keys_tenant_project_fk
    FOREIGN KEY (tenant_id, organization_id, project_id)
    REFERENCES gateway_projects (tenant_id, organization_id, project_id);

ALTER TABLE gateway_role_bindings
    ADD CONSTRAINT gateway_role_bindings_tenant_principal_fk
    FOREIGN KEY (tenant_id, principal_id)
    REFERENCES gateway_principals (tenant_id, principal_id),
    ADD CONSTRAINT gateway_role_bindings_tenant_project_fk
    FOREIGN KEY (tenant_id, organization_id, project_id)
    REFERENCES gateway_projects (tenant_id, organization_id, project_id);

ALTER TABLE gateway_action_grants
    ADD CONSTRAINT gateway_action_grants_tenant_principal_fk
    FOREIGN KEY (tenant_id, principal_id)
    REFERENCES gateway_principals (tenant_id, principal_id),
    ADD CONSTRAINT gateway_action_grants_tenant_project_fk
    FOREIGN KEY (tenant_id, organization_id, project_id)
    REFERENCES gateway_projects (tenant_id, organization_id, project_id);
