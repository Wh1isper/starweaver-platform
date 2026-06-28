-- Core agent platform schema foundation.
-- This migration establishes durable identity, actor-resolution, ownership, and
-- safe business-resource tables before production HTTP entrypoints depend on
-- them. Later migrations should be additive.

CREATE TABLE IF NOT EXISTS platform_tenants (
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

CREATE TABLE IF NOT EXISTS platform_organizations (
    organization_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (organization_id LIKE 'org_%'),
    CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE TABLE IF NOT EXISTS platform_projects (
    project_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (project_id LIKE 'prj_%'),
    CHECK (status IN ('active', 'suspended', 'deleted'))
);

CREATE TABLE IF NOT EXISTS platform_principals (
    principal_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    principal_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (principal_id LIKE 'usr_%' OR principal_id LIKE 'svc_%' OR principal_id LIKE 'sys_%'),
    CHECK (principal_kind IN ('user', 'service_account', 'system')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS platform_users (
    user_id TEXT PRIMARY KEY REFERENCES platform_principals (principal_id),
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    default_organization_id TEXT REFERENCES platform_organizations (organization_id),
    default_project_id TEXT REFERENCES platform_projects (project_id),
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

CREATE TABLE IF NOT EXISTS platform_service_accounts (
    service_account_id TEXT PRIMARY KEY REFERENCES platform_principals (principal_id),
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    display_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (service_account_id LIKE 'svc_%'),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE TABLE IF NOT EXISTS platform_organization_memberships (
    organization_member_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
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

CREATE INDEX IF NOT EXISTS platform_org_members_principal_scope_idx
    ON platform_organization_memberships (tenant_id, principal_id, organization_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_project_memberships (
    project_member_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    organization_member_id TEXT REFERENCES platform_organization_memberships (organization_member_id),
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

CREATE INDEX IF NOT EXISTS platform_project_members_principal_scope_idx
    ON platform_project_memberships (tenant_id, organization_id, principal_id, project_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_identity_providers (
    identity_provider_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    provider_kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    issuer_url TEXT,
    authorization_endpoint TEXT,
    token_endpoint TEXT,
    jwks_uri TEXT,
    client_id TEXT,
    client_secret_ref TEXT,
    redirect_uri TEXT,
    requested_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    oidc_audiences JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_email_domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (identity_provider_id LIKE 'idp_%'),
    CHECK (provider_kind IN ('oidc', 'github_oauth_app', 'single_user')),
    CHECK (provider_kind <> 'oidc' OR issuer_url IS NOT NULL),
    CHECK (provider_kind <> 'oidc' OR jwks_uri IS NOT NULL),
    CHECK (provider_kind <> 'oidc' OR jsonb_array_length(oidc_audiences) > 0),
    CHECK (provider_kind <> 'github_oauth_app' OR client_id IS NOT NULL),
    CHECK (provider_kind <> 'single_user' OR client_secret_ref IS NULL),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_identity_providers_tenant_kind_idx
    ON platform_identity_providers (tenant_id, provider_kind)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_external_identities (
    external_identity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    identity_provider_id TEXT NOT NULL REFERENCES platform_identity_providers (identity_provider_id),
    provider_kind TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    email TEXT,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, identity_provider_id, provider_subject),
    CHECK (external_identity_id LIKE 'xid_%'),
    CHECK (provider_kind IN ('oidc', 'github_oauth_app', 'single_user')),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_external_identities_principal_idx
    ON platform_external_identities (tenant_id, principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_role_bindings (
    role_binding_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    role_id TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (role_binding_id LIKE 'rb_%'),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_role_bindings_principal_scope_idx
    ON platform_role_bindings (tenant_id, organization_id, project_id, principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_action_grants (
    action_grant_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
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
    CHECK (action_id LIKE 'platform.%'),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (status IN ('active', 'disabled', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_action_grants_principal_action_idx
    ON platform_action_grants (tenant_id, organization_id, project_id, principal_id, action_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_auth_sessions (
    auth_session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    actor_kind TEXT NOT NULL,
    identity_provider_id TEXT REFERENCES platform_identity_providers (identity_provider_id),
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (token_hash <> ''),
    CHECK (actor_kind IN ('user', 'service_account', 'system')),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (status IN ('active', 'revoked', 'expired', 'principal_disabled'))
);

CREATE INDEX IF NOT EXISTS platform_auth_sessions_actor_scope_idx
    ON platform_auth_sessions (tenant_id, organization_id, project_id, principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_bearer_credentials (
    credential_id TEXT PRIMARY KEY,
    credential_kind TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    owner_principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    actor_kind TEXT NOT NULL,
    name TEXT NOT NULL,
    token_prefix TEXT,
    token_hash TEXT NOT NULL UNIQUE,
    allowed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    allowed_resources JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_request_id TEXT,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (credential_kind IN ('api_key', 'service_token')),
    CHECK (token_hash <> ''),
    CHECK (actor_kind IN ('user', 'service_account', 'system')),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (status IN ('active', 'disabled', 'revoked', 'expired', 'principal_disabled'))
);

CREATE INDEX IF NOT EXISTS platform_bearer_credentials_actor_scope_idx
    ON platform_bearer_credentials (tenant_id, organization_id, project_id, owner_principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_mtls_identities (
    mtls_identity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    actor_kind TEXT NOT NULL,
    subject TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (mtls_identity_id LIKE 'mtls_%'),
    CHECK (subject <> ''),
    CHECK (actor_kind IN ('user', 'service_account', 'system')),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (status IN ('active', 'disabled', 'revoked', 'expired', 'principal_disabled'))
);

CREATE INDEX IF NOT EXISTS platform_mtls_identities_subject_idx
    ON platform_mtls_identities (subject)
    WHERE status = 'active';

CREATE INDEX IF NOT EXISTS platform_mtls_identities_actor_scope_idx
    ON platform_mtls_identities (tenant_id, organization_id, project_id, principal_id)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform_resource_owners (
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (resource_kind, resource_id),
    CHECK (resource_kind IN (
        'Conversation',
        'Session',
        'Run',
        'RunEvent',
        'Approval',
        'DeferredTool',
        'EnvironmentAttachment',
        'EvidenceArchive'
    )),
    CHECK (resource_id <> ''),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS platform_resource_owners_scope_idx
    ON platform_resource_owners (tenant_id, organization_id, project_id, resource_kind);

CREATE TABLE IF NOT EXISTS platform_conversations (
    conversation_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    owner_principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (conversation_id LIKE 'conv_%'),
    CHECK (status IN ('active', 'archived', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_conversations_project_status_idx
    ON platform_conversations (tenant_id, organization_id, project_id, status);

CREATE TABLE IF NOT EXISTS platform_agent_sessions (
    agent_session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    conversation_id TEXT NOT NULL REFERENCES platform_conversations (conversation_id),
    status TEXT NOT NULL,
    replay_cursor TEXT,
    context_manifest_uri TEXT,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (agent_session_id LIKE 'sess_%'),
    CHECK (status IN ('active', 'paused', 'closed', 'deleted'))
);

CREATE INDEX IF NOT EXISTS platform_agent_sessions_conversation_idx
    ON platform_agent_sessions (tenant_id, organization_id, project_id, conversation_id)
    WHERE status <> 'deleted';

CREATE TABLE IF NOT EXISTS platform_runs (
    run_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    conversation_id TEXT REFERENCES platform_conversations (conversation_id),
    agent_session_id TEXT REFERENCES platform_agent_sessions (agent_session_id),
    requester_principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    status TEXT NOT NULL,
    model_alias TEXT NOT NULL,
    gateway_request_id TEXT,
    cancellation_reason TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (run_id LIKE 'run_%'),
    CHECK (status IN ('queued', 'running', 'cancelling', 'succeeded', 'failed', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS platform_runs_project_status_idx
    ON platform_runs (tenant_id, organization_id, project_id, status, created_at);

CREATE TABLE IF NOT EXISTS platform_run_events (
    run_event_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    run_id TEXT NOT NULL REFERENCES platform_runs (run_id),
    event_sequence BIGINT NOT NULL,
    event_kind TEXT NOT NULL,
    safe_projection JSONB NOT NULL DEFAULT '{}'::jsonb,
    archive_ref TEXT,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    UNIQUE (run_id, event_sequence),
    CHECK (run_event_id LIKE 'runev_%'),
    CHECK (event_sequence >= 0),
    CHECK (event_kind <> '')
);

CREATE INDEX IF NOT EXISTS platform_run_events_run_sequence_idx
    ON platform_run_events (tenant_id, run_id, event_sequence);

CREATE TABLE IF NOT EXISTS platform_approvals (
    approval_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    run_id TEXT NOT NULL REFERENCES platform_runs (run_id),
    requested_action TEXT NOT NULL,
    status TEXT NOT NULL,
    decided_by TEXT REFERENCES platform_principals (principal_id),
    decided_at TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (approval_id LIKE 'appr_%'),
    CHECK (requested_action <> ''),
    CHECK (status IN ('pending', 'approved', 'denied', 'expired', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS platform_approvals_project_status_idx
    ON platform_approvals (tenant_id, organization_id, project_id, status, created_at);

CREATE TABLE IF NOT EXISTS platform_deferred_tools (
    deferred_tool_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    run_id TEXT NOT NULL REFERENCES platform_runs (run_id),
    tool_name TEXT NOT NULL,
    status TEXT NOT NULL,
    resume_after TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (deferred_tool_id LIKE 'dt_%'),
    CHECK (tool_name <> ''),
    CHECK (status IN ('pending', 'ready', 'resumed', 'expired', 'cancelled'))
);

CREATE INDEX IF NOT EXISTS platform_deferred_tools_project_status_idx
    ON platform_deferred_tools (tenant_id, organization_id, project_id, status, created_at);

CREATE TABLE IF NOT EXISTS platform_environment_attachments (
    attachment_lease_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    run_id TEXT REFERENCES platform_runs (run_id),
    provider_ref TEXT NOT NULL,
    readiness TEXT NOT NULL,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ,
    released_at TIMESTAMPTZ,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (attachment_lease_id LIKE 'lease_%'),
    CHECK (provider_ref <> ''),
    CHECK (readiness <> ''),
    CHECK (status IN ('attaching', 'ready', 'degraded', 'released', 'expired', 'failed'))
);

CREATE INDEX IF NOT EXISTS platform_environment_attachments_project_status_idx
    ON platform_environment_attachments (tenant_id, organization_id, project_id, status, created_at);

CREATE TABLE IF NOT EXISTS platform_evidence_archives (
    evidence_archive_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT NOT NULL REFERENCES platform_organizations (organization_id),
    project_id TEXT NOT NULL REFERENCES platform_projects (project_id),
    run_id TEXT NOT NULL REFERENCES platform_runs (run_id),
    manifest_uri TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    debug_available BOOLEAN NOT NULL DEFAULT false,
    redaction_profile TEXT NOT NULL,
    resource_version BIGINT NOT NULL DEFAULT 1,
    schema_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (evidence_archive_id LIKE 'evid_%'),
    CHECK (manifest_uri <> ''),
    CHECK (retention_class IN ('standard', 'compliance', 'short_lived')),
    CHECK (redaction_profile <> '')
);

CREATE INDEX IF NOT EXISTS platform_evidence_archives_project_idx
    ON platform_evidence_archives (tenant_id, organization_id, project_id, run_id, created_at);

CREATE TABLE IF NOT EXISTS platform_idempotency_keys (
    idempotency_key_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES platform_tenants (tenant_id),
    organization_id TEXT REFERENCES platform_organizations (organization_id),
    project_id TEXT REFERENCES platform_projects (project_id),
    principal_id TEXT NOT NULL REFERENCES platform_principals (principal_id),
    operation_kind TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL,
    response_ref TEXT,
    status TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (tenant_id, principal_id, operation_kind, idempotency_key_hash),
    CHECK (idempotency_key_id LIKE 'idem_%'),
    CHECK (operation_kind LIKE 'platform.%'),
    CHECK (project_id IS NULL OR organization_id IS NOT NULL),
    CHECK (idempotency_key_hash <> ''),
    CHECK (status IN ('in_progress', 'completed', 'expired'))
);

CREATE INDEX IF NOT EXISTS platform_idempotency_keys_expiry_idx
    ON platform_idempotency_keys (expires_at);
