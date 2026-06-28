//! PostgreSQL repository adapters for platform durable state.

use std::fmt::{Display, Formatter};

use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};

use crate::action::{ActorKind, AuthenticatedActor, BuiltInRole};
use crate::audit::{
    validate_platform_audit_event_record, PlatformAuditError, PlatformAuditEventRecord,
};
use crate::auth::{
    hash_bearer_credential_token, hash_session_token, AuthError, PlatformAuthSessionRecord,
    PlatformAuthSessionStatus, PlatformBearerCredentialRecord, PlatformMtlsIdentityRecord,
};
use crate::identity::{
    hash_oidc_login_state, validate_external_identity, validate_oidc_login_attempt_record,
    validate_oidc_login_provider_base, OidcLoginAttemptRecord, OidcLoginAttemptStatus,
    OidcLoginProviderRecord, OidcLoginProviderStatus, OidcTokenEndpointAuthMethod,
    OidcValidationError, PlatformExternalIdentityError, PlatformExternalIdentityRecord,
    PlatformExternalIdentityStatus,
};
use crate::invitation::{
    validate_organization_invitation, AcceptPlatformOrganizationInvitationRequest,
    PlatformInvitationError, PlatformInvitationStatus, PlatformOrganizationInvitationRecord,
};
use crate::membership::{
    validate_organization_member, validate_project_member, PlatformMembershipError,
    PlatformMembershipStatus, PlatformOrganizationMembershipRecord,
    PlatformOrganizationMembershipUpsert, PlatformProjectMembershipRecord,
    PlatformProjectMembershipUpsert,
};
use crate::resource::{
    ApprovalRecord, ConversationRecord, DeferredToolRecord, EnvironmentAttachmentRecord,
    EvidenceArchiveRecord, PlatformResourceData, PlatformResourceError, PlatformResourceRecord,
    RunRecord,
};
use crate::role::{
    validate_role_binding, PlatformRoleBindingError, PlatformRoleBindingRecord,
    PlatformRoleBindingStatus, PlatformRoleBindingUpsert,
};
use crate::secret::{
    resolve_environment_secret, validate_secret_ref_record, PlatformSecretError,
    PlatformSecretRefRecord, PlatformSecretRefStatus, PlatformSecretValue,
    ENVIRONMENT_SECRET_BACKEND,
};
use crate::storage::{ResourceOwnerRecord, StoreError};
use crate::user::{
    validate_platform_user_record, PlatformUserError, PlatformUserRecord, PlatformUserStatus,
};

/// Result type returned by `PostgreSQL` platform repository adapters.
pub type Result<T> = std::result::Result<T, PlatformRepositoryError>;

const RECORD_AUTH_SESSION_SQL: &str = r"
INSERT INTO platform_auth_sessions (
    auth_session_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    token_hash,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
ON CONFLICT (auth_session_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    principal_id = EXCLUDED.principal_id,
    actor_kind = EXCLUDED.actor_kind,
    token_hash = EXCLUDED.token_hash,
    status = EXCLUDED.status,
    resource_version = platform_auth_sessions.resource_version + 1,
    updated_at = now()
";

const SELECT_AUTH_SESSION_BY_TOKEN_SQL: &str = r"
SELECT
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
FROM platform_auth_sessions
WHERE token_hash = $1
";

const SELECT_AUTH_SESSION_RECORD_BY_TOKEN_SQL: &str = r"
SELECT
    auth_session_id,
    token_hash,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
FROM platform_auth_sessions
WHERE token_hash = $1
";

const REVOKE_AUTH_SESSION_BY_TOKEN_SQL: &str = r"
UPDATE platform_auth_sessions
SET
    status = 'revoked',
    revoked_at = now(),
    resource_version = resource_version + 1,
    updated_at = now()
WHERE token_hash = $1
  AND status = 'active'
RETURNING
    auth_session_id,
    token_hash,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
";

const UPDATE_AUTH_SESSION_CONTEXT_BY_TOKEN_SQL: &str = r"
UPDATE platform_auth_sessions
SET
    organization_id = $2,
    project_id = $3,
    resource_version = resource_version + 1,
    updated_at = now()
WHERE token_hash = $1
  AND status = 'active'
RETURNING
    auth_session_id,
    token_hash,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
";

const LIST_AUTH_SESSIONS_FOR_PRINCIPAL_SQL: &str = r"
SELECT
    auth_session_id,
    token_hash,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
FROM platform_auth_sessions
WHERE tenant_id = $1
  AND principal_id = $2
ORDER BY auth_session_id
";

const SELECT_AUTH_SESSION_BY_ID_SQL: &str = r"
SELECT
    auth_session_id,
    token_hash,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
FROM platform_auth_sessions
WHERE auth_session_id = $1
";

const REVOKE_AUTH_SESSION_BY_ID_SQL: &str = r"
UPDATE platform_auth_sessions
SET
    status = 'revoked',
    revoked_at = now(),
    resource_version = resource_version + 1,
    updated_at = now()
WHERE auth_session_id = $1
  AND tenant_id = $2
  AND principal_id = $3
  AND status = 'active'
RETURNING
    auth_session_id,
    token_hash,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
";

const DISABLE_AUTH_SESSIONS_FOR_PRINCIPAL_SQL: &str = r"
UPDATE platform_auth_sessions
SET
    status = 'principal_disabled',
    resource_version = resource_version + 1,
    updated_at = now()
WHERE tenant_id = $1
  AND principal_id = $2
  AND status = 'active'
";

const LIST_PLATFORM_USERS_SQL: &str = r"
SELECT
    user_id,
    tenant_id,
    default_organization_id,
    default_project_id,
    primary_email,
    display_name,
    status,
    resource_version
FROM platform_users
WHERE tenant_id = $1
  AND status <> 'deleted'
ORDER BY user_id
";

const SELECT_PLATFORM_USER_SQL: &str = r"
SELECT
    user_id,
    tenant_id,
    default_organization_id,
    default_project_id,
    primary_email,
    display_name,
    status,
    resource_version
FROM platform_users
WHERE user_id = $1
  AND status <> 'deleted'
";

const SELECT_PLATFORM_USER_INCLUDING_DELETED_SQL: &str = r"
SELECT
    user_id,
    tenant_id,
    default_organization_id,
    default_project_id,
    primary_email,
    display_name,
    status,
    resource_version
FROM platform_users
WHERE user_id = $1
";

const UPDATE_PLATFORM_USER_STATUS_SQL: &str = r"
UPDATE platform_users
SET
    status = $2,
    resource_version = resource_version + 1,
    updated_at = now()
WHERE user_id = $1
  AND resource_version = $3
  AND status <> 'deleted'
RETURNING
    user_id,
    tenant_id,
    default_organization_id,
    default_project_id,
    primary_email,
    display_name,
    status,
    resource_version
	";

const RECORD_PLATFORM_AUDIT_EVENT_SQL: &str = r"
INSERT INTO platform_audit_events (
    audit_event_id,
    tenant_id,
    organization_id,
    project_id,
    actor_principal_id,
    actor_kind,
    action_id,
    resource_kind,
    resource_id,
    event_type,
    reason,
    redaction,
    created_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULLIF($11, ''), $12, to_timestamp($13))
ON CONFLICT (audit_event_id)
DO NOTHING
	";

const LIST_PLATFORM_AUDIT_EVENTS_FOR_TENANT_SQL: &str = r"
SELECT
    audit_event_id,
    tenant_id,
    organization_id,
    project_id,
    actor_principal_id,
    actor_kind,
    action_id,
    resource_kind,
    resource_id,
    event_type,
    reason,
    redaction,
    extract(epoch from created_at)::bigint AS created_at_unix
FROM platform_audit_events
WHERE tenant_id = $1
ORDER BY created_at DESC, audit_event_id DESC
	";

const RECORD_BEARER_CREDENTIAL_SQL: &str = r"
INSERT INTO platform_bearer_credentials (
    credential_id,
    credential_kind,
    tenant_id,
    organization_id,
    project_id,
    owner_principal_id,
    actor_kind,
    name,
    token_hash,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now())
ON CONFLICT (credential_id)
DO UPDATE SET
    credential_kind = EXCLUDED.credential_kind,
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    owner_principal_id = EXCLUDED.owner_principal_id,
    actor_kind = EXCLUDED.actor_kind,
    name = EXCLUDED.name,
    token_hash = EXCLUDED.token_hash,
    status = EXCLUDED.status,
    resource_version = platform_bearer_credentials.resource_version + 1,
    updated_at = now()
";

const SELECT_BEARER_CREDENTIAL_BY_TOKEN_SQL: &str = r"
SELECT
    tenant_id,
    organization_id,
    project_id,
    owner_principal_id AS principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS token_expired
FROM platform_bearer_credentials
WHERE token_hash = $1
";

const RECORD_MTLS_IDENTITY_SQL: &str = r"
INSERT INTO platform_mtls_identities (
    mtls_identity_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    subject,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), now())
ON CONFLICT (mtls_identity_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    principal_id = EXCLUDED.principal_id,
    actor_kind = EXCLUDED.actor_kind,
    subject = EXCLUDED.subject,
    status = EXCLUDED.status,
    resource_version = platform_mtls_identities.resource_version + 1,
    updated_at = now()
";

const SELECT_MTLS_IDENTITY_BY_SUBJECT_SQL: &str = r"
SELECT
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    status,
    (expires_at IS NOT NULL AND expires_at <= now()) AS identity_expired
FROM platform_mtls_identities
WHERE subject = $1
";

const SELECT_OIDC_LOGIN_PROVIDER_SQL: &str = r"
SELECT
    identity_provider_id,
    tenant_id,
    display_name,
    COALESCE(issuer_url, '') AS issuer_url,
    COALESCE(authorization_endpoint, '') AS authorization_endpoint,
    COALESCE(token_endpoint, '') AS token_endpoint,
    COALESCE(jwks_uri, '') AS jwks_uri,
    COALESCE(client_id, '') AS client_id,
    client_secret_ref,
    COALESCE(token_endpoint_auth_method, 'none') AS token_endpoint_auth_method,
    COALESCE(redirect_uri, '') AS redirect_uri,
    requested_scopes,
    oidc_audiences,
    status
FROM platform_identity_providers
WHERE identity_provider_id = $1
	  AND provider_kind = 'oidc'
	";

const LIST_OIDC_LOGIN_PROVIDERS_SQL: &str = r"
SELECT
    identity_provider_id,
    tenant_id,
    display_name,
    COALESCE(issuer_url, '') AS issuer_url,
    COALESCE(authorization_endpoint, '') AS authorization_endpoint,
    COALESCE(token_endpoint, '') AS token_endpoint,
    COALESCE(jwks_uri, '') AS jwks_uri,
    COALESCE(client_id, '') AS client_id,
    client_secret_ref,
    COALESCE(token_endpoint_auth_method, 'none') AS token_endpoint_auth_method,
    COALESCE(redirect_uri, '') AS redirect_uri,
    requested_scopes,
    oidc_audiences,
    status
FROM platform_identity_providers
WHERE tenant_id = $1
  AND provider_kind = 'oidc'
  AND status <> 'deleted'
ORDER BY identity_provider_id
";

const UPSERT_OIDC_LOGIN_PROVIDER_SQL: &str = r"
INSERT INTO platform_identity_providers (
    identity_provider_id,
    tenant_id,
    provider_kind,
    display_name,
    issuer_url,
    authorization_endpoint,
    token_endpoint,
    jwks_uri,
    client_id,
    client_secret_ref,
    token_endpoint_auth_method,
    redirect_uri,
    requested_scopes,
    oidc_audiences,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    'oidc',
    $3,
    $4,
    NULLIF($5, ''),
    NULLIF($6, ''),
    NULLIF($7, ''),
    $8,
    $9,
    $10,
    $11,
    $12,
    $13,
    $14,
    $15,
    now(),
    now()
)
ON CONFLICT (identity_provider_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    provider_kind = 'oidc',
    display_name = EXCLUDED.display_name,
    issuer_url = EXCLUDED.issuer_url,
    authorization_endpoint = EXCLUDED.authorization_endpoint,
    token_endpoint = EXCLUDED.token_endpoint,
    jwks_uri = EXCLUDED.jwks_uri,
    client_id = EXCLUDED.client_id,
    client_secret_ref = EXCLUDED.client_secret_ref,
    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method,
    redirect_uri = EXCLUDED.redirect_uri,
    requested_scopes = EXCLUDED.requested_scopes,
    oidc_audiences = EXCLUDED.oidc_audiences,
    status = EXCLUDED.status,
    resource_version = platform_identity_providers.resource_version + 1,
    updated_at = now()
";

const UPSERT_SECRET_REF_SQL: &str = r"
INSERT INTO platform_secret_refs (
    secret_ref_id,
    tenant_id,
    organization_id,
    project_id,
    purpose,
    backend_kind,
    backend_locator,
    display_mask,
    fingerprint,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now(), now())
ON CONFLICT (secret_ref_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    purpose = EXCLUDED.purpose,
    backend_kind = EXCLUDED.backend_kind,
    backend_locator = EXCLUDED.backend_locator,
    display_mask = EXCLUDED.display_mask,
    fingerprint = EXCLUDED.fingerprint,
    status = EXCLUDED.status,
    resource_version = platform_secret_refs.resource_version + 1,
    updated_at = now()
";

const SELECT_SECRET_REF_SQL: &str = r"
SELECT
    secret_ref_id,
    tenant_id,
    organization_id,
    project_id,
    purpose,
    backend_kind,
    backend_locator,
    display_mask,
    fingerprint,
    status
FROM platform_secret_refs
WHERE secret_ref_id = $1
";

const LIST_SECRET_REFS_SQL: &str = r"
SELECT
    secret_ref_id,
    tenant_id,
    organization_id,
    project_id,
    purpose,
    backend_kind,
    backend_locator,
    display_mask,
    fingerprint,
    status
FROM platform_secret_refs
WHERE tenant_id = $1
  AND status <> 'deleted'
ORDER BY secret_ref_id
";

const LIST_EXTERNAL_IDENTITIES_FOR_PRINCIPAL_SQL: &str = r"
SELECT
    external_identity_id,
    tenant_id,
    principal_id,
    identity_provider_id,
    provider_kind,
    provider_subject,
    email,
    email_verified,
    status
FROM platform_external_identities
WHERE tenant_id = $1
  AND principal_id = $2
  AND status <> 'deleted'
ORDER BY external_identity_id
";

const SELECT_EXTERNAL_IDENTITY_SQL: &str = r"
SELECT
    external_identity_id,
    tenant_id,
    principal_id,
    identity_provider_id,
    provider_kind,
    provider_subject,
    email,
    email_verified,
    status
FROM platform_external_identities
WHERE external_identity_id = $1
  AND status <> 'deleted'
";

const UNLINK_EXTERNAL_IDENTITY_SQL: &str = r"
UPDATE platform_external_identities
SET
    status = 'deleted',
    updated_at = now()
WHERE external_identity_id = $1
  AND status <> 'deleted'
RETURNING
    external_identity_id,
    tenant_id,
    principal_id,
    identity_provider_id,
    provider_kind,
    provider_subject,
    email,
    email_verified,
    status
";

const LIST_ROLE_BINDINGS_SQL: &str = r"
SELECT
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    resource_version
FROM platform_role_bindings
WHERE tenant_id = $1
  AND status <> 'deleted'
ORDER BY role_binding_id
";

const ACTIVE_ROLE_BINDINGS_FOR_PRINCIPAL_SQL: &str = r"
SELECT
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    resource_version
FROM platform_role_bindings
WHERE tenant_id = $1
  AND principal_id = $2
  AND status = 'active'
ORDER BY role_binding_id
";

const SELECT_ROLE_BINDING_SQL: &str = r"
SELECT
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    resource_version
FROM platform_role_bindings
WHERE role_binding_id = $1
  AND status <> 'deleted'
";

const UPSERT_ROLE_BINDING_SQL: &str = r"
INSERT INTO platform_role_bindings (
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, 'active', $7, now(), now())
ON CONFLICT (role_binding_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    principal_id = EXCLUDED.principal_id,
    role_id = EXCLUDED.role_id,
    status = 'active',
    resource_version = platform_role_bindings.resource_version + 1,
    updated_at = now()
RETURNING
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    resource_version
";

const UPDATE_ROLE_BINDING_STATUS_SQL: &str = r"
UPDATE platform_role_bindings
SET
    status = $2,
    resource_version = resource_version + 1,
    updated_at = now()
WHERE role_binding_id = $1
  AND resource_version = $3
RETURNING
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    resource_version
";

const DELETE_ROLE_BINDINGS_FOR_ORGANIZATION_PRINCIPAL_SQL: &str = r"
UPDATE platform_role_bindings
SET
    status = 'deleted',
    resource_version = resource_version + 1,
    updated_at = now()
WHERE tenant_id = $1
  AND organization_id = $2
  AND principal_id = $3
  AND status <> 'deleted'
RETURNING role_binding_id
";

const DELETE_ROLE_BINDINGS_FOR_PROJECT_PRINCIPAL_SQL: &str = r"
UPDATE platform_role_bindings
SET
    status = 'deleted',
    resource_version = resource_version + 1,
    updated_at = now()
WHERE tenant_id = $1
  AND project_id = $2
  AND principal_id = $3
  AND status <> 'deleted'
RETURNING role_binding_id
";

const LIST_ORGANIZATION_MEMBERS_SQL: &str = r"
SELECT
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    resource_version
FROM platform_organization_memberships
WHERE organization_id = $1
ORDER BY organization_member_id
";

const SELECT_ORGANIZATION_MEMBER_SQL: &str = r"
SELECT
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    resource_version
FROM platform_organization_memberships
WHERE organization_member_id = $1
";

const UPDATE_ORGANIZATION_MEMBER_STATUS_SQL: &str = r"
UPDATE platform_organization_memberships
SET
    status = $2,
    resource_version = resource_version + 1,
    updated_at = now()
WHERE organization_member_id = $1
  AND resource_version = $3
RETURNING
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    resource_version
";

const UPSERT_ORGANIZATION_MEMBER_SQL: &str = r"
INSERT INTO platform_organization_memberships (
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, 'active', $6, now(), now())
ON CONFLICT (organization_id, principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    membership_kind = EXCLUDED.membership_kind,
    status = 'active',
    resource_version = platform_organization_memberships.resource_version + 1,
    updated_at = now()
RETURNING
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    resource_version
";

const LIST_PROJECT_MEMBERS_SQL: &str = r"
SELECT
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    resource_version
FROM platform_project_memberships
WHERE project_id = $1
ORDER BY project_member_id
";

const SELECT_PROJECT_MEMBER_SQL: &str = r"
SELECT
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    resource_version
FROM platform_project_memberships
WHERE project_member_id = $1
";

const UPDATE_PROJECT_MEMBER_STATUS_SQL: &str = r"
UPDATE platform_project_memberships
SET
    status = $2,
    resource_version = resource_version + 1,
    updated_at = now()
WHERE project_member_id = $1
  AND resource_version = $3
RETURNING
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    resource_version
";

const UPSERT_PROJECT_MEMBER_SQL: &str = r"
INSERT INTO platform_project_memberships (
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'active', $8, now(), now())
ON CONFLICT (project_id, principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    organization_member_id = EXCLUDED.organization_member_id,
    membership_kind = EXCLUDED.membership_kind,
    status = 'active',
    resource_version = platform_project_memberships.resource_version + 1,
    updated_at = now()
RETURNING
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    resource_version
";

const CASCADE_PROJECT_MEMBERS_FOR_ORGANIZATION_MEMBER_SQL: &str = r"
UPDATE platform_project_memberships
SET
    status = $4,
    resource_version = resource_version + 1,
    updated_at = now()
WHERE tenant_id = $1
  AND organization_id = $2
  AND principal_id = $3
  AND (
      ($4 = 'suspended' AND status = 'active')
      OR ($4 = 'removed' AND status <> 'removed')
  )
RETURNING project_member_id
";

const INSERT_ORGANIZATION_INVITATION_SQL: &str = r"
INSERT INTO platform_organization_invitations (
    invitation_id,
    tenant_id,
    organization_id,
    project_id,
    invited_email,
    invited_principal_id,
    invitation_token_hash,
    role_id,
    status,
    expires_at,
    accepted_at,
    created_by,
    resource_version,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    $9,
    to_timestamp($10),
    NULL,
    $11,
    $12,
    to_timestamp($13),
    to_timestamp($14)
)
";

const LIST_ORGANIZATION_INVITATIONS_SQL: &str = r"
SELECT
    invitation_id,
    tenant_id,
    organization_id,
    project_id,
    invited_email,
    invited_principal_id,
    invitation_token_hash,
    role_id,
    status,
    extract(epoch from expires_at)::bigint AS expires_at_unix,
    extract(epoch from accepted_at)::bigint AS accepted_at_unix,
    created_by,
    resource_version,
    extract(epoch from created_at)::bigint AS created_at_unix,
    extract(epoch from updated_at)::bigint AS updated_at_unix
FROM platform_organization_invitations
WHERE tenant_id = $1
  AND organization_id = $2
ORDER BY created_at DESC, invitation_id
";

const SELECT_ORGANIZATION_INVITATION_SQL: &str = r"
SELECT
    invitation_id,
    tenant_id,
    organization_id,
    project_id,
    invited_email,
    invited_principal_id,
    invitation_token_hash,
    role_id,
    status,
    extract(epoch from expires_at)::bigint AS expires_at_unix,
    extract(epoch from accepted_at)::bigint AS accepted_at_unix,
    created_by,
    resource_version,
    extract(epoch from created_at)::bigint AS created_at_unix,
    extract(epoch from updated_at)::bigint AS updated_at_unix
FROM platform_organization_invitations
WHERE invitation_id = $1
";

const SELECT_ORGANIZATION_INVITATION_BY_TOKEN_HASH_SQL: &str = r"
SELECT
    invitation_id,
    tenant_id,
    organization_id,
    project_id,
    invited_email,
    invited_principal_id,
    invitation_token_hash,
    role_id,
    status,
    extract(epoch from expires_at)::bigint AS expires_at_unix,
    extract(epoch from accepted_at)::bigint AS accepted_at_unix,
    created_by,
    resource_version,
    extract(epoch from created_at)::bigint AS created_at_unix,
    extract(epoch from updated_at)::bigint AS updated_at_unix
FROM platform_organization_invitations
WHERE invitation_token_hash = $1
";

const REVOKE_ORGANIZATION_INVITATION_SQL: &str = r"
UPDATE platform_organization_invitations
SET
    status = 'revoked',
    resource_version = resource_version + 1,
    updated_at = to_timestamp($3)
WHERE invitation_id = $1
  AND resource_version = $2
  AND status = 'pending'
RETURNING
    invitation_id,
    tenant_id,
    organization_id,
    project_id,
    invited_email,
    invited_principal_id,
    invitation_token_hash,
    role_id,
    status,
    extract(epoch from expires_at)::bigint AS expires_at_unix,
    extract(epoch from accepted_at)::bigint AS accepted_at_unix,
    created_by,
    resource_version,
    extract(epoch from created_at)::bigint AS created_at_unix,
    extract(epoch from updated_at)::bigint AS updated_at_unix
";

const ACCEPT_ORGANIZATION_INVITATION_SQL: &str = r"
UPDATE platform_organization_invitations
SET
    status = 'accepted',
    accepted_at = to_timestamp($2),
    resource_version = resource_version + 1,
    updated_at = to_timestamp($2)
WHERE invitation_id = $1
  AND status = 'pending'
RETURNING
    invitation_id,
    tenant_id,
    organization_id,
    project_id,
    invited_email,
    invited_principal_id,
    invitation_token_hash,
    role_id,
    status,
    extract(epoch from expires_at)::bigint AS expires_at_unix,
    extract(epoch from accepted_at)::bigint AS accepted_at_unix,
    created_by,
    resource_version,
    extract(epoch from created_at)::bigint AS created_at_unix,
    extract(epoch from updated_at)::bigint AS updated_at_unix
";

const UPSERT_INVITED_ORGANIZATION_MEMBER_SQL: &str = r"
INSERT INTO platform_organization_memberships (
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'user', 'active', $4, to_timestamp($5), to_timestamp($5))
ON CONFLICT (organization_id, principal_id)
DO UPDATE SET
    membership_kind = 'user',
    status = 'active',
    resource_version = platform_organization_memberships.resource_version + 1,
    updated_at = to_timestamp($5)
RETURNING
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    resource_version
";

const UPSERT_INVITED_PROJECT_MEMBER_SQL: &str = r"
INSERT INTO platform_project_memberships (
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, 'user', 'active', $5, to_timestamp($7), to_timestamp($7))
ON CONFLICT (project_id, principal_id)
DO UPDATE SET
    organization_member_id = EXCLUDED.organization_member_id,
    membership_kind = 'user',
    status = 'active',
    resource_version = platform_project_memberships.resource_version + 1,
    updated_at = to_timestamp($7)
RETURNING
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    resource_version
";

const RECORD_OIDC_LOGIN_ATTEMPT_SQL: &str = r"
INSERT INTO platform_oidc_login_attempts (
    oidc_login_attempt_id,
    tenant_id,
    identity_provider_id,
    state_hash,
    nonce_hash,
    pkce_verifier_hash,
    redirect_uri,
    status,
    expires_at,
    consumed_at,
    created_at,
    updated_at
)
VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    $8,
    to_timestamp($9),
    CASE WHEN $10::BIGINT IS NULL THEN NULL ELSE to_timestamp($10) END,
    now(),
    now()
)
ON CONFLICT (oidc_login_attempt_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    identity_provider_id = EXCLUDED.identity_provider_id,
    state_hash = EXCLUDED.state_hash,
    nonce_hash = EXCLUDED.nonce_hash,
    pkce_verifier_hash = EXCLUDED.pkce_verifier_hash,
    redirect_uri = EXCLUDED.redirect_uri,
    status = EXCLUDED.status,
    expires_at = EXCLUDED.expires_at,
    consumed_at = EXCLUDED.consumed_at,
    resource_version = platform_oidc_login_attempts.resource_version + 1,
    updated_at = now()
";

const SELECT_OIDC_LOGIN_ATTEMPT_BY_STATE_SQL: &str = r"
SELECT
    oidc_login_attempt_id,
    tenant_id,
    identity_provider_id,
    state_hash,
    nonce_hash,
    pkce_verifier_hash,
    redirect_uri,
    status,
    extract(epoch from expires_at)::bigint AS expires_at_unix,
    CASE
        WHEN consumed_at IS NULL THEN NULL
        ELSE extract(epoch from consumed_at)::bigint
    END AS consumed_at_unix
FROM platform_oidc_login_attempts
WHERE state_hash = $1
";

const CONSUME_OIDC_LOGIN_ATTEMPT_SQL: &str = r"
UPDATE platform_oidc_login_attempts
SET
    status = 'consumed',
    consumed_at = to_timestamp($2),
    resource_version = platform_oidc_login_attempts.resource_version + 1,
    updated_at = now()
WHERE oidc_login_attempt_id = $1
  AND tenant_id = $3
  AND identity_provider_id = $4
  AND status = 'active'
  AND expires_at > now()
";

const UPSERT_OIDC_USER_ORGANIZATION_SQL: &str = r"
INSERT INTO platform_organizations (
    organization_id,
    tenant_id,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, 'active', now(), now())
ON CONFLICT (organization_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_organizations.resource_version + 1,
    updated_at = now()
";

const UPSERT_OIDC_USER_PROJECT_SQL: &str = r"
INSERT INTO platform_projects (
    project_id,
    tenant_id,
    organization_id,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'active', now(), now())
ON CONFLICT (project_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_projects.resource_version + 1,
    updated_at = now()
";

const UPSERT_OIDC_USER_PRINCIPAL_SQL: &str = r"
INSERT INTO platform_principals (
    principal_id,
    tenant_id,
    principal_kind,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, 'user', $3, 'active', now(), now())
ON CONFLICT (principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    principal_kind = 'user',
    display_name = EXCLUDED.display_name,
    status = platform_principals.status,
    resource_version = platform_principals.resource_version + 1,
    updated_at = now()
";

const UPSERT_OIDC_USER_SQL: &str = r"
INSERT INTO platform_users (
    user_id,
    tenant_id,
    default_organization_id,
    default_project_id,
    primary_email,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, 'active', now(), now())
ON CONFLICT (user_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    default_organization_id = EXCLUDED.default_organization_id,
    default_project_id = EXCLUDED.default_project_id,
    primary_email = EXCLUDED.primary_email,
    display_name = EXCLUDED.display_name,
    status = platform_users.status,
    resource_version = platform_users.resource_version + 1,
    updated_at = now()
";

const UPSERT_OIDC_ORGANIZATION_MEMBERSHIP_SQL: &str = r"
INSERT INTO platform_organization_memberships (
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'user', 'active', $4, now(), now())
ON CONFLICT (organization_id, principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    membership_kind = 'user',
    status = 'active',
    resource_version = platform_organization_memberships.resource_version + 1,
    updated_at = now()
";

const UPSERT_OIDC_PROJECT_MEMBERSHIP_SQL: &str = r"
INSERT INTO platform_project_memberships (
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, 'user', 'active', $5, now(), now())
ON CONFLICT (project_id, principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    organization_member_id = EXCLUDED.organization_member_id,
    membership_kind = 'user',
    status = 'active',
    resource_version = platform_project_memberships.resource_version + 1,
    updated_at = now()
";

const UPSERT_OIDC_EXTERNAL_IDENTITY_SQL: &str = r"
INSERT INTO platform_external_identities (
    external_identity_id,
    tenant_id,
    principal_id,
    identity_provider_id,
    provider_kind,
    provider_subject,
    email,
    email_verified,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'oidc', $5, $6, $7, 'active', now(), now())
ON CONFLICT (tenant_id, identity_provider_id, provider_subject)
DO UPDATE SET
    email = EXCLUDED.email,
    email_verified = EXCLUDED.email_verified,
    status = 'active',
    updated_at = now()
WHERE platform_external_identities.principal_id = EXCLUDED.principal_id
";

const UPSERT_OIDC_ORGANIZATION_ADMIN_ROLE_SQL: &str = r"
INSERT INTO platform_role_bindings (
    role_binding_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    role_id,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, NULL, $4, $5, 'active', $4, now(), now())
ON CONFLICT (role_binding_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = NULL,
    principal_id = EXCLUDED.principal_id,
    role_id = EXCLUDED.role_id,
    status = 'active',
    resource_version = platform_role_bindings.resource_version + 1,
    updated_at = now()
";

const RECORD_OIDC_AUTH_SESSION_SQL: &str = r"
INSERT INTO platform_auth_sessions (
    auth_session_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    actor_kind,
    identity_provider_id,
    token_hash,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, 'user', $6, $7, $8, now(), now())
ON CONFLICT (auth_session_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    principal_id = EXCLUDED.principal_id,
    actor_kind = 'user',
    identity_provider_id = EXCLUDED.identity_provider_id,
    token_hash = EXCLUDED.token_hash,
    status = EXCLUDED.status,
    resource_version = platform_auth_sessions.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_TENANT_SQL: &str = r"
INSERT INTO platform_tenants (
    tenant_id,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, 'active', now(), now())
ON CONFLICT (tenant_id)
DO UPDATE SET
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_tenants.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_ORGANIZATION_SQL: &str = r"
INSERT INTO platform_organizations (
    organization_id,
    tenant_id,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, 'active', now(), now())
ON CONFLICT (organization_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_organizations.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_PROJECT_SQL: &str = r"
INSERT INTO platform_projects (
    project_id,
    tenant_id,
    organization_id,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'active', now(), now())
ON CONFLICT (project_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_projects.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_PRINCIPAL_SQL: &str = r"
INSERT INTO platform_principals (
    principal_id,
    tenant_id,
    principal_kind,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, 'user', $3, 'active', now(), now())
ON CONFLICT (principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    principal_kind = 'user',
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_principals.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_USER_SQL: &str = r"
INSERT INTO platform_users (
    user_id,
    tenant_id,
    default_organization_id,
    default_project_id,
    primary_email,
    display_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, 'active', now(), now())
ON CONFLICT (user_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    default_organization_id = EXCLUDED.default_organization_id,
    default_project_id = EXCLUDED.default_project_id,
    primary_email = EXCLUDED.primary_email,
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_users.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_ORGANIZATION_MEMBERSHIP_SQL: &str = r"
INSERT INTO platform_organization_memberships (
    organization_member_id,
    tenant_id,
    organization_id,
    principal_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'user', 'active', $4, now(), now())
ON CONFLICT (organization_id, principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    membership_kind = 'user',
    status = 'active',
    resource_version = platform_organization_memberships.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_PROJECT_MEMBERSHIP_SQL: &str = r"
INSERT INTO platform_project_memberships (
    project_member_id,
    tenant_id,
    organization_id,
    project_id,
    principal_id,
    organization_member_id,
    membership_kind,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, 'user', 'active', $5, now(), now())
ON CONFLICT (project_id, principal_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    organization_member_id = EXCLUDED.organization_member_id,
    membership_kind = 'user',
    status = 'active',
    resource_version = platform_project_memberships.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_IDENTITY_PROVIDER_SQL: &str = r"
INSERT INTO platform_identity_providers (
    identity_provider_id,
    tenant_id,
    provider_kind,
    display_name,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, 'single_user', $3, 'active', $4, now(), now())
ON CONFLICT (identity_provider_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    provider_kind = 'single_user',
    display_name = EXCLUDED.display_name,
    status = 'active',
    resource_version = platform_identity_providers.resource_version + 1,
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_EXTERNAL_IDENTITY_SQL: &str = r"
INSERT INTO platform_external_identities (
    external_identity_id,
    tenant_id,
    principal_id,
    identity_provider_id,
    provider_kind,
    provider_subject,
    email,
    email_verified,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'single_user', $5, $6, false, 'active', now(), now())
ON CONFLICT (tenant_id, identity_provider_id, provider_subject)
DO UPDATE SET
    principal_id = EXCLUDED.principal_id,
    provider_kind = 'single_user',
    email = EXCLUDED.email,
    status = 'active',
    updated_at = now()
";

const BOOTSTRAP_SINGLE_USER_ROLE_BINDING_SQL: &str = r"
INSERT INTO platform_role_bindings (
    role_binding_id,
    tenant_id,
    principal_id,
    role_id,
    status,
    created_by,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, 'active', $3, now(), now())
ON CONFLICT (role_binding_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = NULL,
    project_id = NULL,
    principal_id = EXCLUDED.principal_id,
    role_id = EXCLUDED.role_id,
    status = 'active',
    resource_version = platform_role_bindings.resource_version + 1,
    updated_at = now()
";

const RECORD_RESOURCE_OWNER_SQL: &str = r"
INSERT INTO platform_resource_owners (
    resource_kind,
    resource_id,
    tenant_id,
    organization_id,
    project_id,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, now(), now())
ON CONFLICT (resource_kind, resource_id)
DO UPDATE SET
    tenant_id = EXCLUDED.tenant_id,
    organization_id = EXCLUDED.organization_id,
    project_id = EXCLUDED.project_id,
    resource_version = platform_resource_owners.resource_version + 1,
    updated_at = now()
";

const SELECT_RESOURCE_OWNER_SQL: &str = r"
SELECT
    resource_kind,
    resource_id,
    tenant_id,
    organization_id,
    project_id
FROM platform_resource_owners
WHERE resource_kind = $1 AND resource_id = $2
";

const RECORD_CONVERSATION_SQL: &str = r"
INSERT INTO platform_conversations (
    conversation_id,
    tenant_id,
    organization_id,
    project_id,
    owner_principal_id,
    title,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (conversation_id)
DO UPDATE SET
    title = EXCLUDED.title,
    status = EXCLUDED.status,
    resource_version = platform_conversations.resource_version + 1,
    updated_at = now()
";

const SELECT_CONVERSATION_SQL: &str = r"
SELECT title, status
FROM platform_conversations
WHERE conversation_id = $1
";

const RECORD_RUN_SQL: &str = r"
INSERT INTO platform_runs (
    run_id,
    tenant_id,
    organization_id,
    project_id,
    conversation_id,
    requester_principal_id,
    status,
    model_alias,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())
ON CONFLICT (run_id)
DO UPDATE SET
    conversation_id = EXCLUDED.conversation_id,
    status = EXCLUDED.status,
    model_alias = EXCLUDED.model_alias,
    resource_version = platform_runs.resource_version + 1,
    updated_at = now()
";

const SELECT_RUN_SQL: &str = r"
SELECT conversation_id, status, model_alias
FROM platform_runs
WHERE run_id = $1
";

const RECORD_APPROVAL_SQL: &str = r"
INSERT INTO platform_approvals (
    approval_id,
    tenant_id,
    organization_id,
    project_id,
    run_id,
    requested_action,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (approval_id)
DO UPDATE SET
    run_id = EXCLUDED.run_id,
    requested_action = EXCLUDED.requested_action,
    status = EXCLUDED.status,
    resource_version = platform_approvals.resource_version + 1,
    updated_at = now()
";

const SELECT_APPROVAL_SQL: &str = r"
SELECT run_id, requested_action, status
FROM platform_approvals
WHERE approval_id = $1
";

const RECORD_DEFERRED_TOOL_SQL: &str = r"
INSERT INTO platform_deferred_tools (
    deferred_tool_id,
    tenant_id,
    organization_id,
    project_id,
    run_id,
    tool_name,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (deferred_tool_id)
DO UPDATE SET
    run_id = EXCLUDED.run_id,
    tool_name = EXCLUDED.tool_name,
    status = EXCLUDED.status,
    resource_version = platform_deferred_tools.resource_version + 1,
    updated_at = now()
";

const SELECT_DEFERRED_TOOL_SQL: &str = r"
SELECT run_id, tool_name, status
FROM platform_deferred_tools
WHERE deferred_tool_id = $1
";

const RECORD_ENVIRONMENT_ATTACHMENT_SQL: &str = r"
INSERT INTO platform_environment_attachments (
    attachment_lease_id,
    tenant_id,
    organization_id,
    project_id,
    provider_ref,
    readiness,
    status,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (attachment_lease_id)
DO UPDATE SET
    provider_ref = EXCLUDED.provider_ref,
    readiness = EXCLUDED.readiness,
    status = EXCLUDED.status,
    resource_version = platform_environment_attachments.resource_version + 1,
    updated_at = now()
";

const SELECT_ENVIRONMENT_ATTACHMENT_SQL: &str = r"
SELECT attachment_lease_id, readiness, status
FROM platform_environment_attachments
WHERE attachment_lease_id = $1
";

const RECORD_EVIDENCE_ARCHIVE_SQL: &str = r"
INSERT INTO platform_evidence_archives (
    evidence_archive_id,
    tenant_id,
    organization_id,
    project_id,
    run_id,
    manifest_uri,
    retention_class,
    debug_available,
    redaction_profile,
    created_at,
    updated_at
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'standard', now(), now())
ON CONFLICT (evidence_archive_id)
DO UPDATE SET
    run_id = EXCLUDED.run_id,
    manifest_uri = EXCLUDED.manifest_uri,
    retention_class = EXCLUDED.retention_class,
    debug_available = EXCLUDED.debug_available,
    resource_version = platform_evidence_archives.resource_version + 1,
    updated_at = now()
";

const SELECT_EVIDENCE_ARCHIVE_SQL: &str = r"
SELECT manifest_uri, retention_class, debug_available
FROM platform_evidence_archives
WHERE evidence_archive_id = $1
";

/// `PostgreSQL` platform repository error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformRepositoryError {
    /// Authentication record validation or status resolution failed.
    Auth(AuthError),
    /// Identity-provider validation failed.
    Identity(OidcValidationError),
    /// Resource ownership validation failed.
    Store(StoreError),
    /// Business resource validation failed.
    Resource(PlatformResourceError),
    /// Membership validation failed.
    Membership(PlatformMembershipError),
    /// Invitation validation failed.
    Invitation(PlatformInvitationError),
    /// Secret-reference validation or resolution failed.
    Secret(PlatformSecretError),
    /// External identity validation failed.
    ExternalIdentity(PlatformExternalIdentityError),
    /// Role-binding validation failed.
    RoleBinding(PlatformRoleBindingError),
    /// User validation failed.
    User(PlatformUserError),
    /// Audit-event validation failed.
    Audit(PlatformAuditError),
    /// Database operation failed.
    Database(String),
    /// Actor kind stored in `PostgreSQL` is not recognized.
    UnknownActorKind(String),
    /// Auth session status stored in `PostgreSQL` is not recognized.
    UnknownSessionStatus(String),
    /// Bearer credential status stored in `PostgreSQL` is not recognized.
    UnknownCredentialStatus(String),
    /// mTLS identity status stored in `PostgreSQL` is not recognized.
    UnknownMtlsIdentityStatus(String),
    /// `OIDC` login-provider status stored in `PostgreSQL` is not recognized.
    UnknownOidcLoginProviderStatus(String),
    /// `OIDC` login-attempt status stored in `PostgreSQL` is not recognized.
    UnknownOidcLoginAttemptStatus(String),
    /// Secret-reference status stored in `PostgreSQL` is not recognized.
    UnknownSecretRefStatus(String),
    /// Membership status stored in `PostgreSQL` is not recognized.
    UnknownMembershipStatus(String),
    /// Invitation status stored in `PostgreSQL` is not recognized.
    UnknownInvitationStatus(String),
    /// External identity status stored in `PostgreSQL` is not recognized.
    UnknownExternalIdentityStatus(String),
    /// Role-binding status stored in `PostgreSQL` is not recognized.
    UnknownRoleBindingStatus(String),
    /// User status stored in `PostgreSQL` is not recognized.
    UnknownUserStatus(String),
    /// `OIDC` login attempt cannot be consumed.
    OidcLoginAttemptUnavailable(String),
    /// `OIDC` external identity already points at a different principal.
    OidcExternalIdentityPrincipalMismatch(String),
    /// `OIDC` issued session actor does not match the linked local user.
    OidcSessionActorMismatch(String),
    /// Business resource requires project scope but owner metadata is not project-scoped.
    ProjectScopeRequired(String),
}

impl PlatformRepositoryError {
    /// Returns a stable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auth(error) => error.as_str(),
            Self::Identity(error) => error.as_str(),
            Self::Store(error) => error.as_str(),
            Self::Resource(error) => error.as_str(),
            Self::Membership(error) => error.as_str(),
            Self::Invitation(error) => error.as_str(),
            Self::Secret(error) => error.as_str(),
            Self::ExternalIdentity(error) => error.as_str(),
            Self::RoleBinding(error) => error.as_str(),
            Self::User(error) => error.as_str(),
            Self::Audit(error) => error.as_str(),
            Self::Database(_) => "database_error",
            Self::UnknownActorKind(_) => "unknown_actor_kind",
            Self::UnknownSessionStatus(_) => "unknown_session_status",
            Self::UnknownCredentialStatus(_) => "unknown_credential_status",
            Self::UnknownMtlsIdentityStatus(_) => "unknown_mtls_identity_status",
            Self::UnknownOidcLoginProviderStatus(_) => "unknown_oidc_login_provider_status",
            Self::UnknownOidcLoginAttemptStatus(_) => "unknown_oidc_login_attempt_status",
            Self::UnknownSecretRefStatus(_) => "unknown_secret_ref_status",
            Self::UnknownMembershipStatus(_) => "unknown_membership_status",
            Self::UnknownInvitationStatus(_) => "unknown_invitation_status",
            Self::UnknownExternalIdentityStatus(_) => "unknown_external_identity_status",
            Self::UnknownRoleBindingStatus(_) => "unknown_role_binding_status",
            Self::UnknownUserStatus(_) => "unknown_user_status",
            Self::OidcLoginAttemptUnavailable(_) => "oidc_login_attempt_unavailable",
            Self::OidcExternalIdentityPrincipalMismatch(_) => {
                "oidc_external_identity_principal_mismatch"
            }
            Self::OidcSessionActorMismatch(_) => "oidc_session_actor_mismatch",
            Self::ProjectScopeRequired(_) => "project_scope_required",
        }
    }
}

impl Display for PlatformRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(error) => write!(formatter, "authentication repository error: {error:?}"),
            Self::Identity(error) => write!(formatter, "identity repository error: {error:?}"),
            Self::Store(error) => write!(formatter, "resource owner repository error: {error:?}"),
            Self::Resource(error) => {
                write!(formatter, "business resource repository error: {error:?}")
            }
            Self::Membership(error) => write!(formatter, "membership repository error: {error:?}"),
            Self::Invitation(error) => {
                write!(formatter, "invitation repository error: {error:?}")
            }
            Self::Secret(error) => write!(formatter, "secret repository error: {error:?}"),
            Self::ExternalIdentity(error) => {
                write!(formatter, "external identity repository error: {error:?}")
            }
            Self::RoleBinding(error) => {
                write!(formatter, "role binding repository error: {error:?}")
            }
            Self::User(error) => write!(formatter, "user repository error: {error:?}"),
            Self::Audit(error) => write!(formatter, "audit repository error: {error:?}"),
            Self::Database(message) => write!(formatter, "database repository error: {message}"),
            Self::UnknownActorKind(value) => write!(formatter, "unknown actor kind: {value}"),
            Self::UnknownSessionStatus(value) => {
                write!(formatter, "unknown auth session status: {value}")
            }
            Self::UnknownCredentialStatus(value) => {
                write!(formatter, "unknown bearer credential status: {value}")
            }
            Self::UnknownMtlsIdentityStatus(value) => {
                write!(formatter, "unknown mTLS identity status: {value}")
            }
            Self::UnknownOidcLoginProviderStatus(value) => {
                write!(formatter, "unknown OIDC login-provider status: {value}")
            }
            Self::UnknownOidcLoginAttemptStatus(value) => {
                write!(formatter, "unknown OIDC login-attempt status: {value}")
            }
            Self::UnknownSecretRefStatus(value) => {
                write!(formatter, "unknown secret-ref status: {value}")
            }
            Self::UnknownMembershipStatus(value) => {
                write!(formatter, "unknown membership status: {value}")
            }
            Self::UnknownInvitationStatus(value) => {
                write!(formatter, "unknown invitation status: {value}")
            }
            Self::UnknownExternalIdentityStatus(value) => {
                write!(formatter, "unknown external identity status: {value}")
            }
            Self::UnknownRoleBindingStatus(value) => {
                write!(formatter, "unknown role binding status: {value}")
            }
            Self::UnknownUserStatus(value) => write!(formatter, "unknown user status: {value}"),
            Self::OidcLoginAttemptUnavailable(value) => {
                write!(formatter, "OIDC login attempt unavailable: {value}")
            }
            Self::OidcExternalIdentityPrincipalMismatch(value) => {
                write!(
                    formatter,
                    "OIDC external identity principal mismatch: {value}"
                )
            }
            Self::OidcSessionActorMismatch(value) => {
                write!(formatter, "OIDC session actor mismatch: {value}")
            }
            Self::ProjectScopeRequired(kind) => {
                write!(formatter, "resource kind requires project scope: {kind}")
            }
        }
    }
}

impl std::error::Error for PlatformRepositoryError {}

impl From<sqlx::Error> for PlatformRepositoryError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

impl From<AuthError> for PlatformRepositoryError {
    fn from(error: AuthError) -> Self {
        Self::Auth(error)
    }
}

impl From<OidcValidationError> for PlatformRepositoryError {
    fn from(error: OidcValidationError) -> Self {
        Self::Identity(error)
    }
}

impl From<StoreError> for PlatformRepositoryError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<PlatformResourceError> for PlatformRepositoryError {
    fn from(error: PlatformResourceError) -> Self {
        Self::Resource(error)
    }
}

impl From<PlatformMembershipError> for PlatformRepositoryError {
    fn from(error: PlatformMembershipError) -> Self {
        Self::Membership(error)
    }
}

impl From<PlatformInvitationError> for PlatformRepositoryError {
    fn from(error: PlatformInvitationError) -> Self {
        Self::Invitation(error)
    }
}

impl From<PlatformSecretError> for PlatformRepositoryError {
    fn from(error: PlatformSecretError) -> Self {
        Self::Secret(error)
    }
}

impl From<PlatformExternalIdentityError> for PlatformRepositoryError {
    fn from(error: PlatformExternalIdentityError) -> Self {
        Self::ExternalIdentity(error)
    }
}

impl From<PlatformRoleBindingError> for PlatformRepositoryError {
    fn from(error: PlatformRoleBindingError) -> Self {
        Self::RoleBinding(error)
    }
}

impl From<PlatformUserError> for PlatformRepositoryError {
    fn from(error: PlatformUserError) -> Self {
        Self::User(error)
    }
}

impl From<PlatformAuditError> for PlatformRepositoryError {
    fn from(error: PlatformAuditError) -> Self {
        Self::Audit(error)
    }
}

/// PostgreSQL-backed repository adapter for platform durable state.
#[derive(Clone, Debug)]
pub struct PostgresPlatformRepository {
    pool: PgPool,
}

/// Durable default resources for local single-user bootstrap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SingleUserBootstrapRecord {
    /// Default tenant id.
    pub tenant_id: String,
    /// Default organization id.
    pub organization_id: String,
    /// Default project id.
    pub project_id: String,
    /// Default user principal id.
    pub user_id: String,
    /// Local single-user identity provider id.
    pub identity_provider_id: String,
    /// External identity row id.
    pub external_identity_id: String,
    /// Organization membership id.
    pub organization_member_id: String,
    /// Project membership id.
    pub project_member_id: String,
    /// Tenant-owner role binding id.
    pub role_binding_id: String,
    /// Login username used as the local provider subject.
    pub username: String,
    /// User display name.
    pub user_display_name: String,
    /// Optional primary email.
    pub user_primary_email: Option<String>,
    /// Tenant display name.
    pub tenant_display_name: String,
    /// Organization display name.
    pub organization_display_name: String,
    /// Project display name.
    pub project_display_name: String,
}

/// Durable local user/session mutation produced by a verified `OIDC` callback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLoginCompletionRecord {
    /// Consumed login attempt id.
    pub login_attempt_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Default organization id repaired for the local user.
    pub organization_id: String,
    /// Default project id repaired for the local user.
    pub project_id: String,
    /// Local user principal id.
    pub user_id: String,
    /// `OIDC` identity provider id.
    pub identity_provider_id: String,
    /// External identity row id.
    pub external_identity_id: String,
    /// Organization membership id.
    pub organization_member_id: String,
    /// Project membership id.
    pub project_member_id: String,
    /// Organization-admin role binding id for the user's default organization.
    pub organization_role_binding_id: String,
    /// Provider subject from verified `OIDC` claims.
    pub provider_subject: String,
    /// Optional verified email metadata.
    pub email: Option<String>,
    /// Whether the email was provider-verified.
    pub email_verified: bool,
    /// User display name repaired from verified claims or operator policy.
    pub user_display_name: String,
    /// Default organization display name.
    pub organization_display_name: String,
    /// Default project display name.
    pub project_display_name: String,
    /// Auth session issued for the completed login.
    pub session: PlatformAuthSessionRecord,
    /// Completion time as a Unix timestamp in seconds.
    pub consumed_at_unix: i64,
}

impl PostgresPlatformRepository {
    /// Creates a repository adapter backed by a `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the underlying `PostgreSQL` pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Idempotently seeds or repairs durable local single-user resources.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` rejects one of the
    /// bootstrap writes.
    pub async fn bootstrap_single_user(&self, record: &SingleUserBootstrapRecord) -> Result<()> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_TENANT_SQL)
            .bind(&record.tenant_id)
            .bind(&record.tenant_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_ORGANIZATION_SQL)
            .bind(&record.organization_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_PROJECT_SQL)
            .bind(&record.project_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_PRINCIPAL_SQL)
            .bind(&record.user_id)
            .bind(&record.tenant_id)
            .bind(&record.user_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_USER_SQL)
            .bind(&record.user_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_id)
            .bind(record.user_primary_email.as_deref())
            .bind(&record.user_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_ORGANIZATION_MEMBERSHIP_SQL)
            .bind(&record.organization_member_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_PROJECT_MEMBERSHIP_SQL)
            .bind(&record.project_member_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_id)
            .bind(&record.user_id)
            .bind(&record.organization_member_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_IDENTITY_PROVIDER_SQL)
            .bind(&record.identity_provider_id)
            .bind(&record.tenant_id)
            .bind("Local single-user password")
            .bind(&record.user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_EXTERNAL_IDENTITY_SQL)
            .bind(&record.external_identity_id)
            .bind(&record.tenant_id)
            .bind(&record.user_id)
            .bind(&record.identity_provider_id)
            .bind(&record.username)
            .bind(record.user_primary_email.as_deref())
            .execute(&mut *transaction)
            .await?;
        sqlx::query(BOOTSTRAP_SINGLE_USER_ROLE_BINDING_SQL)
            .bind(&record.role_binding_id)
            .bind(&record.tenant_id)
            .bind(&record.user_id)
            .bind(BuiltInRole::TenantOwner.as_str())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Records or replaces an auth session.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn record_auth_session(&self, record: &PlatformAuthSessionRecord) -> Result<()> {
        validate_auth_session_record(record)?;
        sqlx::query(RECORD_AUTH_SESSION_SQL)
            .bind(&record.session_id)
            .bind(&record.actor.tenant_id)
            .bind(record.actor.organization_id.as_deref())
            .bind(record.actor.project_id.as_deref())
            .bind(&record.actor.principal_id)
            .bind(actor_kind_as_str(record.actor.actor_kind))
            .bind(&record.token_hash)
            .bind(record.status.as_str())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Resolves a raw bearer token through durable auth sessions.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the bearer token is empty,
    /// unknown, revoked, expired, tied to a disabled principal, or when
    /// `PostgreSQL` cannot be queried.
    pub async fn authenticated_actor_for_session_bearer(
        &self,
        raw_bearer: &str,
    ) -> Result<AuthenticatedActor> {
        let token_hash = session_token_hash_for_lookup(raw_bearer)?;
        let Some(row) = sqlx::query(SELECT_AUTH_SESSION_BY_TOKEN_SQL)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::SessionNotFound.into());
        };

        let status = row.try_get::<String, _>("status")?;
        let token_expired = row.try_get::<bool, _>("token_expired")?;
        match status.as_str() {
            "active" if token_expired => Err(AuthError::SessionExpired.into()),
            "active" => actor_from_row(&row),
            "revoked" => Err(AuthError::SessionRevoked.into()),
            "expired" => Err(AuthError::SessionExpired.into()),
            "principal_disabled" => Err(AuthError::PrincipalDisabled.into()),
            _ => Err(PlatformRepositoryError::UnknownSessionStatus(status)),
        }
    }

    /// Resolves a raw bearer token to an active durable auth session record.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the bearer token is empty,
    /// unknown, revoked, expired, tied to a disabled principal, or when
    /// `PostgreSQL` cannot be queried.
    pub async fn auth_session_for_bearer(
        &self,
        raw_bearer: &str,
    ) -> Result<PlatformAuthSessionRecord> {
        let token_hash = session_token_hash_for_lookup(raw_bearer)?;
        let Some(row) = sqlx::query(SELECT_AUTH_SESSION_RECORD_BY_TOKEN_SQL)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::SessionNotFound.into());
        };
        active_auth_session_from_row(&row)
    }

    /// Revokes an active durable auth session by raw bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the bearer token does not
    /// resolve to an active session or when `PostgreSQL` cannot be queried.
    pub async fn revoke_auth_session_by_bearer(
        &self,
        raw_bearer: &str,
    ) -> Result<PlatformAuthSessionRecord> {
        let token_hash = session_token_hash_for_lookup(raw_bearer)?;
        let Some(row) = sqlx::query(REVOKE_AUTH_SESSION_BY_TOKEN_SQL)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::SessionRevoked.into());
        };
        auth_session_from_row(&row)
    }

    /// Updates active organization and project context for a durable auth session.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the bearer token does not
    /// resolve to an active session or when `PostgreSQL` cannot be queried.
    pub async fn update_auth_session_context_by_bearer(
        &self,
        raw_bearer: &str,
        organization_id: Option<&str>,
        project_id: Option<&str>,
    ) -> Result<PlatformAuthSessionRecord> {
        let token_hash = session_token_hash_for_lookup(raw_bearer)?;
        let Some(row) = sqlx::query(UPDATE_AUTH_SESSION_CONTEXT_BY_TOKEN_SQL)
            .bind(token_hash)
            .bind(organization_id)
            .bind(project_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::SessionRevoked.into());
        };
        active_auth_session_from_row(&row)
    }

    /// Lists durable auth sessions for one tenant principal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored session shape is invalid.
    pub async fn auth_sessions_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<Vec<PlatformAuthSessionRecord>> {
        let rows = sqlx::query(LIST_AUTH_SESSIONS_FOR_PRINCIPAL_SQL)
            .bind(tenant_id)
            .bind(principal_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(auth_session_from_row).collect()
    }

    /// Loads a durable auth session by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored session shape is invalid.
    pub async fn auth_session(
        &self,
        session_id: &str,
    ) -> Result<Option<PlatformAuthSessionRecord>> {
        let row = sqlx::query(SELECT_AUTH_SESSION_BY_ID_SQL)
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| auth_session_from_row(&row)).transpose()
    }

    /// Revokes an active durable auth session by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the session is not active, does
    /// not belong to the requested tenant principal, or `PostgreSQL` cannot be
    /// queried.
    pub async fn revoke_auth_session_by_id(
        &self,
        session_id: &str,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<PlatformAuthSessionRecord> {
        let Some(row) = sqlx::query(REVOKE_AUTH_SESSION_BY_ID_SQL)
            .bind(session_id)
            .bind(tenant_id)
            .bind(principal_id)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::SessionNotFound.into());
        };
        auth_session_from_row(&row)
    }

    /// Marks active sessions for one tenant principal as principal-disabled.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be updated.
    pub async fn disable_auth_sessions_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<u64> {
        let result = sqlx::query(DISABLE_AUTH_SESSIONS_FOR_PRINCIPAL_SQL)
            .bind(tenant_id)
            .bind(principal_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Lists non-deleted platform users for one tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored user shape is invalid.
    pub async fn users_for_tenant(&self, tenant_id: &str) -> Result<Vec<PlatformUserRecord>> {
        let rows = sqlx::query(LIST_PLATFORM_USERS_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(platform_user_from_row).collect()
    }

    /// Loads a non-deleted platform user by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored user shape is invalid.
    pub async fn user(&self, user_id: &str) -> Result<Option<PlatformUserRecord>> {
        let row = sqlx::query(SELECT_PLATFORM_USER_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| platform_user_from_row(&row)).transpose()
    }

    /// Loads a platform user by id, including deleted users.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored user shape is invalid.
    pub async fn user_including_deleted(
        &self,
        user_id: &str,
    ) -> Result<Option<PlatformUserRecord>> {
        let row = sqlx::query(SELECT_PLATFORM_USER_INCLUDING_DELETED_SQL)
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| platform_user_from_row(&row)).transpose()
    }

    /// Updates a platform user's status using optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the user is unknown, the expected
    /// version is stale, validation fails, or `PostgreSQL` rejects the update.
    pub async fn update_user_status(
        &self,
        user_id: &str,
        expected_version: i64,
        status: PlatformUserStatus,
    ) -> Result<PlatformUserRecord> {
        if expected_version < 1 {
            return Err(PlatformUserError::InvalidResourceVersion.into());
        }
        let Some(row) = sqlx::query(UPDATE_PLATFORM_USER_STATUS_SQL)
            .bind(user_id)
            .bind(status.as_str())
            .bind(expected_version)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(PlatformUserError::StaleResourceVersion.into());
        };
        platform_user_from_row(&row)
    }

    /// Records a redacted platform audit event.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn record_audit_event(&self, record: &PlatformAuditEventRecord) -> Result<()> {
        validate_platform_audit_event_record(record)?;
        sqlx::query(RECORD_PLATFORM_AUDIT_EVENT_SQL)
            .bind(&record.audit_event_id)
            .bind(&record.tenant_id)
            .bind(record.organization_id.as_deref())
            .bind(record.project_id.as_deref())
            .bind(&record.actor_principal_id)
            .bind(actor_kind_as_str(record.actor_kind))
            .bind(&record.action_id)
            .bind(&record.resource_kind)
            .bind(&record.resource_id)
            .bind(&record.event_type)
            .bind(record.reason.as_deref().unwrap_or(""))
            .bind(&record.redaction)
            .bind(record.created_at_unix)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Lists redacted platform audit events for one tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored event shape is invalid.
    pub async fn audit_events_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<PlatformAuditEventRecord>> {
        let rows = sqlx::query(LIST_PLATFORM_AUDIT_EVENTS_FOR_TENANT_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(platform_audit_event_from_row).collect()
    }

    /// Records or replaces an API key or service-token bearer credential.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn record_bearer_credential(
        &self,
        record: &PlatformBearerCredentialRecord,
    ) -> Result<()> {
        validate_bearer_credential_record(record)?;
        sqlx::query(RECORD_BEARER_CREDENTIAL_SQL)
            .bind(&record.credential_id)
            .bind(record.credential_kind.as_str())
            .bind(&record.actor.tenant_id)
            .bind(record.actor.organization_id.as_deref())
            .bind(record.actor.project_id.as_deref())
            .bind(&record.actor.principal_id)
            .bind(actor_kind_as_str(record.actor.actor_kind))
            .bind(&record.credential_id)
            .bind(&record.token_hash)
            .bind(record.status.as_str())
            .bind(&record.actor.principal_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Resolves a raw bearer token through durable API key or service-token credentials.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the bearer token is empty,
    /// unknown, revoked, disabled, expired, tied to a disabled principal, or
    /// when `PostgreSQL` cannot be queried.
    pub async fn authenticated_actor_for_bearer_credential(
        &self,
        raw_bearer: &str,
    ) -> Result<AuthenticatedActor> {
        let token_hash = bearer_credential_hash_for_lookup(raw_bearer)?;
        let Some(row) = sqlx::query(SELECT_BEARER_CREDENTIAL_BY_TOKEN_SQL)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::CredentialNotFound.into());
        };

        let status = row.try_get::<String, _>("status")?;
        let token_expired = row.try_get::<bool, _>("token_expired")?;
        match status.as_str() {
            "active" if token_expired => Err(AuthError::CredentialExpired.into()),
            "active" => actor_from_row(&row),
            "disabled" => Err(AuthError::CredentialDisabled.into()),
            "revoked" => Err(AuthError::CredentialRevoked.into()),
            "expired" => Err(AuthError::CredentialExpired.into()),
            "principal_disabled" => Err(AuthError::PrincipalDisabled.into()),
            _ => Err(PlatformRepositoryError::UnknownCredentialStatus(status)),
        }
    }

    /// Records or replaces an mTLS identity.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn record_mtls_identity(&self, record: &PlatformMtlsIdentityRecord) -> Result<()> {
        validate_mtls_identity_record(record)?;
        sqlx::query(RECORD_MTLS_IDENTITY_SQL)
            .bind(&record.identity_id)
            .bind(&record.actor.tenant_id)
            .bind(record.actor.organization_id.as_deref())
            .bind(record.actor.project_id.as_deref())
            .bind(&record.actor.principal_id)
            .bind(actor_kind_as_str(record.actor.actor_kind))
            .bind(&record.subject)
            .bind(record.status.as_str())
            .bind(&record.actor.principal_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Resolves a verified mTLS subject through durable identity bindings.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the subject is empty, unknown,
    /// revoked, disabled, expired, tied to a disabled principal, or when
    /// `PostgreSQL` cannot be queried.
    pub async fn authenticated_actor_for_mtls_subject(
        &self,
        subject: &str,
    ) -> Result<AuthenticatedActor> {
        let subject = mtls_subject_for_lookup(subject)?;
        let Some(row) = sqlx::query(SELECT_MTLS_IDENTITY_BY_SUBJECT_SQL)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await?
        else {
            return Err(AuthError::MtlsIdentityNotFound.into());
        };

        let status = row.try_get::<String, _>("status")?;
        let identity_expired = row.try_get::<bool, _>("identity_expired")?;
        match status.as_str() {
            "active" if identity_expired => Err(AuthError::MtlsIdentityExpired.into()),
            "active" => actor_from_row(&row),
            "disabled" => Err(AuthError::MtlsIdentityDisabled.into()),
            "revoked" => Err(AuthError::MtlsIdentityRevoked.into()),
            "expired" => Err(AuthError::MtlsIdentityExpired.into()),
            "principal_disabled" => Err(AuthError::PrincipalDisabled.into()),
            _ => Err(PlatformRepositoryError::UnknownMtlsIdentityStatus(status)),
        }
    }

    /// Loads an active or inactive `OIDC` login provider by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried,
    /// the provider status is not recognized, or the stored provider shape is
    /// invalid.
    pub async fn oidc_login_provider(
        &self,
        identity_provider_id: &str,
    ) -> Result<Option<OidcLoginProviderRecord>> {
        let row = sqlx::query(SELECT_OIDC_LOGIN_PROVIDER_SQL)
            .bind(identity_provider_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| oidc_login_provider_from_row(&row))
            .transpose()
    }

    /// Lists non-deleted `OIDC` login providers for one tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored provider shape is invalid.
    pub async fn oidc_login_providers_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<OidcLoginProviderRecord>> {
        let rows = sqlx::query(LIST_OIDC_LOGIN_PROVIDERS_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(oidc_login_provider_from_row).collect()
    }

    /// Creates or replaces an `OIDC` login provider and its authorization owner.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn upsert_oidc_login_provider(
        &self,
        record: &OidcLoginProviderRecord,
        created_by: &str,
    ) -> Result<()> {
        validate_oidc_login_provider_base(record)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(UPSERT_OIDC_LOGIN_PROVIDER_SQL)
            .bind(&record.identity_provider_id)
            .bind(&record.tenant_id)
            .bind(&record.display_name)
            .bind(&record.issuer_url)
            .bind(&record.authorization_endpoint)
            .bind(&record.token_endpoint)
            .bind(&record.jwks_uri)
            .bind(&record.client_id)
            .bind(record.client_secret_ref.as_deref())
            .bind(record.token_endpoint_auth_method.as_str())
            .bind(&record.redirect_uri)
            .bind(serde_json::json!(&record.requested_scopes))
            .bind(serde_json::json!(&record.accepted_audiences))
            .bind(record.status.as_str())
            .bind(created_by)
            .execute(&mut *transaction)
            .await?;
        record_resource_owner_in_transaction(
            &mut transaction,
            &ResourceOwnerRecord::tenant(
                "IdentityProvider",
                &record.identity_provider_id,
                &record.tenant_id,
            ),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Creates or replaces safe secret-reference metadata and its authorization owner.
    ///
    /// Raw secret values are never stored by this repository. Only
    /// environment-backed refs are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn upsert_secret_ref(
        &self,
        record: &PlatformSecretRefRecord,
        created_by: &str,
    ) -> Result<()> {
        validate_secret_ref_record(record)?;
        if record.backend_kind != ENVIRONMENT_SECRET_BACKEND {
            return Err(PlatformSecretError::UnsupportedBackendKind.into());
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query(UPSERT_SECRET_REF_SQL)
            .bind(&record.secret_ref_id)
            .bind(&record.tenant_id)
            .bind(record.organization_id.as_deref())
            .bind(record.project_id.as_deref())
            .bind(&record.purpose)
            .bind(&record.backend_kind)
            .bind(&record.backend_locator)
            .bind(&record.display_mask)
            .bind(&record.fingerprint)
            .bind(record.status.as_str())
            .bind(created_by)
            .execute(&mut *transaction)
            .await?;
        record_resource_owner_in_transaction(
            &mut transaction,
            &ResourceOwnerRecord::tenant("SecretRef", &record.secret_ref_id, &record.tenant_id),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Loads safe secret-reference metadata by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn secret_ref(&self, secret_ref_id: &str) -> Result<Option<PlatformSecretRefRecord>> {
        let row = sqlx::query(SELECT_SECRET_REF_SQL)
            .bind(secret_ref_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| secret_ref_from_row(&row)).transpose()
    }

    /// Lists non-deleted secret-reference metadata for one tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn secret_refs_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<PlatformSecretRefRecord>> {
        let rows = sqlx::query(LIST_SECRET_REFS_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(secret_ref_from_row).collect()
    }

    /// Lists non-deleted external identities for one principal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn external_identities_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<Vec<PlatformExternalIdentityRecord>> {
        let rows = sqlx::query(LIST_EXTERNAL_IDENTITIES_FOR_PRINCIPAL_SQL)
            .bind(tenant_id)
            .bind(principal_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(external_identity_from_row).collect()
    }

    /// Loads a non-deleted external identity by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn external_identity(
        &self,
        external_identity_id: &str,
    ) -> Result<Option<PlatformExternalIdentityRecord>> {
        let row = sqlx::query(SELECT_EXTERNAL_IDENTITY_SQL)
            .bind(external_identity_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| external_identity_from_row(&row)).transpose()
    }

    /// Marks an external identity deleted.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the identity is already absent or
    /// deleted, `PostgreSQL` cannot be queried, or the returned record is invalid.
    pub async fn unlink_external_identity(
        &self,
        external_identity_id: &str,
    ) -> Result<PlatformExternalIdentityRecord> {
        let row = sqlx::query(UNLINK_EXTERNAL_IDENTITY_SQL)
            .bind(external_identity_id)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(PlatformExternalIdentityError::InvalidExternalIdentityId.into());
        };
        external_identity_from_row(&row)
    }

    /// Lists non-deleted role bindings for one tenant.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn role_bindings_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<PlatformRoleBindingRecord>> {
        let rows = sqlx::query(LIST_ROLE_BINDINGS_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(role_binding_from_row).collect()
    }

    /// Lists active role bindings for one principal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn active_role_bindings_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Result<Vec<PlatformRoleBindingRecord>> {
        let rows = sqlx::query(ACTIVE_ROLE_BINDINGS_FOR_PRINCIPAL_SQL)
            .bind(tenant_id)
            .bind(principal_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(role_binding_from_row).collect()
    }

    /// Loads a non-deleted role binding by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn role_binding(
        &self,
        role_binding_id: &str,
    ) -> Result<Option<PlatformRoleBindingRecord>> {
        let row = sqlx::query(SELECT_ROLE_BINDING_SQL)
            .bind(role_binding_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| role_binding_from_row(&row)).transpose()
    }

    /// Creates or reactivates a role binding.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn upsert_role_binding(
        &self,
        request: PlatformRoleBindingUpsert<'_>,
        created_by: &str,
    ) -> Result<PlatformRoleBindingRecord> {
        let candidate = PlatformRoleBindingRecord {
            role_binding_id: request.role_binding_id.to_owned(),
            tenant_id: request.tenant_id.to_owned(),
            organization_id: request.organization_id.map(ToOwned::to_owned),
            project_id: request.project_id.map(ToOwned::to_owned),
            principal_id: request.principal_id.to_owned(),
            role_id: request.role_id.to_owned(),
            status: PlatformRoleBindingStatus::Active,
            resource_version: 1,
        };
        validate_role_binding(&candidate)?;
        let row = sqlx::query(UPSERT_ROLE_BINDING_SQL)
            .bind(request.role_binding_id)
            .bind(request.tenant_id)
            .bind(request.organization_id)
            .bind(request.project_id)
            .bind(request.principal_id)
            .bind(request.role_id)
            .bind(created_by)
            .fetch_one(&self.pool)
            .await?;
        role_binding_from_row(&row)
    }

    /// Updates a role binding status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails, the expected
    /// version is stale, or `PostgreSQL` rejects the write.
    pub async fn update_role_binding_status(
        &self,
        role_binding_id: &str,
        expected_resource_version: i64,
        status: PlatformRoleBindingStatus,
    ) -> Result<PlatformRoleBindingRecord> {
        let row = sqlx::query(UPDATE_ROLE_BINDING_STATUS_SQL)
            .bind(role_binding_id)
            .bind(status.as_str())
            .bind(expected_resource_version)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(PlatformRoleBindingError::StaleResourceVersion.into());
        };
        role_binding_from_row(&row)
    }

    /// Deletes non-deleted role bindings under one organization for a principal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried.
    pub async fn delete_role_bindings_for_organization_principal(
        &self,
        tenant_id: &str,
        organization_id: &str,
        principal_id: &str,
    ) -> Result<usize> {
        let rows = sqlx::query(DELETE_ROLE_BINDINGS_FOR_ORGANIZATION_PRINCIPAL_SQL)
            .bind(tenant_id)
            .bind(organization_id)
            .bind(principal_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.len())
    }

    /// Deletes non-deleted role bindings under one project for a principal.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried.
    pub async fn delete_role_bindings_for_project_principal(
        &self,
        tenant_id: &str,
        project_id: &str,
        principal_id: &str,
    ) -> Result<usize> {
        let rows = sqlx::query(DELETE_ROLE_BINDINGS_FOR_PROJECT_PRINCIPAL_SQL)
            .bind(tenant_id)
            .bind(project_id)
            .bind(principal_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.len())
    }

    /// Resolves raw secret material through a stored environment-backed ref.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the ref is unknown, inactive,
    /// unsupported, missing from the environment, or fingerprint-mismatched.
    pub async fn resolve_secret(&self, secret_ref_id: &str) -> Result<PlatformSecretValue> {
        let record = self
            .secret_ref(secret_ref_id)
            .await?
            .ok_or(PlatformSecretError::UnknownSecretRef)?;
        resolve_environment_secret(&record).map_err(Into::into)
    }

    /// Lists organization memberships for one organization.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn organization_members_for_organization(
        &self,
        organization_id: &str,
    ) -> Result<Vec<PlatformOrganizationMembershipRecord>> {
        let rows = sqlx::query(LIST_ORGANIZATION_MEMBERS_SQL)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(organization_member_from_row).collect()
    }

    /// Loads an organization membership by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn organization_member(
        &self,
        organization_member_id: &str,
    ) -> Result<Option<PlatformOrganizationMembershipRecord>> {
        let row = sqlx::query(SELECT_ORGANIZATION_MEMBER_SQL)
            .bind(organization_member_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| organization_member_from_row(&row))
            .transpose()
    }

    /// Updates an organization membership status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails, the expected
    /// version is stale, or `PostgreSQL` rejects the write.
    pub async fn update_organization_member_status(
        &self,
        organization_member_id: &str,
        expected_resource_version: i64,
        status: PlatformMembershipStatus,
    ) -> Result<PlatformOrganizationMembershipRecord> {
        let row = sqlx::query(UPDATE_ORGANIZATION_MEMBER_STATUS_SQL)
            .bind(organization_member_id)
            .bind(status.as_str())
            .bind(expected_resource_version)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(PlatformMembershipError::StaleResourceVersion.into());
        };
        organization_member_from_row(&row)
    }

    /// Creates or reactivates an organization membership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn upsert_organization_member(
        &self,
        request: PlatformOrganizationMembershipUpsert<'_>,
    ) -> Result<PlatformOrganizationMembershipRecord> {
        let candidate = PlatformOrganizationMembershipRecord {
            organization_member_id: request.organization_member_id.to_owned(),
            tenant_id: request.tenant_id.to_owned(),
            organization_id: request.organization_id.to_owned(),
            principal_id: request.principal_id.to_owned(),
            membership_kind: request.membership_kind.to_owned(),
            status: PlatformMembershipStatus::Active,
            resource_version: 1,
        };
        validate_organization_member(&candidate)?;
        let row = sqlx::query(UPSERT_ORGANIZATION_MEMBER_SQL)
            .bind(request.organization_member_id)
            .bind(request.tenant_id)
            .bind(request.organization_id)
            .bind(request.principal_id)
            .bind(request.membership_kind)
            .bind(request.created_by)
            .fetch_one(&self.pool)
            .await?;
        organization_member_from_row(&row)
    }

    /// Lists project memberships for one project.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn project_members_for_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<PlatformProjectMembershipRecord>> {
        let rows = sqlx::query(LIST_PROJECT_MEMBERS_SQL)
            .bind(project_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(project_member_from_row).collect()
    }

    /// Loads a project membership by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn project_member(
        &self,
        project_member_id: &str,
    ) -> Result<Option<PlatformProjectMembershipRecord>> {
        let row = sqlx::query(SELECT_PROJECT_MEMBER_SQL)
            .bind(project_member_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| project_member_from_row(&row)).transpose()
    }

    /// Updates a project membership status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails, the expected
    /// version is stale, or `PostgreSQL` rejects the write.
    pub async fn update_project_member_status(
        &self,
        project_member_id: &str,
        expected_resource_version: i64,
        status: PlatformMembershipStatus,
    ) -> Result<PlatformProjectMembershipRecord> {
        let row = sqlx::query(UPDATE_PROJECT_MEMBER_STATUS_SQL)
            .bind(project_member_id)
            .bind(status.as_str())
            .bind(expected_resource_version)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(PlatformMembershipError::StaleResourceVersion.into());
        };
        project_member_from_row(&row)
    }

    /// Creates or reactivates a project membership from an active organization membership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn upsert_project_member(
        &self,
        request: PlatformProjectMembershipUpsert<'_>,
    ) -> Result<PlatformProjectMembershipRecord> {
        let candidate = PlatformProjectMembershipRecord {
            project_member_id: request.project_member_id.to_owned(),
            tenant_id: request.tenant_id.to_owned(),
            organization_id: request.organization_id.to_owned(),
            project_id: request.project_id.to_owned(),
            principal_id: request.principal_id.to_owned(),
            organization_member_id: Some(request.organization_member_id.to_owned()),
            membership_kind: request.membership_kind.to_owned(),
            status: PlatformMembershipStatus::Active,
            resource_version: 1,
        };
        validate_project_member(&candidate)?;
        let row = sqlx::query(UPSERT_PROJECT_MEMBER_SQL)
            .bind(request.project_member_id)
            .bind(request.tenant_id)
            .bind(request.organization_id)
            .bind(request.project_id)
            .bind(request.principal_id)
            .bind(request.organization_member_id)
            .bind(request.membership_kind)
            .bind(request.created_by)
            .fetch_one(&self.pool)
            .await?;
        project_member_from_row(&row)
    }

    /// Cascades organization membership suspension/removal to child project memberships.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried.
    pub async fn cascade_project_memberships_for_organization_member(
        &self,
        organization_member: &PlatformOrganizationMembershipRecord,
        status: PlatformMembershipStatus,
    ) -> Result<usize> {
        if status == PlatformMembershipStatus::Active {
            return Ok(0);
        }
        let rows = sqlx::query(CASCADE_PROJECT_MEMBERS_FOR_ORGANIZATION_MEMBER_SQL)
            .bind(&organization_member.tenant_id)
            .bind(&organization_member.organization_id)
            .bind(&organization_member.principal_id)
            .bind(status.as_str())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.len())
    }

    /// Creates an organization invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn create_organization_invitation(
        &self,
        invitation: &PlatformOrganizationInvitationRecord,
    ) -> Result<PlatformOrganizationInvitationRecord> {
        validate_organization_invitation(invitation)?;
        sqlx::query(INSERT_ORGANIZATION_INVITATION_SQL)
            .bind(&invitation.invitation_id)
            .bind(&invitation.tenant_id)
            .bind(&invitation.organization_id)
            .bind(invitation.project_id.as_deref())
            .bind(invitation.invited_email.as_deref())
            .bind(invitation.invited_principal_id.as_deref())
            .bind(&invitation.invitation_token_hash)
            .bind(&invitation.role_id)
            .bind(invitation.status.as_str())
            .bind(invitation.expires_at_unix)
            .bind(&invitation.created_by)
            .bind(invitation.resource_version)
            .bind(invitation.created_at_unix)
            .bind(invitation.updated_at_unix)
            .execute(&self.pool)
            .await?;
        Ok(invitation.clone())
    }

    /// Lists organization invitations for one organization.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn organization_invitations(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> Result<Vec<PlatformOrganizationInvitationRecord>> {
        let rows = sqlx::query(LIST_ORGANIZATION_INVITATIONS_SQL)
            .bind(tenant_id)
            .bind(organization_id)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(organization_invitation_from_row).collect()
    }

    /// Loads an organization invitation by id.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn organization_invitation(
        &self,
        invitation_id: &str,
    ) -> Result<Option<PlatformOrganizationInvitationRecord>> {
        let row = sqlx::query(SELECT_ORGANIZATION_INVITATION_SQL)
            .bind(invitation_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| organization_invitation_from_row(&row))
            .transpose()
    }

    /// Loads an organization invitation by raw-token hash.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record shape is invalid.
    pub async fn organization_invitation_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Result<Option<PlatformOrganizationInvitationRecord>> {
        let row = sqlx::query(SELECT_ORGANIZATION_INVITATION_BY_TOKEN_HASH_SQL)
            .bind(token_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| organization_invitation_from_row(&row))
            .transpose()
    }

    /// Revokes a pending organization invitation with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the invitation is stale,
    /// non-pending, or `PostgreSQL` rejects the write.
    pub async fn revoke_organization_invitation(
        &self,
        invitation_id: &str,
        expected_resource_version: i64,
        now_unix: i64,
    ) -> Result<PlatformOrganizationInvitationRecord> {
        let row = sqlx::query(REVOKE_ORGANIZATION_INVITATION_SQL)
            .bind(invitation_id)
            .bind(expected_resource_version)
            .bind(now_unix)
            .fetch_optional(&self.pool)
            .await?;
        let Some(row) = row else {
            return Err(PlatformInvitationError::StaleResourceVersion.into());
        };
        organization_invitation_from_row(&row)
    }

    /// Accepts an invitation and upserts the resulting memberships in one transaction.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the invitation is unavailable,
    /// expired, mismatched, or `PostgreSQL` rejects any write.
    pub async fn accept_organization_invitation(
        &self,
        request: &AcceptPlatformOrganizationInvitationRequest,
    ) -> Result<(
        PlatformOrganizationInvitationRecord,
        PlatformOrganizationMembershipRecord,
        Option<PlatformProjectMembershipRecord>,
    )> {
        let mut transaction = self.pool.begin().await?;
        let before = sqlx::query(SELECT_ORGANIZATION_INVITATION_SQL)
            .bind(&request.invitation_id)
            .fetch_optional(&mut *transaction)
            .await?
            .map(|row| organization_invitation_from_row(&row))
            .transpose()?
            .ok_or(PlatformInvitationError::InvalidInvitationId)?;
        if !before
            .status
            .accepts_at(before.expires_at_unix, request.accepted_at_unix)
        {
            return Err(PlatformInvitationError::InvitationNotAccepting.into());
        }
        if before.invited_principal_id.as_deref() != Some(request.principal_id.as_str()) {
            return Err(PlatformInvitationError::InvitationPrincipalMismatch.into());
        }
        let accepted = sqlx::query(ACCEPT_ORGANIZATION_INVITATION_SQL)
            .bind(&request.invitation_id)
            .bind(request.accepted_at_unix)
            .fetch_optional(&mut *transaction)
            .await
            .map_err(PlatformRepositoryError::from)?
            .map(|row| organization_invitation_from_row(&row))
            .transpose()?
            .ok_or(PlatformInvitationError::InvitationNotAccepting)?;
        let organization_member = sqlx::query(UPSERT_INVITED_ORGANIZATION_MEMBER_SQL)
            .bind(&request.organization_member_id)
            .bind(&accepted.tenant_id)
            .bind(&accepted.organization_id)
            .bind(&request.principal_id)
            .bind(request.accepted_at_unix)
            .fetch_one(&mut *transaction)
            .await
            .map(|row| organization_member_from_row(&row))??;
        let project_member = if let Some(project_id) = accepted.project_id.as_deref() {
            let project_member_id = request
                .project_member_id
                .as_deref()
                .ok_or(PlatformMembershipError::InvalidMembershipId)?;
            Some(
                sqlx::query(UPSERT_INVITED_PROJECT_MEMBER_SQL)
                    .bind(project_member_id)
                    .bind(&accepted.tenant_id)
                    .bind(&accepted.organization_id)
                    .bind(project_id)
                    .bind(&request.principal_id)
                    .bind(&organization_member.organization_member_id)
                    .bind(request.accepted_at_unix)
                    .fetch_one(&mut *transaction)
                    .await
                    .map(|row| project_member_from_row(&row))??,
            )
        } else {
            None
        };
        transaction.commit().await?;
        Ok((accepted, organization_member, project_member))
    }

    /// Records or replaces an `OIDC` login attempt.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn record_oidc_login_attempt(&self, record: &OidcLoginAttemptRecord) -> Result<()> {
        validate_oidc_login_attempt_record(record)?;
        sqlx::query(RECORD_OIDC_LOGIN_ATTEMPT_SQL)
            .bind(&record.login_attempt_id)
            .bind(&record.tenant_id)
            .bind(&record.identity_provider_id)
            .bind(&record.state_hash)
            .bind(&record.nonce_hash)
            .bind(&record.pkce_verifier_hash)
            .bind(&record.redirect_uri)
            .bind(oidc_login_attempt_status_as_str(record.status))
            .bind(record.expires_at_unix)
            .bind(record.consumed_at_unix)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Looks up an `OIDC` login attempt by raw OAuth state.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when the state is empty,
    /// `PostgreSQL` cannot be queried, or a stored record has an invalid shape.
    pub async fn oidc_login_attempt_for_state(
        &self,
        raw_state: &str,
    ) -> Result<Option<OidcLoginAttemptRecord>> {
        let state_hash = oidc_state_hash_for_lookup(raw_state)?;
        let row = sqlx::query(SELECT_OIDC_LOGIN_ATTEMPT_BY_STATE_SQL)
            .bind(state_hash)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| oidc_login_attempt_from_row(&row)).transpose()
    }

    /// Completes a verified `OIDC` login in one durable transaction.
    ///
    /// The transaction consumes the one-time login attempt, repairs the local
    /// user default organization and project, links the external identity, and
    /// records the issued session. It does not verify token signatures; callers
    /// must pass only already-verified claims and a pre-hashed session record.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails, the attempt is
    /// unavailable, the external identity already belongs to another principal,
    /// or `PostgreSQL` rejects one of the writes.
    pub async fn complete_oidc_login(&self, record: &OidcLoginCompletionRecord) -> Result<()> {
        validate_oidc_login_completion_record(record)?;
        let mut transaction = self.pool.begin().await?;

        let consume = sqlx::query(CONSUME_OIDC_LOGIN_ATTEMPT_SQL)
            .bind(&record.login_attempt_id)
            .bind(record.consumed_at_unix)
            .bind(&record.tenant_id)
            .bind(&record.identity_provider_id)
            .execute(&mut *transaction)
            .await?;
        if consume.rows_affected() != 1 {
            return Err(PlatformRepositoryError::OidcLoginAttemptUnavailable(
                record.login_attempt_id.clone(),
            ));
        }
        ensure_oidc_login_user_allows_access_in_transaction(&mut transaction, &record.user_id)
            .await?;

        sqlx::query(UPSERT_OIDC_USER_ORGANIZATION_SQL)
            .bind(&record.organization_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(UPSERT_OIDC_USER_PROJECT_SQL)
            .bind(&record.project_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(UPSERT_OIDC_USER_PRINCIPAL_SQL)
            .bind(&record.user_id)
            .bind(&record.tenant_id)
            .bind(&record.user_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(UPSERT_OIDC_USER_SQL)
            .bind(&record.user_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_id)
            .bind(record.email.as_deref())
            .bind(&record.user_display_name)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(UPSERT_OIDC_ORGANIZATION_MEMBERSHIP_SQL)
            .bind(&record.organization_member_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.user_id)
            .execute(&mut *transaction)
            .await?;
        sqlx::query(UPSERT_OIDC_PROJECT_MEMBERSHIP_SQL)
            .bind(&record.project_member_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_id)
            .bind(&record.user_id)
            .bind(&record.organization_member_id)
            .execute(&mut *transaction)
            .await?;
        let external_identity = sqlx::query(UPSERT_OIDC_EXTERNAL_IDENTITY_SQL)
            .bind(&record.external_identity_id)
            .bind(&record.tenant_id)
            .bind(&record.user_id)
            .bind(&record.identity_provider_id)
            .bind(&record.provider_subject)
            .bind(record.email.as_deref())
            .bind(record.email_verified)
            .execute(&mut *transaction)
            .await?;
        if external_identity.rows_affected() != 1 {
            return Err(
                PlatformRepositoryError::OidcExternalIdentityPrincipalMismatch(
                    record.provider_subject.clone(),
                ),
            );
        }
        sqlx::query(UPSERT_OIDC_ORGANIZATION_ADMIN_ROLE_SQL)
            .bind(&record.organization_role_binding_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.user_id)
            .bind(BuiltInRole::OrganizationAdmin.as_str())
            .execute(&mut *transaction)
            .await?;
        sqlx::query(RECORD_OIDC_AUTH_SESSION_SQL)
            .bind(&record.session.session_id)
            .bind(&record.tenant_id)
            .bind(&record.organization_id)
            .bind(&record.project_id)
            .bind(&record.user_id)
            .bind(&record.identity_provider_id)
            .bind(&record.session.token_hash)
            .bind(record.session.status.as_str())
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;
        Ok(())
    }

    /// Records or replaces resource ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects the write.
    pub async fn record_resource_owner(&self, record: &ResourceOwnerRecord) -> Result<()> {
        validate_resource_owner_record(record)?;
        sqlx::query(RECORD_RESOURCE_OWNER_SQL)
            .bind(&record.resource_kind)
            .bind(&record.resource_id)
            .bind(&record.tenant_id)
            .bind(record.organization_id.as_deref())
            .bind(record.project_id.as_deref())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Loads resource ownership metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried.
    pub async fn resource_owner(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<Option<ResourceOwnerRecord>> {
        let row = sqlx::query(SELECT_RESOURCE_OWNER_SQL)
            .bind(resource_kind)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| resource_owner_from_row(&row)).transpose()
    }

    /// Records a safe business resource projection with its owner metadata.
    ///
    /// The owner row and business projection are written in one transaction so
    /// route authorization never observes a business record without ownership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when validation fails or `PostgreSQL`
    /// rejects either write.
    pub async fn record_platform_resource(
        &self,
        record: &PlatformResourceRecord,
        actor: &AuthenticatedActor,
    ) -> Result<()> {
        validate_platform_resource_record(record)?;
        let mut transaction = self.pool.begin().await?;
        record_resource_owner_in_transaction(&mut transaction, &record.owner).await?;
        record_business_resource_in_transaction(&mut transaction, record, actor).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Loads a safe business resource projection after loading owner metadata.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRepositoryError`] when `PostgreSQL` cannot be queried or
    /// a stored record has an invalid shape.
    pub async fn platform_resource(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<Option<PlatformResourceRecord>> {
        let Some(owner) = self.resource_owner(resource_kind, resource_id).await? else {
            return Ok(None);
        };
        let data = match resource_kind {
            "Conversation" => self.conversation(resource_id).await?,
            "Run" => self.run(resource_id).await?,
            "Approval" => self.approval(resource_id).await?,
            "DeferredTool" => self.deferred_tool(resource_id).await?,
            "EnvironmentAttachment" => self.environment_attachment(resource_id).await?,
            "EvidenceArchive" => self.evidence_archive(resource_id).await?,
            _ => None,
        };
        data.map(|data| PlatformResourceRecord::new(owner, data))
            .transpose()
            .map_err(Into::into)
    }

    async fn conversation(&self, resource_id: &str) -> Result<Option<PlatformResourceData>> {
        let row = sqlx::query(SELECT_CONVERSATION_SQL)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(PlatformResourceData::Conversation(ConversationRecord {
                title: row.try_get("title")?,
                status: row.try_get("status")?,
            }))
        })
        .transpose()
    }

    async fn run(&self, resource_id: &str) -> Result<Option<PlatformResourceData>> {
        let row = sqlx::query(SELECT_RUN_SQL)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(PlatformResourceData::Run(RunRecord {
                conversation_id: row.try_get("conversation_id")?,
                status: row.try_get("status")?,
                model_alias: row.try_get("model_alias")?,
            }))
        })
        .transpose()
    }

    async fn approval(&self, resource_id: &str) -> Result<Option<PlatformResourceData>> {
        let row = sqlx::query(SELECT_APPROVAL_SQL)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(PlatformResourceData::Approval(ApprovalRecord {
                run_id: row.try_get("run_id")?,
                status: row.try_get("status")?,
                requested_action: row.try_get("requested_action")?,
            }))
        })
        .transpose()
    }

    async fn deferred_tool(&self, resource_id: &str) -> Result<Option<PlatformResourceData>> {
        let row = sqlx::query(SELECT_DEFERRED_TOOL_SQL)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(PlatformResourceData::DeferredTool(DeferredToolRecord {
                run_id: row.try_get("run_id")?,
                tool_name: row.try_get("tool_name")?,
                status: row.try_get("status")?,
            }))
        })
        .transpose()
    }

    async fn environment_attachment(
        &self,
        resource_id: &str,
    ) -> Result<Option<PlatformResourceData>> {
        let row = sqlx::query(SELECT_ENVIRONMENT_ATTACHMENT_SQL)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(PlatformResourceData::EnvironmentAttachment(
                EnvironmentAttachmentRecord {
                    lease_id: row.try_get("attachment_lease_id")?,
                    status: row.try_get("status")?,
                    readiness: row.try_get("readiness")?,
                },
            ))
        })
        .transpose()
    }

    async fn evidence_archive(&self, resource_id: &str) -> Result<Option<PlatformResourceData>> {
        let row = sqlx::query(SELECT_EVIDENCE_ARCHIVE_SQL)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| {
            Ok(PlatformResourceData::EvidenceArchive(
                EvidenceArchiveRecord {
                    manifest_uri: row.try_get("manifest_uri")?,
                    retention_class: row.try_get("retention_class")?,
                    debug_available: row.try_get("debug_available")?,
                },
            ))
        })
        .transpose()
    }
}

async fn record_resource_owner_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    record: &ResourceOwnerRecord,
) -> Result<()> {
    validate_resource_owner_record(record)?;
    sqlx::query(RECORD_RESOURCE_OWNER_SQL)
        .bind(&record.resource_kind)
        .bind(&record.resource_id)
        .bind(&record.tenant_id)
        .bind(record.organization_id.as_deref())
        .bind(record.project_id.as_deref())
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn record_business_resource_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    record: &PlatformResourceRecord,
    actor: &AuthenticatedActor,
) -> Result<()> {
    let (organization_id, project_id) = project_scope(&record.owner)?;
    match &record.data {
        PlatformResourceData::Conversation(data) => {
            sqlx::query(RECORD_CONVERSATION_SQL)
                .bind(&record.owner.resource_id)
                .bind(&record.owner.tenant_id)
                .bind(organization_id)
                .bind(project_id)
                .bind(&actor.principal_id)
                .bind(&data.title)
                .bind(&data.status)
                .execute(&mut **transaction)
                .await?;
        }
        PlatformResourceData::Run(data) => {
            sqlx::query(RECORD_RUN_SQL)
                .bind(&record.owner.resource_id)
                .bind(&record.owner.tenant_id)
                .bind(organization_id)
                .bind(project_id)
                .bind(&data.conversation_id)
                .bind(&actor.principal_id)
                .bind(&data.status)
                .bind(&data.model_alias)
                .execute(&mut **transaction)
                .await?;
        }
        PlatformResourceData::Approval(data) => {
            sqlx::query(RECORD_APPROVAL_SQL)
                .bind(&record.owner.resource_id)
                .bind(&record.owner.tenant_id)
                .bind(organization_id)
                .bind(project_id)
                .bind(&data.run_id)
                .bind(&data.requested_action)
                .bind(&data.status)
                .execute(&mut **transaction)
                .await?;
        }
        PlatformResourceData::DeferredTool(data) => {
            sqlx::query(RECORD_DEFERRED_TOOL_SQL)
                .bind(&record.owner.resource_id)
                .bind(&record.owner.tenant_id)
                .bind(organization_id)
                .bind(project_id)
                .bind(&data.run_id)
                .bind(&data.tool_name)
                .bind(&data.status)
                .execute(&mut **transaction)
                .await?;
        }
        PlatformResourceData::EnvironmentAttachment(data) => {
            sqlx::query(RECORD_ENVIRONMENT_ATTACHMENT_SQL)
                .bind(&record.owner.resource_id)
                .bind(&record.owner.tenant_id)
                .bind(organization_id)
                .bind(project_id)
                .bind(&data.lease_id)
                .bind(&data.readiness)
                .bind(&data.status)
                .execute(&mut **transaction)
                .await?;
        }
        PlatformResourceData::EvidenceArchive(data) => {
            sqlx::query(RECORD_EVIDENCE_ARCHIVE_SQL)
                .bind(&record.owner.resource_id)
                .bind(&record.owner.tenant_id)
                .bind(organization_id)
                .bind(project_id)
                .bind(&record.owner.resource_id)
                .bind(&data.manifest_uri)
                .bind(&data.retention_class)
                .bind(data.debug_available)
                .execute(&mut **transaction)
                .await?;
        }
    }
    Ok(())
}

async fn ensure_oidc_login_user_allows_access_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    user_id: &str,
) -> Result<()> {
    if let Some(row) = sqlx::query(SELECT_PLATFORM_USER_INCLUDING_DELETED_SQL)
        .bind(user_id)
        .fetch_optional(&mut **transaction)
        .await?
    {
        let user = platform_user_from_row(&row)?;
        if !user.status.accepts_access() {
            return Err(AuthError::PrincipalDisabled.into());
        }
    }
    Ok(())
}

fn validate_auth_session_record(record: &PlatformAuthSessionRecord) -> Result<()> {
    if record.session_id.trim().is_empty() {
        return Err(AuthError::EmptySessionId.into());
    }
    if record.token_hash.trim().is_empty() {
        return Err(AuthError::EmptyTokenHash.into());
    }
    Ok(())
}

fn validate_bearer_credential_record(record: &PlatformBearerCredentialRecord) -> Result<()> {
    if record.credential_id.trim().is_empty() {
        return Err(AuthError::EmptyCredentialId.into());
    }
    if record.token_hash.trim().is_empty() {
        return Err(AuthError::EmptyCredentialTokenHash.into());
    }
    Ok(())
}

fn validate_mtls_identity_record(record: &PlatformMtlsIdentityRecord) -> Result<()> {
    if record.identity_id.trim().is_empty() {
        return Err(AuthError::EmptyMtlsIdentityId.into());
    }
    if record.subject.trim().is_empty() {
        return Err(AuthError::EmptyMtlsSubject.into());
    }
    Ok(())
}

fn validate_oidc_login_completion_record(record: &OidcLoginCompletionRecord) -> Result<()> {
    validate_prefixed_id(
        &record.login_attempt_id,
        "ola_",
        OidcValidationError::InvalidLoginAttemptId,
    )?;
    validate_prefixed_id(
        &record.tenant_id,
        "ten_",
        OidcValidationError::InvalidTenantId,
    )?;
    validate_prefixed_id(
        &record.organization_id,
        "org_",
        OidcValidationError::InvalidOrganizationId,
    )?;
    validate_prefixed_id(
        &record.project_id,
        "prj_",
        OidcValidationError::InvalidProjectId,
    )?;
    validate_prefixed_id(&record.user_id, "usr_", OidcValidationError::InvalidUserId)?;
    validate_prefixed_id(
        &record.identity_provider_id,
        "idp_",
        OidcValidationError::InvalidProviderId,
    )?;
    validate_prefixed_id(
        &record.external_identity_id,
        "xid_",
        OidcValidationError::InvalidExternalIdentityId,
    )?;
    validate_prefixed_id(
        &record.organization_member_id,
        "om_",
        OidcValidationError::InvalidMembershipId,
    )?;
    validate_prefixed_id(
        &record.project_member_id,
        "pm_",
        OidcValidationError::InvalidMembershipId,
    )?;
    validate_prefixed_id(
        &record.organization_role_binding_id,
        "rb_",
        OidcValidationError::InvalidRoleBindingId,
    )?;
    if record.provider_subject.trim().is_empty() {
        return Err(OidcValidationError::SubjectRequired.into());
    }
    if record.user_display_name.trim().is_empty()
        || record.organization_display_name.trim().is_empty()
        || record.project_display_name.trim().is_empty()
    {
        return Err(OidcValidationError::DisplayNameRequired.into());
    }
    if record.consumed_at_unix <= 0 {
        return Err(OidcValidationError::InvalidAttemptExpiry.into());
    }
    validate_auth_session_record(&record.session)?;
    if record.session.status != PlatformAuthSessionStatus::Active {
        return Err(AuthError::SessionExpired.into());
    }
    if record.session.actor.tenant_id != record.tenant_id
        || record.session.actor.organization_id.as_deref() != Some(record.organization_id.as_str())
        || record.session.actor.project_id.as_deref() != Some(record.project_id.as_str())
        || record.session.actor.principal_id != record.user_id
        || record.session.actor.actor_kind != ActorKind::User
    {
        return Err(PlatformRepositoryError::OidcSessionActorMismatch(
            record.session.session_id.clone(),
        ));
    }
    Ok(())
}

fn validate_prefixed_id(value: &str, prefix: &str, error: OidcValidationError) -> Result<()> {
    if value.starts_with(prefix) {
        Ok(())
    } else {
        Err(error.into())
    }
}

fn validate_resource_owner_record(record: &ResourceOwnerRecord) -> Result<()> {
    if record.resource_kind.trim().is_empty() {
        return Err(StoreError::EmptyResourceKind.into());
    }
    if record.resource_id.trim().is_empty() {
        return Err(StoreError::EmptyResourceId.into());
    }
    if record.tenant_id.trim().is_empty() {
        return Err(StoreError::EmptyTenantId.into());
    }
    if record.project_id.is_some() && record.organization_id.is_none() {
        return Err(StoreError::ProjectWithoutOrganization.into());
    }
    Ok(())
}

fn validate_platform_resource_record(record: &PlatformResourceRecord) -> Result<()> {
    validate_resource_owner_record(&record.owner)?;
    if record.owner.resource_kind != record.data.resource_kind() {
        return Err(PlatformResourceError::ResourceKindMismatch.into());
    }
    Ok(())
}

fn session_token_hash_for_lookup(raw_bearer: &str) -> Result<String> {
    let raw_bearer = raw_bearer.trim();
    if raw_bearer.is_empty() {
        return Err(AuthError::EmptyBearerToken.into());
    }
    Ok(hash_session_token(raw_bearer))
}

fn bearer_credential_hash_for_lookup(raw_bearer: &str) -> Result<String> {
    let raw_bearer = raw_bearer.trim();
    if raw_bearer.is_empty() {
        return Err(AuthError::EmptyBearerToken.into());
    }
    Ok(hash_bearer_credential_token(raw_bearer))
}

fn mtls_subject_for_lookup(subject: &str) -> Result<String> {
    let subject = subject.trim();
    if subject.is_empty() {
        return Err(AuthError::EmptyMtlsSubject.into());
    }
    Ok(subject.to_owned())
}

fn oidc_state_hash_for_lookup(raw_state: &str) -> Result<String> {
    let raw_state = raw_state.trim();
    if raw_state.is_empty() {
        return Err(OidcValidationError::EmptyState.into());
    }
    Ok(hash_oidc_login_state(raw_state))
}

const fn actor_kind_as_str(actor_kind: ActorKind) -> &'static str {
    match actor_kind {
        ActorKind::User => "user",
        ActorKind::ServiceAccount => "service_account",
        ActorKind::System => "system",
    }
}

fn actor_kind_from_str(value: &str) -> Result<ActorKind> {
    match value {
        "user" => Ok(ActorKind::User),
        "service_account" => Ok(ActorKind::ServiceAccount),
        "system" => Ok(ActorKind::System),
        _ => Err(PlatformRepositoryError::UnknownActorKind(value.to_owned())),
    }
}

fn auth_session_status_from_str(value: &str) -> Result<PlatformAuthSessionStatus> {
    match value {
        "active" => Ok(PlatformAuthSessionStatus::Active),
        "revoked" => Ok(PlatformAuthSessionStatus::Revoked),
        "expired" => Ok(PlatformAuthSessionStatus::Expired),
        "principal_disabled" => Ok(PlatformAuthSessionStatus::PrincipalDisabled),
        _ => Err(PlatformRepositoryError::UnknownSessionStatus(
            value.to_owned(),
        )),
    }
}

fn oidc_login_provider_status_from_str(value: &str) -> Result<OidcLoginProviderStatus> {
    match value {
        "active" => Ok(OidcLoginProviderStatus::Active),
        "disabled" => Ok(OidcLoginProviderStatus::Disabled),
        "deleted" => Ok(OidcLoginProviderStatus::Deleted),
        _ => Err(PlatformRepositoryError::UnknownOidcLoginProviderStatus(
            value.to_owned(),
        )),
    }
}

fn oidc_token_endpoint_auth_method_from_str(value: &str) -> Result<OidcTokenEndpointAuthMethod> {
    OidcTokenEndpointAuthMethod::from_id(value).ok_or(PlatformRepositoryError::Identity(
        OidcValidationError::InvalidTokenEndpointAuthMethod,
    ))
}

const fn oidc_login_attempt_status_as_str(status: OidcLoginAttemptStatus) -> &'static str {
    status.as_str()
}

fn oidc_login_attempt_status_from_str(value: &str) -> Result<OidcLoginAttemptStatus> {
    match value {
        "active" => Ok(OidcLoginAttemptStatus::Active),
        "consumed" => Ok(OidcLoginAttemptStatus::Consumed),
        "expired" => Ok(OidcLoginAttemptStatus::Expired),
        "abandoned" => Ok(OidcLoginAttemptStatus::Abandoned),
        _ => Err(PlatformRepositoryError::UnknownOidcLoginAttemptStatus(
            value.to_owned(),
        )),
    }
}

fn secret_ref_status_from_str(value: &str) -> Result<PlatformSecretRefStatus> {
    match value {
        "active" => Ok(PlatformSecretRefStatus::Active),
        "rotating" => Ok(PlatformSecretRefStatus::Rotating),
        "disabled" => Ok(PlatformSecretRefStatus::Disabled),
        "deleted" => Ok(PlatformSecretRefStatus::Deleted),
        _ => Err(PlatformRepositoryError::UnknownSecretRefStatus(
            value.to_owned(),
        )),
    }
}

fn external_identity_status_from_str(value: &str) -> Result<PlatformExternalIdentityStatus> {
    PlatformExternalIdentityStatus::from_id(value)
        .ok_or_else(|| PlatformRepositoryError::UnknownExternalIdentityStatus(value.to_owned()))
}

fn role_binding_status_from_str(value: &str) -> Result<PlatformRoleBindingStatus> {
    PlatformRoleBindingStatus::from_id(value)
        .ok_or_else(|| PlatformRepositoryError::UnknownRoleBindingStatus(value.to_owned()))
}

fn user_status_from_str(value: &str) -> Result<PlatformUserStatus> {
    PlatformUserStatus::from_id(value)
        .ok_or_else(|| PlatformRepositoryError::UnknownUserStatus(value.to_owned()))
}

fn membership_status_from_str(value: &str) -> Result<PlatformMembershipStatus> {
    PlatformMembershipStatus::from_id(value)
        .ok_or_else(|| PlatformRepositoryError::UnknownMembershipStatus(value.to_owned()))
}

fn invitation_status_from_str(value: &str) -> Result<PlatformInvitationStatus> {
    PlatformInvitationStatus::from_id(value)
        .ok_or_else(|| PlatformRepositoryError::UnknownInvitationStatus(value.to_owned()))
}

fn actor_from_row(row: &PgRow) -> Result<AuthenticatedActor> {
    let actor_kind = actor_kind_from_str(&row.try_get::<String, _>("actor_kind")?)?;
    Ok(AuthenticatedActor {
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        principal_id: row.try_get("principal_id")?,
        actor_kind,
    })
}

fn auth_session_from_row(row: &PgRow) -> Result<PlatformAuthSessionRecord> {
    let token_expired = row.try_get::<bool, _>("token_expired")?;
    let status = if token_expired {
        PlatformAuthSessionStatus::Expired
    } else {
        auth_session_status_from_str(&row.try_get::<String, _>("status")?)?
    };
    let record = PlatformAuthSessionRecord {
        session_id: row.try_get("auth_session_id")?,
        token_hash: row.try_get("token_hash")?,
        actor: actor_from_row(row)?,
        status,
    };
    validate_auth_session_record(&record)?;
    Ok(record)
}

fn active_auth_session_from_row(row: &PgRow) -> Result<PlatformAuthSessionRecord> {
    let record = auth_session_from_row(row)?;
    match record.status {
        PlatformAuthSessionStatus::Active => Ok(record),
        PlatformAuthSessionStatus::Revoked => Err(AuthError::SessionRevoked.into()),
        PlatformAuthSessionStatus::Expired => Err(AuthError::SessionExpired.into()),
        PlatformAuthSessionStatus::PrincipalDisabled => Err(AuthError::PrincipalDisabled.into()),
    }
}

fn platform_user_from_row(row: &PgRow) -> Result<PlatformUserRecord> {
    let record = PlatformUserRecord {
        user_id: row.try_get("user_id")?,
        tenant_id: row.try_get("tenant_id")?,
        default_organization_id: row.try_get("default_organization_id")?,
        default_project_id: row.try_get("default_project_id")?,
        primary_email: row.try_get("primary_email")?,
        display_name: row.try_get("display_name")?,
        status: user_status_from_str(&row.try_get::<String, _>("status")?)?,
        resource_version: row.try_get("resource_version")?,
    };
    validate_platform_user_record(&record)?;
    Ok(record)
}

fn platform_audit_event_from_row(row: &PgRow) -> Result<PlatformAuditEventRecord> {
    let actor_kind = actor_kind_from_str(&row.try_get::<String, _>("actor_kind")?)?;
    let record = PlatformAuditEventRecord {
        audit_event_id: row.try_get("audit_event_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        actor_principal_id: row.try_get("actor_principal_id")?,
        actor_kind,
        action_id: row.try_get("action_id")?,
        resource_kind: row.try_get("resource_kind")?,
        resource_id: row.try_get("resource_id")?,
        event_type: row.try_get("event_type")?,
        reason: row.try_get("reason")?,
        redaction: row.try_get("redaction")?,
        created_at_unix: row.try_get("created_at_unix")?,
    };
    validate_platform_audit_event_record(&record)?;
    Ok(record)
}

fn oidc_login_provider_from_row(row: &PgRow) -> Result<OidcLoginProviderRecord> {
    let status = oidc_login_provider_status_from_str(&row.try_get::<String, _>("status")?)?;
    let token_endpoint_auth_method = oidc_token_endpoint_auth_method_from_str(
        &row.try_get::<String, _>("token_endpoint_auth_method")?,
    )?;
    let requested_scopes = row.try_get::<serde_json::Value, _>("requested_scopes")?;
    let oidc_audiences = row.try_get::<serde_json::Value, _>("oidc_audiences")?;
    let record = OidcLoginProviderRecord {
        identity_provider_id: row.try_get("identity_provider_id")?,
        tenant_id: row.try_get("tenant_id")?,
        display_name: row.try_get("display_name")?,
        issuer_url: row.try_get("issuer_url")?,
        authorization_endpoint: row.try_get("authorization_endpoint")?,
        token_endpoint: row.try_get("token_endpoint")?,
        jwks_uri: row.try_get("jwks_uri")?,
        client_id: row.try_get("client_id")?,
        client_secret_ref: row.try_get("client_secret_ref")?,
        token_endpoint_auth_method,
        redirect_uri: row.try_get("redirect_uri")?,
        requested_scopes: json_string_array(&requested_scopes),
        accepted_audiences: json_string_array(&oidc_audiences),
        status,
    };
    validate_oidc_login_provider_base(&record)?;
    Ok(record)
}

fn secret_ref_from_row(row: &PgRow) -> Result<PlatformSecretRefRecord> {
    let status = secret_ref_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = PlatformSecretRefRecord {
        secret_ref_id: row.try_get("secret_ref_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        purpose: row.try_get("purpose")?,
        backend_kind: row.try_get("backend_kind")?,
        backend_locator: row.try_get("backend_locator")?,
        display_mask: row.try_get("display_mask")?,
        fingerprint: row.try_get("fingerprint")?,
        status,
    };
    validate_secret_ref_record(&record)?;
    Ok(record)
}

fn external_identity_from_row(row: &PgRow) -> Result<PlatformExternalIdentityRecord> {
    let status = external_identity_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = PlatformExternalIdentityRecord {
        external_identity_id: row.try_get("external_identity_id")?,
        tenant_id: row.try_get("tenant_id")?,
        principal_id: row.try_get("principal_id")?,
        identity_provider_id: row.try_get("identity_provider_id")?,
        provider_kind: row.try_get("provider_kind")?,
        provider_subject: row.try_get("provider_subject")?,
        email: row.try_get("email")?,
        email_verified: row.try_get("email_verified")?,
        status,
    };
    validate_external_identity(&record)?;
    Ok(record)
}

fn role_binding_from_row(row: &PgRow) -> Result<PlatformRoleBindingRecord> {
    let status = role_binding_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = PlatformRoleBindingRecord {
        role_binding_id: row.try_get("role_binding_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        principal_id: row.try_get("principal_id")?,
        role_id: row.try_get("role_id")?,
        status,
        resource_version: row.try_get("resource_version")?,
    };
    validate_role_binding(&record)?;
    Ok(record)
}

fn organization_member_from_row(row: &PgRow) -> Result<PlatformOrganizationMembershipRecord> {
    let status = membership_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = PlatformOrganizationMembershipRecord {
        organization_member_id: row.try_get("organization_member_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        principal_id: row.try_get("principal_id")?,
        membership_kind: row.try_get("membership_kind")?,
        status,
        resource_version: row.try_get("resource_version")?,
    };
    validate_organization_member(&record)?;
    Ok(record)
}

fn project_member_from_row(row: &PgRow) -> Result<PlatformProjectMembershipRecord> {
    let status = membership_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = PlatformProjectMembershipRecord {
        project_member_id: row.try_get("project_member_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        principal_id: row.try_get("principal_id")?,
        organization_member_id: row.try_get("organization_member_id")?,
        membership_kind: row.try_get("membership_kind")?,
        status,
        resource_version: row.try_get("resource_version")?,
    };
    validate_project_member(&record)?;
    Ok(record)
}

fn organization_invitation_from_row(row: &PgRow) -> Result<PlatformOrganizationInvitationRecord> {
    let status = invitation_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = PlatformOrganizationInvitationRecord {
        invitation_id: row.try_get("invitation_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
        invited_email: row.try_get("invited_email")?,
        invited_principal_id: row.try_get("invited_principal_id")?,
        invitation_token_hash: row.try_get("invitation_token_hash")?,
        role_id: row.try_get("role_id")?,
        status,
        expires_at_unix: row.try_get("expires_at_unix")?,
        accepted_at_unix: row.try_get("accepted_at_unix")?,
        created_by: row.try_get("created_by")?,
        resource_version: row.try_get("resource_version")?,
        created_at_unix: row.try_get("created_at_unix")?,
        updated_at_unix: row.try_get("updated_at_unix")?,
    };
    validate_organization_invitation(&record)?;
    Ok(record)
}

fn json_string_array(value: &serde_json::Value) -> Vec<String> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn oidc_login_attempt_from_row(row: &PgRow) -> Result<OidcLoginAttemptRecord> {
    let status = oidc_login_attempt_status_from_str(&row.try_get::<String, _>("status")?)?;
    let record = OidcLoginAttemptRecord {
        login_attempt_id: row.try_get("oidc_login_attempt_id")?,
        tenant_id: row.try_get("tenant_id")?,
        identity_provider_id: row.try_get("identity_provider_id")?,
        state_hash: row.try_get("state_hash")?,
        nonce_hash: row.try_get("nonce_hash")?,
        pkce_verifier_hash: row.try_get("pkce_verifier_hash")?,
        redirect_uri: row.try_get("redirect_uri")?,
        status,
        expires_at_unix: row.try_get("expires_at_unix")?,
        consumed_at_unix: row.try_get("consumed_at_unix")?,
    };
    validate_oidc_login_attempt_record(&record)?;
    Ok(record)
}

fn resource_owner_from_row(row: &PgRow) -> Result<ResourceOwnerRecord> {
    Ok(ResourceOwnerRecord {
        resource_kind: row.try_get("resource_kind")?,
        resource_id: row.try_get("resource_id")?,
        tenant_id: row.try_get("tenant_id")?,
        organization_id: row.try_get("organization_id")?,
        project_id: row.try_get("project_id")?,
    })
}

fn project_scope(owner: &ResourceOwnerRecord) -> Result<(&str, &str)> {
    let Some(organization_id) = owner.organization_id.as_deref() else {
        return Err(PlatformRepositoryError::ProjectScopeRequired(
            owner.resource_kind.clone(),
        ));
    };
    let Some(project_id) = owner.project_id.as_deref() else {
        return Err(PlatformRepositoryError::ProjectScopeRequired(
            owner.resource_kind.clone(),
        ));
    };
    Ok((organization_id, project_id))
}

#[cfg(test)]
const fn business_resource_table(data: &PlatformResourceData) -> &'static str {
    match data {
        PlatformResourceData::Conversation(_) => "platform_conversations",
        PlatformResourceData::Run(_) => "platform_runs",
        PlatformResourceData::Approval(_) => "platform_approvals",
        PlatformResourceData::DeferredTool(_) => "platform_deferred_tools",
        PlatformResourceData::EnvironmentAttachment(_) => "platform_environment_attachments",
        PlatformResourceData::EvidenceArchive(_) => "platform_evidence_archives",
    }
}

#[cfg(test)]
mod tests {
    use crate::action::{ActorKind, AuthenticatedActor};
    use crate::audit::{
        validate_platform_audit_event_record, PlatformAuditError, PlatformAuditEventRecord,
        PLATFORM_AUDIT_REDACTION_PROFILE,
    };
    use crate::auth::{
        hash_bearer_credential_token, hash_session_token, AuthError, PlatformAuthSessionRecord,
        PlatformAuthSessionStatus, PlatformBearerCredentialKind, PlatformBearerCredentialRecord,
        PlatformBearerCredentialStatus, PlatformMtlsIdentityRecord, PlatformMtlsIdentityStatus,
    };
    use crate::identity::{
        hash_oidc_login_state, validate_oidc_login_attempt_record, OidcLoginAttemptRecord,
        OidcLoginAttemptStart, OidcLoginAttemptStatus, OidcValidationError,
    };
    use crate::postgres::{
        actor_kind_as_str, actor_kind_from_str, bearer_credential_hash_for_lookup,
        business_resource_table, mtls_subject_for_lookup, oidc_login_attempt_status_as_str,
        oidc_login_attempt_status_from_str, oidc_state_hash_for_lookup, project_scope,
        session_token_hash_for_lookup, validate_auth_session_record,
        validate_bearer_credential_record, validate_mtls_identity_record,
        validate_oidc_login_completion_record, validate_platform_resource_record,
        OidcLoginCompletionRecord, PlatformRepositoryError, ACCEPT_ORGANIZATION_INVITATION_SQL,
        ACTIVE_ROLE_BINDINGS_FOR_PRINCIPAL_SQL, BOOTSTRAP_SINGLE_USER_EXTERNAL_IDENTITY_SQL,
        BOOTSTRAP_SINGLE_USER_IDENTITY_PROVIDER_SQL,
        BOOTSTRAP_SINGLE_USER_ORGANIZATION_MEMBERSHIP_SQL, BOOTSTRAP_SINGLE_USER_ORGANIZATION_SQL,
        BOOTSTRAP_SINGLE_USER_PRINCIPAL_SQL, BOOTSTRAP_SINGLE_USER_PROJECT_MEMBERSHIP_SQL,
        BOOTSTRAP_SINGLE_USER_PROJECT_SQL, BOOTSTRAP_SINGLE_USER_ROLE_BINDING_SQL,
        BOOTSTRAP_SINGLE_USER_TENANT_SQL, BOOTSTRAP_SINGLE_USER_USER_SQL,
        CASCADE_PROJECT_MEMBERS_FOR_ORGANIZATION_MEMBER_SQL, CONSUME_OIDC_LOGIN_ATTEMPT_SQL,
        DELETE_ROLE_BINDINGS_FOR_ORGANIZATION_PRINCIPAL_SQL,
        DELETE_ROLE_BINDINGS_FOR_PROJECT_PRINCIPAL_SQL, DISABLE_AUTH_SESSIONS_FOR_PRINCIPAL_SQL,
        INSERT_ORGANIZATION_INVITATION_SQL, LIST_AUTH_SESSIONS_FOR_PRINCIPAL_SQL,
        LIST_EXTERNAL_IDENTITIES_FOR_PRINCIPAL_SQL, LIST_OIDC_LOGIN_PROVIDERS_SQL,
        LIST_ORGANIZATION_INVITATIONS_SQL, LIST_ORGANIZATION_MEMBERS_SQL,
        LIST_PLATFORM_AUDIT_EVENTS_FOR_TENANT_SQL, LIST_PLATFORM_USERS_SQL,
        LIST_PROJECT_MEMBERS_SQL, LIST_ROLE_BINDINGS_SQL, LIST_SECRET_REFS_SQL,
        RECORD_AUTH_SESSION_SQL, RECORD_BEARER_CREDENTIAL_SQL, RECORD_MTLS_IDENTITY_SQL,
        RECORD_OIDC_AUTH_SESSION_SQL, RECORD_OIDC_LOGIN_ATTEMPT_SQL,
        RECORD_PLATFORM_AUDIT_EVENT_SQL, RECORD_RESOURCE_OWNER_SQL, REVOKE_AUTH_SESSION_BY_ID_SQL,
        REVOKE_ORGANIZATION_INVITATION_SQL, SELECT_AUTH_SESSION_BY_ID_SQL,
        SELECT_AUTH_SESSION_BY_TOKEN_SQL, SELECT_BEARER_CREDENTIAL_BY_TOKEN_SQL,
        SELECT_EXTERNAL_IDENTITY_SQL, SELECT_MTLS_IDENTITY_BY_SUBJECT_SQL,
        SELECT_OIDC_LOGIN_ATTEMPT_BY_STATE_SQL, SELECT_OIDC_LOGIN_PROVIDER_SQL,
        SELECT_ORGANIZATION_INVITATION_BY_TOKEN_HASH_SQL, SELECT_ORGANIZATION_INVITATION_SQL,
        SELECT_ORGANIZATION_MEMBER_SQL, SELECT_PLATFORM_USER_INCLUDING_DELETED_SQL,
        SELECT_PLATFORM_USER_SQL, SELECT_PROJECT_MEMBER_SQL, SELECT_ROLE_BINDING_SQL,
        SELECT_SECRET_REF_SQL, UNLINK_EXTERNAL_IDENTITY_SQL, UPDATE_ORGANIZATION_MEMBER_STATUS_SQL,
        UPDATE_PLATFORM_USER_STATUS_SQL, UPDATE_PROJECT_MEMBER_STATUS_SQL,
        UPDATE_ROLE_BINDING_STATUS_SQL, UPSERT_INVITED_ORGANIZATION_MEMBER_SQL,
        UPSERT_INVITED_PROJECT_MEMBER_SQL, UPSERT_OIDC_EXTERNAL_IDENTITY_SQL,
        UPSERT_OIDC_LOGIN_PROVIDER_SQL, UPSERT_OIDC_ORGANIZATION_ADMIN_ROLE_SQL,
        UPSERT_OIDC_ORGANIZATION_MEMBERSHIP_SQL, UPSERT_OIDC_PROJECT_MEMBERSHIP_SQL,
        UPSERT_OIDC_USER_ORGANIZATION_SQL, UPSERT_OIDC_USER_PRINCIPAL_SQL,
        UPSERT_OIDC_USER_PROJECT_SQL, UPSERT_OIDC_USER_SQL, UPSERT_ROLE_BINDING_SQL,
        UPSERT_SECRET_REF_SQL,
    };
    use crate::resource::{
        ApprovalRecord, ConversationRecord, DeferredToolRecord, EnvironmentAttachmentRecord,
        EvidenceArchiveRecord, PlatformResourceData, PlatformResourceError, PlatformResourceRecord,
        RunRecord,
    };
    use crate::storage::{ResourceOwnerRecord, StoreError};

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const USER_ID: &str = "usr_test";
    const MTLS_SUBJECT: &str = "spiffe://platform.test/ns/default/sa/platform-worker";

    #[test]
    fn auth_queries_use_token_hashes_without_raw_material() {
        for query in [
            RECORD_AUTH_SESSION_SQL,
            SELECT_AUTH_SESSION_BY_TOKEN_SQL,
            LIST_AUTH_SESSIONS_FOR_PRINCIPAL_SQL,
            SELECT_AUTH_SESSION_BY_ID_SQL,
            REVOKE_AUTH_SESSION_BY_ID_SQL,
            RECORD_BEARER_CREDENTIAL_SQL,
            SELECT_BEARER_CREDENTIAL_BY_TOKEN_SQL,
            RECORD_MTLS_IDENTITY_SQL,
            SELECT_MTLS_IDENTITY_BY_SUBJECT_SQL,
        ] {
            let lower = query.to_ascii_lowercase();
            assert!(!lower.contains("raw_token"));
            assert!(!lower.contains("raw_bearer"));
            assert!(!lower.contains("raw_api_key"));
        }

        assert!(RECORD_AUTH_SESSION_SQL.contains("token_hash"));
        assert!(RECORD_BEARER_CREDENTIAL_SQL.contains("token_hash"));
        assert!(RECORD_AUTH_SESSION_SQL.contains("ON CONFLICT (auth_session_id)"));
        assert!(RECORD_BEARER_CREDENTIAL_SQL.contains("ON CONFLICT (credential_id)"));
        assert!(RECORD_MTLS_IDENTITY_SQL.contains("ON CONFLICT (mtls_identity_id)"));
        assert!(SELECT_MTLS_IDENTITY_BY_SUBJECT_SQL.contains("WHERE subject = $1"));
    }

    #[test]
    fn admin_user_and_session_queries_are_tenant_scoped_and_versioned() {
        for query in [
            LIST_PLATFORM_USERS_SQL,
            SELECT_PLATFORM_USER_SQL,
            SELECT_PLATFORM_USER_INCLUDING_DELETED_SQL,
            UPDATE_PLATFORM_USER_STATUS_SQL,
        ] {
            assert!(query.contains("platform_users"));
            assert!(query.contains("resource_version"));
        }
        assert!(LIST_PLATFORM_USERS_SQL.contains("WHERE tenant_id = $1"));
        assert!(LIST_PLATFORM_USERS_SQL.contains("status <> 'deleted'"));
        assert!(SELECT_PLATFORM_USER_SQL.contains("WHERE user_id = $1"));
        assert!(SELECT_PLATFORM_USER_SQL.contains("status <> 'deleted'"));
        assert!(!SELECT_PLATFORM_USER_INCLUDING_DELETED_SQL.contains("status <> 'deleted'"));
        assert!(UPDATE_PLATFORM_USER_STATUS_SQL.contains("resource_version = $3"));
        assert!(UPDATE_PLATFORM_USER_STATUS_SQL.contains("status <> 'deleted'"));

        assert!(LIST_AUTH_SESSIONS_FOR_PRINCIPAL_SQL.contains("WHERE tenant_id = $1"));
        assert!(LIST_AUTH_SESSIONS_FOR_PRINCIPAL_SQL.contains("principal_id = $2"));
        assert!(REVOKE_AUTH_SESSION_BY_ID_SQL.contains("auth_session_id = $1"));
        assert!(REVOKE_AUTH_SESSION_BY_ID_SQL.contains("tenant_id = $2"));
        assert!(REVOKE_AUTH_SESSION_BY_ID_SQL.contains("principal_id = $3"));
        assert!(REVOKE_AUTH_SESSION_BY_ID_SQL.contains("status = 'active'"));
        assert!(DISABLE_AUTH_SESSIONS_FOR_PRINCIPAL_SQL.contains("status = 'principal_disabled'"));
    }

    #[test]
    fn platform_audit_queries_store_redacted_envelopes_only() {
        for query in [
            RECORD_PLATFORM_AUDIT_EVENT_SQL,
            LIST_PLATFORM_AUDIT_EVENTS_FOR_TENANT_SQL,
        ] {
            assert!(query.contains("platform_audit_events"));
            assert!(query.contains("audit_event_id"));
            assert!(query.contains("actor_principal_id"));
            assert!(query.contains("action_id"));
            assert!(query.contains("resource_kind"));
            assert!(query.contains("resource_id"));
            assert!(query.contains("event_type"));
            assert!(query.contains("redaction"));

            let lower = query.to_ascii_lowercase();
            assert!(!lower.contains("raw_token"));
            assert!(!lower.contains("raw_bearer"));
            assert!(!lower.contains("raw_api_key"));
            assert!(!lower.contains("raw_password"));
            assert!(!lower.contains("client_secret"));
        }
        assert!(RECORD_PLATFORM_AUDIT_EVENT_SQL.contains("to_timestamp($13)"));
        assert!(LIST_PLATFORM_AUDIT_EVENTS_FOR_TENANT_SQL.contains("WHERE tenant_id = $1"));
    }

    #[test]
    fn oidc_login_attempt_queries_use_hashes_without_raw_material() {
        for query in [
            RECORD_OIDC_LOGIN_ATTEMPT_SQL,
            SELECT_OIDC_LOGIN_ATTEMPT_BY_STATE_SQL,
        ] {
            let lower = query.to_ascii_lowercase();
            assert!(!lower.contains("raw_state"));
            assert!(!lower.contains("raw_nonce"));
            assert!(!lower.contains("raw_pkce"));
            assert!(!lower.contains("state text"));
            assert!(!lower.contains("nonce text"));
            assert!(!lower.contains("pkce_verifier text"));
            assert!(!lower.contains("code_verifier text"));
        }

        assert!(RECORD_OIDC_LOGIN_ATTEMPT_SQL.contains("state_hash"));
        assert!(RECORD_OIDC_LOGIN_ATTEMPT_SQL.contains("nonce_hash"));
        assert!(RECORD_OIDC_LOGIN_ATTEMPT_SQL.contains("pkce_verifier_hash"));
        assert!(RECORD_OIDC_LOGIN_ATTEMPT_SQL.contains("ON CONFLICT (oidc_login_attempt_id)"));
        assert!(SELECT_OIDC_LOGIN_ATTEMPT_BY_STATE_SQL.contains("WHERE state_hash = $1"));
    }

    #[test]
    fn oidc_login_provider_query_supports_discovery_and_secret_refs() {
        for query in [
            SELECT_OIDC_LOGIN_PROVIDER_SQL,
            LIST_OIDC_LOGIN_PROVIDERS_SQL,
            UPSERT_OIDC_LOGIN_PROVIDER_SQL,
        ] {
            assert!(query.contains("provider_kind = 'oidc'") || query.contains("'oidc'"));
            assert!(query.contains("token_endpoint_auth_method"));
            assert!(query.contains("client_secret_ref"));
            assert!(query.contains("requested_scopes"));
            assert!(query.contains("oidc_audiences"));
            assert!(!query.contains("client_secret "));
            assert!(!query.contains("raw_secret"));
        }
        assert!(SELECT_OIDC_LOGIN_PROVIDER_SQL.contains("COALESCE(authorization_endpoint, '')"));
        assert!(SELECT_OIDC_LOGIN_PROVIDER_SQL.contains("COALESCE(token_endpoint, '')"));
        assert!(SELECT_OIDC_LOGIN_PROVIDER_SQL.contains("COALESCE(jwks_uri, '')"));
    }

    #[test]
    fn secret_ref_queries_store_safe_metadata_only() {
        for query in [
            UPSERT_SECRET_REF_SQL,
            SELECT_SECRET_REF_SQL,
            LIST_SECRET_REFS_SQL,
        ] {
            assert!(query.contains("secret_ref_id"));
            assert!(query.contains("backend_locator"));
            assert!(query.contains("display_mask"));
            assert!(query.contains("fingerprint"));
            assert!(!query.contains("secret_value"));
            assert!(!query.contains("raw_secret"));
        }
        assert!(UPSERT_SECRET_REF_SQL.contains("ON CONFLICT (secret_ref_id)"));
    }

    #[test]
    fn external_identity_queries_are_tenant_scoped_and_token_free() {
        for query in [
            LIST_EXTERNAL_IDENTITIES_FOR_PRINCIPAL_SQL,
            SELECT_EXTERNAL_IDENTITY_SQL,
            UNLINK_EXTERNAL_IDENTITY_SQL,
        ] {
            assert!(query.contains("platform_external_identities"));
            assert!(query.contains("external_identity_id"));
            assert!(query.contains("identity_provider_id"));
            assert!(query.contains("provider_subject"));
            assert!(query.contains("status <> 'deleted'"));
            assert!(!query.contains("access_token"));
            assert!(!query.contains("refresh_token"));
            assert!(!query.contains("id_token"));
            assert!(!query.contains("client_secret"));
        }
        assert!(LIST_EXTERNAL_IDENTITIES_FOR_PRINCIPAL_SQL.contains("tenant_id = $1"));
        assert!(LIST_EXTERNAL_IDENTITIES_FOR_PRINCIPAL_SQL.contains("principal_id = $2"));
        assert!(UNLINK_EXTERNAL_IDENTITY_SQL.contains("status = 'deleted'"));
        assert!(UNLINK_EXTERNAL_IDENTITY_SQL.contains("RETURNING"));
    }

    #[test]
    fn role_binding_queries_support_dynamic_authorization_and_cascade() {
        for query in [
            LIST_ROLE_BINDINGS_SQL,
            ACTIVE_ROLE_BINDINGS_FOR_PRINCIPAL_SQL,
            SELECT_ROLE_BINDING_SQL,
            UPSERT_ROLE_BINDING_SQL,
            UPDATE_ROLE_BINDING_STATUS_SQL,
        ] {
            assert!(query.contains("platform_role_bindings"));
            assert!(query.contains("role_binding_id"));
            assert!(query.contains("principal_id"));
            assert!(query.contains("role_id"));
            assert!(query.contains("resource_version"));
        }
        assert!(ACTIVE_ROLE_BINDINGS_FOR_PRINCIPAL_SQL.contains("status = 'active'"));
        assert!(SELECT_ROLE_BINDING_SQL.contains("status <> 'deleted'"));
        assert!(UPSERT_ROLE_BINDING_SQL.contains("ON CONFLICT (role_binding_id)"));
        assert!(UPDATE_ROLE_BINDING_STATUS_SQL.contains("resource_version = $3"));
        assert!(
            DELETE_ROLE_BINDINGS_FOR_ORGANIZATION_PRINCIPAL_SQL.contains("organization_id = $2")
        );
        assert!(DELETE_ROLE_BINDINGS_FOR_PROJECT_PRINCIPAL_SQL.contains("project_id = $2"));
        assert!(DELETE_ROLE_BINDINGS_FOR_ORGANIZATION_PRINCIPAL_SQL.contains("status = 'deleted'"));
        assert!(DELETE_ROLE_BINDINGS_FOR_PROJECT_PRINCIPAL_SQL.contains("status = 'deleted'"));
    }

    #[test]
    fn membership_queries_support_status_update_and_cascade() {
        for query in [
            LIST_ORGANIZATION_MEMBERS_SQL,
            SELECT_ORGANIZATION_MEMBER_SQL,
            UPDATE_ORGANIZATION_MEMBER_STATUS_SQL,
        ] {
            assert!(query.contains("platform_organization_memberships"));
            assert!(query.contains("organization_member_id"));
            assert!(query.contains("resource_version"));
        }
        for query in [
            LIST_PROJECT_MEMBERS_SQL,
            SELECT_PROJECT_MEMBER_SQL,
            UPDATE_PROJECT_MEMBER_STATUS_SQL,
            CASCADE_PROJECT_MEMBERS_FOR_ORGANIZATION_MEMBER_SQL,
        ] {
            assert!(query.contains("platform_project_memberships"));
            assert!(query.contains("project_member_id"));
            assert!(query.contains("resource_version"));
        }
        assert!(UPDATE_ORGANIZATION_MEMBER_STATUS_SQL.contains("resource_version = $3"));
        assert!(UPDATE_PROJECT_MEMBER_STATUS_SQL.contains("resource_version = $3"));
        assert!(CASCADE_PROJECT_MEMBERS_FOR_ORGANIZATION_MEMBER_SQL.contains("status = 'active'"));
        assert!(CASCADE_PROJECT_MEMBERS_FOR_ORGANIZATION_MEMBER_SQL.contains("status <> 'removed'"));
    }

    #[test]
    fn organization_invitation_queries_store_hash_only_and_upsert_memberships() {
        for query in [
            INSERT_ORGANIZATION_INVITATION_SQL,
            LIST_ORGANIZATION_INVITATIONS_SQL,
            SELECT_ORGANIZATION_INVITATION_SQL,
            SELECT_ORGANIZATION_INVITATION_BY_TOKEN_HASH_SQL,
            REVOKE_ORGANIZATION_INVITATION_SQL,
            ACCEPT_ORGANIZATION_INVITATION_SQL,
        ] {
            assert!(query.contains("platform_organization_invitations"));
            assert!(query.contains("invitation_token_hash"));
            assert!(!query.contains("raw_token"));
            assert!(!query.contains("invitation_token text"));
        }
        assert!(SELECT_ORGANIZATION_INVITATION_BY_TOKEN_HASH_SQL
            .contains("WHERE invitation_token_hash = $1"));
        assert!(REVOKE_ORGANIZATION_INVITATION_SQL.contains("resource_version = $2"));
        assert!(REVOKE_ORGANIZATION_INVITATION_SQL.contains("status = 'pending'"));
        assert!(ACCEPT_ORGANIZATION_INVITATION_SQL.contains("accepted_at = to_timestamp($2)"));
        assert!(UPSERT_INVITED_ORGANIZATION_MEMBER_SQL
            .contains("ON CONFLICT (organization_id, principal_id)"));
        assert!(
            UPSERT_INVITED_PROJECT_MEMBER_SQL.contains("ON CONFLICT (project_id, principal_id)")
        );
        assert!(UPSERT_INVITED_PROJECT_MEMBER_SQL.contains("organization_member_id"));
    }

    #[test]
    fn oidc_login_completion_queries_are_replay_safe_and_subject_bound() {
        assert!(CONSUME_OIDC_LOGIN_ATTEMPT_SQL.contains("status = 'active'"));
        assert!(CONSUME_OIDC_LOGIN_ATTEMPT_SQL.contains("expires_at > now()"));
        assert!(CONSUME_OIDC_LOGIN_ATTEMPT_SQL.contains("identity_provider_id = $4"));

        assert!(UPSERT_OIDC_EXTERNAL_IDENTITY_SQL
            .contains("ON CONFLICT (tenant_id, identity_provider_id, provider_subject)"));
        assert!(UPSERT_OIDC_EXTERNAL_IDENTITY_SQL
            .contains("WHERE platform_external_identities.principal_id = EXCLUDED.principal_id"));
        assert!(!UPSERT_OIDC_EXTERNAL_IDENTITY_SQL.contains("raw_token"));
        assert!(!UPSERT_OIDC_EXTERNAL_IDENTITY_SQL.contains("id_token"));

        for query in [
            UPSERT_OIDC_USER_ORGANIZATION_SQL,
            UPSERT_OIDC_USER_PROJECT_SQL,
            UPSERT_OIDC_USER_PRINCIPAL_SQL,
            UPSERT_OIDC_USER_SQL,
            UPSERT_OIDC_ORGANIZATION_MEMBERSHIP_SQL,
            UPSERT_OIDC_PROJECT_MEMBERSHIP_SQL,
            UPSERT_OIDC_ORGANIZATION_ADMIN_ROLE_SQL,
            RECORD_OIDC_AUTH_SESSION_SQL,
        ] {
            assert!(
                query.contains("ON CONFLICT"),
                "OIDC completion query should be idempotent: {query}"
            );
            assert!(!query.to_ascii_lowercase().contains("raw_token"));
        }
        assert!(UPSERT_OIDC_ORGANIZATION_ADMIN_ROLE_SQL.contains("role_id"));
        assert!(RECORD_OIDC_AUTH_SESSION_SQL.contains("identity_provider_id"));
        assert!(RECORD_OIDC_AUTH_SESSION_SQL.contains("token_hash"));
    }

    #[test]
    fn owner_query_uses_kind_and_id_as_durable_key() {
        assert!(RECORD_RESOURCE_OWNER_SQL.contains("resource_kind"));
        assert!(RECORD_RESOURCE_OWNER_SQL.contains("resource_id"));
        assert!(RECORD_RESOURCE_OWNER_SQL.contains("ON CONFLICT (resource_kind, resource_id)"));
    }

    #[test]
    fn single_user_bootstrap_repairs_required_durable_rows() {
        let bootstrap_queries = [
            (BOOTSTRAP_SINGLE_USER_TENANT_SQL, "platform_tenants"),
            (
                BOOTSTRAP_SINGLE_USER_ORGANIZATION_SQL,
                "platform_organizations",
            ),
            (BOOTSTRAP_SINGLE_USER_PROJECT_SQL, "platform_projects"),
            (BOOTSTRAP_SINGLE_USER_PRINCIPAL_SQL, "platform_principals"),
            (BOOTSTRAP_SINGLE_USER_USER_SQL, "platform_users"),
            (
                BOOTSTRAP_SINGLE_USER_ORGANIZATION_MEMBERSHIP_SQL,
                "platform_organization_memberships",
            ),
            (
                BOOTSTRAP_SINGLE_USER_PROJECT_MEMBERSHIP_SQL,
                "platform_project_memberships",
            ),
            (
                BOOTSTRAP_SINGLE_USER_IDENTITY_PROVIDER_SQL,
                "platform_identity_providers",
            ),
            (
                BOOTSTRAP_SINGLE_USER_EXTERNAL_IDENTITY_SQL,
                "platform_external_identities",
            ),
            (
                BOOTSTRAP_SINGLE_USER_ROLE_BINDING_SQL,
                "platform_role_bindings",
            ),
        ];

        for (query, table) in bootstrap_queries {
            assert!(query.contains(table), "{table} should be bootstrapped");
            assert!(
                query.contains("ON CONFLICT"),
                "{table} should be idempotent"
            );
            assert!(
                query.contains("status = 'active'"),
                "{table} should be repaired active"
            );
        }
        assert!(BOOTSTRAP_SINGLE_USER_IDENTITY_PROVIDER_SQL.contains("'single_user'"));
        assert!(BOOTSTRAP_SINGLE_USER_ROLE_BINDING_SQL.contains("role_id"));
    }

    #[test]
    fn bearer_lookup_hashes_match_auth_store_boundaries() {
        assert_eq!(
            session_token_hash_for_lookup("  session-token  "),
            Ok(hash_session_token("session-token"))
        );
        assert_eq!(
            bearer_credential_hash_for_lookup("  api-key-token  "),
            Ok(hash_bearer_credential_token("api-key-token"))
        );
        assert_eq!(
            session_token_hash_for_lookup(" "),
            Err(PlatformRepositoryError::Auth(AuthError::EmptyBearerToken))
        );
        assert_eq!(
            mtls_subject_for_lookup("  spiffe://platform.test/workload  "),
            Ok("spiffe://platform.test/workload".to_owned())
        );
        assert_eq!(
            mtls_subject_for_lookup(" "),
            Err(PlatformRepositoryError::Auth(AuthError::EmptyMtlsSubject))
        );
        assert_eq!(
            oidc_state_hash_for_lookup("  state-token  "),
            Ok(hash_oidc_login_state("state-token"))
        );
        assert_eq!(
            oidc_state_hash_for_lookup(" "),
            Err(PlatformRepositoryError::Identity(
                OidcValidationError::EmptyState
            ))
        );
    }

    #[test]
    fn actor_kind_mapping_matches_platform_actor_contract() {
        assert_eq!(actor_kind_as_str(ActorKind::User), "user");
        assert_eq!(
            actor_kind_as_str(ActorKind::ServiceAccount),
            "service_account"
        );
        assert_eq!(actor_kind_as_str(ActorKind::System), "system");
        assert_eq!(actor_kind_from_str("user"), Ok(ActorKind::User));
        assert_eq!(
            actor_kind_from_str("service_account"),
            Ok(ActorKind::ServiceAccount)
        );
        assert_eq!(
            actor_kind_from_str("unknown"),
            Err(PlatformRepositoryError::UnknownActorKind(
                "unknown".to_owned()
            ))
        );
        assert_eq!(
            oidc_login_attempt_status_as_str(OidcLoginAttemptStatus::Active),
            "active"
        );
        assert_eq!(
            oidc_login_attempt_status_from_str("consumed"),
            Ok(OidcLoginAttemptStatus::Consumed)
        );
        assert_eq!(
            oidc_login_attempt_status_from_str("unknown"),
            Err(PlatformRepositoryError::UnknownOidcLoginAttemptStatus(
                "unknown".to_owned()
            ))
        );
    }

    #[test]
    fn durable_validation_matches_in_memory_auth_shape() {
        let test_actor = actor();
        assert_eq!(
            validate_auth_session_record(&PlatformAuthSessionRecord::active(
                "sess_test",
                "raw-session",
                test_actor.clone(),
            )),
            Ok(())
        );
        assert_eq!(
            validate_bearer_credential_record(&PlatformBearerCredentialRecord::active(
                "apikey_test",
                PlatformBearerCredentialKind::ApiKey,
                "raw-api-key",
                test_actor,
            )),
            Ok(())
        );
        assert_eq!(
            validate_auth_session_record(&PlatformAuthSessionRecord {
                session_id: String::new(),
                token_hash: "hash".to_owned(),
                actor: actor(),
                status: PlatformAuthSessionStatus::Active,
            }),
            Err(PlatformRepositoryError::Auth(AuthError::EmptySessionId))
        );
        assert_eq!(
            validate_bearer_credential_record(&PlatformBearerCredentialRecord {
                credential_id: String::new(),
                credential_kind: PlatformBearerCredentialKind::ServiceToken,
                token_hash: "hash".to_owned(),
                actor: actor(),
                status: PlatformBearerCredentialStatus::Active,
            }),
            Err(PlatformRepositoryError::Auth(AuthError::EmptyCredentialId))
        );
        assert_eq!(
            validate_mtls_identity_record(&PlatformMtlsIdentityRecord::active(
                "mtls_test",
                MTLS_SUBJECT,
                actor(),
            )),
            Ok(())
        );
        assert_eq!(
            validate_mtls_identity_record(&PlatformMtlsIdentityRecord {
                identity_id: String::new(),
                subject: MTLS_SUBJECT.to_owned(),
                actor: actor(),
                status: PlatformMtlsIdentityStatus::Active,
            }),
            Err(PlatformRepositoryError::Auth(
                AuthError::EmptyMtlsIdentityId
            ))
        );
        assert_eq!(
            validate_oidc_login_attempt_record(&valid_oidc_attempt()),
            Ok(())
        );
        assert_eq!(
            validate_oidc_login_attempt_record(&OidcLoginAttemptRecord {
                login_attempt_id: String::new(),
                ..valid_oidc_attempt()
            }),
            Err(OidcValidationError::InvalidLoginAttemptId)
        );
        assert_eq!(
            validate_oidc_login_completion_record(&valid_oidc_completion()),
            Ok(())
        );
        assert_eq!(
            validate_oidc_login_completion_record(&OidcLoginCompletionRecord {
                provider_subject: String::new(),
                ..valid_oidc_completion()
            }),
            Err(PlatformRepositoryError::Identity(
                OidcValidationError::SubjectRequired
            ))
        );
        assert_eq!(
            validate_oidc_login_completion_record(&OidcLoginCompletionRecord {
                session: PlatformAuthSessionRecord::active(
                    "sess_oidc",
                    "raw-session",
                    AuthenticatedActor::project_user(
                        TENANT_ID,
                        ORGANIZATION_ID,
                        PROJECT_ID,
                        "usr_other"
                    ),
                ),
                ..valid_oidc_completion()
            }),
            Err(PlatformRepositoryError::OidcSessionActorMismatch(
                "sess_oidc".to_owned()
            ))
        );
    }

    #[test]
    fn durable_validation_matches_in_memory_audit_shape() {
        assert_eq!(
            validate_platform_audit_event_record(&valid_audit_event()),
            Ok(())
        );
        assert_eq!(
            validate_platform_audit_event_record(&PlatformAuditEventRecord {
                audit_event_id: "evt_invalid".to_owned(),
                ..valid_audit_event()
            }),
            Err(PlatformAuditError::InvalidAuditEventId)
        );
    }

    #[test]
    fn business_resource_tables_cover_every_safe_projection() {
        for (data, table) in [
            (
                PlatformResourceData::Conversation(ConversationRecord {
                    title: "Test".to_owned(),
                    status: "active".to_owned(),
                }),
                "platform_conversations",
            ),
            (
                PlatformResourceData::Run(RunRecord {
                    conversation_id: "conv_test".to_owned(),
                    status: "running".to_owned(),
                    model_alias: "default-agent".to_owned(),
                }),
                "platform_runs",
            ),
            (
                PlatformResourceData::Approval(ApprovalRecord {
                    run_id: "run_test".to_owned(),
                    status: "pending".to_owned(),
                    requested_action: "tool.execute".to_owned(),
                }),
                "platform_approvals",
            ),
            (
                PlatformResourceData::DeferredTool(DeferredToolRecord {
                    run_id: "run_test".to_owned(),
                    tool_name: "shell".to_owned(),
                    status: "pending".to_owned(),
                }),
                "platform_deferred_tools",
            ),
            (
                PlatformResourceData::EnvironmentAttachment(EnvironmentAttachmentRecord {
                    lease_id: "lease_test".to_owned(),
                    status: "ready".to_owned(),
                    readiness: "ok".to_owned(),
                }),
                "platform_environment_attachments",
            ),
            (
                PlatformResourceData::EvidenceArchive(EvidenceArchiveRecord {
                    manifest_uri: "s3://archives/run_test/manifest.json".to_owned(),
                    retention_class: "standard".to_owned(),
                    debug_available: false,
                }),
                "platform_evidence_archives",
            ),
        ] {
            assert_eq!(business_resource_table(&data), table);
        }
    }

    #[test]
    fn business_resource_validation_keeps_owner_and_projection_aligned() {
        let record = PlatformResourceRecord {
            owner: ResourceOwnerRecord::project(
                "Run",
                "run_test",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            ),
            data: PlatformResourceData::Run(RunRecord {
                conversation_id: "conv_test".to_owned(),
                status: "running".to_owned(),
                model_alias: "default-agent".to_owned(),
            }),
        };
        assert_eq!(validate_platform_resource_record(&record), Ok(()));
        assert_eq!(
            project_scope(&record.owner),
            Ok((ORGANIZATION_ID, PROJECT_ID))
        );

        let mismatch = PlatformResourceRecord {
            owner: ResourceOwnerRecord::project(
                "Conversation",
                "run_test",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            ),
            data: record.data,
        };
        assert_eq!(
            validate_platform_resource_record(&mismatch),
            Err(PlatformRepositoryError::Resource(
                PlatformResourceError::ResourceKindMismatch
            ))
        );
    }

    #[test]
    fn business_resource_writes_require_project_scope() {
        let owner = ResourceOwnerRecord::tenant("Run", "run_test", TENANT_ID);
        assert_eq!(
            project_scope(&owner),
            Err(PlatformRepositoryError::ProjectScopeRequired(
                "Run".to_owned()
            ))
        );
    }

    #[test]
    fn owner_validation_rejects_invalid_scope_shape() {
        let owner = ResourceOwnerRecord {
            resource_kind: "Run".to_owned(),
            resource_id: "run_test".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: None,
            project_id: Some(PROJECT_ID.to_owned()),
        };
        assert_eq!(
            validate_platform_resource_record(&PlatformResourceRecord {
                owner,
                data: PlatformResourceData::Run(RunRecord {
                    conversation_id: "conv_test".to_owned(),
                    status: "running".to_owned(),
                    model_alias: "default-agent".to_owned(),
                }),
            }),
            Err(PlatformRepositoryError::Store(
                StoreError::ProjectWithoutOrganization
            ))
        );
    }

    fn actor() -> AuthenticatedActor {
        AuthenticatedActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID)
    }

    fn valid_oidc_attempt() -> OidcLoginAttemptRecord {
        OidcLoginAttemptRecord::active(OidcLoginAttemptStart {
            login_attempt_id: "ola_test".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            identity_provider_id: "idp_oidc".to_owned(),
            raw_state: "state_secret".to_owned(),
            raw_nonce: "nonce_secret".to_owned(),
            raw_pkce_verifier: "pkce_secret".to_owned(),
            redirect_uri: "https://app.example/auth/oidc/callback".to_owned(),
            expires_at_unix: 1_750_000_000,
        })
        .unwrap_or_else(|error| panic!("valid OIDC attempt should build: {error}"))
    }

    fn valid_oidc_completion() -> OidcLoginCompletionRecord {
        OidcLoginCompletionRecord {
            login_attempt_id: "ola_test".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: ORGANIZATION_ID.to_owned(),
            project_id: PROJECT_ID.to_owned(),
            user_id: USER_ID.to_owned(),
            identity_provider_id: "idp_oidc".to_owned(),
            external_identity_id: "xid_oidc_user".to_owned(),
            organization_member_id: "om_oidc_user".to_owned(),
            project_member_id: "pm_oidc_user".to_owned(),
            organization_role_binding_id: "rb_oidc_org_admin".to_owned(),
            provider_subject: "provider-subject".to_owned(),
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            user_display_name: "OIDC User".to_owned(),
            organization_display_name: "OIDC User Organization".to_owned(),
            project_display_name: "OIDC User Project".to_owned(),
            session: PlatformAuthSessionRecord::active("sess_oidc", "raw-session", actor()),
            consumed_at_unix: 1_750_000_001,
        }
    }

    fn valid_audit_event() -> PlatformAuditEventRecord {
        PlatformAuditEventRecord {
            audit_event_id: "audit_test".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: Some(ORGANIZATION_ID.to_owned()),
            project_id: Some(PROJECT_ID.to_owned()),
            actor_principal_id: USER_ID.to_owned(),
            actor_kind: ActorKind::User,
            action_id: "platform.user.write".to_owned(),
            resource_kind: "User".to_owned(),
            resource_id: "usr_target".to_owned(),
            event_type: "platform.user.status.update".to_owned(),
            reason: Some("Operator confirmed request.".to_owned()),
            redaction: PLATFORM_AUDIT_REDACTION_PROFILE.to_owned(),
            created_at_unix: 1_700_000_000,
        }
    }
}
