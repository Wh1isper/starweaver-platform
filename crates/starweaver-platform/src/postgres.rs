//! PostgreSQL repository adapters for platform durable state.

use std::fmt::{Display, Formatter};

use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};

use crate::action::{ActorKind, AuthenticatedActor};
use crate::auth::{
    hash_bearer_credential_token, hash_session_token, AuthError, PlatformAuthSessionRecord,
    PlatformBearerCredentialRecord, PlatformMtlsIdentityRecord,
};
use crate::resource::{
    ApprovalRecord, ConversationRecord, DeferredToolRecord, EnvironmentAttachmentRecord,
    EvidenceArchiveRecord, PlatformResourceData, PlatformResourceError, PlatformResourceRecord,
    RunRecord,
};
use crate::storage::{ResourceOwnerRecord, StoreError};

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
    /// Resource ownership validation failed.
    Store(StoreError),
    /// Business resource validation failed.
    Resource(PlatformResourceError),
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
    /// Business resource requires project scope but owner metadata is not project-scoped.
    ProjectScopeRequired(String),
}

impl PlatformRepositoryError {
    /// Returns a stable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Auth(error) => error.as_str(),
            Self::Store(error) => error.as_str(),
            Self::Resource(error) => error.as_str(),
            Self::Database(_) => "database_error",
            Self::UnknownActorKind(_) => "unknown_actor_kind",
            Self::UnknownSessionStatus(_) => "unknown_session_status",
            Self::UnknownCredentialStatus(_) => "unknown_credential_status",
            Self::UnknownMtlsIdentityStatus(_) => "unknown_mtls_identity_status",
            Self::ProjectScopeRequired(_) => "project_scope_required",
        }
    }
}

impl Display for PlatformRepositoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auth(error) => write!(formatter, "authentication repository error: {error:?}"),
            Self::Store(error) => write!(formatter, "resource owner repository error: {error:?}"),
            Self::Resource(error) => {
                write!(formatter, "business resource repository error: {error:?}")
            }
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

/// PostgreSQL-backed repository adapter for platform durable state.
#[derive(Clone, Debug)]
pub struct PostgresPlatformRepository {
    pool: PgPool,
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
    use crate::auth::{
        hash_bearer_credential_token, hash_session_token, AuthError, PlatformAuthSessionRecord,
        PlatformAuthSessionStatus, PlatformBearerCredentialKind, PlatformBearerCredentialRecord,
        PlatformBearerCredentialStatus, PlatformMtlsIdentityRecord, PlatformMtlsIdentityStatus,
    };
    use crate::postgres::{
        actor_kind_as_str, actor_kind_from_str, bearer_credential_hash_for_lookup,
        business_resource_table, mtls_subject_for_lookup, project_scope,
        session_token_hash_for_lookup, validate_auth_session_record,
        validate_bearer_credential_record, validate_mtls_identity_record,
        validate_platform_resource_record, PlatformRepositoryError, RECORD_AUTH_SESSION_SQL,
        RECORD_BEARER_CREDENTIAL_SQL, RECORD_MTLS_IDENTITY_SQL, RECORD_RESOURCE_OWNER_SQL,
        SELECT_AUTH_SESSION_BY_TOKEN_SQL, SELECT_BEARER_CREDENTIAL_BY_TOKEN_SQL,
        SELECT_MTLS_IDENTITY_BY_SUBJECT_SQL,
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
    fn owner_query_uses_kind_and_id_as_durable_key() {
        assert!(RECORD_RESOURCE_OWNER_SQL.contains("resource_kind"));
        assert!(RECORD_RESOURCE_OWNER_SQL.contains("resource_id"));
        assert!(RECORD_RESOURCE_OWNER_SQL.contains("ON CONFLICT (resource_kind, resource_id)"));
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
}
