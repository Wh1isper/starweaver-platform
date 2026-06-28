//! Gateway domain identifiers and resource shapes.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::ProtocolFamily;

/// Tenant identifier.
pub type TenantId = String;

/// Organization identifier.
pub type OrganizationId = String;

/// Project identifier.
pub type ProjectId = String;

/// Principal identifier for users, service accounts, internal services, or system actors.
pub type PrincipalId = String;

/// User identifier.
pub type UserId = String;

/// API key identifier.
pub type ApiKeyId = String;

/// Auth session identifier.
pub type AuthSessionId = String;

/// Stable config snapshot identifier.
pub type ConfigSnapshotId = String;

/// Organization membership identifier.
pub type OrganizationMemberId = String;

/// Project membership identifier.
pub type ProjectMemberId = String;

/// Gateway request identifier.
pub type RequestId = String;

/// Gateway distributed trace identifier.
pub type TraceId = String;

/// Directory resource lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryStatus {
    /// Resource can be used.
    Active,
    /// Resource is temporarily suspended.
    Suspended,
    /// Resource is administratively disabled.
    Disabled,
    /// Resource was soft-deleted.
    Deleted,
}

impl DirectoryStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    /// Returns whether this directory resource can participate in access.
    #[must_use]
    pub const fn accepts_access(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Actor kind resolved after authentication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// Human user principal.
    User,
    /// Service account principal.
    ServiceAccount,
    /// API key credential actor.
    ApiKey,
    /// Trusted internal service actor.
    InternalService,
    /// System task actor.
    System,
}

impl ActorKind {
    /// Returns the stable actor kind id used by audit evidence.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::ServiceAccount => "service_account",
            Self::ApiKey => "api_key",
            Self::InternalService => "internal_service",
            Self::System => "system",
        }
    }
}

/// Credential kind used to authenticate a gateway request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Bearer-style API key.
    ApiKey,
    /// Server-side human session.
    Session,
    /// Structured service token.
    ServiceToken,
    /// mTLS subject from a trusted ingress proxy.
    MtlsSubject,
    /// Internal service identity.
    InternalService,
    /// System task identity.
    System,
}

/// API key lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyStatus {
    /// Key can authenticate requests.
    Active,
    /// Key is administratively disabled.
    Disabled,
    /// Key is past its expiry.
    Expired,
    /// Key is in a rotation window.
    Rotating,
    /// Key was soft-deleted.
    Deleted,
}

impl ApiKeyStatus {
    /// Returns whether this status can authenticate a presented secret.
    #[must_use]
    pub const fn accepts_authentication(&self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

/// Server-side auth session lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthSessionStatus {
    /// Session can authenticate requests.
    Active,
    /// Session was explicitly revoked.
    Revoked,
    /// Session is past its expiry.
    Expired,
}

impl AuthSessionStatus {
    /// Returns whether this status can authenticate a presented session token.
    #[must_use]
    pub const fn accepts_authentication(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Organization or project membership lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipStatus {
    /// Membership can access scoped resources.
    Active,
    /// Membership is temporarily suspended.
    Suspended,
    /// Membership was removed.
    Removed,
}

/// Organization invitation lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InvitationStatus {
    /// Invitation can be accepted before expiry.
    Pending,
    /// Invitation was accepted and cannot be reused.
    Accepted,
    /// Invitation was revoked before acceptance.
    Revoked,
    /// Invitation is past its expiry.
    Expired,
}

impl InvitationStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    /// Returns whether the invitation can still be accepted at `now`.
    #[must_use]
    pub fn accepts_at(&self, expires_at: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        matches!(self, Self::Pending) && expires_at > now
    }
}

impl MembershipStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }

    /// Returns whether the membership can access scoped resources.
    #[must_use]
    pub const fn accepts_access(&self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Authenticated actor context written into runtime and audit evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticatedActor {
    /// Stable actor id for audit.
    pub actor_id: String,
    /// Kind of actor.
    pub actor_kind: ActorKind,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Owning principal when present.
    pub principal_id: Option<PrincipalId>,
    /// API key used for authentication when present.
    pub api_key_id: Option<ApiKeyId>,
    /// Credential kind used for authentication.
    pub credential_kind: CredentialKind,
    /// Relative auth strength for sensitive actions.
    pub auth_strength: u8,
    /// Credential expiry when present.
    pub expires_at: Option<DateTime<Utc>>,
    /// API key action prefilter when an API key authenticated the request.
    pub api_key_allowed_actions: Vec<String>,
    /// API key resource prefilter when an API key authenticated the request.
    pub api_key_allowed_resources: Vec<String>,
    /// Gateway request id.
    pub request_id: RequestId,
    /// Gateway trace id.
    pub trace_id: TraceId,
}

/// Tenant, organization, and project scope resolved for an actor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActorScope {
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
}

impl ActorScope {
    /// Creates a scoped actor boundary.
    #[must_use]
    pub fn new(
        tenant_id: impl Into<String>,
        organization_id: Option<impl Into<String>>,
        project_id: Option<impl Into<String>>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            organization_id: organization_id.map(Into::into),
            project_id: project_id.map(Into::into),
        }
    }

    /// Creates a scope from a project membership record.
    #[must_use]
    pub fn from_project_membership(membership: &ProjectMembershipRecord) -> Self {
        Self {
            tenant_id: membership.tenant_id.clone(),
            organization_id: Some(membership.organization_id.clone()),
            project_id: Some(membership.project_id.clone()),
        }
    }
}

impl AuthenticatedActor {
    /// Builds an actor for a verified API key.
    #[must_use]
    pub fn for_api_key(record: &ApiKeyRecord, request_id: RequestId, trace_id: TraceId) -> Self {
        Self {
            actor_id: record.api_key_id.clone(),
            actor_kind: ActorKind::ApiKey,
            tenant_id: record.tenant_id.clone(),
            organization_id: record.organization_id.clone(),
            project_id: record.project_id.clone(),
            principal_id: Some(record.owner_principal_id.clone()),
            api_key_id: Some(record.api_key_id.clone()),
            credential_kind: CredentialKind::ApiKey,
            auth_strength: 50,
            expires_at: record.expires_at,
            api_key_allowed_actions: record.allowed_actions.clone(),
            api_key_allowed_resources: record.allowed_resources.clone(),
            request_id,
            trace_id,
        }
    }

    /// Builds an actor for an opaque server-side session.
    #[must_use]
    pub fn for_user_session(
        scope: ActorScope,
        principal_id: PrincipalId,
        session_id: String,
        request_id: RequestId,
        trace_id: TraceId,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            actor_id: session_id,
            actor_kind: ActorKind::User,
            tenant_id: scope.tenant_id,
            organization_id: scope.organization_id,
            project_id: scope.project_id,
            principal_id: Some(principal_id),
            api_key_id: None,
            credential_kind: CredentialKind::Session,
            auth_strength: 80,
            expires_at,
            api_key_allowed_actions: Vec::new(),
            api_key_allowed_resources: Vec::new(),
            request_id,
            trace_id,
        }
    }

    /// Builds an actor for a service account token.
    #[must_use]
    pub fn for_service_account(
        scope: ActorScope,
        service_account_id: PrincipalId,
        request_id: RequestId,
        trace_id: TraceId,
    ) -> Self {
        Self {
            actor_id: service_account_id.clone(),
            actor_kind: ActorKind::ServiceAccount,
            tenant_id: scope.tenant_id,
            organization_id: scope.organization_id,
            project_id: scope.project_id,
            principal_id: Some(service_account_id),
            api_key_id: None,
            credential_kind: CredentialKind::ServiceToken,
            auth_strength: 70,
            expires_at: None,
            api_key_allowed_actions: Vec::new(),
            api_key_allowed_resources: Vec::new(),
            request_id,
            trace_id,
        }
    }

    /// Builds an actor for a trusted internal service identity.
    #[must_use]
    pub fn for_internal_service(
        tenant_id: TenantId,
        service_name: impl Into<String>,
        request_id: RequestId,
        trace_id: TraceId,
    ) -> Self {
        Self {
            actor_id: service_name.into(),
            actor_kind: ActorKind::InternalService,
            tenant_id,
            organization_id: None,
            project_id: None,
            principal_id: None,
            api_key_id: None,
            credential_kind: CredentialKind::InternalService,
            auth_strength: 90,
            expires_at: None,
            api_key_allowed_actions: Vec::new(),
            api_key_allowed_resources: Vec::new(),
            request_id,
            trace_id,
        }
    }

    /// Builds an actor for a system task.
    #[must_use]
    pub fn for_system_task(
        tenant_id: TenantId,
        task_id: impl Into<String>,
        request_id: RequestId,
        trace_id: TraceId,
    ) -> Self {
        Self {
            actor_id: task_id.into(),
            actor_kind: ActorKind::System,
            tenant_id,
            organization_id: None,
            project_id: None,
            principal_id: None,
            api_key_id: None,
            credential_kind: CredentialKind::System,
            auth_strength: 100,
            expires_at: None,
            api_key_allowed_actions: Vec::new(),
            api_key_allowed_resources: Vec::new(),
            request_id,
            trace_id,
        }
    }
}

/// Durable API key metadata. Raw key material is never stored here.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ApiKeyRecord {
    /// Stable API key id.
    pub api_key_id: ApiKeyId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization binding.
    pub organization_id: Option<OrganizationId>,
    /// Optional project binding.
    pub project_id: Option<ProjectId>,
    /// User or service account owner.
    pub owner_principal_id: PrincipalId,
    /// Human label.
    pub name: String,
    /// Visible key prefix for lookup and display.
    pub key_prefix: String,
    /// Password-hash string for the raw secret.
    pub secret_hash: String,
    /// Hashing profile version.
    pub hash_version: u16,
    /// Lifecycle status.
    pub status: ApiKeyStatus,
    /// Optional allowed actions for prefiltering.
    pub allowed_actions: Vec<String>,
    /// Optional allowed resources for prefiltering.
    pub allowed_resources: Vec<String>,
    /// Optional expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Last successful authentication timestamp when flushed from the touch batch.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Request id associated with the latest flushed successful authentication.
    pub last_used_request_id: Option<RequestId>,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for ApiKeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyRecord")
            .field("api_key_id", &self.api_key_id)
            .field("tenant_id", &self.tenant_id)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("owner_principal_id", &self.owner_principal_id)
            .field("name", &self.name)
            .field("key_prefix", &self.key_prefix)
            .field("secret_hash", &"<redacted>")
            .field("hash_version", &self.hash_version)
            .field("status", &self.status)
            .field("allowed_actions", &self.allowed_actions)
            .field("allowed_resources", &self.allowed_resources)
            .field("expires_at", &self.expires_at)
            .field("last_used_at", &self.last_used_at)
            .field("last_used_request_id", &self.last_used_request_id)
            .field("created_by", &self.created_by)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl ApiKeyRecord {
    /// Returns whether the record status and expiry allow authentication now.
    #[must_use]
    pub fn can_authenticate_at(&self, now: DateTime<Utc>) -> bool {
        self.status.accepts_authentication()
            && self.expires_at.is_none_or(|expires_at| expires_at > now)
    }
}

/// Durable server-side session metadata. Raw session tokens are never stored here.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthSessionRecord {
    /// Stable auth session id.
    pub auth_session_id: AuthSessionId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Authenticated principal.
    pub principal_id: PrincipalId,
    /// Active organization context for browser session requests.
    pub active_organization_id: Option<OrganizationId>,
    /// Active project context for browser session requests.
    pub active_project_id: Option<ProjectId>,
    /// Hash of the raw opaque session token.
    pub session_hash: String,
    /// Session lifecycle status.
    pub status: AuthSessionStatus,
    /// Session expiry.
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for AuthSessionRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthSessionRecord")
            .field("auth_session_id", &self.auth_session_id)
            .field("tenant_id", &self.tenant_id)
            .field("principal_id", &self.principal_id)
            .field("active_organization_id", &self.active_organization_id)
            .field("active_project_id", &self.active_project_id)
            .field("session_hash", &"<redacted>")
            .field("status", &self.status)
            .field("expires_at", &self.expires_at)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl AuthSessionRecord {
    /// Returns whether the session status and expiry allow authentication now.
    #[must_use]
    pub fn can_authenticate_at(&self, now: DateTime<Utc>) -> bool {
        self.status.accepts_authentication() && self.expires_at > now
    }
}

/// Durable human login provider configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginProviderRecord {
    /// Stable login provider id.
    pub login_provider_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Provider adapter kind.
    pub provider_kind: String,
    /// Admin-visible display name.
    pub display_name: String,
    /// Safe provider configuration document.
    pub config_document: serde_json::Value,
    /// Provider lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable one-time external login attempt metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginAttemptRecord {
    /// Stable login attempt id.
    pub login_attempt_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Login provider used to start the attempt.
    pub login_provider_id: String,
    /// Provider adapter kind.
    pub provider_kind: String,
    /// Hash of the raw OAuth/OIDC state value.
    pub state_hash: String,
    /// Hash of the raw OIDC nonce when the provider requires one.
    pub nonce_hash: Option<String>,
    /// Hash of the raw PKCE code verifier.
    pub code_verifier_hash: String,
    /// Public PKCE S256 challenge sent to the provider.
    pub code_challenge: String,
    /// Redirect URI used for the authorization request.
    pub redirect_uri: String,
    /// Attempt lifecycle status.
    pub status: String,
    /// Expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Consumption timestamp when the callback succeeds.
    pub consumed_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable organization membership metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrganizationMembershipRecord {
    /// Stable organization membership id.
    pub organization_member_id: OrganizationMemberId,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Organization boundary.
    pub organization_id: OrganizationId,
    /// Principal receiving membership.
    pub principal_id: PrincipalId,
    /// Membership status.
    pub status: MembershipStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
}

/// Durable project membership metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectMembershipRecord {
    /// Stable project membership id.
    pub project_member_id: ProjectMemberId,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Organization boundary.
    pub organization_id: OrganizationId,
    /// Project boundary.
    pub project_id: ProjectId,
    /// Principal receiving membership.
    pub principal_id: PrincipalId,
    /// Parent organization membership when present.
    pub organization_member_id: Option<OrganizationMemberId>,
    /// Membership status.
    pub status: MembershipStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
}

impl ProjectMembershipRecord {
    /// Returns whether this membership can resolve an actor scope.
    #[must_use]
    pub const fn accepts_access(&self) -> bool {
        self.status.accepts_access()
    }
}

/// Durable tenant metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenantRecord {
    /// Stable tenant id.
    pub tenant_id: TenantId,
    /// Admin-visible tenant name.
    pub display_name: String,
    /// Tenant lifecycle status.
    pub status: DirectoryStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable organization metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrganizationRecord {
    /// Stable organization id.
    pub organization_id: OrganizationId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Admin-visible organization name.
    pub display_name: String,
    /// Organization lifecycle status.
    pub status: DirectoryStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable project metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProjectRecord {
    /// Stable project id.
    pub project_id: ProjectId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Owning organization.
    pub organization_id: OrganizationId,
    /// Admin-visible project name.
    pub display_name: String,
    /// Project lifecycle status.
    pub status: DirectoryStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable user metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserRecord {
    /// Stable user id.
    pub user_id: UserId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Default organization for login sessions.
    pub default_organization_id: Option<OrganizationId>,
    /// Default project for login sessions.
    pub default_project_id: Option<ProjectId>,
    /// Primary email when known.
    pub primary_email: Option<String>,
    /// Admin-visible user name.
    pub display_name: String,
    /// User lifecycle status.
    pub status: DirectoryStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable external login identity linked to a gateway-local principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExternalIdentityRecord {
    /// Stable external identity id.
    pub external_identity_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Linked gateway-local principal.
    pub principal_id: PrincipalId,
    /// Login provider that issued the identity when known.
    pub login_provider_id: Option<String>,
    /// Login provider kind.
    pub provider_kind: String,
    /// Stable provider subject.
    pub provider_subject: String,
    /// Last observed email address. Responses expose only a hash.
    pub email: Option<String>,
    /// Whether the provider asserted email verification.
    pub email_verified: bool,
    /// External identity lifecycle status.
    pub status: ResourceStatus,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable organization invitation metadata. Raw invitation tokens are never stored here.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct OrganizationInvitationRecord {
    /// Stable invitation id.
    pub invitation_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Target organization.
    pub organization_id: OrganizationId,
    /// Optional project assignment inside the organization.
    pub project_id: Option<ProjectId>,
    /// Email target when the invitation is email-scoped.
    pub invited_email: Option<String>,
    /// Principal target when the invitation is principal-scoped.
    pub invited_principal_id: Option<PrincipalId>,
    /// Hash of the raw invitation token.
    pub invitation_token_hash: String,
    /// Requested role id.
    pub role_id: String,
    /// Invitation lifecycle status.
    pub status: InvitationStatus,
    /// Expiry timestamp.
    pub expires_at: DateTime<Utc>,
    /// Acceptance timestamp when accepted.
    pub accepted_at: Option<DateTime<Utc>>,
    /// Actor that created the invitation.
    pub created_by: PrincipalId,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

impl fmt::Debug for OrganizationInvitationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OrganizationInvitationRecord")
            .field("invitation_id", &self.invitation_id)
            .field("tenant_id", &self.tenant_id)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("invited_email", &self.invited_email)
            .field("invited_principal_id", &self.invited_principal_id)
            .field("invitation_token_hash", &"<redacted>")
            .field("role_id", &self.role_id)
            .field("status", &self.status)
            .field("expires_at", &self.expires_at)
            .field("accepted_at", &self.accepted_at)
            .field("created_by", &self.created_by)
            .field("resource_version", &self.resource_version)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Durable service account metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ServiceAccountRecord {
    /// Stable service account id.
    pub service_account_id: PrincipalId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Admin-visible service account name.
    pub display_name: String,
    /// Service account lifecycle status.
    pub status: DirectoryStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Seeded tenant, organization, project, user, and membership graph.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TenancySeed {
    /// Tenant record.
    pub tenant: TenantRecord,
    /// Organization record.
    pub organization: OrganizationRecord,
    /// Project record.
    pub project: ProjectRecord,
    /// User record.
    pub user: UserRecord,
    /// Organization membership record.
    pub organization_membership: OrganizationMembershipRecord,
    /// Project membership record.
    pub project_membership: ProjectMembershipRecord,
}

/// Provider endpoint catalog entry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderEndpoint {
    /// Stable endpoint id.
    pub provider_endpoint_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Admin-visible name.
    pub name: String,
    /// Provider kind.
    pub provider_kind: String,
    /// Supported ingress protocol families.
    pub protocol_families: Vec<ProtocolFamily>,
    /// Provider-facing base URL.
    pub upstream_base_url: String,
    /// Lifecycle status.
    pub status: ResourceStatus,
}

/// Generic resource lifecycle status for config resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceStatus {
    /// Resource is active.
    Active,
    /// Resource is disabled.
    Disabled,
    /// Resource is draining.
    Draining,
    /// Resource is degraded.
    Degraded,
    /// Resource was soft-deleted.
    Deleted,
}

impl ResourceStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Draining => "draining",
            Self::Degraded => "degraded",
            Self::Deleted => "deleted",
        }
    }
}

/// Upstream credential lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamCredentialStatus {
    /// Credential can be used.
    Active,
    /// Credential can be used while rotation is in progress.
    Rotating,
    /// Credential is administratively disabled.
    Disabled,
    /// Credential was soft-deleted.
    Deleted,
}

impl UpstreamCredentialStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }
}

/// Secret reference lifecycle status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretRefStatus {
    /// Secret reference can be resolved.
    Active,
    /// Secret reference is in a rotation window.
    Rotating,
    /// Secret reference is administratively disabled.
    Disabled,
    /// Secret reference was soft-deleted.
    Deleted,
}

impl SecretRefStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }
}

/// Durable provider endpoint admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderEndpointRecord {
    /// Stable endpoint id.
    pub provider_endpoint_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Provider kind.
    pub provider_kind: String,
    /// Admin-visible display name.
    pub display_name: String,
    /// Supported ingress protocol families.
    pub protocol_families: Vec<ProtocolFamily>,
    /// Provider-facing base URL.
    pub upstream_base_url: String,
    /// Lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable secret reference admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretRefRecord {
    /// Stable secret reference id.
    pub secret_ref_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Operator-visible purpose for the secret.
    pub purpose: String,
    /// Secret backend kind.
    pub backend_kind: String,
    /// Backend locator. This is returned only through strong-auth locator reads.
    pub backend_locator: String,
    /// Safe display mask derived from the secret value.
    pub display_mask: String,
    /// Stable non-secret fingerprint of the secret value.
    pub fingerprint: String,
    /// Lifecycle status.
    pub status: SecretRefStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable upstream credential admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpstreamCredentialRecord {
    /// Stable upstream credential id.
    pub upstream_credential_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Referenced provider endpoint.
    pub provider_endpoint_id: String,
    /// Credential kind. Raw credential material is never stored here.
    pub credential_kind: String,
    /// Safe secret reference id.
    pub secret_ref_id: String,
    /// Lifecycle status.
    pub status: UpstreamCredentialStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Codex upstream OAuth connection state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexOAuthConnectionStatus {
    /// Connection exists but has no usable OAuth token.
    Unauthenticated,
    /// A login/device session is active.
    LoginPending,
    /// Token material is usable or refreshable.
    Active,
    /// Token material cannot be refreshed without reconnecting.
    Expired,
    /// A transient or unknown auth problem occurred.
    Error,
    /// Admin disabled runtime use.
    Disabled,
}

impl CodexOAuthConnectionStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::LoginPending => "login_pending",
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Error => "error",
            Self::Disabled => "disabled",
        }
    }
}

/// Codex upstream OAuth session state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CodexOAuthSessionStatus {
    /// Device login is pending.
    LoginPending,
    /// Session completed and token material is active.
    Active,
    /// Session was revoked.
    Revoked,
    /// Session expired.
    Expired,
    /// Session encountered an auth error.
    Error,
}

impl CodexOAuthSessionStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::LoginPending => "login_pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Error => "error",
        }
    }
}

/// Durable Codex upstream OAuth connection metadata. Token material is never
/// stored on this record.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CodexOAuthConnectionRecord {
    /// Stable Codex OAuth connection id.
    pub codex_oauth_connection_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Compatible Codex provider endpoint.
    pub provider_endpoint_id: String,
    /// Current upstream credential produced by the active session.
    pub upstream_credential_id: Option<String>,
    /// Admin-visible display name.
    pub display_name: String,
    /// Connection lifecycle status.
    pub status: CodexOAuthConnectionStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable Codex upstream OAuth session metadata. Token material is referenced
/// through a secret ref only.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CodexOAuthSessionRecord {
    /// Stable Codex OAuth session id.
    pub codex_oauth_session_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Parent Codex OAuth connection.
    pub codex_oauth_connection_id: String,
    /// Upstream credential created for the token secret ref.
    pub upstream_credential_id: String,
    /// Secret ref holding the encrypted token bundle.
    pub token_secret_ref_id: String,
    /// Token expiry when known.
    pub token_expires_at: Option<DateTime<Utc>>,
    /// Session lifecycle status.
    pub status: CodexOAuthSessionStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Revocation timestamp.
    pub revoked_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Safe Codex OAuth refresh status metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CodexOAuthRefreshStatusRecord {
    /// Stable refresh status id.
    pub codex_oauth_refresh_status_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Parent Codex OAuth connection.
    pub codex_oauth_connection_id: String,
    /// Current upstream credential when active.
    pub upstream_credential_id: Option<String>,
    /// Current connection status.
    pub status: CodexOAuthConnectionStatus,
    /// Last refresh timestamp when a refresh worker has run.
    pub last_refresh_at: Option<DateTime<Utc>>,
    /// Next scheduled refresh timestamp when known.
    pub next_refresh_at: Option<DateTime<Utc>>,
    /// Token expiry when known.
    pub token_expires_at: Option<DateTime<Utc>>,
    /// Safe error class, never raw provider payload.
    pub last_error: Option<String>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable model target admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelTargetRecord {
    /// Stable model target id.
    pub model_target_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Referenced provider endpoint.
    pub provider_endpoint_id: String,
    /// Optional upstream credential.
    pub upstream_credential_id: Option<String>,
    /// Target protocol family.
    pub protocol_family: ProtocolFamily,
    /// Provider model id sent upstream.
    pub upstream_model_id: String,
    /// Optional explicit pricing SKU override.
    pub pricing_sku_id: Option<String>,
    /// Whether this target can serve streaming requests.
    pub supports_streaming: bool,
    /// Lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable routing group admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingGroupRecord {
    /// Stable routing group id.
    pub routing_group_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Unique group name within the tenant and optional organization boundary.
    pub name: String,
    /// Required target protocol family.
    pub protocol_family: ProtocolFamily,
    /// Human-readable operator purpose.
    pub purpose: Option<String>,
    /// Group lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable routing group target admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingGroupTargetRecord {
    /// Stable routing group target id.
    pub routing_group_target_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Referenced routing group.
    pub routing_group_id: String,
    /// Referenced model target.
    pub model_target_id: String,
    /// Relative weight for weighted strategies.
    pub weight: u32,
    /// Lower priority is tried first for priority strategies.
    pub priority: u32,
    /// Membership lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable model alias admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelAliasRecord {
    /// Stable model alias id.
    pub model_alias_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Client-visible model name.
    pub alias_name: String,
    /// Required ingress protocol family.
    pub protocol_family: ProtocolFamily,
    /// Default route policy. Draft aliases may be unbound.
    pub route_policy_id: Option<String>,
    /// Alias lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable route policy admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutePolicyRecord {
    /// Stable route policy id.
    pub route_policy_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary inferred from alias or routing group.
    pub organization_id: Option<OrganizationId>,
    /// Unique policy name within the tenant and optional organization boundary.
    pub name: String,
    /// Required protocol family.
    pub protocol_family: ProtocolFamily,
    /// Bound model alias.
    pub model_alias_id: String,
    /// Primary routing group.
    pub routing_group_id: String,
    /// Policy lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable catalog import draft admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CatalogImportRecord {
    /// Stable catalog import id.
    pub catalog_import_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Import mode. The v1 admin surface accepts only `draft`.
    pub import_mode: String,
    /// Imported draft bundle document.
    pub import_document: Value,
    /// Stable checksum of the canonical import document.
    pub document_checksum: String,
    /// Number of resource entries in the import document.
    pub resource_count: usize,
    /// Validation diagnostic written before persistence.
    pub validation_id: String,
    /// Lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable provider grant admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderGrantRecord {
    /// Stable provider grant id.
    pub provider_grant_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Grant scope kind, such as `organization` or `project`.
    pub scope_kind: String,
    /// Grant scope id.
    pub scope_id: String,
    /// Optional organization boundary inferred from scope.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary inferred from scope.
    pub project_id: Option<ProjectId>,
    /// Granted or denied resource kind.
    pub resource_kind: String,
    /// Granted or denied resource id.
    pub resource_id: String,
    /// Grant effect, `allow` or `deny`.
    pub effect: String,
    /// Closure mode for route graph expansion.
    pub closure_mode: String,
    /// Grant lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable pricing SKU admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PricingSkuRecord {
    /// Stable pricing SKU id.
    pub pricing_sku_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Admin-visible SKU name.
    pub name: String,
    /// ISO currency code.
    pub currency: String,
    /// Fixed-point unit, such as `micro_usd`.
    pub unit: String,
    /// Model id patterns this SKU can match.
    pub model_id_patterns: Vec<String>,
    /// Optional provider endpoint selectors.
    pub provider_endpoint_patterns: Vec<String>,
    /// Versioned pricing document.
    pub pricing_document: serde_json::Value,
    /// Immutable pricing document version.
    pub pricing_version: i64,
    /// Effective start timestamp.
    pub effective_from: DateTime<Utc>,
    /// Optional effective end timestamp.
    pub effective_until: Option<DateTime<Utc>>,
    /// Whether this SKU is a shipped preset.
    pub is_preset: bool,
    /// SKU lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable budget policy admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BudgetPolicyRecord {
    /// Stable budget policy id.
    pub budget_policy_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Budget scope kind.
    pub scope_kind: String,
    /// Budget scope id.
    pub scope_id: String,
    /// Optional organization boundary inferred from scope.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary inferred from scope.
    pub project_id: Option<ProjectId>,
    /// Cost currency when the budget is cost-based.
    pub currency: Option<String>,
    /// Budget period.
    pub period: String,
    /// Limit kind.
    pub limit_kind: String,
    /// Optional hard block threshold in fixed-point units.
    pub hard_limit: Option<i64>,
    /// Optional soft notification threshold in fixed-point units.
    pub soft_limit: Option<i64>,
    /// Additional notification thresholds.
    pub thresholds: Vec<i64>,
    /// Reset policy label.
    pub reset_policy: String,
    /// Overage behavior.
    pub overage_mode: String,
    /// Consistency behavior for hard budget state.
    pub consistency_mode: String,
    /// Budget lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Runtime budget reservation lease evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeBudgetLeaseRecord {
    /// Stable runtime lease id.
    pub lease_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Budget policy that owns the lease.
    pub budget_policy_id: String,
    /// Runtime hot-state counter key.
    pub counter_key: String,
    /// Gateway request id that acquired the lease.
    pub request_id: RequestId,
    /// Reserved counter amount.
    pub amount: i64,
    /// Lease lifecycle status: `reserved`, `released`, or `expired`.
    pub status: String,
    /// Automatic lease expiry.
    pub expires_at: DateTime<Utc>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Last update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable quota policy admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QuotaPolicyRecord {
    /// Stable quota policy id.
    pub quota_policy_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Quota scope kind.
    pub scope_kind: String,
    /// Quota scope id.
    pub scope_id: String,
    /// Optional organization boundary inferred from scope.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary inferred from scope.
    pub project_id: Option<ProjectId>,
    /// Counter behavior controlled by this policy.
    pub counter_kind: String,
    /// Hard quota limit in the counter's native fixed-point unit.
    pub limit: i64,
    /// Optional bounded allowance used by fail-limited behavior.
    pub burst_limit: Option<i64>,
    /// Counter window kind.
    pub window: String,
    /// Source event that increments or reserves this counter.
    pub increment_source: String,
    /// Hot-state loss behavior.
    pub loss_behavior: String,
    /// Quota lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable export job admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExportJobRecord {
    /// Stable export job id.
    pub export_job_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Export data family.
    pub export_kind: String,
    /// Creating actor.
    pub requested_by: PrincipalId,
    /// Redacted query shape that produced the export.
    pub query_document: serde_json::Value,
    /// Export job lifecycle status.
    pub status: String,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
    /// Completion timestamp.
    pub completed_at: Option<DateTime<Utc>>,
}

/// Durable export manifest metadata.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExportManifestRecord {
    /// Stable export manifest id.
    pub export_manifest_id: String,
    /// Parent export job id.
    pub export_job_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Object-storage reference for the export payload.
    pub object_ref: String,
    /// Number of exported records.
    pub record_count: i64,
    /// Byte size of the exported payload.
    pub byte_count: i64,
    /// Deterministic checksum of the exported payload.
    pub checksum: String,
    /// Redacted manifest document.
    pub manifest_document: serde_json::Value,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Expiration timestamp.
    pub expires_at: DateTime<Utc>,
}

/// Durable planned maintenance window admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MaintenanceWindowRecord {
    /// Stable maintenance window id.
    pub maintenance_window_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Operator-visible name.
    pub name: String,
    /// Safe operator reason.
    pub reason: String,
    /// Window start timestamp.
    pub starts_at: DateTime<Utc>,
    /// Window end timestamp.
    pub ends_at: DateTime<Utc>,
    /// Lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable emergency operation evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EmergencyOperationRecord {
    /// Stable emergency operation id.
    pub emergency_operation_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Emergency operation kind.
    pub operation_kind: String,
    /// Target resource kind.
    pub target_resource_kind: String,
    /// Target resource id.
    pub target_resource_id: String,
    /// Creating actor.
    pub requested_by: PrincipalId,
    /// Safe operator reason.
    pub reason: String,
    /// Operation lifecycle status.
    pub status: String,
    /// Operator alert evidence.
    pub operator_alert_document: serde_json::Value,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
    /// Emergency review or expiry timestamp.
    pub expires_at: DateTime<Utc>,
}

/// Immutable request usage evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageEventRecord {
    /// Stable usage event id.
    pub usage_event_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization attribution captured at request time.
    pub organization_id: Option<OrganizationId>,
    /// Optional project attribution captured at request time.
    pub project_id: Option<ProjectId>,
    /// Optional principal attribution captured at request time.
    pub principal_id: Option<PrincipalId>,
    /// Optional project member attribution captured at request time.
    pub project_member_id: Option<ProjectMemberId>,
    /// Optional service account actor id.
    pub service_account_id: Option<PrincipalId>,
    /// Optional API key used by the request.
    pub api_key_id: Option<ApiKeyId>,
    /// Gateway request id.
    pub request_id: RequestId,
    /// Gateway trace id.
    pub trace_id: TraceId,
    /// Ingress protocol family.
    pub protocol_family: ProtocolFamily,
    /// Route decision evidence id.
    pub route_decision_id: Option<String>,
    /// Model alias id when resolved.
    pub model_alias_id: Option<String>,
    /// Model target id when resolved.
    pub model_target_id: Option<String>,
    /// Route policy id when resolved.
    pub route_policy_id: Option<String>,
    /// Routing group id when resolved.
    pub routing_group_id: Option<String>,
    /// Provider endpoint id when resolved.
    pub provider_endpoint_id: Option<String>,
    /// Upstream credential id when resolved. Secret material is never included.
    pub upstream_credential_id: Option<String>,
    /// Usage confidence label.
    pub usage_confidence: String,
    /// Total request latency in milliseconds.
    pub latency_ms: Option<i64>,
    /// Time to first token in milliseconds when known.
    pub time_to_first_token_ms: Option<i64>,
    /// Terminal request status.
    pub status: String,
    /// Normalized usage payload.
    pub usage_payload: serde_json::Value,
    /// Fixed-point cost estimate payload.
    pub cost_payload: serde_json::Value,
    /// Terminal event timestamp.
    pub occurred_at: DateTime<Utc>,
}

/// Durable usage and cost aggregate bucket.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LedgerBucketRecord {
    /// Stable bucket id.
    pub ledger_bucket_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization dimension.
    pub organization_id: Option<OrganizationId>,
    /// Optional project dimension.
    pub project_id: Option<ProjectId>,
    /// Optional principal dimension.
    pub principal_id: Option<PrincipalId>,
    /// Optional project member dimension.
    pub project_member_id: Option<ProjectMemberId>,
    /// Optional service account dimension.
    pub service_account_id: Option<PrincipalId>,
    /// Optional API key dimension.
    pub api_key_id: Option<ApiKeyId>,
    /// Optional model alias dimension.
    pub model_alias_id: Option<String>,
    /// Optional model target dimension.
    pub model_target_id: Option<String>,
    /// Optional provider endpoint dimension.
    pub provider_endpoint_id: Option<String>,
    /// Optional upstream credential dimension.
    pub upstream_credential_id: Option<String>,
    /// Optional route policy dimension.
    pub route_policy_id: Option<String>,
    /// Optional routing group dimension.
    pub routing_group_id: Option<String>,
    /// Protocol family dimension.
    pub protocol_family: Option<ProtocolFamily>,
    /// Terminal status dimension.
    pub status: Option<String>,
    /// Usage confidence dimension.
    pub usage_confidence: Option<String>,
    /// Bucket kind.
    pub bucket_kind: String,
    /// Bucket start timestamp.
    pub bucket_start: DateTime<Utc>,
    /// Cost currency.
    pub currency_code: String,
    /// Aggregated input tokens.
    pub input_tokens: i64,
    /// Aggregated output tokens.
    pub output_tokens: i64,
    /// Aggregated reasoning tokens.
    pub reasoning_tokens: i64,
    /// Aggregated media units.
    pub media_units: i64,
    /// Aggregated terminal request count.
    pub request_count: i64,
    /// Successful request count.
    pub success_count: i64,
    /// Error request count.
    pub error_count: i64,
    /// Blocked request count.
    pub blocked_count: i64,
    /// Usage missing count.
    pub usage_missing_count: i64,
    /// Usage estimated count.
    pub usage_estimated_count: i64,
    /// Estimated cost in fixed-point micros.
    pub estimated_cost_micros: i64,
    /// Pricing version used for the aggregate.
    pub pricing_version: String,
    /// Latest source event timestamp folded into this bucket.
    pub updated_at: DateTime<Utc>,
}

/// Safe OpenTelemetry header reference.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OtelHeaderRef {
    /// Header name sent to the collector.
    pub name: String,
    /// Secret reference containing the header value.
    pub secret_ref_id: String,
}

/// Bounded static OpenTelemetry resource attribute.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OtelResourceAttribute {
    /// Attribute key.
    pub key: String,
    /// Static attribute value.
    pub value: String,
}

/// Durable OpenTelemetry export configuration admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OtelExportConfigRecord {
    /// Stable OpenTelemetry export config id.
    pub otel_export_config_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Collector endpoint URL.
    pub endpoint_url: String,
    /// Export protocol.
    pub protocol: String,
    /// Secret-backed collector headers.
    pub header_refs: Vec<OtelHeaderRef>,
    /// Enabled telemetry signals.
    pub enabled_signals: Vec<String>,
    /// Bounded static resource attributes.
    pub resource_attributes: Vec<OtelResourceAttribute>,
    /// Export interval in seconds.
    pub export_interval_seconds: i64,
    /// Export timeout in seconds.
    pub timeout_seconds: i64,
    /// Export config lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Latest OpenTelemetry exporter health evidence for one config.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OtelExporterHealthRecord {
    /// Stable exporter health record id.
    pub otel_exporter_health_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Parent OpenTelemetry export config.
    pub otel_export_config_id: String,
    /// Worker role or instance id that produced the record.
    pub worker_id: String,
    /// Health status of the latest export attempt.
    pub status: String,
    /// Number of consecutive export failures.
    pub failure_count: i64,
    /// Number of metrics dropped by the latest failed attempt.
    pub dropped_metric_count: i64,
    /// Number of metrics accepted by the latest successful attempt.
    pub exported_metric_count: i64,
    /// Safe last error code or message.
    pub last_error: Option<String>,
    /// Last export attempt timestamp.
    pub last_attempted_at: DateTime<Utc>,
    /// Last successful export timestamp.
    pub last_successful_export_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable notification sink admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationSinkRecord {
    /// Stable notification sink id.
    pub notification_sink_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Admin-visible sink name.
    pub name: String,
    /// Sink kind.
    pub sink_kind: String,
    /// Redacted endpoint configuration.
    pub endpoint_config: serde_json::Value,
    /// Optional signing secret reference.
    pub signing_secret_ref_id: Option<String>,
    /// Sink lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable notification subscription admin resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationSubscriptionRecord {
    /// Stable notification subscription id.
    pub notification_subscription_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Sink that receives matching events.
    pub notification_sink_id: String,
    /// Notification event family.
    pub event_family: String,
    /// Safe filter document.
    pub filter_document: serde_json::Value,
    /// Subscription lifecycle status.
    pub status: ResourceStatus,
    /// Resource version for optimistic concurrency.
    pub resource_version: i64,
    /// Schema version that wrote this record.
    pub schema_version: u16,
    /// Creating actor.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable notification outbox event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationOutboxEventRecord {
    /// Stable notification outbox event id.
    pub notification_outbox_event_id: String,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Matched subscription when present.
    pub notification_subscription_id: Option<String>,
    /// Matched sink when present.
    pub notification_sink_id: Option<String>,
    /// Stable event kind.
    pub event_kind: String,
    /// Tenant-local idempotency key.
    pub dedupe_key: String,
    /// Redacted event payload.
    pub payload_document: serde_json::Value,
    /// Delivery lifecycle status.
    pub status: String,
    /// Delivery attempts recorded so far.
    pub attempt_count: i32,
    /// Next delivery attempt timestamp.
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// Update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Durable notification delivery attempt evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NotificationDeliveryAttemptRecord {
    /// Stable notification delivery attempt id.
    pub notification_delivery_attempt_id: String,
    /// Parent outbox event.
    pub notification_outbox_event_id: String,
    /// Delivery sink when present.
    pub notification_sink_id: Option<String>,
    /// Zero-based delivery attempt index.
    pub attempt_index: i32,
    /// Attempt status.
    pub status: String,
    /// HTTP response status when available.
    pub response_status: Option<i32>,
    /// Safe error message when available.
    pub error_message: Option<String>,
    /// SHA-256 checksum of the redacted delivery request body.
    pub request_body_sha256: Option<String>,
    /// Signing secret reference used for this attempt.
    pub signing_secret_ref_id: Option<String>,
    /// SHA-256 checksum of the generated signature value.
    pub signature_sha256: Option<String>,
    /// Safe delivery headers and redacted metadata.
    pub delivery_headers: serde_json::Value,
    /// Attempt timestamp.
    pub attempted_at: DateTime<Utc>,
}

/// Config snapshot metadata consumed by runtime workers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigSnapshot {
    /// Stable snapshot id.
    pub snapshot_id: ConfigSnapshotId,
    /// Owning tenant.
    pub tenant_id: TenantId,
    /// Monotonic publication version.
    pub version: i64,
    /// Deterministic checksum.
    pub checksum: String,
    /// Publication status.
    pub status: ConfigSnapshotStatus,
    /// Compilation timestamp.
    pub compiled_at: DateTime<Utc>,
}

/// Config snapshot status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSnapshotStatus {
    /// Snapshot is pending publication.
    Pending,
    /// Snapshot is published.
    Published,
    /// Snapshot was rejected by validation.
    Rejected,
    /// Snapshot represents rollback content.
    RolledBack,
}

impl ConfigSnapshotStatus {
    /// Returns the stable status label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::RolledBack => "rolled_back",
        }
    }
}

/// Latest published config pointer for one tenant.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigPublicationPointerRecord {
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Latest published snapshot id.
    pub snapshot_id: ConfigSnapshotId,
    /// Latest published version.
    pub version: i64,
    /// Latest published checksum.
    pub checksum: String,
    /// Latest invalidation event id.
    pub invalidation_id: String,
    /// Publication timestamp.
    pub published_at: DateTime<Utc>,
    /// Pointer update timestamp.
    pub updated_at: DateTime<Utc>,
}

/// Redis-compatible config invalidation event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigInvalidationEventRecord {
    /// Stable invalidation id.
    pub invalidation_id: String,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Published snapshot id.
    pub snapshot_id: ConfigSnapshotId,
    /// Published snapshot version.
    pub version: i64,
    /// Published snapshot checksum.
    pub checksum: String,
    /// Publication timestamp copied from the snapshot.
    pub published_at: DateTime<Utc>,
    /// Event creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Source that caused a worker config reload.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigReloadSource {
    /// Worker observed the Redis-compatible invalidation event.
    Invalidation,
    /// Worker converged by polling the durable publication pointer.
    Polling,
}

impl ConfigReloadSource {
    /// Returns the stable reload source id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Invalidation => "invalidation",
            Self::Polling => "polling",
        }
    }
}

/// Worker reload status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigWorkerReloadStatus {
    /// Worker loaded the snapshot successfully.
    Loaded,
    /// Worker failed to load the snapshot and kept its last-known-good config.
    Failed,
}

impl ConfigWorkerReloadStatus {
    /// Returns the stable reload status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Loaded => "loaded",
            Self::Failed => "failed",
        }
    }
}

/// Durable operational evidence for one worker config reload.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigWorkerReloadRecord {
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Stable worker id.
    pub worker_id: String,
    /// Loaded snapshot id.
    pub snapshot_id: ConfigSnapshotId,
    /// Loaded config version.
    pub loaded_version: i64,
    /// Loaded snapshot checksum.
    pub checksum: String,
    /// Last-known-good snapshot id after this reload attempt.
    pub last_known_good_snapshot_id: ConfigSnapshotId,
    /// Last-known-good config version after this reload attempt.
    pub last_known_good_version: i64,
    /// Reload source.
    pub reload_source: ConfigReloadSource,
    /// Reload status.
    pub status: ConfigWorkerReloadStatus,
    /// Number of invalidations skipped since the previous successful load.
    pub missed_invalidation_count: usize,
    /// Milliseconds between publication and reload evidence.
    pub publication_lag_ms: i64,
    /// Reload timestamp.
    pub reloaded_at: DateTime<Utc>,
}

/// Safe validation diagnostic evidence for admin dry-runs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ValidationDiagnosticRecord {
    /// Stable validation diagnostic id.
    pub validation_id: String,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Validated resource kind.
    pub resource_kind: String,
    /// Scope kind used for authorization and grouping.
    pub scope_kind: String,
    /// Scope id used for authorization and grouping.
    pub scope_id: String,
    /// Whether validation produced no blocking errors.
    pub valid: bool,
    /// Blocking diagnostics.
    pub errors: serde_json::Value,
    /// Non-blocking diagnostics.
    pub warnings: serde_json::Value,
    /// Safe touched-resource preview.
    pub affected_resources: serde_json::Value,
    /// Optional publication plan preview.
    pub publication_plan: Option<serde_json::Value>,
    /// Optional route simulation preview.
    pub route_simulation: Option<serde_json::Value>,
    /// Optional budget simulation preview.
    pub budget_simulation: Option<serde_json::Value>,
    /// Actor that ran validation.
    pub created_by: PrincipalId,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

/// Immutable audit event written by admin mutations.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEventRecord {
    /// Stable audit event id.
    pub audit_event_id: String,
    /// Stable event type.
    pub event_type: String,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Scope kind for the mutated resource.
    pub scope_kind: String,
    /// Scope id for the mutated resource.
    pub scope_id: String,
    /// Mutated resource kind.
    pub resource_kind: String,
    /// Mutated resource id.
    pub resource_id: String,
    /// Previous resource version when present.
    pub before_version: Option<i64>,
    /// New resource version when present.
    pub after_version: Option<i64>,
    /// Actor id captured at mutation time.
    pub actor_id: String,
    /// Actor kind captured at mutation time.
    pub actor_kind: ActorKind,
    /// Principal id captured at mutation time.
    pub principal_id: Option<PrincipalId>,
    /// Gateway request id.
    pub request_id: RequestId,
    /// Gateway trace id.
    pub trace_id: TraceId,
    /// Safe redacted diff payload.
    pub redacted_diff: serde_json::Value,
    /// Event timestamp.
    pub occurred_at: DateTime<Utc>,
}

/// Creates a stable id with a resource prefix.
#[must_use]
pub fn new_prefixed_id(prefix: &str) -> String {
    format!("{prefix}_{}", Uuid::now_v7().simple())
}

#[cfg(test)]
mod tests {
    use crate::domain::{
        ActorKind, ActorScope, ApiKeyRecord, ApiKeyStatus, AuthSessionRecord, AuthSessionStatus,
        AuthenticatedActor, CredentialKind,
    };

    #[test]
    fn user_session_actor_preserves_scope_and_principal() {
        let actor = AuthenticatedActor::for_user_session(
            ActorScope::new("ten_test", Some("org_test"), Some("prj_test")),
            "usr_test".to_owned(),
            "sess_test".to_owned(),
            "req_test".to_owned(),
            "tr_test".to_owned(),
            None,
        );

        assert_eq!(actor.actor_kind, ActorKind::User);
        assert_eq!(actor.credential_kind, CredentialKind::Session);
        assert_eq!(actor.principal_id.as_deref(), Some("usr_test"));
        assert_eq!(actor.organization_id.as_deref(), Some("org_test"));
        assert_eq!(actor.project_id.as_deref(), Some("prj_test"));
        assert_eq!(actor.trace_id, "tr_test");
    }

    #[test]
    fn service_account_actor_is_principal_backed() {
        let actor = AuthenticatedActor::for_service_account(
            ActorScope::new("ten_test", Some("org_test"), Some("prj_test")),
            "svc_test".to_owned(),
            "req_test".to_owned(),
            "tr_test".to_owned(),
        );

        assert_eq!(actor.actor_kind, ActorKind::ServiceAccount);
        assert_eq!(actor.credential_kind, CredentialKind::ServiceToken);
        assert_eq!(actor.principal_id.as_deref(), Some("svc_test"));
        assert_eq!(actor.trace_id, "tr_test");
    }

    #[test]
    fn system_actor_has_strongest_auth_context() {
        let actor = AuthenticatedActor::for_system_task(
            "ten_test".to_owned(),
            "sys_rollup",
            "req_test".to_owned(),
            "tr_test".to_owned(),
        );

        assert_eq!(actor.actor_kind, ActorKind::System);
        assert_eq!(actor.credential_kind, CredentialKind::System);
        assert_eq!(actor.auth_strength, 100);
        assert!(actor.principal_id.is_none());
        assert_eq!(actor.trace_id, "tr_test");
    }

    #[test]
    fn api_key_debug_redacts_secret_hash() {
        let now = chrono::Utc::now();
        let record = ApiKeyRecord {
            api_key_id: "ak_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: Some("org_test".to_owned()),
            project_id: Some("prj_test".to_owned()),
            owner_principal_id: "usr_test".to_owned(),
            name: "runtime".to_owned(),
            key_prefix: "swk_prefix".to_owned(),
            secret_hash: "$argon2id$secret_hash_material".to_owned(),
            hash_version: 1,
            status: ApiKeyStatus::Active,
            allowed_actions: vec!["gateway.model.invoke".to_owned()],
            allowed_resources: vec!["ma_test".to_owned()],
            expires_at: None,
            last_used_at: Some(now),
            last_used_request_id: Some("req_test".to_owned()),
            created_by: "usr_test".to_owned(),
            created_at: now,
            updated_at: now,
        };

        let debug = format!("{record:?}");

        assert!(debug.contains("key_prefix: \"swk_prefix\""));
        assert!(debug.contains("secret_hash: \"<redacted>\""));
        assert!(!debug.contains("$argon2id$secret_hash_material"));
    }

    #[test]
    fn auth_session_debug_redacts_session_hash() {
        let now = chrono::Utc::now();
        let record = AuthSessionRecord {
            auth_session_id: "sess_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            principal_id: "usr_test".to_owned(),
            active_organization_id: Some("org_test".to_owned()),
            active_project_id: Some("prj_test".to_owned()),
            session_hash: "session_hash_material".to_owned(),
            status: AuthSessionStatus::Active,
            expires_at: now,
            created_at: now,
            updated_at: now,
        };

        let debug = format!("{record:?}");

        assert!(debug.contains("auth_session_id: \"sess_test\""));
        assert!(debug.contains("session_hash: \"<redacted>\""));
        assert!(!debug.contains("session_hash_material"));
    }
}
