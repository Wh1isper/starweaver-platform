//! Storage boundaries for gateway resources.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use chrono::Datelike;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use sqlx::Row;

use crate::action::{ActionGrant, AuthorizationDecisionRecord, AuthorizationEvidenceSink};
use crate::config::{ConfigSnapshotDocument, PublishedConfigSnapshot};
use crate::domain::{
    new_prefixed_id, ApiKeyRecord, ApiKeyStatus, AuditEventRecord, AuthSessionRecord,
    AuthSessionStatus, BudgetPolicyRecord, CodexOAuthConnectionRecord, CodexOAuthConnectionStatus,
    CodexOAuthRefreshStatusRecord, CodexOAuthSessionRecord, CodexOAuthSessionStatus,
    ConfigInvalidationEventRecord, ConfigPublicationPointerRecord, ConfigReloadSource,
    ConfigSnapshot, ConfigSnapshotStatus, ConfigWorkerReloadRecord, ConfigWorkerReloadStatus,
    DirectoryStatus, EmergencyOperationRecord, ExportJobRecord, ExportManifestRecord,
    ExternalIdentityRecord, InvitationStatus, LedgerBucketRecord, LoginAttemptRecord,
    LoginProviderRecord, MembershipStatus, ModelAliasRecord, ModelTargetRecord,
    NotificationDeliveryAttemptRecord, NotificationOutboxEventRecord, NotificationSinkRecord,
    NotificationSubscriptionRecord, OrganizationInvitationRecord, OrganizationMembershipRecord,
    OrganizationRecord, OtelExportConfigRecord, OtelExporterHealthRecord, OtelHeaderRef,
    OtelResourceAttribute, PricingSkuRecord, ProjectMembershipRecord, ProjectRecord,
    ProviderEndpointRecord, ProviderGrantRecord, QuotaPolicyRecord, ResourceStatus,
    RoutePolicyRecord, RoutingGroupRecord, RoutingGroupTargetRecord, RuntimeBudgetLeaseRecord,
    SecretRefRecord, SecretRefStatus, ServiceAccountRecord, TenancySeed, TenantRecord,
    UpstreamCredentialRecord, UpstreamCredentialStatus, UsageEventRecord, UserRecord,
    ValidationDiagnosticRecord,
};
use crate::error::{GatewayError, Result};
use crate::hot_state::{
    EndpointDrainRecord, EndpointHealthRecord, EndpointHealthState, RouteHotState,
    StickyRouteRecord,
};
use crate::routing::{
    RouteAttemptRecord, RouteAttemptStatus, RouteDecisionRecord, RouteDecisionStatus,
    RouteEvidenceSink, RouteFilterSummary,
};
use crate::ProtocolFamily;

type StickyRouteKey = (String, Option<String>, String, String);

const API_KEY_FAILED_AUTH_WINDOW_SECONDS: i64 = 60;
const API_KEY_FAILED_AUTH_MAX_ATTEMPTS: usize = 8;
const API_KEY_CANDIDATE_LIMIT: usize = 8;

/// API key repository boundary.
pub trait ApiKeyRepository: Send + Sync {
    /// Loads candidate API keys by visible prefix.
    fn candidates_by_prefix(&self, prefix: &str) -> Vec<ApiKeyRecord>;

    /// Returns whether another failed authentication attempt is allowed.
    fn api_key_failed_auth_allowed(
        &self,
        throttle_key: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool;

    /// Records a failed API key authentication attempt.
    fn record_api_key_failed_auth(&self, throttle_key: &str, now: chrono::DateTime<chrono::Utc>);

    /// Records a successful API key authentication for batched last-used updates.
    fn record_api_key_last_used(&self, update: ApiKeyLastUsedUpdate);
}

/// Batched API key last-used update.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiKeyLastUsedUpdate {
    /// Tenant boundary.
    pub tenant_id: String,
    /// API key id.
    pub api_key_id: String,
    /// Visible key prefix used as the auth throttle key.
    pub key_prefix: String,
    /// Request id authenticated by this key.
    pub request_id: String,
    /// Successful authentication timestamp.
    pub used_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create a service account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateServiceAccountRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Admin-visible service account name.
    pub display_name: String,
    /// Creating actor.
    pub created_by: String,
}

/// Service account admin repository boundary.
pub trait ServiceAccountAdminRepository: Send + Sync {
    /// Creates a service account.
    fn create_service_account(
        &self,
        request: CreateServiceAccountRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ServiceAccountRecord>;

    /// Lists service accounts in a tenant.
    fn service_accounts_for_tenant(&self, tenant_id: &str) -> Vec<ServiceAccountRecord>;

    /// Loads one service account.
    fn service_account(&self, service_account_id: &str) -> Option<ServiceAccountRecord>;

    /// Updates service account status with optimistic concurrency.
    fn update_service_account_status(
        &self,
        service_account_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ServiceAccountRecord>;
}

/// Auth session repository boundary.
pub trait AuthSessionRepository: Send + Sync {
    /// Loads a session by opaque token hash.
    fn session_by_hash(&self, session_hash: &str) -> Option<AuthSessionRecord>;

    /// Lists sessions for one principal inside one tenant.
    fn sessions_for_principal(&self, tenant_id: &str, principal_id: &str)
        -> Vec<AuthSessionRecord>;

    /// Loads a session by id for one principal inside one tenant.
    fn session_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        auth_session_id: &str,
    ) -> Option<AuthSessionRecord>;

    /// Revokes a session by opaque token hash.
    fn revoke_session_by_hash(
        &self,
        session_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord>;

    /// Updates active organization and project context for an existing session.
    fn update_session_active_context_by_hash(
        &self,
        session_hash: &str,
        active_organization_id: Option<String>,
        active_project_id: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord>;

    /// Revokes active sessions for one principal.
    fn revoke_sessions_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> usize;

    /// Revokes one session by id for one principal inside one tenant.
    fn revoke_session_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        auth_session_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord>;
}

/// External identity repository boundary.
pub trait ExternalIdentityRepository: Send + Sync {
    /// Lists external identities for one principal inside one tenant.
    fn external_identities_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Vec<ExternalIdentityRecord>;

    /// Loads an external identity by id for one principal inside one tenant.
    fn external_identity_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        external_identity_id: &str,
    ) -> Option<ExternalIdentityRecord>;

    /// Marks an external identity as unlinked.
    fn unlink_external_identity(
        &self,
        tenant_id: &str,
        principal_id: &str,
        external_identity_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ExternalIdentityRecord>;
}

/// Config snapshot repository boundary.
pub trait ConfigSnapshotRepository: Send + Sync {
    /// Loads the latest published snapshot metadata for readiness.
    fn latest_published_snapshot(&self) -> Option<ConfigSnapshot>;
}

/// Config snapshot publication store boundary.
pub trait ConfigSnapshotStore: Send + Sync {
    /// Loads the latest published snapshot metadata for a tenant.
    fn latest_published_snapshot_for_tenant(&self, tenant_id: &str) -> Option<ConfigSnapshot>;

    /// Loads a published config snapshot by id.
    fn config_snapshot(&self, snapshot_id: &str) -> Option<PublishedConfigSnapshot>;

    /// Inserts an immutable config snapshot.
    fn insert_config_snapshot(&self, snapshot: PublishedConfigSnapshot);
}

/// Config publication convergence repository boundary.
pub trait ConfigPublicationRepository: Send + Sync {
    /// Loads the durable latest-publication pointer for a tenant.
    fn config_publication(&self, tenant_id: &str) -> Option<ConfigPublicationPointerRecord>;

    /// Lists config invalidation events for a tenant.
    fn config_invalidation_events_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<ConfigInvalidationEventRecord>;

    /// Lists latest worker reload evidence for a tenant.
    fn config_worker_reloads_for_tenant(&self, tenant_id: &str) -> Vec<ConfigWorkerReloadRecord>;

    /// Records a worker reload after observing one invalidation event.
    fn reload_config_worker_from_invalidation(
        &self,
        tenant_id: &str,
        worker_id: &str,
        invalidation_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ConfigWorkerReloadRecord>;

    /// Records a worker reload by polling the durable publication pointer.
    fn reload_config_worker_by_polling(
        &self,
        tenant_id: &str,
        worker_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ConfigWorkerReloadRecord>;
}

/// Validation diagnostic repository boundary.
pub trait ValidationDiagnosticRepository: Send + Sync {
    /// Records safe validation diagnostic evidence.
    fn record_validation_diagnostic(&self, record: ValidationDiagnosticRecord);

    /// Lists validation diagnostics in one tenant.
    fn validation_diagnostics_for_tenant(&self, tenant_id: &str)
        -> Vec<ValidationDiagnosticRecord>;
}

/// Usage accounting repository boundary.
pub trait UsageAccountingRepository: Send + Sync {
    /// Records one immutable usage event and folds it into durable ledger buckets.
    fn record_usage_event(&self, record: UsageEventRecord);

    /// Lists usage events in one tenant.
    fn usage_events_for_tenant(&self, tenant_id: &str) -> Vec<UsageEventRecord>;

    /// Lists ledger buckets in one tenant.
    fn ledger_buckets_for_tenant(&self, tenant_id: &str) -> Vec<LedgerBucketRecord>;
}

/// Runtime policy hot-state repository boundary.
pub trait RuntimePolicyRepository: Send + Sync {
    /// Returns whether runtime policy hot state is currently available.
    fn runtime_policy_hot_state_available(&self) -> bool;

    /// Atomically increments one quota counter and returns the post-increment decision.
    fn increment_runtime_quota_counter(
        &self,
        key: String,
        increment: i64,
        limit: i64,
    ) -> RuntimeQuotaCounterDecision;

    /// Returns the current hot-state policy counter value.
    fn runtime_policy_counter(&self, key: &str) -> i64;

    /// Adjusts one hot-state policy counter and returns the post-adjustment value.
    fn adjust_runtime_policy_counter(&self, key: String, delta: i64) -> i64;

    /// Atomically consumes a local fail-limited allowance when hot state is unavailable.
    fn increment_runtime_policy_loss_allowance_counter(
        &self,
        key: String,
        increment: i64,
        limit: i64,
    ) -> RuntimeQuotaCounterDecision;

    /// Adjusts a fail-limited allowance counter and returns the post-adjustment value.
    fn adjust_runtime_policy_loss_allowance_counter(&self, key: String, delta: i64) -> i64;

    /// Returns the current fail-limited allowance counter value.
    fn runtime_policy_loss_allowance_counter(&self, key: &str) -> i64;

    /// Records a runtime budget reservation lease.
    fn record_runtime_budget_lease(&self, record: RuntimeBudgetLeaseRecord);

    /// Marks a runtime budget reservation lease as released.
    fn release_runtime_budget_lease(
        &self,
        lease_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<RuntimeBudgetLeaseRecord>;

    /// Expires reserved runtime budget leases for one tenant.
    fn expire_runtime_budget_leases(
        &self,
        tenant_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<RuntimeBudgetLeaseRecord>;

    /// Lists runtime budget leases for one tenant.
    fn runtime_budget_leases_for_tenant(&self, tenant_id: &str) -> Vec<RuntimeBudgetLeaseRecord>;
}

/// Runtime quota counter decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeQuotaCounterDecision {
    /// Counter value after the increment.
    pub current: i64,
    /// Whether the request remains within the hard quota limit.
    pub allowed: bool,
}

/// Export job repository boundary.
pub trait ExportRepository: Send + Sync {
    /// Creates one export job.
    fn create_export_job(
        &self,
        request: CreateExportJobRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ExportJobRecord>;

    /// Lists export jobs in one tenant.
    fn export_jobs_for_tenant(&self, tenant_id: &str) -> Vec<ExportJobRecord>;

    /// Loads one export job.
    fn export_job(&self, export_job_id: &str) -> Option<ExportJobRecord>;

    /// Completes one export job and writes its manifest.
    fn complete_export_job(
        &self,
        export_job_id: &str,
        request: CompleteExportJobRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(ExportJobRecord, ExportManifestRecord)>;

    /// Lists manifests for one export job.
    fn export_manifests_for_job(&self, export_job_id: &str) -> Vec<ExportManifestRecord>;
}

/// Emergency operation repository boundary.
pub trait EmergencyOperationRepository: Send + Sync {
    /// Creates durable emergency operation evidence.
    fn create_emergency_operation(
        &self,
        request: CreateEmergencyOperationRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<EmergencyOperationRecord>;

    /// Lists emergency operations in one tenant.
    fn emergency_operations_for_tenant(&self, tenant_id: &str) -> Vec<EmergencyOperationRecord>;

    /// Loads one emergency operation.
    fn emergency_operation(&self, emergency_operation_id: &str)
        -> Option<EmergencyOperationRecord>;

    /// Loads the latest active emergency operation by kind.
    fn active_emergency_operation(
        &self,
        tenant_id: &str,
        operation_kind: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<EmergencyOperationRecord>;
}

/// Notification outbox repository boundary.
pub trait NotificationOutboxRepository: Send + Sync {
    /// Appends one outbox event or returns the existing event for the same dedupe key.
    fn append_notification_outbox_event(
        &self,
        request: CreateNotificationOutboxEventRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> NotificationOutboxEventRecord;

    /// Loads one notification outbox event.
    fn notification_outbox_event(
        &self,
        notification_outbox_event_id: &str,
    ) -> Option<NotificationOutboxEventRecord>;

    /// Reschedules a dead-lettered outbox event for another delivery cycle.
    fn replay_dead_lettered_notification_outbox_event(
        &self,
        notification_outbox_event_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationOutboxEventRecord>;

    /// Lists notification subscriptions in one tenant.
    fn notification_subscriptions_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<NotificationSubscriptionRecord>;

    /// Lists outbox events in one tenant.
    fn notification_outbox_events_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<NotificationOutboxEventRecord>;

    /// Lists due outbox events in one tenant.
    fn due_notification_outbox_events(
        &self,
        tenant_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> Vec<NotificationOutboxEventRecord>;

    /// Records one delivery attempt and updates the parent outbox status.
    fn record_notification_delivery_attempt(
        &self,
        request: CreateNotificationDeliveryAttemptRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationDeliveryAttemptRecord>;

    /// Lists delivery attempts for one outbox event.
    fn notification_delivery_attempts_for_event(
        &self,
        notification_outbox_event_id: &str,
    ) -> Vec<NotificationDeliveryAttemptRecord>;
}

/// Tenancy and membership repository boundary.
pub trait TenancyRepository: Send + Sync {
    /// Loads project membership for a principal.
    fn project_membership(
        &self,
        principal_id: &str,
        project_id: &str,
    ) -> Option<ProjectMembershipRecord>;
}

/// Tenancy bootstrap and resource mutation repository boundary.
pub trait TenancyBootstrapRepository: Send + Sync {
    /// Idempotently creates the default tenant, organization, project, user, and memberships.
    fn bootstrap_default_project(
        &self,
        request: BootstrapDefaultProjectRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TenancySeed>;

    /// Loads tenant metadata.
    fn tenant(&self, tenant_id: &str) -> Option<TenantRecord>;

    /// Loads organization metadata.
    fn organization(&self, organization_id: &str) -> Option<OrganizationRecord>;

    /// Lists organizations in a tenant.
    fn organizations_for_tenant(&self, tenant_id: &str) -> Vec<OrganizationRecord>;

    /// Loads project metadata.
    fn project(&self, project_id: &str) -> Option<ProjectRecord>;

    /// Lists projects in a tenant.
    fn projects_for_tenant(&self, tenant_id: &str) -> Vec<ProjectRecord>;

    /// Lists organization memberships in an organization.
    fn organization_members_for_organization(
        &self,
        organization_id: &str,
    ) -> Vec<OrganizationMembershipRecord>;

    /// Loads organization membership by stable id.
    fn organization_member(
        &self,
        organization_member_id: &str,
    ) -> Option<OrganizationMembershipRecord>;

    /// Lists project memberships in a project.
    fn project_members_for_project(&self, project_id: &str) -> Vec<ProjectMembershipRecord>;

    /// Creates or reactivates a project membership.
    fn create_project_membership(
        &self,
        request: CreateProjectMembershipRequest,
    ) -> Result<ProjectMembershipRecord>;

    /// Loads project membership by stable id.
    fn project_member(&self, project_member_id: &str) -> Option<ProjectMembershipRecord>;

    /// Loads user metadata.
    fn user(&self, user_id: &str) -> Option<UserRecord>;

    /// Lists users in a tenant.
    fn users_for_tenant(&self, tenant_id: &str) -> Vec<UserRecord>;

    /// Updates the user's default organization and project context.
    fn update_user_default_context(
        &self,
        user_id: &str,
        organization_id: Option<String>,
        project_id: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UserRecord>;

    /// Updates user status with optimistic concurrency.
    fn update_user_status(
        &self,
        user_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UserRecord>;

    /// Updates organization status with optimistic concurrency.
    fn update_organization_status(
        &self,
        organization_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationRecord>;

    /// Updates project status with optimistic concurrency.
    fn update_project_status(
        &self,
        project_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProjectRecord>;

    /// Updates organization membership status with optimistic concurrency.
    fn update_organization_member_status(
        &self,
        organization_member_id: &str,
        expected_resource_version: i64,
        status: MembershipStatus,
    ) -> Result<OrganizationMembershipRecord>;

    /// Cascades inactive organization membership status to project memberships.
    fn cascade_project_memberships_for_organization_member(
        &self,
        organization_member: &OrganizationMembershipRecord,
        status: MembershipStatus,
    ) -> usize;

    /// Updates project membership status with optimistic concurrency.
    fn update_project_member_status(
        &self,
        project_member_id: &str,
        expected_resource_version: i64,
        status: MembershipStatus,
    ) -> Result<ProjectMembershipRecord>;
}

/// Organization invitation repository boundary.
pub trait OrganizationInvitationRepository: Send + Sync {
    /// Creates an organization invitation.
    fn create_organization_invitation(
        &self,
        request: CreateOrganizationInvitationRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationInvitationRecord>;

    /// Lists invitations for one organization.
    fn organization_invitations(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> Vec<OrganizationInvitationRecord>;

    /// Loads an invitation by id.
    fn organization_invitation(&self, invitation_id: &str) -> Option<OrganizationInvitationRecord>;

    /// Loads an invitation by token hash.
    fn organization_invitation_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Option<OrganizationInvitationRecord>;

    /// Revokes an invitation with optimistic concurrency.
    fn revoke_organization_invitation(
        &self,
        invitation_id: &str,
        expected_resource_version: i64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationInvitationRecord>;

    /// Accepts an invitation, activates memberships, and updates defaults when needed.
    fn accept_organization_invitation(
        &self,
        invitation_id: &str,
        principal_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationInvitationRecord>;
}

/// Request to create an organization invitation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOrganizationInvitationRequest {
    /// Owning tenant.
    pub tenant_id: String,
    /// Target organization.
    pub organization_id: String,
    /// Optional project assignment.
    pub project_id: Option<String>,
    /// Optional invited email target.
    pub invited_email: Option<String>,
    /// Optional invited principal target.
    pub invited_principal_id: Option<String>,
    /// Hash of the raw invitation token.
    pub invitation_token_hash: String,
    /// Requested role id.
    pub role_id: String,
    /// Expiry timestamp.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Creating actor.
    pub created_by: String,
}

/// Secret reference admin repository boundary.
pub trait SecretRefAdminRepository: Send + Sync {
    /// Creates a secret reference and stores the secret material in the configured backend.
    fn create_secret_ref(
        &self,
        request: CreateSecretRefRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<SecretRefRecord>;

    /// Lists secret references in a tenant.
    fn secret_refs_for_tenant(&self, tenant_id: &str) -> Vec<SecretRefRecord>;

    /// Loads secret reference metadata.
    fn secret_ref(&self, secret_ref_id: &str) -> Option<SecretRefRecord>;

    /// Resolves secret material for runtime use.
    fn secret_value(&self, secret_ref_id: &str) -> Option<SecretString>;
}

/// Provider and upstream credential admin repository boundary.
pub trait ProviderAdminRepository: Send + Sync {
    /// Creates a provider endpoint.
    fn create_provider_endpoint(
        &self,
        request: CreateProviderEndpointRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderEndpointRecord>;

    /// Lists provider endpoints in a tenant.
    fn provider_endpoints_for_tenant(&self, tenant_id: &str) -> Vec<ProviderEndpointRecord>;

    /// Loads provider endpoint metadata.
    fn provider_endpoint(&self, provider_endpoint_id: &str) -> Option<ProviderEndpointRecord>;

    /// Updates provider endpoint status with optimistic concurrency.
    fn update_provider_endpoint_status(
        &self,
        provider_endpoint_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderEndpointRecord>;

    /// Creates an upstream credential.
    fn create_upstream_credential(
        &self,
        request: CreateUpstreamCredentialRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UpstreamCredentialRecord>;

    /// Lists upstream credentials in a tenant.
    fn upstream_credentials_for_tenant(&self, tenant_id: &str) -> Vec<UpstreamCredentialRecord>;

    /// Loads upstream credential metadata.
    fn upstream_credential(&self, upstream_credential_id: &str)
        -> Option<UpstreamCredentialRecord>;

    /// Updates upstream credential status with optimistic concurrency.
    fn update_upstream_credential_status(
        &self,
        upstream_credential_id: &str,
        expected_resource_version: i64,
        status: UpstreamCredentialStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UpstreamCredentialRecord>;
}

/// Model catalog admin repository boundary.
pub trait CatalogAdminRepository: Send + Sync {
    /// Creates a model target.
    fn create_model_target(
        &self,
        request: CreateModelTargetRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelTargetRecord>;

    /// Lists model targets in a tenant.
    fn model_targets_for_tenant(&self, tenant_id: &str) -> Vec<ModelTargetRecord>;

    /// Loads model target metadata.
    fn model_target(&self, model_target_id: &str) -> Option<ModelTargetRecord>;

    /// Updates model target status with optimistic concurrency.
    fn update_model_target_status(
        &self,
        model_target_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelTargetRecord>;

    /// Creates a routing group.
    fn create_routing_group(
        &self,
        request: CreateRoutingGroupRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupRecord>;

    /// Lists routing groups in a tenant.
    fn routing_groups_for_tenant(&self, tenant_id: &str) -> Vec<RoutingGroupRecord>;

    /// Loads routing group metadata.
    fn routing_group(&self, routing_group_id: &str) -> Option<RoutingGroupRecord>;

    /// Updates routing group status with optimistic concurrency.
    fn update_routing_group_status(
        &self,
        routing_group_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupRecord>;

    /// Creates a routing group target membership.
    fn create_routing_group_target(
        &self,
        request: CreateRoutingGroupTargetRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupTargetRecord>;

    /// Lists routing group target memberships for a group.
    fn routing_group_targets_for_group(
        &self,
        tenant_id: &str,
        routing_group_id: &str,
    ) -> Vec<RoutingGroupTargetRecord>;

    /// Loads routing group target membership metadata.
    fn routing_group_target(
        &self,
        routing_group_target_id: &str,
    ) -> Option<RoutingGroupTargetRecord>;

    /// Updates routing group target status with optimistic concurrency.
    fn update_routing_group_target_status(
        &self,
        routing_group_target_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupTargetRecord>;

    /// Creates a model alias.
    fn create_model_alias(
        &self,
        request: CreateModelAliasRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelAliasRecord>;

    /// Lists model aliases in a tenant.
    fn model_aliases_for_tenant(&self, tenant_id: &str) -> Vec<ModelAliasRecord>;

    /// Loads model alias metadata.
    fn model_alias(&self, model_alias_id: &str) -> Option<ModelAliasRecord>;

    /// Updates model alias status or route policy binding with optimistic concurrency.
    fn update_model_alias(
        &self,
        model_alias_id: &str,
        request: UpdateModelAliasRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelAliasRecord>;

    /// Creates a route policy.
    fn create_route_policy(
        &self,
        request: CreateRoutePolicyRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutePolicyRecord>;

    /// Lists route policies in a tenant.
    fn route_policies_for_tenant(&self, tenant_id: &str) -> Vec<RoutePolicyRecord>;

    /// Loads route policy metadata.
    fn route_policy(&self, route_policy_id: &str) -> Option<RoutePolicyRecord>;

    /// Updates route policy status with optimistic concurrency.
    fn update_route_policy_status(
        &self,
        route_policy_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutePolicyRecord>;

    /// Creates a provider grant.
    fn create_provider_grant(
        &self,
        request: CreateProviderGrantRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderGrantRecord>;

    /// Lists provider grants in a tenant.
    fn provider_grants_for_tenant(&self, tenant_id: &str) -> Vec<ProviderGrantRecord>;

    /// Loads provider grant metadata.
    fn provider_grant(&self, provider_grant_id: &str) -> Option<ProviderGrantRecord>;

    /// Updates provider grant status with optimistic concurrency.
    fn update_provider_grant_status(
        &self,
        provider_grant_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderGrantRecord>;

    /// Creates a pricing SKU.
    fn create_pricing_sku(
        &self,
        request: CreatePricingSkuRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PricingSkuRecord>;

    /// Lists pricing SKUs in a tenant.
    fn pricing_skus_for_tenant(&self, tenant_id: &str) -> Vec<PricingSkuRecord>;

    /// Loads pricing SKU metadata.
    fn pricing_sku(&self, pricing_sku_id: &str) -> Option<PricingSkuRecord>;

    /// Updates pricing SKU status with optimistic concurrency.
    fn update_pricing_sku_status(
        &self,
        pricing_sku_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PricingSkuRecord>;

    /// Creates a budget policy.
    fn create_budget_policy(
        &self,
        request: CreateBudgetPolicyRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<BudgetPolicyRecord>;

    /// Lists budget policies in a tenant.
    fn budget_policies_for_tenant(&self, tenant_id: &str) -> Vec<BudgetPolicyRecord>;

    /// Loads budget policy metadata.
    fn budget_policy(&self, budget_policy_id: &str) -> Option<BudgetPolicyRecord>;

    /// Updates budget policy status with optimistic concurrency.
    fn update_budget_policy_status(
        &self,
        budget_policy_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<BudgetPolicyRecord>;

    /// Creates a quota policy.
    fn create_quota_policy(
        &self,
        request: CreateQuotaPolicyRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<QuotaPolicyRecord>;

    /// Lists quota policies in a tenant.
    fn quota_policies_for_tenant(&self, tenant_id: &str) -> Vec<QuotaPolicyRecord>;

    /// Loads quota policy metadata.
    fn quota_policy(&self, quota_policy_id: &str) -> Option<QuotaPolicyRecord>;

    /// Updates quota policy status with optimistic concurrency.
    fn update_quota_policy_status(
        &self,
        quota_policy_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<QuotaPolicyRecord>;

    /// Creates an OpenTelemetry export config.
    fn create_otel_export_config(
        &self,
        request: CreateOtelExportConfigRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExportConfigRecord>;

    /// Lists OpenTelemetry export configs in a tenant.
    fn otel_export_configs_for_tenant(&self, tenant_id: &str) -> Vec<OtelExportConfigRecord>;

    /// Loads OpenTelemetry export config metadata.
    fn otel_export_config(&self, otel_export_config_id: &str) -> Option<OtelExportConfigRecord>;

    /// Updates OpenTelemetry export config status with optimistic concurrency.
    fn update_otel_export_config_status(
        &self,
        otel_export_config_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExportConfigRecord>;

    /// Updates OpenTelemetry export config shape with optimistic concurrency.
    fn update_otel_export_config(
        &self,
        otel_export_config_id: &str,
        request: UpdateOtelExportConfigRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExportConfigRecord>;

    /// Records the latest exporter health for one config.
    fn record_otel_exporter_health(
        &self,
        request: RecordOtelExporterHealthRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExporterHealthRecord>;

    /// Loads exporter health for one config.
    fn otel_exporter_health(&self, otel_export_config_id: &str)
        -> Option<OtelExporterHealthRecord>;

    /// Lists exporter health records in one tenant.
    fn otel_exporter_health_for_tenant(&self, tenant_id: &str) -> Vec<OtelExporterHealthRecord>;

    /// Creates a notification sink.
    fn create_notification_sink(
        &self,
        request: CreateNotificationSinkRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSinkRecord>;

    /// Lists notification sinks in a tenant.
    fn notification_sinks_for_tenant(&self, tenant_id: &str) -> Vec<NotificationSinkRecord>;

    /// Loads notification sink metadata.
    fn notification_sink(&self, notification_sink_id: &str) -> Option<NotificationSinkRecord>;

    /// Updates notification sink configuration with optimistic concurrency.
    fn update_notification_sink(
        &self,
        notification_sink_id: &str,
        request: UpdateNotificationSinkRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSinkRecord>;

    /// Creates a notification subscription.
    fn create_notification_subscription(
        &self,
        request: CreateNotificationSubscriptionRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSubscriptionRecord>;

    /// Lists notification subscriptions for a sink.
    fn notification_subscriptions_for_sink(
        &self,
        notification_sink_id: &str,
    ) -> Vec<NotificationSubscriptionRecord>;

    /// Loads notification subscription metadata.
    fn notification_subscription(
        &self,
        notification_subscription_id: &str,
    ) -> Option<NotificationSubscriptionRecord>;

    /// Updates notification subscription status with optimistic concurrency.
    fn update_notification_subscription_status(
        &self,
        notification_subscription_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSubscriptionRecord>;

    /// Creates a human login provider config.
    fn create_login_provider(
        &self,
        request: CreateLoginProviderRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<LoginProviderRecord>;

    /// Lists human login providers in a tenant.
    fn login_providers_for_tenant(&self, tenant_id: &str) -> Vec<LoginProviderRecord>;

    /// Loads human login provider metadata.
    fn login_provider(&self, login_provider_id: &str) -> Option<LoginProviderRecord>;

    /// Updates login provider status with optimistic concurrency.
    fn update_login_provider_status(
        &self,
        login_provider_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<LoginProviderRecord>;
}

/// Request to idempotently create a default tenant project graph.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BootstrapDefaultProjectRequest {
    /// Tenant id.
    pub tenant_id: String,
    /// Tenant display name.
    pub tenant_display_name: String,
    /// Organization id.
    pub organization_id: String,
    /// Organization display name.
    pub organization_display_name: String,
    /// Project id.
    pub project_id: String,
    /// Project display name.
    pub project_display_name: String,
    /// User id.
    pub user_id: String,
    /// User display name.
    pub user_display_name: String,
    /// User primary email.
    pub user_primary_email: Option<String>,
    /// Organization membership id.
    pub organization_member_id: String,
    /// Project membership id.
    pub project_member_id: String,
    /// Creating actor id.
    pub created_by: String,
}

/// Request to create or reactivate a project membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProjectMembershipRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Organization boundary.
    pub organization_id: String,
    /// Project boundary.
    pub project_id: String,
    /// Principal receiving project membership.
    pub principal_id: String,
    /// Parent active organization membership id.
    pub organization_member_id: String,
}

/// Request to create a provider endpoint admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProviderEndpointRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Provider kind.
    pub provider_kind: String,
    /// Admin-visible display name.
    pub display_name: String,
    /// Supported protocol families.
    pub protocol_families: Vec<crate::ProtocolFamily>,
    /// Provider-facing base URL.
    pub upstream_base_url: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a secret reference admin resource.
#[derive(Clone, Debug)]
pub struct CreateSecretRefRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Operator-visible purpose for the secret.
    pub purpose: String,
    /// Secret backend kind.
    pub backend_kind: String,
    /// Raw secret value to store in the backend.
    pub secret_value: SecretString,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create an upstream credential admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUpstreamCredentialRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Referenced provider endpoint.
    pub provider_endpoint_id: String,
    /// Credential kind.
    pub credential_kind: String,
    /// Safe secret reference id.
    pub secret_ref_id: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a Codex upstream OAuth connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateCodexOAuthConnectionRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Compatible Codex provider endpoint.
    pub provider_endpoint_id: String,
    /// Admin-visible display name.
    pub display_name: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to start a Codex upstream OAuth session from stored token material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StartCodexOAuthSessionRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Parent Codex OAuth connection.
    pub codex_oauth_connection_id: String,
    /// Secret ref that stores the token bundle.
    pub token_secret_ref_id: String,
    /// Token expiry when known.
    pub token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Creating actor.
    pub created_by: String,
}

/// Codex upstream OAuth repository boundary.
pub trait CodexOAuthRepository: Send + Sync {
    /// Creates a Codex OAuth connection.
    fn create_codex_oauth_connection(
        &self,
        request: CreateCodexOAuthConnectionRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthConnectionRecord>;

    /// Lists Codex OAuth connections in a tenant.
    fn codex_oauth_connections_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<CodexOAuthConnectionRecord>;

    /// Loads Codex OAuth connection metadata.
    fn codex_oauth_connection(
        &self,
        codex_oauth_connection_id: &str,
    ) -> Option<CodexOAuthConnectionRecord>;

    /// Updates Codex OAuth connection status.
    fn update_codex_oauth_connection_status(
        &self,
        codex_oauth_connection_id: &str,
        expected_resource_version: i64,
        status: CodexOAuthConnectionStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthConnectionRecord>;

    /// Starts a Codex OAuth session and creates the matching upstream credential.
    fn start_codex_oauth_session(
        &self,
        request: StartCodexOAuthSessionRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthSessionRecord>;

    /// Lists Codex OAuth sessions for a connection.
    fn codex_oauth_sessions_for_connection(
        &self,
        tenant_id: &str,
        codex_oauth_connection_id: &str,
    ) -> Vec<CodexOAuthSessionRecord>;

    /// Loads Codex OAuth session metadata.
    fn codex_oauth_session(&self, codex_oauth_session_id: &str) -> Option<CodexOAuthSessionRecord>;

    /// Revokes a Codex OAuth session.
    fn revoke_codex_oauth_session(
        &self,
        codex_oauth_session_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthSessionRecord>;

    /// Reads safe Codex OAuth refresh status metadata.
    fn codex_oauth_refresh_status(
        &self,
        tenant_id: &str,
        codex_oauth_connection_id: &str,
    ) -> Option<CodexOAuthRefreshStatusRecord>;
}

/// Request to create a model target admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateModelTargetRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Referenced provider endpoint.
    pub provider_endpoint_id: String,
    /// Optional upstream credential.
    pub upstream_credential_id: Option<String>,
    /// Target protocol family.
    pub protocol_family: crate::ProtocolFamily,
    /// Provider model id sent upstream.
    pub upstream_model_id: String,
    /// Whether this target can serve streaming requests.
    pub supports_streaming: bool,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a routing group admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRoutingGroupRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Unique group name within the tenant and optional organization boundary.
    pub name: String,
    /// Required target protocol family.
    pub protocol_family: crate::ProtocolFamily,
    /// Human-readable operator purpose.
    pub purpose: Option<String>,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a routing group target membership admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRoutingGroupTargetRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Referenced routing group.
    pub routing_group_id: String,
    /// Referenced model target.
    pub model_target_id: String,
    /// Relative selection weight.
    pub weight: u32,
    /// Lower priority is tried first.
    pub priority: u32,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a model alias admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateModelAliasRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Client-visible model name.
    pub alias_name: String,
    /// Required ingress protocol family.
    pub protocol_family: crate::ProtocolFamily,
    /// Optional default route policy.
    pub route_policy_id: Option<String>,
    /// Creating actor.
    pub created_by: String,
}

/// Request to update a model alias admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateModelAliasRequest {
    /// Expected resource version.
    pub expected_resource_version: i64,
    /// Optional status update.
    pub status: Option<ResourceStatus>,
    /// Optional route policy binding update.
    pub route_policy_id: Option<String>,
}

/// Request to create a route policy admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRoutePolicyRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Unique policy name within the tenant and optional organization boundary.
    pub name: String,
    /// Bound model alias.
    pub model_alias_id: String,
    /// Primary routing group.
    pub routing_group_id: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a provider grant admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProviderGrantRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Grant scope kind.
    pub scope_kind: String,
    /// Grant scope id.
    pub scope_id: String,
    /// Granted or denied resource kind.
    pub resource_kind: String,
    /// Granted or denied resource id.
    pub resource_id: String,
    /// Grant effect.
    pub effect: String,
    /// Closure mode for graph expansion.
    pub closure_mode: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a pricing SKU admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatePricingSkuRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Admin-visible SKU name.
    pub name: String,
    /// ISO currency code.
    pub currency: String,
    /// Fixed-point unit.
    pub unit: String,
    /// Model id patterns this SKU can match.
    pub model_id_patterns: Vec<String>,
    /// Optional provider endpoint selectors.
    pub provider_endpoint_patterns: Vec<String>,
    /// Versioned pricing document.
    pub pricing_document: Value,
    /// Effective start timestamp.
    pub effective_from: chrono::DateTime<chrono::Utc>,
    /// Optional effective end timestamp.
    pub effective_until: Option<chrono::DateTime<chrono::Utc>>,
    /// Whether this SKU is a shipped preset.
    pub is_preset: bool,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a budget policy admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateBudgetPolicyRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Budget scope kind.
    pub scope_kind: String,
    /// Budget scope id.
    pub scope_id: String,
    /// Cost currency when the budget is cost-based.
    pub currency: Option<String>,
    /// Budget period.
    pub period: String,
    /// Limit kind.
    pub limit_kind: String,
    /// Optional hard block threshold.
    pub hard_limit: Option<i64>,
    /// Optional soft notification threshold.
    pub soft_limit: Option<i64>,
    /// Additional notification thresholds.
    pub thresholds: Vec<i64>,
    /// Reset policy label.
    pub reset_policy: String,
    /// Overage behavior.
    pub overage_mode: String,
    /// Consistency behavior for hard budget state.
    pub consistency_mode: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create a quota policy admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateQuotaPolicyRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Quota scope kind.
    pub scope_kind: String,
    /// Quota scope id.
    pub scope_id: String,
    /// Counter behavior controlled by this policy.
    pub counter_kind: String,
    /// Hard quota limit.
    pub limit: i64,
    /// Optional bounded allowance used by fail-limited behavior.
    pub burst_limit: Option<i64>,
    /// Counter window kind.
    pub window: String,
    /// Source event that increments or reserves this counter.
    pub increment_source: String,
    /// Hot-state loss behavior.
    pub loss_behavior: String,
    /// Creating actor.
    pub created_by: String,
}

/// Request to create an export job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateExportJobRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Export data family.
    pub export_kind: String,
    /// Creating actor.
    pub requested_by: String,
    /// Redacted query shape.
    pub query_document: Value,
}

/// Request to complete an export job with one manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteExportJobRequest {
    /// Terminal export job status.
    pub status: String,
    /// Object-storage reference.
    pub object_ref: String,
    /// Number of records in the export payload.
    pub record_count: i64,
    /// Byte size of the export payload.
    pub byte_count: i64,
    /// Deterministic payload checksum.
    pub checksum: String,
    /// Redacted manifest document.
    pub manifest_document: Value,
    /// Manifest expiration timestamp.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create emergency operation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateEmergencyOperationRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Emergency operation kind.
    pub operation_kind: String,
    /// Target resource kind.
    pub target_resource_kind: String,
    /// Target resource id.
    pub target_resource_id: String,
    /// Creating actor.
    pub requested_by: String,
    /// Safe operator reason.
    pub reason: String,
    /// Operator alert evidence.
    pub operator_alert_document: Value,
    /// Emergency review or expiry timestamp.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Request to create an OpenTelemetry export config admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateOtelExportConfigRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
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
    /// Creating actor.
    pub created_by: String,
}

/// Request to update an OpenTelemetry export config admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateOtelExportConfigRequest {
    /// Expected resource version.
    pub expected_resource_version: i64,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Optional collector endpoint URL.
    pub endpoint_url: Option<String>,
    /// Optional export protocol.
    pub protocol: Option<String>,
    /// Optional secret-backed collector headers.
    pub header_refs: Option<Vec<OtelHeaderRef>>,
    /// Optional enabled telemetry signals.
    pub enabled_signals: Option<Vec<String>>,
    /// Optional bounded static resource attributes.
    pub resource_attributes: Option<Vec<OtelResourceAttribute>>,
    /// Optional export interval in seconds.
    pub export_interval_seconds: Option<i64>,
    /// Optional export timeout in seconds.
    pub timeout_seconds: Option<i64>,
    /// Optional lifecycle status.
    pub status: Option<ResourceStatus>,
}

/// Request to record OpenTelemetry exporter health.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordOtelExporterHealthRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Parent OpenTelemetry export config.
    pub otel_export_config_id: String,
    /// Worker role or instance id.
    pub worker_id: String,
    /// Health status.
    pub status: String,
    /// Metrics exported by the attempt.
    pub exported_metric_count: i64,
    /// Metrics dropped by the attempt.
    pub dropped_metric_count: i64,
    /// Safe last error code or message.
    pub last_error: Option<String>,
}

/// Request to create a notification sink admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateNotificationSinkRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Admin-visible sink name.
    pub name: String,
    /// Sink kind.
    pub sink_kind: String,
    /// Redacted endpoint configuration.
    pub endpoint_config: Value,
    /// Optional signing secret reference.
    pub signing_secret_ref_id: Option<String>,
    /// Creating actor.
    pub created_by: String,
}

/// Nullable patch field that distinguishes omitted, explicit null, and value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum NullablePatch<T> {
    /// Field was not present in the patch request.
    #[default]
    Unset,
    /// Field was present and should replace the current value.
    Set(Option<T>),
}

impl<T> NullablePatch<T> {
    /// Resolves this patch field against the current stored value.
    pub fn resolve(self, current: Option<T>) -> Option<T> {
        match self {
            Self::Unset => current,
            Self::Set(value) => value,
        }
    }
}

impl<'de, T> Deserialize<'de> for NullablePatch<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self::Set)
    }
}

/// Request to update a notification sink admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateNotificationSinkRequest {
    /// Expected resource version.
    pub expected_resource_version: i64,
    /// Replacement display name.
    pub name: Option<String>,
    /// Replacement endpoint configuration.
    pub endpoint_config: Option<Value>,
    /// Replacement signing secret reference.
    pub signing_secret_ref_id: NullablePatch<String>,
    /// Replacement lifecycle status.
    pub status: Option<ResourceStatus>,
}

/// Request to create a notification subscription admin resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateNotificationSubscriptionRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Sink that receives matching events.
    pub notification_sink_id: String,
    /// Notification event family.
    pub event_family: String,
    /// Safe filter document.
    pub filter_document: Value,
    /// Creating actor.
    pub created_by: String,
}

/// Request to append a notification outbox event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateNotificationOutboxEventRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Matched subscription when present.
    pub notification_subscription_id: Option<String>,
    /// Matched sink when present.
    pub notification_sink_id: Option<String>,
    /// Stable event kind.
    pub event_kind: String,
    /// Tenant-local idempotency key.
    pub dedupe_key: String,
    /// Redacted event payload.
    pub payload_document: Value,
    /// First attempt schedule.
    pub next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request to record a notification delivery attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateNotificationDeliveryAttemptRequest {
    /// Parent outbox event id.
    pub notification_outbox_event_id: String,
    /// Delivery sink when present.
    pub notification_sink_id: Option<String>,
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
    pub delivery_headers: Value,
    /// Next retry timestamp when retryable.
    pub next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request to create a human login provider config.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateLoginProviderRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Provider adapter kind.
    pub provider_kind: String,
    /// Admin-visible display name.
    pub display_name: String,
    /// Safe provider configuration document.
    pub config_document: Value,
    /// Creating actor.
    pub created_by: String,
}

/// Request to persist a one-time external login attempt.
#[derive(Clone, Debug)]
pub struct CreateLoginAttemptRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Login provider id.
    pub login_provider_id: String,
    /// Provider adapter kind.
    pub provider_kind: String,
    /// Hash of the raw OAuth/OIDC state value.
    pub state_hash: String,
    /// Hash of the raw OIDC nonce when present.
    pub nonce_hash: Option<String>,
    /// Hash of the raw PKCE code verifier.
    pub code_verifier_hash: String,
    /// Short-lived raw PKCE code verifier for the token exchange.
    pub code_verifier: SecretString,
    /// Public PKCE S256 challenge sent to the provider.
    pub code_challenge: String,
    /// Redirect URI used for this attempt.
    pub redirect_uri: String,
    /// Attempt expiry.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Consumed one-time external login attempt and its short-lived verifier.
#[derive(Clone, Debug)]
pub struct ConsumedLoginAttempt {
    /// Durable attempt metadata.
    pub record: LoginAttemptRecord,
    /// Raw PKCE verifier used once for the provider token exchange.
    pub code_verifier: SecretString,
}

/// Request to create or update a local user from validated external login claims.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpsertExternalLoginIdentityRequest {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Login provider id.
    pub login_provider_id: String,
    /// Provider adapter kind.
    pub provider_kind: String,
    /// Stable provider subject.
    pub provider_subject: String,
    /// Last observed normalized email.
    pub email: Option<String>,
    /// Whether the provider asserted email verification.
    pub email_verified: bool,
    /// Display name for a newly created user.
    pub display_name: String,
}

/// Stored idempotent admin mutation response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdempotencyRecord {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Operation-local idempotency key.
    pub scope_key: String,
    /// Stable hash of the request body.
    pub request_hash: String,
    /// Serialized response from the first successful execution.
    pub response_record: Value,
    /// Expiry time for the replay window.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// In-memory repository used by tests and local skeleton wiring.
#[derive(Clone, Debug, Default)]
pub struct InMemoryGatewayStore {
    tenants: Arc<RwLock<HashMap<String, TenantRecord>>>,
    organizations: Arc<RwLock<HashMap<String, OrganizationRecord>>>,
    projects: Arc<RwLock<HashMap<String, ProjectRecord>>>,
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
    external_identities: Arc<RwLock<HashMap<String, ExternalIdentityRecord>>>,
    service_accounts: Arc<RwLock<HashMap<String, ServiceAccountRecord>>>,
    organization_memberships: Arc<RwLock<HashMap<(String, String), OrganizationMembershipRecord>>>,
    organization_invitations: Arc<RwLock<HashMap<String, OrganizationInvitationRecord>>>,
    api_keys: Arc<RwLock<HashMap<String, Vec<ApiKeyRecord>>>>,
    api_key_failed_auth: Arc<RwLock<HashMap<String, Vec<chrono::DateTime<chrono::Utc>>>>>,
    api_key_last_used_updates: Arc<RwLock<Vec<ApiKeyLastUsedUpdate>>>,
    auth_sessions: Arc<RwLock<HashMap<String, AuthSessionRecord>>>,
    login_attempts: Arc<RwLock<HashMap<String, LoginAttemptRecord>>>,
    login_attempt_code_verifiers: Arc<RwLock<HashMap<String, SecretString>>>,
    project_memberships: Arc<RwLock<HashMap<(String, String), ProjectMembershipRecord>>>,
    latest_snapshot: Arc<RwLock<Option<ConfigSnapshot>>>,
    config_snapshots: Arc<RwLock<Vec<PublishedConfigSnapshot>>>,
    config_publications: Arc<RwLock<HashMap<String, ConfigPublicationPointerRecord>>>,
    config_invalidations: Arc<RwLock<Vec<ConfigInvalidationEventRecord>>>,
    config_worker_reloads: Arc<RwLock<HashMap<(String, String), ConfigWorkerReloadRecord>>>,
    validation_diagnostics: Arc<RwLock<Vec<ValidationDiagnosticRecord>>>,
    usage_events: Arc<RwLock<Vec<UsageEventRecord>>>,
    ledger_buckets: Arc<RwLock<HashMap<String, LedgerBucketRecord>>>,
    runtime_quota_counters: Arc<RwLock<HashMap<String, i64>>>,
    runtime_policy_hot_state_unavailable: Arc<RwLock<bool>>,
    runtime_policy_loss_allowances: Arc<RwLock<HashMap<String, i64>>>,
    runtime_budget_leases: Arc<RwLock<HashMap<String, RuntimeBudgetLeaseRecord>>>,
    authz_decisions: Arc<RwLock<Vec<AuthorizationDecisionRecord>>>,
    action_grants: Arc<RwLock<Vec<ActionGrant>>>,
    route_decisions: Arc<RwLock<Vec<RouteDecisionRecord>>>,
    route_attempts: Arc<RwLock<Vec<RouteAttemptRecord>>>,
    endpoint_health: Arc<RwLock<HashMap<(String, String), EndpointHealthRecord>>>,
    endpoint_drains: Arc<RwLock<HashMap<(String, String), EndpointDrainRecord>>>,
    sticky_routes: Arc<RwLock<HashMap<StickyRouteKey, StickyRouteRecord>>>,
    audit_events: Arc<RwLock<Vec<AuditEventRecord>>>,
    idempotency_records: Arc<RwLock<HashMap<(String, String), IdempotencyRecord>>>,
    provider_endpoints: Arc<RwLock<HashMap<String, ProviderEndpointRecord>>>,
    secret_refs: Arc<RwLock<HashMap<String, SecretRefRecord>>>,
    secret_values: Arc<RwLock<HashMap<String, SecretString>>>,
    upstream_credentials: Arc<RwLock<HashMap<String, UpstreamCredentialRecord>>>,
    codex_oauth_connections: Arc<RwLock<HashMap<String, CodexOAuthConnectionRecord>>>,
    codex_oauth_sessions: Arc<RwLock<HashMap<String, CodexOAuthSessionRecord>>>,
    model_targets: Arc<RwLock<HashMap<String, ModelTargetRecord>>>,
    routing_groups: Arc<RwLock<HashMap<String, RoutingGroupRecord>>>,
    routing_group_targets: Arc<RwLock<HashMap<String, RoutingGroupTargetRecord>>>,
    model_aliases: Arc<RwLock<HashMap<String, ModelAliasRecord>>>,
    route_policies: Arc<RwLock<HashMap<String, RoutePolicyRecord>>>,
    provider_grants: Arc<RwLock<HashMap<String, ProviderGrantRecord>>>,
    pricing_skus: Arc<RwLock<HashMap<String, PricingSkuRecord>>>,
    budget_policies: Arc<RwLock<HashMap<String, BudgetPolicyRecord>>>,
    quota_policies: Arc<RwLock<HashMap<String, QuotaPolicyRecord>>>,
    otel_export_configs: Arc<RwLock<HashMap<String, OtelExportConfigRecord>>>,
    otel_exporter_health: Arc<RwLock<HashMap<String, OtelExporterHealthRecord>>>,
    notification_sinks: Arc<RwLock<HashMap<String, NotificationSinkRecord>>>,
    notification_subscriptions: Arc<RwLock<HashMap<String, NotificationSubscriptionRecord>>>,
    notification_outbox_events: Arc<RwLock<HashMap<String, NotificationOutboxEventRecord>>>,
    notification_delivery_attempts: Arc<RwLock<Vec<NotificationDeliveryAttemptRecord>>>,
    export_jobs: Arc<RwLock<HashMap<String, ExportJobRecord>>>,
    export_manifests: Arc<RwLock<HashMap<String, ExportManifestRecord>>>,
    emergency_operations: Arc<RwLock<HashMap<String, EmergencyOperationRecord>>>,
    login_providers: Arc<RwLock<HashMap<String, LoginProviderRecord>>>,
}

impl InMemoryGatewayStore {
    /// Sets runtime policy hot-state availability for tests and local fault injection.
    pub fn set_runtime_policy_hot_state_available(&self, available: bool) {
        *write_lock(&self.runtime_policy_hot_state_unavailable) = !available;
    }

    /// Inserts an API key record into the prefix index.
    pub fn insert_api_key(&self, record: ApiKeyRecord) {
        let mut api_keys = match self.api_keys.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        api_keys
            .entry(record.key_prefix.clone())
            .or_default()
            .push(record);
    }

    /// Loads an API key by stable id.
    #[must_use]
    pub fn api_key(&self, api_key_id: &str) -> Option<ApiKeyRecord> {
        let api_keys = match self.api_keys.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        api_keys
            .values()
            .flat_map(|records| records.iter())
            .find(|record| record.api_key_id == api_key_id)
            .cloned()
    }

    /// Returns queued API key last-used updates.
    #[must_use]
    pub fn api_key_last_used_updates(&self) -> Vec<ApiKeyLastUsedUpdate> {
        let updates = match self.api_key_last_used_updates.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        updates.clone()
    }

    /// Returns the current failed-auth counter for a throttle key.
    #[must_use]
    pub fn failed_api_key_auth_count(
        &self,
        throttle_key: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> usize {
        let mut failed_auth = match self.api_key_failed_auth.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        retain_fresh_failed_auth(failed_auth.entry(throttle_key.to_owned()).or_default(), now);
        failed_auth.get(throttle_key).map_or(0, Vec::len)
    }

    /// Inserts or replaces an auth session by session hash.
    pub fn insert_auth_session(&self, record: AuthSessionRecord) {
        let mut auth_sessions = match self.auth_sessions.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        auth_sessions.insert(record.session_hash.clone(), record);
    }

    /// Inserts or replaces an external identity by id.
    pub fn insert_external_identity(&self, record: ExternalIdentityRecord) {
        write_lock(&self.external_identities).insert(record.external_identity_id.clone(), record);
    }

    /// Persists one one-time external login attempt by state hash.
    pub fn create_login_attempt(
        &self,
        request: CreateLoginAttemptRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<LoginAttemptRecord> {
        let record = LoginAttemptRecord {
            login_attempt_id: new_prefixed_id("lat"),
            tenant_id: request.tenant_id,
            login_provider_id: request.login_provider_id,
            provider_kind: request.provider_kind,
            state_hash: request.state_hash,
            nonce_hash: request.nonce_hash,
            code_verifier_hash: request.code_verifier_hash,
            code_challenge: request.code_challenge,
            redirect_uri: request.redirect_uri,
            status: "pending".to_owned(),
            expires_at: request.expires_at,
            consumed_at: None,
            created_at: now,
            updated_at: now,
        };
        let mut attempts = write_lock(&self.login_attempts);
        if attempts.contains_key(&record.state_hash) {
            return Err(GatewayError::BadRequest {
                message: "login_attempt_state_conflict".to_owned(),
            });
        }
        let state_hash = record.state_hash.clone();
        attempts.insert(record.state_hash.clone(), record.clone());
        drop(attempts);
        write_lock(&self.login_attempt_code_verifiers).insert(state_hash, request.code_verifier);
        Ok(record)
    }

    /// Consumes one pending external login attempt by state hash.
    pub fn consume_login_attempt(
        &self,
        state_hash: &str,
        login_provider_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ConsumedLoginAttempt> {
        let mut attempts = write_lock(&self.login_attempts);
        let Some(attempt) = attempts.get_mut(state_hash) else {
            return Err(GatewayError::Authentication);
        };
        if attempt.login_provider_id != login_provider_id
            || attempt.status != "pending"
            || attempt.expires_at <= now
        {
            return Err(GatewayError::Authentication);
        }
        "consumed".clone_into(&mut attempt.status);
        attempt.consumed_at = Some(now);
        attempt.updated_at = now;
        let consumed = attempt.clone();
        drop(attempts);
        let code_verifier = write_lock(&self.login_attempt_code_verifiers)
            .remove(state_hash)
            .ok_or(GatewayError::Authentication)?;
        Ok(ConsumedLoginAttempt {
            record: consumed,
            code_verifier,
        })
    }

    /// Creates or updates the local user and external identity for validated claims.
    pub fn upsert_external_login_identity(
        &self,
        request: UpsertExternalLoginIdentityRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(UserRecord, ExternalIdentityRecord, bool)> {
        upsert_external_login_identity(self, request, now)
    }

    /// Lists organization memberships for one principal.
    #[must_use]
    pub fn organization_memberships_for_principal(
        &self,
        principal_id: &str,
    ) -> Vec<OrganizationMembershipRecord> {
        let mut memberships = read_lock(&self.organization_memberships)
            .values()
            .filter(|membership| membership.principal_id == principal_id)
            .cloned()
            .collect::<Vec<_>>();
        memberships.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| {
                    left.organization_member_id
                        .cmp(&right.organization_member_id)
                })
        });
        memberships
    }

    /// Lists project memberships for one principal.
    #[must_use]
    pub fn project_memberships_for_principal(
        &self,
        principal_id: &str,
    ) -> Vec<ProjectMembershipRecord> {
        let mut memberships = read_lock(&self.project_memberships)
            .values()
            .filter(|membership| membership.principal_id == principal_id)
            .cloned()
            .collect::<Vec<_>>();
        memberships.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| left.project_id.cmp(&right.project_id))
                .then_with(|| left.project_member_id.cmp(&right.project_member_id))
        });
        memberships
    }

    /// Stores the latest published snapshot.
    pub fn set_latest_snapshot(&self, snapshot: ConfigSnapshot) {
        let mut latest_snapshot = match self.latest_snapshot.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *latest_snapshot = Some(snapshot);
    }

    /// Inserts or replaces a project membership record.
    pub fn insert_project_membership(&self, record: ProjectMembershipRecord) {
        let mut project_memberships = match self.project_memberships.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        project_memberships.insert(
            (record.principal_id.clone(), record.project_id.clone()),
            record,
        );
    }

    /// Inserts an authorization grant for the foundation policy engine.
    pub fn insert_action_grant(&self, grant: ActionGrant) {
        let mut action_grants = match self.action_grants.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        action_grants.push(grant);
    }

    /// Returns foundation action grants.
    #[must_use]
    pub fn action_grants(&self) -> Vec<ActionGrant> {
        let action_grants = match self.action_grants.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        action_grants.clone()
    }

    /// Returns recorded authorization decisions.
    #[must_use]
    pub fn authorization_decisions(&self) -> Vec<AuthorizationDecisionRecord> {
        let authz_decisions = match self.authz_decisions.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        authz_decisions.clone()
    }

    /// Returns recorded route decisions.
    #[must_use]
    pub fn route_decisions(&self) -> Vec<RouteDecisionRecord> {
        let route_decisions = match self.route_decisions.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        route_decisions.clone()
    }

    /// Returns recorded route attempts.
    #[must_use]
    pub fn route_attempts(&self) -> Vec<RouteAttemptRecord> {
        let route_attempts = match self.route_attempts.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        route_attempts.clone()
    }

    /// Returns known tenant ids.
    #[must_use]
    pub fn tenant_ids(&self) -> Vec<String> {
        let mut tenant_ids = read_lock(&self.tenants).keys().cloned().collect::<Vec<_>>();
        tenant_ids.sort();
        tenant_ids
    }

    /// Returns all OpenTelemetry export configs.
    #[must_use]
    pub fn otel_export_config_records(&self) -> Vec<OtelExportConfigRecord> {
        let mut configs = read_lock(&self.otel_export_configs)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        configs.sort_by(|left, right| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then_with(|| left.otel_export_config_id.cmp(&right.otel_export_config_id))
        });
        configs
    }

    /// Returns all latest OpenTelemetry exporter health records.
    #[must_use]
    pub fn otel_exporter_health_records(&self) -> Vec<OtelExporterHealthRecord> {
        let mut records = read_lock(&self.otel_exporter_health)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.tenant_id
                .cmp(&right.tenant_id)
                .then_with(|| left.otel_export_config_id.cmp(&right.otel_export_config_id))
        });
        records
    }

    /// Inserts or replaces endpoint health hot state.
    pub fn set_endpoint_health(&self, record: EndpointHealthRecord) {
        let mut endpoint_health = match self.endpoint_health.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        endpoint_health.insert(
            (
                record.tenant_id.clone(),
                record.provider_endpoint_id.clone(),
            ),
            record,
        );
    }

    /// Inserts or replaces endpoint drain hot state.
    pub fn set_endpoint_drain(&self, record: EndpointDrainRecord) {
        let mut endpoint_drains = match self.endpoint_drains.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        endpoint_drains.insert(
            (
                record.tenant_id.clone(),
                record.provider_endpoint_id.clone(),
            ),
            record,
        );
    }

    /// Returns sticky route mappings for tests and local diagnostics.
    #[must_use]
    pub fn sticky_routes(&self) -> Vec<StickyRouteRecord> {
        read_lock(&self.sticky_routes).values().cloned().collect()
    }

    /// Returns immutable config snapshot history.
    #[must_use]
    pub fn config_snapshots(&self) -> Vec<PublishedConfigSnapshot> {
        let config_snapshots = match self.config_snapshots.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        config_snapshots.clone()
    }

    fn config_worker_reload(
        &self,
        tenant_id: &str,
        worker_id: &str,
    ) -> Option<ConfigWorkerReloadRecord> {
        read_lock(&self.config_worker_reloads)
            .get(&(tenant_id.to_owned(), worker_id.to_owned()))
            .cloned()
    }

    /// Returns recorded audit events.
    #[must_use]
    pub fn audit_events(&self) -> Vec<AuditEventRecord> {
        read_lock(&self.audit_events).clone()
    }

    /// Returns recorded audit events inside one tenant boundary.
    #[must_use]
    pub fn audit_events_for_tenant(&self, tenant_id: &str) -> Vec<AuditEventRecord> {
        read_lock(&self.audit_events)
            .iter()
            .filter(|event| event.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    /// Records an immutable audit event.
    pub fn record_audit_event(&self, record: AuditEventRecord) {
        write_lock(&self.audit_events).push(record);
    }

    /// Restores one secret reference with its backend value for backup rehearsal.
    pub fn restore_secret_ref(&self, record: SecretRefRecord, secret_value: SecretString) {
        let secret_ref_id = record.secret_ref_id.clone();
        write_lock(&self.secret_refs).insert(secret_ref_id.clone(), record);
        write_lock(&self.secret_values).insert(secret_ref_id, secret_value);
    }

    /// Returns a stored idempotent response, or rejects conflicting replays.
    pub fn idempotency_response(
        &self,
        tenant_id: &str,
        scope_key: &str,
        request_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<Value>> {
        let key = (tenant_id.to_owned(), scope_key.to_owned());
        let mut records = write_lock(&self.idempotency_records);
        let Some(record) = records.get(&key) else {
            return Ok(None);
        };
        if record.expires_at <= now {
            records.remove(&key);
            drop(records);
            return Ok(None);
        }
        if record.request_hash != request_hash {
            drop(records);
            return Err(GatewayError::BadRequest {
                message: "idempotency_key_conflict".to_owned(),
            });
        }
        let response = record.response_record.clone();
        drop(records);
        Ok(Some(response))
    }

    /// Stores an idempotent response for later replay.
    pub fn record_idempotency_response(&self, record: IdempotencyRecord) {
        write_lock(&self.idempotency_records)
            .insert((record.tenant_id.clone(), record.scope_key.clone()), record);
    }
}

impl ApiKeyRepository for InMemoryGatewayStore {
    fn candidates_by_prefix(&self, prefix: &str) -> Vec<ApiKeyRecord> {
        let api_keys = match self.api_keys.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        api_keys
            .get(prefix)
            .map(|records| {
                records
                    .iter()
                    .take(API_KEY_CANDIDATE_LIMIT)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    fn api_key_failed_auth_allowed(
        &self,
        throttle_key: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.failed_api_key_auth_count(throttle_key, now) < API_KEY_FAILED_AUTH_MAX_ATTEMPTS
    }

    fn record_api_key_failed_auth(&self, throttle_key: &str, now: chrono::DateTime<chrono::Utc>) {
        let mut failed_auth = match self.api_key_failed_auth.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let attempts = failed_auth.entry(throttle_key.to_owned()).or_default();
        retain_fresh_failed_auth(attempts, now);
        attempts.push(now);
        drop(failed_auth);
    }

    fn record_api_key_last_used(&self, update: ApiKeyLastUsedUpdate) {
        {
            let mut failed_auth = match self.api_key_failed_auth.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            failed_auth.remove(&update.key_prefix);
        }
        let mut updates = match self.api_key_last_used_updates.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        updates.push(update);
    }
}

impl ServiceAccountAdminRepository for InMemoryGatewayStore {
    fn create_service_account(
        &self,
        request: CreateServiceAccountRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ServiceAccountRecord> {
        let (organization_id, project_id) = validate_service_account_request(self, &request)?;
        let record = ServiceAccountRecord {
            service_account_id: crate::domain::new_prefixed_id("svc"),
            tenant_id: request.tenant_id,
            organization_id,
            project_id,
            display_name: request.display_name,
            status: DirectoryStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.service_accounts)
            .insert(record.service_account_id.clone(), record.clone());
        Ok(record)
    }

    fn service_accounts_for_tenant(&self, tenant_id: &str) -> Vec<ServiceAccountRecord> {
        let mut accounts = read_lock(&self.service_accounts)
            .values()
            .filter(|account| account.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        accounts.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| left.project_id.cmp(&right.project_id))
                .then_with(|| left.service_account_id.cmp(&right.service_account_id))
        });
        accounts
    }

    fn service_account(&self, service_account_id: &str) -> Option<ServiceAccountRecord> {
        read_lock(&self.service_accounts)
            .get(service_account_id)
            .cloned()
    }

    fn update_service_account_status(
        &self,
        service_account_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ServiceAccountRecord> {
        if !service_account_status_supported(&status) {
            return Err(GatewayError::BadRequest {
                message: "unsupported_service_account_status".to_owned(),
            });
        }
        let mut accounts = write_lock(&self.service_accounts);
        let Some(account) = accounts.get_mut(service_account_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("service account {service_account_id}"),
            });
        };
        if account.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        account.status = status;
        account.resource_version += 1;
        account.updated_at = now;
        let updated = account.clone();
        drop(accounts);
        Ok(updated)
    }
}

impl AuthSessionRepository for InMemoryGatewayStore {
    fn session_by_hash(&self, session_hash: &str) -> Option<AuthSessionRecord> {
        let auth_sessions = match self.auth_sessions.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        auth_sessions.get(session_hash).cloned()
    }

    fn sessions_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Vec<AuthSessionRecord> {
        let mut sessions = read_lock(&self.auth_sessions)
            .values()
            .filter(|session| {
                session.tenant_id == tenant_id && session.principal_id == principal_id
            })
            .cloned()
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.auth_session_id.cmp(&right.auth_session_id))
        });
        sessions
    }

    fn session_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        auth_session_id: &str,
    ) -> Option<AuthSessionRecord> {
        read_lock(&self.auth_sessions)
            .values()
            .find(|session| {
                session.tenant_id == tenant_id
                    && session.principal_id == principal_id
                    && session.auth_session_id == auth_session_id
            })
            .cloned()
    }

    fn revoke_session_by_hash(
        &self,
        session_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord> {
        let mut auth_sessions = write_lock(&self.auth_sessions);
        let Some(session) = auth_sessions.get_mut(session_hash) else {
            return Err(GatewayError::Authentication);
        };
        session.status = AuthSessionStatus::Revoked;
        session.updated_at = now;
        let revoked = session.clone();
        drop(auth_sessions);
        Ok(revoked)
    }

    fn update_session_active_context_by_hash(
        &self,
        session_hash: &str,
        active_organization_id: Option<String>,
        active_project_id: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord> {
        let mut auth_sessions = write_lock(&self.auth_sessions);
        let Some(session) = auth_sessions.get_mut(session_hash) else {
            return Err(GatewayError::Authentication);
        };
        if !session.can_authenticate_at(now) {
            return Err(GatewayError::Authentication);
        }
        session.active_organization_id = active_organization_id;
        session.active_project_id = active_project_id;
        session.updated_at = now;
        let updated = session.clone();
        drop(auth_sessions);
        Ok(updated)
    }

    fn revoke_sessions_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> usize {
        let mut auth_sessions = write_lock(&self.auth_sessions);
        let mut revoked_count = 0_usize;
        for session in auth_sessions.values_mut().filter(|session| {
            session.tenant_id == tenant_id
                && session.principal_id == principal_id
                && session.status == AuthSessionStatus::Active
        }) {
            session.status = AuthSessionStatus::Revoked;
            session.updated_at = now;
            revoked_count += 1;
        }
        drop(auth_sessions);
        revoked_count
    }

    fn revoke_session_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        auth_session_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord> {
        let mut auth_sessions = write_lock(&self.auth_sessions);
        let Some(session) = auth_sessions.values_mut().find(|session| {
            session.tenant_id == tenant_id
                && session.principal_id == principal_id
                && session.auth_session_id == auth_session_id
        }) else {
            return Err(GatewayError::NotFound {
                resource: format!("auth session {auth_session_id}"),
            });
        };
        session.status = AuthSessionStatus::Revoked;
        session.updated_at = now;
        let revoked = session.clone();
        drop(auth_sessions);
        Ok(revoked)
    }
}

impl ExternalIdentityRepository for InMemoryGatewayStore {
    fn external_identities_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Vec<ExternalIdentityRecord> {
        let mut identities = read_lock(&self.external_identities)
            .values()
            .filter(|identity| {
                identity.tenant_id == tenant_id && identity.principal_id == principal_id
            })
            .cloned()
            .collect::<Vec<_>>();
        identities
            .sort_by(|left, right| left.external_identity_id.cmp(&right.external_identity_id));
        identities
    }

    fn external_identity_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
        external_identity_id: &str,
    ) -> Option<ExternalIdentityRecord> {
        read_lock(&self.external_identities)
            .get(external_identity_id)
            .filter(|identity| {
                identity.tenant_id == tenant_id && identity.principal_id == principal_id
            })
            .cloned()
    }

    fn unlink_external_identity(
        &self,
        tenant_id: &str,
        principal_id: &str,
        external_identity_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ExternalIdentityRecord> {
        let mut identities = write_lock(&self.external_identities);
        let Some(identity) = identities.get_mut(external_identity_id).filter(|identity| {
            identity.tenant_id == tenant_id && identity.principal_id == principal_id
        }) else {
            return Err(GatewayError::NotFound {
                resource: format!("external identity {external_identity_id}"),
            });
        };
        identity.status = ResourceStatus::Deleted;
        identity.updated_at = now;
        let unlinked = identity.clone();
        drop(identities);
        Ok(unlinked)
    }
}

impl ConfigSnapshotRepository for InMemoryGatewayStore {
    fn latest_published_snapshot(&self) -> Option<ConfigSnapshot> {
        let latest_snapshot = match self.latest_snapshot.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        latest_snapshot.clone()
    }
}

impl ConfigSnapshotStore for InMemoryGatewayStore {
    fn latest_published_snapshot_for_tenant(&self, tenant_id: &str) -> Option<ConfigSnapshot> {
        let publication_pointer = read_lock(&self.config_publications).get(tenant_id).cloned();
        if let Some(pointer) = publication_pointer {
            return self
                .config_snapshot(&pointer.snapshot_id)
                .map(|snapshot| snapshot.metadata);
        }
        let config_snapshots = match self.config_snapshots.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        config_snapshots
            .iter()
            .filter(|snapshot| snapshot.metadata.tenant_id == tenant_id)
            .max_by_key(|snapshot| snapshot.metadata.version)
            .map(|snapshot| snapshot.metadata.clone())
    }

    fn config_snapshot(&self, snapshot_id: &str) -> Option<PublishedConfigSnapshot> {
        let config_snapshots = match self.config_snapshots.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        config_snapshots
            .iter()
            .find(|snapshot| snapshot.metadata.snapshot_id == snapshot_id)
            .cloned()
    }

    fn insert_config_snapshot(&self, snapshot: PublishedConfigSnapshot) {
        {
            let mut config_snapshots = match self.config_snapshots.write() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            config_snapshots.push(snapshot.clone());
        }
        let invalidation_id = crate::domain::new_prefixed_id("cfginv");
        let pointer = ConfigPublicationPointerRecord {
            tenant_id: snapshot.metadata.tenant_id.clone(),
            snapshot_id: snapshot.metadata.snapshot_id.clone(),
            version: snapshot.metadata.version,
            checksum: snapshot.metadata.checksum.clone(),
            invalidation_id: invalidation_id.clone(),
            published_at: snapshot.published_at,
            updated_at: snapshot.published_at,
        };
        let invalidation = ConfigInvalidationEventRecord {
            invalidation_id,
            tenant_id: snapshot.metadata.tenant_id.clone(),
            snapshot_id: snapshot.metadata.snapshot_id.clone(),
            version: snapshot.metadata.version,
            checksum: snapshot.metadata.checksum.clone(),
            published_at: snapshot.published_at,
            created_at: snapshot.published_at,
        };
        write_lock(&self.config_publications).insert(pointer.tenant_id.clone(), pointer);
        write_lock(&self.config_invalidations).push(invalidation);
        self.set_latest_snapshot(snapshot.metadata);
    }
}

impl ConfigPublicationRepository for InMemoryGatewayStore {
    fn config_publication(&self, tenant_id: &str) -> Option<ConfigPublicationPointerRecord> {
        read_lock(&self.config_publications).get(tenant_id).cloned()
    }

    fn config_invalidation_events_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<ConfigInvalidationEventRecord> {
        read_lock(&self.config_invalidations)
            .iter()
            .filter(|event| event.tenant_id == tenant_id)
            .cloned()
            .collect()
    }

    fn config_worker_reloads_for_tenant(&self, tenant_id: &str) -> Vec<ConfigWorkerReloadRecord> {
        let mut reloads = read_lock(&self.config_worker_reloads)
            .values()
            .filter(|record| record.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        reloads.sort_by(|left, right| {
            left.worker_id
                .cmp(&right.worker_id)
                .then_with(|| left.reloaded_at.cmp(&right.reloaded_at))
        });
        reloads
    }

    fn reload_config_worker_from_invalidation(
        &self,
        tenant_id: &str,
        worker_id: &str,
        invalidation_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ConfigWorkerReloadRecord> {
        let event = read_lock(&self.config_invalidations)
            .iter()
            .find(|event| event.tenant_id == tenant_id && event.invalidation_id == invalidation_id)
            .cloned()
            .ok_or_else(|| GatewayError::NotFound {
                resource: format!("config invalidation {invalidation_id}"),
            })?;
        let previous = self.config_worker_reload(tenant_id, worker_id);
        let snapshot =
            self.config_snapshot(&event.snapshot_id)
                .ok_or_else(|| GatewayError::NotFound {
                    resource: format!("config snapshot {}", event.snapshot_id),
                })?;
        let missed_invalidation_count =
            count_missed_invalidations(self, tenant_id, previous.as_ref(), event.version);
        let record = config_worker_reload_record(
            tenant_id,
            worker_id,
            &snapshot.metadata,
            ConfigReloadSource::Invalidation,
            missed_invalidation_count.saturating_sub(1),
            event.published_at,
            now,
        );
        write_lock(&self.config_worker_reloads).insert(
            (record.tenant_id.clone(), record.worker_id.clone()),
            record.clone(),
        );
        Ok(record)
    }

    fn reload_config_worker_by_polling(
        &self,
        tenant_id: &str,
        worker_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ConfigWorkerReloadRecord> {
        let pointer = self
            .config_publication(tenant_id)
            .ok_or_else(|| GatewayError::NotFound {
                resource: format!("config publication pointer {tenant_id}"),
            })?;
        let previous = self.config_worker_reload(tenant_id, worker_id);
        let snapshot =
            self.config_snapshot(&pointer.snapshot_id)
                .ok_or_else(|| GatewayError::NotFound {
                    resource: format!("config snapshot {}", pointer.snapshot_id),
                })?;
        let missed_invalidation_count =
            count_missed_invalidations(self, tenant_id, previous.as_ref(), pointer.version);
        let record = config_worker_reload_record(
            tenant_id,
            worker_id,
            &snapshot.metadata,
            ConfigReloadSource::Polling,
            missed_invalidation_count,
            pointer.published_at,
            now,
        );
        write_lock(&self.config_worker_reloads).insert(
            (record.tenant_id.clone(), record.worker_id.clone()),
            record.clone(),
        );
        Ok(record)
    }
}

impl ValidationDiagnosticRepository for InMemoryGatewayStore {
    fn record_validation_diagnostic(&self, record: ValidationDiagnosticRecord) {
        write_lock(&self.validation_diagnostics).push(record);
    }

    fn validation_diagnostics_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<ValidationDiagnosticRecord> {
        let mut diagnostics = read_lock(&self.validation_diagnostics)
            .iter()
            .filter(|record| record.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        diagnostics.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.validation_id.cmp(&right.validation_id))
        });
        diagnostics
    }
}

impl UsageAccountingRepository for InMemoryGatewayStore {
    fn record_usage_event(&self, record: UsageEventRecord) {
        {
            let mut events = write_lock(&self.usage_events);
            if events.iter().any(|existing| {
                existing.usage_event_id == record.usage_event_id
                    || (existing.tenant_id == record.tenant_id
                        && existing.request_id == record.request_id)
            }) {
                return;
            }
            events.push(record.clone());
        }
        let mut buckets = write_lock(&self.ledger_buckets);
        for bucket_kind in ["event", "minute", "hour", "day", "month"] {
            fold_usage_event_into_bucket(&mut buckets, &record, bucket_kind);
        }
    }

    fn usage_events_for_tenant(&self, tenant_id: &str) -> Vec<UsageEventRecord> {
        let mut events = read_lock(&self.usage_events)
            .iter()
            .filter(|record| record.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            right
                .occurred_at
                .cmp(&left.occurred_at)
                .then_with(|| left.usage_event_id.cmp(&right.usage_event_id))
        });
        events
    }

    fn ledger_buckets_for_tenant(&self, tenant_id: &str) -> Vec<LedgerBucketRecord> {
        let mut buckets = read_lock(&self.ledger_buckets)
            .values()
            .filter(|record| record.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        buckets.sort_by(|left, right| {
            right
                .bucket_start
                .cmp(&left.bucket_start)
                .then_with(|| left.ledger_bucket_id.cmp(&right.ledger_bucket_id))
        });
        buckets
    }
}

impl RuntimePolicyRepository for InMemoryGatewayStore {
    fn runtime_policy_hot_state_available(&self) -> bool {
        !*read_lock(&self.runtime_policy_hot_state_unavailable)
    }

    fn increment_runtime_quota_counter(
        &self,
        key: String,
        increment: i64,
        limit: i64,
    ) -> RuntimeQuotaCounterDecision {
        let mut counters = write_lock(&self.runtime_quota_counters);
        let current = {
            let current = counters.entry(key).or_insert(0);
            *current = current.saturating_add(increment);
            *current
        };
        drop(counters);
        RuntimeQuotaCounterDecision {
            current,
            allowed: current <= limit,
        }
    }

    fn runtime_policy_counter(&self, key: &str) -> i64 {
        read_lock(&self.runtime_quota_counters)
            .get(key)
            .copied()
            .unwrap_or_default()
    }

    fn adjust_runtime_policy_counter(&self, key: String, delta: i64) -> i64 {
        let mut counters = write_lock(&self.runtime_quota_counters);
        let next = counters
            .get(&key)
            .copied()
            .unwrap_or_default()
            .saturating_add(delta)
            .max(0);
        if next == 0 {
            counters.remove(&key);
        } else {
            counters.insert(key, next);
        }
        next
    }

    fn increment_runtime_policy_loss_allowance_counter(
        &self,
        key: String,
        increment: i64,
        limit: i64,
    ) -> RuntimeQuotaCounterDecision {
        let mut counters = write_lock(&self.runtime_policy_loss_allowances);
        let current = {
            let current = counters.entry(key).or_insert(0);
            *current = current.saturating_add(increment);
            *current
        };
        drop(counters);
        RuntimeQuotaCounterDecision {
            current,
            allowed: current <= limit,
        }
    }

    fn adjust_runtime_policy_loss_allowance_counter(&self, key: String, delta: i64) -> i64 {
        let mut counters = write_lock(&self.runtime_policy_loss_allowances);
        let next = counters
            .get(&key)
            .copied()
            .unwrap_or_default()
            .saturating_add(delta)
            .max(0);
        if next == 0 {
            counters.remove(&key);
        } else {
            counters.insert(key, next);
        }
        next
    }

    fn runtime_policy_loss_allowance_counter(&self, key: &str) -> i64 {
        read_lock(&self.runtime_policy_loss_allowances)
            .get(key)
            .copied()
            .unwrap_or_default()
    }

    fn record_runtime_budget_lease(&self, record: RuntimeBudgetLeaseRecord) {
        write_lock(&self.runtime_budget_leases).insert(record.lease_id.clone(), record);
    }

    fn release_runtime_budget_lease(
        &self,
        lease_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<RuntimeBudgetLeaseRecord> {
        let mut leases = write_lock(&self.runtime_budget_leases);
        let released = leases.get_mut(lease_id).and_then(|lease| {
            if lease.status != "reserved" {
                return None;
            }
            "released".clone_into(&mut lease.status);
            lease.updated_at = now;
            Some(lease.clone())
        });
        drop(leases);
        released
    }

    fn expire_runtime_budget_leases(
        &self,
        tenant_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<RuntimeBudgetLeaseRecord> {
        let mut expired = Vec::new();
        let mut leases = write_lock(&self.runtime_budget_leases);
        for lease in leases.values_mut() {
            if lease.tenant_id == tenant_id && lease.status == "reserved" && lease.expires_at <= now
            {
                "expired".clone_into(&mut lease.status);
                lease.updated_at = now;
                expired.push(lease.clone());
            }
        }
        drop(leases);
        expired.sort_by(|left, right| left.lease_id.cmp(&right.lease_id));
        expired
    }

    fn runtime_budget_leases_for_tenant(&self, tenant_id: &str) -> Vec<RuntimeBudgetLeaseRecord> {
        let mut leases = read_lock(&self.runtime_budget_leases)
            .values()
            .filter(|record| record.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        leases.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.lease_id.cmp(&right.lease_id))
        });
        leases
    }
}

impl ExportRepository for InMemoryGatewayStore {
    fn create_export_job(
        &self,
        request: CreateExportJobRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ExportJobRecord> {
        validate_export_job_request(&request)?;
        let record = ExportJobRecord {
            export_job_id: new_prefixed_id("exj"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            export_kind: request.export_kind,
            requested_by: request.requested_by,
            query_document: request.query_document,
            status: "pending".to_owned(),
            resource_version: 1,
            schema_version: 1,
            created_at: now,
            updated_at: now,
            completed_at: None,
        };
        write_lock(&self.export_jobs).insert(record.export_job_id.clone(), record.clone());
        Ok(record)
    }

    fn export_jobs_for_tenant(&self, tenant_id: &str) -> Vec<ExportJobRecord> {
        let mut jobs = read_lock(&self.export_jobs)
            .values()
            .filter(|job| job.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        jobs.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.export_job_id.cmp(&left.export_job_id))
        });
        jobs
    }

    fn export_job(&self, export_job_id: &str) -> Option<ExportJobRecord> {
        read_lock(&self.export_jobs).get(export_job_id).cloned()
    }

    fn complete_export_job(
        &self,
        export_job_id: &str,
        request: CompleteExportJobRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(ExportJobRecord, ExportManifestRecord)> {
        if !matches!(request.status.as_str(), "completed" | "failed") {
            return Err(GatewayError::BadRequest {
                message: "export_job_status_invalid".to_owned(),
            });
        }
        if request.record_count < 0 || request.byte_count < 0 {
            return Err(GatewayError::BadRequest {
                message: "export_manifest_counts_invalid".to_owned(),
            });
        }
        let mut jobs = write_lock(&self.export_jobs);
        let Some(job) = jobs.get_mut(export_job_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("export job {export_job_id}"),
            });
        };
        request.status.clone_into(&mut job.status);
        job.resource_version = job.resource_version.saturating_add(1);
        job.updated_at = now;
        job.completed_at = Some(now);
        let updated_job = job.clone();
        drop(jobs);
        let manifest = ExportManifestRecord {
            export_manifest_id: new_prefixed_id("exm"),
            export_job_id: export_job_id.to_owned(),
            tenant_id: updated_job.tenant_id.clone(),
            object_ref: request.object_ref,
            record_count: request.record_count,
            byte_count: request.byte_count,
            checksum: request.checksum,
            manifest_document: request.manifest_document,
            created_at: now,
            expires_at: request.expires_at,
        };
        write_lock(&self.export_manifests)
            .insert(manifest.export_manifest_id.clone(), manifest.clone());
        Ok((updated_job, manifest))
    }

    fn export_manifests_for_job(&self, export_job_id: &str) -> Vec<ExportManifestRecord> {
        let mut manifests = read_lock(&self.export_manifests)
            .values()
            .filter(|manifest| manifest.export_job_id == export_job_id)
            .cloned()
            .collect::<Vec<_>>();
        manifests.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.export_manifest_id.cmp(&left.export_manifest_id))
        });
        manifests
    }
}

impl EmergencyOperationRepository for InMemoryGatewayStore {
    fn create_emergency_operation(
        &self,
        request: CreateEmergencyOperationRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<EmergencyOperationRecord> {
        if request.reason.trim().is_empty() {
            return Err(GatewayError::BadRequest {
                message: "reason_required".to_owned(),
            });
        }
        if request.expires_at <= now {
            return Err(GatewayError::BadRequest {
                message: "emergency_expiry_must_be_future".to_owned(),
            });
        }
        let record = EmergencyOperationRecord {
            emergency_operation_id: new_prefixed_id("emop"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            operation_kind: request.operation_kind,
            target_resource_kind: request.target_resource_kind,
            target_resource_id: request.target_resource_id,
            requested_by: request.requested_by,
            reason: request.reason.trim().to_owned(),
            status: "applied".to_owned(),
            operator_alert_document: request.operator_alert_document,
            resource_version: 1,
            schema_version: 1,
            created_at: now,
            updated_at: now,
            expires_at: request.expires_at,
        };
        write_lock(&self.emergency_operations)
            .insert(record.emergency_operation_id.clone(), record.clone());
        Ok(record)
    }

    fn emergency_operations_for_tenant(&self, tenant_id: &str) -> Vec<EmergencyOperationRecord> {
        let mut operations = read_lock(&self.emergency_operations)
            .values()
            .filter(|operation| operation.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        operations.sort_by(|left, right| {
            right.created_at.cmp(&left.created_at).then_with(|| {
                right
                    .emergency_operation_id
                    .cmp(&left.emergency_operation_id)
            })
        });
        operations
    }

    fn emergency_operation(
        &self,
        emergency_operation_id: &str,
    ) -> Option<EmergencyOperationRecord> {
        read_lock(&self.emergency_operations)
            .get(emergency_operation_id)
            .cloned()
    }

    fn active_emergency_operation(
        &self,
        tenant_id: &str,
        operation_kind: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<EmergencyOperationRecord> {
        self.emergency_operations_for_tenant(tenant_id)
            .into_iter()
            .find(|operation| {
                operation.operation_kind == operation_kind
                    && operation.status == "applied"
                    && operation.expires_at > now
            })
    }
}

impl NotificationOutboxRepository for InMemoryGatewayStore {
    fn append_notification_outbox_event(
        &self,
        request: CreateNotificationOutboxEventRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> NotificationOutboxEventRecord {
        let mut events = write_lock(&self.notification_outbox_events);
        if let Some(existing) = events
            .values()
            .find(|event| {
                event.tenant_id == request.tenant_id && event.dedupe_key == request.dedupe_key
            })
            .cloned()
        {
            return existing;
        }
        let record = NotificationOutboxEventRecord {
            notification_outbox_event_id: new_prefixed_id("nob"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            notification_subscription_id: request.notification_subscription_id,
            notification_sink_id: request.notification_sink_id,
            event_kind: request.event_kind,
            dedupe_key: request.dedupe_key,
            payload_document: request.payload_document,
            status: "pending".to_owned(),
            attempt_count: 0,
            next_attempt_at: request.next_attempt_at,
            created_at: now,
            updated_at: now,
        };
        events.insert(record.notification_outbox_event_id.clone(), record.clone());
        record
    }

    fn notification_outbox_event(
        &self,
        notification_outbox_event_id: &str,
    ) -> Option<NotificationOutboxEventRecord> {
        read_lock(&self.notification_outbox_events)
            .get(notification_outbox_event_id)
            .cloned()
    }

    fn replay_dead_lettered_notification_outbox_event(
        &self,
        notification_outbox_event_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationOutboxEventRecord> {
        let record = {
            let mut events = write_lock(&self.notification_outbox_events);
            let Some(event) = events.get_mut(notification_outbox_event_id) else {
                return Err(GatewayError::NotFound {
                    resource: format!("notification outbox event {notification_outbox_event_id}"),
                });
            };
            if event.status != "dead_lettered" {
                return Err(GatewayError::BadRequest {
                    message: "notification_replay_requires_dead_lettered_event".to_owned(),
                });
            }
            "pending".clone_into(&mut event.status);
            event.attempt_count = 0;
            event.next_attempt_at = Some(now);
            event.updated_at = now;
            let record = event.clone();
            drop(events);
            record
        };
        Ok(record)
    }

    fn notification_subscriptions_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<NotificationSubscriptionRecord> {
        let mut subscriptions = read_lock(&self.notification_subscriptions)
            .values()
            .filter(|subscription| subscription.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        subscriptions.sort_by(|left, right| {
            left.notification_sink_id
                .cmp(&right.notification_sink_id)
                .then_with(|| left.event_family.cmp(&right.event_family))
                .then_with(|| {
                    left.notification_subscription_id
                        .cmp(&right.notification_subscription_id)
                })
        });
        subscriptions
    }

    fn notification_outbox_events_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<NotificationOutboxEventRecord> {
        let mut events = read_lock(&self.notification_outbox_events)
            .values()
            .filter(|event| event.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            right.created_at.cmp(&left.created_at).then_with(|| {
                left.notification_outbox_event_id
                    .cmp(&right.notification_outbox_event_id)
            })
        });
        events
    }

    fn due_notification_outbox_events(
        &self,
        tenant_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
    ) -> Vec<NotificationOutboxEventRecord> {
        let mut events = read_lock(&self.notification_outbox_events)
            .values()
            .filter(|event| {
                event.tenant_id == tenant_id
                    && matches!(event.status.as_str(), "pending" | "retryable_failed")
                    && event.next_attempt_at.is_none_or(|next| next <= now)
            })
            .cloned()
            .collect::<Vec<_>>();
        events.sort_by(|left, right| {
            left.created_at.cmp(&right.created_at).then_with(|| {
                left.notification_outbox_event_id
                    .cmp(&right.notification_outbox_event_id)
            })
        });
        events.truncate(limit);
        events
    }

    fn record_notification_delivery_attempt(
        &self,
        request: CreateNotificationDeliveryAttemptRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationDeliveryAttemptRecord> {
        let mut events = write_lock(&self.notification_outbox_events);
        let Some(event) = events.get_mut(&request.notification_outbox_event_id) else {
            return Err(GatewayError::NotFound {
                resource: format!(
                    "notification outbox event {}",
                    request.notification_outbox_event_id
                ),
            });
        };
        let attempt_index = event.attempt_count;
        event.attempt_count = event.attempt_count.saturating_add(1);
        match request.status.as_str() {
            "succeeded" => "delivered",
            "retryable_failed" => "retryable_failed",
            "permanent_failed" => "permanent_failed",
            "dead_lettered" => "dead_lettered",
            "started" => "delivering",
            _ => {
                return Err(GatewayError::BadRequest {
                    message: "notification_delivery_attempt_status_invalid".to_owned(),
                });
            }
        }
        .clone_into(&mut event.status);
        event.next_attempt_at = match request.status.as_str() {
            "retryable_failed" => request.next_attempt_at,
            "started" => event.next_attempt_at,
            _ => None,
        };
        event.updated_at = now;
        let record = NotificationDeliveryAttemptRecord {
            notification_delivery_attempt_id: new_prefixed_id("nda"),
            notification_outbox_event_id: request.notification_outbox_event_id,
            notification_sink_id: request.notification_sink_id,
            attempt_index,
            status: request.status,
            response_status: request.response_status,
            error_message: request.error_message,
            request_body_sha256: request.request_body_sha256,
            signing_secret_ref_id: request.signing_secret_ref_id,
            signature_sha256: request.signature_sha256,
            delivery_headers: request.delivery_headers,
            attempted_at: now,
        };
        drop(events);
        write_lock(&self.notification_delivery_attempts).push(record.clone());
        Ok(record)
    }

    fn notification_delivery_attempts_for_event(
        &self,
        notification_outbox_event_id: &str,
    ) -> Vec<NotificationDeliveryAttemptRecord> {
        let mut attempts = read_lock(&self.notification_delivery_attempts)
            .iter()
            .filter(|attempt| attempt.notification_outbox_event_id == notification_outbox_event_id)
            .cloned()
            .collect::<Vec<_>>();
        attempts.sort_by(|left, right| {
            left.attempt_index.cmp(&right.attempt_index).then_with(|| {
                left.notification_delivery_attempt_id
                    .cmp(&right.notification_delivery_attempt_id)
            })
        });
        attempts
    }
}

fn ledger_bucket_record_for_event(
    record: &UsageEventRecord,
    bucket_kind: &str,
) -> Result<LedgerBucketRecord> {
    let mut buckets = HashMap::new();
    fold_usage_event_into_bucket(&mut buckets, record, bucket_kind);
    let bucket_start = usage_bucket_start(bucket_kind, record.occurred_at);
    let key = usage_bucket_key(record, bucket_kind, bucket_start);
    let Some(mut bucket) = buckets.remove(&key) else {
        return Err(GatewayError::Internal {
            message: "folded usage event did not create a ledger bucket".to_owned(),
        });
    };
    bucket.ledger_bucket_id = stable_ledger_bucket_id(&key);
    Ok(bucket)
}

fn stable_ledger_bucket_id(key: &str) -> String {
    let digest = Sha256::digest(key.as_bytes());
    format!("lb_{digest:x}")
}

fn fold_usage_event_into_bucket(
    buckets: &mut HashMap<String, LedgerBucketRecord>,
    record: &UsageEventRecord,
    bucket_kind: &str,
) {
    let bucket_start = usage_bucket_start(bucket_kind, record.occurred_at);
    let key = usage_bucket_key(record, bucket_kind, bucket_start);
    let input_tokens = usage_payload_i64(&record.usage_payload, "input_tokens");
    let output_tokens = usage_payload_i64(&record.usage_payload, "output_tokens");
    let reasoning_tokens = usage_payload_i64(&record.usage_payload, "reasoning_tokens");
    let media_units = usage_payload_i64(&record.usage_payload, "image_input_units")
        + usage_payload_i64(&record.usage_payload, "image_output_units")
        + usage_payload_i64(&record.usage_payload, "audio_input_units")
        + usage_payload_i64(&record.usage_payload, "audio_output_units")
        + usage_payload_i64(&record.usage_payload, "request_units");
    let estimated_cost_micros = record
        .cost_payload
        .get("total_cost")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let currency_code = record
        .cost_payload
        .get("currency")
        .and_then(Value::as_str)
        .unwrap_or("USD")
        .to_owned();
    let pricing_version = record
        .cost_payload
        .get("pricing_version")
        .and_then(Value::as_str)
        .unwrap_or("unpriced")
        .to_owned();
    let bucket = buckets.entry(key).or_insert_with(|| LedgerBucketRecord {
        ledger_bucket_id: new_prefixed_id("lb"),
        tenant_id: record.tenant_id.clone(),
        organization_id: record.organization_id.clone(),
        project_id: record.project_id.clone(),
        principal_id: record.principal_id.clone(),
        project_member_id: record.project_member_id.clone(),
        service_account_id: record.service_account_id.clone(),
        api_key_id: record.api_key_id.clone(),
        model_alias_id: record.model_alias_id.clone(),
        model_target_id: record.model_target_id.clone(),
        provider_endpoint_id: record.provider_endpoint_id.clone(),
        upstream_credential_id: record.upstream_credential_id.clone(),
        route_policy_id: record.route_policy_id.clone(),
        routing_group_id: record.routing_group_id.clone(),
        protocol_family: Some(record.protocol_family),
        status: Some(record.status.clone()),
        usage_confidence: Some(record.usage_confidence.clone()),
        bucket_kind: bucket_kind.to_owned(),
        bucket_start,
        currency_code,
        input_tokens: 0,
        output_tokens: 0,
        reasoning_tokens: 0,
        media_units: 0,
        request_count: 0,
        success_count: 0,
        error_count: 0,
        blocked_count: 0,
        usage_missing_count: 0,
        usage_estimated_count: 0,
        estimated_cost_micros: 0,
        pricing_version,
        updated_at: record.occurred_at,
    });
    bucket.input_tokens += input_tokens;
    bucket.output_tokens += output_tokens;
    bucket.reasoning_tokens += reasoning_tokens;
    bucket.media_units += media_units;
    bucket.request_count += 1;
    bucket.success_count += i64::from(record.status == "success");
    bucket.error_count += i64::from(matches!(
        record.status.as_str(),
        "error" | "partial" | "canceled"
    ));
    bucket.blocked_count += i64::from(record.status == "blocked");
    bucket.usage_missing_count += i64::from(record.usage_confidence == "missing");
    bucket.usage_estimated_count += i64::from(record.usage_confidence == "estimated");
    bucket.estimated_cost_micros += estimated_cost_micros;
    bucket.updated_at = bucket.updated_at.max(record.occurred_at);
}

fn usage_bucket_key(
    record: &UsageEventRecord,
    bucket_kind: &str,
    bucket_start: chrono::DateTime<chrono::Utc>,
) -> String {
    [
        record.tenant_id.as_str(),
        record.organization_id.as_deref().unwrap_or(""),
        record.project_id.as_deref().unwrap_or(""),
        record.principal_id.as_deref().unwrap_or(""),
        record.project_member_id.as_deref().unwrap_or(""),
        record.service_account_id.as_deref().unwrap_or(""),
        record.api_key_id.as_deref().unwrap_or(""),
        record.model_alias_id.as_deref().unwrap_or(""),
        record.model_target_id.as_deref().unwrap_or(""),
        record.provider_endpoint_id.as_deref().unwrap_or(""),
        record.upstream_credential_id.as_deref().unwrap_or(""),
        record.route_policy_id.as_deref().unwrap_or(""),
        record.routing_group_id.as_deref().unwrap_or(""),
        record.protocol_family.as_str(),
        record.status.as_str(),
        record.usage_confidence.as_str(),
        bucket_kind,
    ]
    .join("|")
        + "|"
        + &bucket_start.timestamp().to_string()
}

fn usage_bucket_start(
    bucket_kind: &str,
    occurred_at: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    let seconds = occurred_at.timestamp();
    match bucket_kind {
        "minute" => chrono::DateTime::from_timestamp(seconds - seconds.rem_euclid(60), 0)
            .unwrap_or(occurred_at),
        "hour" => chrono::DateTime::from_timestamp(seconds - seconds.rem_euclid(3_600), 0)
            .unwrap_or(occurred_at),
        "day" => chrono::DateTime::from_timestamp(seconds - seconds.rem_euclid(86_400), 0)
            .unwrap_or(occurred_at),
        "month" => {
            let date = occurred_at.date_naive();
            chrono::NaiveDate::from_ymd_opt(date.year(), date.month(), 1)
                .and_then(|month| month.and_hms_opt(0, 0, 0))
                .map_or(occurred_at, |naive| {
                    chrono::DateTime::from_naive_utc_and_offset(naive, chrono::Utc)
                })
        }
        _ => occurred_at,
    }
}

fn usage_payload_i64(payload: &Value, key: &str) -> i64 {
    payload.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn count_missed_invalidations(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    previous: Option<&ConfigWorkerReloadRecord>,
    target_version: i64,
) -> usize {
    let previous_version = previous.map_or(0, |record| record.loaded_version);
    read_lock(&store.config_invalidations)
        .iter()
        .filter(|event| {
            event.tenant_id == tenant_id
                && event.version > previous_version
                && event.version <= target_version
        })
        .count()
}

fn config_worker_reload_record(
    tenant_id: &str,
    worker_id: &str,
    snapshot: &ConfigSnapshot,
    reload_source: ConfigReloadSource,
    missed_invalidation_count: usize,
    published_at: chrono::DateTime<chrono::Utc>,
    reloaded_at: chrono::DateTime<chrono::Utc>,
) -> ConfigWorkerReloadRecord {
    ConfigWorkerReloadRecord {
        tenant_id: tenant_id.to_owned(),
        worker_id: worker_id.to_owned(),
        snapshot_id: snapshot.snapshot_id.clone(),
        loaded_version: snapshot.version,
        checksum: snapshot.checksum.clone(),
        last_known_good_snapshot_id: snapshot.snapshot_id.clone(),
        last_known_good_version: snapshot.version,
        reload_source,
        status: ConfigWorkerReloadStatus::Loaded,
        missed_invalidation_count,
        publication_lag_ms: reloaded_at
            .signed_duration_since(published_at)
            .num_milliseconds()
            .max(0),
        reloaded_at,
    }
}

impl TenancyRepository for InMemoryGatewayStore {
    fn project_membership(
        &self,
        principal_id: &str,
        project_id: &str,
    ) -> Option<ProjectMembershipRecord> {
        let project_memberships = match self.project_memberships.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        project_memberships
            .get(&(principal_id.to_owned(), project_id.to_owned()))
            .cloned()
    }
}

impl TenancyBootstrapRepository for InMemoryGatewayStore {
    fn bootstrap_default_project(
        &self,
        request: BootstrapDefaultProjectRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<TenancySeed> {
        let seed = tenancy_seed_from_request(&request, now);
        validate_tenancy_seed(self, &seed)?;
        insert_tenancy_seed(self, &seed);
        load_tenancy_seed(self, &request)
    }

    fn tenant(&self, tenant_id: &str) -> Option<TenantRecord> {
        read_lock(&self.tenants).get(tenant_id).cloned()
    }

    fn organization(&self, organization_id: &str) -> Option<OrganizationRecord> {
        read_lock(&self.organizations).get(organization_id).cloned()
    }

    fn organizations_for_tenant(&self, tenant_id: &str) -> Vec<OrganizationRecord> {
        let mut organizations = read_lock(&self.organizations)
            .values()
            .filter(|organization| organization.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        organizations.sort_by(|left, right| left.organization_id.cmp(&right.organization_id));
        organizations
    }

    fn project(&self, project_id: &str) -> Option<ProjectRecord> {
        read_lock(&self.projects).get(project_id).cloned()
    }

    fn projects_for_tenant(&self, tenant_id: &str) -> Vec<ProjectRecord> {
        let mut projects = read_lock(&self.projects)
            .values()
            .filter(|project| project.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        projects.sort_by(|left, right| left.project_id.cmp(&right.project_id));
        projects
    }

    fn organization_members_for_organization(
        &self,
        organization_id: &str,
    ) -> Vec<OrganizationMembershipRecord> {
        let mut members = read_lock(&self.organization_memberships)
            .values()
            .filter(|member| member.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        members.sort_by(|left, right| {
            left.organization_member_id
                .cmp(&right.organization_member_id)
        });
        members
    }

    fn organization_member(
        &self,
        organization_member_id: &str,
    ) -> Option<OrganizationMembershipRecord> {
        read_lock(&self.organization_memberships)
            .values()
            .find(|member| member.organization_member_id == organization_member_id)
            .cloned()
    }

    fn project_members_for_project(&self, project_id: &str) -> Vec<ProjectMembershipRecord> {
        let mut members = read_lock(&self.project_memberships)
            .values()
            .filter(|member| member.project_id == project_id)
            .cloned()
            .collect::<Vec<_>>();
        members.sort_by(|left, right| left.project_member_id.cmp(&right.project_member_id));
        members
    }

    fn create_project_membership(
        &self,
        request: CreateProjectMembershipRequest,
    ) -> Result<ProjectMembershipRecord> {
        let key = (request.principal_id.clone(), request.project_id.clone());
        let mut memberships = write_lock(&self.project_memberships);
        let member = memberships
            .entry(key)
            .or_insert_with(|| ProjectMembershipRecord {
                project_member_id: new_prefixed_id("pm"),
                tenant_id: request.tenant_id.clone(),
                organization_id: request.organization_id.clone(),
                project_id: request.project_id.clone(),
                principal_id: request.principal_id.clone(),
                organization_member_id: Some(request.organization_member_id.clone()),
                status: MembershipStatus::Active,
                resource_version: 1,
            });
        if member.tenant_id != request.tenant_id
            || member.organization_id != request.organization_id
            || member.project_id != request.project_id
            || member.principal_id != request.principal_id
        {
            return Err(GatewayError::BadRequest {
                message: "project_membership_scope_conflict".to_owned(),
            });
        }
        let organization_member_changed = member.organization_member_id.as_deref()
            != Some(request.organization_member_id.as_str());
        let status_changed = member.status != MembershipStatus::Active;
        if organization_member_changed || status_changed {
            member.organization_member_id = Some(request.organization_member_id);
            member.status = MembershipStatus::Active;
            member.resource_version += 1;
        }
        let created = member.clone();
        drop(memberships);
        Ok(created)
    }

    fn project_member(&self, project_member_id: &str) -> Option<ProjectMembershipRecord> {
        read_lock(&self.project_memberships)
            .values()
            .find(|member| member.project_member_id == project_member_id)
            .cloned()
    }

    fn user(&self, user_id: &str) -> Option<UserRecord> {
        read_lock(&self.users).get(user_id).cloned()
    }

    fn users_for_tenant(&self, tenant_id: &str) -> Vec<UserRecord> {
        let mut users = read_lock(&self.users)
            .values()
            .filter(|user| user.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        users.sort_by(|left, right| left.user_id.cmp(&right.user_id));
        users
    }

    fn update_user_default_context(
        &self,
        user_id: &str,
        organization_id: Option<String>,
        project_id: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UserRecord> {
        let mut users = write_lock(&self.users);
        let Some(user) = users.get_mut(user_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("user {user_id}"),
            });
        };
        user.default_organization_id = organization_id;
        user.default_project_id = project_id;
        user.resource_version += 1;
        user.updated_at = now;
        let updated = user.clone();
        drop(users);
        Ok(updated)
    }

    fn update_user_status(
        &self,
        user_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UserRecord> {
        let mut users = write_lock(&self.users);
        let Some(user) = users.get_mut(user_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("user {user_id}"),
            });
        };
        if user.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        user.status = status;
        user.resource_version += 1;
        user.updated_at = now;
        let updated = user.clone();
        drop(users);
        Ok(updated)
    }

    fn update_organization_status(
        &self,
        organization_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationRecord> {
        let mut organizations = write_lock(&self.organizations);
        let Some(organization) = organizations.get_mut(organization_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("organization {organization_id}"),
            });
        };
        if organization.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        organization.status = status;
        organization.resource_version += 1;
        organization.updated_at = now;
        let updated = organization.clone();
        drop(organizations);
        Ok(updated)
    }

    fn update_project_status(
        &self,
        project_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProjectRecord> {
        let mut projects = write_lock(&self.projects);
        let Some(project) = projects.get_mut(project_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("project {project_id}"),
            });
        };
        if project.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        project.status = status;
        project.resource_version += 1;
        project.updated_at = now;
        let updated = project.clone();
        drop(projects);
        Ok(updated)
    }

    fn update_organization_member_status(
        &self,
        organization_member_id: &str,
        expected_resource_version: i64,
        status: MembershipStatus,
    ) -> Result<OrganizationMembershipRecord> {
        let mut memberships = write_lock(&self.organization_memberships);
        let Some(member) = memberships
            .values_mut()
            .find(|member| member.organization_member_id == organization_member_id)
        else {
            return Err(GatewayError::NotFound {
                resource: format!("organization member {organization_member_id}"),
            });
        };
        if member.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        member.status = status;
        member.resource_version += 1;
        let updated = member.clone();
        drop(memberships);
        Ok(updated)
    }

    fn update_project_member_status(
        &self,
        project_member_id: &str,
        expected_resource_version: i64,
        status: MembershipStatus,
    ) -> Result<ProjectMembershipRecord> {
        let mut memberships = write_lock(&self.project_memberships);
        let Some(member) = memberships
            .values_mut()
            .find(|member| member.project_member_id == project_member_id)
        else {
            return Err(GatewayError::NotFound {
                resource: format!("project member {project_member_id}"),
            });
        };
        if member.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        member.status = status;
        member.resource_version += 1;
        let updated = member.clone();
        drop(memberships);
        Ok(updated)
    }

    fn cascade_project_memberships_for_organization_member(
        &self,
        organization_member: &OrganizationMembershipRecord,
        status: MembershipStatus,
    ) -> usize {
        let mut memberships = write_lock(&self.project_memberships);
        let mut updated_count = 0_usize;
        for member in memberships.values_mut().filter(|member| {
            member.tenant_id == organization_member.tenant_id
                && member.organization_id == organization_member.organization_id
                && member.principal_id == organization_member.principal_id
        }) {
            let should_update = match &status {
                MembershipStatus::Active => false,
                MembershipStatus::Suspended => member.status == MembershipStatus::Active,
                MembershipStatus::Removed => member.status != MembershipStatus::Removed,
            };
            if should_update {
                member.status = status.clone();
                member.resource_version += 1;
                updated_count += 1;
            }
        }
        drop(memberships);
        updated_count
    }
}

impl OrganizationInvitationRepository for InMemoryGatewayStore {
    fn create_organization_invitation(
        &self,
        request: CreateOrganizationInvitationRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationInvitationRecord> {
        let invitation = OrganizationInvitationRecord {
            invitation_id: new_prefixed_id("inv"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            invited_email: request.invited_email,
            invited_principal_id: request.invited_principal_id,
            invitation_token_hash: request.invitation_token_hash,
            role_id: request.role_id,
            status: InvitationStatus::Pending,
            expires_at: request.expires_at,
            accepted_at: None,
            created_by: request.created_by,
            resource_version: 1,
            created_at: now,
            updated_at: now,
        };
        let mut invitations = write_lock(&self.organization_invitations);
        invitations.insert(invitation.invitation_id.clone(), invitation.clone());
        drop(invitations);
        Ok(invitation)
    }

    fn organization_invitations(
        &self,
        tenant_id: &str,
        organization_id: &str,
    ) -> Vec<OrganizationInvitationRecord> {
        let mut invitations = read_lock(&self.organization_invitations)
            .values()
            .filter(|invitation| {
                invitation.tenant_id == tenant_id && invitation.organization_id == organization_id
            })
            .cloned()
            .collect::<Vec<_>>();
        invitations.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| left.invitation_id.cmp(&right.invitation_id))
        });
        invitations
    }

    fn organization_invitation(&self, invitation_id: &str) -> Option<OrganizationInvitationRecord> {
        read_lock(&self.organization_invitations)
            .get(invitation_id)
            .cloned()
    }

    fn organization_invitation_by_token_hash(
        &self,
        token_hash: &str,
    ) -> Option<OrganizationInvitationRecord> {
        read_lock(&self.organization_invitations)
            .values()
            .find(|invitation| invitation.invitation_token_hash == token_hash)
            .cloned()
    }

    fn revoke_organization_invitation(
        &self,
        invitation_id: &str,
        expected_resource_version: i64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationInvitationRecord> {
        let mut invitations = write_lock(&self.organization_invitations);
        let Some(invitation) = invitations.get_mut(invitation_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("organization invitation {invitation_id}"),
            });
        };
        if invitation.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        if invitation.status != InvitationStatus::Pending {
            return Err(GatewayError::BadRequest {
                message: "invitation_not_pending".to_owned(),
            });
        }
        invitation.status = InvitationStatus::Revoked;
        invitation.resource_version += 1;
        invitation.updated_at = now;
        let revoked = invitation.clone();
        drop(invitations);
        Ok(revoked)
    }

    fn accept_organization_invitation(
        &self,
        invitation_id: &str,
        principal_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OrganizationInvitationRecord> {
        let mut invitations = write_lock(&self.organization_invitations);
        let Some(invitation) = invitations.get_mut(invitation_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("organization invitation {invitation_id}"),
            });
        };
        if !invitation.status.accepts_at(invitation.expires_at, now) {
            return Err(GatewayError::BadRequest {
                message: "invitation_not_accepting".to_owned(),
            });
        }
        invitation.status = InvitationStatus::Accepted;
        invitation.accepted_at = Some(now);
        invitation.resource_version += 1;
        invitation.updated_at = now;
        let accepted = invitation.clone();
        drop(invitations);

        let organization_membership =
            upsert_invited_organization_membership(self, &accepted, principal_id);
        if let Some(project_id) = accepted.project_id.as_deref() {
            upsert_invited_project_membership(
                self,
                &accepted,
                principal_id,
                project_id,
                &organization_membership.organization_member_id,
            );
        }
        repair_user_defaults_after_invite_accept(self, &accepted, principal_id, now);
        Ok(accepted)
    }
}

fn upsert_invited_organization_membership(
    store: &InMemoryGatewayStore,
    invitation: &OrganizationInvitationRecord,
    principal_id: &str,
) -> OrganizationMembershipRecord {
    let key = (principal_id.to_owned(), invitation.organization_id.clone());
    let mut memberships = write_lock(&store.organization_memberships);
    let membership = memberships
        .entry(key)
        .or_insert_with(|| OrganizationMembershipRecord {
            organization_member_id: new_prefixed_id("om"),
            tenant_id: invitation.tenant_id.clone(),
            organization_id: invitation.organization_id.clone(),
            principal_id: principal_id.to_owned(),
            status: MembershipStatus::Active,
            resource_version: 1,
        });
    if membership.status != MembershipStatus::Active {
        membership.status = MembershipStatus::Active;
        membership.resource_version += 1;
    }
    let updated = membership.clone();
    drop(memberships);
    updated
}

fn upsert_invited_project_membership(
    store: &InMemoryGatewayStore,
    invitation: &OrganizationInvitationRecord,
    principal_id: &str,
    project_id: &str,
    organization_member_id: &str,
) -> ProjectMembershipRecord {
    let key = (principal_id.to_owned(), project_id.to_owned());
    let mut memberships = write_lock(&store.project_memberships);
    let membership = memberships
        .entry(key)
        .or_insert_with(|| ProjectMembershipRecord {
            project_member_id: new_prefixed_id("pm"),
            tenant_id: invitation.tenant_id.clone(),
            organization_id: invitation.organization_id.clone(),
            project_id: project_id.to_owned(),
            principal_id: principal_id.to_owned(),
            organization_member_id: Some(organization_member_id.to_owned()),
            status: MembershipStatus::Active,
            resource_version: 1,
        });
    if membership.status != MembershipStatus::Active {
        membership.status = MembershipStatus::Active;
        membership.resource_version += 1;
    }
    if membership.organization_member_id.is_none() {
        membership.organization_member_id = Some(organization_member_id.to_owned());
        membership.resource_version += 1;
    }
    let updated = membership.clone();
    drop(memberships);
    updated
}

fn repair_user_defaults_after_invite_accept(
    store: &InMemoryGatewayStore,
    invitation: &OrganizationInvitationRecord,
    principal_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    let mut users = write_lock(&store.users);
    let Some(user) = users.get_mut(principal_id) else {
        return;
    };
    let organization_updated = user.default_organization_id.is_none();
    if organization_updated {
        user.default_organization_id = Some(invitation.organization_id.clone());
    }
    let project_updated = user.default_project_id.is_none() && invitation.project_id.is_some();
    if project_updated {
        if let Some(project_id) = invitation.project_id.as_ref() {
            user.default_project_id = Some(project_id.clone());
        }
    }
    if organization_updated || project_updated {
        user.resource_version += 1;
        user.updated_at = now;
    }
    drop(users);
}

impl SecretRefAdminRepository for InMemoryGatewayStore {
    fn create_secret_ref(
        &self,
        request: CreateSecretRefRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<SecretRefRecord> {
        let (organization_id, project_id) = validate_secret_ref_request(self, &request)?;
        let secret_ref_id = crate::domain::new_prefixed_id("sec");
        let display_mask = secret_display_mask(request.secret_value.expose_secret());
        let fingerprint = secret_fingerprint(request.secret_value.expose_secret());
        let record = SecretRefRecord {
            backend_locator: format!("memory://gateway-secrets/{secret_ref_id}"),
            secret_ref_id: secret_ref_id.clone(),
            tenant_id: request.tenant_id,
            organization_id,
            project_id,
            purpose: request.purpose.trim().to_owned(),
            backend_kind: request.backend_kind,
            display_mask,
            fingerprint,
            status: SecretRefStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.secret_refs).insert(secret_ref_id.clone(), record.clone());
        write_lock(&self.secret_values).insert(secret_ref_id, request.secret_value);
        Ok(record)
    }

    fn secret_refs_for_tenant(&self, tenant_id: &str) -> Vec<SecretRefRecord> {
        let mut refs = read_lock(&self.secret_refs)
            .values()
            .filter(|secret_ref| secret_ref.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        refs.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| left.project_id.cmp(&right.project_id))
                .then_with(|| left.purpose.cmp(&right.purpose))
                .then_with(|| left.secret_ref_id.cmp(&right.secret_ref_id))
        });
        refs
    }

    fn secret_ref(&self, secret_ref_id: &str) -> Option<SecretRefRecord> {
        read_lock(&self.secret_refs).get(secret_ref_id).cloned()
    }

    fn secret_value(&self, secret_ref_id: &str) -> Option<SecretString> {
        let active = read_lock(&self.secret_refs)
            .get(secret_ref_id)
            .is_some_and(|record| {
                matches!(
                    record.status,
                    SecretRefStatus::Active | SecretRefStatus::Rotating
                )
            });
        if !active {
            return None;
        }
        read_lock(&self.secret_values)
            .get(secret_ref_id)
            .map(|value| SecretString::from(value.expose_secret().to_owned()))
    }
}

impl ProviderAdminRepository for InMemoryGatewayStore {
    fn create_provider_endpoint(
        &self,
        request: CreateProviderEndpointRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderEndpointRecord> {
        validate_optional_organization_scope(
            self,
            &request.tenant_id,
            request.organization_id.as_deref(),
        )?;
        let record = ProviderEndpointRecord {
            provider_endpoint_id: crate::domain::new_prefixed_id("pep"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            provider_kind: request.provider_kind,
            display_name: request.display_name,
            protocol_families: request.protocol_families,
            upstream_base_url: request.upstream_base_url,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.provider_endpoints)
            .insert(record.provider_endpoint_id.clone(), record.clone());
        Ok(record)
    }

    fn provider_endpoints_for_tenant(&self, tenant_id: &str) -> Vec<ProviderEndpointRecord> {
        let mut endpoints = read_lock(&self.provider_endpoints)
            .values()
            .filter(|endpoint| endpoint.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        endpoints.sort_by(|left, right| left.provider_endpoint_id.cmp(&right.provider_endpoint_id));
        endpoints
    }

    fn provider_endpoint(&self, provider_endpoint_id: &str) -> Option<ProviderEndpointRecord> {
        read_lock(&self.provider_endpoints)
            .get(provider_endpoint_id)
            .cloned()
    }

    fn update_provider_endpoint_status(
        &self,
        provider_endpoint_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderEndpointRecord> {
        let mut endpoints = write_lock(&self.provider_endpoints);
        let Some(endpoint) = endpoints.get_mut(provider_endpoint_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("provider endpoint {provider_endpoint_id}"),
            });
        };
        if endpoint.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        endpoint.status = status;
        endpoint.resource_version += 1;
        endpoint.updated_at = now;
        let updated = endpoint.clone();
        drop(endpoints);
        Ok(updated)
    }

    fn create_upstream_credential(
        &self,
        request: CreateUpstreamCredentialRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UpstreamCredentialRecord> {
        validate_upstream_credential_endpoint(self, &request)?;
        let record = UpstreamCredentialRecord {
            upstream_credential_id: crate::domain::new_prefixed_id("upc"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            provider_endpoint_id: request.provider_endpoint_id,
            credential_kind: request.credential_kind,
            secret_ref_id: request.secret_ref_id,
            status: UpstreamCredentialStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.upstream_credentials)
            .insert(record.upstream_credential_id.clone(), record.clone());
        Ok(record)
    }

    fn upstream_credentials_for_tenant(&self, tenant_id: &str) -> Vec<UpstreamCredentialRecord> {
        let mut credentials = read_lock(&self.upstream_credentials)
            .values()
            .filter(|credential| credential.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        credentials.sort_by(|left, right| {
            left.upstream_credential_id
                .cmp(&right.upstream_credential_id)
        });
        credentials
    }

    fn upstream_credential(
        &self,
        upstream_credential_id: &str,
    ) -> Option<UpstreamCredentialRecord> {
        read_lock(&self.upstream_credentials)
            .get(upstream_credential_id)
            .cloned()
    }

    fn update_upstream_credential_status(
        &self,
        upstream_credential_id: &str,
        expected_resource_version: i64,
        status: UpstreamCredentialStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<UpstreamCredentialRecord> {
        let mut credentials = write_lock(&self.upstream_credentials);
        let Some(credential) = credentials.get_mut(upstream_credential_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("upstream credential {upstream_credential_id}"),
            });
        };
        if credential.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        credential.status = status;
        credential.resource_version += 1;
        credential.updated_at = now;
        let updated = credential.clone();
        drop(credentials);
        Ok(updated)
    }
}

impl CodexOAuthRepository for InMemoryGatewayStore {
    fn create_codex_oauth_connection(
        &self,
        request: CreateCodexOAuthConnectionRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthConnectionRecord> {
        validate_codex_oauth_connection_request(self, &request)?;
        let record = CodexOAuthConnectionRecord {
            codex_oauth_connection_id: new_prefixed_id("coc"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            provider_endpoint_id: request.provider_endpoint_id,
            upstream_credential_id: None,
            display_name: request.display_name.trim().to_owned(),
            status: CodexOAuthConnectionStatus::Unauthenticated,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.codex_oauth_connections)
            .insert(record.codex_oauth_connection_id.clone(), record.clone());
        Ok(record)
    }

    fn codex_oauth_connections_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Vec<CodexOAuthConnectionRecord> {
        let mut connections = read_lock(&self.codex_oauth_connections)
            .values()
            .filter(|connection| connection.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        connections.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| left.display_name.cmp(&right.display_name))
                .then_with(|| {
                    left.codex_oauth_connection_id
                        .cmp(&right.codex_oauth_connection_id)
                })
        });
        connections
    }

    fn codex_oauth_connection(
        &self,
        codex_oauth_connection_id: &str,
    ) -> Option<CodexOAuthConnectionRecord> {
        read_lock(&self.codex_oauth_connections)
            .get(codex_oauth_connection_id)
            .cloned()
    }

    fn update_codex_oauth_connection_status(
        &self,
        codex_oauth_connection_id: &str,
        expected_resource_version: i64,
        status: CodexOAuthConnectionStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthConnectionRecord> {
        let mut connections = write_lock(&self.codex_oauth_connections);
        let Some(connection) = connections.get_mut(codex_oauth_connection_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("codex oauth connection {codex_oauth_connection_id}"),
            });
        };
        if connection.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        if status == CodexOAuthConnectionStatus::Disabled {
            if let Some(upstream_credential_id) = connection.upstream_credential_id.as_deref() {
                disable_upstream_credential_if_current(self, upstream_credential_id, now);
            }
        }
        if status == CodexOAuthConnectionStatus::Unauthenticated {
            connection.upstream_credential_id = None;
        }
        connection.status = status;
        connection.resource_version += 1;
        connection.updated_at = now;
        let updated = connection.clone();
        drop(connections);
        Ok(updated)
    }

    fn start_codex_oauth_session(
        &self,
        request: StartCodexOAuthSessionRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthSessionRecord> {
        if request
            .token_expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            return Err(GatewayError::BadRequest {
                message: "codex_oauth_token_expired".to_owned(),
            });
        }
        let connection = validate_codex_oauth_session_request(self, &request)?;
        let credential = self.create_upstream_credential(
            CreateUpstreamCredentialRequest {
                tenant_id: request.tenant_id.clone(),
                organization_id: connection.organization_id,
                provider_endpoint_id: connection.provider_endpoint_id,
                credential_kind: "codex_oauth".to_owned(),
                secret_ref_id: request.token_secret_ref_id.clone(),
                created_by: request.created_by.clone(),
            },
            now,
        )?;
        let record = CodexOAuthSessionRecord {
            codex_oauth_session_id: new_prefixed_id("cos"),
            tenant_id: request.tenant_id,
            codex_oauth_connection_id: request.codex_oauth_connection_id,
            upstream_credential_id: credential.upstream_credential_id.clone(),
            token_secret_ref_id: request.token_secret_ref_id,
            token_expires_at: request.token_expires_at,
            status: CodexOAuthSessionStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            revoked_at: None,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.codex_oauth_sessions)
            .insert(record.codex_oauth_session_id.clone(), record.clone());
        {
            let mut connections = write_lock(&self.codex_oauth_connections);
            let Some(connection) = connections.get_mut(&record.codex_oauth_connection_id) else {
                return Err(GatewayError::NotFound {
                    resource: format!(
                        "codex oauth connection {}",
                        record.codex_oauth_connection_id
                    ),
                });
            };
            connection.upstream_credential_id = Some(credential.upstream_credential_id);
            connection.status = CodexOAuthConnectionStatus::Active;
            connection.resource_version += 1;
            connection.updated_at = now;
            drop(connections);
        }
        Ok(record)
    }

    fn codex_oauth_sessions_for_connection(
        &self,
        tenant_id: &str,
        codex_oauth_connection_id: &str,
    ) -> Vec<CodexOAuthSessionRecord> {
        let mut sessions = read_lock(&self.codex_oauth_sessions)
            .values()
            .filter(|session| {
                session.tenant_id == tenant_id
                    && session.codex_oauth_connection_id == codex_oauth_connection_id
            })
            .cloned()
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            right.created_at.cmp(&left.created_at).then_with(|| {
                left.codex_oauth_session_id
                    .cmp(&right.codex_oauth_session_id)
            })
        });
        sessions
    }

    fn codex_oauth_session(&self, codex_oauth_session_id: &str) -> Option<CodexOAuthSessionRecord> {
        read_lock(&self.codex_oauth_sessions)
            .get(codex_oauth_session_id)
            .cloned()
    }

    fn revoke_codex_oauth_session(
        &self,
        codex_oauth_session_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<CodexOAuthSessionRecord> {
        let mut sessions = write_lock(&self.codex_oauth_sessions);
        let Some(session) = sessions.get_mut(codex_oauth_session_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("codex oauth session {codex_oauth_session_id}"),
            });
        };
        session.status = CodexOAuthSessionStatus::Revoked;
        session.resource_version += 1;
        session.revoked_at = Some(now);
        session.updated_at = now;
        let updated = session.clone();
        drop(sessions);

        disable_upstream_credential_if_current(self, &updated.upstream_credential_id, now);
        {
            let mut connections = write_lock(&self.codex_oauth_connections);
            if let Some(connection) = connections.get_mut(&updated.codex_oauth_connection_id) {
                if connection.upstream_credential_id.as_deref()
                    == Some(&updated.upstream_credential_id)
                {
                    connection.upstream_credential_id = None;
                    connection.status = CodexOAuthConnectionStatus::Unauthenticated;
                    connection.resource_version += 1;
                    connection.updated_at = now;
                }
            }
            drop(connections);
        }
        Ok(updated)
    }

    fn codex_oauth_refresh_status(
        &self,
        tenant_id: &str,
        codex_oauth_connection_id: &str,
    ) -> Option<CodexOAuthRefreshStatusRecord> {
        let connection = self.codex_oauth_connection(codex_oauth_connection_id)?;
        if connection.tenant_id != tenant_id {
            return None;
        }
        let latest_session = self
            .codex_oauth_sessions_for_connection(tenant_id, codex_oauth_connection_id)
            .into_iter()
            .find(|session| {
                connection.upstream_credential_id.as_deref()
                    == Some(session.upstream_credential_id.as_str())
            });
        Some(CodexOAuthRefreshStatusRecord {
            codex_oauth_refresh_status_id: format!("cofr_{codex_oauth_connection_id}"),
            tenant_id: tenant_id.to_owned(),
            codex_oauth_connection_id: codex_oauth_connection_id.to_owned(),
            upstream_credential_id: connection.upstream_credential_id,
            status: connection.status,
            last_refresh_at: None,
            next_refresh_at: latest_session
                .as_ref()
                .and_then(|session| session.token_expires_at)
                .map(|expires_at| expires_at - chrono::Duration::minutes(5)),
            token_expires_at: latest_session.and_then(|session| session.token_expires_at),
            last_error: None,
            updated_at: connection.updated_at,
        })
    }
}

impl CatalogAdminRepository for InMemoryGatewayStore {
    fn create_model_target(
        &self,
        request: CreateModelTargetRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelTargetRecord> {
        validate_model_target_refs(self, &request)?;
        let record = ModelTargetRecord {
            model_target_id: crate::domain::new_prefixed_id("mt"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            provider_endpoint_id: request.provider_endpoint_id,
            upstream_credential_id: request.upstream_credential_id,
            protocol_family: request.protocol_family,
            upstream_model_id: request.upstream_model_id,
            supports_streaming: request.supports_streaming,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.model_targets).insert(record.model_target_id.clone(), record.clone());
        Ok(record)
    }

    fn model_targets_for_tenant(&self, tenant_id: &str) -> Vec<ModelTargetRecord> {
        let mut targets = read_lock(&self.model_targets)
            .values()
            .filter(|target| target.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| left.model_target_id.cmp(&right.model_target_id));
        targets
    }

    fn model_target(&self, model_target_id: &str) -> Option<ModelTargetRecord> {
        read_lock(&self.model_targets).get(model_target_id).cloned()
    }

    fn update_model_target_status(
        &self,
        model_target_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelTargetRecord> {
        let mut targets = write_lock(&self.model_targets);
        let Some(target) = targets.get_mut(model_target_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("model target {model_target_id}"),
            });
        };
        if target.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        target.status = status;
        target.resource_version += 1;
        target.updated_at = now;
        let updated = target.clone();
        drop(targets);
        Ok(updated)
    }

    fn create_routing_group(
        &self,
        request: CreateRoutingGroupRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupRecord> {
        validate_routing_group_request(self, &request)?;
        let record = RoutingGroupRecord {
            routing_group_id: crate::domain::new_prefixed_id("rg"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            name: request.name.trim().to_owned(),
            protocol_family: request.protocol_family,
            purpose: request.purpose,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.routing_groups).insert(record.routing_group_id.clone(), record.clone());
        Ok(record)
    }

    fn routing_groups_for_tenant(&self, tenant_id: &str) -> Vec<RoutingGroupRecord> {
        let mut groups = read_lock(&self.routing_groups)
            .values()
            .filter(|group| group.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.routing_group_id.cmp(&right.routing_group_id))
        });
        groups
    }

    fn routing_group(&self, routing_group_id: &str) -> Option<RoutingGroupRecord> {
        read_lock(&self.routing_groups)
            .get(routing_group_id)
            .cloned()
    }

    fn update_routing_group_status(
        &self,
        routing_group_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupRecord> {
        let mut groups = write_lock(&self.routing_groups);
        let Some(group) = groups.get_mut(routing_group_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("routing group {routing_group_id}"),
            });
        };
        if group.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        group.status = status;
        group.resource_version += 1;
        group.updated_at = now;
        let updated = group.clone();
        drop(groups);
        Ok(updated)
    }

    fn create_routing_group_target(
        &self,
        request: CreateRoutingGroupTargetRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupTargetRecord> {
        validate_routing_group_target_refs(self, &request)?;
        let record = RoutingGroupTargetRecord {
            routing_group_target_id: crate::domain::new_prefixed_id("rgt"),
            tenant_id: request.tenant_id,
            routing_group_id: request.routing_group_id,
            model_target_id: request.model_target_id,
            weight: request.weight,
            priority: request.priority,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.routing_group_targets)
            .insert(record.routing_group_target_id.clone(), record.clone());
        Ok(record)
    }

    fn routing_group_targets_for_group(
        &self,
        tenant_id: &str,
        routing_group_id: &str,
    ) -> Vec<RoutingGroupTargetRecord> {
        let mut targets = read_lock(&self.routing_group_targets)
            .values()
            .filter(|target| {
                target.tenant_id == tenant_id && target.routing_group_id == routing_group_id
            })
            .cloned()
            .collect::<Vec<_>>();
        targets.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| {
                    left.routing_group_target_id
                        .cmp(&right.routing_group_target_id)
                })
        });
        targets
    }

    fn routing_group_target(
        &self,
        routing_group_target_id: &str,
    ) -> Option<RoutingGroupTargetRecord> {
        read_lock(&self.routing_group_targets)
            .get(routing_group_target_id)
            .cloned()
    }

    fn update_routing_group_target_status(
        &self,
        routing_group_target_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutingGroupTargetRecord> {
        let mut targets = write_lock(&self.routing_group_targets);
        let Some(target) = targets.get_mut(routing_group_target_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("routing group target {routing_group_target_id}"),
            });
        };
        if target.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        target.status = status;
        target.resource_version += 1;
        target.updated_at = now;
        let updated = target.clone();
        drop(targets);
        Ok(updated)
    }

    fn create_model_alias(
        &self,
        request: CreateModelAliasRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelAliasRecord> {
        validate_model_alias_request(self, &request)?;
        let record = ModelAliasRecord {
            model_alias_id: crate::domain::new_prefixed_id("ma"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            alias_name: request.alias_name.trim().to_owned(),
            protocol_family: request.protocol_family,
            route_policy_id: request.route_policy_id,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.model_aliases).insert(record.model_alias_id.clone(), record.clone());
        Ok(record)
    }

    fn model_aliases_for_tenant(&self, tenant_id: &str) -> Vec<ModelAliasRecord> {
        let mut aliases = read_lock(&self.model_aliases)
            .values()
            .filter(|alias| alias.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        aliases.sort_by(|left, right| {
            left.alias_name
                .cmp(&right.alias_name)
                .then_with(|| left.model_alias_id.cmp(&right.model_alias_id))
        });
        aliases
    }

    fn model_alias(&self, model_alias_id: &str) -> Option<ModelAliasRecord> {
        read_lock(&self.model_aliases).get(model_alias_id).cloned()
    }

    fn update_model_alias(
        &self,
        model_alias_id: &str,
        request: UpdateModelAliasRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ModelAliasRecord> {
        if request.status.is_none() && request.route_policy_id.is_none() {
            return Err(GatewayError::BadRequest {
                message: "model_alias_update_empty".to_owned(),
            });
        }
        if let Some(route_policy_id) = request.route_policy_id.as_deref() {
            validate_model_alias_route_policy_binding(self, model_alias_id, route_policy_id)?;
        }
        let mut aliases = write_lock(&self.model_aliases);
        let Some(alias) = aliases.get_mut(model_alias_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("model alias {model_alias_id}"),
            });
        };
        if alias.resource_version != request.expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        if let Some(status) = request.status {
            alias.status = status;
        }
        if let Some(route_policy_id) = request.route_policy_id {
            alias.route_policy_id = Some(route_policy_id);
        }
        alias.resource_version += 1;
        alias.updated_at = now;
        let updated = alias.clone();
        drop(aliases);
        Ok(updated)
    }

    fn create_route_policy(
        &self,
        request: CreateRoutePolicyRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutePolicyRecord> {
        let (alias, group, organization_id) = validate_route_policy_request(self, &request)?;
        let record = RoutePolicyRecord {
            route_policy_id: crate::domain::new_prefixed_id("rp"),
            tenant_id: request.tenant_id,
            organization_id,
            name: request.name.trim().to_owned(),
            protocol_family: alias.protocol_family,
            model_alias_id: alias.model_alias_id,
            routing_group_id: group.routing_group_id,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.route_policies).insert(record.route_policy_id.clone(), record.clone());
        Ok(record)
    }

    fn route_policies_for_tenant(&self, tenant_id: &str) -> Vec<RoutePolicyRecord> {
        let mut policies = read_lock(&self.route_policies)
            .values()
            .filter(|policy| policy.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        policies.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.route_policy_id.cmp(&right.route_policy_id))
        });
        policies
    }

    fn route_policy(&self, route_policy_id: &str) -> Option<RoutePolicyRecord> {
        read_lock(&self.route_policies)
            .get(route_policy_id)
            .cloned()
    }

    fn update_route_policy_status(
        &self,
        route_policy_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<RoutePolicyRecord> {
        let mut policies = write_lock(&self.route_policies);
        let Some(policy) = policies.get_mut(route_policy_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("route policy {route_policy_id}"),
            });
        };
        if policy.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        policy.status = status;
        policy.resource_version += 1;
        policy.updated_at = now;
        let updated = policy.clone();
        drop(policies);
        Ok(updated)
    }

    fn create_provider_grant(
        &self,
        request: CreateProviderGrantRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderGrantRecord> {
        let (organization_id, project_id) = validate_provider_grant_request(self, &request)?;
        let record = ProviderGrantRecord {
            provider_grant_id: crate::domain::new_prefixed_id("pg"),
            tenant_id: request.tenant_id,
            scope_kind: request.scope_kind,
            scope_id: request.scope_id,
            organization_id,
            project_id,
            resource_kind: request.resource_kind,
            resource_id: request.resource_id,
            effect: request.effect,
            closure_mode: request.closure_mode,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.provider_grants).insert(record.provider_grant_id.clone(), record.clone());
        Ok(record)
    }

    fn provider_grants_for_tenant(&self, tenant_id: &str) -> Vec<ProviderGrantRecord> {
        let mut grants = read_lock(&self.provider_grants)
            .values()
            .filter(|grant| grant.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        grants.sort_by(|left, right| {
            left.scope_kind
                .cmp(&right.scope_kind)
                .then_with(|| left.scope_id.cmp(&right.scope_id))
                .then_with(|| left.resource_kind.cmp(&right.resource_kind))
                .then_with(|| left.resource_id.cmp(&right.resource_id))
                .then_with(|| left.provider_grant_id.cmp(&right.provider_grant_id))
        });
        grants
    }

    fn provider_grant(&self, provider_grant_id: &str) -> Option<ProviderGrantRecord> {
        read_lock(&self.provider_grants)
            .get(provider_grant_id)
            .cloned()
    }

    fn update_provider_grant_status(
        &self,
        provider_grant_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProviderGrantRecord> {
        let mut grants = write_lock(&self.provider_grants);
        let Some(grant) = grants.get_mut(provider_grant_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("provider grant {provider_grant_id}"),
            });
        };
        if grant.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        grant.status = status;
        grant.resource_version += 1;
        grant.updated_at = now;
        let updated = grant.clone();
        drop(grants);
        Ok(updated)
    }

    fn create_pricing_sku(
        &self,
        request: CreatePricingSkuRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PricingSkuRecord> {
        validate_pricing_sku_request(self, &request)?;
        let record = PricingSkuRecord {
            pricing_sku_id: crate::domain::new_prefixed_id("sku"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            name: request.name.trim().to_owned(),
            currency: request.currency,
            unit: request.unit,
            model_id_patterns: request.model_id_patterns,
            provider_endpoint_patterns: request.provider_endpoint_patterns,
            pricing_document: request.pricing_document,
            pricing_version: 1,
            effective_from: request.effective_from,
            effective_until: request.effective_until,
            is_preset: request.is_preset,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.pricing_skus).insert(record.pricing_sku_id.clone(), record.clone());
        Ok(record)
    }

    fn pricing_skus_for_tenant(&self, tenant_id: &str) -> Vec<PricingSkuRecord> {
        let mut skus = read_lock(&self.pricing_skus)
            .values()
            .filter(|sku| sku.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        skus.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.pricing_sku_id.cmp(&right.pricing_sku_id))
        });
        skus
    }

    fn pricing_sku(&self, pricing_sku_id: &str) -> Option<PricingSkuRecord> {
        read_lock(&self.pricing_skus).get(pricing_sku_id).cloned()
    }

    fn update_pricing_sku_status(
        &self,
        pricing_sku_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<PricingSkuRecord> {
        let mut skus = write_lock(&self.pricing_skus);
        let Some(sku) = skus.get_mut(pricing_sku_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("pricing SKU {pricing_sku_id}"),
            });
        };
        if sku.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        sku.status = status;
        sku.resource_version += 1;
        sku.updated_at = now;
        let updated = sku.clone();
        drop(skus);
        Ok(updated)
    }

    fn create_budget_policy(
        &self,
        request: CreateBudgetPolicyRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<BudgetPolicyRecord> {
        let (organization_id, project_id) = validate_budget_policy_request(self, &request)?;
        let record = BudgetPolicyRecord {
            budget_policy_id: crate::domain::new_prefixed_id("bp"),
            tenant_id: request.tenant_id,
            scope_kind: request.scope_kind,
            scope_id: request.scope_id,
            organization_id,
            project_id,
            currency: request.currency,
            period: request.period,
            limit_kind: request.limit_kind,
            hard_limit: request.hard_limit,
            soft_limit: request.soft_limit,
            thresholds: request.thresholds,
            reset_policy: request.reset_policy,
            overage_mode: request.overage_mode,
            consistency_mode: request.consistency_mode,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.budget_policies).insert(record.budget_policy_id.clone(), record.clone());
        Ok(record)
    }

    fn budget_policies_for_tenant(&self, tenant_id: &str) -> Vec<BudgetPolicyRecord> {
        let mut policies = read_lock(&self.budget_policies)
            .values()
            .filter(|policy| policy.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        policies.sort_by(|left, right| {
            left.scope_kind
                .cmp(&right.scope_kind)
                .then_with(|| left.scope_id.cmp(&right.scope_id))
                .then_with(|| left.limit_kind.cmp(&right.limit_kind))
                .then_with(|| left.budget_policy_id.cmp(&right.budget_policy_id))
        });
        policies
    }

    fn budget_policy(&self, budget_policy_id: &str) -> Option<BudgetPolicyRecord> {
        read_lock(&self.budget_policies)
            .get(budget_policy_id)
            .cloned()
    }

    fn update_budget_policy_status(
        &self,
        budget_policy_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<BudgetPolicyRecord> {
        let mut policies = write_lock(&self.budget_policies);
        let Some(policy) = policies.get_mut(budget_policy_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("budget policy {budget_policy_id}"),
            });
        };
        if policy.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        policy.status = status;
        policy.resource_version += 1;
        policy.updated_at = now;
        let updated = policy.clone();
        drop(policies);
        Ok(updated)
    }

    fn create_quota_policy(
        &self,
        request: CreateQuotaPolicyRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<QuotaPolicyRecord> {
        let (organization_id, project_id) = validate_quota_policy_request(self, &request)?;
        let record = QuotaPolicyRecord {
            quota_policy_id: crate::domain::new_prefixed_id("qp"),
            tenant_id: request.tenant_id,
            scope_kind: request.scope_kind,
            scope_id: request.scope_id,
            organization_id,
            project_id,
            counter_kind: request.counter_kind,
            limit: request.limit,
            burst_limit: request.burst_limit,
            window: request.window,
            increment_source: request.increment_source,
            loss_behavior: request.loss_behavior,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.quota_policies).insert(record.quota_policy_id.clone(), record.clone());
        Ok(record)
    }

    fn quota_policies_for_tenant(&self, tenant_id: &str) -> Vec<QuotaPolicyRecord> {
        let mut policies = read_lock(&self.quota_policies)
            .values()
            .filter(|policy| policy.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        policies.sort_by(|left, right| {
            left.scope_kind
                .cmp(&right.scope_kind)
                .then_with(|| left.scope_id.cmp(&right.scope_id))
                .then_with(|| left.counter_kind.cmp(&right.counter_kind))
                .then_with(|| left.quota_policy_id.cmp(&right.quota_policy_id))
        });
        policies
    }

    fn quota_policy(&self, quota_policy_id: &str) -> Option<QuotaPolicyRecord> {
        read_lock(&self.quota_policies)
            .get(quota_policy_id)
            .cloned()
    }

    fn update_quota_policy_status(
        &self,
        quota_policy_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<QuotaPolicyRecord> {
        let mut policies = write_lock(&self.quota_policies);
        let Some(policy) = policies.get_mut(quota_policy_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("quota policy {quota_policy_id}"),
            });
        };
        if policy.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        policy.status = status;
        policy.resource_version += 1;
        policy.updated_at = now;
        let updated = policy.clone();
        drop(policies);
        Ok(updated)
    }

    fn create_otel_export_config(
        &self,
        request: CreateOtelExportConfigRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExportConfigRecord> {
        let (organization_id, project_id) = validate_otel_export_config_request(self, &request)?;
        let record = OtelExportConfigRecord {
            otel_export_config_id: crate::domain::new_prefixed_id("otel"),
            tenant_id: request.tenant_id,
            organization_id,
            project_id,
            endpoint_url: request.endpoint_url,
            protocol: request.protocol,
            header_refs: request.header_refs,
            enabled_signals: request.enabled_signals,
            resource_attributes: request.resource_attributes,
            export_interval_seconds: request.export_interval_seconds,
            timeout_seconds: request.timeout_seconds,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.otel_export_configs)
            .insert(record.otel_export_config_id.clone(), record.clone());
        Ok(record)
    }

    fn otel_export_configs_for_tenant(&self, tenant_id: &str) -> Vec<OtelExportConfigRecord> {
        let mut configs = read_lock(&self.otel_export_configs)
            .values()
            .filter(|config| config.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        configs.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| left.project_id.cmp(&right.project_id))
                .then_with(|| left.endpoint_url.cmp(&right.endpoint_url))
                .then_with(|| left.otel_export_config_id.cmp(&right.otel_export_config_id))
        });
        configs
    }

    fn otel_export_config(&self, otel_export_config_id: &str) -> Option<OtelExportConfigRecord> {
        read_lock(&self.otel_export_configs)
            .get(otel_export_config_id)
            .cloned()
    }

    fn update_otel_export_config_status(
        &self,
        otel_export_config_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExportConfigRecord> {
        let mut configs = write_lock(&self.otel_export_configs);
        let Some(config) = configs.get_mut(otel_export_config_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("otel export config {otel_export_config_id}"),
            });
        };
        if config.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        config.status = status;
        config.resource_version += 1;
        config.updated_at = now;
        let updated = config.clone();
        drop(configs);
        Ok(updated)
    }

    fn update_otel_export_config(
        &self,
        otel_export_config_id: &str,
        request: UpdateOtelExportConfigRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExportConfigRecord> {
        let current = self
            .otel_export_config(otel_export_config_id)
            .ok_or_else(|| GatewayError::NotFound {
                resource: format!("otel export config {otel_export_config_id}"),
            })?;
        if current.resource_version != request.expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        let merged = CreateOtelExportConfigRequest {
            tenant_id: current.tenant_id.clone(),
            organization_id: request
                .organization_id
                .or_else(|| current.organization_id.clone()),
            project_id: request.project_id.or_else(|| current.project_id.clone()),
            endpoint_url: request
                .endpoint_url
                .unwrap_or_else(|| current.endpoint_url.clone()),
            protocol: request.protocol.unwrap_or_else(|| current.protocol.clone()),
            header_refs: request
                .header_refs
                .unwrap_or_else(|| current.header_refs.clone()),
            enabled_signals: request
                .enabled_signals
                .unwrap_or_else(|| current.enabled_signals.clone()),
            resource_attributes: request
                .resource_attributes
                .unwrap_or_else(|| current.resource_attributes.clone()),
            export_interval_seconds: request
                .export_interval_seconds
                .unwrap_or(current.export_interval_seconds),
            timeout_seconds: request.timeout_seconds.unwrap_or(current.timeout_seconds),
            created_by: current.created_by,
        };
        let (organization_id, project_id) = validate_otel_export_config_request_with_excluded_id(
            self,
            &merged,
            Some(otel_export_config_id),
        )?;
        let mut configs = write_lock(&self.otel_export_configs);
        let Some(config) = configs.get_mut(otel_export_config_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("otel export config {otel_export_config_id}"),
            });
        };
        config.organization_id = organization_id;
        config.project_id = project_id;
        config.endpoint_url = merged.endpoint_url;
        config.protocol = merged.protocol;
        config.header_refs = merged.header_refs;
        config.enabled_signals = merged.enabled_signals;
        config.resource_attributes = merged.resource_attributes;
        config.export_interval_seconds = merged.export_interval_seconds;
        config.timeout_seconds = merged.timeout_seconds;
        if let Some(status) = request.status {
            config.status = status;
        }
        config.resource_version += 1;
        config.updated_at = now;
        let updated = config.clone();
        drop(configs);
        Ok(updated)
    }

    fn record_otel_exporter_health(
        &self,
        request: RecordOtelExporterHealthRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<OtelExporterHealthRecord> {
        if request.exported_metric_count < 0 || request.dropped_metric_count < 0 {
            return Err(GatewayError::BadRequest {
                message: "otel_exporter_metric_counts_invalid".to_owned(),
            });
        }
        let Some(config) = self.otel_export_config(&request.otel_export_config_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("otel export config {}", request.otel_export_config_id),
            });
        };
        if config.tenant_id != request.tenant_id {
            return Err(GatewayError::BadRequest {
                message: "otel_export_config_tenant_mismatch".to_owned(),
            });
        }
        let mut health = write_lock(&self.otel_exporter_health);
        let previous = health.get(&request.otel_export_config_id);
        let failure_count = if request.status == "succeeded" || request.status == "disabled" {
            0
        } else {
            previous.map_or(1, |record| record.failure_count.saturating_add(1))
        };
        let last_successful_export_at = if request.status == "succeeded" {
            Some(now)
        } else {
            previous.and_then(|record| record.last_successful_export_at)
        };
        let record = OtelExporterHealthRecord {
            otel_exporter_health_id: previous.map_or_else(
                || crate::domain::new_prefixed_id("otelh"),
                |record| record.otel_exporter_health_id.clone(),
            ),
            tenant_id: request.tenant_id,
            otel_export_config_id: request.otel_export_config_id,
            worker_id: request.worker_id,
            status: request.status,
            failure_count,
            dropped_metric_count: request.dropped_metric_count,
            exported_metric_count: request.exported_metric_count,
            last_error: request.last_error,
            last_attempted_at: now,
            last_successful_export_at,
            created_at: previous.map_or(now, |record| record.created_at),
            updated_at: now,
        };
        health.insert(record.otel_export_config_id.clone(), record.clone());
        drop(health);
        Ok(record)
    }

    fn otel_exporter_health(
        &self,
        otel_export_config_id: &str,
    ) -> Option<OtelExporterHealthRecord> {
        read_lock(&self.otel_exporter_health)
            .get(otel_export_config_id)
            .cloned()
    }

    fn otel_exporter_health_for_tenant(&self, tenant_id: &str) -> Vec<OtelExporterHealthRecord> {
        let mut records = read_lock(&self.otel_exporter_health)
            .values()
            .filter(|record| record.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            right
                .last_attempted_at
                .cmp(&left.last_attempted_at)
                .then_with(|| left.otel_export_config_id.cmp(&right.otel_export_config_id))
        });
        records
    }

    fn create_notification_sink(
        &self,
        request: CreateNotificationSinkRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSinkRecord> {
        let (organization_id, project_id) = validate_notification_sink_request(self, &request)?;
        let record = NotificationSinkRecord {
            notification_sink_id: crate::domain::new_prefixed_id("ns"),
            tenant_id: request.tenant_id,
            organization_id,
            project_id,
            name: request.name.trim().to_owned(),
            sink_kind: request.sink_kind,
            endpoint_config: request.endpoint_config,
            signing_secret_ref_id: request.signing_secret_ref_id,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.notification_sinks)
            .insert(record.notification_sink_id.clone(), record.clone());
        Ok(record)
    }

    fn notification_sinks_for_tenant(&self, tenant_id: &str) -> Vec<NotificationSinkRecord> {
        let mut sinks = read_lock(&self.notification_sinks)
            .values()
            .filter(|sink| sink.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        sinks.sort_by(|left, right| {
            left.organization_id
                .cmp(&right.organization_id)
                .then_with(|| left.project_id.cmp(&right.project_id))
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.notification_sink_id.cmp(&right.notification_sink_id))
        });
        sinks
    }

    fn notification_sink(&self, notification_sink_id: &str) -> Option<NotificationSinkRecord> {
        read_lock(&self.notification_sinks)
            .get(notification_sink_id)
            .cloned()
    }

    fn update_notification_sink(
        &self,
        notification_sink_id: &str,
        request: UpdateNotificationSinkRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSinkRecord> {
        let current = self
            .notification_sink(notification_sink_id)
            .ok_or_else(|| GatewayError::NotFound {
                resource: format!("notification sink {notification_sink_id}"),
            })?;
        if current.resource_version != request.expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        let merged = CreateNotificationSinkRequest {
            tenant_id: current.tenant_id.clone(),
            organization_id: current.organization_id.clone(),
            project_id: current.project_id.clone(),
            name: request.name.unwrap_or_else(|| current.name.clone()),
            sink_kind: current.sink_kind.clone(),
            endpoint_config: request
                .endpoint_config
                .unwrap_or_else(|| current.endpoint_config.clone()),
            signing_secret_ref_id: request
                .signing_secret_ref_id
                .resolve(current.signing_secret_ref_id.clone()),
            created_by: current.created_by,
        };
        validate_notification_sink_request_with_excluded_id(
            self,
            &merged,
            Some(notification_sink_id),
        )?;
        let mut sinks = write_lock(&self.notification_sinks);
        let Some(sink) = sinks.get_mut(notification_sink_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("notification sink {notification_sink_id}"),
            });
        };
        merged.name.trim().clone_into(&mut sink.name);
        sink.endpoint_config = merged.endpoint_config;
        sink.signing_secret_ref_id = merged.signing_secret_ref_id;
        if let Some(status) = request.status {
            sink.status = status;
        }
        sink.resource_version += 1;
        sink.updated_at = now;
        let updated = sink.clone();
        drop(sinks);
        Ok(updated)
    }

    fn create_notification_subscription(
        &self,
        request: CreateNotificationSubscriptionRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSubscriptionRecord> {
        let sink = validate_notification_subscription_request(self, &request)?;
        let record = NotificationSubscriptionRecord {
            notification_subscription_id: crate::domain::new_prefixed_id("nsub"),
            tenant_id: request.tenant_id,
            organization_id: sink.organization_id,
            project_id: sink.project_id,
            notification_sink_id: request.notification_sink_id,
            event_family: request.event_family,
            filter_document: request.filter_document,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.notification_subscriptions)
            .insert(record.notification_subscription_id.clone(), record.clone());
        Ok(record)
    }

    fn notification_subscriptions_for_sink(
        &self,
        notification_sink_id: &str,
    ) -> Vec<NotificationSubscriptionRecord> {
        let mut subscriptions = read_lock(&self.notification_subscriptions)
            .values()
            .filter(|subscription| subscription.notification_sink_id == notification_sink_id)
            .cloned()
            .collect::<Vec<_>>();
        subscriptions.sort_by(|left, right| {
            left.event_family.cmp(&right.event_family).then_with(|| {
                left.notification_subscription_id
                    .cmp(&right.notification_subscription_id)
            })
        });
        subscriptions
    }

    fn notification_subscription(
        &self,
        notification_subscription_id: &str,
    ) -> Option<NotificationSubscriptionRecord> {
        read_lock(&self.notification_subscriptions)
            .get(notification_subscription_id)
            .cloned()
    }

    fn update_notification_subscription_status(
        &self,
        notification_subscription_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<NotificationSubscriptionRecord> {
        let mut subscriptions = write_lock(&self.notification_subscriptions);
        let Some(subscription) = subscriptions.get_mut(notification_subscription_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("notification subscription {notification_subscription_id}"),
            });
        };
        if subscription.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        subscription.status = status;
        subscription.resource_version += 1;
        subscription.updated_at = now;
        let updated = subscription.clone();
        drop(subscriptions);
        Ok(updated)
    }

    fn create_login_provider(
        &self,
        request: CreateLoginProviderRequest,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<LoginProviderRecord> {
        validate_login_provider_request(self, &request)?;
        let record = LoginProviderRecord {
            login_provider_id: new_prefixed_id("lp"),
            tenant_id: request.tenant_id,
            provider_kind: request.provider_kind,
            display_name: request.display_name.trim().to_owned(),
            config_document: request.config_document,
            status: ResourceStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        };
        write_lock(&self.login_providers).insert(record.login_provider_id.clone(), record.clone());
        Ok(record)
    }

    fn login_providers_for_tenant(&self, tenant_id: &str) -> Vec<LoginProviderRecord> {
        let mut providers = read_lock(&self.login_providers)
            .values()
            .filter(|provider| provider.tenant_id == tenant_id)
            .cloned()
            .collect::<Vec<_>>();
        providers.sort_by(|left, right| {
            left.provider_kind
                .cmp(&right.provider_kind)
                .then_with(|| left.display_name.cmp(&right.display_name))
                .then_with(|| left.login_provider_id.cmp(&right.login_provider_id))
        });
        providers
    }

    fn login_provider(&self, login_provider_id: &str) -> Option<LoginProviderRecord> {
        read_lock(&self.login_providers)
            .get(login_provider_id)
            .cloned()
    }

    fn update_login_provider_status(
        &self,
        login_provider_id: &str,
        expected_resource_version: i64,
        status: ResourceStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<LoginProviderRecord> {
        let mut providers = write_lock(&self.login_providers);
        let Some(provider) = providers.get_mut(login_provider_id) else {
            return Err(GatewayError::NotFound {
                resource: format!("login provider {login_provider_id}"),
            });
        };
        if provider.resource_version != expected_resource_version {
            return Err(GatewayError::BadRequest {
                message: "stale_resource_version".to_owned(),
            });
        }
        provider.status = status;
        provider.resource_version += 1;
        provider.updated_at = now;
        let updated = provider.clone();
        drop(providers);
        Ok(updated)
    }
}

impl AuthorizationEvidenceSink for InMemoryGatewayStore {
    fn record_authorization_decision(&self, record: AuthorizationDecisionRecord) {
        let mut authz_decisions = match self.authz_decisions.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        authz_decisions.push(record);
    }
}

impl RouteEvidenceSink for InMemoryGatewayStore {
    fn record_route_decision(&self, record: RouteDecisionRecord) {
        let mut route_decisions = match self.route_decisions.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        route_decisions.push(record);
    }

    fn record_route_attempt(&self, record: RouteAttemptRecord) {
        let mut route_attempts = match self.route_attempts.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        route_attempts.push(record);
    }
}

impl RouteHotState for InMemoryGatewayStore {
    fn endpoint_health_state(
        &self,
        tenant_id: &str,
        provider_endpoint_id: &str,
        config_version: Option<i64>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> EndpointHealthState {
        let endpoint_health = match self.endpoint_health.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        endpoint_health
            .get(&(tenant_id.to_owned(), provider_endpoint_id.to_owned()))
            .filter(|record| record.is_fresh_for(config_version, now))
            .map_or(EndpointHealthState::Unknown, |record| record.state)
    }

    fn endpoint_is_drained(
        &self,
        tenant_id: &str,
        provider_endpoint_id: &str,
        config_version: Option<i64>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        let endpoint_drains = match self.endpoint_drains.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        endpoint_drains
            .get(&(tenant_id.to_owned(), provider_endpoint_id.to_owned()))
            .is_some_and(|record| record.is_fresh_for(config_version, now))
    }

    fn sticky_route(
        &self,
        tenant_id: &str,
        project_id: Option<&str>,
        model_alias_id: &str,
        affinity_hash: &str,
        config_version: Option<i64>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<StickyRouteRecord> {
        let sticky_routes = match self.sticky_routes.read() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        sticky_routes
            .get(&(
                tenant_id.to_owned(),
                project_id.map(ToOwned::to_owned),
                model_alias_id.to_owned(),
                affinity_hash.to_owned(),
            ))
            .filter(|record| record.is_fresh_for(config_version, now))
            .cloned()
    }

    fn set_sticky_route(&self, record: StickyRouteRecord) {
        let mut sticky_routes = match self.sticky_routes.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        sticky_routes.insert(
            (
                record.tenant_id.clone(),
                record.project_id.clone(),
                record.model_alias_id.clone(),
                record.affinity_hash.clone(),
            ),
            record,
        );
    }
}

fn validate_optional_organization_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: Option<&str>,
) -> Result<()> {
    let Some(organization_id) = organization_id else {
        return Ok(());
    };
    let Some(organization) = read_lock(&store.organizations)
        .get(organization_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        });
    };
    if organization.tenant_id != tenant_id {
        return Err(GatewayError::Authorization {
            reason: "organization_tenant_mismatch",
        });
    }
    Ok(())
}

fn validate_upstream_credential_endpoint(
    store: &InMemoryGatewayStore,
    request: &CreateUpstreamCredentialRequest,
) -> Result<()> {
    validate_optional_organization_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
    )?;
    let Some(endpoint) = read_lock(&store.provider_endpoints)
        .get(&request.provider_endpoint_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("provider endpoint {}", request.provider_endpoint_id),
        });
    };
    if endpoint.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "provider_endpoint_tenant_mismatch",
        });
    }
    if request.organization_id.is_some()
        && endpoint.organization_id.is_some()
        && endpoint.organization_id != request.organization_id
    {
        return Err(GatewayError::Authorization {
            reason: "provider_endpoint_organization_mismatch",
        });
    }
    ensure_secret_ref_usable(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
        None,
        &request.secret_ref_id,
        "upstream_credential_secret_ref",
    )?;
    Ok(())
}

fn validate_codex_oauth_connection_request(
    store: &InMemoryGatewayStore,
    request: &CreateCodexOAuthConnectionRequest,
) -> Result<()> {
    validate_optional_organization_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
    )?;
    if request.display_name.trim().is_empty() || request.display_name.len() > 120 {
        return Err(GatewayError::BadRequest {
            message: "codex_oauth_connection_display_name_invalid".to_owned(),
        });
    }
    let Some(endpoint) = read_lock(&store.provider_endpoints)
        .get(&request.provider_endpoint_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("provider endpoint {}", request.provider_endpoint_id),
        });
    };
    if endpoint.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "provider_endpoint_tenant_mismatch",
        });
    }
    if endpoint.provider_kind != "codex" {
        return Err(GatewayError::BadRequest {
            message: "codex_oauth_requires_codex_provider_endpoint".to_owned(),
        });
    }
    if !endpoint
        .protocol_families
        .contains(&ProtocolFamily::OpenAiResponses)
    {
        return Err(GatewayError::BadRequest {
            message: "codex_oauth_requires_openai_responses_protocol".to_owned(),
        });
    }
    if request.organization_id.is_some()
        && endpoint.organization_id.is_some()
        && endpoint.organization_id != request.organization_id
    {
        return Err(GatewayError::Authorization {
            reason: "provider_endpoint_organization_mismatch",
        });
    }
    let duplicate = read_lock(&store.codex_oauth_connections)
        .values()
        .any(|connection| {
            connection.tenant_id == request.tenant_id
                && connection.organization_id == request.organization_id
                && connection.display_name == request.display_name.trim()
                && connection.status != CodexOAuthConnectionStatus::Disabled
        });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "codex_oauth_connection_conflict".to_owned(),
        });
    }
    Ok(())
}

fn validate_codex_oauth_session_request(
    store: &InMemoryGatewayStore,
    request: &StartCodexOAuthSessionRequest,
) -> Result<CodexOAuthConnectionRecord> {
    let Some(connection) = read_lock(&store.codex_oauth_connections)
        .get(&request.codex_oauth_connection_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!(
                "codex oauth connection {}",
                request.codex_oauth_connection_id
            ),
        });
    };
    if connection.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "codex_oauth_connection_tenant_mismatch",
        });
    }
    if connection.status == CodexOAuthConnectionStatus::Disabled {
        return Err(GatewayError::BadRequest {
            message: "codex_oauth_connection_disabled".to_owned(),
        });
    }
    ensure_secret_ref_usable(
        store,
        &request.tenant_id,
        connection.organization_id.as_deref(),
        None,
        &request.token_secret_ref_id,
        "codex_oauth_token_secret_ref",
    )?;
    Ok(connection)
}

fn disable_upstream_credential_if_current(
    store: &InMemoryGatewayStore,
    upstream_credential_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) {
    let mut credentials = write_lock(&store.upstream_credentials);
    if let Some(credential) = credentials.get_mut(upstream_credential_id) {
        credential.status = UpstreamCredentialStatus::Disabled;
        credential.resource_version += 1;
        credential.updated_at = now;
    }
}

fn validate_model_target_refs(
    store: &InMemoryGatewayStore,
    request: &CreateModelTargetRequest,
) -> Result<()> {
    validate_optional_organization_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
    )?;
    let Some(endpoint) = read_lock(&store.provider_endpoints)
        .get(&request.provider_endpoint_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("provider endpoint {}", request.provider_endpoint_id),
        });
    };
    if endpoint.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "provider_endpoint_tenant_mismatch",
        });
    }
    if !endpoint
        .protocol_families
        .contains(&request.protocol_family)
    {
        return Err(GatewayError::BadRequest {
            message: "provider_endpoint_protocol_mismatch".to_owned(),
        });
    }
    if let Some(credential_id) = request.upstream_credential_id.as_deref() {
        let Some(credential) = read_lock(&store.upstream_credentials)
            .get(credential_id)
            .cloned()
        else {
            return Err(GatewayError::NotFound {
                resource: format!("upstream credential {credential_id}"),
            });
        };
        if credential.tenant_id != request.tenant_id {
            return Err(GatewayError::Authorization {
                reason: "upstream_credential_tenant_mismatch",
            });
        }
        if credential.provider_endpoint_id != request.provider_endpoint_id {
            return Err(GatewayError::BadRequest {
                message: "upstream_credential_endpoint_mismatch".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_service_account_request(
    store: &InMemoryGatewayStore,
    request: &CreateServiceAccountRequest,
) -> Result<(Option<String>, Option<String>)> {
    if request.display_name.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "service_account_display_name_required".to_owned(),
        });
    }
    if request.organization_id.is_none() && request.project_id.is_none() {
        return Err(GatewayError::BadRequest {
            message: "service_account_scope_required".to_owned(),
        });
    }
    let project = if let Some(project_id) = request.project_id.as_deref() {
        let Some(project) = read_lock(&store.projects).get(project_id).cloned() else {
            return Err(GatewayError::NotFound {
                resource: format!("project {project_id}"),
            });
        };
        if project.tenant_id != request.tenant_id {
            return Err(GatewayError::Authorization {
                reason: "project_tenant_mismatch",
            });
        }
        Some(project)
    } else {
        None
    };
    let organization_id = request
        .organization_id
        .clone()
        .or_else(|| {
            project
                .as_ref()
                .map(|project| project.organization_id.clone())
        })
        .ok_or_else(|| GatewayError::BadRequest {
            message: "service_account_scope_required".to_owned(),
        })?;
    let Some(organization) = read_lock(&store.organizations)
        .get(&organization_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        });
    };
    if organization.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "organization_tenant_mismatch",
        });
    }
    if let Some(project) = project.as_ref() {
        if project.organization_id != organization.organization_id {
            return Err(GatewayError::BadRequest {
                message: "service_account_project_organization_mismatch".to_owned(),
            });
        }
    }
    Ok((
        Some(organization.organization_id),
        project.map(|project| project.project_id),
    ))
}

const fn service_account_status_supported(status: &DirectoryStatus) -> bool {
    matches!(
        status,
        DirectoryStatus::Active | DirectoryStatus::Disabled | DirectoryStatus::Deleted
    )
}

fn validate_routing_group_request(
    store: &InMemoryGatewayStore,
    request: &CreateRoutingGroupRequest,
) -> Result<()> {
    validate_optional_organization_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
    )?;
    if request.name.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "routing_group_name_required".to_owned(),
        });
    }
    let duplicate = read_lock(&store.routing_groups).values().any(|group| {
        group.tenant_id == request.tenant_id
            && group.organization_id == request.organization_id
            && group.name == request.name.trim()
            && group.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "routing_group_name_conflict".to_owned(),
        });
    }
    Ok(())
}

fn validate_routing_group_target_refs(
    store: &InMemoryGatewayStore,
    request: &CreateRoutingGroupTargetRequest,
) -> Result<()> {
    if request.weight == 0 {
        return Err(GatewayError::BadRequest {
            message: "routing_group_target_weight_required".to_owned(),
        });
    }
    let Some(group) = read_lock(&store.routing_groups)
        .get(&request.routing_group_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("routing group {}", request.routing_group_id),
        });
    };
    if group.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "routing_group_tenant_mismatch",
        });
    }
    let Some(model_target) = read_lock(&store.model_targets)
        .get(&request.model_target_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("model target {}", request.model_target_id),
        });
    };
    if model_target.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "model_target_tenant_mismatch",
        });
    }
    if group.protocol_family != model_target.protocol_family {
        return Err(GatewayError::BadRequest {
            message: "routing_group_target_protocol_mismatch".to_owned(),
        });
    }
    if group.organization_id.is_some()
        && model_target.organization_id.is_some()
        && group.organization_id != model_target.organization_id
    {
        return Err(GatewayError::BadRequest {
            message: "routing_group_target_organization_mismatch".to_owned(),
        });
    }
    let duplicate = read_lock(&store.routing_group_targets)
        .values()
        .any(|target| {
            target.tenant_id == request.tenant_id
                && target.routing_group_id == request.routing_group_id
                && target.model_target_id == request.model_target_id
                && target.status != ResourceStatus::Deleted
        });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "routing_group_target_conflict".to_owned(),
        });
    }
    Ok(())
}

fn validate_optional_project_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<()> {
    validate_optional_organization_scope(store, tenant_id, organization_id)?;
    let Some(project_id) = project_id else {
        return Ok(());
    };
    let Some(project) = read_lock(&store.projects).get(project_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("project {project_id}"),
        });
    };
    if project.tenant_id != tenant_id {
        return Err(GatewayError::Authorization {
            reason: "project_tenant_mismatch",
        });
    }
    if let Some(organization_id) = organization_id {
        if project.organization_id != organization_id {
            return Err(GatewayError::BadRequest {
                message: "project_organization_mismatch".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_model_alias_request(
    store: &InMemoryGatewayStore,
    request: &CreateModelAliasRequest,
) -> Result<()> {
    validate_optional_project_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
        request.project_id.as_deref(),
    )?;
    if request.alias_name.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "model_alias_name_required".to_owned(),
        });
    }
    if request.route_policy_id.is_some() {
        return Err(GatewayError::BadRequest {
            message: "model_alias_route_policy_must_bind_after_create".to_owned(),
        });
    }
    let duplicate = read_lock(&store.model_aliases).values().any(|alias| {
        alias.tenant_id == request.tenant_id
            && alias.organization_id == request.organization_id
            && alias.project_id == request.project_id
            && alias.alias_name == request.alias_name.trim()
            && alias.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "model_alias_name_conflict".to_owned(),
        });
    }
    Ok(())
}

fn validate_model_alias_route_policy_binding(
    store: &InMemoryGatewayStore,
    model_alias_id: &str,
    route_policy_id: &str,
) -> Result<()> {
    let Some(alias) = read_lock(&store.model_aliases).get(model_alias_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("model alias {model_alias_id}"),
        });
    };
    let Some(policy) = read_lock(&store.route_policies)
        .get(route_policy_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("route policy {route_policy_id}"),
        });
    };
    if policy.tenant_id != alias.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "route_policy_tenant_mismatch",
        });
    }
    if policy.model_alias_id != alias.model_alias_id {
        return Err(GatewayError::BadRequest {
            message: "route_policy_model_alias_mismatch".to_owned(),
        });
    }
    if policy.protocol_family != alias.protocol_family {
        return Err(GatewayError::BadRequest {
            message: "route_policy_protocol_mismatch".to_owned(),
        });
    }
    Ok(())
}

fn validate_route_policy_request(
    store: &InMemoryGatewayStore,
    request: &CreateRoutePolicyRequest,
) -> Result<(ModelAliasRecord, RoutingGroupRecord, Option<String>)> {
    if request.name.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "route_policy_name_required".to_owned(),
        });
    }
    let Some(alias) = read_lock(&store.model_aliases)
        .get(&request.model_alias_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("model alias {}", request.model_alias_id),
        });
    };
    if alias.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "model_alias_tenant_mismatch",
        });
    }
    let Some(group) = read_lock(&store.routing_groups)
        .get(&request.routing_group_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("routing group {}", request.routing_group_id),
        });
    };
    if group.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "routing_group_tenant_mismatch",
        });
    }
    if alias.protocol_family != group.protocol_family {
        return Err(GatewayError::BadRequest {
            message: "route_policy_protocol_mismatch".to_owned(),
        });
    }
    if alias.organization_id.is_some()
        && group.organization_id.is_some()
        && alias.organization_id != group.organization_id
    {
        return Err(GatewayError::BadRequest {
            message: "route_policy_organization_mismatch".to_owned(),
        });
    }
    let organization_id = alias
        .organization_id
        .clone()
        .or_else(|| group.organization_id.clone());
    let duplicate = read_lock(&store.route_policies).values().any(|policy| {
        policy.tenant_id == request.tenant_id
            && policy.organization_id == organization_id
            && policy.name == request.name.trim()
            && policy.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "route_policy_name_conflict".to_owned(),
        });
    }
    Ok((alias, group, organization_id))
}

fn validate_provider_grant_request(
    store: &InMemoryGatewayStore,
    request: &CreateProviderGrantRequest,
) -> Result<(Option<String>, Option<String>)> {
    let (organization_id, project_id) =
        validate_provider_grant_scope(store, &request.tenant_id, request)?;
    validate_provider_grant_resource(store, &request.tenant_id, request)?;
    validate_provider_grant_effect(&request.effect, &request.closure_mode)?;
    let duplicate = read_lock(&store.provider_grants).values().any(|grant| {
        grant.tenant_id == request.tenant_id
            && grant.scope_kind == request.scope_kind
            && grant.scope_id == request.scope_id
            && grant.resource_kind == request.resource_kind
            && grant.resource_id == request.resource_id
            && grant.effect == request.effect
            && grant.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "provider_grant_conflict".to_owned(),
        });
    }
    Ok((organization_id, project_id))
}

fn validate_provider_grant_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    request: &CreateProviderGrantRequest,
) -> Result<(Option<String>, Option<String>)> {
    match request.scope_kind.as_str() {
        "organization" => {
            let Some(organization) = read_lock(&store.organizations)
                .get(&request.scope_id)
                .cloned()
            else {
                return Err(GatewayError::NotFound {
                    resource: format!("organization {}", request.scope_id),
                });
            };
            if organization.tenant_id != tenant_id {
                return Err(GatewayError::Authorization {
                    reason: "provider_grant_scope_tenant_mismatch",
                });
            }
            Ok((Some(organization.organization_id), None))
        }
        "project" => {
            let Some(project) = read_lock(&store.projects).get(&request.scope_id).cloned() else {
                return Err(GatewayError::NotFound {
                    resource: format!("project {}", request.scope_id),
                });
            };
            if project.tenant_id != tenant_id {
                return Err(GatewayError::Authorization {
                    reason: "provider_grant_scope_tenant_mismatch",
                });
            }
            Ok((Some(project.organization_id), Some(project.project_id)))
        }
        _ => Err(GatewayError::BadRequest {
            message: "provider_grant_scope_kind_invalid".to_owned(),
        }),
    }
}

fn validate_provider_grant_resource(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    request: &CreateProviderGrantRequest,
) -> Result<()> {
    let found = match request.resource_kind.as_str() {
        "model_alias" => read_lock(&store.model_aliases)
            .get(&request.resource_id)
            .is_some_and(|alias| alias.tenant_id == tenant_id),
        "route_policy" => read_lock(&store.route_policies)
            .get(&request.resource_id)
            .is_some_and(|policy| policy.tenant_id == tenant_id),
        "routing_group" => read_lock(&store.routing_groups)
            .get(&request.resource_id)
            .is_some_and(|group| group.tenant_id == tenant_id),
        "model_target" => read_lock(&store.model_targets)
            .get(&request.resource_id)
            .is_some_and(|target| target.tenant_id == tenant_id),
        "provider_endpoint" => read_lock(&store.provider_endpoints)
            .get(&request.resource_id)
            .is_some_and(|endpoint| endpoint.tenant_id == tenant_id),
        "pricing_sku" => read_lock(&store.pricing_skus)
            .get(&request.resource_id)
            .is_some_and(|sku| sku.tenant_id == tenant_id),
        _ => {
            return Err(GatewayError::BadRequest {
                message: "provider_grant_resource_kind_invalid".to_owned(),
            });
        }
    };
    if found {
        Ok(())
    } else {
        Err(GatewayError::NotFound {
            resource: format!(
                "{} {}",
                request.resource_kind.replace('_', " "),
                request.resource_id
            ),
        })
    }
}

fn validate_provider_grant_effect(effect: &str, closure_mode: &str) -> Result<()> {
    match effect {
        "allow" | "deny" => {}
        _ => {
            return Err(GatewayError::BadRequest {
                message: "provider_grant_effect_invalid".to_owned(),
            });
        }
    }
    match closure_mode {
        "self_only" | "include_descendants" | "deny_descendants" => {}
        _ => {
            return Err(GatewayError::BadRequest {
                message: "provider_grant_closure_mode_invalid".to_owned(),
            });
        }
    }
    if effect == "allow" && closure_mode == "deny_descendants" {
        return Err(GatewayError::BadRequest {
            message: "provider_grant_allow_deny_descendants_invalid".to_owned(),
        });
    }
    if effect == "deny" && closure_mode == "include_descendants" {
        return Err(GatewayError::BadRequest {
            message: "provider_grant_deny_include_descendants_invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_pricing_sku_request(
    store: &InMemoryGatewayStore,
    request: &CreatePricingSkuRequest,
) -> Result<()> {
    validate_optional_organization_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
    )?;
    if request.name.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "pricing_sku_name_required".to_owned(),
        });
    }
    if !valid_currency_code(&request.currency) {
        return Err(GatewayError::BadRequest {
            message: "pricing_sku_currency_invalid".to_owned(),
        });
    }
    if request.unit != "micro_usd" {
        return Err(GatewayError::BadRequest {
            message: "pricing_sku_unit_invalid".to_owned(),
        });
    }
    if request.model_id_patterns.is_empty()
        || request
            .model_id_patterns
            .iter()
            .any(|pattern| pattern.trim().is_empty())
    {
        return Err(GatewayError::BadRequest {
            message: "pricing_sku_model_patterns_required".to_owned(),
        });
    }
    if request
        .provider_endpoint_patterns
        .iter()
        .any(|pattern| pattern.trim().is_empty())
    {
        return Err(GatewayError::BadRequest {
            message: "pricing_sku_provider_patterns_invalid".to_owned(),
        });
    }
    if let Some(effective_until) = request.effective_until {
        if effective_until <= request.effective_from {
            return Err(GatewayError::BadRequest {
                message: "pricing_sku_effective_window_invalid".to_owned(),
            });
        }
    }
    validate_pricing_document(&request.pricing_document, &request.currency, &request.unit)?;
    let duplicate = read_lock(&store.pricing_skus).values().any(|sku| {
        sku.tenant_id == request.tenant_id
            && sku.organization_id == request.organization_id
            && sku.name == request.name.trim()
            && sku.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "pricing_sku_name_conflict".to_owned(),
        });
    }
    Ok(())
}

fn valid_currency_code(value: &str) -> bool {
    value.len() == 3 && value.chars().all(|ch| ch.is_ascii_uppercase())
}

fn validate_pricing_document(document: &Value, currency: &str, unit: &str) -> Result<()> {
    let Some(object) = document.as_object() else {
        return Err(GatewayError::BadRequest {
            message: "pricing_document_invalid".to_owned(),
        });
    };
    if object.get("schema").and_then(Value::as_str) != Some("gateway.pricing.v1") {
        return Err(GatewayError::BadRequest {
            message: "pricing_document_schema_invalid".to_owned(),
        });
    }
    if object.get("currency").and_then(Value::as_str) != Some(currency) {
        return Err(GatewayError::BadRequest {
            message: "pricing_document_currency_mismatch".to_owned(),
        });
    }
    if object.get("unit").and_then(Value::as_str) != Some(unit) {
        return Err(GatewayError::BadRequest {
            message: "pricing_document_unit_mismatch".to_owned(),
        });
    }
    if object.get("tokens").is_none() && object.get("flat_request_cost").is_none() {
        return Err(GatewayError::BadRequest {
            message: "pricing_document_missing_price_components".to_owned(),
        });
    }
    Ok(())
}

fn validate_budget_policy_request(
    store: &InMemoryGatewayStore,
    request: &CreateBudgetPolicyRequest,
) -> Result<(Option<String>, Option<String>)> {
    let (organization_id, project_id) =
        validate_budget_policy_scope(store, &request.tenant_id, request)?;
    validate_budget_policy_enums(request)?;
    validate_budget_policy_limits(request)?;
    let duplicate = read_lock(&store.budget_policies).values().any(|policy| {
        policy.tenant_id == request.tenant_id
            && policy.scope_kind == request.scope_kind
            && policy.scope_id == request.scope_id
            && policy.limit_kind == request.limit_kind
            && policy.period == request.period
            && policy.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_conflict".to_owned(),
        });
    }
    Ok((organization_id, project_id))
}

fn validate_budget_policy_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    request: &CreateBudgetPolicyRequest,
) -> Result<(Option<String>, Option<String>)> {
    match request.scope_kind.as_str() {
        "tenant" if request.scope_id == tenant_id => Ok((None, None)),
        "tenant" => Err(GatewayError::Authorization {
            reason: "budget_scope_tenant_mismatch",
        }),
        "organization" => budget_organization_scope(store, tenant_id, &request.scope_id),
        "project" => budget_project_scope(store, tenant_id, &request.scope_id),
        "credential" => budget_credential_scope(store, tenant_id, &request.scope_id),
        "alias" => budget_alias_scope(store, tenant_id, &request.scope_id),
        "group" => budget_group_scope(store, tenant_id, &request.scope_id),
        "endpoint" => budget_endpoint_scope(store, tenant_id, &request.scope_id),
        "target" => budget_target_scope(store, tenant_id, &request.scope_id),
        _ => Err(GatewayError::BadRequest {
            message: "budget_policy_scope_kind_invalid".to_owned(),
        }),
    }
}

fn budget_organization_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(organization) = read_lock(&store.organizations)
        .get(organization_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        });
    };
    ensure_budget_scope_tenant(&organization.tenant_id, tenant_id)?;
    Ok((Some(organization.organization_id), None))
}

fn budget_project_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    project_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(project) = read_lock(&store.projects).get(project_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("project {project_id}"),
        });
    };
    ensure_budget_scope_tenant(&project.tenant_id, tenant_id)?;
    Ok((Some(project.organization_id), Some(project.project_id)))
}

fn budget_credential_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    credential_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(credential) = read_lock(&store.upstream_credentials)
        .get(credential_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("upstream credential {credential_id}"),
        });
    };
    ensure_budget_scope_tenant(&credential.tenant_id, tenant_id)?;
    Ok((credential.organization_id, None))
}

fn budget_alias_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    model_alias_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(alias) = read_lock(&store.model_aliases).get(model_alias_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("model alias {model_alias_id}"),
        });
    };
    ensure_budget_scope_tenant(&alias.tenant_id, tenant_id)?;
    Ok((alias.organization_id, alias.project_id))
}

fn budget_group_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    routing_group_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(group) = read_lock(&store.routing_groups)
        .get(routing_group_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("routing group {routing_group_id}"),
        });
    };
    ensure_budget_scope_tenant(&group.tenant_id, tenant_id)?;
    Ok((group.organization_id, None))
}

fn budget_endpoint_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    provider_endpoint_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(endpoint) = read_lock(&store.provider_endpoints)
        .get(provider_endpoint_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("provider endpoint {provider_endpoint_id}"),
        });
    };
    ensure_budget_scope_tenant(&endpoint.tenant_id, tenant_id)?;
    Ok((endpoint.organization_id, None))
}

fn budget_target_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    model_target_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(target) = read_lock(&store.model_targets)
        .get(model_target_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("model target {model_target_id}"),
        });
    };
    ensure_budget_scope_tenant(&target.tenant_id, tenant_id)?;
    Ok((target.organization_id, None))
}

fn ensure_budget_scope_tenant(resource_tenant_id: &str, tenant_id: &str) -> Result<()> {
    if resource_tenant_id == tenant_id {
        Ok(())
    } else {
        Err(GatewayError::Authorization {
            reason: "budget_scope_tenant_mismatch",
        })
    }
}

fn validate_export_job_request(request: &CreateExportJobRequest) -> Result<()> {
    if !matches!(request.export_kind.as_str(), "usage" | "audit") {
        return Err(GatewayError::BadRequest {
            message: "export_kind_invalid".to_owned(),
        });
    }
    if request.tenant_id.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "export_tenant_required".to_owned(),
        });
    }
    if request.requested_by.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "export_requested_by_required".to_owned(),
        });
    }
    Ok(())
}

fn validate_budget_policy_enums(request: &CreateBudgetPolicyRequest) -> Result<()> {
    if !matches!(
        request.period.as_str(),
        "rolling" | "calendar_day" | "calendar_month" | "lifetime" | "custom_window"
    ) {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_period_invalid".to_owned(),
        });
    }
    if !matches!(
        request.limit_kind.as_str(),
        "cost" | "tokens" | "requests" | "concurrency" | "stream_seconds"
    ) {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_limit_kind_invalid".to_owned(),
        });
    }
    if !matches!(
        request.overage_mode.as_str(),
        "notify_only"
            | "block_new_requests"
            | "prefer_low_cost_route"
            | "fallback_low_cost_route"
            | "require_exact_usage"
    ) {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_overage_mode_invalid".to_owned(),
        });
    }
    if !matches!(
        request.consistency_mode.as_str(),
        "eventual" | "strong_terminal" | "manual_review"
    ) {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_consistency_mode_invalid".to_owned(),
        });
    }
    if request.reset_policy.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_reset_policy_required".to_owned(),
        });
    }
    Ok(())
}

fn validate_budget_policy_limits(request: &CreateBudgetPolicyRequest) -> Result<()> {
    if request.limit_kind == "cost" {
        let Some(currency) = request.currency.as_deref() else {
            return Err(GatewayError::BadRequest {
                message: "budget_policy_currency_required".to_owned(),
            });
        };
        if !valid_currency_code(currency) {
            return Err(GatewayError::BadRequest {
                message: "budget_policy_currency_invalid".to_owned(),
            });
        }
    } else if request.currency.is_some() {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_currency_for_non_cost".to_owned(),
        });
    }
    if request.hard_limit.is_none() && request.soft_limit.is_none() && request.thresholds.is_empty()
    {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_limit_required".to_owned(),
        });
    }
    if request.hard_limit.is_some_and(|limit| limit <= 0)
        || request.soft_limit.is_some_and(|limit| limit <= 0)
        || request.thresholds.iter().any(|threshold| *threshold <= 0)
    {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_limit_positive_required".to_owned(),
        });
    }
    if let (Some(soft_limit), Some(hard_limit)) = (request.soft_limit, request.hard_limit) {
        if soft_limit > hard_limit {
            return Err(GatewayError::BadRequest {
                message: "budget_policy_soft_limit_exceeds_hard_limit".to_owned(),
            });
        }
    }
    if request.hard_limit.is_some()
        && request.overage_mode == "notify_only"
        && request.consistency_mode != "manual_review"
    {
        return Err(GatewayError::BadRequest {
            message: "budget_policy_hard_limit_notify_only_invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_quota_policy_request(
    store: &InMemoryGatewayStore,
    request: &CreateQuotaPolicyRequest,
) -> Result<(Option<String>, Option<String>)> {
    let (organization_id, project_id) =
        validate_quota_policy_scope(store, &request.tenant_id, request)?;
    validate_quota_policy_shape(request)?;
    let duplicate = read_lock(&store.quota_policies).values().any(|policy| {
        policy.tenant_id == request.tenant_id
            && policy.scope_kind == request.scope_kind
            && policy.scope_id == request.scope_id
            && policy.counter_kind == request.counter_kind
            && policy.window == request.window
            && policy.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_conflict".to_owned(),
        });
    }
    Ok((organization_id, project_id))
}

fn validate_quota_policy_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    request: &CreateQuotaPolicyRequest,
) -> Result<(Option<String>, Option<String>)> {
    match request.scope_kind.as_str() {
        "tenant" if request.scope_id == tenant_id => Ok((None, None)),
        "tenant" => Err(GatewayError::Authorization {
            reason: "quota_scope_tenant_mismatch",
        }),
        "organization" => quota_organization_scope(store, tenant_id, &request.scope_id),
        "project" => quota_project_scope(store, tenant_id, &request.scope_id),
        "credential" => quota_credential_scope(store, tenant_id, &request.scope_id),
        "alias" => quota_alias_scope(store, tenant_id, &request.scope_id),
        "endpoint" => quota_endpoint_scope(store, tenant_id, &request.scope_id),
        "protocol_family" => quota_protocol_family_scope(&request.scope_id),
        _ => Err(GatewayError::BadRequest {
            message: "quota_policy_scope_kind_invalid".to_owned(),
        }),
    }
}

fn quota_organization_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(organization) = read_lock(&store.organizations)
        .get(organization_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        });
    };
    ensure_quota_scope_tenant(&organization.tenant_id, tenant_id)?;
    Ok((Some(organization.organization_id), None))
}

fn quota_project_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    project_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(project) = read_lock(&store.projects).get(project_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("project {project_id}"),
        });
    };
    ensure_quota_scope_tenant(&project.tenant_id, tenant_id)?;
    Ok((Some(project.organization_id), Some(project.project_id)))
}

fn quota_credential_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    credential_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(credential) = read_lock(&store.upstream_credentials)
        .get(credential_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("upstream credential {credential_id}"),
        });
    };
    ensure_quota_scope_tenant(&credential.tenant_id, tenant_id)?;
    Ok((credential.organization_id, None))
}

fn quota_alias_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    model_alias_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(alias) = read_lock(&store.model_aliases).get(model_alias_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("model alias {model_alias_id}"),
        });
    };
    ensure_quota_scope_tenant(&alias.tenant_id, tenant_id)?;
    Ok((alias.organization_id, alias.project_id))
}

fn quota_endpoint_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    provider_endpoint_id: &str,
) -> Result<(Option<String>, Option<String>)> {
    let Some(endpoint) = read_lock(&store.provider_endpoints)
        .get(provider_endpoint_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("provider endpoint {provider_endpoint_id}"),
        });
    };
    ensure_quota_scope_tenant(&endpoint.tenant_id, tenant_id)?;
    Ok((endpoint.organization_id, None))
}

fn quota_protocol_family_scope(scope_id: &str) -> Result<(Option<String>, Option<String>)> {
    if ProtocolFamily::all()
        .iter()
        .any(|family| family.as_str() == scope_id)
    {
        Ok((None, None))
    } else {
        Err(GatewayError::BadRequest {
            message: "quota_policy_protocol_family_invalid".to_owned(),
        })
    }
}

fn ensure_quota_scope_tenant(resource_tenant_id: &str, tenant_id: &str) -> Result<()> {
    if resource_tenant_id == tenant_id {
        Ok(())
    } else {
        Err(GatewayError::Authorization {
            reason: "quota_scope_tenant_mismatch",
        })
    }
}

fn validate_quota_policy_shape(request: &CreateQuotaPolicyRequest) -> Result<()> {
    if !matches!(
        request.counter_kind.as_str(),
        "request_rate"
            | "token_estimate_rate"
            | "token_actual_rate"
            | "concurrent_request"
            | "concurrent_stream"
            | "stream_duration"
            | "request_body_bytes"
    ) {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_counter_kind_invalid".to_owned(),
        });
    }
    if request.limit <= 0 {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_limit_positive_required".to_owned(),
        });
    }
    if request.burst_limit.is_some_and(|limit| limit <= 0) {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_burst_limit_positive_required".to_owned(),
        });
    }
    if !matches!(
        request.loss_behavior.as_str(),
        "fail_open" | "fail_limited" | "fail_closed"
    ) {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_loss_behavior_invalid".to_owned(),
        });
    }
    if request.loss_behavior == "fail_limited" && request.burst_limit.is_none() {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_fail_limited_burst_required".to_owned(),
        });
    }
    if !quota_counter_scope_supported(&request.counter_kind, &request.scope_kind) {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_counter_scope_invalid".to_owned(),
        });
    }
    if !quota_counter_window_supported(&request.counter_kind, &request.window) {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_window_invalid".to_owned(),
        });
    }
    if !quota_counter_increment_source_supported(&request.counter_kind, &request.increment_source) {
        return Err(GatewayError::BadRequest {
            message: "quota_policy_increment_source_invalid".to_owned(),
        });
    }
    Ok(())
}

fn quota_counter_scope_supported(counter_kind: &str, scope_kind: &str) -> bool {
    match counter_kind {
        "request_rate" | "token_estimate_rate" | "token_actual_rate" => matches!(
            scope_kind,
            "tenant" | "organization" | "project" | "credential" | "alias"
        ),
        "concurrent_request" | "concurrent_stream" => matches!(
            scope_kind,
            "tenant" | "organization" | "project" | "credential"
        ),
        "stream_duration" => matches!(scope_kind, "credential" | "alias" | "endpoint"),
        "request_body_bytes" => {
            matches!(scope_kind, "credential" | "alias" | "protocol_family")
        }
        _ => false,
    }
}

fn quota_counter_window_supported(counter_kind: &str, window: &str) -> bool {
    match counter_kind {
        "request_rate" | "token_estimate_rate" | "request_body_bytes" => {
            matches!(window, "fixed" | "sliding")
        }
        "token_actual_rate" => matches!(window, "fixed" | "ledger_bucket"),
        "concurrent_request" => window == "request_lifetime",
        "concurrent_stream" => window == "stream_lifetime",
        "stream_duration" => matches!(window, "fixed" | "sliding" | "stream_lifetime"),
        _ => false,
    }
}

fn quota_counter_increment_source_supported(counter_kind: &str, increment_source: &str) -> bool {
    match counter_kind {
        "request_rate" => increment_source == "accepted_preflight_request",
        "token_estimate_rate" => increment_source == "request_estimate",
        "token_actual_rate" => increment_source == "terminal_usage_event",
        "concurrent_request" => increment_source == "preflight_acquire",
        "concurrent_stream" | "stream_duration" => increment_source == "stream_start",
        "request_body_bytes" => increment_source == "request_body_bytes",
        _ => false,
    }
}

fn validate_otel_export_config_request(
    store: &InMemoryGatewayStore,
    request: &CreateOtelExportConfigRequest,
) -> Result<(Option<String>, Option<String>)> {
    validate_otel_export_config_request_with_excluded_id(store, request, None)
}

fn validate_otel_export_config_request_with_excluded_id(
    store: &InMemoryGatewayStore,
    request: &CreateOtelExportConfigRequest,
    excluded_config_id: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let (organization_id, project_id) = validate_otel_export_scope(store, request)?;
    validate_otel_export_shape(
        store,
        request,
        organization_id.as_deref(),
        project_id.as_deref(),
    )?;
    let duplicate = read_lock(&store.otel_export_configs)
        .values()
        .any(|config| {
            excluded_config_id.is_none_or(|excluded_id| config.otel_export_config_id != excluded_id)
                && config.tenant_id == request.tenant_id
                && config.organization_id == organization_id
                && config.project_id == project_id
                && config.endpoint_url == request.endpoint_url
                && config.protocol == request.protocol
                && config.status != ResourceStatus::Deleted
        });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "otel_export_config_conflict".to_owned(),
        });
    }
    Ok((organization_id, project_id))
}

fn validate_otel_export_scope(
    store: &InMemoryGatewayStore,
    request: &CreateOtelExportConfigRequest,
) -> Result<(Option<String>, Option<String>)> {
    let organization_id = match request.organization_id.as_deref() {
        Some(organization_id) => Some(otel_organization_scope(
            store,
            &request.tenant_id,
            organization_id,
        )?),
        None => None,
    };
    let Some(project_id) = request.project_id.as_deref() else {
        return Ok((organization_id, None));
    };
    let project = otel_project_scope(store, &request.tenant_id, project_id)?;
    if organization_id
        .as_deref()
        .is_some_and(|organization_id| organization_id != project.organization_id)
    {
        return Err(GatewayError::BadRequest {
            message: "otel_export_scope_project_organization_mismatch".to_owned(),
        });
    }
    Ok((Some(project.organization_id), Some(project.project_id)))
}

fn otel_organization_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: &str,
) -> Result<String> {
    let Some(organization) = read_lock(&store.organizations)
        .get(organization_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        });
    };
    ensure_otel_scope_tenant(&organization.tenant_id, tenant_id)?;
    Ok(organization.organization_id)
}

fn otel_project_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    project_id: &str,
) -> Result<ProjectRecord> {
    let Some(project) = read_lock(&store.projects).get(project_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("project {project_id}"),
        });
    };
    ensure_otel_scope_tenant(&project.tenant_id, tenant_id)?;
    Ok(project)
}

fn ensure_otel_scope_tenant(resource_tenant_id: &str, tenant_id: &str) -> Result<()> {
    if resource_tenant_id == tenant_id {
        Ok(())
    } else {
        Err(GatewayError::Authorization {
            reason: "otel_export_scope_tenant_mismatch",
        })
    }
}

fn validate_otel_export_shape(
    store: &InMemoryGatewayStore,
    request: &CreateOtelExportConfigRequest,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<()> {
    if otel_endpoint_host(&request.endpoint_url).is_none() {
        return Err(GatewayError::BadRequest {
            message: "otel_export_endpoint_url_invalid".to_owned(),
        });
    }
    if !matches!(request.protocol.as_str(), "otlp_http" | "otlp_grpc") {
        return Err(GatewayError::BadRequest {
            message: "otel_export_protocol_invalid".to_owned(),
        });
    }
    validate_otel_header_refs(store, request, organization_id, project_id)?;
    validate_otel_signals(&request.enabled_signals)?;
    validate_otel_resource_attributes(&request.resource_attributes)?;
    if !(5..=3600).contains(&request.export_interval_seconds) {
        return Err(GatewayError::BadRequest {
            message: "otel_export_interval_invalid".to_owned(),
        });
    }
    if !(1..=60).contains(&request.timeout_seconds)
        || request.timeout_seconds >= request.export_interval_seconds
    {
        return Err(GatewayError::BadRequest {
            message: "otel_export_timeout_invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_secret_ref_request(
    store: &InMemoryGatewayStore,
    request: &CreateSecretRefRequest,
) -> Result<(Option<String>, Option<String>)> {
    if request.purpose.trim().is_empty() || request.purpose.len() > 120 {
        return Err(GatewayError::BadRequest {
            message: "secret_ref_purpose_invalid".to_owned(),
        });
    }
    if request.backend_kind != "memory" {
        return Err(GatewayError::BadRequest {
            message: "secret_ref_backend_kind_unsupported".to_owned(),
        });
    }
    if request.secret_value.expose_secret().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "secret_ref_value_required".to_owned(),
        });
    }
    validate_notification_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
        request.project_id.as_deref(),
    )
}

fn ensure_secret_ref_usable(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: Option<&str>,
    project_id: Option<&str>,
    secret_ref_id: &str,
    error_prefix: &str,
) -> Result<()> {
    if !valid_secret_ref_id(secret_ref_id) {
        return Err(GatewayError::BadRequest {
            message: format!("{error_prefix}_invalid"),
        });
    }
    let Some(secret_ref) = read_lock(&store.secret_refs).get(secret_ref_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("secret ref {secret_ref_id}"),
        });
    };
    if secret_ref.tenant_id != tenant_id {
        return Err(GatewayError::Authorization {
            reason: "secret_ref_tenant_mismatch",
        });
    }
    if !matches!(
        secret_ref.status,
        SecretRefStatus::Active | SecretRefStatus::Rotating
    ) {
        return Err(GatewayError::BadRequest {
            message: format!("{error_prefix}_not_active"),
        });
    }
    if secret_ref
        .organization_id
        .as_deref()
        .is_some_and(|secret_org| organization_id != Some(secret_org))
    {
        return Err(GatewayError::BadRequest {
            message: format!("{error_prefix}_scope_mismatch"),
        });
    }
    if secret_ref
        .project_id
        .as_deref()
        .is_some_and(|secret_project| project_id != Some(secret_project))
    {
        return Err(GatewayError::BadRequest {
            message: format!("{error_prefix}_scope_mismatch"),
        });
    }
    Ok(())
}

fn secret_display_mask(secret_value: &str) -> String {
    let suffix = secret_value
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<String>();
    if suffix.is_empty() {
        "****".to_owned()
    } else {
        format!("****{suffix}")
    }
}

fn secret_fingerprint(secret_value: &str) -> String {
    let digest = Sha256::digest(secret_value.as_bytes());
    format!("sha256:{digest:x}")
}

fn validate_otel_header_refs(
    store: &InMemoryGatewayStore,
    request: &CreateOtelExportConfigRequest,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<()> {
    if request.header_refs.len() > 8 {
        return Err(GatewayError::BadRequest {
            message: "otel_export_header_ref_limit_exceeded".to_owned(),
        });
    }
    let mut names = HashSet::new();
    for header in &request.header_refs {
        let normalized_name = header.name.to_ascii_lowercase();
        if !valid_otel_header_name(&normalized_name) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_header_name_invalid".to_owned(),
            });
        }
        if !names.insert(normalized_name) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_header_name_duplicate".to_owned(),
            });
        }
        if !valid_secret_ref_id(&header.secret_ref_id) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_header_secret_ref_invalid".to_owned(),
            });
        }
        ensure_secret_ref_usable(
            store,
            &request.tenant_id,
            organization_id,
            project_id,
            &header.secret_ref_id,
            "otel_export_header_secret_ref",
        )?;
    }
    Ok(())
}

fn validate_otel_signals(enabled_signals: &[String]) -> Result<()> {
    if enabled_signals.is_empty() || !enabled_signals.iter().any(|signal| signal == "metrics") {
        return Err(GatewayError::BadRequest {
            message: "otel_export_metrics_signal_required".to_owned(),
        });
    }
    let mut signals = HashSet::new();
    for signal in enabled_signals {
        if signal != "metrics" {
            return Err(GatewayError::BadRequest {
                message: "otel_export_signal_invalid".to_owned(),
            });
        }
        if !signals.insert(signal) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_signal_duplicate".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_otel_resource_attributes(attributes: &[OtelResourceAttribute]) -> Result<()> {
    if attributes.len() > 16 {
        return Err(GatewayError::BadRequest {
            message: "otel_export_attribute_limit_exceeded".to_owned(),
        });
    }
    let mut keys = HashSet::new();
    for attribute in attributes {
        if !valid_otel_attribute_key(&attribute.key) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_attribute_key_invalid".to_owned(),
            });
        }
        if !keys.insert(attribute.key.to_ascii_lowercase()) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_attribute_key_duplicate".to_owned(),
            });
        }
        if attribute.value.is_empty() || attribute.value.len() > 128 {
            return Err(GatewayError::BadRequest {
                message: "otel_export_attribute_value_invalid".to_owned(),
            });
        }
        if otel_attribute_key_is_dynamic_or_secret(&attribute.key) {
            return Err(GatewayError::BadRequest {
                message: "otel_export_attribute_key_forbidden".to_owned(),
            });
        }
    }
    Ok(())
}

fn otel_endpoint_host(value: &str) -> Option<String> {
    let uri = value.parse::<http::Uri>().ok()?;
    if uri.query().is_some() {
        return None;
    }
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    match scheme {
        "https" => Some(host.to_owned()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") => {
            Some(host.to_owned())
        }
        _ => None,
    }
}

fn webhook_endpoint_host(value: &str) -> Option<String> {
    let uri = value.parse::<http::Uri>().ok()?;
    if uri.query().is_some() {
        return None;
    }
    let scheme = uri.scheme_str()?;
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    match scheme {
        "https" => Some(host.to_owned()),
        "http" if matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1") => {
            Some(host.to_owned())
        }
        _ => None,
    }
}

fn valid_otel_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn valid_secret_ref_id(value: &str) -> bool {
    value.starts_with("sec_")
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn valid_otel_attribute_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic())
}

fn otel_attribute_key_is_dynamic_or_secret(value: &str) -> bool {
    let normalized = value.to_ascii_lowercase();
    [
        "api_key",
        "authorization",
        "completion",
        "prompt",
        "request",
        "secret",
        "session",
        "token",
        "user_id",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn validate_notification_sink_request(
    store: &InMemoryGatewayStore,
    request: &CreateNotificationSinkRequest,
) -> Result<(Option<String>, Option<String>)> {
    validate_notification_sink_request_with_excluded_id(store, request, None)
}

fn validate_notification_sink_request_with_excluded_id(
    store: &InMemoryGatewayStore,
    request: &CreateNotificationSinkRequest,
    excluded_notification_sink_id: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let (organization_id, project_id) = validate_notification_scope(
        store,
        &request.tenant_id,
        request.organization_id.as_deref(),
        request.project_id.as_deref(),
    )?;
    validate_notification_sink_shape(request)?;
    if let Some(signing_secret_ref_id) = request.signing_secret_ref_id.as_deref() {
        ensure_secret_ref_usable(
            store,
            &request.tenant_id,
            organization_id.as_deref(),
            project_id.as_deref(),
            signing_secret_ref_id,
            "notification_sink_signing_secret_ref",
        )?;
    }
    let duplicate = read_lock(&store.notification_sinks).values().any(|sink| {
        sink.tenant_id == request.tenant_id
            && sink.organization_id == organization_id
            && sink.project_id == project_id
            && sink.name == request.name.trim()
            && sink.sink_kind == request.sink_kind
            && sink.status != ResourceStatus::Deleted
            && Some(sink.notification_sink_id.as_str()) != excluded_notification_sink_id
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_conflict".to_owned(),
        });
    }
    Ok((organization_id, project_id))
}

fn validate_notification_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<(Option<String>, Option<String>)> {
    let organization_id = match organization_id {
        Some(organization_id) => Some(notification_organization_scope(
            store,
            tenant_id,
            organization_id,
        )?),
        None => None,
    };
    let Some(project_id) = project_id else {
        return Ok((organization_id, None));
    };
    let project = notification_project_scope(store, tenant_id, project_id)?;
    if organization_id
        .as_deref()
        .is_some_and(|organization_id| organization_id != project.organization_id)
    {
        return Err(GatewayError::BadRequest {
            message: "notification_scope_project_organization_mismatch".to_owned(),
        });
    }
    Ok((Some(project.organization_id), Some(project.project_id)))
}

fn notification_organization_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    organization_id: &str,
) -> Result<String> {
    let Some(organization) = read_lock(&store.organizations)
        .get(organization_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        });
    };
    ensure_notification_scope_tenant(&organization.tenant_id, tenant_id)?;
    Ok(organization.organization_id)
}

fn notification_project_scope(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    project_id: &str,
) -> Result<ProjectRecord> {
    let Some(project) = read_lock(&store.projects).get(project_id).cloned() else {
        return Err(GatewayError::NotFound {
            resource: format!("project {project_id}"),
        });
    };
    ensure_notification_scope_tenant(&project.tenant_id, tenant_id)?;
    Ok(project)
}

fn ensure_notification_scope_tenant(resource_tenant_id: &str, tenant_id: &str) -> Result<()> {
    if resource_tenant_id == tenant_id {
        Ok(())
    } else {
        Err(GatewayError::Authorization {
            reason: "notification_scope_tenant_mismatch",
        })
    }
}

fn validate_notification_sink_shape(request: &CreateNotificationSinkRequest) -> Result<()> {
    if request.name.trim().is_empty() || request.name.len() > 80 {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_name_invalid".to_owned(),
        });
    }
    if notification_document_contains_sensitive_keys(&request.endpoint_config) {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_endpoint_config_sensitive".to_owned(),
        });
    }
    match request.sink_kind.as_str() {
        "webhook" => validate_webhook_notification_sink(request),
        "stdout" | "disabled" => validate_local_notification_sink(request),
        "object_export" | "pubsub" => Err(GatewayError::BadRequest {
            message: "notification_sink_kind_not_supported".to_owned(),
        }),
        _ => Err(GatewayError::BadRequest {
            message: "notification_sink_kind_invalid".to_owned(),
        }),
    }
}

fn validate_webhook_notification_sink(request: &CreateNotificationSinkRequest) -> Result<()> {
    let Some(object) = request.endpoint_config.as_object() else {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_endpoint_config_invalid".to_owned(),
        });
    };
    let Some(url) = object.get("url").and_then(Value::as_str) else {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_webhook_url_required".to_owned(),
        });
    };
    if webhook_endpoint_host(url).is_none() {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_webhook_url_invalid".to_owned(),
        });
    }
    if !request
        .signing_secret_ref_id
        .as_deref()
        .is_some_and(valid_secret_ref_id)
    {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_signing_secret_ref_required".to_owned(),
        });
    }
    Ok(())
}

fn validate_local_notification_sink(request: &CreateNotificationSinkRequest) -> Result<()> {
    if request.signing_secret_ref_id.is_some() {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_signing_secret_ref_forbidden".to_owned(),
        });
    }
    if !request.endpoint_config.is_object() {
        return Err(GatewayError::BadRequest {
            message: "notification_sink_endpoint_config_invalid".to_owned(),
        });
    }
    Ok(())
}

fn validate_notification_subscription_request(
    store: &InMemoryGatewayStore,
    request: &CreateNotificationSubscriptionRequest,
) -> Result<NotificationSinkRecord> {
    let Some(sink) = read_lock(&store.notification_sinks)
        .get(&request.notification_sink_id)
        .cloned()
    else {
        return Err(GatewayError::NotFound {
            resource: format!("notification sink {}", request.notification_sink_id),
        });
    };
    if sink.tenant_id != request.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "notification_subscription_tenant_mismatch",
        });
    }
    if sink.status == ResourceStatus::Deleted {
        return Err(GatewayError::BadRequest {
            message: "notification_subscription_deleted_sink".to_owned(),
        });
    }
    if !valid_notification_event_family(&request.event_family) {
        return Err(GatewayError::BadRequest {
            message: "notification_subscription_event_family_invalid".to_owned(),
        });
    }
    if !request.filter_document.is_object()
        || notification_document_contains_sensitive_keys(&request.filter_document)
    {
        return Err(GatewayError::BadRequest {
            message: "notification_subscription_filter_invalid".to_owned(),
        });
    }
    let duplicate = read_lock(&store.notification_subscriptions)
        .values()
        .any(|subscription| {
            subscription.notification_sink_id == request.notification_sink_id
                && subscription.event_family == request.event_family
                && subscription.filter_document == request.filter_document
                && subscription.status != ResourceStatus::Deleted
        });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "notification_subscription_conflict".to_owned(),
        });
    }
    Ok(sink)
}

fn validate_login_provider_request(
    store: &InMemoryGatewayStore,
    request: &CreateLoginProviderRequest,
) -> Result<()> {
    validate_login_provider_shape(request)?;
    let duplicate = read_lock(&store.login_providers).values().any(|provider| {
        provider.tenant_id == request.tenant_id
            && provider.provider_kind == request.provider_kind
            && provider.display_name == request.display_name.trim()
            && provider.status != ResourceStatus::Deleted
    });
    if duplicate {
        return Err(GatewayError::BadRequest {
            message: "login_provider_conflict".to_owned(),
        });
    }
    Ok(())
}

fn validate_login_provider_shape(request: &CreateLoginProviderRequest) -> Result<()> {
    if request.provider_kind != "oidc" {
        return Err(GatewayError::BadRequest {
            message: "login_provider_kind_invalid".to_owned(),
        });
    }
    if request.display_name.trim().is_empty() || request.display_name.len() > 120 {
        return Err(GatewayError::BadRequest {
            message: "login_provider_display_name_invalid".to_owned(),
        });
    }
    if !request.config_document.is_object()
        || login_provider_config_contains_sensitive_material(&request.config_document)
    {
        return Err(GatewayError::BadRequest {
            message: "login_provider_config_invalid".to_owned(),
        });
    }
    let client_id = request
        .config_document
        .get("client_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if client_id.trim().is_empty() || client_id.len() > 256 {
        return Err(GatewayError::BadRequest {
            message: "login_provider_client_id_invalid".to_owned(),
        });
    }
    let client_secret_ref = request
        .config_document
        .get("client_secret_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !valid_secret_ref_id(client_secret_ref) {
        return Err(GatewayError::BadRequest {
            message: "login_provider_client_secret_ref_invalid".to_owned(),
        });
    }
    for field in [
        "redirect_uri",
        "authorization_url",
        "token_url",
        "jwks_url",
        "discovery_url",
        "user_api_url",
        "emails_api_url",
    ] {
        if let Some(url) = request.config_document.get(field).and_then(Value::as_str) {
            validate_https_url_field(url, field)?;
        }
    }
    if request
        .config_document
        .get("redirect_uri")
        .and_then(Value::as_str)
        .is_none()
    {
        return Err(GatewayError::BadRequest {
            message: "login_provider_redirect_uri_required".to_owned(),
        });
    }
    if request.provider_kind == "oidc" {
        let issuer = request
            .config_document
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap_or_default();
        validate_https_url_field(issuer, "issuer")?;
    }
    if let Some(scopes) = request.config_document.get("scopes") {
        let Some(scopes) = scopes.as_array() else {
            return Err(GatewayError::BadRequest {
                message: "login_provider_scopes_invalid".to_owned(),
            });
        };
        if scopes
            .iter()
            .any(|scope| scope.as_str().is_none_or(|value| value.trim().is_empty()))
        {
            return Err(GatewayError::BadRequest {
                message: "login_provider_scopes_invalid".to_owned(),
            });
        }
    }
    Ok(())
}

fn login_provider_config_contains_sensitive_material(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "access_token"
                    | "client_secret"
                    | "client_secret_value"
                    | "id_token"
                    | "password"
                    | "raw_secret"
                    | "refresh_token"
            ) || login_provider_config_contains_sensitive_material(value)
        }),
        Value::Array(values) => values
            .iter()
            .any(login_provider_config_contains_sensitive_material),
        _ => false,
    }
}

fn validate_https_url_field(url: &str, field: &str) -> Result<()> {
    if login_provider_url_is_safe(url) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: format!("login_provider_{field}_invalid"),
        })
    }
}

fn login_provider_url_is_safe(url: &str) -> bool {
    let Ok(parsed) = url.parse::<http::Uri>() else {
        return false;
    };
    if parsed.query().is_some() || url.contains(char::is_whitespace) {
        return false;
    }
    let Some(authority) = parsed.authority() else {
        return false;
    };
    if authority.as_str().contains('@') {
        return false;
    }
    let host = authority.host();
    match parsed.scheme_str() {
        Some("https") => true,
        Some("http") => matches!(host, "localhost" | "127.0.0.1" | "[::1]" | "::1"),
        _ => false,
    }
}

fn valid_notification_event_family(value: &str) -> bool {
    matches!(
        value,
        "usage"
            | "budget"
            | "quota"
            | "routing"
            | "provider_health"
            | "credential"
            | "admin"
            | "delivery"
    )
}

fn notification_document_contains_sensitive_keys(value: &Value) -> bool {
    let Ok(encoded) = serde_json::to_string(value) else {
        return true;
    };
    let normalized = encoded.to_ascii_lowercase();
    [
        "authorization",
        "completion",
        "oauth",
        "prompt",
        "raw_response",
        "secret",
        "token",
        "upstream_api_key",
    ]
    .iter()
    .any(|needle| normalized.contains(needle))
}

fn validate_tenancy_seed(store: &InMemoryGatewayStore, seed: &TenancySeed) -> Result<()> {
    validate_entry(
        &read_lock(&store.tenants),
        &seed.tenant.tenant_id,
        &seed.tenant,
        tenant_seed_matches,
        "tenant_seed_conflict",
    )?;
    validate_entry(
        &read_lock(&store.organizations),
        &seed.organization.organization_id,
        &seed.organization,
        organization_seed_matches,
        "organization_seed_conflict",
    )?;
    validate_entry(
        &read_lock(&store.projects),
        &seed.project.project_id,
        &seed.project,
        project_seed_matches,
        "project_seed_conflict",
    )?;
    validate_entry(
        &read_lock(&store.users),
        &seed.user.user_id,
        &seed.user,
        user_seed_matches,
        "user_seed_conflict",
    )?;
    validate_seed_memberships(store, seed)
}

fn validate_seed_memberships(store: &InMemoryGatewayStore, seed: &TenancySeed) -> Result<()> {
    validate_entry(
        &read_lock(&store.organization_memberships),
        &organization_membership_key(seed),
        &seed.organization_membership,
        organization_membership_seed_matches,
        "organization_membership_seed_conflict",
    )?;
    validate_entry(
        &read_lock(&store.project_memberships),
        &project_membership_key(seed),
        &seed.project_membership,
        project_membership_seed_matches,
        "project_membership_seed_conflict",
    )
}

fn insert_tenancy_seed(store: &InMemoryGatewayStore, seed: &TenancySeed) {
    write_lock(&store.tenants)
        .entry(seed.tenant.tenant_id.clone())
        .or_insert_with(|| seed.tenant.clone());
    write_lock(&store.organizations)
        .entry(seed.organization.organization_id.clone())
        .or_insert_with(|| seed.organization.clone());
    write_lock(&store.projects)
        .entry(seed.project.project_id.clone())
        .or_insert_with(|| seed.project.clone());
    write_lock(&store.users)
        .entry(seed.user.user_id.clone())
        .or_insert_with(|| seed.user.clone());
    write_lock(&store.organization_memberships)
        .entry(organization_membership_key(seed))
        .or_insert_with(|| seed.organization_membership.clone());
    write_lock(&store.project_memberships)
        .entry(project_membership_key(seed))
        .or_insert_with(|| seed.project_membership.clone());
}

fn load_tenancy_seed(
    store: &InMemoryGatewayStore,
    request: &BootstrapDefaultProjectRequest,
) -> Result<TenancySeed> {
    Ok(TenancySeed {
        tenant: store
            .tenant(&request.tenant_id)
            .ok_or_else(|| GatewayError::Internal {
                message: "bootstrapped tenant is missing".to_owned(),
            })?,
        organization: store
            .organization(&request.organization_id)
            .ok_or_else(|| GatewayError::Internal {
                message: "bootstrapped organization is missing".to_owned(),
            })?,
        project: store
            .project(&request.project_id)
            .ok_or_else(|| GatewayError::Internal {
                message: "bootstrapped project is missing".to_owned(),
            })?,
        user: store
            .user(&request.user_id)
            .ok_or_else(|| GatewayError::Internal {
                message: "bootstrapped user is missing".to_owned(),
            })?,
        organization_membership: read_lock(&store.organization_memberships)
            .get(&(request.user_id.clone(), request.organization_id.clone()))
            .cloned()
            .ok_or_else(|| GatewayError::Internal {
                message: "bootstrapped organization membership is missing".to_owned(),
            })?,
        project_membership: store
            .project_membership(&request.user_id, &request.project_id)
            .ok_or_else(|| GatewayError::Internal {
                message: "bootstrapped project membership is missing".to_owned(),
            })?,
    })
}

fn organization_membership_key(seed: &TenancySeed) -> (String, String) {
    (
        seed.organization_membership.principal_id.clone(),
        seed.organization_membership.organization_id.clone(),
    )
}

fn project_membership_key(seed: &TenancySeed) -> (String, String) {
    (
        seed.project_membership.principal_id.clone(),
        seed.project_membership.project_id.clone(),
    )
}

fn upsert_external_login_identity(
    store: &InMemoryGatewayStore,
    request: UpsertExternalLoginIdentityRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(UserRecord, ExternalIdentityRecord, bool)> {
    if request.provider_subject.trim().is_empty() || request.display_name.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "external_login_claims_invalid".to_owned(),
        });
    }
    if let Some((user, identity)) = update_existing_external_identity(store, &request, now)? {
        return Ok((user, identity, false));
    }

    let user_id = new_prefixed_id("usr");
    let user = UserRecord {
        user_id: user_id.clone(),
        tenant_id: request.tenant_id.clone(),
        default_organization_id: None,
        default_project_id: None,
        primary_email: request.email.clone(),
        display_name: request.display_name.trim().to_owned(),
        status: DirectoryStatus::Active,
        resource_version: 1,
        schema_version: 1,
        created_at: now,
        updated_at: now,
    };
    let identity = ExternalIdentityRecord {
        external_identity_id: new_prefixed_id("xid"),
        tenant_id: request.tenant_id,
        principal_id: user_id,
        login_provider_id: Some(request.login_provider_id),
        provider_kind: request.provider_kind,
        provider_subject: request.provider_subject,
        email: request.email,
        email_verified: request.email_verified,
        status: ResourceStatus::Active,
        created_at: now,
        updated_at: now,
    };
    write_lock(&store.users).insert(user.user_id.clone(), user.clone());
    write_lock(&store.external_identities)
        .insert(identity.external_identity_id.clone(), identity.clone());
    Ok((user, identity, true))
}

fn update_existing_external_identity(
    store: &InMemoryGatewayStore,
    request: &UpsertExternalLoginIdentityRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<(UserRecord, ExternalIdentityRecord)>> {
    let mut identities = write_lock(&store.external_identities);
    let identity = identities.values_mut().find(|identity| {
        identity.tenant_id == request.tenant_id
            && identity.login_provider_id.as_deref() == Some(request.login_provider_id.as_str())
            && identity.provider_kind == request.provider_kind
            && identity.provider_subject == request.provider_subject
    });
    let Some(identity) = identity else {
        return Ok(None);
    };
    if identity.status != ResourceStatus::Active {
        return Err(GatewayError::Authentication);
    }
    let user = read_lock(&store.users)
        .get(&identity.principal_id)
        .cloned()
        .ok_or_else(|| GatewayError::Internal {
            message: "external identity principal is missing".to_owned(),
        })?;
    if user.status != DirectoryStatus::Active {
        return Err(GatewayError::Authentication);
    }
    identity.email.clone_from(&request.email);
    identity.email_verified = request.email_verified;
    identity.updated_at = now;
    let updated = identity.clone();
    drop(identities);
    Ok(Some((user, updated)))
}

fn retain_fresh_failed_auth(
    attempts: &mut Vec<chrono::DateTime<chrono::Utc>>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let window_start = now - chrono::Duration::seconds(API_KEY_FAILED_AUTH_WINDOW_SECONDS);
    attempts.retain(|attempt| *attempt > window_start);
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    match lock.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    match lock.write() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn validate_entry<K, V, F>(
    map: &HashMap<K, V>,
    key: &K,
    value: &V,
    is_match: F,
    reason: &'static str,
) -> Result<()>
where
    K: Eq + std::hash::Hash,
    F: Fn(&V, &V) -> bool,
{
    if let Some(existing) = map.get(key) {
        if is_match(existing, value) {
            return Ok(());
        }
        return Err(GatewayError::BadRequest {
            message: reason.to_owned(),
        });
    }
    Ok(())
}

fn tenancy_seed_from_request(
    request: &BootstrapDefaultProjectRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> TenancySeed {
    TenancySeed {
        tenant: TenantRecord {
            tenant_id: request.tenant_id.clone(),
            display_name: request.tenant_display_name.clone(),
            status: DirectoryStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_at: now,
            updated_at: now,
        },
        organization: OrganizationRecord {
            organization_id: request.organization_id.clone(),
            tenant_id: request.tenant_id.clone(),
            display_name: request.organization_display_name.clone(),
            status: DirectoryStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_at: now,
            updated_at: now,
        },
        project: ProjectRecord {
            project_id: request.project_id.clone(),
            tenant_id: request.tenant_id.clone(),
            organization_id: request.organization_id.clone(),
            display_name: request.project_display_name.clone(),
            status: DirectoryStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_at: now,
            updated_at: now,
        },
        user: UserRecord {
            user_id: request.user_id.clone(),
            tenant_id: request.tenant_id.clone(),
            default_organization_id: Some(request.organization_id.clone()),
            default_project_id: Some(request.project_id.clone()),
            primary_email: request.user_primary_email.clone(),
            display_name: request.user_display_name.clone(),
            status: DirectoryStatus::Active,
            resource_version: 1,
            schema_version: 1,
            created_at: now,
            updated_at: now,
        },
        organization_membership: OrganizationMembershipRecord {
            organization_member_id: request.organization_member_id.clone(),
            tenant_id: request.tenant_id.clone(),
            organization_id: request.organization_id.clone(),
            principal_id: request.user_id.clone(),
            status: MembershipStatus::Active,
            resource_version: 1,
        },
        project_membership: ProjectMembershipRecord {
            project_member_id: request.project_member_id.clone(),
            tenant_id: request.tenant_id.clone(),
            organization_id: request.organization_id.clone(),
            project_id: request.project_id.clone(),
            principal_id: request.user_id.clone(),
            organization_member_id: Some(request.organization_member_id.clone()),
            status: MembershipStatus::Active,
            resource_version: 1,
        },
    }
}

fn tenant_seed_matches(existing: &TenantRecord, value: &TenantRecord) -> bool {
    existing.tenant_id == value.tenant_id && existing.display_name == value.display_name
}

fn organization_seed_matches(existing: &OrganizationRecord, value: &OrganizationRecord) -> bool {
    existing.organization_id == value.organization_id
        && existing.tenant_id == value.tenant_id
        && existing.display_name == value.display_name
}

fn project_seed_matches(existing: &ProjectRecord, value: &ProjectRecord) -> bool {
    existing.project_id == value.project_id
        && existing.tenant_id == value.tenant_id
        && existing.organization_id == value.organization_id
        && existing.display_name == value.display_name
}

fn user_seed_matches(existing: &UserRecord, value: &UserRecord) -> bool {
    existing.user_id == value.user_id
        && existing.tenant_id == value.tenant_id
        && existing.default_organization_id == value.default_organization_id
        && existing.default_project_id == value.default_project_id
        && existing.primary_email == value.primary_email
        && existing.display_name == value.display_name
}

fn organization_membership_seed_matches(
    existing: &OrganizationMembershipRecord,
    value: &OrganizationMembershipRecord,
) -> bool {
    existing.organization_member_id == value.organization_member_id
        && existing.tenant_id == value.tenant_id
        && existing.organization_id == value.organization_id
        && existing.principal_id == value.principal_id
}

fn project_membership_seed_matches(
    existing: &ProjectMembershipRecord,
    value: &ProjectMembershipRecord,
) -> bool {
    existing.project_member_id == value.project_member_id
        && existing.tenant_id == value.tenant_id
        && existing.organization_id == value.organization_id
        && existing.project_id == value.project_id
        && existing.principal_id == value.principal_id
        && existing.organization_member_id == value.organization_member_id
}

/// `PostgreSQL` repository implementation for durable gateway state.
#[derive(Clone, Debug)]
pub struct PostgresGatewayStore {
    pool: PgPool,
}

impl PostgresGatewayStore {
    /// Creates a store backed by a `PostgreSQL` pool.
    #[must_use]
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Returns the underlying `PostgreSQL` pool.
    #[must_use]
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Loads an auth session by opaque token hash.
    pub async fn auth_session_by_hash(
        &self,
        session_hash: &str,
    ) -> Result<Option<AuthSessionRecord>> {
        let row = sqlx::query(
            r"
            SELECT
                auth_session_id,
                tenant_id,
                principal_id,
                active_organization_id,
                active_project_id,
                session_hash,
                status,
                expires_at,
                created_at,
                updated_at
            FROM gateway_auth_sessions
            WHERE session_hash = $1
              AND status IN ('active', 'revoked', 'expired')
            LIMIT 1
            ",
        )
        .bind(session_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load auth session: {error}"),
        })?;

        row.map_or(Ok(None), |row| auth_session_record_from_row(&row).map(Some))
    }

    /// Inserts an auth session record.
    pub async fn insert_auth_session(&self, record: &AuthSessionRecord) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO gateway_auth_sessions (
                auth_session_id,
                tenant_id,
                principal_id,
                active_organization_id,
                active_project_id,
                session_hash,
                status,
                expires_at,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            ON CONFLICT (auth_session_id) DO NOTHING
            ",
        )
        .bind(&record.auth_session_id)
        .bind(&record.tenant_id)
        .bind(&record.principal_id)
        .bind(&record.active_organization_id)
        .bind(&record.active_project_id)
        .bind(&record.session_hash)
        .bind(auth_session_status_as_str(&record.status))
        .bind(record.expires_at)
        .bind(record.created_at)
        .bind(record.updated_at)
        .execute(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to insert auth session: {error}"),
        })?;
        Ok(())
    }

    /// Updates active organization and project context for one active session.
    pub async fn update_auth_session_active_context_by_hash(
        &self,
        session_hash: &str,
        active_organization_id: Option<String>,
        active_project_id: Option<String>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord> {
        let row = sqlx::query(
            r"
            UPDATE gateway_auth_sessions
            SET active_organization_id = $2,
                active_project_id = $3,
                updated_at = $4
            WHERE session_hash = $1
              AND status = 'active'
              AND expires_at > $4
            RETURNING
                auth_session_id,
                tenant_id,
                principal_id,
                active_organization_id,
                active_project_id,
                session_hash,
                status,
                expires_at,
                created_at,
                updated_at
            ",
        )
        .bind(session_hash)
        .bind(active_organization_id)
        .bind(active_project_id)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to update auth session context: {error}"),
        })?;

        row.map_or(Err(GatewayError::Authentication), |row| {
            auth_session_record_from_row(&row)
        })
    }

    /// Revokes an auth session by opaque token hash.
    pub async fn revoke_auth_session_by_hash(
        &self,
        session_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<AuthSessionRecord> {
        let row = sqlx::query(
            r"
            UPDATE gateway_auth_sessions
            SET status = 'revoked',
                updated_at = $2
            WHERE session_hash = $1
            RETURNING
                auth_session_id,
                tenant_id,
                principal_id,
                active_organization_id,
                active_project_id,
                session_hash,
                status,
                expires_at,
                created_at,
                updated_at
            ",
        )
        .bind(session_hash)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to revoke auth session: {error}"),
        })?;

        row.map_or(Err(GatewayError::Authentication), |row| {
            auth_session_record_from_row(&row)
        })
    }

    /// Loads tenant metadata by id.
    pub async fn tenant_by_id(&self, tenant_id: &str) -> Result<Option<TenantRecord>> {
        let row = sqlx::query(
            r"
            SELECT
                tenant_id,
                display_name,
                status,
                resource_version,
                schema_version,
                created_at,
                updated_at
            FROM gateway_tenants
            WHERE tenant_id = $1
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load tenant: {error}"),
        })?;

        row.map_or(Ok(None), |row| tenant_record_from_row(&row).map(Some))
    }

    /// Loads organization metadata by id.
    pub async fn organization_by_id(
        &self,
        organization_id: &str,
    ) -> Result<Option<OrganizationRecord>> {
        let row = sqlx::query(
            r"
            SELECT
                organization_id,
                tenant_id,
                display_name,
                status,
                resource_version,
                schema_version,
                created_at,
                updated_at
            FROM gateway_organizations
            WHERE organization_id = $1
            LIMIT 1
            ",
        )
        .bind(organization_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load organization: {error}"),
        })?;

        row.map_or(Ok(None), |row| organization_record_from_row(&row).map(Some))
    }

    /// Loads project metadata by id.
    pub async fn project_by_id(&self, project_id: &str) -> Result<Option<ProjectRecord>> {
        let row = sqlx::query(
            r"
            SELECT
                project_id,
                tenant_id,
                organization_id,
                display_name,
                status,
                resource_version,
                schema_version,
                created_at,
                updated_at
            FROM gateway_projects
            WHERE project_id = $1
            LIMIT 1
            ",
        )
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load project: {error}"),
        })?;

        row.map_or(Ok(None), |row| project_record_from_row(&row).map(Some))
    }

    /// Loads user metadata by id.
    pub async fn user_by_id(&self, user_id: &str) -> Result<Option<UserRecord>> {
        let row = sqlx::query(
            r"
            SELECT
                user_id,
                tenant_id,
                default_organization_id,
                default_project_id,
                primary_email,
                display_name,
                status,
                resource_version,
                schema_version,
                created_at,
                updated_at
            FROM gateway_users
            WHERE user_id = $1
            LIMIT 1
            ",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load user: {error}"),
        })?;

        row.map_or(Ok(None), |row| user_record_from_row(&row).map(Some))
    }

    /// Updates project status with optimistic concurrency.
    pub async fn update_project_status(
        &self,
        project_id: &str,
        expected_resource_version: i64,
        status: DirectoryStatus,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ProjectRecord> {
        let row = sqlx::query(
            r"
            UPDATE gateway_projects
            SET status = $3,
                resource_version = resource_version + 1,
                updated_at = $4
            WHERE project_id = $1
              AND resource_version = $2
            RETURNING
                project_id,
                tenant_id,
                organization_id,
                display_name,
                status,
                resource_version,
                schema_version,
                created_at,
                updated_at
            ",
        )
        .bind(project_id)
        .bind(expected_resource_version)
        .bind(status.as_str())
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to update project status: {error}"),
        })?;

        row.map_or_else(
            || {
                Err(GatewayError::BadRequest {
                    message: "stale_resource_version".to_owned(),
                })
            },
            |row| project_record_from_row(&row),
        )
    }

    /// Loads bounded API key candidates by visible prefix.
    pub async fn api_key_candidates_by_prefix(&self, prefix: &str) -> Result<Vec<ApiKeyRecord>> {
        let rows = sqlx::query(
            r"
            SELECT
                api_key_id,
                tenant_id,
                organization_id,
                project_id,
                owner_principal_id,
                name,
                key_prefix,
                secret_hash,
                hash_version,
                status,
                allowed_actions,
                allowed_resources,
                expires_at,
                last_used_at,
                last_used_request_id,
                created_by,
                created_at,
                updated_at
            FROM gateway_api_keys
            WHERE key_prefix = $1
              AND status IN ('active', 'rotating', 'disabled', 'expired')
            ORDER BY updated_at DESC
            LIMIT 8
            ",
        )
        .bind(prefix)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load api key candidates: {error}"),
        })?;

        rows.iter().map(api_key_record_from_row).collect()
    }

    /// Flushes queued API key last-used updates.
    pub async fn flush_api_key_last_used_updates(
        &self,
        updates: &[ApiKeyLastUsedUpdate],
    ) -> Result<()> {
        for update in updates {
            sqlx::query(
                r"
                UPDATE gateway_api_keys
                SET last_used_at = $3,
                    last_used_request_id = $4,
                    updated_at = $3
                WHERE tenant_id = $1
                  AND api_key_id = $2
                  AND (last_used_at IS NULL OR last_used_at <= $3)
                ",
            )
            .bind(&update.tenant_id)
            .bind(&update.api_key_id)
            .bind(update.used_at)
            .bind(&update.request_id)
            .execute(&self.pool)
            .await
            .map_err(|error| GatewayError::Internal {
                message: format!("failed to flush api key last-used update: {error}"),
            })?;
        }
        Ok(())
    }

    /// Loads the latest published config snapshot metadata.
    pub async fn latest_published_snapshot(&self) -> Result<Option<ConfigSnapshot>> {
        let row = sqlx::query(
            r"
            SELECT
                config_snapshot_id,
                tenant_id,
                version,
                checksum,
                status,
                compiled_at
            FROM gateway_config_snapshots
            WHERE status = 'published'
            ORDER BY version DESC
            LIMIT 1
            ",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load latest config snapshot: {error}"),
        })?;

        row.map_or(Ok(None), |row| config_snapshot_from_row(&row).map(Some))
    }

    /// Loads the latest published config snapshot metadata for one tenant.
    pub async fn latest_published_snapshot_for_tenant(
        &self,
        tenant_id: &str,
    ) -> Result<Option<ConfigSnapshot>> {
        let row = sqlx::query(
            r"
            SELECT
                config_snapshot_id,
                tenant_id,
                version,
                checksum,
                status,
                compiled_at
            FROM gateway_config_snapshots
            WHERE tenant_id = $1
              AND status = 'published'
            ORDER BY version DESC
            LIMIT 1
            ",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load tenant config snapshot: {error}"),
        })?;

        row.map_or(Ok(None), |row| config_snapshot_from_row(&row).map(Some))
    }

    /// Loads a published config snapshot document by id.
    pub async fn config_snapshot_by_id(
        &self,
        snapshot_id: &str,
    ) -> Result<Option<PublishedConfigSnapshot>> {
        let row = sqlx::query(
            r"
            SELECT
                config_snapshot_id,
                tenant_id,
                version,
                checksum,
                status,
                compiled_at,
                snapshot_document,
                created_by,
                published_at
            FROM gateway_config_snapshots
            WHERE config_snapshot_id = $1
            LIMIT 1
            ",
        )
        .bind(snapshot_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load config snapshot document: {error}"),
        })?;

        row.map_or(Ok(None), |row| {
            published_config_snapshot_from_row(&row).map(Some)
        })
    }

    /// Lists published config snapshots for one tenant.
    pub async fn config_snapshots_for_tenant(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<PublishedConfigSnapshot>> {
        let rows = sqlx::query(
            r"
            SELECT
                config_snapshot_id,
                tenant_id,
                version,
                checksum,
                status,
                compiled_at,
                snapshot_document,
                created_by,
                published_at
            FROM gateway_config_snapshots
            WHERE tenant_id = $1
              AND status = 'published'
            ORDER BY version DESC, config_snapshot_id ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to list config snapshots: {error}"),
        })?;

        rows.iter()
            .map(published_config_snapshot_from_row)
            .collect()
    }

    /// Inserts a published config snapshot.
    pub async fn insert_config_snapshot(&self, snapshot: &PublishedConfigSnapshot) -> Result<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| GatewayError::Internal {
                message: format!("failed to begin config snapshot transaction: {error}"),
            })?;
        insert_config_snapshot_row(&mut transaction, snapshot).await?;
        let invalidation_id = crate::domain::new_prefixed_id("cfginv");
        insert_config_invalidation_event(&mut transaction, snapshot, &invalidation_id).await?;
        upsert_config_publication_pointer(&mut transaction, snapshot, &invalidation_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| GatewayError::Internal {
                message: format!("failed to commit config snapshot transaction: {error}"),
            })?;
        Ok(())
    }

    /// Loads project membership for a principal and project.
    pub async fn project_membership_for_principal(
        &self,
        principal_id: &str,
        project_id: &str,
    ) -> Result<Option<ProjectMembershipRecord>> {
        let row = sqlx::query(
            r"
            SELECT
                project_member_id,
                tenant_id,
                organization_id,
                project_id,
                principal_id,
                organization_member_id,
                status,
                resource_version
            FROM gateway_project_memberships
            WHERE principal_id = $1
              AND project_id = $2
              AND status IN ('active', 'suspended')
            LIMIT 1
            ",
        )
        .bind(principal_id)
        .bind(project_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to load project membership: {error}"),
        })?;

        row.map_or(Ok(None), |row| project_membership_from_row(&row).map(Some))
    }

    /// Records durable authorization decision evidence.
    pub async fn insert_authorization_decision(
        &self,
        record: &AuthorizationDecisionRecord,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO gateway_authz_decision_events (
                authz_decision_id,
                tenant_id,
                organization_id,
                project_id,
                actor_id,
                actor_kind,
                action_id,
                resource_kind,
                resource_id,
                decision,
                reason,
                policy_snapshot_id,
                request_id,
                occurred_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            ",
        )
        .bind(&record.authz_decision_id)
        .bind(&record.tenant_id)
        .bind(&record.organization_id)
        .bind(&record.project_id)
        .bind(&record.actor_id)
        .bind(record.actor_kind.as_str())
        .bind(record.action.as_str())
        .bind(&record.resource_kind)
        .bind(&record.resource_id)
        .bind(record.decision_label())
        .bind(&record.reason)
        .bind(&record.policy_snapshot_id)
        .bind(&record.request_id)
        .bind(record.occurred_at)
        .execute(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to insert authorization decision: {error}"),
        })?;
        Ok(())
    }

    /// Records durable route decision evidence.
    pub async fn insert_route_decision(&self, record: &RouteDecisionRecord) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO gateway_route_decisions (
                route_decision_id,
                tenant_id,
                organization_id,
                project_id,
                principal_id,
                api_key_id,
                actor_id,
                actor_kind,
                request_id,
                trace_id,
                protocol_family,
                config_snapshot_id,
                config_version,
                model_alias_id,
                alias_name,
                route_policy_id,
                routing_group_id,
                model_target_id,
                provider_endpoint_id,
                upstream_credential_id,
                filtered_summary,
                sticky_hit,
                sticky_miss_reason,
                decision_status,
                reason,
                occurred_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14, $15, $16,
                $17, $18, $19, $20, $21, $22, $23, $24,
                $25, $26
            )
            ON CONFLICT (route_decision_id) DO NOTHING
            ",
        )
        .bind(&record.route_decision_id)
        .bind(&record.tenant_id)
        .bind(&record.organization_id)
        .bind(&record.project_id)
        .bind(&record.principal_id)
        .bind(&record.api_key_id)
        .bind(&record.actor_id)
        .bind(record.actor_kind.as_str())
        .bind(&record.request_id)
        .bind(&record.trace_id)
        .bind(record.protocol_family.as_str())
        .bind(&record.config_snapshot_id)
        .bind(record.config_version)
        .bind(&record.model_alias_id)
        .bind(&record.alias_name)
        .bind(&record.route_policy_id)
        .bind(&record.routing_group_id)
        .bind(&record.model_target_id)
        .bind(&record.provider_endpoint_id)
        .bind(&record.upstream_credential_id)
        .bind(
            serde_json::to_value(&record.filtered_summary).map_err(|error| {
                GatewayError::Internal {
                    message: format!("failed to encode route filter summary: {error}"),
                }
            })?,
        )
        .bind(record.sticky_hit)
        .bind(&record.sticky_miss_reason)
        .bind(record.status.as_str())
        .bind(&record.reason)
        .bind(record.occurred_at)
        .execute(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to insert route decision: {error}"),
        })?;
        Ok(())
    }

    /// Records durable route attempt evidence.
    pub async fn insert_route_attempt(&self, record: &RouteAttemptRecord) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO gateway_route_attempt_events (
                route_attempt_event_id,
                route_decision_id,
                attempt_index,
                routing_group_id,
                model_target_id,
                provider_endpoint_id,
                status,
                started_at,
                ended_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            ON CONFLICT (route_attempt_event_id) DO NOTHING
            ",
        )
        .bind(&record.route_attempt_event_id)
        .bind(&record.route_decision_id)
        .bind(
            i32::try_from(record.attempt_index).map_err(|error| GatewayError::Internal {
                message: format!("invalid route attempt index: {error}"),
            })?,
        )
        .bind(&record.routing_group_id)
        .bind(&record.model_target_id)
        .bind(&record.provider_endpoint_id)
        .bind(record.status.as_str())
        .bind(record.started_at)
        .bind(record.ended_at)
        .execute(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to insert route attempt: {error}"),
        })?;
        Ok(())
    }

    /// Records a durable usage event and folds it into ledger buckets.
    pub async fn insert_usage_event(&self, record: &UsageEventRecord) -> Result<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| GatewayError::Internal {
                message: format!("failed to begin usage event transaction: {error}"),
            })?;
        let insert = sqlx::query(
            r"
            INSERT INTO gateway_usage_events (
                usage_event_id,
                tenant_id,
                organization_id,
                project_id,
                principal_id,
                project_member_id,
                service_account_id,
                api_key_id,
                request_id,
                trace_id,
                protocol_family,
                route_decision_id,
                model_alias_id,
                model_target_id,
                route_policy_id,
                routing_group_id,
                provider_endpoint_id,
                upstream_credential_id,
                usage_confidence,
                latency_ms,
                time_to_first_token_ms,
                status,
                usage_payload,
                cost_payload,
                occurred_at
            )
            VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14, $15, $16,
                $17, $18, $19, $20, $21, $22, $23, $24,
                $25
            )
            ON CONFLICT DO NOTHING
            ",
        )
        .bind(&record.usage_event_id)
        .bind(&record.tenant_id)
        .bind(&record.organization_id)
        .bind(&record.project_id)
        .bind(&record.principal_id)
        .bind(&record.project_member_id)
        .bind(&record.service_account_id)
        .bind(&record.api_key_id)
        .bind(&record.request_id)
        .bind(&record.trace_id)
        .bind(record.protocol_family.as_str())
        .bind(&record.route_decision_id)
        .bind(&record.model_alias_id)
        .bind(&record.model_target_id)
        .bind(&record.route_policy_id)
        .bind(&record.routing_group_id)
        .bind(&record.provider_endpoint_id)
        .bind(&record.upstream_credential_id)
        .bind(&record.usage_confidence)
        .bind(record.latency_ms)
        .bind(record.time_to_first_token_ms)
        .bind(&record.status)
        .bind(&record.usage_payload)
        .bind(&record.cost_payload)
        .bind(record.occurred_at)
        .execute(&mut *transaction)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to insert usage event: {error}"),
        })?;
        if insert.rows_affected() == 0 {
            transaction
                .commit()
                .await
                .map_err(|error| GatewayError::Internal {
                    message: format!("failed to commit duplicate usage event transaction: {error}"),
                })?;
            return Ok(());
        }
        for bucket_kind in ["event", "minute", "hour", "day", "month"] {
            let bucket = ledger_bucket_record_for_event(record, bucket_kind)?;
            upsert_ledger_bucket(&mut transaction, &bucket, record).await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| GatewayError::Internal {
                message: format!("failed to commit usage event transaction: {error}"),
            })?;
        Ok(())
    }

    /// Lists usage events for one tenant.
    pub async fn usage_events_for_tenant(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<UsageEventRecord>> {
        let rows = sqlx::query(
            r"
            SELECT
                usage_event_id,
                tenant_id,
                organization_id,
                project_id,
                principal_id,
                project_member_id,
                service_account_id,
                api_key_id,
                request_id,
                trace_id,
                protocol_family,
                route_decision_id,
                model_alias_id,
                model_target_id,
                route_policy_id,
                routing_group_id,
                provider_endpoint_id,
                upstream_credential_id,
                usage_confidence,
                latency_ms,
                time_to_first_token_ms,
                status,
                usage_payload,
                cost_payload,
                occurred_at
            FROM gateway_usage_events
            WHERE tenant_id = $1
            ORDER BY occurred_at DESC, usage_event_id ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to list usage events: {error}"),
        })?;

        rows.iter().map(usage_event_record_from_row).collect()
    }

    /// Lists ledger buckets for one tenant.
    pub async fn ledger_buckets_for_tenant(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<LedgerBucketRecord>> {
        let rows = sqlx::query(
            r"
            SELECT
                ledger_bucket_id,
                tenant_id,
                organization_id,
                project_id,
                principal_id,
                project_member_id,
                service_account_id,
                api_key_id,
                model_alias_id,
                model_target_id,
                provider_endpoint_id,
                upstream_credential_id,
                route_policy_id,
                routing_group_id,
                protocol_family,
                status,
                usage_confidence,
                bucket_kind,
                bucket_start,
                currency_code,
                input_tokens,
                output_tokens,
                reasoning_tokens,
                media_units,
                request_count,
                success_count,
                error_count,
                blocked_count,
                usage_missing_count,
                usage_estimated_count,
                estimated_cost_micros,
                pricing_version,
                updated_at
            FROM gateway_ledger_buckets
            WHERE tenant_id = $1
            ORDER BY bucket_start DESC, ledger_bucket_id ASC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to list ledger buckets: {error}"),
        })?;

        rows.iter().map(ledger_bucket_record_from_row).collect()
    }

    /// Lists route decisions for one tenant.
    pub async fn route_decisions_for_tenant(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<RouteDecisionRecord>> {
        let rows = sqlx::query(
            r"
            SELECT
                route_decision_id,
                tenant_id,
                organization_id,
                project_id,
                principal_id,
                api_key_id,
                actor_id,
                actor_kind,
                request_id,
                trace_id,
                protocol_family,
                config_snapshot_id,
                config_version,
                model_alias_id,
                alias_name,
                route_policy_id,
                routing_group_id,
                model_target_id,
                provider_endpoint_id,
                upstream_credential_id,
                filtered_summary,
                sticky_hit,
                sticky_miss_reason,
                decision_status,
                reason,
                occurred_at
            FROM gateway_route_decisions
            WHERE tenant_id = $1
            ORDER BY occurred_at DESC, route_decision_id DESC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to list route decisions: {error}"),
        })?;

        rows.iter().map(route_decision_record_from_row).collect()
    }

    /// Lists route attempts for one tenant by joining parent decisions.
    pub async fn route_attempts_for_tenant(
        &self,
        tenant_id: &str,
        limit: i64,
    ) -> Result<Vec<RouteAttemptRecord>> {
        let rows = sqlx::query(
            r"
            SELECT
                attempt.route_attempt_event_id,
                attempt.route_decision_id,
                attempt.attempt_index,
                attempt.routing_group_id,
                attempt.model_target_id,
                attempt.provider_endpoint_id,
                attempt.status,
                attempt.started_at,
                attempt.ended_at
            FROM gateway_route_attempt_events attempt
            INNER JOIN gateway_route_decisions decision
                ON decision.route_decision_id = attempt.route_decision_id
            WHERE decision.tenant_id = $1
            ORDER BY attempt.started_at DESC, attempt.route_attempt_event_id DESC
            LIMIT $2
            ",
        )
        .bind(tenant_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to list route attempts: {error}"),
        })?;

        rows.iter().map(route_attempt_record_from_row).collect()
    }
}

async fn insert_config_snapshot_row(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot: &PublishedConfigSnapshot,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO gateway_config_snapshots (
            config_snapshot_id,
            tenant_id,
            version,
            checksum,
            status,
            diagnostics,
            snapshot_document,
            schema_version,
            compiled_at,
            published_at,
            created_by
        )
        VALUES ($1, $2, $3, $4, 'published', '[]'::jsonb, $5, 1, $6, $7, $8)
        ",
    )
    .bind(&snapshot.metadata.snapshot_id)
    .bind(&snapshot.metadata.tenant_id)
    .bind(snapshot.metadata.version)
    .bind(&snapshot.metadata.checksum)
    .bind(
        serde_json::to_value(&snapshot.document).map_err(|error| GatewayError::Internal {
            message: format!("failed to encode config snapshot document: {error}"),
        })?,
    )
    .bind(snapshot.metadata.compiled_at)
    .bind(snapshot.published_at)
    .bind(&snapshot.created_by)
    .execute(&mut **transaction)
    .await
    .map_err(|error| GatewayError::Internal {
        message: format!("failed to insert config snapshot: {error}"),
    })?;
    Ok(())
}

async fn insert_config_invalidation_event(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot: &PublishedConfigSnapshot,
    invalidation_id: &str,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO gateway_config_invalidation_events (
            config_invalidation_id,
            tenant_id,
            config_snapshot_id,
            version,
            checksum,
            published_at,
            created_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        ",
    )
    .bind(invalidation_id)
    .bind(&snapshot.metadata.tenant_id)
    .bind(&snapshot.metadata.snapshot_id)
    .bind(snapshot.metadata.version)
    .bind(&snapshot.metadata.checksum)
    .bind(snapshot.published_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| GatewayError::Internal {
        message: format!("failed to insert config invalidation event: {error}"),
    })?;
    Ok(())
}

async fn upsert_config_publication_pointer(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    snapshot: &PublishedConfigSnapshot,
    invalidation_id: &str,
) -> Result<()> {
    sqlx::query(
        r"
        INSERT INTO gateway_config_publications (
            tenant_id,
            config_snapshot_id,
            version,
            checksum,
            config_invalidation_id,
            published_at,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $6)
        ON CONFLICT (tenant_id) DO UPDATE
        SET config_snapshot_id = EXCLUDED.config_snapshot_id,
            version = EXCLUDED.version,
            checksum = EXCLUDED.checksum,
            config_invalidation_id = EXCLUDED.config_invalidation_id,
            published_at = EXCLUDED.published_at,
            updated_at = EXCLUDED.updated_at
        ",
    )
    .bind(&snapshot.metadata.tenant_id)
    .bind(&snapshot.metadata.snapshot_id)
    .bind(snapshot.metadata.version)
    .bind(&snapshot.metadata.checksum)
    .bind(invalidation_id)
    .bind(snapshot.published_at)
    .execute(&mut **transaction)
    .await
    .map_err(|error| GatewayError::Internal {
        message: format!("failed to upsert config publication pointer: {error}"),
    })?;
    Ok(())
}

const LEDGER_BUCKET_UPSERT_SQL: &str = r"
    INSERT INTO gateway_ledger_buckets (
        ledger_bucket_id,
        tenant_id,
        organization_id,
        project_id,
        principal_id,
        project_member_id,
        service_account_id,
        api_key_id,
        model_alias_id,
        model_target_id,
        provider_endpoint_id,
        upstream_credential_id,
        route_policy_id,
        routing_group_id,
        protocol_family,
        status,
        usage_confidence,
        bucket_kind,
        bucket_start,
        currency_code,
        input_tokens,
        output_tokens,
        reasoning_tokens,
        media_units,
        request_count,
        success_count,
        error_count,
        blocked_count,
        usage_missing_count,
        usage_estimated_count,
        estimated_cost_micros,
        latency_ms_sum,
        latency_sample_count,
        ttft_ms_sum,
        ttft_sample_count,
        pricing_version,
        updated_at
    )
    VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8,
        $9, $10, $11, $12, $13, $14, $15, $16,
        $17, $18, $19, $20, $21, $22, $23, $24,
        $25, $26, $27, $28, $29, $30, $31, $32,
        $33, $34, $35, $36, $37
    )
    ON CONFLICT (ledger_bucket_id) DO UPDATE SET
        input_tokens = gateway_ledger_buckets.input_tokens + EXCLUDED.input_tokens,
        output_tokens = gateway_ledger_buckets.output_tokens + EXCLUDED.output_tokens,
        reasoning_tokens = gateway_ledger_buckets.reasoning_tokens + EXCLUDED.reasoning_tokens,
        media_units = gateway_ledger_buckets.media_units + EXCLUDED.media_units,
        request_count = gateway_ledger_buckets.request_count + EXCLUDED.request_count,
        success_count = gateway_ledger_buckets.success_count + EXCLUDED.success_count,
        error_count = gateway_ledger_buckets.error_count + EXCLUDED.error_count,
        blocked_count = gateway_ledger_buckets.blocked_count + EXCLUDED.blocked_count,
        usage_missing_count = gateway_ledger_buckets.usage_missing_count + EXCLUDED.usage_missing_count,
        usage_estimated_count = gateway_ledger_buckets.usage_estimated_count + EXCLUDED.usage_estimated_count,
        estimated_cost_micros = gateway_ledger_buckets.estimated_cost_micros + EXCLUDED.estimated_cost_micros,
        latency_ms_sum = gateway_ledger_buckets.latency_ms_sum + EXCLUDED.latency_ms_sum,
        latency_sample_count = gateway_ledger_buckets.latency_sample_count + EXCLUDED.latency_sample_count,
        ttft_ms_sum = gateway_ledger_buckets.ttft_ms_sum + EXCLUDED.ttft_ms_sum,
        ttft_sample_count = gateway_ledger_buckets.ttft_sample_count + EXCLUDED.ttft_sample_count,
        updated_at = GREATEST(gateway_ledger_buckets.updated_at, EXCLUDED.updated_at)
    ";

async fn upsert_ledger_bucket(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    bucket: &LedgerBucketRecord,
    source_event: &UsageEventRecord,
) -> Result<()> {
    let protocol_family = bucket.protocol_family.map(ProtocolFamily::as_str);
    let latency_ms_sum = source_event.latency_ms.unwrap_or(0);
    let latency_sample_count = i64::from(source_event.latency_ms.is_some());
    let ttft_ms_sum = source_event.time_to_first_token_ms.unwrap_or(0);
    let ttft_sample_count = i64::from(source_event.time_to_first_token_ms.is_some());
    sqlx::query(LEDGER_BUCKET_UPSERT_SQL)
        .bind(&bucket.ledger_bucket_id)
        .bind(&bucket.tenant_id)
        .bind(&bucket.organization_id)
        .bind(&bucket.project_id)
        .bind(&bucket.principal_id)
        .bind(&bucket.project_member_id)
        .bind(&bucket.service_account_id)
        .bind(&bucket.api_key_id)
        .bind(&bucket.model_alias_id)
        .bind(&bucket.model_target_id)
        .bind(&bucket.provider_endpoint_id)
        .bind(&bucket.upstream_credential_id)
        .bind(&bucket.route_policy_id)
        .bind(&bucket.routing_group_id)
        .bind(protocol_family)
        .bind(&bucket.status)
        .bind(&bucket.usage_confidence)
        .bind(&bucket.bucket_kind)
        .bind(bucket.bucket_start)
        .bind(&bucket.currency_code)
        .bind(bucket.input_tokens)
        .bind(bucket.output_tokens)
        .bind(bucket.reasoning_tokens)
        .bind(bucket.media_units)
        .bind(bucket.request_count)
        .bind(bucket.success_count)
        .bind(bucket.error_count)
        .bind(bucket.blocked_count)
        .bind(bucket.usage_missing_count)
        .bind(bucket.usage_estimated_count)
        .bind(bucket.estimated_cost_micros)
        .bind(latency_ms_sum)
        .bind(latency_sample_count)
        .bind(ttft_ms_sum)
        .bind(ttft_sample_count)
        .bind(&bucket.pricing_version)
        .bind(bucket.updated_at)
        .execute(&mut **transaction)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to upsert ledger bucket: {error}"),
        })?;
    Ok(())
}

fn api_key_record_from_row(row: &sqlx::postgres::PgRow) -> Result<ApiKeyRecord> {
    let allowed_actions = row.get("allowed_actions");
    let allowed_resources = row.get("allowed_resources");
    Ok(ApiKeyRecord {
        api_key_id: row.get("api_key_id"),
        tenant_id: row.get("tenant_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        owner_principal_id: row.get("owner_principal_id"),
        name: row.get("name"),
        key_prefix: row.get("key_prefix"),
        secret_hash: row.get("secret_hash"),
        hash_version: checked_u16(row.get::<i32, _>("hash_version"), "hash_version")?,
        status: parse_api_key_status(row.get("status"))?,
        allowed_actions: json_string_vec(&allowed_actions, "allowed_actions")?,
        allowed_resources: json_string_vec(&allowed_resources, "allowed_resources")?,
        expires_at: row.get("expires_at"),
        last_used_at: row.get("last_used_at"),
        last_used_request_id: row.get("last_used_request_id"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn auth_session_record_from_row(row: &sqlx::postgres::PgRow) -> Result<AuthSessionRecord> {
    Ok(AuthSessionRecord {
        auth_session_id: row.get("auth_session_id"),
        tenant_id: row.get("tenant_id"),
        principal_id: row.get("principal_id"),
        active_organization_id: row.get("active_organization_id"),
        active_project_id: row.get("active_project_id"),
        session_hash: row.get("session_hash"),
        status: parse_auth_session_status(row.get("status"))?,
        expires_at: row.get("expires_at"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn tenant_record_from_row(row: &sqlx::postgres::PgRow) -> Result<TenantRecord> {
    Ok(TenantRecord {
        tenant_id: row.get("tenant_id"),
        display_name: row.get("display_name"),
        status: parse_directory_status(row.get("status"))?,
        resource_version: row.get("resource_version"),
        schema_version: checked_u16(row.get::<i32, _>("schema_version"), "schema_version")?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn organization_record_from_row(row: &sqlx::postgres::PgRow) -> Result<OrganizationRecord> {
    Ok(OrganizationRecord {
        organization_id: row.get("organization_id"),
        tenant_id: row.get("tenant_id"),
        display_name: row.get("display_name"),
        status: parse_directory_status(row.get("status"))?,
        resource_version: row.get("resource_version"),
        schema_version: checked_u16(row.get::<i32, _>("schema_version"), "schema_version")?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn project_record_from_row(row: &sqlx::postgres::PgRow) -> Result<ProjectRecord> {
    Ok(ProjectRecord {
        project_id: row.get("project_id"),
        tenant_id: row.get("tenant_id"),
        organization_id: row.get("organization_id"),
        display_name: row.get("display_name"),
        status: parse_directory_status(row.get("status"))?,
        resource_version: row.get("resource_version"),
        schema_version: checked_u16(row.get::<i32, _>("schema_version"), "schema_version")?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn user_record_from_row(row: &sqlx::postgres::PgRow) -> Result<UserRecord> {
    Ok(UserRecord {
        user_id: row.get("user_id"),
        tenant_id: row.get("tenant_id"),
        default_organization_id: row.get("default_organization_id"),
        default_project_id: row.get("default_project_id"),
        primary_email: row.get("primary_email"),
        display_name: row.get("display_name"),
        status: parse_directory_status(row.get("status"))?,
        resource_version: row.get("resource_version"),
        schema_version: checked_u16(row.get::<i32, _>("schema_version"), "schema_version")?,
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

fn config_snapshot_from_row(row: &sqlx::postgres::PgRow) -> Result<ConfigSnapshot> {
    Ok(ConfigSnapshot {
        snapshot_id: row.get("config_snapshot_id"),
        tenant_id: row.get("tenant_id"),
        version: row.get("version"),
        checksum: row.get("checksum"),
        status: parse_config_snapshot_status(row.get("status"))?,
        compiled_at: row.get("compiled_at"),
    })
}

fn published_config_snapshot_from_row(
    row: &sqlx::postgres::PgRow,
) -> Result<PublishedConfigSnapshot> {
    let metadata = config_snapshot_from_row(row)?;
    if metadata.status != ConfigSnapshotStatus::Published {
        return Err(GatewayError::Internal {
            message: format!("config snapshot {} is not published", metadata.snapshot_id),
        });
    }
    let document = serde_json::from_value::<ConfigSnapshotDocument>(row.get("snapshot_document"))
        .map_err(|error| GatewayError::Internal {
        message: format!("failed to decode config snapshot document: {error}"),
    })?;
    let published_at = row
        .get::<Option<chrono::DateTime<chrono::Utc>>, _>("published_at")
        .ok_or_else(|| GatewayError::Internal {
            message: format!(
                "published config snapshot {} is missing published_at",
                metadata.snapshot_id
            ),
        })?;
    Ok(PublishedConfigSnapshot {
        metadata,
        document,
        created_by: row.get("created_by"),
        published_at,
    })
}

fn project_membership_from_row(row: &sqlx::postgres::PgRow) -> Result<ProjectMembershipRecord> {
    Ok(ProjectMembershipRecord {
        project_member_id: row.get("project_member_id"),
        tenant_id: row.get("tenant_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        principal_id: row.get("principal_id"),
        organization_member_id: row.get("organization_member_id"),
        status: parse_membership_status(row.get("status"))?,
        resource_version: row.get("resource_version"),
    })
}

fn route_decision_record_from_row(row: &sqlx::postgres::PgRow) -> Result<RouteDecisionRecord> {
    Ok(RouteDecisionRecord {
        route_decision_id: row.get("route_decision_id"),
        tenant_id: row.get("tenant_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        principal_id: row.get("principal_id"),
        api_key_id: row.get("api_key_id"),
        actor_id: row.get("actor_id"),
        actor_kind: parse_actor_kind(row.get("actor_kind"))?,
        request_id: row.get("request_id"),
        trace_id: row.get("trace_id"),
        protocol_family: parse_protocol_family(row.get("protocol_family"))?,
        config_snapshot_id: row.get("config_snapshot_id"),
        config_version: row.get("config_version"),
        model_alias_id: row.get("model_alias_id"),
        alias_name: row.get("alias_name"),
        route_policy_id: row.get("route_policy_id"),
        routing_group_id: row.get("routing_group_id"),
        model_target_id: row.get("model_target_id"),
        provider_endpoint_id: row.get("provider_endpoint_id"),
        upstream_credential_id: row.get("upstream_credential_id"),
        filtered_summary: route_filter_summary_vec(row.get("filtered_summary"))?,
        sticky_hit: row.get("sticky_hit"),
        sticky_miss_reason: row.get("sticky_miss_reason"),
        status: parse_route_decision_status(row.get("decision_status"))?,
        reason: row.get("reason"),
        occurred_at: row.get("occurred_at"),
    })
}

fn route_attempt_record_from_row(row: &sqlx::postgres::PgRow) -> Result<RouteAttemptRecord> {
    Ok(RouteAttemptRecord {
        route_attempt_event_id: row.get("route_attempt_event_id"),
        route_decision_id: row.get("route_decision_id"),
        attempt_index: u32::try_from(row.get::<i32, _>("attempt_index")).map_err(|error| {
            GatewayError::Internal {
                message: format!("invalid route attempt index: {error}"),
            }
        })?,
        routing_group_id: row.get("routing_group_id"),
        model_target_id: row.get("model_target_id"),
        provider_endpoint_id: row.get("provider_endpoint_id"),
        status: parse_route_attempt_status(row.get("status"))?,
        started_at: row.get("started_at"),
        ended_at: row.get("ended_at"),
    })
}

fn usage_event_record_from_row(row: &sqlx::postgres::PgRow) -> Result<UsageEventRecord> {
    Ok(UsageEventRecord {
        usage_event_id: row.get("usage_event_id"),
        tenant_id: row.get("tenant_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        principal_id: row.get("principal_id"),
        project_member_id: row.get("project_member_id"),
        service_account_id: row.get("service_account_id"),
        api_key_id: row.get("api_key_id"),
        request_id: row.get("request_id"),
        trace_id: row.get("trace_id"),
        protocol_family: parse_protocol_family(row.get("protocol_family"))?,
        route_decision_id: row.get("route_decision_id"),
        model_alias_id: row.get("model_alias_id"),
        model_target_id: row.get("model_target_id"),
        route_policy_id: row.get("route_policy_id"),
        routing_group_id: row.get("routing_group_id"),
        provider_endpoint_id: row.get("provider_endpoint_id"),
        upstream_credential_id: row.get("upstream_credential_id"),
        usage_confidence: row.get("usage_confidence"),
        latency_ms: row.get("latency_ms"),
        time_to_first_token_ms: row.get("time_to_first_token_ms"),
        status: row.get("status"),
        usage_payload: row.get("usage_payload"),
        cost_payload: row.get("cost_payload"),
        occurred_at: row.get("occurred_at"),
    })
}

fn ledger_bucket_record_from_row(row: &sqlx::postgres::PgRow) -> Result<LedgerBucketRecord> {
    let protocol_family = row
        .get::<Option<String>, _>("protocol_family")
        .as_deref()
        .map(parse_protocol_family)
        .transpose()?;
    Ok(LedgerBucketRecord {
        ledger_bucket_id: row.get("ledger_bucket_id"),
        tenant_id: row.get("tenant_id"),
        organization_id: row.get("organization_id"),
        project_id: row.get("project_id"),
        principal_id: row.get("principal_id"),
        project_member_id: row.get("project_member_id"),
        service_account_id: row.get("service_account_id"),
        api_key_id: row.get("api_key_id"),
        model_alias_id: row.get("model_alias_id"),
        model_target_id: row.get("model_target_id"),
        provider_endpoint_id: row.get("provider_endpoint_id"),
        upstream_credential_id: row.get("upstream_credential_id"),
        route_policy_id: row.get("route_policy_id"),
        routing_group_id: row.get("routing_group_id"),
        protocol_family,
        status: row.get("status"),
        usage_confidence: row.get("usage_confidence"),
        bucket_kind: row.get("bucket_kind"),
        bucket_start: row.get("bucket_start"),
        currency_code: row.get("currency_code"),
        input_tokens: row.get("input_tokens"),
        output_tokens: row.get("output_tokens"),
        reasoning_tokens: row.get("reasoning_tokens"),
        media_units: row.get("media_units"),
        request_count: row.get("request_count"),
        success_count: row.get("success_count"),
        error_count: row.get("error_count"),
        blocked_count: row.get("blocked_count"),
        usage_missing_count: row.get("usage_missing_count"),
        usage_estimated_count: row.get("usage_estimated_count"),
        estimated_cost_micros: row.get("estimated_cost_micros"),
        pricing_version: row.get("pricing_version"),
        updated_at: row.get("updated_at"),
    })
}

fn checked_u16(value: i32, field: &str) -> Result<u16> {
    u16::try_from(value).map_err(|error| GatewayError::Internal {
        message: format!("invalid {field}: {error}"),
    })
}

fn json_string_vec(value: &Value, field: &str) -> Result<Vec<String>> {
    let Some(items) = value.as_array() else {
        return Err(GatewayError::Internal {
            message: format!("{field} must be a JSON array"),
        });
    };
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| GatewayError::Internal {
                    message: format!("{field} must contain strings"),
                })
        })
        .collect()
}

fn route_filter_summary_vec(value: Value) -> Result<Vec<RouteFilterSummary>> {
    serde_json::from_value(value).map_err(|error| GatewayError::Internal {
        message: format!("failed to decode route filter summary: {error}"),
    })
}

fn parse_actor_kind(value: &str) -> Result<crate::domain::ActorKind> {
    match value {
        "user" => Ok(crate::domain::ActorKind::User),
        "service_account" => Ok(crate::domain::ActorKind::ServiceAccount),
        "api_key" => Ok(crate::domain::ActorKind::ApiKey),
        "internal_service" => Ok(crate::domain::ActorKind::InternalService),
        "system" => Ok(crate::domain::ActorKind::System),
        _ => Err(GatewayError::Internal {
            message: format!("unknown actor kind: {value}"),
        }),
    }
}

fn parse_protocol_family(value: &str) -> Result<ProtocolFamily> {
    ProtocolFamily::all()
        .iter()
        .copied()
        .find(|family| family.as_str() == value)
        .ok_or_else(|| GatewayError::Internal {
            message: format!("unknown protocol family: {value}"),
        })
}

fn parse_api_key_status(value: &str) -> Result<ApiKeyStatus> {
    match value {
        "active" => Ok(ApiKeyStatus::Active),
        "disabled" => Ok(ApiKeyStatus::Disabled),
        "expired" => Ok(ApiKeyStatus::Expired),
        "rotating" => Ok(ApiKeyStatus::Rotating),
        "deleted" => Ok(ApiKeyStatus::Deleted),
        _ => Err(GatewayError::Internal {
            message: format!("unknown api key status: {value}"),
        }),
    }
}

fn parse_route_decision_status(value: &str) -> Result<RouteDecisionStatus> {
    match value {
        "started" => Ok(RouteDecisionStatus::Started),
        "selected" => Ok(RouteDecisionStatus::Selected),
        "blocked" => Ok(RouteDecisionStatus::Blocked),
        "no_route" => Ok(RouteDecisionStatus::NoRoute),
        "completed" => Ok(RouteDecisionStatus::Completed),
        "failed" => Ok(RouteDecisionStatus::Failed),
        _ => Err(GatewayError::Internal {
            message: format!("unknown route decision status: {value}"),
        }),
    }
}

fn parse_route_attempt_status(value: &str) -> Result<RouteAttemptStatus> {
    match value {
        "started" => Ok(RouteAttemptStatus::Started),
        "completed" => Ok(RouteAttemptStatus::Completed),
        "failed" => Ok(RouteAttemptStatus::Failed),
        "client_disconnected" => Ok(RouteAttemptStatus::ClientDisconnected),
        _ => Err(GatewayError::Internal {
            message: format!("unknown route attempt status: {value}"),
        }),
    }
}

fn parse_auth_session_status(value: &str) -> Result<AuthSessionStatus> {
    match value {
        "active" => Ok(AuthSessionStatus::Active),
        "revoked" => Ok(AuthSessionStatus::Revoked),
        "expired" => Ok(AuthSessionStatus::Expired),
        _ => Err(GatewayError::Internal {
            message: format!("unknown auth session status: {value}"),
        }),
    }
}

const fn auth_session_status_as_str(status: &AuthSessionStatus) -> &'static str {
    match status {
        AuthSessionStatus::Active => "active",
        AuthSessionStatus::Revoked => "revoked",
        AuthSessionStatus::Expired => "expired",
    }
}

fn parse_directory_status(value: &str) -> Result<DirectoryStatus> {
    match value {
        "active" => Ok(DirectoryStatus::Active),
        "suspended" => Ok(DirectoryStatus::Suspended),
        "disabled" => Ok(DirectoryStatus::Disabled),
        "deleted" => Ok(DirectoryStatus::Deleted),
        _ => Err(GatewayError::Internal {
            message: format!("unknown directory status: {value}"),
        }),
    }
}

fn parse_config_snapshot_status(value: &str) -> Result<ConfigSnapshotStatus> {
    match value {
        "pending" => Ok(ConfigSnapshotStatus::Pending),
        "published" => Ok(ConfigSnapshotStatus::Published),
        "rejected" => Ok(ConfigSnapshotStatus::Rejected),
        "rolled_back" => Ok(ConfigSnapshotStatus::RolledBack),
        _ => Err(GatewayError::Internal {
            message: format!("unknown config snapshot status: {value}"),
        }),
    }
}

fn parse_membership_status(value: &str) -> Result<MembershipStatus> {
    match value {
        "active" => Ok(MembershipStatus::Active),
        "suspended" => Ok(MembershipStatus::Suspended),
        "removed" => Ok(MembershipStatus::Removed),
        _ => Err(GatewayError::Internal {
            message: format!("unknown membership status: {value}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::domain::{DirectoryStatus, UsageEventRecord};
    use crate::fixtures::bootstrap_request;
    use crate::storage::{
        ledger_bucket_record_for_event, InMemoryGatewayStore, TenancyBootstrapRepository,
        TenancyRepository,
    };
    use crate::ProtocolFamily;

    const CORE_SCHEMA: &str = include_str!("../migrations/20260625000001_core_schema.sql");
    const ROUTE_EVIDENCE_FIELDS_MIGRATION: &str =
        include_str!("../migrations/20260628000001_route_evidence_fields.sql");
    const USAGE_EVENT_TRACE_ID_MIGRATION: &str =
        include_str!("../migrations/20260628000002_usage_event_trace_id.sql");

    #[test]
    fn in_memory_bootstrap_default_project_is_idempotent() {
        let store = InMemoryGatewayStore::default();
        let request = bootstrap_request();
        let first = match store.bootstrap_default_project(request.clone(), chrono::Utc::now()) {
            Ok(seed) => seed,
            Err(error) => panic!("first bootstrap should succeed: {error}"),
        };
        let second = match store
            .bootstrap_default_project(request, chrono::Utc::now() + chrono::Duration::seconds(1))
        {
            Ok(seed) => seed,
            Err(error) => panic!("second bootstrap should be idempotent: {error}"),
        };

        assert_eq!(first.tenant.tenant_id, "ten_test");
        assert_eq!(second.tenant.created_at, first.tenant.created_at);
        assert_eq!(second.organization.tenant_id, "ten_test");
        assert_eq!(second.project.organization_id, "org_test");
        assert_eq!(second.user.default_project_id.as_deref(), Some("prj_test"));
        assert!(store.project_membership("usr_test", "prj_test").is_some());
    }

    #[test]
    fn in_memory_bootstrap_rejects_scope_conflict() {
        let store = InMemoryGatewayStore::default();
        let request = bootstrap_request();
        match store.bootstrap_default_project(request.clone(), chrono::Utc::now()) {
            Ok(_) => {}
            Err(error) => panic!("first bootstrap should succeed: {error}"),
        }
        let mut conflicting = request;
        conflicting.organization_id = "org_other".to_owned();

        let Err(error) = store.bootstrap_default_project(conflicting, chrono::Utc::now()) else {
            panic!("conflicting bootstrap should fail");
        };

        assert!(error.to_string().contains("project_seed_conflict"));
        assert!(store.organization("org_other").is_none());
    }

    #[test]
    fn in_memory_project_status_update_uses_optimistic_concurrency() {
        let store = InMemoryGatewayStore::default();
        let request = bootstrap_request();
        match store.bootstrap_default_project(request, chrono::Utc::now()) {
            Ok(_) => {}
            Err(error) => panic!("bootstrap should succeed: {error}"),
        }

        let updated = match store.update_project_status(
            "prj_test",
            1,
            DirectoryStatus::Suspended,
            chrono::Utc::now(),
        ) {
            Ok(project) => project,
            Err(error) => panic!("project status update should succeed: {error}"),
        };
        assert_eq!(updated.status, DirectoryStatus::Suspended);
        assert_eq!(updated.resource_version, 2);

        let stale =
            store.update_project_status("prj_test", 1, DirectoryStatus::Active, chrono::Utc::now());
        assert!(stale.is_err());
        assert_eq!(
            store.project("prj_test").map(|project| project.status),
            Some(DirectoryStatus::Suspended)
        );
    }

    #[test]
    fn core_schema_declares_foundation_tables() {
        for table in [
            "gateway_tenants",
            "gateway_organizations",
            "gateway_projects",
            "gateway_principals",
            "gateway_users",
            "gateway_service_accounts",
            "gateway_organization_memberships",
            "gateway_project_memberships",
            "gateway_external_identities",
            "gateway_api_keys",
            "gateway_role_bindings",
            "gateway_action_grants",
            "gateway_secret_refs",
            "gateway_provider_endpoints",
            "gateway_upstream_credentials",
            "gateway_codex_oauth_connections",
            "gateway_codex_oauth_sessions",
            "gateway_codex_oauth_refresh_status",
            "gateway_provider_grants",
            "gateway_pricing_skus",
            "gateway_model_targets",
            "gateway_model_aliases",
            "gateway_routing_groups",
            "gateway_routing_group_targets",
            "gateway_route_policies",
            "gateway_route_rules",
            "gateway_route_decisions",
            "gateway_route_attempt_events",
            "gateway_config_snapshots",
            "gateway_config_invalidation_events",
            "gateway_config_publications",
            "gateway_config_worker_reloads",
            "gateway_validation_diagnostics",
            "gateway_usage_events",
            "gateway_ledger_buckets",
            "gateway_budget_policies",
            "gateway_quota_policies",
            "gateway_rate_limit_policies",
            "gateway_audit_events",
            "gateway_authz_decision_events",
            "gateway_auth_sessions",
            "gateway_login_providers",
            "gateway_login_attempts",
            "gateway_dashboard_configs",
            "gateway_otel_export_configs",
            "gateway_redaction_policies",
            "gateway_debug_capture_policies",
            "gateway_debug_capture_records",
            "gateway_notification_sinks",
            "gateway_notification_subscriptions",
            "gateway_notification_outbox_events",
            "gateway_notification_delivery_attempts",
            "gateway_export_jobs",
            "gateway_export_manifests",
            "gateway_invitations",
            "gateway_idempotency_keys",
        ] {
            assert!(CORE_SCHEMA.contains(table), "missing table {table}");
        }
    }

    #[test]
    fn core_schema_indexes_security_and_audit_paths() {
        assert!(CORE_SCHEMA.contains("gateway_api_keys_prefix_idx"));
        assert!(CORE_SCHEMA.contains("gateway_model_aliases_scope_alias_idx"));
        assert!(CORE_SCHEMA.contains("gateway_project_members_principal_scope_idx"));
        assert!(CORE_SCHEMA.contains("gateway_usage_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_ledger_buckets_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_ledger_buckets_member_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_route_decisions_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_route_attempts_decision_idx"));
        assert!(CORE_SCHEMA.contains("gateway_config_invalidations_tenant_version_idx"));
        assert!(CORE_SCHEMA.contains("gateway_config_worker_reloads_tenant_status_idx"));
        assert!(CORE_SCHEMA.contains("gateway_validation_diagnostics_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_audit_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_authz_decision_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_budget_policies_scope_idx"));
        assert!(CORE_SCHEMA.contains("gateway_quota_policies_scope_idx"));
        assert!(CORE_SCHEMA.contains("gateway_quota_policies_active_shape_idx"));
        assert!(CORE_SCHEMA.contains("gateway_rate_limit_policies_scope_idx"));
        assert!(CORE_SCHEMA.contains("gateway_notification_sinks_scope_idx"));
        assert!(CORE_SCHEMA.contains("gateway_notification_subscriptions_sink_idx"));
        assert!(CORE_SCHEMA.contains("gateway_notification_outbox_status_idx"));
        assert!(CORE_SCHEMA.contains("gateway_notification_delivery_attempts_event_idx"));
        assert!(CORE_SCHEMA.contains("gateway_export_jobs_scope_status_idx"));
        assert!(CORE_SCHEMA.contains("gateway_debug_capture_records_scope_time_idx"));
        assert!(CORE_SCHEMA.contains("gateway_otel_export_configs_scope_idx"));
        assert!(CORE_SCHEMA.contains("UNIQUE (tenant_id, request_id)"));
        assert!(CORE_SCHEMA
            .contains("upstream_credential_id TEXT REFERENCES gateway_upstream_credentials"));
        assert!(
            CORE_SCHEMA.contains("provider_endpoint_id, upstream_credential_id, route_policy_id")
        );
        assert!(CORE_SCHEMA.contains("bucket_kind IN ('event', 'minute', 'hour', 'day', 'month')"));
        assert!(CORE_SCHEMA.contains("UNIQUE (tenant_id, dedupe_key)"));
        assert!(CORE_SCHEMA.contains("last_used_at TIMESTAMPTZ"));
        assert!(CORE_SCHEMA.contains("last_used_request_id TEXT"));
        assert!(CORE_SCHEMA.contains("config_invalidation_id LIKE 'cfginv_%'"));
        assert!(CORE_SCHEMA.contains("reload_source IN ('invalidation', 'polling')"));
        assert!(CORE_SCHEMA.contains("last_known_good_snapshot_id TEXT NOT NULL"));
        assert!(CORE_SCHEMA.contains("validation_id LIKE 'vdiag_%'"));
        assert!(CORE_SCHEMA.contains("'dead_lettered'"));
    }

    #[test]
    fn route_evidence_migration_adds_runtime_evidence_fields() {
        for token in [
            "ADD COLUMN IF NOT EXISTS trace_id TEXT NOT NULL",
            "ADD COLUMN IF NOT EXISTS sticky_hit BOOLEAN NOT NULL DEFAULT FALSE",
            "ADD COLUMN IF NOT EXISTS sticky_miss_reason TEXT",
            "gateway_route_decisions_trace_idx",
        ] {
            assert!(
                ROUTE_EVIDENCE_FIELDS_MIGRATION.contains(token),
                "missing route evidence migration token {token}"
            );
        }
    }

    #[test]
    fn usage_event_trace_migration_preserves_runtime_trace_evidence() {
        for token in [
            "ADD COLUMN IF NOT EXISTS trace_id TEXT",
            "ALTER COLUMN trace_id SET NOT NULL",
            "gateway_usage_trace_time_idx",
        ] {
            assert!(
                USAGE_EVENT_TRACE_ID_MIGRATION.contains(token),
                "missing usage trace migration token {token}"
            );
        }
    }

    #[test]
    fn usage_ledger_bucket_ids_are_stable_for_nullable_dimensions() {
        let record = usage_event_for_ledger_test();
        let left = match ledger_bucket_record_for_event(&record, "minute") {
            Ok(bucket) => bucket,
            Err(error) => panic!("left bucket should fold: {error}"),
        };
        let right = match ledger_bucket_record_for_event(&record, "minute") {
            Ok(bucket) => bucket,
            Err(error) => panic!("right bucket should fold: {error}"),
        };

        assert_eq!(left.ledger_bucket_id, right.ledger_bucket_id);
        assert!(left.ledger_bucket_id.starts_with("lb_"));
        assert_eq!(left.request_count, 1);
        assert_eq!(left.input_tokens, 3);
        assert_eq!(left.output_tokens, 5);
    }

    #[test]
    fn core_schema_stores_config_snapshot_documents_for_runtime_replay() {
        for token in [
            "snapshot_document JSONB NOT NULL DEFAULT '{}'::jsonb",
            "published_at TIMESTAMPTZ",
            "created_by TEXT NOT NULL",
            "UNIQUE (tenant_id, version)",
        ] {
            assert!(
                CORE_SCHEMA.contains(token),
                "missing config snapshot schema token {token}"
            );
        }
    }

    fn usage_event_for_ledger_test() -> UsageEventRecord {
        UsageEventRecord {
            usage_event_id: "use_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: Some("org_test".to_owned()),
            project_id: Some("prj_test".to_owned()),
            principal_id: Some("usr_test".to_owned()),
            project_member_id: None,
            service_account_id: None,
            api_key_id: Some("ak_test".to_owned()),
            request_id: "req_test".to_owned(),
            trace_id: "tr_test".to_owned(),
            protocol_family: ProtocolFamily::OpenAiResponses,
            route_decision_id: Some("rd_test".to_owned()),
            model_alias_id: Some("ma_test".to_owned()),
            model_target_id: Some("mt_test".to_owned()),
            route_policy_id: Some("rp_test".to_owned()),
            routing_group_id: Some("rg_test".to_owned()),
            provider_endpoint_id: Some("pe_test".to_owned()),
            upstream_credential_id: None,
            usage_confidence: "exact".to_owned(),
            latency_ms: Some(42),
            time_to_first_token_ms: Some(11),
            status: "success".to_owned(),
            usage_payload: json!({
                "input_tokens": 3,
                "output_tokens": 5
            }),
            cost_payload: json!({
                "currency": "USD",
                "total_cost": 7,
                "pricing_version": "test"
            }),
            occurred_at: chrono::DateTime::from_timestamp_nanos(1_800_000_123_000_000_000),
        }
    }

    #[test]
    fn core_schema_enforces_scope_consistency() {
        for constraint in [
            "gateway_projects_tenant_org_fk",
            "gateway_org_members_tenant_principal_fk",
            "gateway_project_members_tenant_project_fk",
            "gateway_project_members_tenant_principal_fk",
            "gateway_api_keys_tenant_owner_fk",
            "gateway_role_bindings_tenant_project_fk",
            "gateway_action_grants_tenant_project_fk",
        ] {
            assert!(
                CORE_SCHEMA.contains(constraint),
                "missing scope constraint {constraint}"
            );
        }
    }

    #[test]
    fn core_schema_declares_optimistic_concurrency_columns() {
        assert!(CORE_SCHEMA.matches("resource_version BIGINT").count() >= 30);
        assert!(CORE_SCHEMA.matches("schema_version INTEGER").count() >= 30);
    }

    #[test]
    fn core_schema_declares_policy_failure_modes() {
        for mode in ["fail_closed", "fail_limited", "fail_open"] {
            assert!(CORE_SCHEMA.contains(mode), "missing failure mode {mode}");
        }
        for quota_column in [
            "counter_kind TEXT NOT NULL",
            "limit_value BIGINT NOT NULL",
            "increment_source TEXT NOT NULL",
            "loss_behavior TEXT NOT NULL",
            "'protocol_family'",
            "'request_body_bytes'",
        ] {
            assert!(
                CORE_SCHEMA.contains(quota_column),
                "missing quota policy schema token {quota_column}"
            );
        }
        for otel_constraint in [
            "endpoint_url LIKE 'https://%'",
            "jsonb_typeof(header_refs) = 'array'",
            "jsonb_typeof(signal_config->'enabled_signals') = 'array'",
            "(signal_config->'enabled_signals') ? 'metrics'",
        ] {
            assert!(
                CORE_SCHEMA.contains(otel_constraint),
                "missing otel export schema token {otel_constraint}"
            );
        }
        for status in [
            "dead_lettered",
            "retryable_failed",
            "permanent_failed",
            "expired",
        ] {
            assert!(
                CORE_SCHEMA.contains(status),
                "missing operational status {status}"
            );
        }
        for notification_token in [
            "'object_export'",
            "'pubsub'",
            "'stdout'",
            "event_family TEXT NOT NULL",
            "'provider_health'",
        ] {
            assert!(
                CORE_SCHEMA.contains(notification_token),
                "missing notification schema token {notification_token}"
            );
        }
    }
}
