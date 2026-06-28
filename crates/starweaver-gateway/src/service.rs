//! Gateway HTTP service skeleton.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{header, Extensions, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use chrono::Datelike;
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpStream;
use url::Url;

use crate::action::{
    authorize_item_list, ActionGrant, AuthorizableItem, AuthorizationEngine, BuiltInRole,
    FoundationAuthorizationEngine, GatewayAction,
};
use crate::auth::{
    create_auth_session, resolve_user_session_actor, verify_api_key, verify_session_token,
    CreateAuthSessionRequest, ResolveUserSessionRequest,
};
use crate::catalog::{GatewayCatalogSnapshot, RoutePlanOutcome, RoutePlanRequest};
use crate::config::{
    publish_config_snapshot as publish_config_snapshot_document,
    rollback_config_snapshot as rollback_config_snapshot_document,
    validate_config_snapshot_payload, PublishConfigSnapshotRequest, ResourceVersion,
};
use crate::domain::{
    new_prefixed_id, ActorKind, ActorScope, ApiKeyRecord, AuditEventRecord, AuthSessionRecord,
    AuthenticatedActor, BudgetPolicyRecord, ConfigPublicationPointerRecord,
    ConfigWorkerReloadRecord, DirectoryStatus, EmergencyOperationRecord, ExportJobRecord,
    ExportManifestRecord, ExternalIdentityRecord, LedgerBucketRecord, LoginProviderRecord,
    MembershipStatus, ModelAliasRecord, ModelTargetRecord, NotificationDeliveryAttemptRecord,
    NotificationSinkRecord, NotificationSubscriptionRecord, OrganizationInvitationRecord,
    OrganizationMembershipRecord, OrganizationRecord, OtelExportConfigRecord,
    OtelExporterHealthRecord, OtelHeaderRef, OtelResourceAttribute, PricingSkuRecord,
    ProjectMembershipRecord, ProjectRecord, ProviderEndpointRecord, ProviderGrantRecord,
    QuotaPolicyRecord, ResourceStatus, RoutePolicyRecord, RoutingGroupRecord,
    RoutingGroupTargetRecord, SecretRefRecord, SecretRefStatus, ServiceAccountRecord,
    UpstreamCredentialRecord, UpstreamCredentialStatus, UsageEventRecord,
    ValidationDiagnosticRecord,
};
use crate::error::{GatewayError, Result};
use crate::hot_state::{EndpointDrainRecord, EndpointHealthState, RouteHotState};
use crate::migrations;
use crate::policy::CedarAuthorizationEngine;
use crate::replay::{foundation_route_replay_cases, GatewayReplayCase};
use crate::route::{authorize_route_with_evidence, foundation_routes, RouteMetadata};
use crate::routing::{
    RouteAttemptRecord, RouteAttemptStatus, RouteDecisionRecord, RouteDecisionRequest,
    RouteDecisionStatus, RouteEvidenceSink, SelectedRouteEvidence,
};
use crate::runtime::{
    authorize_fake_provider_replay_target, fake_provider_response_for_authorization,
    FakeProviderReplayEvidence, FakeProviderReplayTarget, RuntimeIngressResponse,
};
use crate::storage::{
    AuthSessionRepository, BootstrapDefaultProjectRequest, CatalogAdminRepository,
    CompleteExportJobRequest, ConfigPublicationRepository, ConfigSnapshotRepository,
    ConfigSnapshotStore, CreateBudgetPolicyRequest, CreateEmergencyOperationRequest,
    CreateExportJobRequest, CreateLoginProviderRequest, CreateModelAliasRequest,
    CreateModelTargetRequest, CreateNotificationDeliveryAttemptRequest,
    CreateNotificationOutboxEventRequest, CreateNotificationSinkRequest,
    CreateNotificationSubscriptionRequest, CreateOrganizationInvitationRequest,
    CreateOtelExportConfigRequest, CreatePricingSkuRequest, CreateProjectMembershipRequest,
    CreateProviderEndpointRequest, CreateProviderGrantRequest, CreateQuotaPolicyRequest,
    CreateRoutePolicyRequest, CreateRoutingGroupRequest, CreateRoutingGroupTargetRequest,
    CreateSecretRefRequest, CreateServiceAccountRequest, CreateUpstreamCredentialRequest,
    EmergencyOperationRepository, ExportRepository, ExternalIdentityRepository, IdempotencyRecord,
    InMemoryGatewayStore, NotificationOutboxRepository, NullablePatch,
    OrganizationInvitationRepository, ProviderAdminRepository, RecordOtelExporterHealthRequest,
    RuntimePolicyRepository, SecretRefAdminRepository, ServiceAccountAdminRepository,
    TenancyBootstrapRepository, TenancyRepository, UpdateModelAliasRequest,
    UpdateNotificationSinkRequest, UpdateOtelExportConfigRequest, UsageAccountingRepository,
    ValidationDiagnosticRepository,
};
use crate::{ProtocolFamily, SERVICE_NAME};

const REQUEST_ID_HEADER: &str = "x-gateway-request-id";
const PROJECT_ID_HEADER: &str = "x-gateway-project-id";
const PERCENT_HEX: &[u8; 16] = b"0123456789ABCDEF";
const ADMIN_CONFIG_SNAPSHOT_GET_PATH: &str =
    concat!("/admin/v1/config/snapshots/", "{snapshot_id}");
const ADMIN_CONFIG_VALIDATION_DIAGNOSTICS_PATH: &str = "/admin/v1/config/validation-diagnostics";
const ADMIN_AUDIT_EVENT_LIST_PATH: &str = "/admin/v1/audit/events";
const ADMIN_EXPORT_JOB_LIST_PATH: &str = "/admin/v1/exports/jobs";
const ADMIN_EXPORT_JOB_GET_PATH: &str = concat!("/admin/v1/exports/jobs/", "{export_job_id}");
const ADMIN_EXPORT_JOB_MANIFEST_PATH: &str =
    concat!("/admin/v1/exports/jobs/", "{export_job_id}", "/manifest");
const ADMIN_EMERGENCY_OPERATION_LIST_PATH: &str = "/admin/v1/emergency/operations";
const ADMIN_EMERGENCY_OPERATION_GET_PATH: &str = concat!(
    "/admin/v1/emergency/operations/",
    "{emergency_operation_id}"
);
const ADMIN_EMERGENCY_DISABLE_UPSTREAM_CREDENTIAL_PATH: &str = concat!(
    "/admin/v1/emergency/upstream-credentials/",
    "{upstream_credential_id}",
    "/disable"
);
const ADMIN_EMERGENCY_DISABLE_PROVIDER_ENDPOINT_PATH: &str = concat!(
    "/admin/v1/emergency/provider-endpoints/",
    "{provider_endpoint_id}",
    "/disable"
);
const ADMIN_EMERGENCY_DRAIN_ROUTING_GROUP_PATH: &str = concat!(
    "/admin/v1/emergency/routing-groups/",
    "{routing_group_id}",
    "/drain"
);
const ADMIN_EMERGENCY_FREEZE_CONFIG_PATH: &str = "/admin/v1/emergency/config/freeze";
const ADMIN_PROJECT_GET_PATH: &str = concat!("/admin/v1/projects/", "{project_id}");
const ADMIN_ORGANIZATION_GET_PATH: &str = concat!("/admin/v1/organizations/", "{organization_id}");
const ADMIN_USER_GET_PATH: &str = concat!("/admin/v1/users/", "{user_id}");
const ADMIN_USER_SESSION_LIST_PATH: &str = concat!("/admin/v1/users/", "{user_id}", "/sessions");
const ADMIN_USER_SESSION_REVOKE_PATH: &str = concat!(
    "/admin/v1/users/",
    "{user_id}",
    "/sessions/",
    "{auth_session_id}",
    "/revoke"
);
const ADMIN_USER_EXTERNAL_IDENTITY_LIST_PATH: &str =
    concat!("/admin/v1/users/", "{user_id}", "/external-identities");
const ADMIN_USER_EXTERNAL_IDENTITY_GET_PATH: &str = concat!(
    "/admin/v1/users/",
    "{user_id}",
    "/external-identities/",
    "{external_identity_id}"
);
const ADMIN_USER_EXTERNAL_IDENTITY_UNLINK_PATH: &str = concat!(
    "/admin/v1/users/",
    "{user_id}",
    "/external-identities/",
    "{external_identity_id}",
    "/unlink"
);
const ADMIN_ORGANIZATION_MEMBER_LIST_PATH: &str =
    concat!("/admin/v1/organizations/", "{organization_id}", "/members");
const ADMIN_ORGANIZATION_MEMBER_GET_PATH: &str = concat!(
    "/admin/v1/organizations/",
    "{organization_id}",
    "/members/",
    "{organization_member_id}"
);
const ADMIN_PROJECT_MEMBER_LIST_PATH: &str =
    concat!("/admin/v1/projects/", "{project_id}", "/members");
const ADMIN_PROJECT_MEMBER_GET_PATH: &str = concat!(
    "/admin/v1/projects/",
    "{project_id}",
    "/members/",
    "{project_member_id}"
);
const ADMIN_PROVIDER_ENDPOINT_GET_PATH: &str =
    concat!("/admin/v1/provider-endpoints/", "{provider_endpoint_id}");
const ADMIN_UPSTREAM_CREDENTIAL_GET_PATH: &str = concat!(
    "/admin/v1/upstream-credentials/",
    "{upstream_credential_id}"
);
const ADMIN_SECRET_REF_GET_PATH: &str = concat!("/admin/v1/secret-refs/", "{secret_ref_id}");
const ADMIN_SECRET_REF_LOCATOR_PATH: &str =
    concat!("/admin/v1/secret-refs/", "{secret_ref_id}", "/locator");
const ADMIN_MODEL_TARGET_GET_PATH: &str = concat!("/admin/v1/model-targets/", "{model_target_id}");
const ADMIN_MODEL_ALIAS_GET_PATH: &str = concat!("/admin/v1/model-aliases/", "{model_alias_id}");
const ADMIN_SERVICE_ACCOUNT_GET_PATH: &str =
    concat!("/admin/v1/service-accounts/", "{service_account_id}");
const ADMIN_PRICING_SKU_GET_PATH: &str = concat!("/admin/v1/pricing-skus/", "{pricing_sku_id}");
const ADMIN_BUDGET_POLICY_GET_PATH: &str =
    concat!("/admin/v1/budget-policies/", "{budget_policy_id}");
const ADMIN_QUOTA_POLICY_GET_PATH: &str = concat!("/admin/v1/quota-policies/", "{quota_policy_id}");
const ADMIN_OTEL_EXPORT_CONFIG_GET_PATH: &str = concat!(
    "/admin/v1/observability/otel-export/configs/",
    "{otel_export_config_id}"
);
const ADMIN_OTEL_EXPORT_CONFIG_VALIDATE_PATH: &str = concat!(
    "/admin/v1/observability/otel-export/configs/",
    "{otel_export_config_id}",
    "/validate"
);
const ADMIN_OTEL_EXPORT_CONFIG_DISABLE_PATH: &str = concat!(
    "/admin/v1/observability/otel-export/configs/",
    "{otel_export_config_id}",
    "/disable"
);
const ADMIN_NOTIFICATION_SINK_GET_PATH: &str =
    concat!("/admin/v1/notification/sinks/", "{notification_sink_id}");
const ADMIN_NOTIFICATION_SUBSCRIPTION_LIST_PATH: &str = concat!(
    "/admin/v1/notification/sinks/",
    "{notification_sink_id}",
    "/subscriptions"
);
const ADMIN_NOTIFICATION_SUBSCRIPTION_VALIDATE_PATH: &str = concat!(
    "/admin/v1/notification/sinks/",
    "{notification_sink_id}",
    "/subscriptions:validate"
);
const ADMIN_NOTIFICATION_SUBSCRIPTION_GET_PATH: &str = concat!(
    "/admin/v1/notification/sinks/",
    "{notification_sink_id}",
    "/subscriptions/",
    "{notification_subscription_id}"
);
const ADMIN_LOGIN_PROVIDER_GET_PATH: &str =
    concat!("/admin/v1/identity-providers/", "{login_provider_id}");
const ADMIN_ORGANIZATION_INVITATION_LIST_PATH: &str = concat!(
    "/admin/v1/organizations/",
    "{organization_id}",
    "/invitations"
);
const ADMIN_ORGANIZATION_INVITATION_GET_PATH: &str = concat!(
    "/admin/v1/organizations/",
    "{organization_id}",
    "/invitations/",
    "{invitation_id}"
);
const ADMIN_ORGANIZATION_INVITATION_REVOKE_PATH: &str = concat!(
    "/admin/v1/organizations/",
    "{organization_id}",
    "/invitations/",
    "{invitation_id}",
    "/revoke"
);
const AUTH_INVITATION_PREVIEW_PATH: &str = concat!("/auth/v1/invitations/", "{token}", "/preview");
const AUTH_INVITATION_ACCEPT_PATH: &str = concat!("/auth/v1/invitations/", "{token}", "/accept");
const AUTH_LOGIN_PROVIDER_GET_PATH: &str = concat!("/auth/v1/providers/", "{login_provider_id}");
const AUTH_LOGIN_PROVIDER_START_PATH: &str =
    concat!("/auth/v1/providers/", "{login_provider_id}", "/login");
const ADMIN_DASHBOARD_ORGANIZATION_PATH: &str =
    concat!("/admin/v1/dashboards/organizations/", "{organization_id}");
const ADMIN_DASHBOARD_PROJECT_PATH: &str =
    concat!("/admin/v1/dashboards/projects/", "{project_id}");
const ADMIN_DASHBOARD_PROJECT_MEMBER_PATH: &str = concat!(
    "/admin/v1/dashboards/project-members/",
    "{project_member_id}"
);
const ADMIN_DASHBOARD_API_KEY_PATH: &str =
    concat!("/admin/v1/dashboards/api-keys/", "{api_key_id}");
const ADMIN_DASHBOARD_SERVICE_ACCOUNT_PATH: &str = concat!(
    "/admin/v1/dashboards/service-accounts/",
    "{service_account_id}"
);
const ADMIN_MODEL_ALIAS_DASHBOARD_PATH: &str = concat!(
    "/admin/v1/models/aliases/",
    "{model_alias_id}",
    "/dashboard"
);
const ADMIN_MODEL_TARGET_DASHBOARD_PATH: &str = concat!(
    "/admin/v1/models/targets/",
    "{model_target_id}",
    "/dashboard"
);
const ADMIN_PROVIDER_ENDPOINT_OBSERVABILITY_USAGE_PATH: &str = concat!(
    "/admin/v1/provider-endpoints/",
    "{provider_endpoint_id}",
    "/observability/usage"
);
const ADMIN_USAGE_SUMMARY_PATH: &str = "/admin/v1/usage/summary";
const ADMIN_USAGE_TIMESERIES_PATH: &str = "/admin/v1/usage/timeseries";
const ADMIN_USAGE_EVENTS_PATH: &str = "/admin/v1/usage/events";
const ADMIN_USAGE_BREAKDOWN_BY_PROJECT_PATH: &str = "/admin/v1/usage/breakdown/by-project";
const ADMIN_USAGE_BREAKDOWN_BY_PROJECT_MEMBER_PATH: &str =
    "/admin/v1/usage/breakdown/by-project-member";
const ADMIN_USAGE_BREAKDOWN_BY_MODEL_PATH: &str = "/admin/v1/usage/breakdown/by-model";
const ADMIN_USAGE_BREAKDOWN_BY_PROVIDER_ENDPOINT_PATH: &str =
    "/admin/v1/usage/breakdown/by-provider-endpoint";
const ADMIN_ROUTE_POLICY_GET_PATH: &str = concat!("/admin/v1/route-policies/", "{route_policy_id}");
const ADMIN_PROVIDER_GRANT_GET_PATH: &str =
    concat!("/admin/v1/provider-grants/", "{provider_grant_id}");
const ADMIN_ROUTING_GROUP_GET_PATH: &str =
    concat!("/admin/v1/routing-groups/", "{routing_group_id}");
const ADMIN_ROUTING_GROUP_TARGET_LIST_PATH: &str = concat!(
    "/admin/v1/routing-groups/",
    "{routing_group_id}",
    "/targets"
);
const ADMIN_ROUTING_GROUP_TARGET_VALIDATE_PATH: &str = concat!(
    "/admin/v1/routing-groups/",
    "{routing_group_id}",
    "/targets:validate"
);
const ADMIN_ROUTING_GROUP_TARGET_GET_PATH: &str = concat!(
    "/admin/v1/routing-groups/",
    "{routing_group_id}",
    "/targets/",
    "{routing_group_target_id}"
);
const SESSION_TOKEN_PREFIX: &str = "sws_";
const IDEMPOTENCY_TTL_HOURS: i64 = 24;
const SINGLE_USER_PROVIDER_ID: &str = "local_single_user";
const SINGLE_USER_TENANT_ID: &str = "ten_single_user";
const SINGLE_USER_ORGANIZATION_ID: &str = "org_single_user";
const SINGLE_USER_PROJECT_ID: &str = "prj_single_user";
const SINGLE_USER_ID: &str = "usr_single_user";
const SINGLE_USER_ORGANIZATION_MEMBER_ID: &str = "om_single_user";
const SINGLE_USER_PROJECT_MEMBER_ID: &str = "pm_single_user";
const SINGLE_USER_SESSION_TTL_SECONDS: i64 = 12 * 60 * 60;
const NOTIFICATION_DELIVERY_MAX_ATTEMPTS: i32 = 3;
const NOTIFICATION_DELIVERY_RETRY_DELAY_SECONDS: i64 = 60;
type HmacSha256 = Hmac<Sha256>;

/// Gateway service configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayConfig {
    /// Address used by the binary listener.
    pub listen_addr: String,
    /// Deployment profile.
    pub environment: String,
    /// Optional `PostgreSQL` connection string.
    pub database_url: Option<String>,
    /// Optional Redis-compatible hot-state connection string.
    pub redis_url: Option<String>,
    /// Secret backend profile name.
    pub secret_backend_profile: String,
    /// Telemetry profile name.
    pub telemetry_profile: String,
    /// Maximum accepted request body bytes.
    pub max_body_bytes: usize,
    /// Dependency probe mode used by `/readyz`.
    pub dependency_probe_mode: DependencyProbeMode,
    /// Per-dependency readiness probe timeout in milliseconds.
    pub readiness_probe_timeout_ms: u64,
    /// Whether readiness requires a published config snapshot.
    pub require_published_snapshot: bool,
    /// Optional local single-user password login configuration.
    pub single_user_auth: Option<SingleUserAuthConfig>,
}

/// Dependency probing behavior for `/readyz`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DependencyProbeMode {
    /// Report configured dependency state without opening network connections.
    Configured,
    /// Open dependency connections and validate lightweight health state.
    Live,
}

impl DependencyProbeMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Live => "live",
        }
    }
}

/// Local single-user password login configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct SingleUserAuthConfig {
    /// Login username.
    pub username: String,
    /// Login password read from environment.
    pub password: String,
    /// Default tenant id.
    pub tenant_id: String,
    /// Default tenant display name.
    pub tenant_display_name: String,
    /// Default organization id.
    pub organization_id: String,
    /// Default organization display name.
    pub organization_display_name: String,
    /// Default project id.
    pub project_id: String,
    /// Default project display name.
    pub project_display_name: String,
    /// Default user id.
    pub user_id: String,
    /// Default user display name.
    pub user_display_name: String,
    /// Default user primary email.
    pub user_primary_email: Option<String>,
    /// Session lifetime in seconds.
    pub session_ttl_seconds: i64,
}

impl std::fmt::Debug for SingleUserAuthConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SingleUserAuthConfig")
            .field("username", &self.username)
            .field("password", &"***")
            .field("tenant_id", &self.tenant_id)
            .field("tenant_display_name", &self.tenant_display_name)
            .field("organization_id", &self.organization_id)
            .field("organization_display_name", &self.organization_display_name)
            .field("project_id", &self.project_id)
            .field("project_display_name", &self.project_display_name)
            .field("user_id", &self.user_id)
            .field("user_display_name", &self.user_display_name)
            .field("user_primary_email", &self.user_primary_email)
            .field("session_ttl_seconds", &self.session_ttl_seconds)
            .finish()
    }
}

impl SingleUserAuthConfig {
    /// Builds a single-user config from required credentials and safe defaults.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        Self {
            user_display_name: username.clone(),
            username,
            password: password.into(),
            tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
            tenant_display_name: "Single User Tenant".to_owned(),
            organization_id: SINGLE_USER_ORGANIZATION_ID.to_owned(),
            organization_display_name: "Single User Organization".to_owned(),
            project_id: SINGLE_USER_PROJECT_ID.to_owned(),
            project_display_name: "Default Project".to_owned(),
            user_id: SINGLE_USER_ID.to_owned(),
            user_primary_email: None,
            session_ttl_seconds: SINGLE_USER_SESSION_TTL_SECONDS,
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8080".to_owned(),
            environment: "local".to_owned(),
            database_url: None,
            redis_url: None,
            secret_backend_profile: "memory".to_owned(),
            telemetry_profile: "disabled".to_owned(),
            max_body_bytes: 1024 * 1024,
            dependency_probe_mode: DependencyProbeMode::Configured,
            readiness_probe_timeout_ms: 750,
            require_published_snapshot: false,
            single_user_auth: None,
        }
    }
}

impl GatewayConfig {
    /// Reads configuration from environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_LISTEN_ADDR") {
            config.listen_addr = value;
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_ENV") {
            config.environment = value;
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_DATABASE_URL") {
            config.database_url = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_REDIS_URL") {
            config.redis_url = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_SECRET_BACKEND") {
            if let Some(value) = non_empty_env(&value) {
                config.secret_backend_profile = value;
            }
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_TELEMETRY") {
            if let Some(value) = non_empty_env(&value) {
                config.telemetry_profile = value;
            }
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_MAX_BODY_BYTES") {
            if let Ok(parsed) = value.parse::<usize>() {
                config.max_body_bytes = parsed;
            }
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_REQUIRE_SNAPSHOT") {
            config.require_published_snapshot = matches!(value.as_str(), "1" | "true" | "yes");
        }
        config.dependency_probe_mode = default_dependency_probe_mode(&config);
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_DEPENDENCY_PROBE_MODE") {
            if let Some(mode) = parse_dependency_probe_mode(&value) {
                config.dependency_probe_mode = mode;
            }
        }
        if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_READINESS_PROBE_TIMEOUT_MS") {
            if let Ok(parsed) = value.parse::<u64>() {
                if (50..=5_000).contains(&parsed) {
                    config.readiness_probe_timeout_ms = parsed;
                }
            }
        }
        config.single_user_auth = single_user_auth_from_env();
        config
    }
}

fn validate_gateway_config(config: &GatewayConfig) -> Result<()> {
    let diagnostics = production_profile_diagnostics(config);
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: format!(
                "production profile is unsafe: {}",
                diagnostics
                    .iter()
                    .map(|diagnostic| diagnostic.code)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct StartupDiagnostic {
    code: &'static str,
    message: &'static str,
}

fn production_profile_diagnostics(config: &GatewayConfig) -> Vec<StartupDiagnostic> {
    if !is_production_environment(&config.environment) {
        return Vec::new();
    }
    let mut diagnostics = Vec::new();
    if config.database_url.is_none() {
        diagnostics.push(StartupDiagnostic {
            code: "database_url_required",
            message: "production requires STARWEAVER_GATEWAY_DATABASE_URL",
        });
    }
    if config.redis_url.is_none() {
        diagnostics.push(StartupDiagnostic {
            code: "redis_url_required",
            message: "production requires STARWEAVER_GATEWAY_REDIS_URL",
        });
    }
    if config.secret_backend_profile == "memory" {
        diagnostics.push(StartupDiagnostic {
            code: "durable_secret_backend_required",
            message: "production must not use the in-memory secret backend",
        });
    }
    if config.telemetry_profile == "disabled" {
        diagnostics.push(StartupDiagnostic {
            code: "telemetry_required",
            message: "production requires telemetry to be enabled",
        });
    }
    if !config.require_published_snapshot {
        diagnostics.push(StartupDiagnostic {
            code: "published_snapshot_required",
            message: "production must require a published config snapshot",
        });
    }
    if config.dependency_probe_mode != DependencyProbeMode::Live {
        diagnostics.push(StartupDiagnostic {
            code: "live_dependency_probe_required",
            message: "production requires live dependency readiness probes",
        });
    }
    if config.max_body_bytes == 0 || config.max_body_bytes > 16 * 1024 * 1024 {
        diagnostics.push(StartupDiagnostic {
            code: "body_limit_invalid",
            message: "production requires a positive request body limit no larger than 16 MiB",
        });
    }
    diagnostics
}

fn is_production_environment(environment: &str) -> bool {
    matches!(environment, "prod" | "production")
}

fn default_dependency_probe_mode(config: &GatewayConfig) -> DependencyProbeMode {
    if is_production_environment(&config.environment)
        || config.database_url.is_some()
        || config.redis_url.is_some()
    {
        DependencyProbeMode::Live
    } else {
        DependencyProbeMode::Configured
    }
}

fn parse_dependency_probe_mode(value: &str) -> Option<DependencyProbeMode> {
    match value.trim() {
        "configured" | "config" => Some(DependencyProbeMode::Configured),
        "live" => Some(DependencyProbeMode::Live),
        _ => None,
    }
}

fn non_empty_env(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn single_user_auth_from_env() -> Option<SingleUserAuthConfig> {
    let username = std::env::var("STARWEAVER_GATEWAY_SINGLE_USER_USERNAME")
        .ok()
        .and_then(|value| non_empty_env(&value));
    let password = std::env::var("STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD")
        .ok()
        .and_then(|value| non_empty_env(&value));
    let (Some(username), Some(password)) = (username, password) else {
        return None;
    };
    let mut config = SingleUserAuthConfig::new(username, password);
    if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_SINGLE_USER_EMAIL") {
        config.user_primary_email = non_empty_env(&value);
    }
    if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_SINGLE_USER_DISPLAY_NAME") {
        if let Some(value) = non_empty_env(&value) {
            config.user_display_name = value;
        }
    }
    if let Ok(value) = std::env::var("STARWEAVER_GATEWAY_SINGLE_USER_SESSION_TTL_SECONDS") {
        if let Ok(parsed) = value.parse::<i64>() {
            if (300..=86_400).contains(&parsed) {
                config.session_ttl_seconds = parsed;
            }
        }
    }
    Some(config)
}

/// Gateway app state.
#[derive(Clone, Debug)]
pub struct AppState {
    config: GatewayConfig,
    store: InMemoryGatewayStore,
}

impl AppState {
    /// Creates app state from config and in-memory foundation store.
    #[must_use]
    pub const fn new(config: GatewayConfig, store: InMemoryGatewayStore) -> Self {
        Self { config, store }
    }

    /// Returns the service configuration.
    #[must_use]
    pub const fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Returns the foundation store.
    #[must_use]
    pub const fn store(&self) -> &InMemoryGatewayStore {
        &self.store
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new(GatewayConfig::default(), InMemoryGatewayStore::default())
    }
}

/// Builds the gateway router.
pub fn router(state: AppState) -> Router {
    let max_body_bytes = state.config.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/version", get(version))
        .merge(model_routes(&state))
        .merge(auth_routes())
        .merge(admin_routes(&state))
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(middleware::from_fn(request_id_middleware))
        .with_state(state)
}

fn model_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/v1/responses", post(model_ingress))
        .route("/v1/chat/completions", post(model_ingress))
        .route("/v1/messages", post(model_ingress))
        .route(
            "/v1beta/models/gemini-pro:generateContent",
            post(model_ingress),
        )
        .route(
            "/model/anthropic.claude-3-sonnet/converse",
            post(model_ingress),
        )
        .route("/native/custom_native/invoke", post(model_ingress))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_context_middleware,
        ))
}

fn admin_routes(state: &AppState) -> Router<AppState> {
    Router::new()
        .route("/admin/v1/config/snapshots", get(list_config_snapshots))
        .route(ADMIN_CONFIG_SNAPSHOT_GET_PATH, get(get_config_snapshot))
        .route(
            "/admin/v1/config/snapshots:validate",
            post(validate_config_snapshot),
        )
        .route(
            "/admin/v1/config/snapshots:publish",
            post(publish_config_snapshot),
        )
        .route(
            "/admin/v1/config/snapshots:rollback",
            post(rollback_config_snapshot),
        )
        .route(
            ADMIN_CONFIG_VALIDATION_DIAGNOSTICS_PATH,
            get(list_validation_diagnostics),
        )
        .route(ADMIN_AUDIT_EVENT_LIST_PATH, get(list_audit_events))
        .merge(dashboard_admin_routes())
        .merge(user_admin_routes())
        .merge(tenancy_admin_routes())
        .route(
            "/admin/v1/provider-endpoints",
            get(list_provider_endpoints).post(create_provider_endpoint),
        )
        .route(
            "/admin/v1/provider-endpoints:validate",
            post(validate_provider_endpoint),
        )
        .route(
            ADMIN_PROVIDER_ENDPOINT_GET_PATH,
            get(get_provider_endpoint).patch(update_provider_endpoint),
        )
        .route(
            "/admin/v1/upstream-credentials",
            get(list_upstream_credentials).post(create_upstream_credential),
        )
        .route(
            "/admin/v1/upstream-credentials:validate",
            post(validate_upstream_credential),
        )
        .route(
            ADMIN_UPSTREAM_CREDENTIAL_GET_PATH,
            get(get_upstream_credential).patch(update_upstream_credential),
        )
        .route(
            "/admin/v1/model-targets",
            get(list_model_targets).post(create_model_target),
        )
        .route(
            "/admin/v1/model-targets:validate",
            post(validate_model_target),
        )
        .route(
            ADMIN_MODEL_TARGET_GET_PATH,
            get(get_model_target).patch(update_model_target),
        )
        .merge(model_alias_admin_routes())
        .merge(secret_ref_admin_routes())
        .merge(service_account_admin_routes())
        .merge(pricing_sku_admin_routes())
        .merge(budget_policy_admin_routes())
        .merge(quota_policy_admin_routes())
        .merge(otel_export_config_admin_routes())
        .merge(notification_admin_routes())
        .merge(export_admin_routes())
        .merge(emergency_admin_routes())
        .merge(login_provider_admin_routes())
        .merge(organization_invitation_admin_routes())
        .merge(route_policy_admin_routes())
        .merge(provider_grant_admin_routes())
        .merge(routing_group_admin_routes())
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth_context_middleware,
        ))
}

fn tenancy_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/admin/v1/projects", get(list_projects))
        .route(
            ADMIN_PROJECT_GET_PATH,
            get(get_project).patch(update_project),
        )
        .route("/admin/v1/organizations", get(list_organizations))
        .route(
            ADMIN_ORGANIZATION_GET_PATH,
            get(get_organization).patch(update_organization),
        )
        .route(
            ADMIN_ORGANIZATION_MEMBER_LIST_PATH,
            get(list_organization_members),
        )
        .route(
            ADMIN_ORGANIZATION_MEMBER_GET_PATH,
            get(get_organization_member).patch(update_organization_member),
        )
        .route(
            ADMIN_PROJECT_MEMBER_LIST_PATH,
            get(list_project_members).post(create_project_member),
        )
        .route(
            ADMIN_PROJECT_MEMBER_GET_PATH,
            get(get_project_member).patch(update_project_member),
        )
}

fn secret_ref_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/secret-refs",
            get(list_secret_refs).post(create_secret_ref),
        )
        .route(ADMIN_SECRET_REF_GET_PATH, get(get_secret_ref))
        .route(ADMIN_SECRET_REF_LOCATOR_PATH, get(get_secret_ref_locator))
}

fn export_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            ADMIN_EXPORT_JOB_LIST_PATH,
            get(list_export_jobs).post(create_export_job),
        )
        .route(ADMIN_EXPORT_JOB_GET_PATH, get(get_export_job))
        .route(ADMIN_EXPORT_JOB_MANIFEST_PATH, get(get_export_job_manifest))
}

fn emergency_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            ADMIN_EMERGENCY_OPERATION_LIST_PATH,
            get(list_emergency_operations),
        )
        .route(
            ADMIN_EMERGENCY_OPERATION_GET_PATH,
            get(get_emergency_operation),
        )
        .route(
            ADMIN_EMERGENCY_DISABLE_UPSTREAM_CREDENTIAL_PATH,
            post(emergency_disable_upstream_credential),
        )
        .route(
            ADMIN_EMERGENCY_DISABLE_PROVIDER_ENDPOINT_PATH,
            post(emergency_disable_provider_endpoint),
        )
        .route(
            ADMIN_EMERGENCY_DRAIN_ROUTING_GROUP_PATH,
            post(emergency_drain_routing_group),
        )
        .route(
            ADMIN_EMERGENCY_FREEZE_CONFIG_PATH,
            post(emergency_freeze_config),
        )
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/v1/providers", get(list_auth_login_providers))
        .route("/auth/v1/single-user/login", post(single_user_login))
        .route("/auth/v1/session", get(get_current_auth_session))
        .route(
            "/auth/v1/session/default-organization",
            post(update_session_default_organization),
        )
        .route(
            "/auth/v1/session/active-organization",
            post(update_session_active_organization),
        )
        .route(
            "/auth/v1/session/active-project",
            post(update_session_active_project),
        )
        .route("/auth/v1/logout", post(logout_current_auth_session))
        .route(AUTH_INVITATION_PREVIEW_PATH, get(preview_auth_invitation))
        .route(AUTH_INVITATION_ACCEPT_PATH, post(accept_auth_invitation))
        .route(AUTH_LOGIN_PROVIDER_GET_PATH, get(get_auth_login_provider))
        .route(
            AUTH_LOGIN_PROVIDER_START_PATH,
            get(start_auth_login_provider),
        )
}

fn dashboard_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/admin/v1/realtime/overview", get(get_realtime_overview))
        .merge(usage_admin_routes())
        .route(
            "/admin/v1/dashboards/tenant/overview",
            get(get_tenant_dashboard_overview),
        )
        .route(
            ADMIN_DASHBOARD_ORGANIZATION_PATH,
            get(get_organization_dashboard_overview),
        )
        .route(
            ADMIN_DASHBOARD_PROJECT_PATH,
            get(get_project_dashboard_overview),
        )
        .route(
            ADMIN_DASHBOARD_PROJECT_MEMBER_PATH,
            get(get_project_member_dashboard_overview),
        )
        .route(
            ADMIN_DASHBOARD_API_KEY_PATH,
            get(get_api_key_dashboard_overview),
        )
        .route(
            ADMIN_DASHBOARD_SERVICE_ACCOUNT_PATH,
            get(get_service_account_dashboard_overview),
        )
        .route(
            ADMIN_MODEL_ALIAS_DASHBOARD_PATH,
            get(get_model_alias_dashboard_overview),
        )
        .route(
            ADMIN_MODEL_TARGET_DASHBOARD_PATH,
            get(get_model_target_dashboard_overview),
        )
        .route(
            ADMIN_PROVIDER_ENDPOINT_OBSERVABILITY_USAGE_PATH,
            get(get_provider_endpoint_observability_usage),
        )
}

fn usage_admin_routes() -> Router<AppState> {
    Router::new()
        .route(ADMIN_USAGE_SUMMARY_PATH, get(get_usage_summary))
        .route(ADMIN_USAGE_TIMESERIES_PATH, get(get_usage_timeseries))
        .route(ADMIN_USAGE_EVENTS_PATH, get(list_usage_events))
        .route(
            ADMIN_USAGE_BREAKDOWN_BY_PROJECT_PATH,
            get(get_usage_breakdown_by_project),
        )
        .route(
            ADMIN_USAGE_BREAKDOWN_BY_PROJECT_MEMBER_PATH,
            get(get_usage_breakdown_by_project_member),
        )
        .route(
            ADMIN_USAGE_BREAKDOWN_BY_MODEL_PATH,
            get(get_usage_breakdown_by_model),
        )
        .route(
            ADMIN_USAGE_BREAKDOWN_BY_PROVIDER_ENDPOINT_PATH,
            get(get_usage_breakdown_by_provider_endpoint),
        )
}

fn model_alias_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/model-aliases",
            get(list_model_aliases).post(create_model_alias),
        )
        .route(
            "/admin/v1/model-aliases:validate",
            post(validate_model_alias),
        )
        .route(
            ADMIN_MODEL_ALIAS_GET_PATH,
            get(get_model_alias).patch(update_model_alias),
        )
}

fn service_account_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/service-accounts",
            get(list_service_accounts).post(create_service_account),
        )
        .route(
            ADMIN_SERVICE_ACCOUNT_GET_PATH,
            get(get_service_account).patch(update_service_account),
        )
}

fn pricing_sku_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/pricing-skus",
            get(list_pricing_skus).post(create_pricing_sku),
        )
        .route(
            "/admin/v1/pricing-skus:validate",
            post(validate_pricing_sku),
        )
        .route(
            ADMIN_PRICING_SKU_GET_PATH,
            get(get_pricing_sku).patch(update_pricing_sku),
        )
}

fn budget_policy_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/budget-policies",
            get(list_budget_policies).post(create_budget_policy),
        )
        .route(
            "/admin/v1/budget-policies:validate",
            post(validate_budget_policy),
        )
        .route(
            ADMIN_BUDGET_POLICY_GET_PATH,
            get(get_budget_policy).patch(update_budget_policy),
        )
}

fn quota_policy_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/quota-policies",
            get(list_quota_policies).post(create_quota_policy),
        )
        .route(
            "/admin/v1/quota-policies:validate",
            post(validate_quota_policy),
        )
        .route(
            ADMIN_QUOTA_POLICY_GET_PATH,
            get(get_quota_policy).patch(update_quota_policy),
        )
}

fn otel_export_config_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/observability/otel-export/configs",
            get(list_otel_export_configs).post(create_otel_export_config),
        )
        .route(
            ADMIN_OTEL_EXPORT_CONFIG_GET_PATH,
            get(get_otel_export_config).patch(update_otel_export_config),
        )
        .route(
            ADMIN_OTEL_EXPORT_CONFIG_VALIDATE_PATH,
            post(validate_otel_export_config),
        )
        .route(
            ADMIN_OTEL_EXPORT_CONFIG_DISABLE_PATH,
            post(disable_otel_export_config),
        )
}

fn notification_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/notification/sinks",
            get(list_notification_sinks).post(create_notification_sink),
        )
        .route(
            "/admin/v1/notification/sinks:validate",
            post(validate_notification_sink),
        )
        .route(
            ADMIN_NOTIFICATION_SINK_GET_PATH,
            get(get_notification_sink).patch(update_notification_sink),
        )
        .route(
            ADMIN_NOTIFICATION_SUBSCRIPTION_LIST_PATH,
            get(list_notification_subscriptions).post(create_notification_subscription),
        )
        .route(
            ADMIN_NOTIFICATION_SUBSCRIPTION_VALIDATE_PATH,
            post(validate_notification_subscription),
        )
        .route(
            ADMIN_NOTIFICATION_SUBSCRIPTION_GET_PATH,
            get(get_notification_subscription).patch(update_notification_subscription),
        )
}

fn user_admin_routes() -> Router<AppState> {
    Router::new()
        .route("/admin/v1/users", get(list_users))
        .route(ADMIN_USER_GET_PATH, get(get_user).patch(update_user))
        .route(ADMIN_USER_SESSION_LIST_PATH, get(list_user_sessions))
        .route(ADMIN_USER_SESSION_REVOKE_PATH, post(revoke_user_session))
        .route(
            ADMIN_USER_EXTERNAL_IDENTITY_LIST_PATH,
            get(list_user_external_identities),
        )
        .route(
            ADMIN_USER_EXTERNAL_IDENTITY_GET_PATH,
            get(get_user_external_identity),
        )
        .route(
            ADMIN_USER_EXTERNAL_IDENTITY_UNLINK_PATH,
            post(unlink_user_external_identity),
        )
}

fn login_provider_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/identity-providers",
            get(list_login_providers).post(create_login_provider),
        )
        .route(
            "/admin/v1/identity-providers:validate",
            post(validate_login_provider),
        )
        .route(
            ADMIN_LOGIN_PROVIDER_GET_PATH,
            get(get_login_provider).patch(update_login_provider),
        )
}

fn organization_invitation_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            ADMIN_ORGANIZATION_INVITATION_LIST_PATH,
            get(list_organization_invitations).post(create_organization_invitation),
        )
        .route(
            ADMIN_ORGANIZATION_INVITATION_GET_PATH,
            get(get_organization_invitation),
        )
        .route(
            ADMIN_ORGANIZATION_INVITATION_REVOKE_PATH,
            post(revoke_organization_invitation),
        )
}

fn route_policy_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/route-policies",
            get(list_route_policies).post(create_route_policy),
        )
        .route(
            "/admin/v1/route-policies:validate",
            post(validate_route_policy),
        )
        .route(
            ADMIN_ROUTE_POLICY_GET_PATH,
            get(get_route_policy).patch(update_route_policy),
        )
}

fn provider_grant_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/provider-grants",
            get(list_provider_grants).post(create_provider_grant),
        )
        .route(
            "/admin/v1/provider-grants:validate",
            post(validate_provider_grant),
        )
        .route(
            ADMIN_PROVIDER_GRANT_GET_PATH,
            get(get_provider_grant).patch(update_provider_grant),
        )
}

fn routing_group_admin_routes() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/v1/routing-groups",
            get(list_routing_groups).post(create_routing_group),
        )
        .route(
            "/admin/v1/routing-groups:validate",
            post(validate_routing_group),
        )
        .route(
            ADMIN_ROUTING_GROUP_GET_PATH,
            get(get_routing_group).patch(update_routing_group),
        )
        .route(
            ADMIN_ROUTING_GROUP_TARGET_LIST_PATH,
            get(list_routing_group_targets).post(create_routing_group_target),
        )
        .route(
            ADMIN_ROUTING_GROUP_TARGET_VALIDATE_PATH,
            post(validate_routing_group_target),
        )
        .route(
            ADMIN_ROUTING_GROUP_TARGET_GET_PATH,
            get(get_routing_group_target).patch(update_routing_group_target),
        )
}

/// Runs the gateway HTTP server.
pub async fn run(config: GatewayConfig) -> crate::error::Result<()> {
    validate_gateway_config(&config)?;
    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|error| crate::error::GatewayError::Internal {
            message: format!("failed to bind gateway listener: {error}"),
        })?;
    let store = InMemoryGatewayStore::default();
    bootstrap_single_user_if_configured(&store, &config, chrono::Utc::now())?;
    let state = AppState::new(config, store);
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| crate::error::GatewayError::Internal {
            message: format!("gateway server failed: {error}"),
        })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let wait_forever = tokio::time::sleep(Duration::from_secs(u64::MAX));
    tokio::select! {
        () = ctrl_c => {}
        () = wait_forever => {}
    }
}

fn bootstrap_single_user_if_configured(
    store: &InMemoryGatewayStore,
    config: &GatewayConfig,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let Some(single_user) = config.single_user_auth.as_ref() else {
        return Ok(());
    };
    store.bootstrap_default_project(single_user_bootstrap_request(single_user), now)?;
    seed_single_user_action_grants_if_needed(store, single_user);
    Ok(())
}

fn single_user_bootstrap_request(config: &SingleUserAuthConfig) -> BootstrapDefaultProjectRequest {
    BootstrapDefaultProjectRequest {
        tenant_id: config.tenant_id.clone(),
        tenant_display_name: config.tenant_display_name.clone(),
        organization_id: config.organization_id.clone(),
        organization_display_name: config.organization_display_name.clone(),
        project_id: config.project_id.clone(),
        project_display_name: config.project_display_name.clone(),
        user_id: config.user_id.clone(),
        user_display_name: config.user_display_name.clone(),
        user_primary_email: config.user_primary_email.clone(),
        organization_member_id: SINGLE_USER_ORGANIZATION_MEMBER_ID.to_owned(),
        project_member_id: SINGLE_USER_PROJECT_MEMBER_ID.to_owned(),
        created_by: config.user_id.clone(),
    }
}

fn seed_single_user_action_grants_if_needed(
    store: &InMemoryGatewayStore,
    config: &SingleUserAuthConfig,
) {
    let already_seeded = store.action_grants().iter().any(|grant| {
        (grant.tenant_id.as_str(), grant.principal_id.as_str())
            == (config.tenant_id.as_str(), config.user_id.as_str())
    });
    if already_seeded {
        return;
    }
    for grant in ActionGrant::for_builtin_role(
        config.tenant_id.clone(),
        None::<String>,
        None::<String>,
        config.user_id.clone(),
        BuiltInRole::TenantOwner,
    ) {
        store.insert_action_grant(grant);
    }
}

async fn request_id_middleware(mut request: Request<Body>, next: Next) -> Response {
    let request_id = request
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_safe_request_id(value))
        .map_or_else(|| new_prefixed_id("req"), ToOwned::to_owned);
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        request.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    response
}

async fn auth_context_middleware(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response> {
    let actor = authenticate_request(&state, request.headers(), chrono::Utc::now())?;
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
}

fn is_safe_request_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    schema: &'static str,
    service: &'static str,
    status: &'static str,
}

#[derive(Debug, Serialize)]
struct ReadinessResponse {
    schema: &'static str,
    service: &'static str,
    ready: bool,
    latest_config_version: Option<i64>,
    reason: &'static str,
    profile: ReadinessProfile,
    dependencies: ReadinessDependencies,
    diagnostics: Vec<StartupDiagnostic>,
}

#[derive(Debug, Serialize)]
struct ReadinessProfile {
    environment: String,
    production_profile: bool,
    production_profile_valid: bool,
    dependency_probe_mode: &'static str,
}

#[derive(Debug, Serialize)]
struct ReadinessDependencies {
    database: &'static str,
    database_migrations: &'static str,
    database_missing_migrations: Vec<i64>,
    hot_state: &'static str,
    secret_backend: &'static str,
    secret_backend_profile: String,
    telemetry: &'static str,
    telemetry_profile: String,
    otel_exporter: &'static str,
    published_snapshot_requirement: &'static str,
    published_snapshot: &'static str,
}

#[derive(Debug)]
struct DependencyReadiness {
    database: &'static str,
    database_migrations: &'static str,
    database_missing_migrations: Vec<i64>,
    hot_state: &'static str,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct VersionResponse {
    schema: &'static str,
    service: &'static str,
    version: &'static str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminPublishConfigSnapshotRequest {
    idempotency_key: String,
    #[serde(default)]
    resource_versions: Vec<ResourceVersion>,
    payload: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminRollbackConfigSnapshotRequest {
    idempotency_key: String,
    source_snapshot_id: String,
    reason: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminValidateConfigSnapshotRequest {
    payload: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateDirectoryStatusRequest {
    expected_version: i64,
    status: DirectoryStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateMembershipRequest {
    expected_version: i64,
    status: MembershipStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateServiceAccountRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    display_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateProviderEndpointRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    provider_kind: String,
    display_name: String,
    protocol_families: Vec<ProtocolFamily>,
    upstream_base_url: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateProviderEndpointRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateUpstreamCredentialRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    provider_endpoint_id: String,
    credential_kind: String,
    secret_ref_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateSecretRefRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    purpose: String,
    #[serde(default = "default_secret_ref_backend_kind")]
    backend_kind: String,
    secret_value: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateUpstreamCredentialRequest {
    expected_version: i64,
    status: UpstreamCredentialStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateModelTargetRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    provider_endpoint_id: String,
    upstream_credential_id: Option<String>,
    protocol_family: ProtocolFamily,
    upstream_model_id: String,
    #[serde(default = "default_true")]
    supports_streaming: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateModelTargetRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateModelAliasRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    alias_name: String,
    protocol_family: ProtocolFamily,
    route_policy_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateModelAliasRequest {
    expected_version: i64,
    status: Option<ResourceStatus>,
    route_policy_id: Option<String>,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreatePricingSkuRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    name: String,
    currency: String,
    unit: String,
    model_id_patterns: Vec<String>,
    #[serde(default)]
    provider_endpoint_patterns: Vec<String>,
    pricing_document: Value,
    effective_from: Option<chrono::DateTime<chrono::Utc>>,
    effective_until: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    is_preset: bool,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdatePricingSkuRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateBudgetPolicyRequest {
    idempotency_key: String,
    scope_kind: String,
    scope_id: String,
    currency: Option<String>,
    period: String,
    limit_kind: String,
    hard_limit: Option<i64>,
    soft_limit: Option<i64>,
    #[serde(default)]
    thresholds: Vec<i64>,
    reset_policy: String,
    overage_mode: String,
    consistency_mode: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateBudgetPolicyRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateQuotaPolicyRequest {
    idempotency_key: String,
    scope_kind: String,
    scope_id: String,
    counter_kind: String,
    limit: i64,
    burst_limit: Option<i64>,
    window: String,
    increment_source: String,
    loss_behavior: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateQuotaPolicyRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateExportJobRequest {
    idempotency_key: String,
    export_kind: String,
    #[serde(default)]
    scope_kind: Option<String>,
    #[serde(default)]
    scope_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default = "default_export_retention_days")]
    retention_days: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminExportJobListQuery {
    export_kind: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminEmergencyOperationRequest {
    idempotency_key: String,
    #[serde(default)]
    expected_version: Option<i64>,
    reason: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminEmergencyOperationListQuery {
    operation_kind: Option<String>,
    target_resource_kind: Option<String>,
    status: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateOtelExportConfigRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    endpoint_url: String,
    protocol: String,
    #[serde(default)]
    header_refs: Vec<OtelHeaderRef>,
    enabled_signals: Vec<String>,
    #[serde(default)]
    resource_attributes: Vec<OtelResourceAttribute>,
    #[serde(default = "default_otel_export_interval_seconds")]
    export_interval_seconds: i64,
    #[serde(default = "default_otel_export_timeout_seconds")]
    timeout_seconds: i64,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateOtelExportConfigRequest {
    expected_version: i64,
    organization_id: Option<String>,
    project_id: Option<String>,
    endpoint_url: Option<String>,
    protocol: Option<String>,
    header_refs: Option<Vec<OtelHeaderRef>>,
    enabled_signals: Option<Vec<String>>,
    resource_attributes: Option<Vec<OtelResourceAttribute>>,
    export_interval_seconds: Option<i64>,
    timeout_seconds: Option<i64>,
    status: Option<ResourceStatus>,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminDisableOtelExportConfigRequest {
    expected_version: i64,
    reason: String,
}

/// Summary returned by one deterministic OpenTelemetry exporter worker tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtelExporterRunSummary {
    /// Tenant processed by this tick.
    pub tenant_id: String,
    /// Worker role or instance id.
    pub worker_id: String,
    /// Number of configs considered.
    pub attempted_config_count: usize,
    /// Number of successful export attempts.
    pub succeeded_count: usize,
    /// Number of retryable failed export attempts.
    pub failed_count: usize,
    /// Number of disabled configs observed.
    pub disabled_count: usize,
    /// Metrics accepted by the simulated exporter.
    pub exported_metric_count: i64,
    /// Metrics dropped because the collector was unavailable.
    pub dropped_metric_count: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateNotificationSinkRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    name: String,
    sink_kind: String,
    #[serde(default)]
    endpoint_config: Value,
    signing_secret_ref_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateNotificationSinkRequest {
    expected_version: i64,
    name: Option<String>,
    #[serde(default)]
    endpoint_config: Option<Value>,
    #[serde(default)]
    signing_secret_ref_id: NullablePatch<String>,
    status: Option<ResourceStatus>,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateNotificationSubscriptionRequest {
    idempotency_key: String,
    event_family: String,
    #[serde(default)]
    filter_document: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateNotificationSubscriptionRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateLoginProviderRequest {
    idempotency_key: String,
    provider_kind: String,
    display_name: String,
    #[serde(default)]
    config_document: Value,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateLoginProviderRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateOrganizationInvitationRequest {
    idempotency_key: String,
    invited_email: Option<String>,
    invited_principal_id: Option<String>,
    project_id: Option<String>,
    role_id: Option<String>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminRevokeOrganizationInvitationRequest {
    expected_version: i64,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateUserRequest {
    expected_version: i64,
    status: DirectoryStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminRevokeUserSessionRequest {
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUnlinkExternalIdentityRequest {
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateProjectMemberRequest {
    idempotency_key: String,
    principal_id: String,
    organization_member_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AuthProviderListQuery {
    tenant_id: Option<String>,
}

#[derive(Clone, Deserialize)]
struct SingleUserLoginRequest {
    username: String,
    password: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SessionDefaultOrganizationRequest {
    organization_id: String,
    project_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SessionActiveOrganizationRequest {
    organization_id: String,
    project_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct SessionActiveProjectRequest {
    project_id: String,
}

impl std::fmt::Debug for SingleUserLoginRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SingleUserLoginRequest")
            .field("username", &self.username)
            .field("password", &"***")
            .finish()
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AdminAuditEventListQuery {
    scope_kind: Option<String>,
    scope_id: Option<String>,
    organization_id: Option<String>,
    project_id: Option<String>,
    event_type: Option<String>,
    resource_kind: Option<String>,
    resource_id: Option<String>,
    actor_id: Option<String>,
    principal_id: Option<String>,
    request_id: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUsageScopeQuery {
    scope_kind: Option<String>,
    scope_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUsageTimeseriesQuery {
    scope_kind: Option<String>,
    scope_id: Option<String>,
    bucket_kind: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUsageEventsQuery {
    scope_kind: Option<String>,
    scope_id: Option<String>,
    status: Option<String>,
    protocol_family: Option<String>,
    usage_confidence: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUsageBreakdownQuery {
    scope_kind: Option<String>,
    scope_id: Option<String>,
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateRoutePolicyRequest {
    idempotency_key: String,
    name: String,
    model_alias_id: String,
    routing_group_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateRoutePolicyRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateProviderGrantRequest {
    idempotency_key: String,
    scope_kind: String,
    scope_id: String,
    resource_kind: String,
    resource_id: String,
    effect: String,
    closure_mode: String,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateProviderGrantRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateRoutingGroupRequest {
    idempotency_key: String,
    organization_id: Option<String>,
    name: String,
    protocol_family: ProtocolFamily,
    purpose: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateRoutingGroupRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdminCreateRoutingGroupTargetRequest {
    idempotency_key: String,
    model_target_id: String,
    weight: u32,
    priority: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct AdminUpdateRoutingGroupTargetRequest {
    expected_version: i64,
    status: ResourceStatus,
    reason: Option<String>,
}

struct ConfigSnapshotAuditInput {
    event_type: &'static str,
    resource_id: String,
    before_version: Option<i64>,
    after_version: Option<i64>,
    redacted_diff: Value,
    occurred_at: chrono::DateTime<chrono::Utc>,
}

struct ProjectAuditInput {
    project_id: String,
    before_version: Option<i64>,
    after_version: Option<i64>,
    redacted_diff: Value,
    occurred_at: chrono::DateTime<chrono::Utc>,
}

struct AdminResourceAuditInput {
    event_type: &'static str,
    scope_kind: &'static str,
    scope_id: String,
    resource_kind: &'static str,
    resource_id: String,
    before_version: Option<i64>,
    after_version: Option<i64>,
    redacted_diff: Value,
    occurred_at: chrono::DateTime<chrono::Utc>,
}

struct EmergencyOperationInput {
    operation_kind: &'static str,
    target_resource_kind: &'static str,
    target_resource_id: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    reason: String,
    expires_at: chrono::DateTime<chrono::Utc>,
}

struct DashboardScopeInput {
    schema: &'static str,
    tenant_id: String,
    scope_kind: &'static str,
    scope_id: String,
    organization_id: Option<String>,
    project_id: Option<String>,
    project_member_id: Option<String>,
    principal_id: Option<String>,
}

struct ValidationResponseInput {
    schema: &'static str,
    resource_kind: &'static str,
    scope_kind: &'static str,
    scope_id: String,
    errors: Vec<Value>,
    warnings: Vec<Value>,
    affected_resources: Vec<Value>,
    publication_plan: Option<Value>,
    route_simulation: Option<Value>,
    budget_simulation: Option<Value>,
    occurred_at: chrono::DateTime<chrono::Utc>,
}

async fn healthz() -> Json<HealthResponse> {
    Json(HealthResponse {
        schema: "gateway.health.v1",
        service: SERVICE_NAME,
        status: "ok",
    })
}

async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<ReadinessResponse>) {
    let latest_snapshot = state.store.latest_published_snapshot();
    let diagnostics = production_profile_diagnostics(&state.config);
    let dependency_readiness = dependency_readiness(&state.config).await;
    let snapshot_ready = !state.config.require_published_snapshot || latest_snapshot.is_some();
    let ready = diagnostics.is_empty() && dependency_readiness.ready && snapshot_ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let reason = if !diagnostics.is_empty() {
        "production_profile_invalid"
    } else if !dependency_readiness.ready {
        "dependency_unready"
    } else if !snapshot_ready {
        "missing_published_snapshot"
    } else {
        "ready"
    };
    (
        status,
        Json(ReadinessResponse {
            schema: "gateway.readiness.v1",
            service: SERVICE_NAME,
            ready,
            latest_config_version: latest_snapshot.as_ref().map(|snapshot| snapshot.version),
            reason,
            profile: ReadinessProfile {
                environment: state.config.environment.clone(),
                production_profile: is_production_environment(&state.config.environment),
                production_profile_valid: diagnostics.is_empty(),
                dependency_probe_mode: state.config.dependency_probe_mode.as_str(),
            },
            dependencies: ReadinessDependencies {
                database: dependency_readiness.database,
                database_migrations: dependency_readiness.database_migrations,
                database_missing_migrations: dependency_readiness.database_missing_migrations,
                hot_state: dependency_readiness.hot_state,
                secret_backend: secret_backend_readiness_status(&state.config),
                secret_backend_profile: state.config.secret_backend_profile.clone(),
                telemetry: telemetry_readiness_status(&state.config),
                telemetry_profile: state.config.telemetry_profile.clone(),
                otel_exporter: otel_exporter_readiness_status(&state),
                published_snapshot_requirement: if state.config.require_published_snapshot {
                    "required"
                } else {
                    "not_required"
                },
                published_snapshot: if latest_snapshot.is_some() {
                    "available"
                } else {
                    "missing"
                },
            },
            diagnostics,
        }),
    )
}

async fn dependency_readiness(config: &GatewayConfig) -> DependencyReadiness {
    if config.dependency_probe_mode == DependencyProbeMode::Configured {
        return DependencyReadiness {
            database: configured_status(config.database_url.is_some()),
            database_migrations: if config.database_url.is_some() {
                "not_checked"
            } else {
                "not_applicable"
            },
            database_missing_migrations: Vec::new(),
            hot_state: configured_status(config.redis_url.is_some()),
            ready: true,
        };
    }

    let (database, database_migrations, database_missing_migrations, database_ready) =
        postgres_readiness(config).await;
    let (hot_state, hot_state_ready) = hot_state_readiness(config).await;
    DependencyReadiness {
        database,
        database_migrations,
        database_missing_migrations,
        hot_state,
        ready: database_ready && hot_state_ready,
    }
}

async fn postgres_readiness(
    config: &GatewayConfig,
) -> (&'static str, &'static str, Vec<i64>, bool) {
    let Some(database_url) = config.database_url.as_deref() else {
        return ("missing", "not_applicable", Vec::new(), true);
    };
    let timeout = Duration::from_millis(config.readiness_probe_timeout_ms);
    let applied_versions = match tokio::time::timeout(
        timeout,
        applied_postgres_migration_versions(database_url),
    )
    .await
    {
        Ok(Ok(applied_versions)) => applied_versions,
        Ok(Err(_)) => return ("unavailable", "unavailable", Vec::new(), false),
        Err(_) => return ("timeout", "not_checked", Vec::new(), false),
    };
    let missing_versions = migrations::missing_versions(&applied_versions);
    if missing_versions.is_empty() {
        ("connected", "ready", missing_versions, true)
    } else {
        ("connected", "pending", missing_versions, false)
    }
}

async fn applied_postgres_migration_versions(
    database_url: &str,
) -> Result<std::collections::HashSet<i64>> {
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(database_url)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to connect to PostgreSQL: {error}"),
        })?;
    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .map_err(|error| GatewayError::Internal {
            message: format!("failed to probe PostgreSQL: {error}"),
        })?;
    migrations::applied_versions(&pool).await
}

async fn hot_state_readiness(config: &GatewayConfig) -> (&'static str, bool) {
    let Some(redis_url) = config.redis_url.as_deref() else {
        return ("missing", true);
    };
    let Some((host, port)) = redis_host_port(redis_url) else {
        return ("invalid", false);
    };
    let timeout = Duration::from_millis(config.readiness_probe_timeout_ms);
    match tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port))).await {
        Ok(Ok(_stream)) => ("connected", true),
        Ok(Err(_)) => ("unavailable", false),
        Err(_) => ("timeout", false),
    }
}

fn redis_host_port(redis_url: &str) -> Option<(String, u16)> {
    let parsed = Url::parse(redis_url).ok()?;
    if !matches!(parsed.scheme(), "redis" | "rediss") {
        return None;
    }
    Some((parsed.host_str()?.to_owned(), parsed.port().unwrap_or(6379)))
}

fn secret_backend_readiness_status(config: &GatewayConfig) -> &'static str {
    if config.secret_backend_profile == "memory" {
        "memory"
    } else {
        "profile_configured"
    }
}

fn telemetry_readiness_status(config: &GatewayConfig) -> &'static str {
    if config.telemetry_profile == "disabled" {
        "disabled"
    } else {
        "profile_configured"
    }
}

const fn configured_status(configured: bool) -> &'static str {
    if configured {
        "configured"
    } else {
        "missing"
    }
}

fn otel_exporter_readiness_status(state: &AppState) -> &'static str {
    let configs = state
        .store
        .otel_export_config_records()
        .into_iter()
        .filter(|config| config.status != ResourceStatus::Deleted)
        .collect::<Vec<_>>();
    if configs.is_empty() {
        return "not_configured";
    }
    let active_configs = configs
        .iter()
        .filter(|config| config.status == ResourceStatus::Active)
        .collect::<Vec<_>>();
    if active_configs.is_empty() {
        return "disabled";
    }
    let health_by_config = state
        .store
        .otel_exporter_health_records()
        .into_iter()
        .map(|record| (record.otel_export_config_id.clone(), record))
        .collect::<HashMap<_, _>>();
    let mut missing_health = false;
    for config in active_configs {
        let Some(health) = health_by_config.get(&config.otel_export_config_id) else {
            missing_health = true;
            continue;
        };
        if health.status == "retryable_failed" {
            return "degraded";
        }
        if health.status != "succeeded" {
            missing_health = true;
        }
    }
    if missing_health {
        "not_connected"
    } else {
        "ready"
    }
}

async fn version() -> Json<VersionResponse> {
    Json(VersionResponse {
        schema: "gateway.version.v1",
        service: SERVICE_NAME,
        version: env!("CARGO_PKG_VERSION"),
    })
}

async fn list_config_snapshots(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/config/snapshots",
        &actor.tenant_id,
        now,
    )?;
    let snapshots = state
        .store
        .config_snapshots()
        .iter()
        .filter(|snapshot| snapshot.metadata.tenant_id == actor.tenant_id)
        .map(config_snapshot_summary)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.config_snapshot_list.v1",
        "snapshots": snapshots,
        "next_cursor": null
    })))
}

async fn get_config_snapshot(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(snapshot_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_CONFIG_SNAPSHOT_GET_PATH,
        &snapshot_id,
        now,
    )?;
    let snapshot = state
        .store
        .config_snapshot(&snapshot_id)
        .filter(|snapshot| snapshot.metadata.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("config snapshot {snapshot_id}"),
        })?;
    Ok(Json(json!({
        "schema": "gateway.admin.config_snapshot.v1",
        "snapshot": snapshot
    })))
}

async fn list_validation_diagnostics(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_CONFIG_VALIDATION_DIAGNOSTICS_PATH,
        &actor.tenant_id,
        now,
    )?;
    let diagnostics = state
        .store
        .validation_diagnostics_for_tenant(&actor.tenant_id)
        .into_iter()
        .map(|record| validation_diagnostic_body(&record))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.config_validation_diagnostic_list.v1",
        "diagnostics": diagnostics,
        "next_cursor": null
    })))
}

async fn list_audit_events(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminAuditEventListQuery>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_AUDIT_EVENT_LIST_PATH,
        &actor.tenant_id,
        now,
    )?;
    let limit = audit_event_list_limit(query.limit)?;
    let offset = audit_event_list_offset(query.cursor.as_deref())?;
    let mut events = state
        .store
        .audit_events_for_tenant(&actor.tenant_id)
        .into_iter()
        .filter(|event| audit_event_matches_query(event, &query))
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        right
            .occurred_at
            .cmp(&left.occurred_at)
            .then_with(|| right.audit_event_id.cmp(&left.audit_event_id))
    });
    let total_filtered_count = events.len();
    let page = events
        .iter()
        .skip(offset)
        .take(limit)
        .map(audit_event_body)
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(page.len());
    let next_cursor = (next_offset < total_filtered_count).then(|| next_offset.to_string());
    Ok(Json(json!({
        "schema": "gateway.admin.audit_event_list.v1",
        "events": page,
        "limit": limit,
        "cursor": query.cursor,
        "next_cursor": next_cursor,
        "total_filtered_count": total_filtered_count
    })))
}

async fn list_export_jobs(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminExportJobListQuery>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_EXPORT_JOB_LIST_PATH,
        &actor.tenant_id,
        now,
    )?;
    let limit = export_list_limit(query.limit)?;
    let offset = export_list_offset(query.cursor.as_deref())?;
    let route = route_metadata(&Method::GET, ADMIN_EXPORT_JOB_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .export_jobs_for_tenant(&actor.tenant_id)
            .into_iter()
            .filter(|job| export_job_matches_query(job, &query))
            .map(|job| AuthorizableItem {
                resource: route.resource(job.export_job_id.clone()),
                item: job,
            }),
    );
    let total_filtered_count = authorized.items.len();
    let resources = authorized
        .items
        .iter()
        .skip(offset)
        .take(limit)
        .map(|job| export_job_resource_envelope(&state, job))
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(resources.len());
    let next_cursor = (next_offset < total_filtered_count).then(|| next_offset.to_string());
    Ok(Json(json!({
        "schema": "gateway.admin.export_job_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "total_filtered_count": total_filtered_count,
        "limit": limit,
        "cursor": query.cursor,
        "next_cursor": next_cursor
    })))
}

async fn create_export_job(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateExportJobRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    validate_export_kind(&request.export_kind)?;
    let scope = usage_scope_from_query(
        &state,
        &actor,
        request.scope_kind.as_deref(),
        request.scope_id.as_deref(),
    )?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_EXPORT_JOB_LIST_PATH,
        &scope.scope_id,
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("exports:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let limit = export_list_limit(request.limit)?;
    let offset = export_list_offset(request.cursor.as_deref())?;
    let retention_days = export_retention_days(request.retention_days)?;
    let export_page = build_export_page(&state, &request.export_kind, &scope, limit, offset)?;
    let query_document = export_query_document(&request, &scope, limit);
    let job = state.store.create_export_job(
        CreateExportJobRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: scope.organization_id.clone(),
            project_id: scope.project_id.clone(),
            export_kind: request.export_kind.clone(),
            requested_by: actor_principal_or_actor_id(&actor),
            query_document,
        },
        now,
    )?;
    let object_ref = export_object_ref(&job);
    let payload_document = export_payload_document(&job, &scope, &request, &export_page, limit);
    let payload_bytes =
        serde_json::to_vec(&payload_document).map_err(|error| GatewayError::Internal {
            message: format!("failed to encode export payload: {error}"),
        })?;
    let checksum = export_payload_checksum(&payload_bytes);
    let expires_at = now + chrono::Duration::days(retention_days);
    let manifest_document =
        export_manifest_document(&job, &scope, &export_page, &object_ref, &checksum);
    let (job, manifest) = state.store.complete_export_job(
        &job.export_job_id,
        CompleteExportJobRequest {
            object_ref,
            record_count: i64::try_from(export_page.rows.len()).unwrap_or(i64::MAX),
            byte_count: i64::try_from(payload_bytes.len()).unwrap_or(i64::MAX),
            checksum,
            manifest_document,
            expires_at,
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.export_job.create",
            scope_kind: scope.scope_kind,
            scope_id: scope.scope_id.clone(),
            resource_kind: "ExportJob",
            resource_id: job.export_job_id.clone(),
            before_version: None,
            after_version: Some(job.resource_version),
            redacted_diff: export_job_create_diff(&job, &manifest, &scope, &export_page),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.export_job_mutation.v1",
        "resource": export_job_resource_body(&state, &job),
        "manifest": export_manifest_resource_body(&manifest),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
    });
    Ok(Json(response))
}

async fn get_export_job(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(export_job_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_EXPORT_JOB_GET_PATH,
        &export_job_id,
        now,
    )?;
    let job = export_job_for_actor(&state, &actor, &export_job_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.export_job.v1",
        "resource": export_job_resource_body(&state, &job)
    })))
}

async fn get_export_job_manifest(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(export_job_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_EXPORT_JOB_MANIFEST_PATH,
        &export_job_id,
        now,
    )?;
    let job = export_job_for_actor(&state, &actor, &export_job_id)?;
    let manifest = export_manifest_for_job(&state, &job)?;
    Ok(Json(json!({
        "schema": "gateway.admin.export_manifest.v1",
        "resource": export_manifest_resource_body(&manifest)
    })))
}

async fn list_emergency_operations(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminEmergencyOperationListQuery>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_EMERGENCY_OPERATION_LIST_PATH,
        &actor.tenant_id,
        now,
    )?;
    let limit = export_list_limit(query.limit)?;
    let offset = export_list_offset(query.cursor.as_deref())?;
    let route = route_metadata(&Method::GET, ADMIN_EMERGENCY_OPERATION_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .emergency_operations_for_tenant(&actor.tenant_id)
            .into_iter()
            .filter(|operation| emergency_operation_matches_query(operation, &query))
            .map(|operation| AuthorizableItem {
                resource: route.resource(operation.emergency_operation_id.clone()),
                item: operation,
            }),
    );
    let total_filtered_count = authorized.items.len();
    let resources = authorized
        .items
        .iter()
        .skip(offset)
        .take(limit)
        .map(emergency_operation_resource_envelope)
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(resources.len());
    let next_cursor = (next_offset < total_filtered_count).then(|| next_offset.to_string());
    Ok(Json(json!({
        "schema": "gateway.admin.emergency_operation_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "total_filtered_count": total_filtered_count,
        "limit": limit,
        "cursor": query.cursor,
        "next_cursor": next_cursor
    })))
}

async fn get_emergency_operation(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(emergency_operation_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_EMERGENCY_OPERATION_GET_PATH,
        &emergency_operation_id,
        now,
    )?;
    let operation = emergency_operation_for_actor(&state, &actor, &emergency_operation_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.emergency_operation.v1",
        "resource": emergency_operation_resource_body(&operation)
    })))
}

async fn emergency_disable_upstream_credential(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(upstream_credential_id): Path<String>,
    Json(request): Json<AdminEmergencyOperationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_emergency_operation_request(&request, now)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_EMERGENCY_DISABLE_UPSTREAM_CREDENTIAL_PATH,
        &upstream_credential_id,
        now,
    )?;
    let scope_key = emergency_idempotency_scope_key(
        "disable_upstream_credential",
        &upstream_credential_id,
        &request.idempotency_key,
    );
    let request_hash = emergency_request_hash(&upstream_credential_id, &request)?;
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let before = upstream_credential_for_actor(&state, &actor, &upstream_credential_id)?;
    let expected_version = required_emergency_expected_version(&request)?;
    let updated = state.store.update_upstream_credential_status(
        &upstream_credential_id,
        expected_version,
        UpstreamCredentialStatus::Disabled,
        now,
    )?;
    let operation = create_emergency_operation_record(
        &state,
        &actor,
        EmergencyOperationInput {
            operation_kind: "disable_upstream_credential",
            target_resource_kind: "UpstreamCredential",
            target_resource_id: updated.upstream_credential_id.clone(),
            organization_id: updated.organization_id.clone(),
            project_id: None,
            reason: request.reason.clone(),
            expires_at: request.expires_at,
        },
        now,
    )?;
    let audit_event_id = record_emergency_operation_audit(
        &state,
        &actor,
        &operation,
        Some(before.resource_version),
        Some(updated.resource_version),
        &json!({
            "target_status": {
                "before": before.status.as_str(),
                "after": updated.status.as_str()
            }
        }),
        now,
    );
    let affected_resource = upstream_credential_resource_body(&updated);
    let response =
        emergency_operation_mutation_response(&operation, &affected_resource, &audit_event_id);
    record_idempotent_admin_response(
        &state,
        actor.tenant_id,
        scope_key,
        request_hash,
        &response,
        now,
    );
    Ok(Json(response))
}

async fn emergency_disable_provider_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(provider_endpoint_id): Path<String>,
    Json(request): Json<AdminEmergencyOperationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_emergency_operation_request(&request, now)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_EMERGENCY_DISABLE_PROVIDER_ENDPOINT_PATH,
        &provider_endpoint_id,
        now,
    )?;
    let scope_key = emergency_idempotency_scope_key(
        "disable_provider_endpoint",
        &provider_endpoint_id,
        &request.idempotency_key,
    );
    let request_hash = emergency_request_hash(&provider_endpoint_id, &request)?;
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let before = provider_endpoint_for_actor(&state, &actor, &provider_endpoint_id)?;
    let expected_version = required_emergency_expected_version(&request)?;
    let updated = state.store.update_provider_endpoint_status(
        &provider_endpoint_id,
        expected_version,
        ResourceStatus::Disabled,
        now,
    )?;
    set_endpoint_emergency_drain(&state, &updated, &request.reason, request.expires_at, now);
    let operation = create_emergency_operation_record(
        &state,
        &actor,
        EmergencyOperationInput {
            operation_kind: "disable_provider_endpoint",
            target_resource_kind: "ProviderEndpoint",
            target_resource_id: updated.provider_endpoint_id.clone(),
            organization_id: updated.organization_id.clone(),
            project_id: None,
            reason: request.reason.clone(),
            expires_at: request.expires_at,
        },
        now,
    )?;
    let audit_event_id = record_emergency_operation_audit(
        &state,
        &actor,
        &operation,
        Some(before.resource_version),
        Some(updated.resource_version),
        &json!({
            "target_status": {
                "before": before.status.as_str(),
                "after": updated.status.as_str()
            },
            "hot_state_drain_written": true
        }),
        now,
    );
    let affected_resource = provider_endpoint_resource_body(&updated);
    let response =
        emergency_operation_mutation_response(&operation, &affected_resource, &audit_event_id);
    record_idempotent_admin_response(
        &state,
        actor.tenant_id,
        scope_key,
        request_hash,
        &response,
        now,
    );
    Ok(Json(response))
}

async fn emergency_drain_routing_group(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(routing_group_id): Path<String>,
    Json(request): Json<AdminEmergencyOperationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_emergency_operation_request(&request, now)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_EMERGENCY_DRAIN_ROUTING_GROUP_PATH,
        &routing_group_id,
        now,
    )?;
    let scope_key = emergency_idempotency_scope_key(
        "drain_routing_group",
        &routing_group_id,
        &request.idempotency_key,
    );
    let request_hash = emergency_request_hash(&routing_group_id, &request)?;
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let before = routing_group_for_actor(&state, &actor, &routing_group_id)?;
    let expected_version = required_emergency_expected_version(&request)?;
    let updated = state.store.update_routing_group_status(
        &routing_group_id,
        expected_version,
        ResourceStatus::Draining,
        now,
    )?;
    let operation = create_emergency_operation_record(
        &state,
        &actor,
        EmergencyOperationInput {
            operation_kind: "drain_routing_group",
            target_resource_kind: "RoutingGroup",
            target_resource_id: updated.routing_group_id.clone(),
            organization_id: updated.organization_id.clone(),
            project_id: None,
            reason: request.reason.clone(),
            expires_at: request.expires_at,
        },
        now,
    )?;
    let audit_event_id = record_emergency_operation_audit(
        &state,
        &actor,
        &operation,
        Some(before.resource_version),
        Some(updated.resource_version),
        &json!({
            "target_status": {
                "before": before.status.as_str(),
                "after": updated.status.as_str()
            }
        }),
        now,
    );
    let affected_resource = routing_group_resource_body(&updated);
    let response =
        emergency_operation_mutation_response(&operation, &affected_resource, &audit_event_id);
    record_idempotent_admin_response(
        &state,
        actor.tenant_id,
        scope_key,
        request_hash,
        &response,
        now,
    );
    Ok(Json(response))
}

async fn emergency_freeze_config(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminEmergencyOperationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_emergency_operation_request(&request, now)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_EMERGENCY_FREEZE_CONFIG_PATH,
        &actor.tenant_id,
        now,
    )?;
    let scope_key = emergency_idempotency_scope_key(
        "freeze_config",
        &actor.tenant_id,
        &request.idempotency_key,
    );
    let request_hash = emergency_request_hash(&actor.tenant_id, &request)?;
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let operation = create_emergency_operation_record(
        &state,
        &actor,
        EmergencyOperationInput {
            operation_kind: "freeze_config",
            target_resource_kind: "Config",
            target_resource_id: actor.tenant_id.clone(),
            organization_id: None,
            project_id: None,
            reason: request.reason.clone(),
            expires_at: request.expires_at,
        },
        now,
    )?;
    let audit_event_id = record_emergency_operation_audit(
        &state,
        &actor,
        &operation,
        None,
        Some(operation.resource_version),
        &json!({
            "config_mutation_gate": "frozen"
        }),
        now,
    );
    let affected_resource = json!({
        "kind": "config",
        "id": &actor.tenant_id,
        "tenant_id": &actor.tenant_id,
        "status": "frozen",
        "expires_at": request.expires_at
    });
    let response =
        emergency_operation_mutation_response(&operation, &affected_resource, &audit_event_id);
    record_idempotent_admin_response(
        &state,
        actor.tenant_id,
        scope_key,
        request_hash,
        &response,
        now,
    );
    Ok(Json(response))
}

async fn validate_config_snapshot(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminValidateConfigSnapshotRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/config/snapshots:validate",
        &actor.tenant_id,
        now,
    )?;
    let errors = match validate_config_snapshot_payload(&request.payload) {
        Ok(()) => Vec::new(),
        Err(error) => vec![json!({
            "reason": error.code(),
            "message": error.to_string()
        })],
    };
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.config_snapshot_validation.v1",
            "ConfigSnapshot",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn publish_config_snapshot(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminPublishConfigSnapshotRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/config/snapshots:publish",
        &actor.tenant_id,
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("config_snapshots:publish", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }

    let before_version = state
        .store
        .latest_published_snapshot_for_tenant(&actor.tenant_id)
        .map(|snapshot| snapshot.version);
    let snapshot = publish_config_snapshot_document(
        &state.store,
        PublishConfigSnapshotRequest {
            tenant_id: actor.tenant_id.clone(),
            resource_versions: request.resource_versions,
            payload: request.payload,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_config_snapshot_audit(
        &state,
        &actor,
        ConfigSnapshotAuditInput {
            event_type: "gateway.config.publish",
            resource_id: snapshot.metadata.snapshot_id.clone(),
            before_version,
            after_version: Some(snapshot.metadata.version),
            redacted_diff: json!({
                "published_snapshot_id": &snapshot.metadata.snapshot_id,
                "checksum": &snapshot.metadata.checksum
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.config_snapshot_mutation.v1",
        "snapshot": snapshot,
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn rollback_config_snapshot(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminRollbackConfigSnapshotRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    validate_required_reason(&request.reason)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/config/snapshots:rollback",
        &request.source_snapshot_id,
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("config_snapshots:rollback", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }

    let before_version = state
        .store
        .latest_published_snapshot_for_tenant(&actor.tenant_id)
        .map(|snapshot| snapshot.version);
    let snapshot = rollback_config_snapshot_document(
        &state.store,
        actor.tenant_id.clone(),
        &request.source_snapshot_id,
        actor_principal_or_actor_id(&actor),
        now,
    )?;
    let audit_event_id = record_config_snapshot_audit(
        &state,
        &actor,
        ConfigSnapshotAuditInput {
            event_type: "gateway.config.rollback",
            resource_id: snapshot.metadata.snapshot_id.clone(),
            before_version,
            after_version: Some(snapshot.metadata.version),
            redacted_diff: json!({
                "rollback_of": request.source_snapshot_id,
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.config_snapshot_mutation.v1",
        "snapshot": snapshot,
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_realtime_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/realtime/overview",
        &actor.tenant_id,
        now,
    )?;
    let latest_config = state
        .store
        .latest_published_snapshot_for_tenant(&actor.tenant_id);
    let config_version = latest_config.as_ref().map(|snapshot| snapshot.version);
    let publication = state.store.config_publication(&actor.tenant_id);
    let provider_summary = realtime_provider_summary(&state, &actor.tenant_id, config_version, now);
    let route_summary = realtime_route_summary(&state, &actor.tenant_id);
    let worker_summary = realtime_worker_summary(&state, &actor.tenant_id, config_version);
    let otel_exporter_summary = realtime_otel_exporter_summary(&state, &actor.tenant_id);
    let validation_summary = validation_diagnostics_summary(&state, &actor.tenant_id);
    let budget_policy_count = state
        .store
        .budget_policies_for_tenant(&actor.tenant_id)
        .into_iter()
        .filter(|policy| policy.status != ResourceStatus::Deleted)
        .count();
    let quota_policy_count = state
        .store
        .quota_policies_for_tenant(&actor.tenant_id)
        .into_iter()
        .filter(|policy| policy.status != ResourceStatus::Deleted)
        .count();
    Ok(Json(json!({
        "schema": "gateway.admin.realtime_overview.v1",
        "source": {
            "kind": "redis_compatible_hot_state",
            "role": "builtin_realtime_dashboard",
            "metrics_backend_queried": false
        },
        "tenant_id": &actor.tenant_id,
        "generated_at": now,
        "freshness": {
            "status": provider_summary["freshness_status"],
            "source_freshness_timestamp": provider_summary["latest_observed_at"],
            "partial_data": true,
            "fallback_reason": "budget_quota_usage_hot_counters_not_connected"
        },
        "config": {
            "loaded_config_version": config_version,
            "snapshot_status": latest_config
                .as_ref()
                .map(|snapshot| snapshot.status.as_str().to_owned()),
            "publication": publication
                .as_ref()
                .map(config_publication_body)
        },
        "providers": provider_summary,
        "routes": route_summary,
        "validation": validation_summary,
        "budgets": {
            "configured_policy_count": budget_policy_count,
            "hot_state_status": "unavailable",
            "source": "policy_config_only"
        },
        "quotas": {
            "configured_policy_count": quota_policy_count,
            "hot_state_status": "unavailable",
            "source": "policy_config_only"
        },
        "workers": worker_summary,
        "otel_exporter": otel_exporter_summary,
        "unavailable_sources": [
            "usage_ledger_rollups",
            "budget_hot_counters",
            "quota_hot_counters",
            "worker_heartbeats"
        ]
    })))
}

async fn get_usage_summary(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageScopeQuery>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let scope = usage_scope_from_query(
        &state,
        &actor,
        query.scope_kind.as_deref(),
        query.scope_id.as_deref(),
    )?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USAGE_SUMMARY_PATH,
        &scope.scope_id,
        now,
    )?;
    let rollup = dashboard_usage_rollup(&state, &scope);
    Ok(Json(json!({
        "schema": "gateway.admin.usage_summary.v1",
        "scope": dashboard_scope_body(&scope),
        "generated_at": now,
        "measures": usage_rollup_measures_body(&rollup),
        "sources": {
            "usage_ledger_rollups": dashboard_usage_source(rollup.request_count > 0),
            "metrics_backend_queried": false
        }
    })))
}

async fn get_usage_timeseries(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageTimeseriesQuery>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let scope = usage_scope_from_query(
        &state,
        &actor,
        query.scope_kind.as_deref(),
        query.scope_id.as_deref(),
    )?;
    let bucket_kind = usage_bucket_kind(query.bucket_kind.as_deref())?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USAGE_TIMESERIES_PATH,
        &scope.scope_id,
        now,
    )?;
    Ok(Json(json!({
        "schema": "gateway.admin.usage_timeseries.v1",
        "scope": dashboard_scope_body(&scope),
        "bucket_kind": bucket_kind,
        "points": usage_timeseries_points(&state, &scope, bucket_kind),
        "sources": {
            "usage_ledger_rollups": "durable_ledger_buckets",
            "metrics_backend_queried": false
        }
    })))
}

async fn list_usage_events(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageEventsQuery>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let scope = usage_scope_from_query(
        &state,
        &actor,
        query.scope_kind.as_deref(),
        query.scope_id.as_deref(),
    )?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USAGE_EVENTS_PATH,
        &scope.scope_id,
        now,
    )?;
    let limit = usage_list_limit(query.limit)?;
    let offset = usage_list_offset(query.cursor.as_deref())?;
    let events = state
        .store
        .usage_events_for_tenant(&actor.tenant_id)
        .into_iter()
        .filter(|event| dashboard_usage_event_matches_scope(event, &scope))
        .filter(|event| usage_event_matches_query(event, &query))
        .collect::<Vec<_>>();
    let total_filtered_count = events.len();
    let page = events
        .iter()
        .skip(offset)
        .take(limit)
        .map(usage_event_body)
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(page.len());
    let next_cursor = (next_offset < total_filtered_count).then(|| next_offset.to_string());
    Ok(Json(json!({
        "schema": "gateway.admin.usage_event_list.v1",
        "scope": dashboard_scope_body(&scope),
        "events": page,
        "limit": limit,
        "cursor": query.cursor,
        "next_cursor": next_cursor,
        "total_filtered_count": total_filtered_count
    })))
}

async fn get_usage_breakdown_by_project(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageBreakdownQuery>,
) -> Result<Json<Value>> {
    get_usage_breakdown(
        &state,
        &actor,
        &query,
        ADMIN_USAGE_BREAKDOWN_BY_PROJECT_PATH,
        UsageBreakdownDimension::Project,
    )
}

async fn get_usage_breakdown_by_project_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageBreakdownQuery>,
) -> Result<Json<Value>> {
    get_usage_breakdown(
        &state,
        &actor,
        &query,
        ADMIN_USAGE_BREAKDOWN_BY_PROJECT_MEMBER_PATH,
        UsageBreakdownDimension::ProjectMember,
    )
}

async fn get_usage_breakdown_by_model(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageBreakdownQuery>,
) -> Result<Json<Value>> {
    get_usage_breakdown(
        &state,
        &actor,
        &query,
        ADMIN_USAGE_BREAKDOWN_BY_MODEL_PATH,
        UsageBreakdownDimension::Model,
    )
}

async fn get_usage_breakdown_by_provider_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Query(query): Query<AdminUsageBreakdownQuery>,
) -> Result<Json<Value>> {
    get_usage_breakdown(
        &state,
        &actor,
        &query,
        ADMIN_USAGE_BREAKDOWN_BY_PROVIDER_ENDPOINT_PATH,
        UsageBreakdownDimension::ProviderEndpoint,
    )
}

async fn get_tenant_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/dashboards/tenant/overview",
        &actor.tenant_id,
        now,
    )?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.tenant_overview.v1",
            tenant_id: tenant_id.clone(),
            scope_kind: "tenant",
            scope_id: tenant_id,
            organization_id: None,
            project_id: None,
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn get_organization_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_DASHBOARD_ORGANIZATION_PATH,
        &organization_id,
        now,
    )?;
    let organization = organization_for_actor(&state, &actor, &organization_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.organization_overview.v1",
            tenant_id,
            scope_kind: "organization",
            scope_id: organization.organization_id.clone(),
            organization_id: Some(organization.organization_id),
            project_id: None,
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn get_project_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(project_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_DASHBOARD_PROJECT_PATH,
        &project_id,
        now,
    )?;
    let project = project_for_actor(&state, &actor, &project_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.project_overview.v1",
            tenant_id,
            scope_kind: "project",
            scope_id: project.project_id.clone(),
            organization_id: Some(project.organization_id),
            project_id: Some(project.project_id),
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn get_project_member_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(project_member_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_DASHBOARD_PROJECT_MEMBER_PATH,
        &project_member_id,
        now,
    )?;
    let member = project_member_by_id_for_actor(&state, &actor, &project_member_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.project_member_overview.v1",
            tenant_id,
            scope_kind: "project_member",
            scope_id: member.project_member_id.clone(),
            organization_id: Some(member.organization_id),
            project_id: Some(member.project_id),
            project_member_id: Some(member.project_member_id),
            principal_id: Some(member.principal_id),
        },
        now,
    )))
}

async fn get_api_key_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(api_key_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_DASHBOARD_API_KEY_PATH,
        &api_key_id,
        now,
    )?;
    let api_key = api_key_for_actor(&state, &actor, &api_key_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.api_key_overview.v1",
            tenant_id,
            scope_kind: "api_key",
            scope_id: api_key.api_key_id,
            organization_id: api_key.organization_id,
            project_id: api_key.project_id,
            project_member_id: None,
            principal_id: Some(api_key.owner_principal_id),
        },
        now,
    )))
}

async fn get_service_account_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(service_account_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_DASHBOARD_SERVICE_ACCOUNT_PATH,
        &service_account_id,
        now,
    )?;
    let account = service_account_for_actor(&state, &actor, &service_account_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.service_account_overview.v1",
            tenant_id,
            scope_kind: "service_account",
            scope_id: account.service_account_id,
            organization_id: account.organization_id,
            project_id: account.project_id,
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn get_model_alias_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(model_alias_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_MODEL_ALIAS_DASHBOARD_PATH,
        &model_alias_id,
        now,
    )?;
    let alias = model_alias_for_actor(&state, &actor, &model_alias_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.model_alias_overview.v1",
            tenant_id,
            scope_kind: "model_alias",
            scope_id: alias.model_alias_id,
            organization_id: alias.organization_id,
            project_id: alias.project_id,
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn get_model_target_dashboard_overview(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(model_target_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_MODEL_TARGET_DASHBOARD_PATH,
        &model_target_id,
        now,
    )?;
    let target = model_target_for_actor(&state, &actor, &model_target_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.dashboard.model_target_overview.v1",
            tenant_id,
            scope_kind: "model_target",
            scope_id: target.model_target_id,
            organization_id: target.organization_id,
            project_id: None,
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn get_provider_endpoint_observability_usage(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(provider_endpoint_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PROVIDER_ENDPOINT_OBSERVABILITY_USAGE_PATH,
        &provider_endpoint_id,
        now,
    )?;
    let endpoint = provider_endpoint_for_actor(&state, &actor, &provider_endpoint_id)?;
    let tenant_id = actor.tenant_id;
    Ok(Json(dashboard_overview_response(
        &state,
        &DashboardScopeInput {
            schema: "gateway.admin.observability.provider_endpoint_usage.v1",
            tenant_id,
            scope_kind: "provider_endpoint",
            scope_id: endpoint.provider_endpoint_id,
            organization_id: endpoint.organization_id,
            project_id: None,
            project_member_id: None,
            principal_id: None,
        },
        now,
    )))
}

async fn list_projects(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(&state, &actor, &Method::GET, "/admin/v1/projects", "*", now)?;
    let route = route_metadata(&Method::GET, ADMIN_PROJECT_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .projects_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|project| AuthorizableItem {
                resource: route.resource(project.project_id.clone()),
                item: project,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(project_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.project_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn get_project(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(project_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PROJECT_GET_PATH,
        &project_id,
        now,
    )?;
    let project = project_for_actor(&state, &actor, &project_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.project.v1",
        "resource": project_resource_body(&project)
    })))
}

async fn update_project(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(project_id): Path<String>,
    Json(request): Json<AdminUpdateDirectoryStatusRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_PROJECT_GET_PATH,
        &project_id,
        now,
    )?;
    let before = project_for_actor(&state, &actor, &project_id)?;
    let updated = state.store.update_project_status(
        &project_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_project_audit(
        &state,
        &actor,
        ProjectAuditInput {
            project_id: updated.project_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.project_mutation.v1",
        "resource": project_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_organizations(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/organizations",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_ORGANIZATION_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .organizations_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|organization| AuthorizableItem {
                resource: route.resource(organization.organization_id.clone()),
                item: organization,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(organization_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.organization_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn get_organization(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ORGANIZATION_GET_PATH,
        &organization_id,
        now,
    )?;
    let organization = organization_for_actor(&state, &actor, &organization_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.organization.v1",
        "resource": organization_resource_body(&organization)
    })))
}

async fn update_organization(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(organization_id): Path<String>,
    Json(request): Json<AdminUpdateDirectoryStatusRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_ORGANIZATION_GET_PATH,
        &organization_id,
        now,
    )?;
    let before = organization_for_actor(&state, &actor, &organization_id)?;
    let updated = state.store.update_organization_status(
        &organization_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.organization.update",
            scope_kind: "organization",
            scope_id: updated.organization_id.clone(),
            resource_kind: "Organization",
            resource_id: updated.organization_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.organization_mutation.v1",
        "resource": organization_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_users(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(&state, &actor, &Method::GET, "/admin/v1/users", "*", now)?;
    let route = route_metadata(&Method::GET, ADMIN_USER_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .users_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|user| AuthorizableItem {
                resource: route.resource(user.user_id.clone()),
                item: user,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(user_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.user_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn get_user(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USER_GET_PATH,
        &user_id,
        now,
    )?;
    let user = user_for_actor(&state, &actor, &user_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.user.v1",
        "resource": user_resource_body(&user)
    })))
}

async fn update_user(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(user_id): Path<String>,
    Json(request): Json<AdminUpdateUserRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_user_status(&request.status)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_USER_GET_PATH,
        &user_id,
        now,
    )?;
    let before = user_for_actor(&state, &actor, &user_id)?;
    let updated =
        state
            .store
            .update_user_status(&user_id, request.expected_version, request.status, now)?;
    let revoked_session_count = if updated.status.accepts_access() {
        0
    } else {
        state
            .store
            .revoke_sessions_for_principal(&actor.tenant_id, &updated.user_id, now)
    };
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.user.disable",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "UserPrincipal",
            resource_id: updated.user_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "revoked_session_count": revoked_session_count,
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.user_mutation.v1",
        "resource": user_resource_body(&updated),
        "revoked_session_count": revoked_session_count,
        "audit_event_id": audit_event_id
    })))
}

async fn list_user_sessions(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let user = user_for_actor(&state, &actor, &user_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USER_SESSION_LIST_PATH,
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_USER_SESSION_LIST_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .sessions_for_principal(&actor.tenant_id, &user.user_id)
            .into_iter()
            .map(|session| AuthorizableItem {
                resource: route.resource(session.auth_session_id.clone()),
                item: session,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(auth_session_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.auth_session_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn revoke_user_session(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((user_id, auth_session_id)): Path<(String, String)>,
    Json(request): Json<AdminRevokeUserSessionRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let user = user_for_actor(&state, &actor, &user_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_USER_SESSION_REVOKE_PATH,
        &auth_session_id,
        now,
    )?;
    let before = auth_session_for_actor(&state, &actor, &user.user_id, &auth_session_id)?;
    let revoked = state.store.revoke_session_for_principal(
        &actor.tenant_id,
        &user.user_id,
        &auth_session_id,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.session.revoke",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "AuthSession",
            resource_id: revoked.auth_session_id.clone(),
            before_version: None,
            after_version: None,
            redacted_diff: json!({
                "principal_id": &revoked.principal_id,
                "status": {
                    "before": &before.status,
                    "after": &revoked.status
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.auth_session_mutation.v1",
        "resource": safe_auth_session_body(&revoked),
        "audit_event_id": audit_event_id
    })))
}

async fn list_user_external_identities(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(user_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let user = user_for_actor(&state, &actor, &user_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USER_EXTERNAL_IDENTITY_LIST_PATH,
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_USER_EXTERNAL_IDENTITY_LIST_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .external_identities_for_principal(&actor.tenant_id, &user.user_id)
            .into_iter()
            .map(|identity| AuthorizableItem {
                resource: route.resource(identity.external_identity_id.clone()),
                item: identity,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(external_identity_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.external_identity_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn get_user_external_identity(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((user_id, external_identity_id)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let user = user_for_actor(&state, &actor, &user_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_USER_EXTERNAL_IDENTITY_GET_PATH,
        &external_identity_id,
        now,
    )?;
    let identity =
        external_identity_for_actor(&state, &actor, &user.user_id, &external_identity_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.external_identity.v1",
        "resource": external_identity_resource_body(&identity)
    })))
}

async fn unlink_user_external_identity(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((user_id, external_identity_id)): Path<(String, String)>,
    Json(request): Json<AdminUnlinkExternalIdentityRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let user = user_for_actor(&state, &actor, &user_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_USER_EXTERNAL_IDENTITY_UNLINK_PATH,
        &external_identity_id,
        now,
    )?;
    let before = external_identity_for_actor(&state, &actor, &user.user_id, &external_identity_id)?;
    let unlinked = state.store.unlink_external_identity(
        &actor.tenant_id,
        &user.user_id,
        &external_identity_id,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.external_identity.unlink",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ExternalIdentity",
            resource_id: unlinked.external_identity_id.clone(),
            before_version: None,
            after_version: None,
            redacted_diff: json!({
                "principal_id": &unlinked.principal_id,
                "provider_kind": &unlinked.provider_kind,
                "status": {
                    "before": before.status.as_str(),
                    "after": unlinked.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.external_identity_mutation.v1",
        "resource": external_identity_resource_body(&unlinked),
        "audit_event_id": audit_event_id
    })))
}

async fn list_organization_members(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    organization_for_actor(&state, &actor, &organization_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ORGANIZATION_MEMBER_LIST_PATH,
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_ORGANIZATION_MEMBER_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .organization_members_for_organization(&organization_id)
            .into_iter()
            .map(|member| AuthorizableItem {
                resource: route.resource(member.organization_member_id.clone()),
                item: member,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(organization_member_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.organization_member_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn get_organization_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((organization_id, organization_member_id)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ORGANIZATION_MEMBER_GET_PATH,
        &organization_member_id,
        now,
    )?;
    let member =
        organization_member_for_actor(&state, &actor, &organization_id, &organization_member_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.organization_member.v1",
        "resource": organization_member_resource_body(&member)
    })))
}

async fn update_organization_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((organization_id, organization_member_id)): Path<(String, String)>,
    Json(request): Json<AdminUpdateMembershipRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_ORGANIZATION_MEMBER_GET_PATH,
        &organization_member_id,
        now,
    )?;
    let before =
        organization_member_for_actor(&state, &actor, &organization_id, &organization_member_id)?;
    let updated = state.store.update_organization_member_status(
        &organization_member_id,
        request.expected_version,
        request.status,
    )?;
    let cascaded_project_member_count = state
        .store
        .cascade_project_memberships_for_organization_member(&updated, updated.status.clone());
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.organization_member.update",
            scope_kind: "organization",
            scope_id: updated.organization_id.clone(),
            resource_kind: "OrganizationMember",
            resource_id: updated.organization_member_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "cascaded_project_member_count": cascaded_project_member_count,
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.organization_member_mutation.v1",
        "resource": organization_member_resource_body(&updated),
        "cascaded_project_member_count": cascaded_project_member_count,
        "audit_event_id": audit_event_id
    })))
}

async fn list_project_members(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(project_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    project_for_actor(&state, &actor, &project_id)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PROJECT_MEMBER_LIST_PATH,
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_PROJECT_MEMBER_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .project_members_for_project(&project_id)
            .into_iter()
            .map(|member| AuthorizableItem {
                resource: route.resource(member.project_member_id.clone()),
                item: member,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(project_member_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.project_member_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn create_project_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(project_id): Path<String>,
    Json(request): Json<AdminCreateProjectMemberRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let project = project_for_actor(&state, &actor, &project_id)?;
    if !project.status.accepts_access() {
        return Err(GatewayError::BadRequest {
            message: "project_not_active".to_owned(),
        });
    }
    let user = user_for_actor(&state, &actor, &request.principal_id)?;
    if !user.status.accepts_access() {
        return Err(GatewayError::BadRequest {
            message: "project_member_principal_inactive".to_owned(),
        });
    }
    let organization_member = active_organization_member_for_project_assignment(
        &state,
        &actor,
        &project.organization_id,
        &user.user_id,
        request.organization_member_id.as_deref(),
    )?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_PROJECT_MEMBER_LIST_PATH,
        "*",
        now,
    )?;
    let scope_key = idempotency_scope_key(
        "project_members:create",
        &format!("{}:{}", project.project_id, request.idempotency_key),
    );
    let request_hash = stable_request_hash(&request)?;
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let member = state
        .store
        .create_project_membership(CreateProjectMembershipRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: project.organization_id,
            project_id: project.project_id,
            principal_id: user.user_id,
            organization_member_id: organization_member.organization_member_id,
        })?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.project_member.create",
            scope_kind: "project",
            scope_id: member.project_id.clone(),
            resource_kind: "ProjectMember",
            resource_id: member.project_member_id.clone(),
            before_version: None,
            after_version: Some(member.resource_version),
            redacted_diff: json!({
                "principal_id": &member.principal_id,
                "organization_id": &member.organization_id,
                "organization_member_id": &member.organization_member_id,
                "status": member.status.as_str()
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.project_member_mutation.v1",
        "resource": project_member_resource_body(&member),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_project_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((project_id, project_member_id)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PROJECT_MEMBER_GET_PATH,
        &project_member_id,
        now,
    )?;
    let member = project_member_for_actor(&state, &actor, &project_id, &project_member_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.project_member.v1",
        "resource": project_member_resource_body(&member)
    })))
}

async fn update_project_member(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((project_id, project_member_id)): Path<(String, String)>,
    Json(request): Json<AdminUpdateMembershipRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_PROJECT_MEMBER_GET_PATH,
        &project_member_id,
        now,
    )?;
    let before = project_member_for_actor(&state, &actor, &project_id, &project_member_id)?;
    let updated = state.store.update_project_member_status(
        &project_member_id,
        request.expected_version,
        request.status,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.project_member.update",
            scope_kind: "project",
            scope_id: updated.project_id.clone(),
            resource_kind: "ProjectMember",
            resource_id: updated.project_member_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.project_member_mutation.v1",
        "resource": project_member_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_service_accounts(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/service-accounts",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_SERVICE_ACCOUNT_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .service_accounts_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|account| AuthorizableItem {
                resource: route.resource(account.service_account_id.clone()),
                item: account,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(service_account_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.service_account_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn create_service_account(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateServiceAccountRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/service-accounts",
        "*",
        now,
    )?;
    let scope_key = idempotency_scope_key("service_accounts:create", &request.idempotency_key);
    let request_hash = stable_request_hash(&request)?;
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let account = state.store.create_service_account(
        CreateServiceAccountRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            display_name: request.display_name.trim().to_owned(),
            created_by: actor.actor_id.clone(),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.service_account.create",
            scope_kind: "service_account",
            scope_id: account.service_account_id.clone(),
            resource_kind: "ServiceAccount",
            resource_id: account.service_account_id.clone(),
            before_version: None,
            after_version: Some(account.resource_version),
            redacted_diff: json!({
                "created": true,
                "organization_id": account.organization_id.as_deref(),
                "project_id": account.project_id.as_deref(),
                "display_name": &account.display_name
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.service_account_mutation.v1",
        "resource": service_account_resource_body(&account),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_service_account(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(service_account_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_SERVICE_ACCOUNT_GET_PATH,
        &service_account_id,
        now,
    )?;
    let account = service_account_for_actor(&state, &actor, &service_account_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.service_account.v1",
        "resource": service_account_resource_body(&account)
    })))
}

async fn update_service_account(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(service_account_id): Path<String>,
    Json(request): Json<AdminUpdateDirectoryStatusRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_SERVICE_ACCOUNT_GET_PATH,
        &service_account_id,
        now,
    )?;
    let before = service_account_for_actor(&state, &actor, &service_account_id)?;
    let updated = state.store.update_service_account_status(
        &service_account_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.service_account.update",
            scope_kind: "service_account",
            scope_id: updated.service_account_id.clone(),
            resource_kind: "ServiceAccount",
            resource_id: updated.service_account_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.service_account_mutation.v1",
        "resource": service_account_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_provider_endpoints(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/provider-endpoints",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_PROVIDER_ENDPOINT_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .provider_endpoints_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|endpoint| AuthorizableItem {
                resource: route.resource(endpoint.provider_endpoint_id.clone()),
                item: endpoint,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(provider_endpoint_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.provider_endpoint_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_provider_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateProviderEndpointRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/provider-endpoints:validate",
        "*",
        now,
    )?;
    let errors = provider_endpoint_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.provider_endpoint_validation.v1",
            "ProviderEndpoint",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_provider_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateProviderEndpointRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/provider-endpoints",
        "*",
        now,
    )?;
    reject_validation_errors(&provider_endpoint_validation_errors(
        &state, &actor, &request,
    ))?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("provider_endpoints:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let endpoint = state.store.create_provider_endpoint(
        CreateProviderEndpointRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            provider_kind: request.provider_kind,
            display_name: request.display_name,
            protocol_families: request.protocol_families,
            upstream_base_url: request.upstream_base_url,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.provider_endpoint.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ProviderEndpoint",
            resource_id: endpoint.provider_endpoint_id.clone(),
            before_version: None,
            after_version: Some(endpoint.resource_version),
            redacted_diff: json!({
                "provider_kind": &endpoint.provider_kind,
                "protocol_families": &endpoint.protocol_families,
                "upstream_base_url": redact_url_for_audit(&endpoint.upstream_base_url)
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.provider_endpoint_mutation.v1",
        "resource": provider_endpoint_resource_body(&endpoint),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_provider_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(provider_endpoint_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PROVIDER_ENDPOINT_GET_PATH,
        &provider_endpoint_id,
        now,
    )?;
    let endpoint = provider_endpoint_for_actor(&state, &actor, &provider_endpoint_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.provider_endpoint.v1",
        "resource": provider_endpoint_resource_body(&endpoint)
    })))
}

async fn update_provider_endpoint(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(provider_endpoint_id): Path<String>,
    Json(request): Json<AdminUpdateProviderEndpointRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_PROVIDER_ENDPOINT_GET_PATH,
        &provider_endpoint_id,
        now,
    )?;
    let before = provider_endpoint_for_actor(&state, &actor, &provider_endpoint_id)?;
    let updated = state.store.update_provider_endpoint_status(
        &provider_endpoint_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.provider_endpoint.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ProviderEndpoint",
            resource_id: updated.provider_endpoint_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.provider_endpoint_mutation.v1",
        "resource": provider_endpoint_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_upstream_credentials(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/upstream-credentials",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_UPSTREAM_CREDENTIAL_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .upstream_credentials_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|credential| AuthorizableItem {
                resource: route.resource(credential.upstream_credential_id.clone()),
                item: credential,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(upstream_credential_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.upstream_credential_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_upstream_credential(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateUpstreamCredentialRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/upstream-credentials:validate",
        "*",
        now,
    )?;
    let errors = upstream_credential_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.upstream_credential_validation.v1",
            "UpstreamCredential",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_upstream_credential(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateUpstreamCredentialRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/upstream-credentials",
        "*",
        now,
    )?;
    reject_validation_errors(&upstream_credential_validation_errors(
        &state, &actor, &request,
    ))?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("upstream_credentials:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let credential = state.store.create_upstream_credential(
        CreateUpstreamCredentialRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            provider_endpoint_id: request.provider_endpoint_id,
            credential_kind: request.credential_kind,
            secret_ref_id: request.secret_ref_id,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.upstream_credential.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "UpstreamCredential",
            resource_id: credential.upstream_credential_id.clone(),
            before_version: None,
            after_version: Some(credential.resource_version),
            redacted_diff: json!({
                "provider_endpoint_id": &credential.provider_endpoint_id,
                "credential_kind": &credential.credential_kind,
                "secret_ref_id": mask_secret_ref_id(&credential.secret_ref_id)
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.upstream_credential_mutation.v1",
        "resource": upstream_credential_resource_body(&credential),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_upstream_credential(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(upstream_credential_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_UPSTREAM_CREDENTIAL_GET_PATH,
        &upstream_credential_id,
        now,
    )?;
    let credential = upstream_credential_for_actor(&state, &actor, &upstream_credential_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.upstream_credential.v1",
        "resource": upstream_credential_resource_body(&credential)
    })))
}

async fn update_upstream_credential(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(upstream_credential_id): Path<String>,
    Json(request): Json<AdminUpdateUpstreamCredentialRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_UPSTREAM_CREDENTIAL_GET_PATH,
        &upstream_credential_id,
        now,
    )?;
    let before = upstream_credential_for_actor(&state, &actor, &upstream_credential_id)?;
    let updated = state.store.update_upstream_credential_status(
        &upstream_credential_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.upstream_credential.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "UpstreamCredential",
            resource_id: updated.upstream_credential_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.upstream_credential_mutation.v1",
        "resource": upstream_credential_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_secret_refs(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/secret-refs",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_SECRET_REF_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .secret_refs_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|secret_ref| AuthorizableItem {
                resource: route.resource(secret_ref.secret_ref_id.clone()),
                item: secret_ref,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(secret_ref_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.secret_ref_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn create_secret_ref(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateSecretRefRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/secret-refs",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("secret_refs:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let secret_ref = state.store.create_secret_ref(
        CreateSecretRefRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            purpose: request.purpose,
            backend_kind: request.backend_kind,
            secret_value: SecretString::from(request.secret_value),
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.secret_ref.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "SecretRef",
            resource_id: secret_ref.secret_ref_id.clone(),
            before_version: None,
            after_version: Some(secret_ref.resource_version),
            redacted_diff: json!({
                "organization_id": &secret_ref.organization_id,
                "project_id": &secret_ref.project_id,
                "purpose": &secret_ref.purpose,
                "backend_kind": &secret_ref.backend_kind,
                "display_mask": &secret_ref.display_mask,
                "fingerprint": &secret_ref.fingerprint
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.secret_ref_mutation.v1",
        "resource": secret_ref_resource_body(&secret_ref),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_secret_ref(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(secret_ref_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_SECRET_REF_GET_PATH,
        &secret_ref_id,
        now,
    )?;
    let secret_ref = secret_ref_for_actor(&state, &actor, &secret_ref_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.secret_ref.v1",
        "resource": secret_ref_resource_body(&secret_ref)
    })))
}

async fn get_secret_ref_locator(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(secret_ref_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_SECRET_REF_LOCATOR_PATH,
        &secret_ref_id,
        now,
    )?;
    let secret_ref = secret_ref_for_actor(&state, &actor, &secret_ref_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.secret_ref_locator.v1",
        "resource": secret_ref_locator_resource_body(&secret_ref)
    })))
}

async fn list_model_targets(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/model-targets",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_MODEL_TARGET_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .model_targets_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|target| AuthorizableItem {
                resource: route.resource(target.model_target_id.clone()),
                item: target,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(model_target_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.model_target_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_model_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateModelTargetRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/model-targets:validate",
        "*",
        now,
    )?;
    let errors = model_target_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.model_target_validation.v1",
            "ModelTarget",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_model_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateModelTargetRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/model-targets",
        "*",
        now,
    )?;
    reject_validation_errors(&model_target_validation_errors(&state, &actor, &request))?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("model_targets:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    let target = state.store.create_model_target(
        CreateModelTargetRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            provider_endpoint_id: request.provider_endpoint_id,
            upstream_credential_id: request.upstream_credential_id,
            protocol_family: request.protocol_family,
            upstream_model_id: request.upstream_model_id,
            supports_streaming: request.supports_streaming,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.model_target.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ModelTarget",
            resource_id: target.model_target_id.clone(),
            before_version: None,
            after_version: Some(target.resource_version),
            redacted_diff: json!({
                "provider_endpoint_id": &target.provider_endpoint_id,
                "upstream_credential_id": &target.upstream_credential_id,
                "protocol_family": target.protocol_family.as_str(),
                "upstream_model_id": &target.upstream_model_id
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.model_target_mutation.v1",
        "resource": model_target_resource_body(&target),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_model_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(model_target_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_MODEL_TARGET_GET_PATH,
        &model_target_id,
        now,
    )?;
    let target = model_target_for_actor(&state, &actor, &model_target_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.model_target.v1",
        "resource": model_target_resource_body(&target)
    })))
}

async fn update_model_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(model_target_id): Path<String>,
    Json(request): Json<AdminUpdateModelTargetRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_MODEL_TARGET_GET_PATH,
        &model_target_id,
        now,
    )?;
    let before = model_target_for_actor(&state, &actor, &model_target_id)?;
    let updated = state.store.update_model_target_status(
        &model_target_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.model_target.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ModelTarget",
            resource_id: updated.model_target_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.model_target_mutation.v1",
        "resource": model_target_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_model_aliases(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/model-aliases",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_MODEL_ALIAS_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .model_aliases_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|alias| AuthorizableItem {
                resource: route.resource(alias.model_alias_id.clone()),
                item: alias,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(model_alias_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.model_alias_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_model_alias(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateModelAliasRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/model-aliases:validate",
        "*",
        now,
    )?;
    let errors = model_alias_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.model_alias_validation.v1",
            "ModelAlias",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_model_alias(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateModelAliasRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/model-aliases",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("model_aliases:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&model_alias_validation_errors(&state, &actor, &request))?;
    let alias = state.store.create_model_alias(
        CreateModelAliasRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            alias_name: request.alias_name,
            protocol_family: request.protocol_family,
            route_policy_id: request.route_policy_id,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.model_alias.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ModelAlias",
            resource_id: alias.model_alias_id.clone(),
            before_version: None,
            after_version: Some(alias.resource_version),
            redacted_diff: json!({
                "organization_id": &alias.organization_id,
                "project_id": &alias.project_id,
                "alias_name": &alias.alias_name,
                "protocol_family": alias.protocol_family.as_str(),
                "route_policy_id": &alias.route_policy_id
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.model_alias_mutation.v1",
        "resource": model_alias_resource_body(&alias),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_model_alias(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(model_alias_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_MODEL_ALIAS_GET_PATH,
        &model_alias_id,
        now,
    )?;
    let alias = model_alias_for_actor(&state, &actor, &model_alias_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.model_alias.v1",
        "resource": model_alias_resource_body(&alias)
    })))
}

async fn update_model_alias(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(model_alias_id): Path<String>,
    Json(request): Json<AdminUpdateModelAliasRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_MODEL_ALIAS_GET_PATH,
        &model_alias_id,
        now,
    )?;
    let before = model_alias_for_actor(&state, &actor, &model_alias_id)?;
    reject_validation_errors(&model_alias_update_validation_errors(
        &state,
        &actor,
        &model_alias_id,
        &request,
    ))?;
    let updated = state.store.update_model_alias(
        &model_alias_id,
        UpdateModelAliasRequest {
            expected_resource_version: request.expected_version,
            status: request.status,
            route_policy_id: request.route_policy_id,
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.model_alias.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ModelAlias",
            resource_id: updated.model_alias_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "route_policy_id": {
                    "before": before.route_policy_id,
                    "after": updated.route_policy_id
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.model_alias_mutation.v1",
        "resource": model_alias_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_pricing_skus(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/pricing-skus",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_PRICING_SKU_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .pricing_skus_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|sku| AuthorizableItem {
                resource: route.resource(sku.pricing_sku_id.clone()),
                item: sku,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(pricing_sku_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.pricing_sku_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_pricing_sku(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreatePricingSkuRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/pricing-skus:validate",
        "*",
        now,
    )?;
    let errors = pricing_sku_validation_errors(&state, &actor, &request, now);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.pricing_sku_validation.v1",
            "PricingSku",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_pricing_sku(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreatePricingSkuRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/pricing-skus",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("pricing_skus:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&pricing_sku_validation_errors(
        &state, &actor, &request, now,
    ))?;
    let sku = state.store.create_pricing_sku(
        CreatePricingSkuRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            name: request.name,
            currency: request.currency,
            unit: request.unit,
            model_id_patterns: request.model_id_patterns,
            provider_endpoint_patterns: request.provider_endpoint_patterns,
            pricing_document: request.pricing_document,
            effective_from: request.effective_from.unwrap_or(now),
            effective_until: request.effective_until,
            is_preset: request.is_preset,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.pricing_sku.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "PricingSku",
            resource_id: sku.pricing_sku_id.clone(),
            before_version: None,
            after_version: Some(sku.resource_version),
            redacted_diff: json!({
                "organization_id": &sku.organization_id,
                "name": &sku.name,
                "currency": &sku.currency,
                "unit": &sku.unit,
                "pricing_version": sku.pricing_version,
                "model_id_patterns": &sku.model_id_patterns,
                "provider_endpoint_patterns": &sku.provider_endpoint_patterns,
                "effective_from": sku.effective_from,
                "effective_until": sku.effective_until,
                "is_preset": sku.is_preset
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.pricing_sku_mutation.v1",
        "resource": pricing_sku_resource_body(&sku),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_pricing_sku(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(pricing_sku_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PRICING_SKU_GET_PATH,
        &pricing_sku_id,
        now,
    )?;
    let sku = pricing_sku_for_actor(&state, &actor, &pricing_sku_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.pricing_sku.v1",
        "resource": pricing_sku_resource_body(&sku)
    })))
}

async fn update_pricing_sku(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(pricing_sku_id): Path<String>,
    Json(request): Json<AdminUpdatePricingSkuRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_PRICING_SKU_GET_PATH,
        &pricing_sku_id,
        now,
    )?;
    let before = pricing_sku_for_actor(&state, &actor, &pricing_sku_id)?;
    let updated = state.store.update_pricing_sku_status(
        &pricing_sku_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.pricing_sku.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "PricingSku",
            resource_id: updated.pricing_sku_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.pricing_sku_mutation.v1",
        "resource": pricing_sku_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_budget_policies(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/budget-policies",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_BUDGET_POLICY_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .budget_policies_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|policy| AuthorizableItem {
                resource: route.resource(policy.budget_policy_id.clone()),
                item: policy,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(budget_policy_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.budget_policy_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_budget_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateBudgetPolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/budget-policies:validate",
        "*",
        now,
    )?;
    let errors = budget_policy_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.budget_policy_validation.v1",
            "BudgetPolicy",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_budget_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateBudgetPolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/budget-policies",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("budget_policies:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&budget_policy_validation_errors(&state, &actor, &request))?;
    let policy = state.store.create_budget_policy(
        CreateBudgetPolicyRequest {
            tenant_id: actor.tenant_id.clone(),
            scope_kind: request.scope_kind,
            scope_id: request.scope_id,
            currency: request.currency,
            period: request.period,
            limit_kind: request.limit_kind,
            hard_limit: request.hard_limit,
            soft_limit: request.soft_limit,
            thresholds: request.thresholds,
            reset_policy: request.reset_policy,
            overage_mode: request.overage_mode,
            consistency_mode: request.consistency_mode,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.budget_policy.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "BudgetPolicy",
            resource_id: policy.budget_policy_id.clone(),
            before_version: None,
            after_version: Some(policy.resource_version),
            redacted_diff: json!({
                "scope_kind": &policy.scope_kind,
                "scope_id": &policy.scope_id,
                "currency": &policy.currency,
                "period": &policy.period,
                "limit_kind": &policy.limit_kind,
                "hard_limit": policy.hard_limit,
                "soft_limit": policy.soft_limit,
                "thresholds": &policy.thresholds,
                "reset_policy": &policy.reset_policy,
                "overage_mode": &policy.overage_mode,
                "consistency_mode": &policy.consistency_mode
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.budget_policy_mutation.v1",
        "resource": budget_policy_resource_body(&policy),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_budget_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(budget_policy_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_BUDGET_POLICY_GET_PATH,
        &budget_policy_id,
        now,
    )?;
    let policy = budget_policy_for_actor(&state, &actor, &budget_policy_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.budget_policy.v1",
        "resource": budget_policy_resource_body(&policy)
    })))
}

async fn update_budget_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(budget_policy_id): Path<String>,
    Json(request): Json<AdminUpdateBudgetPolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_BUDGET_POLICY_GET_PATH,
        &budget_policy_id,
        now,
    )?;
    let before = budget_policy_for_actor(&state, &actor, &budget_policy_id)?;
    let updated = state.store.update_budget_policy_status(
        &budget_policy_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.budget_policy.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "BudgetPolicy",
            resource_id: updated.budget_policy_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.budget_policy_mutation.v1",
        "resource": budget_policy_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_quota_policies(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/quota-policies",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_QUOTA_POLICY_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .quota_policies_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|policy| AuthorizableItem {
                resource: route.resource(policy.quota_policy_id.clone()),
                item: policy,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(quota_policy_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.quota_policy_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_quota_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateQuotaPolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/quota-policies:validate",
        "*",
        now,
    )?;
    let errors = quota_policy_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.quota_policy_validation.v1",
            "QuotaPolicy",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_quota_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateQuotaPolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/quota-policies",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("quota_policies:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&quota_policy_validation_errors(&state, &actor, &request))?;
    let policy = state.store.create_quota_policy(
        CreateQuotaPolicyRequest {
            tenant_id: actor.tenant_id.clone(),
            scope_kind: request.scope_kind,
            scope_id: request.scope_id,
            counter_kind: request.counter_kind,
            limit: request.limit,
            burst_limit: request.burst_limit,
            window: request.window,
            increment_source: request.increment_source,
            loss_behavior: request.loss_behavior,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.quota_policy.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "QuotaPolicy",
            resource_id: policy.quota_policy_id.clone(),
            before_version: None,
            after_version: Some(policy.resource_version),
            redacted_diff: json!({
                "scope_kind": &policy.scope_kind,
                "scope_id": &policy.scope_id,
                "counter_kind": &policy.counter_kind,
                "limit": policy.limit,
                "burst_limit": policy.burst_limit,
                "window": &policy.window,
                "increment_source": &policy.increment_source,
                "loss_behavior": &policy.loss_behavior
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.quota_policy_mutation.v1",
        "resource": quota_policy_resource_body(&policy),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_quota_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(quota_policy_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_QUOTA_POLICY_GET_PATH,
        &quota_policy_id,
        now,
    )?;
    let policy = quota_policy_for_actor(&state, &actor, &quota_policy_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.quota_policy.v1",
        "resource": quota_policy_resource_body(&policy)
    })))
}

async fn update_quota_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(quota_policy_id): Path<String>,
    Json(request): Json<AdminUpdateQuotaPolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_QUOTA_POLICY_GET_PATH,
        &quota_policy_id,
        now,
    )?;
    let before = quota_policy_for_actor(&state, &actor, &quota_policy_id)?;
    let updated = state.store.update_quota_policy_status(
        &quota_policy_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.quota_policy.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "QuotaPolicy",
            resource_id: updated.quota_policy_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.quota_policy_mutation.v1",
        "resource": quota_policy_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_otel_export_configs(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/observability/otel-export/configs",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_OTEL_EXPORT_CONFIG_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .otel_export_configs_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|config| AuthorizableItem {
                resource: route.resource(config.otel_export_config_id.clone()),
                item: config,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(|config| otel_export_config_resource_envelope(&state, config))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.otel_export_config_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_otel_export_config(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(otel_export_config_id): Path<String>,
    Json(request): Json<AdminCreateOtelExportConfigRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_OTEL_EXPORT_CONFIG_VALIDATE_PATH,
        &otel_export_config_id,
        now,
    )?;
    let errors = otel_export_config_validation_errors(
        &state,
        &actor,
        &request,
        Some(&otel_export_config_id),
    );
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.otel_export_config_validation.v1",
            "OpenTelemetryExportConfig",
            "otel_export_config",
            otel_export_config_id,
            errors,
            now,
        ),
    ))
}

async fn create_otel_export_config(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateOtelExportConfigRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/observability/otel-export/configs",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("otel_export_configs:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&otel_export_config_validation_errors(
        &state, &actor, &request, None,
    ))?;
    let config = state.store.create_otel_export_config(
        CreateOtelExportConfigRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            endpoint_url: request.endpoint_url,
            protocol: request.protocol,
            header_refs: request.header_refs,
            enabled_signals: request.enabled_signals,
            resource_attributes: request.resource_attributes,
            export_interval_seconds: request.export_interval_seconds,
            timeout_seconds: request.timeout_seconds,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.observability_export.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "OpenTelemetryExportConfig",
            resource_id: config.otel_export_config_id.clone(),
            before_version: None,
            after_version: Some(config.resource_version),
            redacted_diff: otel_export_config_create_diff(&config),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.otel_export_config_mutation.v1",
        "resource": otel_export_config_resource_body(&state, &config),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_otel_export_config(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(otel_export_config_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_OTEL_EXPORT_CONFIG_GET_PATH,
        &otel_export_config_id,
        now,
    )?;
    let config = otel_export_config_for_actor(&state, &actor, &otel_export_config_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.otel_export_config.v1",
        "resource": otel_export_config_resource_body(&state, &config)
    })))
}

async fn update_otel_export_config(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(otel_export_config_id): Path<String>,
    Json(request): Json<AdminUpdateOtelExportConfigRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_OTEL_EXPORT_CONFIG_GET_PATH,
        &otel_export_config_id,
        now,
    )?;
    let before = otel_export_config_for_actor(&state, &actor, &otel_export_config_id)?;
    let merged_request = merged_otel_export_config_request(&before, &request);
    reject_validation_errors(&otel_export_config_validation_errors(
        &state,
        &actor,
        &merged_request,
        Some(&otel_export_config_id),
    ))?;
    let updated = state.store.update_otel_export_config(
        &otel_export_config_id,
        UpdateOtelExportConfigRequest {
            expected_resource_version: request.expected_version,
            organization_id: request.organization_id,
            project_id: request.project_id,
            endpoint_url: request.endpoint_url,
            protocol: request.protocol,
            header_refs: request.header_refs,
            enabled_signals: request.enabled_signals,
            resource_attributes: request.resource_attributes,
            export_interval_seconds: request.export_interval_seconds,
            timeout_seconds: request.timeout_seconds,
            status: request.status,
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.observability_export.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "OpenTelemetryExportConfig",
            resource_id: updated.otel_export_config_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: otel_export_config_update_diff(
                &before,
                &updated,
                request.reason.as_deref(),
            ),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.otel_export_config_mutation.v1",
        "resource": otel_export_config_resource_body(&state, &updated),
        "audit_event_id": audit_event_id
    })))
}

async fn disable_otel_export_config(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(otel_export_config_id): Path<String>,
    Json(request): Json<AdminDisableOtelExportConfigRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_required_reason(&request.reason)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_OTEL_EXPORT_CONFIG_DISABLE_PATH,
        &otel_export_config_id,
        now,
    )?;
    let before = otel_export_config_for_actor(&state, &actor, &otel_export_config_id)?;
    let updated = state.store.update_otel_export_config(
        &otel_export_config_id,
        UpdateOtelExportConfigRequest {
            expected_resource_version: request.expected_version,
            organization_id: None,
            project_id: None,
            endpoint_url: None,
            protocol: None,
            header_refs: None,
            enabled_signals: None,
            resource_attributes: None,
            export_interval_seconds: None,
            timeout_seconds: None,
            status: Some(ResourceStatus::Disabled),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.observability_export.disable",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "OpenTelemetryExportConfig",
            resource_id: updated.otel_export_config_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: otel_export_config_update_diff(
                &before,
                &updated,
                Some(request.reason.as_str()),
            ),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.otel_export_config_mutation.v1",
        "resource": otel_export_config_resource_body(&state, &updated),
        "audit_event_id": audit_event_id
    })))
}

/// Runs one deterministic OpenTelemetry metrics export tick for a tenant.
///
/// This worker records exporter health evidence without requiring a live
/// collector during local validation. A collector outage updates health and
/// dropped metric counts, but it never blocks model ingress.
pub fn run_otel_exporter_once(
    store: &InMemoryGatewayStore,
    tenant_id: &str,
    worker_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<OtelExporterRunSummary> {
    let configs = store.otel_export_configs_for_tenant(tenant_id);
    let mut summary = OtelExporterRunSummary {
        tenant_id: tenant_id.to_owned(),
        worker_id: worker_id.to_owned(),
        attempted_config_count: 0,
        succeeded_count: 0,
        failed_count: 0,
        disabled_count: 0,
        exported_metric_count: 0,
        dropped_metric_count: 0,
    };

    for config in configs {
        summary.attempted_config_count += 1;
        let metric_count = otel_export_metric_count(store, &config);
        let (status, exported_metric_count, dropped_metric_count, last_error) =
            if config.status != ResourceStatus::Active {
                summary.disabled_count += 1;
                ("disabled", 0, 0, None)
            } else if otel_export_endpoint_unavailable(&config) {
                summary.failed_count += 1;
                summary.dropped_metric_count =
                    summary.dropped_metric_count.saturating_add(metric_count);
                (
                    "retryable_failed",
                    0,
                    metric_count,
                    Some("collector_unavailable".to_owned()),
                )
            } else {
                summary.succeeded_count += 1;
                summary.exported_metric_count =
                    summary.exported_metric_count.saturating_add(metric_count);
                ("succeeded", metric_count, 0, None)
            };

        store.record_otel_exporter_health(
            RecordOtelExporterHealthRequest {
                tenant_id: tenant_id.to_owned(),
                otel_export_config_id: config.otel_export_config_id,
                worker_id: worker_id.to_owned(),
                status: status.to_owned(),
                exported_metric_count,
                dropped_metric_count,
                last_error,
            },
            now,
        )?;
    }

    Ok(summary)
}

fn otel_export_metric_count(store: &InMemoryGatewayStore, config: &OtelExportConfigRecord) -> i64 {
    let ledger_count = store
        .ledger_buckets_for_tenant(&config.tenant_id)
        .into_iter()
        .filter(|bucket| {
            otel_config_scope_matches(
                config,
                bucket.organization_id.as_deref(),
                bucket.project_id.as_deref(),
            )
        })
        .fold(0_i64, |count, _| count.saturating_add(1));
    let usage_event_count = store
        .usage_events_for_tenant(&config.tenant_id)
        .into_iter()
        .filter(|event| {
            otel_config_scope_matches(
                config,
                event.organization_id.as_deref(),
                event.project_id.as_deref(),
            )
        })
        .fold(0_i64, |count, _| count.saturating_add(1));
    let route_decision_count = store
        .route_decisions()
        .into_iter()
        .filter(|decision| {
            decision.tenant_id == config.tenant_id
                && otel_config_scope_matches(
                    config,
                    decision.organization_id.as_deref(),
                    decision.project_id.as_deref(),
                )
        })
        .fold(0_i64, |count, _| count.saturating_add(1));

    6_i64
        .saturating_add(ledger_count.saturating_mul(6))
        .saturating_add(usage_event_count.saturating_mul(4))
        .saturating_add(route_decision_count.saturating_mul(3))
}

fn otel_config_scope_matches(
    config: &OtelExportConfigRecord,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> bool {
    config
        .organization_id
        .as_deref()
        .is_none_or(|expected| organization_id == Some(expected))
        && config
            .project_id
            .as_deref()
            .is_none_or(|expected| project_id == Some(expected))
}

fn otel_export_endpoint_unavailable(config: &OtelExportConfigRecord) -> bool {
    safe_otel_endpoint_host(&config.endpoint_url).is_none_or(|host| {
        let host = host.to_ascii_lowercase();
        host.contains("unreachable") || host.contains("blackhole") || host.contains("fail")
    })
}

async fn list_notification_sinks(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/notification/sinks",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_NOTIFICATION_SINK_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .notification_sinks_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|sink| AuthorizableItem {
                resource: route.resource(sink.notification_sink_id.clone()),
                item: sink,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(notification_sink_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.notification_sink_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_notification_sink(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateNotificationSinkRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/notification/sinks:validate",
        "*",
        now,
    )?;
    let errors = notification_sink_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.notification_sink_validation.v1",
            "NotificationSink",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_notification_sink(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateNotificationSinkRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/notification/sinks",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("notification_sinks:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&notification_sink_validation_errors(
        &state, &actor, &request,
    ))?;
    let sink = state.store.create_notification_sink(
        CreateNotificationSinkRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            project_id: request.project_id,
            name: request.name,
            sink_kind: request.sink_kind,
            endpoint_config: request.endpoint_config,
            signing_secret_ref_id: request.signing_secret_ref_id,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.notification_sink.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "NotificationSink",
            resource_id: sink.notification_sink_id.clone(),
            before_version: None,
            after_version: Some(sink.resource_version),
            redacted_diff: notification_sink_create_diff(&sink),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.notification_sink_mutation.v1",
        "resource": notification_sink_resource_body(&sink),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_notification_sink(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(notification_sink_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_NOTIFICATION_SINK_GET_PATH,
        &notification_sink_id,
        now,
    )?;
    let sink = notification_sink_for_actor(&state, &actor, &notification_sink_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.notification_sink.v1",
        "resource": notification_sink_resource_body(&sink)
    })))
}

async fn update_notification_sink(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(notification_sink_id): Path<String>,
    Json(request): Json<AdminUpdateNotificationSinkRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    if let Some(status) = request.status.as_ref() {
        validate_notification_sink_status(status)?;
    }
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_NOTIFICATION_SINK_GET_PATH,
        &notification_sink_id,
        now,
    )?;
    let before = notification_sink_for_actor(&state, &actor, &notification_sink_id)?;
    let merged_request = merged_notification_sink_request(&before, &request);
    reject_validation_errors(&notification_sink_validation_errors_with_excluded_id(
        &state,
        &actor,
        &merged_request,
        Some(&notification_sink_id),
    ))?;
    let updated = state.store.update_notification_sink(
        &notification_sink_id,
        UpdateNotificationSinkRequest {
            expected_resource_version: request.expected_version,
            name: request.name,
            endpoint_config: request.endpoint_config,
            signing_secret_ref_id: request.signing_secret_ref_id,
            status: request.status,
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.notification_sink.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "NotificationSink",
            resource_id: updated.notification_sink_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: notification_sink_update_diff(
                &before,
                &updated,
                request.reason.as_deref(),
            ),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.notification_sink_mutation.v1",
        "resource": notification_sink_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_notification_subscriptions(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(notification_sink_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_NOTIFICATION_SUBSCRIPTION_LIST_PATH,
        &notification_sink_id,
        now,
    )?;
    let sink = notification_sink_for_actor(&state, &actor, &notification_sink_id)?;
    let resources = state
        .store
        .notification_subscriptions_for_sink(&sink.notification_sink_id)
        .into_iter()
        .filter(|subscription| subscription.tenant_id == actor.tenant_id)
        .map(|subscription| notification_subscription_resource_envelope(&subscription))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.notification_subscription_list.v1",
        "resources": resources,
        "filtered_count": 0,
        "next_cursor": null
    })))
}

async fn validate_notification_subscription(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(notification_sink_id): Path<String>,
    Json(request): Json<AdminCreateNotificationSubscriptionRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_NOTIFICATION_SUBSCRIPTION_VALIDATE_PATH,
        &notification_sink_id,
        now,
    )?;
    let errors = notification_subscription_validation_errors(
        &state,
        &actor,
        &notification_sink_id,
        &request,
    );
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.notification_subscription_validation.v1",
            "NotificationSubscription",
            "notification_sink",
            notification_sink_id,
            errors,
            now,
        ),
    ))
}

async fn create_notification_subscription(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(notification_sink_id): Path<String>,
    Json(request): Json<AdminCreateNotificationSubscriptionRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_NOTIFICATION_SUBSCRIPTION_LIST_PATH,
        &notification_sink_id,
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key(
        &format!("notification_subscriptions:create:{notification_sink_id}"),
        &request.idempotency_key,
    );
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&notification_subscription_validation_errors(
        &state,
        &actor,
        &notification_sink_id,
        &request,
    ))?;
    let subscription = state.store.create_notification_subscription(
        CreateNotificationSubscriptionRequest {
            tenant_id: actor.tenant_id.clone(),
            notification_sink_id,
            event_family: request.event_family,
            filter_document: request.filter_document,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.notification_subscription.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "NotificationSink",
            resource_id: subscription.notification_sink_id.clone(),
            before_version: None,
            after_version: Some(subscription.resource_version),
            redacted_diff: notification_subscription_create_diff(&subscription),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.notification_subscription_mutation.v1",
        "resource": notification_subscription_resource_body(&subscription),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_notification_subscription(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((notification_sink_id, notification_subscription_id)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_NOTIFICATION_SUBSCRIPTION_GET_PATH,
        &notification_sink_id,
        now,
    )?;
    let subscription = notification_subscription_for_actor(
        &state,
        &actor,
        &notification_sink_id,
        &notification_subscription_id,
    )?;
    Ok(Json(json!({
        "schema": "gateway.admin.notification_subscription.v1",
        "resource": notification_subscription_resource_body(&subscription)
    })))
}

async fn update_notification_subscription(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((notification_sink_id, notification_subscription_id)): Path<(String, String)>,
    Json(request): Json<AdminUpdateNotificationSubscriptionRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_notification_subscription_status(&request.status)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_NOTIFICATION_SUBSCRIPTION_GET_PATH,
        &notification_sink_id,
        now,
    )?;
    let before = notification_subscription_for_actor(
        &state,
        &actor,
        &notification_sink_id,
        &notification_subscription_id,
    )?;
    let updated = state.store.update_notification_subscription_status(
        &notification_subscription_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.notification_subscription.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "NotificationSink",
            resource_id: updated.notification_sink_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "notification_subscription_id": &updated.notification_subscription_id,
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.notification_subscription_mutation.v1",
        "resource": notification_subscription_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_login_providers(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/identity-providers",
        &actor.tenant_id,
        now,
    )?;
    let resources = state
        .store
        .login_providers_for_tenant(&actor.tenant_id)
        .iter()
        .map(login_provider_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.identity_provider_list.v1",
        "resources": resources,
        "next_cursor": null
    })))
}

async fn validate_login_provider(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateLoginProviderRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/identity-providers:validate",
        &actor.tenant_id,
        now,
    )?;
    let errors = login_provider_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.identity_provider_validation.v1",
            "IdentityProvider",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_login_provider(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateLoginProviderRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/identity-providers",
        &actor.tenant_id,
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("identity_providers:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&login_provider_validation_errors(&state, &actor, &request))?;
    let provider = state.store.create_login_provider(
        CreateLoginProviderRequest {
            tenant_id: actor.tenant_id.clone(),
            provider_kind: request.provider_kind,
            display_name: request.display_name,
            config_document: request.config_document,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.identity_provider.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "IdentityProvider",
            resource_id: provider.login_provider_id.clone(),
            before_version: None,
            after_version: Some(provider.resource_version),
            redacted_diff: login_provider_create_diff(&provider),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.identity_provider_mutation.v1",
        "resource": login_provider_resource_body(&provider),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_login_provider(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(login_provider_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_LOGIN_PROVIDER_GET_PATH,
        &login_provider_id,
        now,
    )?;
    let provider = login_provider_for_actor(&state, &actor, &login_provider_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.identity_provider.v1",
        "resource": login_provider_resource_body(&provider)
    })))
}

async fn update_login_provider(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(login_provider_id): Path<String>,
    Json(request): Json<AdminUpdateLoginProviderRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_login_provider_status(&request.status)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_LOGIN_PROVIDER_GET_PATH,
        &login_provider_id,
        now,
    )?;
    let before = login_provider_for_actor(&state, &actor, &login_provider_id)?;
    let updated = state.store.update_login_provider_status(
        &login_provider_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.identity_provider.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "IdentityProvider",
            resource_id: updated.login_provider_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.identity_provider_mutation.v1",
        "resource": login_provider_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_organization_invitations(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ORGANIZATION_INVITATION_LIST_PATH,
        &organization_id,
        now,
    )?;
    let organization = organization_for_actor(&state, &actor, &organization_id)?;
    let resources = state
        .store
        .organization_invitations(&actor.tenant_id, &organization.organization_id)
        .iter()
        .map(organization_invitation_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.organization_invitation_list.v1",
        "resources": resources,
        "next_cursor": null
    })))
}

async fn create_organization_invitation(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(organization_id): Path<String>,
    Json(request): Json<AdminCreateOrganizationInvitationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_ORGANIZATION_INVITATION_LIST_PATH,
        &organization_id,
        now,
    )?;
    let organization = active_organization_for_actor(&state, &actor, &organization_id)?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key(
        &format!("organization_invitations:create:{organization_id}"),
        &request.idempotency_key,
    );
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&organization_invitation_validation_errors(
        &state,
        &actor,
        &organization,
        &request,
        now,
    ))?;
    let raw_token = generate_invitation_token();
    let invitation = state.store.create_organization_invitation(
        CreateOrganizationInvitationRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: organization.organization_id.clone(),
            project_id: request.project_id,
            invited_email: request
                .invited_email
                .and_then(|email| normalized_email(&email)),
            invited_principal_id: request
                .invited_principal_id
                .map(|principal_id| principal_id.trim().to_owned())
                .filter(|principal_id| !principal_id.is_empty()),
            invitation_token_hash: invitation_token_hash(&raw_token),
            role_id: request
                .role_id
                .map(|role_id| role_id.trim().to_owned())
                .filter(|role_id| !role_id.is_empty())
                .unwrap_or_else(|| "organization_member".to_owned()),
            expires_at: request
                .expires_at
                .unwrap_or_else(|| now + chrono::Duration::days(7)),
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.organization_invite.create",
            scope_kind: "organization",
            scope_id: organization.organization_id,
            resource_kind: "OrganizationInvite",
            resource_id: invitation.invitation_id.clone(),
            before_version: None,
            after_version: Some(invitation.resource_version),
            redacted_diff: organization_invitation_create_diff(&invitation),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.organization_invitation_mutation.v1",
        "resource": organization_invitation_resource_body(&invitation),
        "invitation_token": raw_token,
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response_without_invitation_token(&response),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_organization_invitation(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((organization_id, invitation_id)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ORGANIZATION_INVITATION_GET_PATH,
        &invitation_id,
        now,
    )?;
    organization_for_actor(&state, &actor, &organization_id)?;
    let invitation =
        organization_invitation_for_actor(&state, &actor, &organization_id, &invitation_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.organization_invitation.v1",
        "resource": organization_invitation_resource_body(&invitation)
    })))
}

async fn revoke_organization_invitation(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((organization_id, invitation_id)): Path<(String, String)>,
    Json(request): Json<AdminRevokeOrganizationInvitationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_ORGANIZATION_INVITATION_REVOKE_PATH,
        &invitation_id,
        now,
    )?;
    organization_for_actor(&state, &actor, &organization_id)?;
    let before =
        organization_invitation_for_actor(&state, &actor, &organization_id, &invitation_id)?;
    let revoked = state.store.revoke_organization_invitation(
        &invitation_id,
        request.expected_version,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.organization_invite.revoke",
            scope_kind: "organization",
            scope_id: organization_id,
            resource_kind: "OrganizationInvite",
            resource_id: revoked.invitation_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(revoked.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": revoked.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.organization_invitation_mutation.v1",
        "resource": organization_invitation_resource_body(&revoked),
        "audit_event_id": audit_event_id
    })))
}

async fn list_auth_login_providers(
    State(state): State<AppState>,
    Query(query): Query<AuthProviderListQuery>,
) -> Result<Json<Value>> {
    let mut resources = Vec::new();
    if state.config.single_user_auth.is_some()
        && query.tenant_id.as_deref().is_none_or(|tenant_id| {
            state
                .config
                .single_user_auth
                .as_ref()
                .is_some_and(|config| config.tenant_id == tenant_id)
        })
    {
        if let Some(config) = state.config.single_user_auth.as_ref() {
            resources.push(single_user_auth_provider_resource_body(config));
        }
    }
    if let Some(tenant_id) = query.tenant_id {
        resources.extend(
            state
                .store
                .login_providers_for_tenant(&tenant_id)
                .into_iter()
                .filter(|provider| provider.status == ResourceStatus::Active)
                .map(|provider| auth_login_provider_resource_body(&provider)),
        );
    }
    Ok(Json(json!({
        "schema": "gateway.auth.provider_list.v1",
        "resources": resources,
        "next_cursor": null
    })))
}

async fn get_auth_login_provider(
    State(state): State<AppState>,
    Path(login_provider_id): Path<String>,
) -> Result<Json<Value>> {
    if login_provider_id == SINGLE_USER_PROVIDER_ID {
        return single_user_provider_response(&state);
    }
    let provider = active_login_provider(&state, &login_provider_id)?;
    Ok(Json(json!({
        "schema": "gateway.auth.provider.v1",
        "resource": auth_login_provider_resource_body(&provider)
    })))
}

async fn start_auth_login_provider(
    State(state): State<AppState>,
    Path(login_provider_id): Path<String>,
) -> Result<Json<Value>> {
    if login_provider_id == SINGLE_USER_PROVIDER_ID {
        if state.config.single_user_auth.is_none() {
            return Err(GatewayError::NotFound {
                resource: format!("login provider {SINGLE_USER_PROVIDER_ID}"),
            });
        }
        return Err(GatewayError::BadRequest {
            message: "single_user_provider_uses_password_login".to_owned(),
        });
    }
    let provider = active_login_provider(&state, &login_provider_id)?;
    let start = login_provider_start_response(&provider)?;
    Ok(Json(json!({
        "schema": "gateway.auth.login_start.v1",
        "provider": auth_login_provider_resource_body(&provider),
        "authorization": start
    })))
}

async fn preview_auth_invitation(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let invitation = invitation_by_raw_token(&state, &token)?;
    let organization = state
        .store
        .organization(&invitation.organization_id)
        .filter(|organization| organization.tenant_id == invitation.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: "organization invitation".to_owned(),
        })?;
    let project = invitation
        .project_id
        .as_deref()
        .and_then(|project_id| state.store.project(project_id))
        .filter(|project| project.tenant_id == invitation.tenant_id);
    Ok(Json(json!({
        "schema": "gateway.auth.invitation_preview.v1",
        "resource": organization_invitation_preview_body(
            &organization,
            project.as_ref(),
            &invitation,
            now
        )
    })))
}

async fn accept_auth_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let session = verify_auth_session_from_headers(&state, &headers, now)?;
    let invitation = invitation_by_raw_token(&state, &token)?;
    verify_session_matches_invitation(&state, &session, &invitation)?;
    let accepted = state.store.accept_organization_invitation(
        &invitation.invitation_id,
        &session.principal_id,
        now,
    )?;
    let updated_session = state.store.update_session_active_context_by_hash(
        &session.session_hash,
        Some(accepted.organization_id.clone()),
        accepted.project_id.clone(),
        now,
    )?;
    let actor = AuthenticatedActor::for_user_session(
        ActorScope::new(
            accepted.tenant_id.clone(),
            Some(accepted.organization_id.clone()),
            accepted.project_id.clone(),
        ),
        session.principal_id.clone(),
        session.auth_session_id.clone(),
        request_id_from_headers(&headers),
        Some(session.expires_at),
    );
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.organization_invite.accept",
            scope_kind: "organization",
            scope_id: accepted.organization_id.clone(),
            resource_kind: "OrganizationInvite",
            resource_id: accepted.invitation_id.clone(),
            before_version: Some(invitation.resource_version),
            after_version: Some(accepted.resource_version),
            redacted_diff: json!({
                "accepted_principal_id": &session.principal_id,
                "organization_id": &accepted.organization_id,
                "project_id": &accepted.project_id,
                "role_id": &accepted.role_id,
                "status": {
                    "before": invitation.status.as_str(),
                    "after": accepted.status.as_str()
                }
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.auth.invitation_accept.v1",
        "resource": organization_invitation_resource_body(&accepted),
        "session": auth_session_response_body(&state, &updated_session),
        "audit_event_id": audit_event_id
    })))
}

async fn single_user_login(
    State(state): State<AppState>,
    Json(request): Json<SingleUserLoginRequest>,
) -> Result<Json<Value>> {
    let config = state
        .config
        .single_user_auth
        .as_ref()
        .ok_or(GatewayError::NotReady)?;
    if !single_user_credentials_match(config, &request) {
        return Err(GatewayError::Authentication);
    }
    let now = chrono::Utc::now();
    bootstrap_single_user_if_configured(&state.store, &state.config, now)?;
    let session = create_auth_session(
        CreateAuthSessionRequest {
            tenant_id: config.tenant_id.clone(),
            principal_id: config.user_id.clone(),
            active_organization_id: Some(config.organization_id.clone()),
            active_project_id: Some(config.project_id.clone()),
            expires_at: now + chrono::Duration::seconds(config.session_ttl_seconds),
        },
        now,
    );
    let raw_token = session.raw_token.expose_secret().to_owned();
    let expires_at = session.record.expires_at;
    state.store.insert_auth_session(session.record);
    Ok(Json(json!({
        "schema": "gateway.auth.single_user_login.v1",
        "session": {
            "token_type": "Bearer",
            "session_token": raw_token,
            "expires_at": expires_at
        },
        "user": {
            "id": &config.user_id,
            "display_name": &config.user_display_name,
            "primary_email": &config.user_primary_email
        },
        "tenant": {
            "id": &config.tenant_id,
            "display_name": &config.tenant_display_name
        },
        "organization": {
            "id": &config.organization_id,
            "display_name": &config.organization_display_name
        },
        "project": {
            "id": &config.project_id,
            "display_name": &config.project_display_name
        }
    })))
}

async fn get_current_auth_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let session = verify_auth_session_from_headers(&state, &headers, now)?;
    Ok(Json(auth_session_response_body(&state, &session)))
}

async fn update_session_default_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SessionDefaultOrganizationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let session = verify_auth_session_from_headers(&state, &headers, now)?;
    let organization_id = normalized_auth_context_id(&request.organization_id, "organization_id")?;
    let organization = active_organization_for_session(&state, &session, &organization_id)?;
    let project = select_session_project_for_organization(
        &state,
        &session,
        &organization_id,
        request.project_id.as_deref(),
    )?;
    let active_project_id = project
        .as_ref()
        .map(|membership| membership.project_id.clone());
    state.store.update_user_default_context(
        &session.principal_id,
        Some(organization.organization_id.clone()),
        active_project_id.clone(),
        now,
    )?;
    let updated = state.store.update_session_active_context_by_hash(
        &session.session_hash,
        Some(organization.organization_id),
        active_project_id,
        now,
    )?;
    Ok(Json(auth_session_response_body(&state, &updated)))
}

async fn update_session_active_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SessionActiveOrganizationRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let session = verify_auth_session_from_headers(&state, &headers, now)?;
    let organization_id = normalized_auth_context_id(&request.organization_id, "organization_id")?;
    let organization = active_organization_for_session(&state, &session, &organization_id)?;
    let project = select_session_project_for_organization(
        &state,
        &session,
        &organization_id,
        request.project_id.as_deref(),
    )?;
    let updated = state.store.update_session_active_context_by_hash(
        &session.session_hash,
        Some(organization.organization_id),
        project.map(|membership| membership.project_id),
        now,
    )?;
    Ok(Json(auth_session_response_body(&state, &updated)))
}

async fn update_session_active_project(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SessionActiveProjectRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let session = verify_auth_session_from_headers(&state, &headers, now)?;
    let project_id = normalized_auth_context_id(&request.project_id, "project_id")?;
    let project = active_project_for_session(&state, &session, &project_id, None)?;
    let updated = state.store.update_session_active_context_by_hash(
        &session.session_hash,
        Some(project.organization_id),
        Some(project.project_id),
        now,
    )?;
    Ok(Json(auth_session_response_body(&state, &updated)))
}

async fn logout_current_auth_session(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let session = verify_auth_session_from_headers(&state, &headers, now)?;
    let revoked = state
        .store
        .revoke_session_by_hash(&session.session_hash, now)?;
    Ok(Json(json!({
        "schema": "gateway.auth.logout.v1",
        "session": safe_auth_session_body(&revoked)
    })))
}

fn verify_auth_session_from_headers(
    state: &AppState,
    headers: &HeaderMap,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AuthSessionRecord> {
    let presented_token = bearer_token(headers)?;
    if !presented_token.starts_with(SESSION_TOKEN_PREFIX) {
        return Err(GatewayError::Authentication);
    }
    let session = verify_session_token(state.store(), presented_token, now)?;
    let user = state
        .store
        .user(&session.principal_id)
        .ok_or(GatewayError::Authentication)?;
    if user.status != DirectoryStatus::Active {
        return Err(GatewayError::Authentication);
    }
    Ok(session)
}

fn normalized_auth_context_id(value: &str, field_name: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(GatewayError::BadRequest {
            message: format!("{field_name}_required"),
        });
    }
    Ok(trimmed.to_owned())
}

fn active_organization_for_session(
    state: &AppState,
    session: &AuthSessionRecord,
    organization_id: &str,
) -> Result<OrganizationRecord> {
    let organization = state
        .store
        .organization(organization_id)
        .filter(|organization| organization.tenant_id == session.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        })?;
    if !organization.status.accepts_access() {
        return Err(GatewayError::Authorization {
            reason: "organization_inactive",
        });
    }
    let has_membership = state
        .store
        .organization_memberships_for_principal(&session.principal_id)
        .into_iter()
        .any(|membership| {
            membership.tenant_id == session.tenant_id
                && membership.organization_id == organization_id
                && membership.status.accepts_access()
        });
    if !has_membership {
        return Err(GatewayError::Authorization {
            reason: "organization_membership_required",
        });
    }
    Ok(organization)
}

fn active_project_for_session(
    state: &AppState,
    session: &AuthSessionRecord,
    project_id: &str,
    required_organization_id: Option<&str>,
) -> Result<ProjectRecord> {
    let project = state
        .store
        .project(project_id)
        .filter(|project| project.tenant_id == session.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("project {project_id}"),
        })?;
    if required_organization_id
        .is_some_and(|organization_id| organization_id != project.organization_id.as_str())
    {
        return Err(GatewayError::Authorization {
            reason: "project_organization_mismatch",
        });
    }
    if !project.status.accepts_access() {
        return Err(GatewayError::Authorization {
            reason: "project_inactive",
        });
    }
    active_organization_for_session(state, session, &project.organization_id)?;
    let membership = state
        .store
        .project_membership(&session.principal_id, project_id)
        .ok_or(GatewayError::Authorization {
            reason: "project_membership_required",
        })?;
    if !membership.status.accepts_access() {
        return Err(GatewayError::Authorization {
            reason: "project_membership_inactive",
        });
    }
    Ok(project)
}

fn select_session_project_for_organization(
    state: &AppState,
    session: &AuthSessionRecord,
    organization_id: &str,
    requested_project_id: Option<&str>,
) -> Result<Option<ProjectMembershipRecord>> {
    if let Some(project_id) = requested_project_id {
        let project_id = normalized_auth_context_id(project_id, "project_id")?;
        let project =
            active_project_for_session(state, session, &project_id, Some(organization_id))?;
        return Ok(state
            .store
            .project_membership(&session.principal_id, &project.project_id));
    }

    let user = state.store.user(&session.principal_id);
    let mut candidate_ids = Vec::new();
    if let Some(project_id) = user
        .as_ref()
        .and_then(|user| user.default_project_id.as_deref())
    {
        candidate_ids.push(project_id.to_owned());
    }
    if let Some(project_id) = session.active_project_id.as_deref() {
        if !candidate_ids
            .iter()
            .any(|candidate| candidate == project_id)
        {
            candidate_ids.push(project_id.to_owned());
        }
    }
    for membership in state
        .store
        .project_memberships_for_principal(&session.principal_id)
        .into_iter()
        .filter(|membership| {
            membership.tenant_id == session.tenant_id
                && membership.organization_id == organization_id
                && membership.status.accepts_access()
        })
    {
        if !candidate_ids
            .iter()
            .any(|candidate| candidate == &membership.project_id)
        {
            candidate_ids.push(membership.project_id);
        }
    }

    for project_id in candidate_ids {
        if active_project_for_session(state, session, &project_id, Some(organization_id)).is_ok() {
            return Ok(state
                .store
                .project_membership(&session.principal_id, &project_id));
        }
    }
    Ok(None)
}

fn invitation_by_raw_token(
    state: &AppState,
    raw_token: &str,
) -> Result<OrganizationInvitationRecord> {
    if raw_token.trim().is_empty() || !raw_token.starts_with("gwinv_") {
        return Err(GatewayError::NotFound {
            resource: "organization invitation".to_owned(),
        });
    }
    state
        .store
        .organization_invitation_by_token_hash(&invitation_token_hash(raw_token))
        .ok_or_else(|| GatewayError::NotFound {
            resource: "organization invitation".to_owned(),
        })
}

fn verify_session_matches_invitation(
    state: &AppState,
    session: &AuthSessionRecord,
    invitation: &OrganizationInvitationRecord,
) -> Result<()> {
    if session.tenant_id != invitation.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "invitation_tenant_mismatch",
        });
    }
    if invitation
        .invited_principal_id
        .as_deref()
        .is_some_and(|principal_id| principal_id == session.principal_id)
    {
        return Ok(());
    }
    let Some(invited_email) = invitation.invited_email.as_deref() else {
        return Err(GatewayError::Authorization {
            reason: "invitation_principal_mismatch",
        });
    };
    let user = state
        .store
        .user(&session.principal_id)
        .ok_or(GatewayError::Authentication)?;
    if user
        .primary_email
        .as_deref()
        .and_then(normalized_email)
        .as_deref()
        == Some(invited_email)
    {
        Ok(())
    } else {
        Err(GatewayError::Authorization {
            reason: "invitation_email_mismatch",
        })
    }
}

fn auth_session_response_body(state: &AppState, session: &AuthSessionRecord) -> Value {
    let user = state.store.user(&session.principal_id);
    let organization_memberships = state
        .store
        .organization_memberships_for_principal(&session.principal_id)
        .into_iter()
        .filter(|membership| membership.tenant_id == session.tenant_id)
        .collect::<Vec<_>>();
    let project_memberships = state
        .store
        .project_memberships_for_principal(&session.principal_id)
        .into_iter()
        .filter(|membership| membership.tenant_id == session.tenant_id)
        .collect::<Vec<_>>();
    json!({
        "schema": "gateway.auth.session.v1",
        "session": safe_auth_session_body(session),
        "user": user.as_ref().map(user_session_resource_body),
        "organization_memberships": organization_memberships
            .iter()
            .map(organization_member_resource_body)
            .collect::<Vec<_>>(),
        "project_memberships": project_memberships
            .iter()
            .map(project_member_resource_body)
            .collect::<Vec<_>>()
    })
}

async fn list_route_policies(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/route-policies",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_ROUTE_POLICY_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .route_policies_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|policy| AuthorizableItem {
                resource: route.resource(policy.route_policy_id.clone()),
                item: policy,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(route_policy_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.route_policy_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_route_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateRoutePolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/route-policies:validate",
        "*",
        now,
    )?;
    let errors = route_policy_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.route_policy_validation.v1",
            "RoutePolicy",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_route_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateRoutePolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/route-policies",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("route_policies:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&route_policy_validation_errors(&state, &actor, &request))?;
    let policy = state.store.create_route_policy(
        CreateRoutePolicyRequest {
            tenant_id: actor.tenant_id.clone(),
            name: request.name,
            model_alias_id: request.model_alias_id,
            routing_group_id: request.routing_group_id,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.route_policy.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "RoutePolicy",
            resource_id: policy.route_policy_id.clone(),
            before_version: None,
            after_version: Some(policy.resource_version),
            redacted_diff: json!({
                "organization_id": &policy.organization_id,
                "name": &policy.name,
                "protocol_family": policy.protocol_family.as_str(),
                "model_alias_id": &policy.model_alias_id,
                "routing_group_id": &policy.routing_group_id
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.route_policy_mutation.v1",
        "resource": route_policy_resource_body(&policy),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_route_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(route_policy_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ROUTE_POLICY_GET_PATH,
        &route_policy_id,
        now,
    )?;
    let policy = route_policy_for_actor(&state, &actor, &route_policy_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.route_policy.v1",
        "resource": route_policy_resource_body(&policy)
    })))
}

async fn update_route_policy(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(route_policy_id): Path<String>,
    Json(request): Json<AdminUpdateRoutePolicyRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_ROUTE_POLICY_GET_PATH,
        &route_policy_id,
        now,
    )?;
    let before = route_policy_for_actor(&state, &actor, &route_policy_id)?;
    let updated = state.store.update_route_policy_status(
        &route_policy_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.route_policy.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "RoutePolicy",
            resource_id: updated.route_policy_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.route_policy_mutation.v1",
        "resource": route_policy_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_provider_grants(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/provider-grants",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_PROVIDER_GRANT_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .provider_grants_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|grant| AuthorizableItem {
                resource: route.resource(grant.provider_grant_id.clone()),
                item: grant,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(provider_grant_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.provider_grant_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_provider_grant(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateProviderGrantRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/provider-grants:validate",
        "*",
        now,
    )?;
    let errors = provider_grant_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.provider_grant_validation.v1",
            "ProviderGrant",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_provider_grant(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateProviderGrantRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/provider-grants",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("provider_grants:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&provider_grant_validation_errors(&state, &actor, &request))?;
    let grant = state.store.create_provider_grant(
        CreateProviderGrantRequest {
            tenant_id: actor.tenant_id.clone(),
            scope_kind: request.scope_kind,
            scope_id: request.scope_id,
            resource_kind: request.resource_kind,
            resource_id: request.resource_id,
            effect: request.effect,
            closure_mode: request.closure_mode,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.provider_grant.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ProviderGrant",
            resource_id: grant.provider_grant_id.clone(),
            before_version: None,
            after_version: Some(grant.resource_version),
            redacted_diff: json!({
                "scope_kind": &grant.scope_kind,
                "scope_id": &grant.scope_id,
                "resource_kind": &grant.resource_kind,
                "resource_id": &grant.resource_id,
                "effect": &grant.effect,
                "closure_mode": &grant.closure_mode
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.provider_grant_mutation.v1",
        "resource": provider_grant_resource_body(&grant),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_provider_grant(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(provider_grant_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_PROVIDER_GRANT_GET_PATH,
        &provider_grant_id,
        now,
    )?;
    let grant = provider_grant_for_actor(&state, &actor, &provider_grant_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.provider_grant.v1",
        "resource": provider_grant_resource_body(&grant)
    })))
}

async fn update_provider_grant(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(provider_grant_id): Path<String>,
    Json(request): Json<AdminUpdateProviderGrantRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_PROVIDER_GRANT_GET_PATH,
        &provider_grant_id,
        now,
    )?;
    let before = provider_grant_for_actor(&state, &actor, &provider_grant_id)?;
    let updated = state.store.update_provider_grant_status(
        &provider_grant_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.provider_grant.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "ProviderGrant",
            resource_id: updated.provider_grant_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.provider_grant_mutation.v1",
        "resource": provider_grant_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_routing_groups(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        "/admin/v1/routing-groups",
        "*",
        now,
    )?;
    let route = route_metadata(&Method::GET, ADMIN_ROUTING_GROUP_GET_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .routing_groups_for_tenant(&actor.tenant_id)
            .into_iter()
            .map(|group| AuthorizableItem {
                resource: route.resource(group.routing_group_id.clone()),
                item: group,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(routing_group_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.routing_group_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_routing_group(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateRoutingGroupRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/routing-groups:validate",
        "*",
        now,
    )?;
    let errors = routing_group_validation_errors(&state, &actor, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.routing_group_validation.v1",
            "RoutingGroup",
            "tenant",
            actor.tenant_id.clone(),
            errors,
            now,
        ),
    ))
}

async fn create_routing_group(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Json(request): Json<AdminCreateRoutingGroupRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        "/admin/v1/routing-groups",
        "*",
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key("routing_groups:create", &request.idempotency_key);
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&routing_group_validation_errors(&state, &actor, &request))?;
    let group = state.store.create_routing_group(
        CreateRoutingGroupRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: request.organization_id,
            name: request.name,
            protocol_family: request.protocol_family,
            purpose: request.purpose,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.routing_group.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "RoutingGroup",
            resource_id: group.routing_group_id.clone(),
            before_version: None,
            after_version: Some(group.resource_version),
            redacted_diff: json!({
                "organization_id": &group.organization_id,
                "name": &group.name,
                "protocol_family": group.protocol_family.as_str(),
                "purpose": &group.purpose
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.routing_group_mutation.v1",
        "resource": routing_group_resource_body(&group),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_routing_group(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(routing_group_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ROUTING_GROUP_GET_PATH,
        &routing_group_id,
        now,
    )?;
    let group = routing_group_for_actor(&state, &actor, &routing_group_id)?;
    Ok(Json(json!({
        "schema": "gateway.admin.routing_group.v1",
        "resource": routing_group_resource_body(&group)
    })))
}

async fn update_routing_group(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(routing_group_id): Path<String>,
    Json(request): Json<AdminUpdateRoutingGroupRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_ROUTING_GROUP_GET_PATH,
        &routing_group_id,
        now,
    )?;
    let before = routing_group_for_actor(&state, &actor, &routing_group_id)?;
    let updated = state.store.update_routing_group_status(
        &routing_group_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.routing_group.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "RoutingGroup",
            resource_id: updated.routing_group_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.routing_group_mutation.v1",
        "resource": routing_group_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn list_routing_group_targets(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(routing_group_id): Path<String>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ROUTING_GROUP_TARGET_LIST_PATH,
        &routing_group_id,
        now,
    )?;
    routing_group_for_actor(&state, &actor, &routing_group_id)?;
    let route = route_metadata(&Method::GET, ADMIN_ROUTING_GROUP_TARGET_LIST_PATH)?;
    let (engine, _) = authorization_engine_for_actor(&state, &actor)?;
    let authorized = authorize_item_list(
        engine.as_ref(),
        &actor,
        route.action,
        state
            .store
            .routing_group_targets_for_group(&actor.tenant_id, &routing_group_id)
            .into_iter()
            .map(|target| AuthorizableItem {
                resource: route.resource(target.routing_group_id.clone()),
                item: target,
            }),
    );
    let resources = authorized
        .items
        .iter()
        .map(routing_group_target_resource_envelope)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "gateway.admin.routing_group_target_list.v1",
        "resources": resources,
        "filtered_count": authorized.filtered_count,
        "next_cursor": null
    })))
}

async fn validate_routing_group_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(routing_group_id): Path<String>,
    Json(request): Json<AdminCreateRoutingGroupTargetRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_ROUTING_GROUP_TARGET_VALIDATE_PATH,
        &routing_group_id,
        now,
    )?;
    let errors =
        routing_group_target_validation_errors(&state, &actor, &routing_group_id, &request);
    Ok(validation_response(
        &state,
        &actor,
        validation_input(
            "gateway.admin.routing_group_target_validation.v1",
            "RoutingGroupTarget",
            "routing_group",
            routing_group_id,
            errors,
            now,
        ),
    ))
}

async fn create_routing_group_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path(routing_group_id): Path<String>,
    Json(request): Json<AdminCreateRoutingGroupTargetRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    validate_idempotency_key(&request.idempotency_key)?;
    authorize_admin_route(
        &state,
        &actor,
        &Method::POST,
        ADMIN_ROUTING_GROUP_TARGET_LIST_PATH,
        &routing_group_id,
        now,
    )?;
    let request_hash = stable_request_hash(&request)?;
    let scope_key = idempotency_scope_key(
        &format!("routing_group_targets:{routing_group_id}:create"),
        &request.idempotency_key,
    );
    if let Some(response) =
        state
            .store
            .idempotency_response(&actor.tenant_id, &scope_key, &request_hash, now)?
    {
        return Ok(Json(response_with_replay_flag(response, true)));
    }
    reject_validation_errors(&routing_group_target_validation_errors(
        &state,
        &actor,
        &routing_group_id,
        &request,
    ))?;
    let target = state.store.create_routing_group_target(
        CreateRoutingGroupTargetRequest {
            tenant_id: actor.tenant_id.clone(),
            routing_group_id,
            model_target_id: request.model_target_id,
            weight: request.weight,
            priority: request.priority,
            created_by: actor_principal_or_actor_id(&actor),
        },
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.routing_group_target.create",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "RoutingGroupTarget",
            resource_id: target.routing_group_target_id.clone(),
            before_version: None,
            after_version: Some(target.resource_version),
            redacted_diff: json!({
                "routing_group_target_id": &target.routing_group_target_id,
                "model_target_id": &target.model_target_id,
                "weight": target.weight,
                "priority": target.priority
            }),
            occurred_at: now,
        },
    );
    let response = json!({
        "schema": "gateway.admin.routing_group_target_mutation.v1",
        "resource": routing_group_target_resource_body(&target),
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    });
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id: actor.tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
        created_at: now,
    });
    Ok(Json(response))
}

async fn get_routing_group_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((routing_group_id, routing_group_target_id)): Path<(String, String)>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::GET,
        ADMIN_ROUTING_GROUP_TARGET_GET_PATH,
        &routing_group_id,
        now,
    )?;
    let target = routing_group_target_for_actor(
        &state,
        &actor,
        &routing_group_id,
        &routing_group_target_id,
    )?;
    Ok(Json(json!({
        "schema": "gateway.admin.routing_group_target.v1",
        "resource": routing_group_target_resource_body(&target)
    })))
}

async fn update_routing_group_target(
    State(state): State<AppState>,
    Extension(actor): Extension<AuthenticatedActor>,
    Path((routing_group_id, routing_group_target_id)): Path<(String, String)>,
    Json(request): Json<AdminUpdateRoutingGroupTargetRequest>,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    authorize_admin_route(
        &state,
        &actor,
        &Method::PATCH,
        ADMIN_ROUTING_GROUP_TARGET_GET_PATH,
        &routing_group_id,
        now,
    )?;
    let before = routing_group_target_for_actor(
        &state,
        &actor,
        &routing_group_id,
        &routing_group_target_id,
    )?;
    let updated = state.store.update_routing_group_target_status(
        &routing_group_target_id,
        request.expected_version,
        request.status,
        now,
    )?;
    let audit_event_id = record_admin_resource_audit(
        &state,
        &actor,
        AdminResourceAuditInput {
            event_type: "gateway.routing_group_target.update",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "RoutingGroupTarget",
            resource_id: updated.routing_group_target_id.clone(),
            before_version: Some(before.resource_version),
            after_version: Some(updated.resource_version),
            redacted_diff: json!({
                "routing_group_target_id": &updated.routing_group_target_id,
                "status": {
                    "before": before.status.as_str(),
                    "after": updated.status.as_str()
                },
                "reason": request.reason
            }),
            occurred_at: now,
        },
    );
    Ok(Json(json!({
        "schema": "gateway.admin.routing_group_target_mutation.v1",
        "resource": routing_group_target_resource_body(&updated),
        "audit_event_id": audit_event_id
    })))
}

async fn model_ingress(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Result<Json<RuntimeIngressResponse>> {
    let (parts, body) = request.into_parts();
    let method = parts.method;
    let path = parts.uri.path().to_owned();
    let replay_case = replay_case_for_request(&method, &path)?;
    let actor = authenticated_actor_from_extensions(&parts.extensions)?;
    let body_bytes = to_bytes(body, state.config.max_body_bytes)
        .await
        .map_err(|error| GatewayError::BadRequest {
            message: format!("failed to read request body: {error}"),
        })?;
    let request_body_bytes = body_bytes.len();
    let body = request_body_from_bytes(&body_bytes)?;
    let requested_model = requested_resource_id(&body, &path);
    let route_target = runtime_route_target(&state, &actor, replay_case, &requested_model)?;
    let (engine, policy_snapshot_id) = authorization_engine_for_actor(&state, &actor)?;
    let attempt_started_at = chrono::Utc::now();
    let provider_target = FakeProviderReplayTarget {
        alias_resource_id: route_target.authorization_resource_id.clone(),
        upstream_model_id: route_target.upstream_model_id.clone(),
    };
    let authorization = authorize_fake_provider_replay_target(
        replay_case,
        engine.as_ref(),
        state.store(),
        actor.clone(),
        &provider_target,
        FakeProviderReplayEvidence {
            policy_snapshot_id,
            occurred_at: chrono::Utc::now(),
        },
    )?;
    if !authorization.authorization.allowed {
        return Err(GatewayError::Authorization {
            reason: authorization.authorization.reason,
        });
    }
    let preflight = match enforce_runtime_policy_preflight(
        &state,
        &actor,
        replay_case,
        route_target.selected_route.as_ref(),
        request_body_bytes,
        chrono::Utc::now(),
    ) {
        Ok(preflight) => preflight,
        Err(error) => {
            record_runtime_policy_block_decision(
                &state,
                &actor,
                replay_case,
                &requested_model,
                &route_target,
                &error,
            );
            return Err(error);
        }
    };
    let response =
        fake_provider_response_for_authorization(&authorization, &provider_target, &body);
    if let (Some(route_decision_id), Some(selected)) = (
        route_target.route_decision_id.as_deref(),
        route_target.selected_route.as_ref(),
    ) {
        let attempt_ended_at = chrono::Utc::now();
        state
            .store
            .record_route_attempt(RouteAttemptRecord::completed(
                route_decision_id,
                selected,
                attempt_started_at,
                attempt_ended_at,
            ));
        record_terminal_usage_event(
            &state,
            &actor,
            &TerminalUsageInput {
                replay_case,
                route_decision_id,
                selected,
                response: &response,
                started_at: attempt_started_at,
                ended_at: attempt_ended_at,
            },
        );
    }
    release_runtime_policy_reservations(&state, &preflight);
    Ok(Json(response))
}

struct TerminalUsageInput<'a> {
    replay_case: &'a GatewayReplayCase,
    route_decision_id: &'a str,
    selected: &'a SelectedRouteEvidence,
    response: &'a RuntimeIngressResponse,
    started_at: chrono::DateTime<chrono::Utc>,
    ended_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RuntimePolicyPreflight {
    budget_reservations: Vec<RuntimeBudgetReservation>,
    quota_reservations: Vec<RuntimeQuotaReservation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeBudgetReservation {
    counter_key: String,
    amount: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeQuotaReservation {
    counter_key: String,
    amount: i64,
}

fn record_terminal_usage_event(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: &TerminalUsageInput<'_>,
) {
    let (usage_payload, usage_confidence) =
        normalized_usage_payload(input.response.protocol_family, &input.response.body);
    finalize_runtime_policy_terminal(state, actor, input, &usage_payload);
    let latency_ms = input
        .ended_at
        .signed_duration_since(input.started_at)
        .num_milliseconds()
        .max(0);
    let project_member_id = actor
        .principal_id
        .as_deref()
        .zip(actor.project_id.as_deref())
        .and_then(|(principal_id, project_id)| {
            state
                .store
                .project_membership(principal_id, project_id)
                .map(|membership| membership.project_member_id)
        });
    let service_account_id =
        matches!(actor.actor_kind, ActorKind::ServiceAccount).then(|| actor.actor_id.clone());
    state.store.record_usage_event(UsageEventRecord {
        usage_event_id: new_prefixed_id("use"),
        tenant_id: actor.tenant_id.clone(),
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        principal_id: actor.principal_id.clone(),
        project_member_id,
        service_account_id,
        api_key_id: actor.api_key_id.clone(),
        request_id: actor.request_id.clone(),
        protocol_family: input.replay_case.protocol_family,
        route_decision_id: Some(input.route_decision_id.to_owned()),
        model_alias_id: Some(input.selected.model_alias_id.clone()),
        model_target_id: Some(input.selected.model_target_id.clone()),
        route_policy_id: Some(input.selected.route_policy_id.clone()),
        routing_group_id: Some(input.selected.routing_group_id.clone()),
        provider_endpoint_id: Some(input.selected.provider_endpoint_id.clone()),
        upstream_credential_id: input.selected.upstream_credential_id.clone(),
        usage_confidence,
        latency_ms: Some(latency_ms),
        time_to_first_token_ms: input.replay_case.streaming.then_some(latency_ms),
        status: "success".to_owned(),
        usage_payload,
        cost_payload: json!({
            "currency": "USD",
            "unit": "micro_usd",
            "total_cost": 0,
            "confidence": "unpriced",
            "pricing_version": "unpriced",
            "diagnostics": ["pricing_resolution_not_connected"]
        }),
        occurred_at: input.ended_at,
    });
}

fn finalize_runtime_policy_terminal(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: &TerminalUsageInput<'_>,
    usage_payload: &Value,
) {
    let terminal_tokens = terminal_usage_token_count(usage_payload);
    if terminal_tokens <= 0 {
        return;
    }
    for policy in state.store.quota_policies_for_tenant(&actor.tenant_id) {
        if policy.status != ResourceStatus::Active
            || policy.counter_kind != "token_actual_rate"
            || policy.increment_source != "terminal_usage_event"
            || !runtime_quota_policy_matches_request(
                &policy,
                actor,
                input.replay_case,
                Some(input.selected),
            )
        {
            continue;
        }
        let key = runtime_quota_counter_key(&policy, input.ended_at);
        state
            .store
            .adjust_runtime_policy_counter(key, terminal_tokens);
    }
}

fn terminal_usage_token_count(usage_payload: &Value) -> i64 {
    usage_payload
        .get("total_tokens")
        .and_then(Value::as_i64)
        .or_else(|| {
            let input = usage_payload.get("input_tokens").and_then(Value::as_i64);
            let output = usage_payload.get("output_tokens").and_then(Value::as_i64);
            input.zip(output).map(|(input, output)| {
                input.saturating_add(output).saturating_add(
                    usage_payload
                        .get("reasoning_tokens")
                        .and_then(Value::as_i64)
                        .unwrap_or_default(),
                )
            })
        })
        .unwrap_or_default()
}

fn enforce_runtime_policy_preflight(
    state: &AppState,
    actor: &AuthenticatedActor,
    replay_case: &GatewayReplayCase,
    selected: Option<&SelectedRouteEvidence>,
    request_body_bytes: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RuntimePolicyPreflight> {
    let budget_reservations = enforce_runtime_budget_preflight(state, actor, selected, now)?;
    let quota_reservations = match enforce_runtime_quota_preflight(
        state,
        actor,
        replay_case,
        selected,
        request_body_bytes,
        now,
    ) {
        Ok(reservations) => reservations,
        Err(error) => {
            release_runtime_budget_reservations(state, &budget_reservations);
            return Err(error);
        }
    };
    Ok(RuntimePolicyPreflight {
        budget_reservations,
        quota_reservations,
    })
}

fn release_runtime_policy_reservations(state: &AppState, preflight: &RuntimePolicyPreflight) {
    release_runtime_budget_reservations(state, &preflight.budget_reservations);
    release_runtime_quota_reservations(state, &preflight.quota_reservations);
}

fn release_runtime_budget_reservations(
    state: &AppState,
    reservations: &[RuntimeBudgetReservation],
) {
    for reservation in reservations {
        state
            .store
            .adjust_runtime_policy_counter(reservation.counter_key.clone(), -reservation.amount);
    }
}

fn release_runtime_quota_reservations(state: &AppState, reservations: &[RuntimeQuotaReservation]) {
    for reservation in reservations {
        state
            .store
            .adjust_runtime_policy_counter(reservation.counter_key.clone(), -reservation.amount);
    }
}

fn enforce_runtime_budget_preflight(
    state: &AppState,
    actor: &AuthenticatedActor,
    selected: Option<&SelectedRouteEvidence>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<RuntimeBudgetReservation>> {
    let ledger_buckets = state.store.ledger_buckets_for_tenant(&actor.tenant_id);
    let mut reservations = Vec::new();
    for policy in state.store.budget_policies_for_tenant(&actor.tenant_id) {
        let Some(limit) = policy.hard_limit else {
            continue;
        };
        if !runtime_budget_policy_is_preflight_enforced(&policy)
            || !runtime_budget_policy_matches_request(&policy, actor, selected)
        {
            continue;
        }
        let current = ledger_buckets
            .iter()
            .filter(|bucket| runtime_budget_bucket_matches(&policy, bucket, now))
            .map(|bucket| runtime_budget_bucket_value(&policy, bucket))
            .sum::<i64>();
        let exceeded = match policy.limit_kind.as_str() {
            "requests" => current.saturating_add(1) > limit,
            "tokens" | "cost" => current >= limit,
            _ => false,
        };
        if exceeded {
            release_runtime_budget_reservations(state, &reservations);
            return Err(GatewayError::BudgetExceeded {
                reason: "hard_limit_reached",
            });
        }
        if policy.limit_kind == "requests" {
            let reservation = reserve_runtime_request_budget(state, &policy, current, limit, now)?;
            reservations.push(reservation);
        }
    }
    Ok(reservations)
}

fn runtime_budget_policy_is_preflight_enforced(policy: &BudgetPolicyRecord) -> bool {
    policy.status == ResourceStatus::Active
        && policy.overage_mode == "block_new_requests"
        && matches!(policy.limit_kind.as_str(), "requests" | "tokens" | "cost")
}

fn reserve_runtime_request_budget(
    state: &AppState,
    policy: &BudgetPolicyRecord,
    current_ledger_value: i64,
    limit: i64,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RuntimeBudgetReservation> {
    let counter_key = runtime_budget_reservation_key(policy, now);
    let reserved_after_increment = state
        .store
        .adjust_runtime_policy_counter(counter_key.clone(), 1);
    if current_ledger_value.saturating_add(reserved_after_increment) > limit {
        state.store.adjust_runtime_policy_counter(counter_key, -1);
        return Err(GatewayError::BudgetExceeded {
            reason: "hard_limit_reserved",
        });
    }
    Ok(RuntimeBudgetReservation {
        counter_key,
        amount: 1,
    })
}

fn runtime_budget_reservation_key(
    policy: &BudgetPolicyRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let period_key = runtime_budget_reservation_period_key(policy, now);
    [
        policy.tenant_id.as_str(),
        policy.budget_policy_id.as_str(),
        policy.scope_kind.as_str(),
        policy.scope_id.as_str(),
        policy.limit_kind.as_str(),
        policy.period.as_str(),
        period_key.as_str(),
    ]
    .join("|")
}

fn runtime_budget_reservation_period_key(
    policy: &BudgetPolicyRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    match policy.period.as_str() {
        "calendar_day" => now.format("%Y-%m-%d").to_string(),
        "calendar_month" => format!("{}-{:02}", now.year(), now.month()),
        _ => "all_time".to_owned(),
    }
}

fn runtime_budget_policy_matches_request(
    policy: &BudgetPolicyRecord,
    actor: &AuthenticatedActor,
    selected: Option<&SelectedRouteEvidence>,
) -> bool {
    match policy.scope_kind.as_str() {
        "tenant" => policy.scope_id == actor.tenant_id,
        "organization" => actor.organization_id.as_deref() == Some(policy.scope_id.as_str()),
        "project" => actor.project_id.as_deref() == Some(policy.scope_id.as_str()),
        "credential" => {
            selected.and_then(|route| route.upstream_credential_id.as_deref())
                == Some(policy.scope_id.as_str())
        }
        "alias" => selected.is_some_and(|route| route.model_alias_id == policy.scope_id),
        "group" => selected.is_some_and(|route| route.routing_group_id == policy.scope_id),
        "endpoint" => selected.is_some_and(|route| route.provider_endpoint_id == policy.scope_id),
        "target" => selected.is_some_and(|route| route.model_target_id == policy.scope_id),
        _ => false,
    }
}

fn runtime_budget_bucket_matches(
    policy: &BudgetPolicyRecord,
    bucket: &LedgerBucketRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    bucket.bucket_kind == "event"
        && runtime_budget_period_matches(policy, bucket.bucket_start, now)
        && runtime_budget_bucket_scope_matches(policy, bucket)
        && runtime_budget_bucket_currency_matches(policy, bucket)
}

fn runtime_budget_period_matches(
    policy: &BudgetPolicyRecord,
    bucket_start: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    match policy.period.as_str() {
        "calendar_day" => bucket_start.date_naive() == now.date_naive(),
        "calendar_month" => {
            let bucket_date = bucket_start.date_naive();
            let now_date = now.date_naive();
            bucket_date.year() == now_date.year() && bucket_date.month() == now_date.month()
        }
        _ => true,
    }
}

fn runtime_budget_bucket_scope_matches(
    policy: &BudgetPolicyRecord,
    bucket: &LedgerBucketRecord,
) -> bool {
    match policy.scope_kind.as_str() {
        "tenant" => bucket.tenant_id == policy.scope_id,
        "organization" => bucket.organization_id.as_deref() == Some(policy.scope_id.as_str()),
        "project" => bucket.project_id.as_deref() == Some(policy.scope_id.as_str()),
        "credential" => bucket.upstream_credential_id.as_deref() == Some(policy.scope_id.as_str()),
        "alias" => bucket.model_alias_id.as_deref() == Some(policy.scope_id.as_str()),
        "group" => bucket.routing_group_id.as_deref() == Some(policy.scope_id.as_str()),
        "endpoint" => bucket.provider_endpoint_id.as_deref() == Some(policy.scope_id.as_str()),
        "target" => bucket.model_target_id.as_deref() == Some(policy.scope_id.as_str()),
        _ => false,
    }
}

fn runtime_budget_bucket_currency_matches(
    policy: &BudgetPolicyRecord,
    bucket: &LedgerBucketRecord,
) -> bool {
    policy
        .currency
        .as_deref()
        .is_none_or(|currency| currency == bucket.currency_code)
}

fn runtime_budget_bucket_value(policy: &BudgetPolicyRecord, bucket: &LedgerBucketRecord) -> i64 {
    match policy.limit_kind.as_str() {
        "requests" => bucket.request_count,
        "tokens" => bucket
            .input_tokens
            .saturating_add(bucket.output_tokens)
            .saturating_add(bucket.reasoning_tokens),
        "cost" => bucket.estimated_cost_micros,
        _ => 0,
    }
}

fn enforce_runtime_quota_preflight(
    state: &AppState,
    actor: &AuthenticatedActor,
    replay_case: &GatewayReplayCase,
    selected: Option<&SelectedRouteEvidence>,
    request_body_bytes: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<RuntimeQuotaReservation>> {
    let policies = state
        .store
        .quota_policies_for_tenant(&actor.tenant_id)
        .into_iter()
        .filter(|policy| {
            policy.status == ResourceStatus::Active
                && runtime_quota_policy_matches_request(policy, actor, replay_case, selected)
        })
        .collect::<Vec<_>>();

    for policy in &policies {
        if matches!(
            (
                policy.counter_kind.as_str(),
                policy.increment_source.as_str()
            ),
            ("request_body_bytes", "request_body_bytes")
        ) && usize_to_i64(request_body_bytes) > policy.limit
        {
            return Err(GatewayError::QuotaExceeded {
                reason: "request_body_size_limit_reached",
            });
        }
        if matches!(
            (
                policy.counter_kind.as_str(),
                policy.increment_source.as_str()
            ),
            ("token_actual_rate", "terminal_usage_event")
        ) && runtime_quota_current_value(state, policy, now) >= policy.limit
        {
            return Err(GatewayError::QuotaExceeded {
                reason: "token_actual_rate_limit_reached",
            });
        }
    }

    let mut reservations = Vec::new();
    for policy in policies {
        match (
            policy.counter_kind.as_str(),
            policy.increment_source.as_str(),
        ) {
            ("request_rate", "accepted_preflight_request") => {
                let key = runtime_quota_counter_key(&policy, now);
                let decision = state
                    .store
                    .increment_runtime_quota_counter(key, 1, policy.limit);
                if !decision.allowed {
                    release_runtime_quota_reservations(state, &reservations);
                    return Err(GatewayError::QuotaExceeded {
                        reason: "request_rate_limit_reached",
                    });
                }
            }
            ("concurrent_request", "preflight_acquire") => {
                match reserve_runtime_quota_counter(
                    state,
                    &policy,
                    1,
                    "concurrent_request_limit_reached",
                    now,
                ) {
                    Ok(reservation) => reservations.push(reservation),
                    Err(error) => {
                        release_runtime_quota_reservations(state, &reservations);
                        return Err(error);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(reservations)
}

fn runtime_quota_current_value(
    state: &AppState,
    policy: &QuotaPolicyRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> i64 {
    let key = runtime_quota_counter_key(policy, now);
    state.store.runtime_policy_counter(&key)
}

fn reserve_runtime_quota_counter(
    state: &AppState,
    policy: &QuotaPolicyRecord,
    amount: i64,
    reason: &'static str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<RuntimeQuotaReservation> {
    let counter_key = runtime_quota_counter_key(policy, now);
    let current = state
        .store
        .adjust_runtime_policy_counter(counter_key.clone(), amount);
    if current > policy.limit {
        state
            .store
            .adjust_runtime_policy_counter(counter_key, -amount);
        return Err(GatewayError::QuotaExceeded { reason });
    }
    Ok(RuntimeQuotaReservation {
        counter_key,
        amount,
    })
}

fn runtime_quota_policy_matches_request(
    policy: &QuotaPolicyRecord,
    actor: &AuthenticatedActor,
    replay_case: &GatewayReplayCase,
    selected: Option<&SelectedRouteEvidence>,
) -> bool {
    match policy.scope_kind.as_str() {
        "tenant" => policy.scope_id == actor.tenant_id,
        "organization" => actor.organization_id.as_deref() == Some(policy.scope_id.as_str()),
        "project" => actor.project_id.as_deref() == Some(policy.scope_id.as_str()),
        "credential" => {
            selected.and_then(|route| route.upstream_credential_id.as_deref())
                == Some(policy.scope_id.as_str())
        }
        "alias" => selected.is_some_and(|route| route.model_alias_id == policy.scope_id),
        "endpoint" => selected.is_some_and(|route| route.provider_endpoint_id == policy.scope_id),
        "protocol_family" => replay_case.protocol_family.as_str() == policy.scope_id,
        _ => false,
    }
}

fn runtime_quota_counter_key(
    policy: &QuotaPolicyRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    let window_slot = match policy.window.as_str() {
        "fixed" | "sliding" => now.timestamp().div_euclid(60).to_string(),
        "request_lifetime" | "stream_lifetime" => "active".to_owned(),
        "ledger_bucket" => "ledger_bucket".to_owned(),
        _ => "default".to_owned(),
    };
    [
        policy.tenant_id.as_str(),
        policy.quota_policy_id.as_str(),
        policy.scope_kind.as_str(),
        policy.scope_id.as_str(),
        policy.counter_kind.as_str(),
        policy.window.as_str(),
        window_slot.as_str(),
    ]
    .join("|")
}

fn usize_to_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn record_runtime_policy_block_decision(
    state: &AppState,
    actor: &AuthenticatedActor,
    replay_case: &GatewayReplayCase,
    requested_model: &str,
    route_target: &RuntimeRouteTarget,
    error: &GatewayError,
) {
    let reason = match error {
        GatewayError::BudgetExceeded { .. } => "budget_exceeded",
        GatewayError::QuotaExceeded { .. } => "quota_exceeded",
        _ => return,
    };
    let now = chrono::Utc::now();
    let decision_request =
        route_target
            .decision_request
            .clone()
            .unwrap_or_else(|| RouteDecisionRequest {
                protocol_family: replay_case.protocol_family,
                alias_name: requested_model.to_owned(),
                config_snapshot_id: None,
                config_version: None,
            });
    let filtered_summary = route_target
        .selected_route
        .as_ref()
        .map_or_else(Vec::new, |route| route.filtered_summary.clone());
    state
        .store
        .record_route_decision(RouteDecisionRecord::terminal(
            actor,
            decision_request,
            RouteDecisionStatus::Blocked,
            reason,
            filtered_summary,
            now,
        ));
    enqueue_runtime_policy_notification_events(
        state,
        actor,
        replay_case,
        requested_model,
        route_target,
        error,
        now,
    );
}

fn enqueue_runtime_policy_notification_events(
    state: &AppState,
    actor: &AuthenticatedActor,
    replay_case: &GatewayReplayCase,
    requested_model: &str,
    route_target: &RuntimeRouteTarget,
    error: &GatewayError,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Some((event_family, event_kind, reason)) = runtime_policy_notification_kind(error) else {
        return;
    };
    let (scope_kind, scope_id) = runtime_notification_scope(actor);
    let selected = route_target.selected_route.as_ref();
    let payload = json!({
        "schema": "gateway.notification.runtime_policy_block.v1",
        "event_type": event_kind,
        "event_family": event_family,
        "tenant_id": &actor.tenant_id,
        "organization_id": &actor.organization_id,
        "project_id": &actor.project_id,
        "scope": {
            "kind": scope_kind,
            "id": scope_id
        },
        "request": {
            "request_id": &actor.request_id,
            "protocol_family": replay_case.protocol_family.as_str(),
            "requested_model": requested_model
        },
        "actor": {
            "actor_kind": actor.actor_kind.as_str(),
            "actor_id": &actor.actor_id
        },
        "route": {
            "model_alias_id": selected.map(|route| route.model_alias_id.as_str()),
            "model_target_id": selected.map(|route| route.model_target_id.as_str()),
            "routing_group_id": selected.map(|route| route.routing_group_id.as_str()),
            "provider_endpoint_id": selected.map(|route| route.provider_endpoint_id.as_str()),
            "upstream_credential_id": selected.and_then(|route| route.upstream_credential_id.as_deref())
        },
        "policy": {
            "reason": reason
        },
        "redaction": {
            "request_body_included": false,
            "provider_body_included": false,
            "secret_material_included": false
        },
        "occurred_at": now
    });
    for subscription in state
        .store
        .notification_subscriptions_for_tenant(&actor.tenant_id)
        .into_iter()
        .filter(|subscription| {
            subscription.status == ResourceStatus::Active
                && subscription.event_family == event_family
                && notification_subscription_filter_matches(
                    &subscription.filter_document,
                    event_kind,
                    scope_kind,
                    &scope_id,
                )
        })
    {
        let Some(sink) = state
            .store
            .notification_sink(&subscription.notification_sink_id)
        else {
            continue;
        };
        if sink.status != ResourceStatus::Active {
            continue;
        }
        state.store.append_notification_outbox_event(
            CreateNotificationOutboxEventRequest {
                tenant_id: actor.tenant_id.clone(),
                organization_id: actor.organization_id.clone(),
                project_id: actor.project_id.clone(),
                notification_subscription_id: Some(
                    subscription.notification_subscription_id.clone(),
                ),
                notification_sink_id: Some(sink.notification_sink_id.clone()),
                event_kind: event_kind.to_owned(),
                dedupe_key: format!(
                    "runtime-policy-block:{}:{}:{}",
                    actor.request_id, subscription.notification_subscription_id, event_kind
                ),
                payload_document: payload.clone(),
                next_attempt_at: Some(now),
            },
            now,
        );
    }
}

const fn runtime_policy_notification_kind(
    error: &GatewayError,
) -> Option<(&'static str, &'static str, &'static str)> {
    match error {
        GatewayError::BudgetExceeded { reason } => {
            Some(("budget", "gateway.budget.hard_block", *reason))
        }
        GatewayError::QuotaExceeded { reason } => {
            Some(("quota", "gateway.quota.limit_exceeded", *reason))
        }
        _ => None,
    }
}

fn runtime_notification_scope(actor: &AuthenticatedActor) -> (&'static str, String) {
    actor.project_id.as_deref().map_or_else(
        || {
            actor.organization_id.as_deref().map_or_else(
                || ("tenant", actor.tenant_id.clone()),
                |organization_id| ("organization", organization_id.to_owned()),
            )
        },
        |project_id| ("project", project_id.to_owned()),
    )
}

fn notification_subscription_filter_matches(
    filter: &Value,
    event_kind: &str,
    scope_kind: &str,
    scope_id: &str,
) -> bool {
    if filter.is_null() {
        return true;
    }
    if let Some(event_types) = filter.get("event_types").and_then(Value::as_array) {
        let matches_event = event_types
            .iter()
            .filter_map(Value::as_str)
            .any(|candidate| candidate == event_kind);
        if !matches_event {
            return false;
        }
    }
    if let Some(filter_scope_kind) = filter.get("scope_kind").and_then(Value::as_str) {
        if filter_scope_kind != scope_kind {
            return false;
        }
    }
    if let Some(filter_scope_id) = filter.get("scope_id").and_then(Value::as_str) {
        if filter_scope_id != scope_id {
            return false;
        }
    }
    true
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportPage {
    rows: Vec<Value>,
    next_cursor: Option<String>,
    total_filtered_count: usize,
}

fn build_export_page(
    state: &AppState,
    export_kind: &str,
    scope: &DashboardScopeInput,
    limit: usize,
    offset: usize,
) -> Result<ExportPage> {
    match export_kind {
        "usage" => {
            let mut events = state
                .store
                .usage_events_for_tenant(&scope.tenant_id)
                .into_iter()
                .filter(|event| dashboard_usage_event_matches_scope(event, scope))
                .collect::<Vec<_>>();
            events.sort_by(|left, right| {
                right
                    .occurred_at
                    .cmp(&left.occurred_at)
                    .then_with(|| right.usage_event_id.cmp(&left.usage_event_id))
            });
            let total_filtered_count = events.len();
            let rows = events
                .iter()
                .skip(offset)
                .take(limit)
                .map(usage_event_body)
                .collect::<Vec<_>>();
            let next_offset = offset.saturating_add(rows.len());
            Ok(ExportPage {
                rows,
                next_cursor: (next_offset < total_filtered_count).then(|| next_offset.to_string()),
                total_filtered_count,
            })
        }
        "audit" => {
            let mut events = state
                .store
                .audit_events_for_tenant(&scope.tenant_id)
                .into_iter()
                .filter(|event| export_audit_event_matches_scope(event, scope))
                .collect::<Vec<_>>();
            events.sort_by(|left, right| {
                right
                    .occurred_at
                    .cmp(&left.occurred_at)
                    .then_with(|| right.audit_event_id.cmp(&left.audit_event_id))
            });
            let total_filtered_count = events.len();
            let rows = events
                .iter()
                .skip(offset)
                .take(limit)
                .map(audit_event_body)
                .collect::<Vec<_>>();
            let next_offset = offset.saturating_add(rows.len());
            Ok(ExportPage {
                rows,
                next_cursor: (next_offset < total_filtered_count).then(|| next_offset.to_string()),
                total_filtered_count,
            })
        }
        _ => Err(GatewayError::BadRequest {
            message: "export_kind_invalid".to_owned(),
        }),
    }
}

fn export_audit_event_matches_scope(event: &AuditEventRecord, scope: &DashboardScopeInput) -> bool {
    if event.tenant_id != scope.tenant_id {
        return false;
    }
    match scope.scope_kind {
        "tenant" => event.tenant_id == scope.scope_id,
        "organization" => {
            event.organization_id.as_deref() == scope.organization_id.as_deref()
                || (event.scope_kind == "organization" && event.scope_id == scope.scope_id)
        }
        "project" => {
            event.project_id.as_deref() == scope.project_id.as_deref()
                || (event.scope_kind == "project" && event.scope_id == scope.scope_id)
        }
        _ => event.scope_kind == scope.scope_kind && event.scope_id == scope.scope_id,
    }
}

fn validate_export_kind(export_kind: &str) -> Result<()> {
    if matches!(export_kind, "usage" | "audit") {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "export_kind_invalid".to_owned(),
        })
    }
}

fn export_list_limit(limit: Option<usize>) -> Result<usize> {
    const DEFAULT_LIMIT: usize = 100;
    const MAX_LIMIT: usize = 200;
    match limit.unwrap_or(DEFAULT_LIMIT) {
        0 => Err(GatewayError::BadRequest {
            message: "export_limit_must_be_positive".to_owned(),
        }),
        value if value > MAX_LIMIT => Err(GatewayError::BadRequest {
            message: "export_limit_exceeds_maximum".to_owned(),
        }),
        value => Ok(value),
    }
}

fn export_list_offset(cursor: Option<&str>) -> Result<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    cursor
        .parse::<usize>()
        .map_err(|_| GatewayError::BadRequest {
            message: "export_cursor_invalid".to_owned(),
        })
}

fn export_retention_days(retention_days: i64) -> Result<i64> {
    if (1..=365).contains(&retention_days) {
        Ok(retention_days)
    } else {
        Err(GatewayError::BadRequest {
            message: "export_retention_days_invalid".to_owned(),
        })
    }
}

fn export_query_document(
    request: &AdminCreateExportJobRequest,
    scope: &DashboardScopeInput,
    limit: usize,
) -> Value {
    json!({
        "schema": "gateway.admin.export_query.v1",
        "export_kind": &request.export_kind,
        "scope": dashboard_scope_body(scope),
        "limit": limit,
        "cursor": &request.cursor,
        "retention_days": request.retention_days
    })
}

fn export_payload_document(
    job: &ExportJobRecord,
    scope: &DashboardScopeInput,
    request: &AdminCreateExportJobRequest,
    page: &ExportPage,
    limit: usize,
) -> Value {
    json!({
        "schema": "gateway.export_payload.v1",
        "export_job_id": &job.export_job_id,
        "export_kind": &job.export_kind,
        "scope": dashboard_scope_body(scope),
        "format": "json",
        "rows": &page.rows,
        "limit": limit,
        "cursor": &request.cursor,
        "next_cursor": &page.next_cursor,
        "total_filtered_count": page.total_filtered_count,
        "redaction": {
            "raw_request_body_included": false,
            "raw_provider_body_included": false,
            "secret_material_included": false
        }
    })
}

fn export_manifest_document(
    job: &ExportJobRecord,
    scope: &DashboardScopeInput,
    page: &ExportPage,
    object_ref: &str,
    checksum: &str,
) -> Value {
    json!({
        "schema": "gateway.export_manifest.v1",
        "export_job_id": &job.export_job_id,
        "export_kind": &job.export_kind,
        "scope": dashboard_scope_body(scope),
        "format": "json",
        "object": {
            "object_ref": object_ref,
            "backend": "inline_manifest",
            "object_storage_connected": false
        },
        "checksum": checksum,
        "record_count": page.rows.len(),
        "total_filtered_count": page.total_filtered_count,
        "next_cursor": &page.next_cursor,
        "rows": &page.rows,
        "redaction": {
            "raw_request_body_included": false,
            "raw_provider_body_included": false,
            "secret_material_included": false
        }
    })
}

fn export_object_ref(job: &ExportJobRecord) -> String {
    format!(
        "memory://gateway-exports/{}/{}.json",
        job.tenant_id, job.export_job_id
    )
}

/// Delivers due notification outbox events for one tenant.
#[must_use]
pub fn deliver_due_notifications(
    state: &AppState,
    tenant_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    limit: usize,
) -> Vec<NotificationDeliveryAttemptRecord> {
    state
        .store
        .due_notification_outbox_events(tenant_id, now, limit)
        .into_iter()
        .filter_map(|event| deliver_notification_outbox_event(state, event, now).ok())
        .collect()
}

fn deliver_notification_outbox_event(
    state: &AppState,
    event: crate::domain::NotificationOutboxEventRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<NotificationDeliveryAttemptRecord> {
    let sink = event
        .notification_sink_id
        .as_deref()
        .and_then(|sink_id| state.store.notification_sink(sink_id));
    let plan = match sink.as_ref() {
        Some(sink) if sink.status != ResourceStatus::Active => NotificationDeliveryPlan::failure(
            "permanent_failed",
            None,
            "notification_sink_not_active",
            json!({"transport": sink.sink_kind.as_str()}),
        ),
        Some(sink) if sink.sink_kind == "stdout" => {
            NotificationDeliveryPlan::success(Some(204), json!({"transport": "stdout"}))
        }
        Some(sink) if sink.sink_kind == "disabled" => NotificationDeliveryPlan::failure(
            "permanent_failed",
            None,
            "notification_sink_disabled",
            json!({"transport": "disabled"}),
        ),
        Some(sink) if sink.sink_kind == "webhook" => {
            webhook_delivery_plan(state, sink, &event, now)?
        }
        Some(sink) => NotificationDeliveryPlan::failure(
            "retryable_failed",
            None,
            "notification_delivery_backend_not_connected",
            json!({"transport": sink.sink_kind.as_str()}),
        )
        .with_next_attempt_at(
            now + chrono::Duration::seconds(NOTIFICATION_DELIVERY_RETRY_DELAY_SECONDS),
        ),
        None => NotificationDeliveryPlan::failure(
            "permanent_failed",
            None,
            "notification_sink_missing",
            json!({"transport": null}),
        ),
    };
    state.store.record_notification_delivery_attempt(
        CreateNotificationDeliveryAttemptRequest {
            notification_outbox_event_id: event.notification_outbox_event_id,
            notification_sink_id: event.notification_sink_id,
            status: plan.status,
            response_status: plan.response_status,
            error_message: plan.error_message,
            request_body_sha256: plan.request_body_sha256,
            signing_secret_ref_id: plan.signing_secret_ref_id,
            signature_sha256: plan.signature_sha256,
            delivery_headers: plan.delivery_headers,
            next_attempt_at: plan.next_attempt_at,
        },
        now,
    )
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NotificationDeliveryPlan {
    status: String,
    response_status: Option<i32>,
    error_message: Option<String>,
    request_body_sha256: Option<String>,
    signing_secret_ref_id: Option<String>,
    signature_sha256: Option<String>,
    delivery_headers: Value,
    next_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl NotificationDeliveryPlan {
    fn success(response_status: Option<i32>, delivery_headers: Value) -> Self {
        Self {
            status: "succeeded".to_owned(),
            response_status,
            error_message: None,
            request_body_sha256: None,
            signing_secret_ref_id: None,
            signature_sha256: None,
            delivery_headers,
            next_attempt_at: None,
        }
    }

    fn failure(
        status: &str,
        response_status: Option<i32>,
        error_message: &str,
        delivery_headers: Value,
    ) -> Self {
        Self {
            status: status.to_owned(),
            response_status,
            error_message: Some(error_message.to_owned()),
            request_body_sha256: None,
            signing_secret_ref_id: None,
            signature_sha256: None,
            delivery_headers,
            next_attempt_at: None,
        }
    }

    const fn with_next_attempt_at(
        mut self,
        next_attempt_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        self.next_attempt_at = Some(next_attempt_at);
        self
    }
}

fn webhook_delivery_plan(
    state: &AppState,
    sink: &NotificationSinkRecord,
    event: &crate::domain::NotificationOutboxEventRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<NotificationDeliveryPlan> {
    let url = sink
        .endpoint_config
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::BadRequest {
            message: "notification_sink_webhook_url_required".to_owned(),
        })?;
    let host = safe_otel_endpoint_host(url).ok_or_else(|| GatewayError::BadRequest {
        message: "notification_sink_webhook_url_invalid".to_owned(),
    })?;
    let signing_secret_ref_id =
        sink.signing_secret_ref_id
            .clone()
            .ok_or_else(|| GatewayError::BadRequest {
                message: "notification_sink_signing_secret_ref_required".to_owned(),
            })?;
    let signing_secret = state
        .store
        .secret_value(&signing_secret_ref_id)
        .ok_or_else(|| GatewayError::BadRequest {
            message: "notification_sink_signing_secret_missing".to_owned(),
        })?;
    let body =
        serde_json::to_vec(&event.payload_document).map_err(|error| GatewayError::Internal {
            message: format!("failed to encode notification payload: {error}"),
        })?;
    let body_sha256 = sha256_hex(&body);
    let timestamp = now.to_rfc3339();
    let signature =
        notification_signature(signing_secret.expose_secret().as_bytes(), &timestamp, &body)?;
    let signature_sha256 = sha256_hex(signature.as_bytes());
    let host_lower = host.to_ascii_lowercase();
    let (status, response_status, error_message, next_attempt_at) = if host_lower.contains("gone")
        || host_lower.contains("permanent")
    {
        (
            "permanent_failed".to_owned(),
            Some(410),
            Some("notification_webhook_permanent_failure".to_owned()),
            None,
        )
    } else if host_lower.contains("retry")
        || host_lower.contains("unavailable")
        || host_lower.contains("fail")
    {
        if event.attempt_count.saturating_add(1) >= NOTIFICATION_DELIVERY_MAX_ATTEMPTS {
            (
                "dead_lettered".to_owned(),
                Some(503),
                Some("notification_webhook_retry_exhausted".to_owned()),
                None,
            )
        } else {
            (
                "retryable_failed".to_owned(),
                Some(503),
                Some("notification_webhook_retryable_failure".to_owned()),
                Some(now + chrono::Duration::seconds(NOTIFICATION_DELIVERY_RETRY_DELAY_SECONDS)),
            )
        }
    } else {
        ("succeeded".to_owned(), Some(204), None, None)
    };

    Ok(NotificationDeliveryPlan {
        status,
        response_status,
        error_message,
        request_body_sha256: Some(body_sha256.clone()),
        signing_secret_ref_id: Some(signing_secret_ref_id.clone()),
        signature_sha256: Some(signature_sha256.clone()),
        delivery_headers: json!({
            "transport": "webhook",
            "url_host": host,
            "url_path": safe_url_path(url),
            "body_sha256": body_sha256,
            "signature_algorithm": "hmac-sha256",
            "signature_sha256": signature_sha256,
            "headers": {
                "x-gateway-delivery-id": &event.notification_outbox_event_id,
                "x-gateway-event-id": &event.dedupe_key,
                "x-gateway-timestamp": timestamp,
                "x-gateway-signature": "hmac-sha256:***"
            },
            "signing_secret_ref_id": mask_secret_ref_id(&signing_secret_ref_id)
        }),
        next_attempt_at,
    })
}

fn notification_signature(signing_secret: &[u8], timestamp: &str, body: &[u8]) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(signing_secret).map_err(|error| GatewayError::Internal {
            message: format!("failed to initialize notification signer: {error}"),
        })?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(format!(
        "v1={}",
        base64_url_no_pad(&mac.finalize().into_bytes())
    ))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn normalized_usage_payload(protocol_family: ProtocolFamily, body: &Value) -> (Value, String) {
    let usage = match protocol_family {
        ProtocolFamily::OpenAiResponses
        | ProtocolFamily::OpenAiChat
        | ProtocolFamily::AnthropicMessages
        | ProtocolFamily::BedrockConverse => body.get("usage"),
        ProtocolFamily::GeminiGenerateContent => body.get("usageMetadata"),
        ProtocolFamily::ProviderNative => None,
    };
    let Some(usage) = usage else {
        return (empty_usage_payload(), "missing".to_owned());
    };
    let input_tokens = first_i64(usage, &["input_tokens", "promptTokenCount", "inputTokens"]);
    let output_tokens = first_i64(
        usage,
        &["output_tokens", "candidatesTokenCount", "outputTokens"],
    );
    let total_tokens = first_i64(usage, &["total_tokens", "totalTokenCount", "totalTokens"])
        .or_else(|| {
            input_tokens
                .zip(output_tokens)
                .map(|(input, output)| input + output)
        });
    let mut payload = empty_usage_payload();
    payload["input_tokens"] = json!(input_tokens.unwrap_or(0));
    payload["output_tokens"] = json!(output_tokens.unwrap_or(0));
    payload["total_tokens"] = json!(total_tokens.unwrap_or(0));
    (payload, "exact".to_owned())
}

fn empty_usage_payload() -> Value {
    json!({
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "cache_read_tokens": 0,
        "cache_write_tokens": 0,
        "cache_write_5m_tokens": 0,
        "cache_write_1h_tokens": 0,
        "reasoning_tokens": 0,
        "tool_tokens": 0,
        "image_input_units": 0,
        "image_output_units": 0,
        "audio_input_units": 0,
        "audio_output_units": 0,
        "request_units": 0,
        "provider_usage_metadata": {}
    })
}

fn first_i64(value: &Value, keys: &[&str]) -> Option<i64> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_i64))
}

fn authorization_engine_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
) -> Result<(Box<dyn AuthorizationEngine>, Option<String>)> {
    let Some(snapshot) = latest_snapshot_for_actor(state, actor)? else {
        return Ok((
            Box::new(FoundationAuthorizationEngine::new(
                state.store.action_grants(),
            )),
            None,
        ));
    };
    let Some(policy_bundle) = snapshot
        .document
        .payload
        .get("cedar_policy_bundle")
        .and_then(Value::as_str)
    else {
        return Ok((
            Box::new(FoundationAuthorizationEngine::new(
                state.store.action_grants(),
            )),
            None,
        ));
    };
    let engine = CedarAuthorizationEngine::from_policy_source(policy_bundle)?;
    Ok((Box::new(engine), Some(snapshot.metadata.snapshot_id)))
}

fn replay_case_for_request(method: &Method, path: &str) -> Result<&'static GatewayReplayCase> {
    foundation_route_replay_cases()
        .iter()
        .find(|case| case.method == *method && case.ingress_path == path)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("gateway route {method} {path}"),
        })
}

fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<AuthenticatedActor> {
    let request_id = request_id_from_headers(headers);
    let presented_key = bearer_token(headers)?;
    if presented_key.starts_with(SESSION_TOKEN_PREFIX) {
        let session = verify_session_token(state.store(), presented_key, now)?;
        let project_id = optional_header(headers, PROJECT_ID_HEADER)?
            .or_else(|| session.active_project_id.clone())
            .ok_or(GatewayError::Authentication)?;
        return resolve_user_session_actor(
            state.store(),
            ResolveUserSessionRequest {
                principal_id: session.principal_id,
                session_id: session.auth_session_id,
                project_id,
                request_id,
                expires_at: Some(session.expires_at),
            },
        );
    }
    verify_api_key(state.store(), presented_key, request_id, now)
}

fn authenticated_actor_from_extensions(extensions: &Extensions) -> Result<AuthenticatedActor> {
    extensions
        .get::<AuthenticatedActor>()
        .cloned()
        .ok_or_else(|| GatewayError::Internal {
            message: "authenticated actor missing from request context".to_owned(),
        })
}

fn authorize_admin_route(
    state: &AppState,
    actor: &AuthenticatedActor,
    method: &Method,
    path_pattern: &'static str,
    resource_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let route = route_metadata(method, path_pattern)?;
    reject_frozen_config_mutation(state, route, method, actor, now)?;
    let (engine, policy_snapshot_id) = authorization_engine_for_actor(state, actor)?;
    let decision = authorize_route_with_evidence(
        route,
        engine.as_ref(),
        state.store(),
        actor.clone(),
        resource_id,
        policy_snapshot_id,
        now,
    );
    if decision.allowed {
        Ok(())
    } else {
        Err(GatewayError::Authorization {
            reason: decision.reason,
        })
    }
}

fn reject_frozen_config_mutation(
    state: &AppState,
    route: &RouteMetadata,
    method: &Method,
    actor: &AuthenticatedActor,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if !admin_route_mutates(method) || route_allowed_during_config_freeze(route) {
        return Ok(());
    }
    if let Some(freeze) =
        state
            .store
            .active_emergency_operation(&actor.tenant_id, "freeze_config", now)
    {
        return Err(GatewayError::BadRequest {
            message: format!(
                "config_frozen: emergency operation {} expires at {}",
                freeze.emergency_operation_id, freeze.expires_at
            ),
        });
    }
    Ok(())
}

fn admin_route_mutates(method: &Method) -> bool {
    method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
}

fn route_allowed_during_config_freeze(route: &RouteMetadata) -> bool {
    matches!(
        route.action,
        GatewayAction::EmergencyDisable
            | GatewayAction::ConfigRollback
            | GatewayAction::ExternalIdentityUnlink
            | GatewayAction::SessionRevoke
    ) || route.audit_event_type.ends_with(".validate")
}

fn route_metadata(method: &Method, path_pattern: &'static str) -> Result<&'static RouteMetadata> {
    foundation_routes()
        .iter()
        .find(|route| {
            route.method.as_str() == method.as_str() && route.path_pattern == path_pattern
        })
        .ok_or_else(|| GatewayError::Internal {
            message: format!("missing route metadata for {method} {path_pattern}"),
        })
}

fn validate_idempotency_key(idempotency_key: &str) -> Result<()> {
    let is_valid = !idempotency_key.trim().is_empty()
        && idempotency_key.len() <= 160
        && idempotency_key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'));
    if is_valid {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "invalid_idempotency_key".to_owned(),
        })
    }
}

fn validate_required_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "reason_required".to_owned(),
        });
    }
    Ok(())
}

fn idempotency_scope_key(operation: &str, idempotency_key: &str) -> String {
    format!("{operation}:{idempotency_key}")
}

fn stable_request_hash<T: Serialize>(request: &T) -> Result<String> {
    let bytes = serde_json::to_vec(request).map_err(|error| GatewayError::Internal {
        message: format!("failed to encode idempotency request: {error}"),
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

fn emergency_request_hash(
    target_resource_id: &str,
    request: &AdminEmergencyOperationRequest,
) -> Result<String> {
    stable_request_hash(&json!({
        "target_resource_id": target_resource_id,
        "request": request
    }))
}

fn emergency_idempotency_scope_key(
    operation_kind: &str,
    target_resource_id: &str,
    idempotency_key: &str,
) -> String {
    idempotency_scope_key(
        &format!("emergency:{operation_kind}:{target_resource_id}"),
        idempotency_key,
    )
}

fn validate_emergency_operation_request(
    request: &AdminEmergencyOperationRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    validate_idempotency_key(&request.idempotency_key)?;
    validate_required_reason(&request.reason)?;
    if request.expires_at <= now {
        return Err(GatewayError::BadRequest {
            message: "emergency_expiry_must_be_future".to_owned(),
        });
    }
    Ok(())
}

fn required_emergency_expected_version(request: &AdminEmergencyOperationRequest) -> Result<i64> {
    request
        .expected_version
        .filter(|version| *version > 0)
        .ok_or_else(|| GatewayError::BadRequest {
            message: "expected_version_required".to_owned(),
        })
}

fn record_idempotent_admin_response(
    state: &AppState,
    tenant_id: String,
    scope_key: String,
    request_hash: String,
    response: &Value,
    now: chrono::DateTime<chrono::Utc>,
) {
    state.store.record_idempotency_response(IdempotencyRecord {
        tenant_id,
        scope_key,
        request_hash,
        response_record: response.clone(),
        created_at: now,
        expires_at: now + chrono::Duration::hours(IDEMPOTENCY_TTL_HOURS),
    });
}

fn export_payload_checksum(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn response_with_replay_flag(mut response: Value, replayed: bool) -> Value {
    if let Some(object) = response.as_object_mut() {
        object.insert("idempotency_replayed".to_owned(), json!(replayed));
    }
    response
}

fn response_without_invitation_token(response: &Value) -> Value {
    let mut response = response.clone();
    if let Some(object) = response.as_object_mut() {
        object.remove("invitation_token");
    }
    response
}

fn actor_principal_or_actor_id(actor: &AuthenticatedActor) -> String {
    actor
        .principal_id
        .clone()
        .unwrap_or_else(|| actor.actor_id.clone())
}

fn record_config_snapshot_audit(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: ConfigSnapshotAuditInput,
) -> String {
    let audit_event_id = new_prefixed_id("aud");
    state.store.record_audit_event(AuditEventRecord {
        audit_event_id: audit_event_id.clone(),
        event_type: input.event_type.to_owned(),
        tenant_id: actor.tenant_id.clone(),
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        scope_kind: "tenant".to_owned(),
        scope_id: actor.tenant_id.clone(),
        resource_kind: "ConfigSnapshot".to_owned(),
        resource_id: input.resource_id,
        before_version: input.before_version,
        after_version: input.after_version,
        actor_id: actor.actor_id.clone(),
        actor_kind: actor.actor_kind.clone(),
        principal_id: actor.principal_id.clone(),
        request_id: actor.request_id.clone(),
        redacted_diff: input.redacted_diff,
        occurred_at: input.occurred_at,
    });
    audit_event_id
}

fn record_project_audit(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: ProjectAuditInput,
) -> String {
    let audit_event_id = new_prefixed_id("aud");
    state.store.record_audit_event(AuditEventRecord {
        audit_event_id: audit_event_id.clone(),
        event_type: "gateway.project.update".to_owned(),
        tenant_id: actor.tenant_id.clone(),
        organization_id: actor.organization_id.clone(),
        project_id: Some(input.project_id.clone()),
        scope_kind: "project".to_owned(),
        scope_id: input.project_id.clone(),
        resource_kind: "Project".to_owned(),
        resource_id: input.project_id,
        before_version: input.before_version,
        after_version: input.after_version,
        actor_id: actor.actor_id.clone(),
        actor_kind: actor.actor_kind.clone(),
        principal_id: actor.principal_id.clone(),
        request_id: actor.request_id.clone(),
        redacted_diff: input.redacted_diff,
        occurred_at: input.occurred_at,
    });
    audit_event_id
}

fn record_admin_resource_audit(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: AdminResourceAuditInput,
) -> String {
    let audit_event_id = new_prefixed_id("aud");
    state.store.record_audit_event(AuditEventRecord {
        audit_event_id: audit_event_id.clone(),
        event_type: input.event_type.to_owned(),
        tenant_id: actor.tenant_id.clone(),
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        scope_kind: input.scope_kind.to_owned(),
        scope_id: input.scope_id,
        resource_kind: input.resource_kind.to_owned(),
        resource_id: input.resource_id,
        before_version: input.before_version,
        after_version: input.after_version,
        actor_id: actor.actor_id.clone(),
        actor_kind: actor.actor_kind.clone(),
        principal_id: actor.principal_id.clone(),
        request_id: actor.request_id.clone(),
        redacted_diff: input.redacted_diff,
        occurred_at: input.occurred_at,
    });
    audit_event_id
}

fn create_emergency_operation_record(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: EmergencyOperationInput,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<EmergencyOperationRecord> {
    state.store.create_emergency_operation(
        CreateEmergencyOperationRequest {
            tenant_id: actor.tenant_id.clone(),
            organization_id: input.organization_id,
            project_id: input.project_id,
            operation_kind: input.operation_kind.to_owned(),
            target_resource_kind: input.target_resource_kind.to_owned(),
            target_resource_id: input.target_resource_id,
            requested_by: actor_principal_or_actor_id(actor),
            reason: input.reason,
            operator_alert_document: operator_alert_document(
                input.operation_kind,
                input.target_resource_kind,
            ),
            expires_at: input.expires_at,
        },
        now,
    )
}

fn operator_alert_document(operation_kind: &str, target_resource_kind: &str) -> Value {
    json!({
        "alert_required": true,
        "alert_kind": "emergency_operation",
        "operation_kind": operation_kind,
        "target_resource_kind": target_resource_kind,
        "delivery_status": "not_connected",
        "redacted": true
    })
}

fn record_emergency_operation_audit(
    state: &AppState,
    actor: &AuthenticatedActor,
    operation: &EmergencyOperationRecord,
    before_version: Option<i64>,
    after_version: Option<i64>,
    target_diff: &Value,
    now: chrono::DateTime<chrono::Utc>,
) -> String {
    record_admin_resource_audit(
        state,
        actor,
        AdminResourceAuditInput {
            event_type: "gateway.emergency.disable",
            scope_kind: "tenant",
            scope_id: actor.tenant_id.clone(),
            resource_kind: "EmergencyOperation",
            resource_id: operation.emergency_operation_id.clone(),
            before_version,
            after_version,
            redacted_diff: json!({
                "operation_kind": &operation.operation_kind,
                "target_resource_kind": &operation.target_resource_kind,
                "target_resource_id": &operation.target_resource_id,
                "reason": &operation.reason,
                "expires_at": operation.expires_at,
                "operator_alert": &operation.operator_alert_document,
                "target_diff": target_diff
            }),
            occurred_at: now,
        },
    )
}

fn set_endpoint_emergency_drain(
    state: &AppState,
    endpoint: &ProviderEndpointRecord,
    reason: &str,
    expires_at: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) {
    let Some(publication) = state.store.config_publication(&endpoint.tenant_id) else {
        return;
    };
    state.store.set_endpoint_drain(EndpointDrainRecord {
        tenant_id: endpoint.tenant_id.clone(),
        provider_endpoint_id: endpoint.provider_endpoint_id.clone(),
        config_version: publication.version,
        reason: reason.trim().to_owned(),
        created_at: now,
        expires_at,
    });
}

fn config_snapshot_summary(snapshot: &crate::config::PublishedConfigSnapshot) -> Value {
    json!({
        "snapshot_id": &snapshot.metadata.snapshot_id,
        "tenant_id": &snapshot.metadata.tenant_id,
        "version": snapshot.metadata.version,
        "checksum": &snapshot.metadata.checksum,
        "status": &snapshot.metadata.status,
        "compiled_at": snapshot.metadata.compiled_at,
        "published_at": snapshot.published_at,
        "created_by": &snapshot.created_by,
        "rollback_of": &snapshot.document.rollback_of
    })
}

fn organization_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: &str,
) -> Result<OrganizationRecord> {
    state
        .store
        .organization(organization_id)
        .filter(|organization| organization.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("organization {organization_id}"),
        })
}

fn active_organization_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: &str,
) -> Result<OrganizationRecord> {
    let organization = organization_for_actor(state, actor, organization_id)?;
    if !organization.status.accepts_access() {
        return Err(GatewayError::Authorization {
            reason: "organization_inactive",
        });
    }
    Ok(organization)
}

fn project_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    project_id: &str,
) -> Result<ProjectRecord> {
    state
        .store
        .project(project_id)
        .filter(|project| project.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("project {project_id}"),
        })
}

fn organization_invitation_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: &str,
    invitation_id: &str,
) -> Result<OrganizationInvitationRecord> {
    state
        .store
        .organization_invitation(invitation_id)
        .filter(|invitation| {
            invitation.tenant_id == actor.tenant_id && invitation.organization_id == organization_id
        })
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("organization invitation {invitation_id}"),
        })
}

fn user_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    user_id: &str,
) -> Result<crate::domain::UserRecord> {
    state
        .store
        .user(user_id)
        .filter(|user| user.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("user {user_id}"),
        })
}

fn auth_session_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    user_id: &str,
    auth_session_id: &str,
) -> Result<AuthSessionRecord> {
    state
        .store
        .session_for_principal(&actor.tenant_id, user_id, auth_session_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("auth session {auth_session_id}"),
        })
}

fn external_identity_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    user_id: &str,
    external_identity_id: &str,
) -> Result<ExternalIdentityRecord> {
    state
        .store
        .external_identity_for_principal(&actor.tenant_id, user_id, external_identity_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("external identity {external_identity_id}"),
        })
}

fn organization_member_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: &str,
    organization_member_id: &str,
) -> Result<OrganizationMembershipRecord> {
    organization_for_actor(state, actor, organization_id)?;
    state
        .store
        .organization_member(organization_member_id)
        .filter(|member| {
            member.tenant_id == actor.tenant_id && member.organization_id == organization_id
        })
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("organization member {organization_member_id}"),
        })
}

fn active_organization_member_for_project_assignment(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: &str,
    principal_id: &str,
    organization_member_id: Option<&str>,
) -> Result<OrganizationMembershipRecord> {
    if let Some(organization_member_id) = organization_member_id {
        let member =
            organization_member_for_actor(state, actor, organization_id, organization_member_id)?;
        if member.principal_id == principal_id && member.status.accepts_access() {
            return Ok(member);
        }
        return Err(GatewayError::Authorization {
            reason: "active_organization_membership_required",
        });
    }
    state
        .store
        .organization_memberships_for_principal(principal_id)
        .into_iter()
        .find(|member| {
            member.tenant_id == actor.tenant_id
                && member.organization_id == organization_id
                && member.status.accepts_access()
        })
        .ok_or(GatewayError::Authorization {
            reason: "active_organization_membership_required",
        })
}

fn project_member_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    project_id: &str,
    project_member_id: &str,
) -> Result<ProjectMembershipRecord> {
    project_for_actor(state, actor, project_id)?;
    state
        .store
        .project_member(project_member_id)
        .filter(|member| member.tenant_id == actor.tenant_id && member.project_id == project_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("project member {project_member_id}"),
        })
}

fn project_member_by_id_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    project_member_id: &str,
) -> Result<ProjectMembershipRecord> {
    let member = state
        .store
        .project_member(project_member_id)
        .filter(|member| member.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("project member {project_member_id}"),
        })?;
    project_for_actor(state, actor, &member.project_id)?;
    Ok(member)
}

fn service_account_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    service_account_id: &str,
) -> Result<ServiceAccountRecord> {
    state
        .store
        .service_account(service_account_id)
        .filter(|account| account.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("service account {service_account_id}"),
        })
}

fn api_key_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    api_key_id: &str,
) -> Result<ApiKeyRecord> {
    state
        .store
        .api_key(api_key_id)
        .filter(|api_key| api_key.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("API key {api_key_id}"),
        })
}

fn provider_endpoint_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    provider_endpoint_id: &str,
) -> Result<ProviderEndpointRecord> {
    state
        .store
        .provider_endpoint(provider_endpoint_id)
        .filter(|endpoint| endpoint.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("provider endpoint {provider_endpoint_id}"),
        })
}

fn upstream_credential_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    upstream_credential_id: &str,
) -> Result<UpstreamCredentialRecord> {
    state
        .store
        .upstream_credential(upstream_credential_id)
        .filter(|credential| credential.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("upstream credential {upstream_credential_id}"),
        })
}

fn secret_ref_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    secret_ref_id: &str,
) -> Result<SecretRefRecord> {
    state
        .store
        .secret_ref(secret_ref_id)
        .filter(|secret_ref| secret_ref.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("secret ref {secret_ref_id}"),
        })
}

fn model_target_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    model_target_id: &str,
) -> Result<ModelTargetRecord> {
    state
        .store
        .model_target(model_target_id)
        .filter(|target| target.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("model target {model_target_id}"),
        })
}

fn model_alias_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    model_alias_id: &str,
) -> Result<ModelAliasRecord> {
    state
        .store
        .model_alias(model_alias_id)
        .filter(|alias| alias.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("model alias {model_alias_id}"),
        })
}

fn pricing_sku_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    pricing_sku_id: &str,
) -> Result<PricingSkuRecord> {
    state
        .store
        .pricing_sku(pricing_sku_id)
        .filter(|sku| sku.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("pricing SKU {pricing_sku_id}"),
        })
}

fn budget_policy_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    budget_policy_id: &str,
) -> Result<BudgetPolicyRecord> {
    state
        .store
        .budget_policy(budget_policy_id)
        .filter(|policy| policy.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("budget policy {budget_policy_id}"),
        })
}

fn quota_policy_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    quota_policy_id: &str,
) -> Result<QuotaPolicyRecord> {
    state
        .store
        .quota_policy(quota_policy_id)
        .filter(|policy| policy.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("quota policy {quota_policy_id}"),
        })
}

fn export_job_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    export_job_id: &str,
) -> Result<ExportJobRecord> {
    state
        .store
        .export_job(export_job_id)
        .filter(|job| job.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("export job {export_job_id}"),
        })
}

fn emergency_operation_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    emergency_operation_id: &str,
) -> Result<EmergencyOperationRecord> {
    state
        .store
        .emergency_operation(emergency_operation_id)
        .filter(|operation| operation.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("emergency operation {emergency_operation_id}"),
        })
}

fn export_manifest_for_job(
    state: &AppState,
    job: &ExportJobRecord,
) -> Result<ExportManifestRecord> {
    state
        .store
        .export_manifests_for_job(&job.export_job_id)
        .into_iter()
        .find(|manifest| manifest.tenant_id == job.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("export manifest for job {}", job.export_job_id),
        })
}

fn otel_export_config_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    otel_export_config_id: &str,
) -> Result<OtelExportConfigRecord> {
    state
        .store
        .otel_export_config(otel_export_config_id)
        .filter(|config| config.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("otel export config {otel_export_config_id}"),
        })
}

fn notification_sink_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    notification_sink_id: &str,
) -> Result<NotificationSinkRecord> {
    state
        .store
        .notification_sink(notification_sink_id)
        .filter(|sink| sink.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("notification sink {notification_sink_id}"),
        })
}

fn notification_subscription_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    notification_sink_id: &str,
    notification_subscription_id: &str,
) -> Result<NotificationSubscriptionRecord> {
    state
        .store
        .notification_subscription(notification_subscription_id)
        .filter(|subscription| {
            subscription.tenant_id == actor.tenant_id
                && subscription.notification_sink_id == notification_sink_id
        })
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("notification subscription {notification_subscription_id}"),
        })
}

fn login_provider_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    login_provider_id: &str,
) -> Result<LoginProviderRecord> {
    state
        .store
        .login_provider(login_provider_id)
        .filter(|provider| provider.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("login provider {login_provider_id}"),
        })
}

fn active_login_provider(state: &AppState, login_provider_id: &str) -> Result<LoginProviderRecord> {
    state
        .store
        .login_provider(login_provider_id)
        .filter(|provider| provider.status == ResourceStatus::Active)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("login provider {login_provider_id}"),
        })
}

fn route_policy_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    route_policy_id: &str,
) -> Result<RoutePolicyRecord> {
    state
        .store
        .route_policy(route_policy_id)
        .filter(|policy| policy.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("route policy {route_policy_id}"),
        })
}

fn provider_grant_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    provider_grant_id: &str,
) -> Result<ProviderGrantRecord> {
    state
        .store
        .provider_grant(provider_grant_id)
        .filter(|grant| grant.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("provider grant {provider_grant_id}"),
        })
}

fn routing_group_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    routing_group_id: &str,
) -> Result<RoutingGroupRecord> {
    state
        .store
        .routing_group(routing_group_id)
        .filter(|group| group.tenant_id == actor.tenant_id)
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("routing group {routing_group_id}"),
        })
}

fn routing_group_target_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
    routing_group_id: &str,
    routing_group_target_id: &str,
) -> Result<RoutingGroupTargetRecord> {
    routing_group_for_actor(state, actor, routing_group_id)?;
    state
        .store
        .routing_group_target(routing_group_target_id)
        .filter(|target| {
            target.tenant_id == actor.tenant_id && target.routing_group_id == routing_group_id
        })
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("routing group target {routing_group_target_id}"),
        })
}

fn provider_endpoint_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateProviderEndpointRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.provider_kind.trim().is_empty() {
        errors.push(validation_error("provider_kind", "required"));
    }
    if request.display_name.trim().is_empty() {
        errors.push(validation_error("display_name", "required"));
    }
    if request.protocol_families.is_empty() {
        errors.push(validation_error("protocol_families", "required"));
    }
    let mut protocol_ids = std::collections::HashSet::new();
    for family in &request.protocol_families {
        if !protocol_ids.insert(family.as_str()) {
            errors.push(validation_error(
                "protocol_families",
                "duplicate_protocol_family",
            ));
            break;
        }
    }
    if !safe_http_base_url(&request.upstream_base_url) {
        errors.push(validation_error(
            "upstream_base_url",
            "invalid_http_base_url",
        ));
    }
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    errors
}

fn upstream_credential_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateUpstreamCredentialRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.credential_kind.trim().is_empty() {
        errors.push(validation_error("credential_kind", "required"));
    }
    if valid_secret_ref_id(&request.secret_ref_id) {
        validate_secret_ref_scope_fields(
            state,
            actor,
            "secret_ref_id",
            &request.secret_ref_id,
            request.organization_id.as_deref(),
            None,
            &mut errors,
        );
    } else {
        errors.push(validation_error("secret_ref_id", "invalid_secret_ref"));
    }
    let endpoint = state.store.provider_endpoint(&request.provider_endpoint_id);
    match endpoint {
        Some(endpoint) if endpoint.tenant_id == actor.tenant_id => {
            if request.organization_id.is_some()
                && endpoint.organization_id.is_some()
                && endpoint.organization_id != request.organization_id
            {
                errors.push(validation_error(
                    "provider_endpoint_id",
                    "organization_mismatch",
                ));
            }
        }
        _ => errors.push(validation_error(
            "provider_endpoint_id",
            "unknown_provider_endpoint",
        )),
    }
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    errors
}

fn validate_secret_ref_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    field: &str,
    secret_ref_id: &str,
    organization_id: Option<&str>,
    project_id: Option<&str>,
    errors: &mut Vec<Value>,
) {
    let Some(secret_ref) = state.store.secret_ref(secret_ref_id) else {
        errors.push(validation_error(field, "unknown_secret_ref"));
        return;
    };
    if secret_ref.tenant_id != actor.tenant_id {
        errors.push(validation_error(field, "unknown_secret_ref"));
        return;
    }
    if !matches!(
        secret_ref.status,
        SecretRefStatus::Active | SecretRefStatus::Rotating
    ) {
        errors.push(validation_error(field, "inactive_secret_ref"));
    }
    if secret_ref
        .organization_id
        .as_deref()
        .is_some_and(|secret_org| organization_id != Some(secret_org))
    {
        errors.push(validation_error(field, "secret_ref_scope_mismatch"));
    }
    if secret_ref
        .project_id
        .as_deref()
        .is_some_and(|secret_project| project_id != Some(secret_project))
    {
        errors.push(validation_error(field, "secret_ref_scope_mismatch"));
    }
}

fn model_target_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateModelTargetRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.upstream_model_id.trim().is_empty() {
        errors.push(validation_error("upstream_model_id", "required"));
    }
    let endpoint = state.store.provider_endpoint(&request.provider_endpoint_id);
    match endpoint {
        Some(endpoint) if endpoint.tenant_id == actor.tenant_id => {
            if !endpoint
                .protocol_families
                .contains(&request.protocol_family)
            {
                errors.push(validation_error(
                    "protocol_family",
                    "provider_endpoint_protocol_mismatch",
                ));
            }
            if request.organization_id.is_some()
                && endpoint.organization_id.is_some()
                && endpoint.organization_id != request.organization_id
            {
                errors.push(validation_error(
                    "provider_endpoint_id",
                    "organization_mismatch",
                ));
            }
        }
        _ => errors.push(validation_error(
            "provider_endpoint_id",
            "unknown_provider_endpoint",
        )),
    }
    if let Some(credential_id) = request.upstream_credential_id.as_deref() {
        match state.store.upstream_credential(credential_id) {
            Some(credential) if credential.tenant_id == actor.tenant_id => {
                if credential.provider_endpoint_id != request.provider_endpoint_id {
                    errors.push(validation_error(
                        "upstream_credential_id",
                        "provider_endpoint_mismatch",
                    ));
                }
            }
            _ => errors.push(validation_error(
                "upstream_credential_id",
                "unknown_upstream_credential",
            )),
        }
    }
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    errors
}

fn model_alias_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateModelAliasRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.alias_name.trim().is_empty() {
        errors.push(validation_error("alias_name", "required"));
    }
    if request.route_policy_id.is_some() {
        errors.push(validation_error(
            "route_policy_id",
            "bind_after_route_policy_create",
        ));
    }
    if state
        .store
        .model_aliases_for_tenant(&actor.tenant_id)
        .iter()
        .any(|alias| {
            alias.organization_id == request.organization_id
                && alias.project_id == request.project_id
                && alias.alias_name == request.alias_name.trim()
                && alias.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("alias_name", "duplicate_name"));
    }
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    if let Some(project_id) = request.project_id.as_deref() {
        match project_for_actor(state, actor, project_id) {
            Ok(project) => {
                if request.organization_id.is_some()
                    && Some(project.organization_id.as_str()) != request.organization_id.as_deref()
                {
                    errors.push(validation_error("project_id", "organization_mismatch"));
                }
            }
            Err(_) => errors.push(validation_error("project_id", "unknown_project")),
        }
    }
    errors
}

fn model_alias_update_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    model_alias_id: &str,
    request: &AdminUpdateModelAliasRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.status.is_none() && request.route_policy_id.is_none() {
        errors.push(validation_error("update", "empty_update"));
    }
    if let Some(route_policy_id) = request.route_policy_id.as_deref() {
        let alias = state.store.model_alias(model_alias_id);
        let policy = state.store.route_policy(route_policy_id);
        match (&alias, &policy) {
            (Some(alias), Some(policy))
                if alias.tenant_id == actor.tenant_id && policy.tenant_id == actor.tenant_id =>
            {
                if policy.model_alias_id != alias.model_alias_id {
                    errors.push(validation_error("route_policy_id", "model_alias_mismatch"));
                }
                if policy.protocol_family != alias.protocol_family {
                    errors.push(validation_error(
                        "route_policy_id",
                        "protocol_family_mismatch",
                    ));
                }
            }
            (_, Some(_)) => {
                errors.push(validation_error("route_policy_id", "unknown_route_policy"));
            }
            _ => errors.push(validation_error("route_policy_id", "unknown_route_policy")),
        }
    }
    errors
}

fn pricing_sku_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreatePricingSkuRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.name.trim().is_empty() {
        errors.push(validation_error("name", "required"));
    }
    if !valid_currency_code(&request.currency) {
        errors.push(validation_error("currency", "invalid_currency"));
    }
    if request.unit != "micro_usd" {
        errors.push(validation_error("unit", "invalid_unit"));
    }
    if request.model_id_patterns.is_empty()
        || request
            .model_id_patterns
            .iter()
            .any(|pattern| pattern.trim().is_empty())
    {
        errors.push(validation_error("model_id_patterns", "required"));
    }
    if request
        .provider_endpoint_patterns
        .iter()
        .any(|pattern| pattern.trim().is_empty())
    {
        errors.push(validation_error(
            "provider_endpoint_patterns",
            "empty_pattern",
        ));
    }
    let effective_from = request.effective_from.unwrap_or(now);
    if let Some(effective_until) = request.effective_until {
        if effective_until <= effective_from {
            errors.push(validation_error("effective_until", "invalid_window"));
        }
    }
    pricing_document_validation_errors(
        &request.pricing_document,
        &request.currency,
        &request.unit,
        &mut errors,
    );
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    if state
        .store
        .pricing_skus_for_tenant(&actor.tenant_id)
        .iter()
        .any(|sku| {
            sku.organization_id == request.organization_id
                && sku.name == request.name.trim()
                && sku.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("name", "duplicate_name"));
    }
    errors
}

fn pricing_document_validation_errors(
    document: &Value,
    currency: &str,
    unit: &str,
    errors: &mut Vec<Value>,
) {
    let Some(object) = document.as_object() else {
        errors.push(validation_error("pricing_document", "invalid_document"));
        return;
    };
    if object.get("schema").and_then(Value::as_str) != Some("gateway.pricing.v1") {
        errors.push(validation_error(
            "pricing_document.schema",
            "invalid_schema",
        ));
    }
    if object.get("currency").and_then(Value::as_str) != Some(currency) {
        errors.push(validation_error(
            "pricing_document.currency",
            "currency_mismatch",
        ));
    }
    if object.get("unit").and_then(Value::as_str) != Some(unit) {
        errors.push(validation_error("pricing_document.unit", "unit_mismatch"));
    }
    if object.get("tokens").is_none() && object.get("flat_request_cost").is_none() {
        errors.push(validation_error(
            "pricing_document",
            "missing_price_components",
        ));
    }
}

fn valid_currency_code(value: &str) -> bool {
    value.len() == 3 && value.chars().all(|ch| ch.is_ascii_uppercase())
}

fn budget_policy_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateBudgetPolicyRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    validate_budget_scope_fields(state, actor, request, &mut errors);
    validate_budget_enum_fields(request, &mut errors);
    validate_budget_limit_fields(request, &mut errors);
    if state
        .store
        .budget_policies_for_tenant(&actor.tenant_id)
        .iter()
        .any(|policy| {
            policy.scope_kind == request.scope_kind
                && policy.scope_id == request.scope_id
                && policy.limit_kind == request.limit_kind
                && policy.period == request.period
                && policy.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("scope_id", "duplicate_policy"));
    }
    errors
}

fn validate_budget_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateBudgetPolicyRequest,
    errors: &mut Vec<Value>,
) {
    match request.scope_kind.as_str() {
        "tenant" if request.scope_id == actor.tenant_id => {}
        "tenant" => errors.push(validation_error("scope_id", "tenant_mismatch")),
        "organization" => {
            if organization_for_actor(state, actor, &request.scope_id).is_err() {
                errors.push(validation_error("scope_id", "unknown_organization"));
            }
        }
        "project" => {
            if project_for_actor(state, actor, &request.scope_id).is_err() {
                errors.push(validation_error("scope_id", "unknown_project"));
            }
        }
        "credential" => {
            if state
                .store
                .upstream_credential(&request.scope_id)
                .is_none_or(|credential| credential.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_credential"));
            }
        }
        "alias" => {
            if state
                .store
                .model_alias(&request.scope_id)
                .is_none_or(|alias| alias.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_alias"));
            }
        }
        "group" => {
            if state
                .store
                .routing_group(&request.scope_id)
                .is_none_or(|group| group.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_group"));
            }
        }
        "endpoint" => {
            if state
                .store
                .provider_endpoint(&request.scope_id)
                .is_none_or(|endpoint| endpoint.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_endpoint"));
            }
        }
        "target" => {
            if state
                .store
                .model_target(&request.scope_id)
                .is_none_or(|target| target.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_target"));
            }
        }
        _ => errors.push(validation_error("scope_kind", "invalid_scope_kind")),
    }
}

fn validate_budget_enum_fields(request: &AdminCreateBudgetPolicyRequest, errors: &mut Vec<Value>) {
    if !matches!(
        request.period.as_str(),
        "rolling" | "calendar_day" | "calendar_month" | "lifetime" | "custom_window"
    ) {
        errors.push(validation_error("period", "invalid_period"));
    }
    if !matches!(
        request.limit_kind.as_str(),
        "cost" | "tokens" | "requests" | "concurrency" | "stream_seconds"
    ) {
        errors.push(validation_error("limit_kind", "invalid_limit_kind"));
    }
    if !matches!(
        request.overage_mode.as_str(),
        "notify_only"
            | "block_new_requests"
            | "prefer_low_cost_route"
            | "fallback_low_cost_route"
            | "require_exact_usage"
    ) {
        errors.push(validation_error("overage_mode", "invalid_overage_mode"));
    }
    if !matches!(
        request.consistency_mode.as_str(),
        "eventual" | "strong_terminal" | "manual_review"
    ) {
        errors.push(validation_error(
            "consistency_mode",
            "invalid_consistency_mode",
        ));
    }
    if request.reset_policy.trim().is_empty() {
        errors.push(validation_error("reset_policy", "required"));
    }
}

fn validate_budget_limit_fields(request: &AdminCreateBudgetPolicyRequest, errors: &mut Vec<Value>) {
    if request.limit_kind == "cost" {
        match request.currency.as_deref() {
            Some(currency) if valid_currency_code(currency) => {}
            Some(_) => errors.push(validation_error("currency", "invalid_currency")),
            None => errors.push(validation_error("currency", "required")),
        }
    } else if request.currency.is_some() {
        errors.push(validation_error("currency", "non_cost_currency"));
    }
    if request.hard_limit.is_none() && request.soft_limit.is_none() && request.thresholds.is_empty()
    {
        errors.push(validation_error("limit", "required"));
    }
    if request.hard_limit.is_some_and(|limit| limit <= 0)
        || request.soft_limit.is_some_and(|limit| limit <= 0)
        || request.thresholds.iter().any(|threshold| *threshold <= 0)
    {
        errors.push(validation_error("limit", "positive_required"));
    }
    if let (Some(soft_limit), Some(hard_limit)) = (request.soft_limit, request.hard_limit) {
        if soft_limit > hard_limit {
            errors.push(validation_error("soft_limit", "exceeds_hard_limit"));
        }
    }
    if request.hard_limit.is_some()
        && request.overage_mode == "notify_only"
        && request.consistency_mode != "manual_review"
    {
        errors.push(validation_error(
            "overage_mode",
            "hard_limit_notify_only_invalid",
        ));
    }
}

fn quota_policy_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateQuotaPolicyRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    validate_quota_scope_fields(state, actor, request, &mut errors);
    validate_quota_shape_fields(request, &mut errors);
    if state
        .store
        .quota_policies_for_tenant(&actor.tenant_id)
        .iter()
        .any(|policy| {
            policy.scope_kind == request.scope_kind
                && policy.scope_id == request.scope_id
                && policy.counter_kind == request.counter_kind
                && policy.window == request.window
                && policy.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("scope_id", "duplicate_policy"));
    }
    errors
}

fn validate_quota_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateQuotaPolicyRequest,
    errors: &mut Vec<Value>,
) {
    match request.scope_kind.as_str() {
        "tenant" if request.scope_id == actor.tenant_id => {}
        "tenant" => errors.push(validation_error("scope_id", "tenant_mismatch")),
        "organization" => {
            if organization_for_actor(state, actor, &request.scope_id).is_err() {
                errors.push(validation_error("scope_id", "unknown_organization"));
            }
        }
        "project" => {
            if project_for_actor(state, actor, &request.scope_id).is_err() {
                errors.push(validation_error("scope_id", "unknown_project"));
            }
        }
        "credential" => {
            if state
                .store
                .upstream_credential(&request.scope_id)
                .is_none_or(|credential| credential.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_credential"));
            }
        }
        "alias" => {
            if state
                .store
                .model_alias(&request.scope_id)
                .is_none_or(|alias| alias.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_alias"));
            }
        }
        "endpoint" => {
            if state
                .store
                .provider_endpoint(&request.scope_id)
                .is_none_or(|endpoint| endpoint.tenant_id != actor.tenant_id)
            {
                errors.push(validation_error("scope_id", "unknown_endpoint"));
            }
        }
        "protocol_family" => {
            if !protocol_family_scope_exists(&request.scope_id) {
                errors.push(validation_error("scope_id", "unknown_protocol_family"));
            }
        }
        _ => errors.push(validation_error("scope_kind", "invalid_scope_kind")),
    }
}

fn validate_quota_shape_fields(request: &AdminCreateQuotaPolicyRequest, errors: &mut Vec<Value>) {
    let counter_valid = matches!(
        request.counter_kind.as_str(),
        "request_rate"
            | "token_estimate_rate"
            | "token_actual_rate"
            | "concurrent_request"
            | "concurrent_stream"
            | "stream_duration"
            | "request_body_bytes"
    );
    if !counter_valid {
        errors.push(validation_error("counter_kind", "invalid_counter_kind"));
    }
    if request.limit <= 0 {
        errors.push(validation_error("limit", "positive_required"));
    }
    if request.burst_limit.is_some_and(|limit| limit <= 0) {
        errors.push(validation_error("burst_limit", "positive_required"));
    }
    if !matches!(
        request.loss_behavior.as_str(),
        "fail_open" | "fail_limited" | "fail_closed"
    ) {
        errors.push(validation_error("loss_behavior", "invalid_loss_behavior"));
    }
    if request.loss_behavior == "fail_limited" && request.burst_limit.is_none() {
        errors.push(validation_error("burst_limit", "required_for_fail_limited"));
    }
    if counter_valid {
        if !quota_counter_scope_supported(&request.counter_kind, &request.scope_kind) {
            errors.push(validation_error("scope_kind", "unsupported_counter_scope"));
        }
        if !quota_counter_window_supported(&request.counter_kind, &request.window) {
            errors.push(validation_error("window", "unsupported_counter_window"));
        }
        if !quota_counter_increment_source_supported(
            &request.counter_kind,
            &request.increment_source,
        ) {
            errors.push(validation_error(
                "increment_source",
                "unsupported_increment_source",
            ));
        }
    }
}

fn protocol_family_scope_exists(scope_id: &str) -> bool {
    ProtocolFamily::all()
        .iter()
        .any(|family| family.as_str() == scope_id)
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

fn otel_export_config_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateOtelExportConfigRequest,
    existing_config_id: Option<&str>,
) -> Vec<Value> {
    let mut errors = Vec::new();
    validate_otel_export_scope_fields(state, actor, request, &mut errors);
    validate_otel_export_shape_fields(request, &mut errors);
    validate_otel_header_secret_ref_scope_fields(state, actor, request, &mut errors);
    let duplicate = state
        .store
        .otel_export_configs_for_tenant(&actor.tenant_id)
        .iter()
        .any(|config| {
            existing_config_id.is_none_or(|existing_id| config.otel_export_config_id != existing_id)
                && config.organization_id == inferred_otel_organization_id(state, actor, request)
                && config.project_id == request.project_id
                && config.endpoint_url == request.endpoint_url
                && config.protocol == request.protocol
                && config.status != ResourceStatus::Deleted
        });
    if duplicate {
        errors.push(validation_error("endpoint_url", "duplicate_config"));
    }
    errors
}

fn validate_otel_export_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateOtelExportConfigRequest,
    errors: &mut Vec<Value>,
) {
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    if let Some(project_id) = request.project_id.as_deref() {
        let Some(project) = state.store.project(project_id) else {
            errors.push(validation_error("project_id", "unknown_project"));
            return;
        };
        if project.tenant_id != actor.tenant_id {
            errors.push(validation_error("project_id", "unknown_project"));
            return;
        }
        if request
            .organization_id
            .as_deref()
            .is_some_and(|organization_id| organization_id != project.organization_id)
        {
            errors.push(validation_error(
                "organization_id",
                "project_organization_mismatch",
            ));
        }
    }
}

fn validate_otel_export_shape_fields(
    request: &AdminCreateOtelExportConfigRequest,
    errors: &mut Vec<Value>,
) {
    if safe_otel_endpoint_host(&request.endpoint_url).is_none() {
        errors.push(validation_error("endpoint_url", "invalid_endpoint_url"));
    }
    if !matches!(request.protocol.as_str(), "otlp_http" | "otlp_grpc") {
        errors.push(validation_error("protocol", "invalid_protocol"));
    }
    validate_otel_header_ref_fields(&request.header_refs, errors);
    validate_otel_signal_fields(&request.enabled_signals, errors);
    validate_otel_resource_attribute_fields(&request.resource_attributes, errors);
    if !(5..=3600).contains(&request.export_interval_seconds) {
        errors.push(validation_error(
            "export_interval_seconds",
            "invalid_interval",
        ));
    }
    if !(1..=60).contains(&request.timeout_seconds)
        || request.timeout_seconds >= request.export_interval_seconds
    {
        errors.push(validation_error("timeout_seconds", "invalid_timeout"));
    }
}

fn validate_otel_header_ref_fields(header_refs: &[OtelHeaderRef], errors: &mut Vec<Value>) {
    if header_refs.len() > 8 {
        errors.push(validation_error("header_refs", "too_many_header_refs"));
    }
    let mut names = HashSet::new();
    for header in header_refs {
        let normalized_name = header.name.to_ascii_lowercase();
        if !valid_otel_header_name(&normalized_name) {
            errors.push(validation_error("header_refs.name", "invalid_header_name"));
        }
        if !names.insert(normalized_name) {
            errors.push(validation_error(
                "header_refs.name",
                "duplicate_header_name",
            ));
        }
        if !valid_secret_ref_id(&header.secret_ref_id) {
            errors.push(validation_error(
                "header_refs.secret_ref_id",
                "invalid_secret_ref",
            ));
        }
    }
}

fn validate_otel_header_secret_ref_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateOtelExportConfigRequest,
    errors: &mut Vec<Value>,
) {
    let organization_id = inferred_otel_organization_id(state, actor, request);
    for header in &request.header_refs {
        if valid_secret_ref_id(&header.secret_ref_id) {
            validate_secret_ref_scope_fields(
                state,
                actor,
                "header_refs.secret_ref_id",
                &header.secret_ref_id,
                organization_id.as_deref(),
                request.project_id.as_deref(),
                errors,
            );
        }
    }
}

fn validate_otel_signal_fields(enabled_signals: &[String], errors: &mut Vec<Value>) {
    if enabled_signals.is_empty() || !enabled_signals.iter().any(|signal| signal == "metrics") {
        errors.push(validation_error("enabled_signals", "metrics_required"));
    }
    let mut signals = HashSet::new();
    for signal in enabled_signals {
        if signal != "metrics" {
            errors.push(validation_error("enabled_signals", "unsupported_signal"));
        }
        if !signals.insert(signal) {
            errors.push(validation_error("enabled_signals", "duplicate_signal"));
        }
    }
}

fn validate_otel_resource_attribute_fields(
    attributes: &[OtelResourceAttribute],
    errors: &mut Vec<Value>,
) {
    if attributes.len() > 16 {
        errors.push(validation_error(
            "resource_attributes",
            "too_many_attributes",
        ));
    }
    let mut keys = HashSet::new();
    for attribute in attributes {
        if !valid_otel_attribute_key(&attribute.key) {
            errors.push(validation_error(
                "resource_attributes.key",
                "invalid_attribute_key",
            ));
        }
        if !keys.insert(attribute.key.to_ascii_lowercase()) {
            errors.push(validation_error(
                "resource_attributes.key",
                "duplicate_attribute_key",
            ));
        }
        if attribute.value.is_empty() || attribute.value.len() > 128 {
            errors.push(validation_error(
                "resource_attributes.value",
                "invalid_attribute_value",
            ));
        }
        if otel_attribute_key_is_dynamic_or_secret(&attribute.key) {
            errors.push(validation_error(
                "resource_attributes.key",
                "forbidden_attribute_key",
            ));
        }
    }
}

fn inferred_otel_organization_id(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateOtelExportConfigRequest,
) -> Option<String> {
    request.organization_id.clone().or_else(|| {
        request.project_id.as_deref().and_then(|project_id| {
            state
                .store
                .project(project_id)
                .filter(|project| project.tenant_id == actor.tenant_id)
                .map(|project| project.organization_id)
        })
    })
}

fn merged_otel_export_config_request(
    current: &OtelExportConfigRecord,
    update: &AdminUpdateOtelExportConfigRequest,
) -> AdminCreateOtelExportConfigRequest {
    AdminCreateOtelExportConfigRequest {
        idempotency_key: "merged_update".to_owned(),
        organization_id: update
            .organization_id
            .clone()
            .or_else(|| current.organization_id.clone()),
        project_id: update
            .project_id
            .clone()
            .or_else(|| current.project_id.clone()),
        endpoint_url: update
            .endpoint_url
            .clone()
            .unwrap_or_else(|| current.endpoint_url.clone()),
        protocol: update
            .protocol
            .clone()
            .unwrap_or_else(|| current.protocol.clone()),
        header_refs: update
            .header_refs
            .clone()
            .unwrap_or_else(|| current.header_refs.clone()),
        enabled_signals: update
            .enabled_signals
            .clone()
            .unwrap_or_else(|| current.enabled_signals.clone()),
        resource_attributes: update
            .resource_attributes
            .clone()
            .unwrap_or_else(|| current.resource_attributes.clone()),
        export_interval_seconds: update
            .export_interval_seconds
            .unwrap_or(current.export_interval_seconds),
        timeout_seconds: update.timeout_seconds.unwrap_or(current.timeout_seconds),
    }
}

fn merged_notification_sink_request(
    current: &NotificationSinkRecord,
    update: &AdminUpdateNotificationSinkRequest,
) -> AdminCreateNotificationSinkRequest {
    AdminCreateNotificationSinkRequest {
        idempotency_key: "merged_update".to_owned(),
        organization_id: current.organization_id.clone(),
        project_id: current.project_id.clone(),
        name: update.name.clone().unwrap_or_else(|| current.name.clone()),
        sink_kind: current.sink_kind.clone(),
        endpoint_config: update
            .endpoint_config
            .clone()
            .unwrap_or_else(|| current.endpoint_config.clone()),
        signing_secret_ref_id: match &update.signing_secret_ref_id {
            NullablePatch::Unset => current.signing_secret_ref_id.clone(),
            NullablePatch::Set(value) => value.clone(),
        },
    }
}

fn safe_otel_endpoint_host(value: &str) -> Option<String> {
    let uri = value.parse::<http::Uri>().ok()?;
    if uri.scheme_str() != Some("https") || uri.query().is_some() {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host();
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    Some(host.to_owned())
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

fn notification_sink_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateNotificationSinkRequest,
) -> Vec<Value> {
    notification_sink_validation_errors_with_excluded_id(state, actor, request, None)
}

fn notification_sink_validation_errors_with_excluded_id(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateNotificationSinkRequest,
    excluded_notification_sink_id: Option<&str>,
) -> Vec<Value> {
    let mut errors = Vec::new();
    validate_notification_scope_fields(
        state,
        actor,
        request.organization_id.as_deref(),
        request.project_id.as_deref(),
        &mut errors,
    );
    validate_notification_sink_shape_fields(request, &mut errors);
    let inferred_organization_id = inferred_notification_organization_id(
        state,
        actor,
        request.organization_id.as_deref(),
        request.project_id.as_deref(),
    );
    if request.sink_kind == "webhook" {
        if let Some(signing_secret_ref_id) = request.signing_secret_ref_id.as_deref() {
            if valid_secret_ref_id(signing_secret_ref_id) {
                validate_secret_ref_scope_fields(
                    state,
                    actor,
                    "signing_secret_ref_id",
                    signing_secret_ref_id,
                    inferred_organization_id.as_deref(),
                    request.project_id.as_deref(),
                    &mut errors,
                );
            }
        }
    }
    if state
        .store
        .notification_sinks_for_tenant(&actor.tenant_id)
        .iter()
        .any(|sink| {
            sink.organization_id == inferred_organization_id
                && sink.project_id == request.project_id
                && sink.name == request.name.trim()
                && sink.sink_kind == request.sink_kind
                && sink.status != ResourceStatus::Deleted
                && Some(sink.notification_sink_id.as_str()) != excluded_notification_sink_id
        })
    {
        errors.push(validation_error("name", "duplicate_sink"));
    }
    errors
}

fn validate_notification_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: Option<&str>,
    project_id: Option<&str>,
    errors: &mut Vec<Value>,
) {
    if let Some(organization_id) = organization_id {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    if let Some(project_id) = project_id {
        let Some(project) = state.store.project(project_id) else {
            errors.push(validation_error("project_id", "unknown_project"));
            return;
        };
        if project.tenant_id != actor.tenant_id {
            errors.push(validation_error("project_id", "unknown_project"));
            return;
        }
        if organization_id.is_some_and(|organization_id| organization_id != project.organization_id)
        {
            errors.push(validation_error(
                "organization_id",
                "project_organization_mismatch",
            ));
        }
    }
}

fn validate_notification_sink_shape_fields(
    request: &AdminCreateNotificationSinkRequest,
    errors: &mut Vec<Value>,
) {
    if request.name.trim().is_empty() || request.name.len() > 80 {
        errors.push(validation_error("name", "invalid_name"));
    }
    if notification_document_contains_sensitive_keys(&request.endpoint_config) {
        errors.push(validation_error(
            "endpoint_config",
            "sensitive_endpoint_config",
        ));
    }
    match request.sink_kind.as_str() {
        "webhook" => validate_webhook_notification_sink_fields(request, errors),
        "stdout" | "disabled" => validate_local_notification_sink_fields(request, errors),
        "object_export" | "pubsub" => {
            errors.push(validation_error("sink_kind", "unsupported_sink_kind"));
        }
        _ => errors.push(validation_error("sink_kind", "invalid_sink_kind")),
    }
}

fn validate_webhook_notification_sink_fields(
    request: &AdminCreateNotificationSinkRequest,
    errors: &mut Vec<Value>,
) {
    let Some(object) = request.endpoint_config.as_object() else {
        errors.push(validation_error("endpoint_config", "invalid_document"));
        return;
    };
    match object.get("url").and_then(Value::as_str) {
        Some(url) if safe_otel_endpoint_host(url).is_some() => {}
        Some(_) => errors.push(validation_error("endpoint_config.url", "invalid_url")),
        None => errors.push(validation_error("endpoint_config.url", "required")),
    }
    if !request
        .signing_secret_ref_id
        .as_deref()
        .is_some_and(valid_secret_ref_id)
    {
        errors.push(validation_error(
            "signing_secret_ref_id",
            "required_secret_ref",
        ));
    }
}

fn validate_local_notification_sink_fields(
    request: &AdminCreateNotificationSinkRequest,
    errors: &mut Vec<Value>,
) {
    if request.signing_secret_ref_id.is_some() {
        errors.push(validation_error(
            "signing_secret_ref_id",
            "forbidden_secret_ref",
        ));
    }
    if !request.endpoint_config.is_object() {
        errors.push(validation_error("endpoint_config", "invalid_document"));
    }
}

fn notification_subscription_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    notification_sink_id: &str,
    request: &AdminCreateNotificationSubscriptionRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    let sink = state.store.notification_sink(notification_sink_id);
    match sink.as_ref() {
        Some(sink)
            if sink.tenant_id == actor.tenant_id && sink.status != ResourceStatus::Deleted => {}
        Some(_) | None => errors.push(validation_error("notification_sink_id", "unknown_sink")),
    }
    if !valid_notification_event_family(&request.event_family) {
        errors.push(validation_error("event_family", "invalid_event_family"));
    }
    if !request.filter_document.is_object()
        || notification_document_contains_sensitive_keys(&request.filter_document)
    {
        errors.push(validation_error("filter_document", "invalid_filter"));
    }
    if state
        .store
        .notification_subscriptions_for_sink(notification_sink_id)
        .iter()
        .any(|subscription| {
            subscription.event_family == request.event_family
                && subscription.filter_document == request.filter_document
                && subscription.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("event_family", "duplicate_subscription"));
    }
    errors
}

fn login_provider_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateLoginProviderRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if !matches!(request.provider_kind.as_str(), "github_oauth_app" | "oidc") {
        errors.push(validation_error("provider_kind", "invalid_provider_kind"));
    }
    if request.display_name.trim().is_empty() || request.display_name.len() > 120 {
        errors.push(validation_error("display_name", "invalid_display_name"));
    }
    if !request.config_document.is_object()
        || login_provider_config_contains_sensitive_material(&request.config_document)
    {
        errors.push(validation_error("config_document", "invalid_config"));
        return errors;
    }
    if !login_config_string(&request.config_document, "client_id")
        .is_some_and(|value| !value.trim().is_empty() && value.len() <= 256)
    {
        errors.push(validation_error(
            "config_document.client_id",
            "invalid_client_id",
        ));
    }
    if !login_config_string(&request.config_document, "client_secret_ref")
        .is_some_and(valid_secret_ref_id)
    {
        errors.push(validation_error(
            "config_document.client_secret_ref",
            "invalid_secret_ref",
        ));
    }
    if !login_config_string(&request.config_document, "redirect_uri")
        .is_some_and(login_provider_https_url_is_safe)
    {
        errors.push(validation_error(
            "config_document.redirect_uri",
            "invalid_redirect_uri",
        ));
    }
    if request.provider_kind == "oidc" {
        if !login_config_string(&request.config_document, "issuer")
            .is_some_and(login_provider_https_url_is_safe)
        {
            errors.push(validation_error("config_document.issuer", "invalid_issuer"));
        }
        if !login_config_string(&request.config_document, "authorization_url")
            .is_some_and(login_provider_https_url_is_safe)
        {
            errors.push(validation_error(
                "config_document.authorization_url",
                "invalid_authorization_url",
            ));
        }
    }
    for field in ["authorization_url", "token_url"] {
        if login_config_string(&request.config_document, field)
            .is_some_and(|url| !login_provider_https_url_is_safe(url))
        {
            errors.push(validation_error(
                &format!("config_document.{field}"),
                "invalid_url",
            ));
        }
    }
    if request
        .config_document
        .get("scopes")
        .is_some_and(|scopes| !login_provider_scopes_are_valid(scopes))
    {
        errors.push(validation_error("config_document.scopes", "invalid_scopes"));
    }
    if state
        .store
        .login_providers_for_tenant(&actor.tenant_id)
        .iter()
        .any(|provider| {
            provider.provider_kind == request.provider_kind
                && provider.display_name == request.display_name.trim()
                && provider.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("display_name", "duplicate_provider"));
    }
    errors
}

fn organization_invitation_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization: &OrganizationRecord,
    request: &AdminCreateOrganizationInvitationRequest,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request
        .invited_email
        .as_deref()
        .and_then(normalized_email)
        .is_none()
        && request
            .invited_principal_id
            .as_deref()
            .is_none_or(|principal_id| principal_id.trim().is_empty())
    {
        errors.push(validation_error("invited_target", "required"));
    }
    if request.invited_email.is_some() && request.invited_principal_id.is_some() {
        errors.push(validation_error("invited_target", "ambiguous"));
    }
    if request
        .role_id
        .as_deref()
        .is_some_and(|role_id| role_id.trim().is_empty() || role_id.len() > 80)
    {
        errors.push(validation_error("role_id", "invalid_role_id"));
    }
    if request.expires_at.is_some_and(|expires_at| {
        expires_at <= now || expires_at > now + chrono::Duration::days(30)
    }) {
        errors.push(validation_error("expires_at", "invalid_expiry"));
    }
    if let Some(project_id) = request.project_id.as_deref() {
        match state.store.project(project_id) {
            Some(project)
                if project.tenant_id == actor.tenant_id
                    && project.organization_id == organization.organization_id
                    && project.status.accepts_access() => {}
            Some(_) | None => errors.push(validation_error("project_id", "invalid_project")),
        }
    }
    errors
}

fn normalized_email(value: &str) -> Option<String> {
    let email = value.trim().to_ascii_lowercase();
    if email.len() <= 320
        && email.contains('@')
        && !email.contains(char::is_whitespace)
        && !email.starts_with('@')
        && !email.ends_with('@')
    {
        Some(email)
    } else {
        None
    }
}

fn validate_notification_sink_status(status: &ResourceStatus) -> Result<()> {
    if matches!(
        status,
        ResourceStatus::Active
            | ResourceStatus::Disabled
            | ResourceStatus::Degraded
            | ResourceStatus::Deleted
    ) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "notification_sink_status_invalid".to_owned(),
        })
    }
}

fn validate_notification_subscription_status(status: &ResourceStatus) -> Result<()> {
    if matches!(
        status,
        ResourceStatus::Active | ResourceStatus::Disabled | ResourceStatus::Deleted
    ) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "notification_subscription_status_invalid".to_owned(),
        })
    }
}

fn validate_login_provider_status(status: &ResourceStatus) -> Result<()> {
    if matches!(
        status,
        ResourceStatus::Active | ResourceStatus::Disabled | ResourceStatus::Deleted
    ) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "login_provider_status_invalid".to_owned(),
        })
    }
}

fn validate_user_status(status: &DirectoryStatus) -> Result<()> {
    if matches!(
        status,
        DirectoryStatus::Active | DirectoryStatus::Disabled | DirectoryStatus::Deleted
    ) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "user_status_invalid".to_owned(),
        })
    }
}

fn single_user_credentials_match(
    config: &SingleUserAuthConfig,
    request: &SingleUserLoginRequest,
) -> bool {
    constant_time_bytes_eq(config.username.as_bytes(), request.username.as_bytes())
        && constant_time_bytes_eq(config.password.as_bytes(), request.password.as_bytes())
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn login_config_string<'a>(config: &'a Value, field: &str) -> Option<&'a str> {
    config.get(field).and_then(Value::as_str)
}

fn login_provider_https_url_is_safe(value: &str) -> bool {
    value.starts_with("https://") && !value.contains(char::is_whitespace) && !value.contains('?')
}

fn login_provider_scopes_are_valid(value: &Value) -> bool {
    value.as_array().is_some_and(|scopes| {
        scopes
            .iter()
            .all(|scope| scope.as_str().is_some_and(|value| !value.trim().is_empty()))
    })
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

fn inferred_notification_organization_id(
    state: &AppState,
    actor: &AuthenticatedActor,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Option<String> {
    organization_id.map(ToOwned::to_owned).or_else(|| {
        project_id.and_then(|project_id| {
            state
                .store
                .project(project_id)
                .filter(|project| project.tenant_id == actor.tenant_id)
                .map(|project| project.organization_id)
        })
    })
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

fn route_policy_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateRoutePolicyRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.name.trim().is_empty() {
        errors.push(validation_error("name", "required"));
    }
    let alias = state.store.model_alias(&request.model_alias_id);
    let group = state.store.routing_group(&request.routing_group_id);
    match &alias {
        Some(alias) if alias.tenant_id == actor.tenant_id => {}
        _ => errors.push(validation_error("model_alias_id", "unknown_model_alias")),
    }
    match &group {
        Some(group) if group.tenant_id == actor.tenant_id => {}
        _ => errors.push(validation_error(
            "routing_group_id",
            "unknown_routing_group",
        )),
    }
    if let (Some(alias), Some(group)) = (&alias, &group) {
        if alias.tenant_id == actor.tenant_id && group.tenant_id == actor.tenant_id {
            if alias.protocol_family != group.protocol_family {
                errors.push(validation_error(
                    "routing_group_id",
                    "protocol_family_mismatch",
                ));
            }
            if alias.organization_id.is_some()
                && group.organization_id.is_some()
                && alias.organization_id != group.organization_id
            {
                errors.push(validation_error(
                    "routing_group_id",
                    "organization_mismatch",
                ));
            }
            let organization_id = alias
                .organization_id
                .clone()
                .or_else(|| group.organization_id.clone());
            if state
                .store
                .route_policies_for_tenant(&actor.tenant_id)
                .iter()
                .any(|policy| {
                    policy.organization_id == organization_id
                        && policy.name == request.name.trim()
                        && policy.status != ResourceStatus::Deleted
                })
            {
                errors.push(validation_error("name", "duplicate_name"));
            }
        }
    }
    errors
}

fn provider_grant_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateProviderGrantRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    validate_provider_grant_scope_fields(state, actor, request, &mut errors);
    validate_provider_grant_resource_fields(state, actor, request, &mut errors);
    validate_provider_grant_effect_fields(request, &mut errors);
    if state
        .store
        .provider_grants_for_tenant(&actor.tenant_id)
        .iter()
        .any(|grant| {
            grant.scope_kind == request.scope_kind
                && grant.scope_id == request.scope_id
                && grant.resource_kind == request.resource_kind
                && grant.resource_id == request.resource_id
                && grant.effect == request.effect
                && grant.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("resource_id", "duplicate_grant"));
    }
    errors
}

fn validate_provider_grant_scope_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateProviderGrantRequest,
    errors: &mut Vec<Value>,
) {
    match request.scope_kind.as_str() {
        "organization" => {
            if organization_for_actor(state, actor, &request.scope_id).is_err() {
                errors.push(validation_error("scope_id", "unknown_organization"));
            }
        }
        "project" => {
            if project_for_actor(state, actor, &request.scope_id).is_err() {
                errors.push(validation_error("scope_id", "unknown_project"));
            }
        }
        _ => errors.push(validation_error("scope_kind", "invalid_scope_kind")),
    }
}

fn validate_provider_grant_resource_fields(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateProviderGrantRequest,
    errors: &mut Vec<Value>,
) {
    let exists = match request.resource_kind.as_str() {
        "model_alias" => state
            .store
            .model_alias(&request.resource_id)
            .is_some_and(|alias| alias.tenant_id == actor.tenant_id),
        "route_policy" => state
            .store
            .route_policy(&request.resource_id)
            .is_some_and(|policy| policy.tenant_id == actor.tenant_id),
        "routing_group" => state
            .store
            .routing_group(&request.resource_id)
            .is_some_and(|group| group.tenant_id == actor.tenant_id),
        "model_target" => state
            .store
            .model_target(&request.resource_id)
            .is_some_and(|target| target.tenant_id == actor.tenant_id),
        "provider_endpoint" => state
            .store
            .provider_endpoint(&request.resource_id)
            .is_some_and(|endpoint| endpoint.tenant_id == actor.tenant_id),
        "pricing_sku" => state
            .store
            .pricing_sku(&request.resource_id)
            .is_some_and(|sku| sku.tenant_id == actor.tenant_id),
        _ => {
            errors.push(validation_error("resource_kind", "invalid_resource_kind"));
            return;
        }
    };
    if !exists {
        errors.push(validation_error("resource_id", "unknown_resource"));
    }
}

fn validate_provider_grant_effect_fields(
    request: &AdminCreateProviderGrantRequest,
    errors: &mut Vec<Value>,
) {
    if !matches!(request.effect.as_str(), "allow" | "deny") {
        errors.push(validation_error("effect", "invalid_effect"));
    }
    if !matches!(
        request.closure_mode.as_str(),
        "self_only" | "include_descendants" | "deny_descendants"
    ) {
        errors.push(validation_error("closure_mode", "invalid_closure_mode"));
    }
    if request.effect == "allow" && request.closure_mode == "deny_descendants" {
        errors.push(validation_error("closure_mode", "allow_deny_descendants"));
    }
    if request.effect == "deny" && request.closure_mode == "include_descendants" {
        errors.push(validation_error("closure_mode", "deny_include_descendants"));
    }
}

fn routing_group_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    request: &AdminCreateRoutingGroupRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.name.trim().is_empty() {
        errors.push(validation_error("name", "required"));
    }
    if state
        .store
        .routing_groups_for_tenant(&actor.tenant_id)
        .iter()
        .any(|group| {
            group.organization_id == request.organization_id
                && group.name == request.name.trim()
                && group.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("name", "duplicate_name"));
    }
    if let Some(organization_id) = request.organization_id.as_deref() {
        if organization_for_actor(state, actor, organization_id).is_err() {
            errors.push(validation_error("organization_id", "unknown_organization"));
        }
    }
    errors
}

fn routing_group_target_validation_errors(
    state: &AppState,
    actor: &AuthenticatedActor,
    routing_group_id: &str,
    request: &AdminCreateRoutingGroupTargetRequest,
) -> Vec<Value> {
    let mut errors = Vec::new();
    if request.weight == 0 {
        errors.push(validation_error("weight", "required"));
    }
    let group = state.store.routing_group(routing_group_id);
    let model_target = state.store.model_target(&request.model_target_id);
    match &group {
        Some(group) if group.tenant_id == actor.tenant_id => {}
        _ => errors.push(validation_error(
            "routing_group_id",
            "unknown_routing_group",
        )),
    }
    match &model_target {
        Some(target) if target.tenant_id == actor.tenant_id => {}
        _ => errors.push(validation_error("model_target_id", "unknown_model_target")),
    }
    if let (Some(group), Some(target)) = (&group, &model_target) {
        if group.tenant_id == actor.tenant_id
            && target.tenant_id == actor.tenant_id
            && group.protocol_family != target.protocol_family
        {
            errors.push(validation_error(
                "model_target_id",
                "protocol_family_mismatch",
            ));
        }
        if group.tenant_id == actor.tenant_id
            && target.tenant_id == actor.tenant_id
            && group.organization_id.is_some()
            && target.organization_id.is_some()
            && group.organization_id != target.organization_id
        {
            errors.push(validation_error("model_target_id", "organization_mismatch"));
        }
    }
    if state
        .store
        .routing_group_targets_for_group(&actor.tenant_id, routing_group_id)
        .iter()
        .any(|target| {
            target.model_target_id == request.model_target_id
                && target.status != ResourceStatus::Deleted
        })
    {
        errors.push(validation_error("model_target_id", "duplicate_membership"));
    }
    errors
}

fn validation_error(field: &str, reason: &str) -> Value {
    json!({
        "field": field,
        "reason": reason
    })
}

const fn validation_input(
    schema: &'static str,
    resource_kind: &'static str,
    scope_kind: &'static str,
    scope_id: String,
    errors: Vec<Value>,
    occurred_at: chrono::DateTime<chrono::Utc>,
) -> ValidationResponseInput {
    ValidationResponseInput {
        schema,
        resource_kind,
        scope_kind,
        scope_id,
        errors,
        warnings: Vec::new(),
        affected_resources: Vec::new(),
        publication_plan: None,
        route_simulation: None,
        budget_simulation: None,
        occurred_at,
    }
}

fn validation_response(
    state: &AppState,
    actor: &AuthenticatedActor,
    input: ValidationResponseInput,
) -> Json<Value> {
    let valid = input.errors.is_empty();
    let validation_id = new_prefixed_id("vdiag");
    let errors = Value::Array(input.errors);
    let warnings = Value::Array(input.warnings);
    let affected_resources = Value::Array(input.affected_resources);
    let record = ValidationDiagnosticRecord {
        validation_id: validation_id.clone(),
        tenant_id: actor.tenant_id.clone(),
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        resource_kind: input.resource_kind.to_owned(),
        scope_kind: input.scope_kind.to_owned(),
        scope_id: input.scope_id,
        valid,
        errors: errors.clone(),
        warnings: warnings.clone(),
        affected_resources: affected_resources.clone(),
        publication_plan: input.publication_plan.clone(),
        route_simulation: input.route_simulation.clone(),
        budget_simulation: input.budget_simulation.clone(),
        created_by: actor_principal_or_actor_id(actor),
        created_at: input.occurred_at,
    };
    state.store.record_validation_diagnostic(record);
    Json(json!({
        "schema": input.schema,
        "validation_id": validation_id,
        "valid": valid,
        "errors": errors,
        "warnings": warnings,
        "affected_resources": affected_resources,
        "publication_plan": input.publication_plan,
        "route_simulation": input.route_simulation,
        "budget_simulation": input.budget_simulation
    }))
}

fn validation_diagnostic_body(record: &ValidationDiagnosticRecord) -> Value {
    json!({
        "validation_id": &record.validation_id,
        "tenant_id": &record.tenant_id,
        "organization_id": &record.organization_id,
        "project_id": &record.project_id,
        "resource_kind": &record.resource_kind,
        "scope_kind": &record.scope_kind,
        "scope_id": &record.scope_id,
        "valid": record.valid,
        "errors": &record.errors,
        "warnings": &record.warnings,
        "affected_resources": &record.affected_resources,
        "publication_plan": &record.publication_plan,
        "route_simulation": &record.route_simulation,
        "budget_simulation": &record.budget_simulation,
        "created_by": &record.created_by,
        "created_at": record.created_at
    })
}

fn audit_event_body(record: &AuditEventRecord) -> Value {
    json!({
        "kind": "audit_event",
        "id": &record.audit_event_id,
        "audit_event_id": &record.audit_event_id,
        "event_type": &record.event_type,
        "tenant_id": &record.tenant_id,
        "organization_id": &record.organization_id,
        "project_id": &record.project_id,
        "scope_kind": &record.scope_kind,
        "scope_id": &record.scope_id,
        "resource_kind": &record.resource_kind,
        "resource_id": &record.resource_id,
        "before_version": record.before_version,
        "after_version": record.after_version,
        "actor_id": &record.actor_id,
        "actor_kind": record.actor_kind.as_str(),
        "principal_id": &record.principal_id,
        "request_id": &record.request_id,
        "redacted_diff": &record.redacted_diff,
        "occurred_at": record.occurred_at
    })
}

fn audit_event_matches_query(record: &AuditEventRecord, query: &AdminAuditEventListQuery) -> bool {
    matches_optional_filter(query.scope_kind.as_ref(), Some(record.scope_kind.as_str()))
        && matches_optional_filter(query.scope_id.as_ref(), Some(record.scope_id.as_str()))
        && matches_optional_filter(
            query.organization_id.as_ref(),
            record.organization_id.as_deref(),
        )
        && matches_optional_filter(query.project_id.as_ref(), record.project_id.as_deref())
        && matches_optional_filter(query.event_type.as_ref(), Some(record.event_type.as_str()))
        && matches_optional_filter(
            query.resource_kind.as_ref(),
            Some(record.resource_kind.as_str()),
        )
        && matches_optional_filter(
            query.resource_id.as_ref(),
            Some(record.resource_id.as_str()),
        )
        && matches_optional_filter(query.actor_id.as_ref(), Some(record.actor_id.as_str()))
        && matches_optional_filter(query.principal_id.as_ref(), record.principal_id.as_deref())
        && matches_optional_filter(query.request_id.as_ref(), Some(record.request_id.as_str()))
}

fn matches_optional_filter(filter: Option<&String>, value: Option<&str>) -> bool {
    filter.is_none_or(|filter| value == Some(filter.as_str()))
}

fn audit_event_list_limit(limit: Option<usize>) -> Result<usize> {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;
    match limit.unwrap_or(DEFAULT_LIMIT) {
        0 => Err(GatewayError::BadRequest {
            message: "audit_event_limit_must_be_positive".to_owned(),
        }),
        value if value > MAX_LIMIT => Err(GatewayError::BadRequest {
            message: "audit_event_limit_exceeds_maximum".to_owned(),
        }),
        value => Ok(value),
    }
}

fn audit_event_list_offset(cursor: Option<&str>) -> Result<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    if cursor.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "audit_event_cursor_invalid".to_owned(),
        });
    }
    cursor
        .parse::<usize>()
        .map_err(|_| GatewayError::BadRequest {
            message: "audit_event_cursor_invalid".to_owned(),
        })
}

fn export_job_resource_envelope(state: &AppState, job: &ExportJobRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": export_job_resource_body(state, job)
    })
}

fn export_job_resource_body(state: &AppState, job: &ExportJobRecord) -> Value {
    let manifest = state
        .store
        .export_manifests_for_job(&job.export_job_id)
        .into_iter()
        .next();
    json!({
        "kind": "export_job",
        "id": &job.export_job_id,
        "export_job_id": &job.export_job_id,
        "tenant_id": &job.tenant_id,
        "organization_id": &job.organization_id,
        "project_id": &job.project_id,
        "export_kind": &job.export_kind,
        "requested_by": &job.requested_by,
        "query": &job.query_document,
        "status": &job.status,
        "version": job.resource_version,
        "schema_version": job.schema_version,
        "manifest_id": manifest.as_ref().map(|manifest| manifest.export_manifest_id.as_str()),
        "record_count": manifest.as_ref().map(|manifest| manifest.record_count),
        "object_ref": manifest.as_ref().map(|manifest| manifest.object_ref.as_str()),
        "checksum": manifest.as_ref().map(|manifest| manifest.checksum.as_str()),
        "expires_at": manifest.as_ref().map(|manifest| manifest.expires_at),
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "completed_at": job.completed_at
    })
}

fn export_manifest_resource_body(manifest: &ExportManifestRecord) -> Value {
    json!({
        "kind": "export_manifest",
        "id": &manifest.export_manifest_id,
        "export_manifest_id": &manifest.export_manifest_id,
        "export_job_id": &manifest.export_job_id,
        "tenant_id": &manifest.tenant_id,
        "object_ref": &manifest.object_ref,
        "record_count": manifest.record_count,
        "byte_count": manifest.byte_count,
        "checksum": &manifest.checksum,
        "manifest": &manifest.manifest_document,
        "created_at": manifest.created_at,
        "expires_at": manifest.expires_at
    })
}

fn emergency_operation_resource_envelope(operation: &EmergencyOperationRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": emergency_operation_resource_body(operation)
    })
}

fn emergency_operation_resource_body(operation: &EmergencyOperationRecord) -> Value {
    json!({
        "kind": "emergency_operation",
        "id": &operation.emergency_operation_id,
        "emergency_operation_id": &operation.emergency_operation_id,
        "tenant_id": &operation.tenant_id,
        "organization_id": &operation.organization_id,
        "project_id": &operation.project_id,
        "operation_kind": &operation.operation_kind,
        "target_resource_kind": &operation.target_resource_kind,
        "target_resource_id": &operation.target_resource_id,
        "requested_by": &operation.requested_by,
        "reason": &operation.reason,
        "status": &operation.status,
        "operator_alert": &operation.operator_alert_document,
        "version": operation.resource_version,
        "schema_version": operation.schema_version,
        "created_at": operation.created_at,
        "updated_at": operation.updated_at,
        "expires_at": operation.expires_at
    })
}

fn emergency_operation_mutation_response(
    operation: &EmergencyOperationRecord,
    affected_resource: &Value,
    audit_event_id: &str,
) -> Value {
    json!({
        "schema": "gateway.admin.emergency_operation_mutation.v1",
        "resource": emergency_operation_resource_body(operation),
        "affected_resource": affected_resource,
        "audit_event_id": audit_event_id,
        "idempotency_replayed": false
    })
}

fn emergency_operation_matches_query(
    operation: &EmergencyOperationRecord,
    query: &AdminEmergencyOperationListQuery,
) -> bool {
    matches_optional_filter(
        query.operation_kind.as_ref(),
        Some(operation.operation_kind.as_str()),
    ) && matches_optional_filter(
        query.target_resource_kind.as_ref(),
        Some(operation.target_resource_kind.as_str()),
    ) && matches_optional_filter(query.status.as_ref(), Some(operation.status.as_str()))
}

fn export_job_matches_query(job: &ExportJobRecord, query: &AdminExportJobListQuery) -> bool {
    matches_optional_filter(query.export_kind.as_ref(), Some(job.export_kind.as_str()))
        && matches_optional_filter(query.status.as_ref(), Some(job.status.as_str()))
}

fn export_job_create_diff(
    job: &ExportJobRecord,
    manifest: &ExportManifestRecord,
    scope: &DashboardScopeInput,
    page: &ExportPage,
) -> Value {
    json!({
        "export_job_id": &job.export_job_id,
        "export_kind": &job.export_kind,
        "scope": dashboard_scope_body(scope),
        "status": &job.status,
        "manifest_id": &manifest.export_manifest_id,
        "object_ref": &manifest.object_ref,
        "record_count": manifest.record_count,
        "byte_count": manifest.byte_count,
        "checksum": &manifest.checksum,
        "next_cursor": &page.next_cursor,
        "total_filtered_count": page.total_filtered_count,
        "redaction": {
            "rows_included": false,
            "raw_request_body_included": false,
            "raw_provider_body_included": false,
            "secret_material_included": false
        }
    })
}

fn validation_diagnostics_summary(state: &AppState, tenant_id: &str) -> Value {
    let diagnostics = state.store.validation_diagnostics_for_tenant(tenant_id);
    let failed_count = diagnostics
        .iter()
        .filter(|diagnostic| !diagnostic.valid)
        .count();
    let warning_count = diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic
                .warnings
                .as_array()
                .is_some_and(|warnings| !warnings.is_empty())
        })
        .count();
    let latest = diagnostics.first();
    json!({
        "diagnostic_count": diagnostics.len(),
        "failed_count": failed_count,
        "warning_count": warning_count,
        "latest_validation_id": latest.map(|diagnostic| diagnostic.validation_id.as_str()),
        "latest_resource_kind": latest.map(|diagnostic| diagnostic.resource_kind.as_str()),
        "latest_valid": latest.map(|diagnostic| diagnostic.valid),
        "latest_created_at": latest.map(|diagnostic| diagnostic.created_at),
        "source": "durable_validation_diagnostics"
    })
}

fn reject_validation_errors(errors: &[Value]) -> Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(GatewayError::BadRequest {
            message: "validation_failed".to_owned(),
        })
    }
}

fn safe_http_base_url(value: &str) -> bool {
    let value = value.trim();
    (value.starts_with("https://") || value.starts_with("http://"))
        && !value.contains(char::is_whitespace)
        && !value.contains('?')
        && !value.contains('#')
}

fn redact_url_for_audit(value: &str) -> String {
    value.split('?').next().unwrap_or(value).to_owned()
}

fn organization_resource_envelope(organization: &OrganizationRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": organization_resource_body(organization)
    })
}

fn organization_resource_body(organization: &OrganizationRecord) -> Value {
    json!({
        "kind": "organization",
        "id": &organization.organization_id,
        "tenant_id": &organization.tenant_id,
        "version": organization.resource_version,
        "status": &organization.status,
        "display_name": &organization.display_name,
        "created_at": organization.created_at,
        "updated_at": organization.updated_at
    })
}

fn project_resource_envelope(project: &ProjectRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": project_resource_body(project)
    })
}

fn project_resource_body(project: &ProjectRecord) -> Value {
    json!({
        "kind": "project",
        "id": &project.project_id,
        "tenant_id": &project.tenant_id,
        "organization_id": &project.organization_id,
        "version": project.resource_version,
        "status": &project.status,
        "display_name": &project.display_name,
        "created_at": project.created_at,
        "updated_at": project.updated_at
    })
}

fn organization_member_resource_envelope(member: &OrganizationMembershipRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": organization_member_resource_body(member)
    })
}

fn organization_member_resource_body(member: &OrganizationMembershipRecord) -> Value {
    json!({
        "kind": "organization_member",
        "id": &member.organization_member_id,
        "tenant_id": &member.tenant_id,
        "organization_id": &member.organization_id,
        "principal_id": &member.principal_id,
        "version": member.resource_version,
        "status": &member.status
    })
}

fn project_member_resource_envelope(member: &ProjectMembershipRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": project_member_resource_body(member)
    })
}

fn project_member_resource_body(member: &ProjectMembershipRecord) -> Value {
    json!({
        "kind": "project_member",
        "id": &member.project_member_id,
        "tenant_id": &member.tenant_id,
        "organization_id": &member.organization_id,
        "project_id": &member.project_id,
        "principal_id": &member.principal_id,
        "organization_member_id": &member.organization_member_id,
        "version": member.resource_version,
        "status": &member.status
    })
}

fn safe_auth_session_body(session: &AuthSessionRecord) -> Value {
    json!({
        "kind": "auth_session",
        "id": &session.auth_session_id,
        "tenant_id": &session.tenant_id,
        "principal_id": &session.principal_id,
        "active_organization_id": &session.active_organization_id,
        "active_project_id": &session.active_project_id,
        "status": &session.status,
        "expires_at": session.expires_at,
        "created_at": session.created_at,
        "updated_at": session.updated_at
    })
}

fn auth_session_resource_envelope(session: &AuthSessionRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": safe_auth_session_body(session)
    })
}

fn external_identity_resource_envelope(identity: &ExternalIdentityRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": external_identity_resource_body(identity)
    })
}

fn external_identity_resource_body(identity: &ExternalIdentityRecord) -> Value {
    json!({
        "kind": "external_identity",
        "id": &identity.external_identity_id,
        "tenant_id": &identity.tenant_id,
        "principal_id": &identity.principal_id,
        "login_provider_id": &identity.login_provider_id,
        "provider_kind": &identity.provider_kind,
        "provider_subject": &identity.provider_subject,
        "email_hash": identity.email.as_deref().and_then(external_identity_email_hash),
        "email_verified": identity.email_verified,
        "status": identity.status.as_str(),
        "created_at": identity.created_at,
        "updated_at": identity.updated_at
    })
}

fn external_identity_email_hash(email: &str) -> Option<String> {
    let normalized = normalized_email(email)?;
    let digest = Sha256::digest(normalized.as_bytes());
    Some(format!("sha256:{digest:x}"))
}

fn user_resource_envelope(user: &crate::domain::UserRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": user_resource_body(user)
    })
}

fn user_resource_body(user: &crate::domain::UserRecord) -> Value {
    json!({
        "kind": "user",
        "id": &user.user_id,
        "tenant_id": &user.tenant_id,
        "display_name": &user.display_name,
        "primary_email": &user.primary_email,
        "default_organization_id": &user.default_organization_id,
        "default_project_id": &user.default_project_id,
        "status": &user.status,
        "version": user.resource_version,
        "created_at": user.created_at,
        "updated_at": user.updated_at
    })
}

fn user_session_resource_body(user: &crate::domain::UserRecord) -> Value {
    user_resource_body(user)
}

fn service_account_resource_envelope(account: &ServiceAccountRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": service_account_resource_body(account)
    })
}

fn service_account_resource_body(account: &ServiceAccountRecord) -> Value {
    json!({
        "kind": "service_account",
        "id": &account.service_account_id,
        "tenant_id": &account.tenant_id,
        "organization_id": &account.organization_id,
        "project_id": &account.project_id,
        "version": account.resource_version,
        "status": &account.status,
        "display_name": &account.display_name,
        "created_by": &account.created_by,
        "created_at": account.created_at,
        "updated_at": account.updated_at
    })
}

fn provider_endpoint_resource_envelope(endpoint: &ProviderEndpointRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": provider_endpoint_resource_body(endpoint)
    })
}

fn provider_endpoint_resource_body(endpoint: &ProviderEndpointRecord) -> Value {
    json!({
        "kind": "provider_endpoint",
        "id": &endpoint.provider_endpoint_id,
        "tenant_id": &endpoint.tenant_id,
        "organization_id": &endpoint.organization_id,
        "provider_kind": &endpoint.provider_kind,
        "display_name": &endpoint.display_name,
        "protocol_families": &endpoint.protocol_families,
        "upstream_base_url": &endpoint.upstream_base_url,
        "version": endpoint.resource_version,
        "status": &endpoint.status,
        "created_by": &endpoint.created_by,
        "created_at": endpoint.created_at,
        "updated_at": endpoint.updated_at
    })
}

fn upstream_credential_resource_envelope(credential: &UpstreamCredentialRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": upstream_credential_resource_body(credential)
    })
}

fn upstream_credential_resource_body(credential: &UpstreamCredentialRecord) -> Value {
    json!({
        "kind": "upstream_credential",
        "id": &credential.upstream_credential_id,
        "tenant_id": &credential.tenant_id,
        "organization_id": &credential.organization_id,
        "provider_endpoint_id": &credential.provider_endpoint_id,
        "credential_kind": &credential.credential_kind,
        "secret_ref_id": &credential.secret_ref_id,
        "version": credential.resource_version,
        "status": &credential.status,
        "created_by": &credential.created_by,
        "created_at": credential.created_at,
        "updated_at": credential.updated_at
    })
}

fn secret_ref_resource_envelope(secret_ref: &SecretRefRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": secret_ref_resource_body(secret_ref)
    })
}

fn secret_ref_resource_body(secret_ref: &SecretRefRecord) -> Value {
    json!({
        "kind": "secret_ref",
        "id": &secret_ref.secret_ref_id,
        "tenant_id": &secret_ref.tenant_id,
        "organization_id": &secret_ref.organization_id,
        "project_id": &secret_ref.project_id,
        "purpose": &secret_ref.purpose,
        "backend_kind": &secret_ref.backend_kind,
        "display_mask": &secret_ref.display_mask,
        "fingerprint": &secret_ref.fingerprint,
        "version": secret_ref.resource_version,
        "status": &secret_ref.status,
        "created_by": &secret_ref.created_by,
        "created_at": secret_ref.created_at,
        "updated_at": secret_ref.updated_at
    })
}

fn secret_ref_locator_resource_body(secret_ref: &SecretRefRecord) -> Value {
    json!({
        "kind": "secret_ref_locator",
        "id": &secret_ref.secret_ref_id,
        "tenant_id": &secret_ref.tenant_id,
        "backend_kind": &secret_ref.backend_kind,
        "backend_locator": &secret_ref.backend_locator,
        "display_mask": &secret_ref.display_mask,
        "fingerprint": &secret_ref.fingerprint,
        "version": secret_ref.resource_version,
        "status": &secret_ref.status,
        "updated_at": secret_ref.updated_at
    })
}

fn model_target_resource_envelope(target: &ModelTargetRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": model_target_resource_body(target)
    })
}

fn model_target_resource_body(target: &ModelTargetRecord) -> Value {
    json!({
        "kind": "model_target",
        "id": &target.model_target_id,
        "tenant_id": &target.tenant_id,
        "organization_id": &target.organization_id,
        "provider_endpoint_id": &target.provider_endpoint_id,
        "upstream_credential_id": &target.upstream_credential_id,
        "protocol_family": target.protocol_family.as_str(),
        "upstream_model_id": &target.upstream_model_id,
        "supports_streaming": target.supports_streaming,
        "version": target.resource_version,
        "status": &target.status,
        "created_by": &target.created_by,
        "created_at": target.created_at,
        "updated_at": target.updated_at
    })
}

fn model_alias_resource_envelope(alias: &ModelAliasRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": model_alias_resource_body(alias)
    })
}

fn model_alias_resource_body(alias: &ModelAliasRecord) -> Value {
    json!({
        "kind": "model_alias",
        "id": &alias.model_alias_id,
        "tenant_id": &alias.tenant_id,
        "organization_id": &alias.organization_id,
        "project_id": &alias.project_id,
        "alias_name": &alias.alias_name,
        "protocol_family": alias.protocol_family.as_str(),
        "route_policy_id": &alias.route_policy_id,
        "version": alias.resource_version,
        "status": &alias.status,
        "created_by": &alias.created_by,
        "created_at": alias.created_at,
        "updated_at": alias.updated_at
    })
}

fn pricing_sku_resource_envelope(sku: &PricingSkuRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": pricing_sku_resource_body(sku)
    })
}

fn pricing_sku_resource_body(sku: &PricingSkuRecord) -> Value {
    json!({
        "kind": "pricing_sku",
        "id": &sku.pricing_sku_id,
        "tenant_id": &sku.tenant_id,
        "organization_id": &sku.organization_id,
        "name": &sku.name,
        "currency": &sku.currency,
        "unit": &sku.unit,
        "model_id_patterns": &sku.model_id_patterns,
        "provider_endpoint_patterns": &sku.provider_endpoint_patterns,
        "pricing_document": &sku.pricing_document,
        "pricing_version": sku.pricing_version,
        "effective_from": sku.effective_from,
        "effective_until": sku.effective_until,
        "is_preset": sku.is_preset,
        "version": sku.resource_version,
        "status": &sku.status,
        "created_by": &sku.created_by,
        "created_at": sku.created_at,
        "updated_at": sku.updated_at
    })
}

fn budget_policy_resource_envelope(policy: &BudgetPolicyRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": budget_policy_resource_body(policy)
    })
}

fn budget_policy_resource_body(policy: &BudgetPolicyRecord) -> Value {
    json!({
        "kind": "budget_policy",
        "id": &policy.budget_policy_id,
        "tenant_id": &policy.tenant_id,
        "scope_kind": &policy.scope_kind,
        "scope_id": &policy.scope_id,
        "organization_id": &policy.organization_id,
        "project_id": &policy.project_id,
        "currency": &policy.currency,
        "period": &policy.period,
        "limit_kind": &policy.limit_kind,
        "hard_limit": policy.hard_limit,
        "soft_limit": policy.soft_limit,
        "thresholds": &policy.thresholds,
        "reset_policy": &policy.reset_policy,
        "overage_mode": &policy.overage_mode,
        "consistency_mode": &policy.consistency_mode,
        "version": policy.resource_version,
        "status": &policy.status,
        "created_by": &policy.created_by,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at
    })
}

fn quota_policy_resource_envelope(policy: &QuotaPolicyRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": quota_policy_resource_body(policy)
    })
}

fn quota_policy_resource_body(policy: &QuotaPolicyRecord) -> Value {
    json!({
        "kind": "quota_policy",
        "id": &policy.quota_policy_id,
        "tenant_id": &policy.tenant_id,
        "scope_kind": &policy.scope_kind,
        "scope_id": &policy.scope_id,
        "organization_id": &policy.organization_id,
        "project_id": &policy.project_id,
        "counter_kind": &policy.counter_kind,
        "limit": policy.limit,
        "burst_limit": policy.burst_limit,
        "window": &policy.window,
        "increment_source": &policy.increment_source,
        "loss_behavior": &policy.loss_behavior,
        "version": policy.resource_version,
        "status": &policy.status,
        "created_by": &policy.created_by,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at
    })
}

fn otel_export_config_resource_envelope(
    state: &AppState,
    config: &OtelExportConfigRecord,
) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": otel_export_config_resource_body(state, config)
    })
}

fn otel_export_config_resource_body(state: &AppState, config: &OtelExportConfigRecord) -> Value {
    let health = state
        .store
        .otel_exporter_health(&config.otel_export_config_id);
    let health = health.as_ref();
    json!({
        "kind": "otel_export_config",
        "id": &config.otel_export_config_id,
        "tenant_id": &config.tenant_id,
        "organization_id": &config.organization_id,
        "project_id": &config.project_id,
        "endpoint_url": &config.endpoint_url,
        "endpoint_host": safe_otel_endpoint_host(&config.endpoint_url),
        "protocol": &config.protocol,
        "header_refs": masked_otel_header_refs(&config.header_refs),
        "enabled_signals": &config.enabled_signals,
        "resource_attributes": &config.resource_attributes,
        "export_interval_seconds": config.export_interval_seconds,
        "timeout_seconds": config.timeout_seconds,
        "last_validation_status": "not_run",
        "exporter_health_status": health.map_or("not_run", |record| record.status.as_str()),
        "exporter_failure_count": health.map_or(0, |record| record.failure_count),
        "dropped_metric_count": health.map_or(0, |record| record.dropped_metric_count),
        "exported_metric_count": health.map_or(0, |record| record.exported_metric_count),
        "last_export_attempt_at": health.map(|record| record.last_attempted_at),
        "last_successful_export_at": health.and_then(|record| record.last_successful_export_at),
        "last_export_error": health.and_then(|record| record.last_error.as_deref()),
        "version": config.resource_version,
        "status": &config.status,
        "created_by": &config.created_by,
        "created_at": config.created_at,
        "updated_at": config.updated_at
    })
}

fn otel_export_config_create_diff(config: &OtelExportConfigRecord) -> Value {
    json!({
        "organization_id": &config.organization_id,
        "project_id": &config.project_id,
        "endpoint_host": safe_otel_endpoint_host(&config.endpoint_url),
        "protocol": &config.protocol,
        "header_refs": masked_otel_header_refs(&config.header_refs),
        "enabled_signals": &config.enabled_signals,
        "resource_attribute_keys": config
            .resource_attributes
            .iter()
            .map(|attribute| attribute.key.as_str())
            .collect::<Vec<_>>(),
        "export_interval_seconds": config.export_interval_seconds,
        "timeout_seconds": config.timeout_seconds,
        "status": config.status.as_str()
    })
}

fn otel_export_config_update_diff(
    before: &OtelExportConfigRecord,
    after: &OtelExportConfigRecord,
    reason: Option<&str>,
) -> Value {
    json!({
        "organization_id": {
            "before": &before.organization_id,
            "after": &after.organization_id
        },
        "project_id": {
            "before": &before.project_id,
            "after": &after.project_id
        },
        "endpoint_host": {
            "before": safe_otel_endpoint_host(&before.endpoint_url),
            "after": safe_otel_endpoint_host(&after.endpoint_url)
        },
        "protocol": {
            "before": &before.protocol,
            "after": &after.protocol
        },
        "header_refs": {
            "before": masked_otel_header_refs(&before.header_refs),
            "after": masked_otel_header_refs(&after.header_refs)
        },
        "enabled_signals": {
            "before": &before.enabled_signals,
            "after": &after.enabled_signals
        },
        "resource_attribute_keys": {
            "before": before
                .resource_attributes
                .iter()
                .map(|attribute| attribute.key.as_str())
                .collect::<Vec<_>>(),
            "after": after
                .resource_attributes
                .iter()
                .map(|attribute| attribute.key.as_str())
                .collect::<Vec<_>>()
        },
        "export_interval_seconds": {
            "before": before.export_interval_seconds,
            "after": after.export_interval_seconds
        },
        "timeout_seconds": {
            "before": before.timeout_seconds,
            "after": after.timeout_seconds
        },
        "status": {
            "before": before.status.as_str(),
            "after": after.status.as_str()
        },
        "reason": reason
    })
}

fn masked_otel_header_refs(header_refs: &[OtelHeaderRef]) -> Vec<Value> {
    header_refs
        .iter()
        .map(|header| {
            json!({
                "name": &header.name,
                "secret_ref_id": mask_secret_ref_id(&header.secret_ref_id)
            })
        })
        .collect()
}

fn mask_secret_ref_id(secret_ref_id: &str) -> String {
    if secret_ref_id.starts_with("sec_") {
        "sec_***".to_owned()
    } else {
        "***".to_owned()
    }
}

fn organization_invitation_resource_envelope(invitation: &OrganizationInvitationRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": organization_invitation_resource_body(invitation)
    })
}

fn organization_invitation_resource_body(invitation: &OrganizationInvitationRecord) -> Value {
    json!({
        "kind": "organization_invitation",
        "id": &invitation.invitation_id,
        "tenant_id": &invitation.tenant_id,
        "organization_id": &invitation.organization_id,
        "project_id": &invitation.project_id,
        "invited_email": &invitation.invited_email,
        "invited_principal_id": &invitation.invited_principal_id,
        "role_id": &invitation.role_id,
        "status": &invitation.status,
        "expires_at": invitation.expires_at,
        "accepted_at": invitation.accepted_at,
        "created_by": &invitation.created_by,
        "version": invitation.resource_version,
        "created_at": invitation.created_at,
        "updated_at": invitation.updated_at
    })
}

fn organization_invitation_preview_body(
    organization: &OrganizationRecord,
    project: Option<&ProjectRecord>,
    invitation: &OrganizationInvitationRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    json!({
        "kind": "organization_invitation_preview",
        "id": &invitation.invitation_id,
        "tenant_id": &invitation.tenant_id,
        "organization": {
            "id": &organization.organization_id,
            "display_name": &organization.display_name
        },
        "project": project.map(|project| json!({
            "id": &project.project_id,
            "display_name": &project.display_name
        })),
        "invited_email": &invitation.invited_email,
        "role_id": &invitation.role_id,
        "status": invitation_effective_status(invitation, now),
        "expires_at": invitation.expires_at
    })
}

fn invitation_effective_status(
    invitation: &OrganizationInvitationRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> &'static str {
    if invitation.status.accepts_at(invitation.expires_at, now) {
        "pending"
    } else if invitation.status == crate::domain::InvitationStatus::Pending {
        "expired"
    } else {
        invitation.status.as_str()
    }
}

fn organization_invitation_create_diff(invitation: &OrganizationInvitationRecord) -> Value {
    json!({
        "organization_id": &invitation.organization_id,
        "project_id": &invitation.project_id,
        "invited_email": &invitation.invited_email,
        "invited_principal_id": &invitation.invited_principal_id,
        "role_id": &invitation.role_id,
        "status": invitation.status.as_str(),
        "expires_at": invitation.expires_at
    })
}

fn notification_sink_resource_envelope(sink: &NotificationSinkRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": notification_sink_resource_body(sink)
    })
}

fn notification_sink_resource_body(sink: &NotificationSinkRecord) -> Value {
    json!({
        "kind": "notification_sink",
        "id": &sink.notification_sink_id,
        "tenant_id": &sink.tenant_id,
        "organization_id": &sink.organization_id,
        "project_id": &sink.project_id,
        "name": &sink.name,
        "sink_kind": &sink.sink_kind,
        "endpoint_config": redacted_notification_endpoint_config(sink),
        "signing_secret_ref_id": sink
            .signing_secret_ref_id
            .as_deref()
            .map(mask_secret_ref_id),
        "version": sink.resource_version,
        "status": &sink.status,
        "created_by": &sink.created_by,
        "created_at": sink.created_at,
        "updated_at": sink.updated_at
    })
}

fn notification_subscription_resource_envelope(
    subscription: &NotificationSubscriptionRecord,
) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": notification_subscription_resource_body(subscription)
    })
}

fn notification_subscription_resource_body(subscription: &NotificationSubscriptionRecord) -> Value {
    json!({
        "kind": "notification_subscription",
        "id": &subscription.notification_subscription_id,
        "tenant_id": &subscription.tenant_id,
        "organization_id": &subscription.organization_id,
        "project_id": &subscription.project_id,
        "notification_sink_id": &subscription.notification_sink_id,
        "event_family": &subscription.event_family,
        "filter_document": &subscription.filter_document,
        "version": subscription.resource_version,
        "status": &subscription.status,
        "created_by": &subscription.created_by,
        "created_at": subscription.created_at,
        "updated_at": subscription.updated_at
    })
}

fn notification_sink_create_diff(sink: &NotificationSinkRecord) -> Value {
    json!({
        "organization_id": &sink.organization_id,
        "project_id": &sink.project_id,
        "name": &sink.name,
        "sink_kind": &sink.sink_kind,
        "endpoint_config": redacted_notification_endpoint_config(sink),
        "signing_secret_ref_id": sink
            .signing_secret_ref_id
            .as_deref()
            .map(mask_secret_ref_id),
        "status": sink.status.as_str()
    })
}

fn notification_sink_update_diff(
    before: &NotificationSinkRecord,
    after: &NotificationSinkRecord,
    reason: Option<&str>,
) -> Value {
    json!({
        "name": {
            "before": &before.name,
            "after": &after.name
        },
        "endpoint_config": {
            "before": redacted_notification_endpoint_config(before),
            "after": redacted_notification_endpoint_config(after)
        },
        "signing_secret_ref_id": {
            "before": before.signing_secret_ref_id.as_deref().map(mask_secret_ref_id),
            "after": after.signing_secret_ref_id.as_deref().map(mask_secret_ref_id)
        },
        "status": {
            "before": before.status.as_str(),
            "after": after.status.as_str()
        },
        "reason": reason
    })
}

fn notification_subscription_create_diff(subscription: &NotificationSubscriptionRecord) -> Value {
    json!({
        "notification_subscription_id": &subscription.notification_subscription_id,
        "notification_sink_id": &subscription.notification_sink_id,
        "organization_id": &subscription.organization_id,
        "project_id": &subscription.project_id,
        "event_family": &subscription.event_family,
        "filter_keys": subscription
            .filter_document
            .as_object()
            .map(|object| object.keys().map(String::as_str).collect::<Vec<_>>())
            .unwrap_or_default(),
        "status": subscription.status.as_str()
    })
}

fn login_provider_resource_envelope(provider: &LoginProviderRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": login_provider_resource_body(provider)
    })
}

fn login_provider_resource_body(provider: &LoginProviderRecord) -> Value {
    json!({
        "kind": "identity_provider",
        "id": &provider.login_provider_id,
        "tenant_id": &provider.tenant_id,
        "provider_kind": &provider.provider_kind,
        "display_name": &provider.display_name,
        "config_document": redacted_login_provider_config(provider),
        "version": provider.resource_version,
        "status": &provider.status,
        "created_by": &provider.created_by,
        "created_at": provider.created_at,
        "updated_at": provider.updated_at
    })
}

fn auth_login_provider_resource_body(provider: &LoginProviderRecord) -> Value {
    json!({
        "kind": "auth_provider",
        "id": &provider.login_provider_id,
        "tenant_id": &provider.tenant_id,
        "provider_kind": &provider.provider_kind,
        "display_name": &provider.display_name,
        "client_id": login_config_string(&provider.config_document, "client_id"),
        "scopes": login_provider_scope_values(provider),
        "login_url": format!("/auth/v1/providers/{}/login", provider.login_provider_id),
        "status": &provider.status
    })
}

fn single_user_provider_response(state: &AppState) -> Result<Json<Value>> {
    let config = state
        .config
        .single_user_auth
        .as_ref()
        .ok_or_else(|| GatewayError::NotFound {
            resource: format!("login provider {SINGLE_USER_PROVIDER_ID}"),
        })?;
    Ok(Json(json!({
        "schema": "gateway.auth.provider.v1",
        "resource": single_user_auth_provider_resource_body(config)
    })))
}

fn single_user_auth_provider_resource_body(config: &SingleUserAuthConfig) -> Value {
    json!({
        "kind": "auth_provider",
        "id": SINGLE_USER_PROVIDER_ID,
        "tenant_id": &config.tenant_id,
        "provider_kind": "single_user_password",
        "display_name": "Single User",
        "auth_mode": "password",
        "requires_username": true,
        "login_url": "/auth/v1/single-user/login",
        "status": "active"
    })
}

fn login_provider_create_diff(provider: &LoginProviderRecord) -> Value {
    json!({
        "provider_kind": &provider.provider_kind,
        "display_name": &provider.display_name,
        "config_document": redacted_login_provider_config(provider),
        "status": provider.status.as_str()
    })
}

fn redacted_login_provider_config(provider: &LoginProviderRecord) -> Value {
    let Some(object) = provider.config_document.as_object() else {
        return json!({});
    };
    let mut redacted = serde_json::Map::new();
    for (key, value) in object {
        if key == "client_secret_ref" {
            redacted.insert(
                key.clone(),
                value
                    .as_str()
                    .map(mask_secret_ref_id)
                    .map_or(Value::Null, Value::String),
            );
        } else {
            redacted.insert(key.clone(), value.clone());
        }
    }
    Value::Object(redacted)
}

fn login_provider_start_response(provider: &LoginProviderRecord) -> Result<Value> {
    let authorization_endpoint = login_provider_authorization_endpoint(provider)?;
    let client_id =
        login_config_string(&provider.config_document, "client_id").ok_or_else(|| {
            GatewayError::BadRequest {
                message: "login_provider_client_id_missing".to_owned(),
            }
        })?;
    let redirect_uri =
        login_config_string(&provider.config_document, "redirect_uri").ok_or_else(|| {
            GatewayError::BadRequest {
                message: "login_provider_redirect_uri_missing".to_owned(),
            }
        })?;
    let state = random_login_token("gwst");
    let nonce = (provider.provider_kind == "oidc").then(|| random_login_token("gwnc"));
    let code_verifier = random_pkce_code_verifier();
    let code_challenge = pkce_s256_challenge(&code_verifier);
    let scope = login_provider_scope_values(provider).join(" ");
    let mut params = vec![
        ("response_type", "code".to_owned()),
        ("client_id", client_id.to_owned()),
        ("redirect_uri", redirect_uri.to_owned()),
        ("scope", scope),
        ("state", state.clone()),
        ("code_challenge", code_challenge.clone()),
        ("code_challenge_method", "S256".to_owned()),
    ];
    if let Some(nonce) = &nonce {
        params.push(("nonce", nonce.clone()));
    }
    Ok(json!({
        "authorization_url": format!(
            "{authorization_endpoint}?{}",
            oauth_query_string(&params)
        ),
        "state": state,
        "nonce": nonce,
        "pkce": {
            "code_challenge": code_challenge,
            "code_challenge_method": "S256"
        },
        "expires_in_seconds": 600
    }))
}

fn login_provider_authorization_endpoint(provider: &LoginProviderRecord) -> Result<&str> {
    if let Some(endpoint) = login_config_string(&provider.config_document, "authorization_url") {
        return Ok(endpoint);
    }
    match provider.provider_kind.as_str() {
        "github_oauth_app" => Ok("https://github.com/login/oauth/authorize"),
        _ => Err(GatewayError::BadRequest {
            message: "login_provider_authorization_url_missing".to_owned(),
        }),
    }
}

fn login_provider_scope_values(provider: &LoginProviderRecord) -> Vec<String> {
    if let Some(scopes) = provider
        .config_document
        .get("scopes")
        .and_then(Value::as_array)
    {
        let configured = scopes
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|scope| !scope.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if !configured.is_empty() {
            return configured;
        }
    }
    match provider.provider_kind.as_str() {
        "oidc" => ["openid", "email", "profile"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        _ => ["read:user", "user:email"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
    }
}

fn random_login_token(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    format!("{prefix}_{}", base64_url_no_pad(&bytes))
}

fn generate_invitation_token() -> String {
    random_login_token("gwinv")
}

fn invitation_token_hash(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    format!("sha256:{digest:x}")
}

fn random_pkce_code_verifier() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64_url_no_pad(&bytes)
}

fn pkce_s256_challenge(code_verifier: &str) -> String {
    let digest = Sha256::digest(code_verifier.as_bytes());
    base64_url_no_pad(&digest)
}

fn oauth_query_string(params: &[(&str, String)]) -> String {
    params
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(PERCENT_HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(PERCENT_HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        encoded.push(char::from(TABLE[usize::from(first >> 2)]));
        encoded.push(char::from(
            TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))],
        ));
        if chunk.len() > 1 {
            encoded.push(char::from(
                TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))],
            ));
        }
        if chunk.len() > 2 {
            encoded.push(char::from(TABLE[usize::from(third & 0x3f)]));
        }
    }
    encoded
}

fn redacted_notification_endpoint_config(sink: &NotificationSinkRecord) -> Value {
    match sink.sink_kind.as_str() {
        "webhook" => redacted_webhook_endpoint_config(&sink.endpoint_config),
        "stdout" | "disabled" => sink.endpoint_config.clone(),
        _ => json!({"kind": &sink.sink_kind}),
    }
}

fn redacted_webhook_endpoint_config(endpoint_config: &Value) -> Value {
    let url = endpoint_config.get("url").and_then(Value::as_str);
    json!({
        "url_host": url.and_then(safe_otel_endpoint_host),
        "url_path": url.and_then(safe_url_path),
        "retry_policy": endpoint_config.get("retry_policy"),
        "batching": endpoint_config.get("batching")
    })
}

fn safe_url_path(value: &str) -> Option<String> {
    value
        .parse::<http::Uri>()
        .ok()
        .map(|uri| uri.path().to_owned())
        .filter(|path| !path.is_empty())
}

fn config_publication_body(pointer: &ConfigPublicationPointerRecord) -> Value {
    json!({
        "tenant_id": &pointer.tenant_id,
        "snapshot_id": &pointer.snapshot_id,
        "version": pointer.version,
        "checksum": &pointer.checksum,
        "invalidation_id": &pointer.invalidation_id,
        "published_at": pointer.published_at,
        "updated_at": pointer.updated_at,
        "source": "durable_publication_pointer"
    })
}

fn realtime_worker_summary(
    state: &AppState,
    tenant_id: &str,
    latest_config_version: Option<i64>,
) -> Value {
    let reloads = state.store.config_worker_reloads_for_tenant(tenant_id);
    let latest = reloads.iter().max_by(|left, right| {
        left.reloaded_at
            .cmp(&right.reloaded_at)
            .then_with(|| left.loaded_version.cmp(&right.loaded_version))
    });
    let Some(latest) = latest else {
        return json!({
            "loaded_config_version": latest_config_version,
            "latest_published_config_version": latest_config_version,
            "heartbeat_status": "unavailable",
            "reload_evidence": "not_connected",
            "latest_worker_id": null,
            "last_reloaded_at": null,
            "last_reload_source": null,
            "last_known_good_snapshot_id": null,
            "last_known_good_version": null,
            "publication_lag_ms": null,
            "missed_invalidation_count": null,
            "workers": []
        });
    };
    let (heartbeat_status, reload_evidence) = match latest_config_version {
        Some(version) if latest.loaded_version == version => ("fresh", "converged"),
        Some(version) if latest.loaded_version < version => ("stale", "lagging"),
        Some(_) => ("fresh", "ahead_of_publication_pointer"),
        None => ("unavailable", "no_publication_pointer"),
    };
    json!({
        "loaded_config_version": latest.loaded_version,
        "latest_published_config_version": latest_config_version,
        "heartbeat_status": heartbeat_status,
        "reload_evidence": reload_evidence,
        "latest_worker_id": &latest.worker_id,
        "last_reloaded_at": latest.reloaded_at,
        "last_reload_source": latest.reload_source.as_str(),
        "last_known_good_snapshot_id": &latest.last_known_good_snapshot_id,
        "last_known_good_version": latest.last_known_good_version,
        "publication_lag_ms": latest.publication_lag_ms,
        "missed_invalidation_count": latest.missed_invalidation_count,
        "workers": reloads
            .iter()
            .map(config_worker_reload_body)
            .collect::<Vec<_>>()
    })
}

fn realtime_otel_exporter_summary(state: &AppState, tenant_id: &str) -> Value {
    let configs = state
        .store
        .otel_export_configs_for_tenant(tenant_id)
        .into_iter()
        .filter(|config| config.status != ResourceStatus::Deleted)
        .collect::<Vec<_>>();
    let health_records = state.store.otel_exporter_health_for_tenant(tenant_id);
    let health_by_config = health_records
        .iter()
        .map(|record| (record.otel_export_config_id.as_str(), record))
        .collect::<HashMap<_, _>>();
    let active_configs = configs
        .iter()
        .filter(|config| config.status == ResourceStatus::Active)
        .collect::<Vec<_>>();
    let configured_count = configs.len();
    let active_count = active_configs.len();
    let disabled_count = configs
        .iter()
        .filter(|config| config.status == ResourceStatus::Disabled)
        .count();
    let healthy_count = active_configs
        .iter()
        .filter(|config| {
            health_by_config
                .get(config.otel_export_config_id.as_str())
                .is_some_and(|record| record.status == "succeeded")
        })
        .count();
    let failing_count = active_configs
        .iter()
        .filter(|config| {
            health_by_config
                .get(config.otel_export_config_id.as_str())
                .is_some_and(|record| record.status == "retryable_failed")
        })
        .count();
    let not_connected_count = active_configs
        .iter()
        .filter(|config| !health_by_config.contains_key(config.otel_export_config_id.as_str()))
        .count();
    let latest_attempted_at = health_records
        .iter()
        .map(|record| record.last_attempted_at)
        .max();
    let last_successful_export_at = health_records
        .iter()
        .filter_map(|record| record.last_successful_export_at)
        .max();
    let exporter_failure_count = health_records
        .iter()
        .map(|record| record.failure_count)
        .sum::<i64>();
    let dropped_metric_count = health_records
        .iter()
        .map(|record| record.dropped_metric_count)
        .sum::<i64>();
    let exported_metric_count = health_records
        .iter()
        .map(|record| record.exported_metric_count)
        .sum::<i64>();
    let status = if configured_count == 0 {
        "not_configured"
    } else if failing_count > 0 {
        "degraded"
    } else if not_connected_count > 0 {
        "not_connected"
    } else if active_count == 0 {
        "disabled"
    } else {
        "healthy"
    };

    json!({
        "source": "durable_exporter_health",
        "status": status,
        "configured_count": configured_count,
        "active_count": active_count,
        "healthy_count": healthy_count,
        "failing_count": failing_count,
        "disabled_count": disabled_count,
        "not_connected_count": not_connected_count,
        "exporter_failure_count": exporter_failure_count,
        "dropped_metric_count": dropped_metric_count,
        "exported_metric_count": exported_metric_count,
        "last_attempted_at": latest_attempted_at,
        "last_successful_export_at": last_successful_export_at,
        "health_records": health_records
            .iter()
            .map(otel_exporter_health_record_body)
            .collect::<Vec<_>>()
    })
}

fn otel_exporter_health_record_body(record: &OtelExporterHealthRecord) -> Value {
    json!({
        "id": &record.otel_exporter_health_id,
        "tenant_id": &record.tenant_id,
        "otel_export_config_id": &record.otel_export_config_id,
        "worker_id": &record.worker_id,
        "status": &record.status,
        "failure_count": record.failure_count,
        "dropped_metric_count": record.dropped_metric_count,
        "exported_metric_count": record.exported_metric_count,
        "last_error": &record.last_error,
        "last_attempted_at": record.last_attempted_at,
        "last_successful_export_at": record.last_successful_export_at,
        "created_at": record.created_at,
        "updated_at": record.updated_at
    })
}

fn config_worker_reload_body(record: &ConfigWorkerReloadRecord) -> Value {
    json!({
        "tenant_id": &record.tenant_id,
        "worker_id": &record.worker_id,
        "snapshot_id": &record.snapshot_id,
        "loaded_version": record.loaded_version,
        "checksum": &record.checksum,
        "last_known_good_snapshot_id": &record.last_known_good_snapshot_id,
        "last_known_good_version": record.last_known_good_version,
        "reload_source": record.reload_source.as_str(),
        "status": record.status.as_str(),
        "missed_invalidation_count": record.missed_invalidation_count,
        "publication_lag_ms": record.publication_lag_ms,
        "reloaded_at": record.reloaded_at
    })
}

fn realtime_provider_summary(
    state: &AppState,
    tenant_id: &str,
    config_version: Option<i64>,
    now: chrono::DateTime<chrono::Utc>,
) -> Value {
    let mut healthy_count = 0usize;
    let mut warmup_count = 0usize;
    let mut degraded_count = 0usize;
    let mut unhealthy_count = 0usize;
    let mut blocked_count = 0usize;
    let mut unknown_count = 0usize;
    let mut drained_count = 0usize;
    let endpoints = state
        .store
        .provider_endpoints_for_tenant(tenant_id)
        .into_iter()
        .filter(|endpoint| endpoint.status != ResourceStatus::Deleted)
        .map(|endpoint| {
            let health_state = state.store.endpoint_health_state(
                tenant_id,
                &endpoint.provider_endpoint_id,
                config_version,
                now,
            );
            match health_state {
                EndpointHealthState::Healthy => healthy_count += 1,
                EndpointHealthState::Warmup => warmup_count += 1,
                EndpointHealthState::Degraded => degraded_count += 1,
                EndpointHealthState::Unhealthy => unhealthy_count += 1,
                EndpointHealthState::Blocked => blocked_count += 1,
                EndpointHealthState::Unknown => unknown_count += 1,
            }
            let drained = state.store.endpoint_is_drained(
                tenant_id,
                &endpoint.provider_endpoint_id,
                config_version,
                now,
            );
            if drained {
                drained_count += 1;
            }
            json!({
                "provider_endpoint_id": endpoint.provider_endpoint_id,
                "organization_id": endpoint.organization_id,
                "provider_kind": endpoint.provider_kind,
                "status": endpoint.status.as_str(),
                "health_state": health_state.as_str(),
                "drained": drained,
                "config_version": config_version,
                "source": "redis_compatible_hot_state"
            })
        })
        .collect::<Vec<_>>();
    let freshness_status = if endpoints.is_empty() || unknown_count == endpoints.len() {
        "unavailable"
    } else if unknown_count > 0 {
        "partial"
    } else {
        "fresh"
    };
    json!({
        "endpoint_count": endpoints.len(),
        "health_counts": {
            "healthy": healthy_count,
            "warmup": warmup_count,
            "degraded": degraded_count,
            "unhealthy": unhealthy_count,
            "blocked": blocked_count,
            "unknown": unknown_count
        },
        "drained_count": drained_count,
        "freshness_status": freshness_status,
        "latest_observed_at": null,
        "endpoints": endpoints
    })
}

fn realtime_route_summary(state: &AppState, tenant_id: &str) -> Value {
    let route_decisions = state
        .store
        .route_decisions()
        .into_iter()
        .filter(|decision| decision.tenant_id == tenant_id)
        .collect::<Vec<_>>();
    let attempt_count = state
        .store
        .route_attempts()
        .into_iter()
        .filter(|attempt| {
            route_decisions
                .iter()
                .any(|decision| decision.route_decision_id == attempt.route_decision_id)
        })
        .count();
    let selected_count = route_decisions
        .iter()
        .filter(|decision| decision.status == RouteDecisionStatus::Selected)
        .count();
    let blocked_count = route_decisions
        .iter()
        .filter(|decision| decision.status == RouteDecisionStatus::Blocked)
        .count();
    let no_route_count = route_decisions
        .iter()
        .filter(|decision| decision.status == RouteDecisionStatus::NoRoute)
        .count();
    let latest_decision_at = route_decisions
        .iter()
        .map(|decision| decision.occurred_at)
        .max();
    json!({
        "decision_count": route_decisions.len(),
        "attempt_count": attempt_count,
        "selected_count": selected_count,
        "blocked_count": blocked_count,
        "no_route_count": no_route_count,
        "latest_decision_at": latest_decision_at,
        "source": "durable_route_evidence"
    })
}

fn dashboard_overview_response(
    state: &AppState,
    scope: &DashboardScopeInput,
    generated_at: chrono::DateTime<chrono::Utc>,
) -> Value {
    let route_rollup = dashboard_route_rollup(state, scope);
    let usage_rollup = dashboard_usage_rollup(state, scope);
    let usage_available = usage_rollup.request_count > 0;
    let source_freshness_timestamp = route_rollup
        .latest_decision_at
        .max(usage_rollup.latest_source_at);
    json!({
        "schema": scope.schema,
        "scope": dashboard_scope_body(scope),
        "generated_at": generated_at,
        "freshness": {
            "source_freshness_timestamp": source_freshness_timestamp,
            "partial_data": true,
            "fallback_reason": dashboard_fallback_reason(usage_available)
        },
        "measures": dashboard_measures_body(&route_rollup, &usage_rollup, usage_available),
        "sources": {
            "route_evidence": "durable",
            "usage_ledger_rollups": dashboard_usage_source(usage_available),
            "budget_hot_state": "unavailable",
            "quota_hot_state": "unavailable"
        },
        "unavailable_sources": dashboard_unavailable_sources(usage_available)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsageBreakdownDimension {
    Project,
    ProjectMember,
    Model,
    ProviderEndpoint,
}

impl UsageBreakdownDimension {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::ProjectMember => "project_member",
            Self::Model => "model",
            Self::ProviderEndpoint => "provider_endpoint",
        }
    }
}

fn get_usage_breakdown(
    state: &AppState,
    actor: &AuthenticatedActor,
    query: &AdminUsageBreakdownQuery,
    path_pattern: &'static str,
    dimension: UsageBreakdownDimension,
) -> Result<Json<Value>> {
    let now = chrono::Utc::now();
    let scope = usage_scope_from_query(
        state,
        actor,
        query.scope_kind.as_deref(),
        query.scope_id.as_deref(),
    )?;
    authorize_admin_route(
        state,
        actor,
        &Method::GET,
        path_pattern,
        &scope.scope_id,
        now,
    )?;
    let limit = usage_list_limit(query.limit)?;
    let offset = usage_list_offset(query.cursor.as_deref())?;
    let mut groups: HashMap<String, (String, String, DashboardUsageRollup)> = HashMap::new();
    for bucket in state
        .store
        .ledger_buckets_for_tenant(&scope.tenant_id)
        .into_iter()
        .filter(|bucket| bucket.bucket_kind == "event")
        .filter(|bucket| dashboard_bucket_matches_scope(bucket, &scope))
    {
        let Some((group_kind, group_id)) = usage_breakdown_group(&bucket, dimension) else {
            continue;
        };
        let entry = groups
            .entry(format!("{group_kind}:{group_id}"))
            .or_insert_with(|| (group_kind, group_id, DashboardUsageRollup::default()));
        accumulate_usage_bucket(&mut entry.2, &bucket);
    }
    let mut rows = groups
        .into_iter()
        .map(|(_, (group_kind, group_id, rollup))| {
            json!({
                "group_kind": group_kind,
                "group_id": group_id,
                "measures": usage_rollup_measures_body(&rollup)
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right["measures"]["request_count"]
            .as_i64()
            .unwrap_or_default()
            .cmp(
                &left["measures"]["request_count"]
                    .as_i64()
                    .unwrap_or_default(),
            )
            .then_with(|| {
                left["group_id"]
                    .as_str()
                    .unwrap_or_default()
                    .cmp(right["group_id"].as_str().unwrap_or_default())
            })
    });
    let total_filtered_count = rows.len();
    let page = rows
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(page.len());
    let next_cursor = (next_offset < total_filtered_count).then(|| next_offset.to_string());
    Ok(Json(json!({
        "schema": "gateway.admin.usage_breakdown.v1",
        "scope": dashboard_scope_body(&scope),
        "dimension": dimension.as_str(),
        "rows": page,
        "limit": limit,
        "cursor": query.cursor,
        "next_cursor": next_cursor,
        "total_filtered_count": total_filtered_count,
        "sources": {
            "usage_ledger_rollups": "durable_ledger_buckets",
            "metrics_backend_queried": false
        }
    })))
}

fn usage_scope_from_query(
    state: &AppState,
    actor: &AuthenticatedActor,
    scope_kind: Option<&str>,
    scope_id: Option<&str>,
) -> Result<DashboardScopeInput> {
    let scope_kind = scope_kind.unwrap_or("tenant");
    match scope_kind {
        "tenant" => usage_tenant_scope(actor, scope_id),
        "organization" | "project" | "project_member" | "api_key" | "service_account" => {
            usage_identity_scope_from_query(state, actor, scope_kind, scope_id)
        }
        "model_alias" | "model_target" | "provider_endpoint" | "route_policy" | "routing_group" => {
            usage_catalog_scope_from_query(state, actor, scope_kind, scope_id)
        }
        "protocol_family" => usage_protocol_family_scope(actor, scope_kind, scope_id),
        _ => Err(GatewayError::BadRequest {
            message: "usage_scope_kind_invalid".to_owned(),
        }),
    }
}

fn usage_tenant_scope(
    actor: &AuthenticatedActor,
    scope_id: Option<&str>,
) -> Result<DashboardScopeInput> {
    let scope_id = scope_id.unwrap_or(actor.tenant_id.as_str());
    if scope_id != actor.tenant_id {
        return Err(GatewayError::Authorization {
            reason: "tenant_scope_mismatch",
        });
    }
    Ok(DashboardScopeInput {
        schema: "gateway.admin.usage.scope.v1",
        tenant_id: actor.tenant_id.clone(),
        scope_kind: "tenant",
        scope_id: actor.tenant_id.clone(),
        organization_id: None,
        project_id: None,
        project_member_id: None,
        principal_id: None,
    })
}

fn usage_identity_scope_from_query(
    state: &AppState,
    actor: &AuthenticatedActor,
    scope_kind: &str,
    scope_id: Option<&str>,
) -> Result<DashboardScopeInput> {
    match scope_kind {
        "organization" => {
            let organization = organization_for_actor(
                state,
                actor,
                required_usage_scope_id(scope_kind, scope_id)?,
            )?;
            Ok(DashboardScopeInput {
                schema: "gateway.admin.usage.scope.v1",
                tenant_id: actor.tenant_id.clone(),
                scope_kind: "organization",
                scope_id: organization.organization_id.clone(),
                organization_id: Some(organization.organization_id),
                project_id: None,
                project_member_id: None,
                principal_id: None,
            })
        }
        "project" => {
            let project =
                project_for_actor(state, actor, required_usage_scope_id(scope_kind, scope_id)?)?;
            Ok(DashboardScopeInput {
                schema: "gateway.admin.usage.scope.v1",
                tenant_id: actor.tenant_id.clone(),
                scope_kind: "project",
                scope_id: project.project_id.clone(),
                organization_id: Some(project.organization_id),
                project_id: Some(project.project_id),
                project_member_id: None,
                principal_id: None,
            })
        }
        "project_member" => {
            let member = project_member_by_id_for_actor(
                state,
                actor,
                required_usage_scope_id(scope_kind, scope_id)?,
            )?;
            Ok(DashboardScopeInput {
                schema: "gateway.admin.usage.scope.v1",
                tenant_id: actor.tenant_id.clone(),
                scope_kind: "project_member",
                scope_id: member.project_member_id.clone(),
                organization_id: Some(member.organization_id),
                project_id: Some(member.project_id),
                project_member_id: Some(member.project_member_id),
                principal_id: Some(member.principal_id),
            })
        }
        "api_key" => {
            let api_key =
                api_key_for_actor(state, actor, required_usage_scope_id(scope_kind, scope_id)?)?;
            Ok(DashboardScopeInput {
                schema: "gateway.admin.usage.scope.v1",
                tenant_id: actor.tenant_id.clone(),
                scope_kind: "api_key",
                scope_id: api_key.api_key_id,
                organization_id: api_key.organization_id,
                project_id: api_key.project_id,
                project_member_id: None,
                principal_id: Some(api_key.owner_principal_id),
            })
        }
        "service_account" => {
            let account = service_account_for_actor(
                state,
                actor,
                required_usage_scope_id(scope_kind, scope_id)?,
            )?;
            Ok(DashboardScopeInput {
                schema: "gateway.admin.usage.scope.v1",
                tenant_id: actor.tenant_id.clone(),
                scope_kind: "service_account",
                scope_id: account.service_account_id,
                organization_id: account.organization_id,
                project_id: account.project_id,
                project_member_id: None,
                principal_id: None,
            })
        }
        _ => Err(GatewayError::BadRequest {
            message: "usage_scope_kind_invalid".to_owned(),
        }),
    }
}

fn usage_catalog_scope_from_query(
    state: &AppState,
    actor: &AuthenticatedActor,
    scope_kind: &str,
    scope_id: Option<&str>,
) -> Result<DashboardScopeInput> {
    let scope_id = required_usage_scope_id(scope_kind, scope_id)?;
    match scope_kind {
        "model_alias" => {
            let alias = model_alias_for_actor(state, actor, scope_id)?;
            Ok(catalog_usage_scope(
                actor,
                "model_alias",
                alias.model_alias_id,
                alias.organization_id,
                alias.project_id,
            ))
        }
        "model_target" => {
            let target = model_target_for_actor(state, actor, scope_id)?;
            Ok(catalog_usage_scope(
                actor,
                "model_target",
                target.model_target_id,
                target.organization_id,
                None,
            ))
        }
        "provider_endpoint" => {
            let endpoint = provider_endpoint_for_actor(state, actor, scope_id)?;
            Ok(catalog_usage_scope(
                actor,
                "provider_endpoint",
                endpoint.provider_endpoint_id,
                endpoint.organization_id,
                None,
            ))
        }
        "route_policy" => {
            let policy = route_policy_for_actor(state, actor, scope_id)?;
            Ok(catalog_usage_scope(
                actor,
                "route_policy",
                policy.route_policy_id,
                policy.organization_id,
                None,
            ))
        }
        "routing_group" => {
            let group = routing_group_for_actor(state, actor, scope_id)?;
            Ok(catalog_usage_scope(
                actor,
                "routing_group",
                group.routing_group_id,
                group.organization_id,
                None,
            ))
        }
        _ => Err(GatewayError::BadRequest {
            message: "usage_scope_kind_invalid".to_owned(),
        }),
    }
}

fn catalog_usage_scope(
    actor: &AuthenticatedActor,
    scope_kind: &'static str,
    scope_id: String,
    organization_id: Option<String>,
    project_id: Option<String>,
) -> DashboardScopeInput {
    DashboardScopeInput {
        schema: "gateway.admin.usage.scope.v1",
        tenant_id: actor.tenant_id.clone(),
        scope_kind,
        scope_id,
        organization_id,
        project_id,
        project_member_id: None,
        principal_id: None,
    }
}

fn usage_protocol_family_scope(
    actor: &AuthenticatedActor,
    scope_kind: &str,
    scope_id: Option<&str>,
) -> Result<DashboardScopeInput> {
    let protocol_family = required_usage_scope_id(scope_kind, scope_id)?;
    if !ProtocolFamily::all()
        .iter()
        .any(|candidate| candidate.as_str() == protocol_family)
    {
        return Err(GatewayError::BadRequest {
            message: "usage_scope_protocol_family_invalid".to_owned(),
        });
    }
    Ok(DashboardScopeInput {
        schema: "gateway.admin.usage.scope.v1",
        tenant_id: actor.tenant_id.clone(),
        scope_kind: "protocol_family",
        scope_id: protocol_family.to_owned(),
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        project_member_id: None,
        principal_id: actor.principal_id.clone(),
    })
}

fn required_usage_scope_id<'a>(scope_kind: &str, scope_id: Option<&'a str>) -> Result<&'a str> {
    scope_id
        .filter(|scope_id| !scope_id.trim().is_empty())
        .ok_or_else(|| GatewayError::BadRequest {
            message: format!("usage_scope_id_required:{scope_kind}"),
        })
}

fn usage_rollup_measures_body(rollup: &DashboardUsageRollup) -> Value {
    json!({
        "request_count": rollup.request_count,
        "success_count": rollup.success_count,
        "error_count": rollup.error_count,
        "input_tokens": rollup.input_tokens,
        "output_tokens": rollup.output_tokens,
        "reasoning_tokens": rollup.reasoning_tokens,
        "media_units": rollup.media_units,
        "estimated_cost": rollup.estimated_cost_micros,
        "usage_missing_count": rollup.usage_missing_count,
        "usage_estimated_count": rollup.usage_estimated_count,
        "p50_latency_ms": rollup.p50_latency_ms,
        "p95_latency_ms": rollup.p95_latency_ms,
        "p99_latency_ms": rollup.p99_latency_ms,
        "p50_ttft_ms": rollup.p50_ttft_ms,
        "latest_source_at": rollup.latest_source_at
    })
}

fn usage_bucket_kind(bucket_kind: Option<&str>) -> Result<&'static str> {
    match bucket_kind.unwrap_or("day") {
        "minute" => Ok("minute"),
        "hour" => Ok("hour"),
        "day" => Ok("day"),
        "month" => Ok("month"),
        _ => Err(GatewayError::BadRequest {
            message: "usage_bucket_kind_invalid".to_owned(),
        }),
    }
}

fn usage_timeseries_points(
    state: &AppState,
    scope: &DashboardScopeInput,
    bucket_kind: &str,
) -> Vec<Value> {
    let mut points: BTreeMap<chrono::DateTime<chrono::Utc>, DashboardUsageRollup> = BTreeMap::new();
    for bucket in state
        .store
        .ledger_buckets_for_tenant(&scope.tenant_id)
        .into_iter()
        .filter(|bucket| bucket.bucket_kind == bucket_kind)
        .filter(|bucket| dashboard_bucket_matches_scope(bucket, scope))
    {
        accumulate_usage_bucket(points.entry(bucket.bucket_start).or_default(), &bucket);
    }
    points
        .into_iter()
        .map(|(bucket_start, rollup)| {
            json!({
                "bucket_start": bucket_start,
                "measures": usage_rollup_measures_body(&rollup)
            })
        })
        .collect()
}

fn accumulate_usage_bucket(
    rollup: &mut DashboardUsageRollup,
    bucket: &crate::domain::LedgerBucketRecord,
) {
    rollup.request_count += bucket.request_count;
    rollup.success_count += bucket.success_count;
    rollup.error_count += bucket.error_count;
    rollup.input_tokens += bucket.input_tokens;
    rollup.output_tokens += bucket.output_tokens;
    rollup.reasoning_tokens += bucket.reasoning_tokens;
    rollup.media_units += bucket.media_units;
    rollup.estimated_cost_micros += bucket.estimated_cost_micros;
    rollup.usage_missing_count += bucket.usage_missing_count;
    rollup.usage_estimated_count += bucket.usage_estimated_count;
    rollup.latest_source_at = rollup.latest_source_at.max(Some(bucket.updated_at));
}

fn usage_breakdown_group(
    bucket: &crate::domain::LedgerBucketRecord,
    dimension: UsageBreakdownDimension,
) -> Option<(String, String)> {
    match dimension {
        UsageBreakdownDimension::Project => bucket
            .project_id
            .as_ref()
            .map(|id| ("project".to_owned(), id.clone())),
        UsageBreakdownDimension::ProjectMember => bucket
            .project_member_id
            .as_ref()
            .map(|id| ("project_member".to_owned(), id.clone())),
        UsageBreakdownDimension::Model => bucket
            .model_alias_id
            .as_ref()
            .map(|id| ("model_alias".to_owned(), id.clone()))
            .or_else(|| {
                bucket
                    .model_target_id
                    .as_ref()
                    .map(|id| ("model_target".to_owned(), id.clone()))
            }),
        UsageBreakdownDimension::ProviderEndpoint => bucket
            .provider_endpoint_id
            .as_ref()
            .map(|id| ("provider_endpoint".to_owned(), id.clone())),
    }
}

fn usage_event_matches_query(event: &UsageEventRecord, query: &AdminUsageEventsQuery) -> bool {
    matches_optional_filter(query.status.as_ref(), Some(event.status.as_str()))
        && matches_optional_filter(
            query.protocol_family.as_ref(),
            Some(event.protocol_family.as_str()),
        )
        && matches_optional_filter(
            query.usage_confidence.as_ref(),
            Some(event.usage_confidence.as_str()),
        )
}

fn usage_event_body(event: &UsageEventRecord) -> Value {
    json!({
        "kind": "usage_event",
        "id": &event.usage_event_id,
        "usage_event_id": &event.usage_event_id,
        "tenant_id": &event.tenant_id,
        "organization_id": &event.organization_id,
        "project_id": &event.project_id,
        "principal_id": &event.principal_id,
        "project_member_id": &event.project_member_id,
        "service_account_id": &event.service_account_id,
        "api_key_id": &event.api_key_id,
        "request_id": &event.request_id,
        "protocol_family": event.protocol_family.as_str(),
        "route_decision_id": &event.route_decision_id,
        "model_alias_id": &event.model_alias_id,
        "model_target_id": &event.model_target_id,
        "route_policy_id": &event.route_policy_id,
        "routing_group_id": &event.routing_group_id,
        "provider_endpoint_id": &event.provider_endpoint_id,
        "usage_confidence": &event.usage_confidence,
        "latency_ms": event.latency_ms,
        "time_to_first_token_ms": event.time_to_first_token_ms,
        "status": &event.status,
        "usage_payload": &event.usage_payload,
        "cost_payload": &event.cost_payload,
        "occurred_at": event.occurred_at
    })
}

fn usage_list_limit(limit: Option<usize>) -> Result<usize> {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;
    match limit.unwrap_or(DEFAULT_LIMIT) {
        0 => Err(GatewayError::BadRequest {
            message: "usage_limit_must_be_positive".to_owned(),
        }),
        value if value > MAX_LIMIT => Err(GatewayError::BadRequest {
            message: "usage_limit_exceeds_maximum".to_owned(),
        }),
        value => Ok(value),
    }
}

fn usage_list_offset(cursor: Option<&str>) -> Result<usize> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    if cursor.trim().is_empty() {
        return Err(GatewayError::BadRequest {
            message: "usage_cursor_invalid".to_owned(),
        });
    }
    cursor
        .parse::<usize>()
        .map_err(|_| GatewayError::BadRequest {
            message: "usage_cursor_invalid".to_owned(),
        })
}

#[derive(Clone, Debug, Default)]
struct DashboardRouteRollup {
    request_count: usize,
    blocked_count: usize,
    no_route_count: usize,
    success_count: usize,
    error_count: usize,
    attempt_count: usize,
    latest_decision_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn dashboard_route_rollup(state: &AppState, scope: &DashboardScopeInput) -> DashboardRouteRollup {
    let decisions = state
        .store
        .route_decisions()
        .into_iter()
        .filter(|decision| dashboard_decision_matches_scope(decision, scope))
        .collect::<Vec<_>>();
    let decision_ids = decisions
        .iter()
        .map(|decision| decision.route_decision_id.as_str())
        .collect::<HashSet<_>>();
    let attempts = state
        .store
        .route_attempts()
        .into_iter()
        .filter(|attempt| decision_ids.contains(attempt.route_decision_id.as_str()))
        .collect::<Vec<_>>();
    let latest_decision_at = decisions.iter().map(|decision| decision.occurred_at).max();
    let request_count = decisions.len();
    let blocked_count = decisions
        .iter()
        .filter(|decision| decision.status == RouteDecisionStatus::Blocked)
        .count();
    let no_route_count = decisions
        .iter()
        .filter(|decision| decision.status == RouteDecisionStatus::NoRoute)
        .count();
    let success_count = attempts
        .iter()
        .filter(|attempt| attempt.status == RouteAttemptStatus::Completed)
        .count();
    let error_count = attempts
        .iter()
        .filter(|attempt| attempt.status == RouteAttemptStatus::Failed)
        .count();
    DashboardRouteRollup {
        request_count,
        blocked_count,
        no_route_count,
        success_count,
        error_count,
        attempt_count: attempts.len(),
        latest_decision_at,
    }
}

fn dashboard_scope_body(scope: &DashboardScopeInput) -> Value {
    json!({
        "kind": scope.scope_kind,
        "id": &scope.scope_id,
        "organization_id": scope.organization_id.as_deref(),
        "project_id": scope.project_id.as_deref(),
        "project_member_id": scope.project_member_id.as_deref(),
        "principal_id": scope.principal_id.as_deref()
    })
}

fn dashboard_measures_body(
    route_rollup: &DashboardRouteRollup,
    usage_rollup: &DashboardUsageRollup,
    usage_available: bool,
) -> Value {
    let request_count = if usage_available {
        usize::try_from(usage_rollup.request_count).unwrap_or(usize::MAX)
    } else {
        route_rollup.request_count
    };
    let success_count = if usage_available {
        usize::try_from(usage_rollup.success_count).unwrap_or(usize::MAX)
    } else {
        route_rollup.success_count
    };
    let error_count = if usage_available {
        usize::try_from(usage_rollup.error_count).unwrap_or(usize::MAX)
    } else {
        route_rollup.error_count
    };
    json!({
        "request_count": request_count,
        "success_count": success_count,
        "error_count": error_count,
        "blocked_count": route_rollup.blocked_count,
        "no_route_count": route_rollup.no_route_count,
        "attempt_count": route_rollup.attempt_count,
        "input_tokens": usage_rollup.input_tokens_if_available(),
        "output_tokens": usage_rollup.output_tokens_if_available(),
        "reasoning_tokens": usage_rollup.reasoning_tokens_if_available(),
        "media_units": usage_rollup.media_units_if_available(),
        "estimated_cost": usage_rollup.estimated_cost_if_available(),
        "budget_remaining": null,
        "burn_rate": null,
        "p50_latency_ms": usage_rollup.p50_latency_ms,
        "p95_latency_ms": usage_rollup.p95_latency_ms,
        "p99_latency_ms": usage_rollup.p99_latency_ms,
        "p50_ttft_ms": usage_rollup.p50_ttft_ms,
        "provider_error_rate": null,
        "usage_missing_count": usage_rollup.usage_missing_count_if_available(),
        "usage_estimated_count": usage_rollup.usage_estimated_count_if_available()
    })
}

const fn dashboard_fallback_reason(usage_available: bool) -> &'static str {
    if usage_available {
        "budget_quota_hot_state_not_connected"
    } else {
        "usage_ledger_rollups_not_connected"
    }
}

const fn dashboard_usage_source(usage_available: bool) -> &'static str {
    if usage_available {
        "durable_ledger_buckets"
    } else {
        "unavailable"
    }
}

fn dashboard_unavailable_sources(usage_available: bool) -> Value {
    if usage_available {
        json!(["budget_timeseries", "quota_timeseries"])
    } else {
        json!([
            "usage_ledger_rollups",
            "budget_timeseries",
            "quota_timeseries",
            "latency_rollups"
        ])
    }
}

#[derive(Clone, Debug, Default)]
struct DashboardUsageRollup {
    request_count: i64,
    success_count: i64,
    error_count: i64,
    input_tokens: i64,
    output_tokens: i64,
    reasoning_tokens: i64,
    media_units: i64,
    estimated_cost_micros: i64,
    usage_missing_count: i64,
    usage_estimated_count: i64,
    p50_latency_ms: Option<i64>,
    p95_latency_ms: Option<i64>,
    p99_latency_ms: Option<i64>,
    p50_ttft_ms: Option<i64>,
    latest_source_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl DashboardUsageRollup {
    const fn input_tokens_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.input_tokens)
        } else {
            None
        }
    }

    const fn output_tokens_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.output_tokens)
        } else {
            None
        }
    }

    const fn reasoning_tokens_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.reasoning_tokens)
        } else {
            None
        }
    }

    const fn media_units_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.media_units)
        } else {
            None
        }
    }

    const fn estimated_cost_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.estimated_cost_micros)
        } else {
            None
        }
    }

    const fn usage_missing_count_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.usage_missing_count)
        } else {
            None
        }
    }

    const fn usage_estimated_count_if_available(&self) -> Option<i64> {
        if self.request_count > 0 {
            Some(self.usage_estimated_count)
        } else {
            None
        }
    }
}

fn dashboard_usage_rollup(state: &AppState, scope: &DashboardScopeInput) -> DashboardUsageRollup {
    let mut rollup = DashboardUsageRollup::default();
    for bucket in state
        .store
        .ledger_buckets_for_tenant(&scope.tenant_id)
        .into_iter()
        .filter(|bucket| bucket.bucket_kind == "event")
        .filter(|bucket| dashboard_bucket_matches_scope(bucket, scope))
    {
        rollup.request_count += bucket.request_count;
        rollup.success_count += bucket.success_count;
        rollup.error_count += bucket.error_count;
        rollup.input_tokens += bucket.input_tokens;
        rollup.output_tokens += bucket.output_tokens;
        rollup.reasoning_tokens += bucket.reasoning_tokens;
        rollup.media_units += bucket.media_units;
        rollup.estimated_cost_micros += bucket.estimated_cost_micros;
        rollup.usage_missing_count += bucket.usage_missing_count;
        rollup.usage_estimated_count += bucket.usage_estimated_count;
        rollup.latest_source_at = rollup.latest_source_at.max(Some(bucket.updated_at));
    }
    let usage_events = state
        .store
        .usage_events_for_tenant(&scope.tenant_id)
        .into_iter()
        .filter(|event| dashboard_usage_event_matches_scope(event, scope))
        .collect::<Vec<_>>();
    let latencies = usage_events
        .iter()
        .filter_map(|event| event.latency_ms)
        .collect::<Vec<_>>();
    let ttfts = usage_events
        .iter()
        .filter_map(|event| event.time_to_first_token_ms)
        .collect::<Vec<_>>();
    rollup.p50_latency_ms = percentile_i64(latencies.clone(), 50);
    rollup.p95_latency_ms = percentile_i64(latencies.clone(), 95);
    rollup.p99_latency_ms = percentile_i64(latencies, 99);
    rollup.p50_ttft_ms = percentile_i64(ttfts, 50);
    rollup
}

fn dashboard_bucket_matches_scope(
    bucket: &crate::domain::LedgerBucketRecord,
    scope: &DashboardScopeInput,
) -> bool {
    if bucket.tenant_id != scope.tenant_id {
        return false;
    }
    match scope.scope_kind {
        "tenant" => bucket.tenant_id == scope.scope_id,
        "organization" => bucket.organization_id.as_deref() == scope.organization_id.as_deref(),
        "project" => bucket.project_id.as_deref() == scope.project_id.as_deref(),
        "project_member" => {
            bucket.project_member_id.as_deref() == scope.project_member_id.as_deref()
        }
        "api_key" => bucket.api_key_id.as_deref() == Some(scope.scope_id.as_str()),
        "service_account" => bucket.service_account_id.as_deref() == Some(scope.scope_id.as_str()),
        "model_alias" => bucket.model_alias_id.as_deref() == Some(scope.scope_id.as_str()),
        "model_target" => bucket.model_target_id.as_deref() == Some(scope.scope_id.as_str()),
        "provider_endpoint" => {
            bucket.provider_endpoint_id.as_deref() == Some(scope.scope_id.as_str())
        }
        "route_policy" => bucket.route_policy_id.as_deref() == Some(scope.scope_id.as_str()),
        "routing_group" => bucket.routing_group_id.as_deref() == Some(scope.scope_id.as_str()),
        "protocol_family" => bucket
            .protocol_family
            .is_some_and(|protocol_family| protocol_family.as_str() == scope.scope_id),
        _ => false,
    }
}

fn dashboard_usage_event_matches_scope(
    event: &UsageEventRecord,
    scope: &DashboardScopeInput,
) -> bool {
    if event.tenant_id != scope.tenant_id {
        return false;
    }
    match scope.scope_kind {
        "tenant" => event.tenant_id == scope.scope_id,
        "organization" => event.organization_id.as_deref() == scope.organization_id.as_deref(),
        "project" => event.project_id.as_deref() == scope.project_id.as_deref(),
        "project_member" => {
            event.project_member_id.as_deref() == scope.project_member_id.as_deref()
        }
        "api_key" => event.api_key_id.as_deref() == Some(scope.scope_id.as_str()),
        "service_account" => event.service_account_id.as_deref() == Some(scope.scope_id.as_str()),
        "model_alias" => event.model_alias_id.as_deref() == Some(scope.scope_id.as_str()),
        "model_target" => event.model_target_id.as_deref() == Some(scope.scope_id.as_str()),
        "provider_endpoint" => {
            event.provider_endpoint_id.as_deref() == Some(scope.scope_id.as_str())
        }
        "route_policy" => event.route_policy_id.as_deref() == Some(scope.scope_id.as_str()),
        "routing_group" => event.routing_group_id.as_deref() == Some(scope.scope_id.as_str()),
        "protocol_family" => event.protocol_family.as_str() == scope.scope_id,
        _ => false,
    }
}

fn percentile_i64(mut values: Vec<i64>, percentile: usize) -> Option<i64> {
    if values.is_empty() {
        return None;
    }
    values.sort_unstable();
    let rank = ((values.len() - 1) * percentile).div_ceil(100);
    values.get(rank).copied()
}

fn dashboard_decision_matches_scope(
    decision: &RouteDecisionRecord,
    scope: &DashboardScopeInput,
) -> bool {
    if decision.tenant_id != scope.tenant_id {
        return false;
    }
    match scope.scope_kind {
        "tenant" => decision.tenant_id == scope.scope_id,
        "organization" => decision.organization_id.as_deref() == scope.organization_id.as_deref(),
        "project" => decision.project_id.as_deref() == scope.project_id.as_deref(),
        "project_member" => {
            decision.project_id.as_deref() == scope.project_id.as_deref()
                && decision.principal_id.as_deref() == scope.principal_id.as_deref()
        }
        "api_key" => decision.api_key_id.as_deref() == Some(scope.scope_id.as_str()),
        "service_account" => decision.principal_id.as_deref() == Some(scope.scope_id.as_str()),
        "model_alias" => decision.model_alias_id.as_deref() == Some(scope.scope_id.as_str()),
        "model_target" => decision.model_target_id.as_deref() == Some(scope.scope_id.as_str()),
        "provider_endpoint" => {
            decision.provider_endpoint_id.as_deref() == Some(scope.scope_id.as_str())
        }
        _ => false,
    }
}

fn route_policy_resource_envelope(policy: &RoutePolicyRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": route_policy_resource_body(policy)
    })
}

fn route_policy_resource_body(policy: &RoutePolicyRecord) -> Value {
    json!({
        "kind": "route_policy",
        "id": &policy.route_policy_id,
        "tenant_id": &policy.tenant_id,
        "organization_id": &policy.organization_id,
        "name": &policy.name,
        "protocol_family": policy.protocol_family.as_str(),
        "model_alias_id": &policy.model_alias_id,
        "routing_group_id": &policy.routing_group_id,
        "version": policy.resource_version,
        "status": &policy.status,
        "created_by": &policy.created_by,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at
    })
}

fn provider_grant_resource_envelope(grant: &ProviderGrantRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": provider_grant_resource_body(grant)
    })
}

fn provider_grant_resource_body(grant: &ProviderGrantRecord) -> Value {
    json!({
        "kind": "provider_grant",
        "id": &grant.provider_grant_id,
        "tenant_id": &grant.tenant_id,
        "scope_kind": &grant.scope_kind,
        "scope_id": &grant.scope_id,
        "organization_id": &grant.organization_id,
        "project_id": &grant.project_id,
        "resource_kind": &grant.resource_kind,
        "resource_id": &grant.resource_id,
        "effect": &grant.effect,
        "closure_mode": &grant.closure_mode,
        "version": grant.resource_version,
        "status": &grant.status,
        "created_by": &grant.created_by,
        "created_at": grant.created_at,
        "updated_at": grant.updated_at
    })
}

fn routing_group_resource_envelope(group: &RoutingGroupRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": routing_group_resource_body(group)
    })
}

fn routing_group_resource_body(group: &RoutingGroupRecord) -> Value {
    json!({
        "kind": "routing_group",
        "id": &group.routing_group_id,
        "tenant_id": &group.tenant_id,
        "organization_id": &group.organization_id,
        "name": &group.name,
        "protocol_family": group.protocol_family.as_str(),
        "purpose": &group.purpose,
        "version": group.resource_version,
        "status": &group.status,
        "created_by": &group.created_by,
        "created_at": group.created_at,
        "updated_at": group.updated_at
    })
}

fn routing_group_target_resource_envelope(target: &RoutingGroupTargetRecord) -> Value {
    json!({
        "schema": "gateway.admin.resource.v1",
        "resource": routing_group_target_resource_body(target)
    })
}

fn routing_group_target_resource_body(target: &RoutingGroupTargetRecord) -> Value {
    json!({
        "kind": "routing_group_target",
        "id": &target.routing_group_target_id,
        "tenant_id": &target.tenant_id,
        "routing_group_id": &target.routing_group_id,
        "model_target_id": &target.model_target_id,
        "weight": target.weight,
        "priority": target.priority,
        "version": target.resource_version,
        "status": &target.status,
        "created_by": &target.created_by,
        "created_at": target.created_at,
        "updated_at": target.updated_at
    })
}

const fn default_true() -> bool {
    true
}

fn default_secret_ref_backend_kind() -> String {
    "memory".to_owned()
}

const fn default_otel_export_interval_seconds() -> i64 {
    60
}

const fn default_otel_export_timeout_seconds() -> i64 {
    10
}

const fn default_export_retention_days() -> i64 {
    30
}

fn request_id_from_headers(headers: &HeaderMap) -> String {
    headers
        .get(REQUEST_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| is_safe_request_id(value))
        .map_or_else(|| new_prefixed_id("req"), ToOwned::to_owned)
}

fn bearer_token(headers: &HeaderMap) -> Result<&str> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Err(GatewayError::Authentication);
    };
    let value = value.to_str().map_err(|_| GatewayError::Authentication)?;
    let Some((scheme, token)) = value.split_once(' ') else {
        return Err(GatewayError::Authentication);
    };
    let token = token.trim();
    if !scheme.eq_ignore_ascii_case("Bearer") || token.is_empty() {
        return Err(GatewayError::Authentication);
    }
    Ok(token)
}

fn optional_header(headers: &HeaderMap, name: &'static str) -> Result<Option<String>> {
    headers
        .get(name)
        .map(|value| {
            value
                .to_str()
                .map(|value| value.trim().to_owned())
                .map_err(|_| GatewayError::BadRequest {
                    message: format!("invalid header {name}"),
                })
        })
        .transpose()
        .map(|value| value.filter(|value| !value.is_empty()))
}

fn request_body_from_bytes(bytes: &[u8]) -> Result<Value> {
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice::<Value>(bytes).map_err(|error| GatewayError::BadRequest {
        message: format!("request body must be JSON: {error}"),
    })
}

fn requested_resource_id(body: &Value, path: &str) -> String {
    body.get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.trim().is_empty())
        .map_or_else(|| resource_id_from_path(path), ToOwned::to_owned)
}

fn resource_id_from_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("/v1beta/models/") {
        return rest
            .split(':')
            .next()
            .filter(|model| !model.is_empty())
            .unwrap_or("unknown")
            .to_owned();
    }
    if let Some(rest) = path.strip_prefix("/model/") {
        return rest
            .split('/')
            .next()
            .filter(|model| !model.is_empty())
            .unwrap_or("unknown")
            .to_owned();
    }
    if let Some(rest) = path.strip_prefix("/native/") {
        return rest.replace('/', ":");
    }
    "unknown".to_owned()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeRouteTarget {
    authorization_resource_id: String,
    upstream_model_id: String,
    route_decision_id: Option<String>,
    selected_route: Option<SelectedRouteEvidence>,
    decision_request: Option<RouteDecisionRequest>,
}

fn runtime_route_target(
    state: &AppState,
    actor: &AuthenticatedActor,
    replay_case: &GatewayReplayCase,
    requested_model: &str,
) -> Result<RuntimeRouteTarget> {
    let Some(loaded_catalog) = latest_catalog_for_actor(state, actor)? else {
        return Ok(RuntimeRouteTarget {
            authorization_resource_id: requested_model.to_owned(),
            upstream_model_id: requested_model.to_owned(),
            route_decision_id: None,
            selected_route: None,
            decision_request: None,
        });
    };
    let decision_request = RouteDecisionRequest {
        protocol_family: replay_case.protocol_family,
        alias_name: requested_model.to_owned(),
        config_snapshot_id: Some(loaded_catalog.snapshot_id.clone()),
        config_version: Some(loaded_catalog.version),
    };
    let plan = loaded_catalog
        .catalog
        .plan_runtime_route_with_hot_state(&RoutePlanRequest {
            actor,
            protocol_family: replay_case.protocol_family,
            alias_name: requested_model,
            streaming: replay_case.streaming,
            hot_state: state.store(),
            config_version: Some(loaded_catalog.version),
            now: chrono::Utc::now(),
        })?;
    match plan.outcome {
        RoutePlanOutcome::Selected(selection) => {
            let selected_evidence = SelectedRouteEvidence {
                model_alias_id: selection.model_alias_id.clone(),
                route_policy_id: selection.route_policy_id.clone(),
                routing_group_id: selection.routing_group_id.clone(),
                model_target_id: selection.model_target_id.clone(),
                provider_endpoint_id: selection.provider_endpoint.provider_endpoint_id.clone(),
                upstream_credential_id: selection.upstream_credential_id.clone(),
                filtered_summary: selection.filtered_summary.clone(),
            };
            let decision = RouteDecisionRecord::selected(
                actor,
                decision_request.clone(),
                selected_evidence.clone(),
                chrono::Utc::now(),
            );
            let route_decision_id = decision.route_decision_id.clone();
            state.store.record_route_decision(decision);
            Ok(RuntimeRouteTarget {
                authorization_resource_id: selection.model_alias_id,
                upstream_model_id: selection.upstream_model_id,
                route_decision_id: Some(route_decision_id),
                selected_route: Some(selected_evidence),
                decision_request: Some(decision_request),
            })
        }
        RoutePlanOutcome::ProviderGrantDenied => {
            state
                .store
                .record_route_decision(RouteDecisionRecord::terminal(
                    actor,
                    decision_request,
                    RouteDecisionStatus::Blocked,
                    "provider_grant_denied",
                    plan.filtered_summary,
                    chrono::Utc::now(),
                ));
            Err(GatewayError::Authorization {
                reason: "provider_grant_denied",
            })
        }
        RoutePlanOutcome::NoRoute => {
            state
                .store
                .record_route_decision(RouteDecisionRecord::terminal(
                    actor,
                    decision_request,
                    RouteDecisionStatus::NoRoute,
                    "no_eligible_model_target",
                    plan.filtered_summary,
                    chrono::Utc::now(),
                ));
            Err(GatewayError::NoRoute {
                reason: "no_eligible_model_target",
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadedCatalog {
    catalog: GatewayCatalogSnapshot,
    snapshot_id: String,
    version: i64,
}

fn latest_catalog_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
) -> Result<Option<LoadedCatalog>> {
    let Some(snapshot) = latest_snapshot_for_actor(state, actor)? else {
        return Ok(None);
    };
    GatewayCatalogSnapshot::from_payload(&snapshot.document.payload).map(|catalog| {
        catalog.map(|catalog| LoadedCatalog {
            catalog,
            snapshot_id: snapshot.metadata.snapshot_id,
            version: snapshot.metadata.version,
        })
    })
}

fn latest_snapshot_for_actor(
    state: &AppState,
    actor: &AuthenticatedActor,
) -> Result<Option<crate::config::PublishedConfigSnapshot>> {
    let Some(metadata) = state
        .store
        .latest_published_snapshot_for_tenant(&actor.tenant_id)
    else {
        return Ok(None);
    };
    let snapshot = state
        .store
        .config_snapshot(&metadata.snapshot_id)
        .ok_or_else(|| GatewayError::Internal {
            message: format!(
                "latest config snapshot {} is missing from store",
                metadata.snapshot_id
            ),
        })?;
    Ok(Some(snapshot))
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode};
    use chrono::Duration;
    use secrecy::ExposeSecret;
    use serde_json::json;
    use tower::ServiceExt;

    use super::{
        authenticate_request, deliver_due_notifications, enforce_runtime_policy_preflight,
        release_runtime_policy_reservations, router, run_otel_exporter_once,
        runtime_budget_reservation_key, runtime_quota_counter_key, runtime_route_target,
        validate_gateway_config, AppState, DependencyProbeMode, GatewayConfig,
        SingleUserAuthConfig, PROJECT_ID_HEADER, REQUEST_ID_HEADER, SESSION_TOKEN_PREFIX,
        SINGLE_USER_ID, SINGLE_USER_ORGANIZATION_ID, SINGLE_USER_PROJECT_ID,
        SINGLE_USER_PROVIDER_ID, SINGLE_USER_TENANT_ID,
    };
    use crate::action::{ActionGrant, BuiltInRole};
    use crate::auth::{create_auth_session, verify_api_key, CreateAuthSessionRequest};
    use crate::config::{publish_config_snapshot, PublishConfigSnapshotRequest};
    use crate::domain::{
        new_prefixed_id, ActorKind, DirectoryStatus, ExternalIdentityRecord, MembershipStatus,
        NotificationDeliveryAttemptRecord, ResourceStatus, UpstreamCredentialStatus,
        UsageEventRecord, ValidationDiagnosticRecord,
    };
    use crate::error::GatewayError;
    use crate::fixtures::{
        FoundationTestFixture, TEST_ORGANIZATION_ID, TEST_PROJECT_ID, TEST_TENANT_ID, TEST_USER_ID,
    };
    use crate::hot_state::{EndpointDrainRecord, EndpointHealthRecord, EndpointHealthState};
    use crate::replay::{foundation_route_replay_cases, GatewayReplayCase};
    use crate::route::foundation_routes;
    use crate::routing::{
        RouteAttemptRecord, RouteAttemptStatus, RouteDecisionRecord, RouteDecisionStatus,
        RouteEvidenceSink, RouteFilterReason,
    };
    use crate::storage::{
        CatalogAdminRepository, ConfigPublicationRepository, CreateNotificationOutboxEventRequest,
        CreateSecretRefRequest, InMemoryGatewayStore, NotificationOutboxRepository,
        ProviderAdminRepository, RuntimePolicyRepository, SecretRefAdminRepository,
        ServiceAccountAdminRepository, TenancyBootstrapRepository, TenancyRepository,
        UsageAccountingRepository, ValidationDiagnosticRepository,
    };
    use crate::ProtocolFamily;

    static ENV_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvRestore {
        values: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl EnvRestore {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                values: keys
                    .iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            }
        }
    }

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.values {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[tokio::test]
    async fn healthz_returns_service_status() {
        let response = match router(AppState::default())
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("health request should complete: {error}"),
        };

        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key(REQUEST_ID_HEADER));
    }

    #[test]
    fn gateway_config_from_env_enables_single_user_only_with_required_credentials() {
        const KEYS: &[&str] = &[
            "STARWEAVER_GATEWAY_DATABASE_URL",
            "STARWEAVER_GATEWAY_REDIS_URL",
            "STARWEAVER_GATEWAY_ENV",
            "STARWEAVER_GATEWAY_DEPENDENCY_PROBE_MODE",
            "STARWEAVER_GATEWAY_READINESS_PROBE_TIMEOUT_MS",
            "STARWEAVER_GATEWAY_SINGLE_USER_USERNAME",
            "STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD",
            "STARWEAVER_GATEWAY_SINGLE_USER_EMAIL",
            "STARWEAVER_GATEWAY_SINGLE_USER_DISPLAY_NAME",
            "STARWEAVER_GATEWAY_SINGLE_USER_SESSION_TTL_SECONDS",
        ];

        let _lock = ENV_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _restore = EnvRestore::capture(KEYS);
        for key in KEYS {
            std::env::remove_var(key);
        }

        assert!(GatewayConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_USERNAME", "admin");
        assert!(GatewayConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD", " ");
        assert!(GatewayConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_USERNAME", " ");
        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD", "secret");
        assert!(GatewayConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_USERNAME", " admin ");
        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_PASSWORD", " secret ");
        std::env::set_var(
            "STARWEAVER_GATEWAY_SINGLE_USER_EMAIL",
            " admin@example.com ",
        );
        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_DISPLAY_NAME", " Admin ");
        std::env::set_var("STARWEAVER_GATEWAY_SINGLE_USER_SESSION_TTL_SECONDS", "600");

        let config = GatewayConfig::from_env();
        let single_user = config
            .single_user_auth
            .unwrap_or_else(|| panic!("single-user config should be enabled"));

        assert_eq!(single_user.username, "admin");
        assert_eq!(single_user.password, "secret");
        assert_eq!(
            config.dependency_probe_mode,
            DependencyProbeMode::Configured
        );
        assert_eq!(
            single_user.user_primary_email.as_deref(),
            Some("admin@example.com")
        );
        assert_eq!(single_user.user_display_name, "Admin");
        assert_eq!(single_user.session_ttl_seconds, 600);
    }

    #[test]
    fn gateway_config_from_env_defaults_live_dependency_probes_when_dependencies_are_configured() {
        const KEYS: &[&str] = &[
            "STARWEAVER_GATEWAY_DATABASE_URL",
            "STARWEAVER_GATEWAY_REDIS_URL",
            "STARWEAVER_GATEWAY_ENV",
            "STARWEAVER_GATEWAY_DEPENDENCY_PROBE_MODE",
            "STARWEAVER_GATEWAY_READINESS_PROBE_TIMEOUT_MS",
        ];

        let _lock = ENV_TEST_MUTEX
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _restore = EnvRestore::capture(KEYS);
        for key in KEYS {
            std::env::remove_var(key);
        }

        assert_eq!(
            GatewayConfig::from_env().dependency_probe_mode,
            DependencyProbeMode::Configured
        );

        std::env::set_var(
            "STARWEAVER_GATEWAY_DATABASE_URL",
            "postgres://gateway.example/starweaver",
        );
        assert_eq!(
            GatewayConfig::from_env().dependency_probe_mode,
            DependencyProbeMode::Live
        );

        std::env::set_var("STARWEAVER_GATEWAY_DEPENDENCY_PROBE_MODE", "configured");
        std::env::set_var("STARWEAVER_GATEWAY_READINESS_PROBE_TIMEOUT_MS", "50");
        let config = GatewayConfig::from_env();
        assert_eq!(
            config.dependency_probe_mode,
            DependencyProbeMode::Configured
        );
        assert_eq!(config.readiness_probe_timeout_ms, 50);

        std::env::remove_var("STARWEAVER_GATEWAY_DATABASE_URL");
        std::env::remove_var("STARWEAVER_GATEWAY_DEPENDENCY_PROBE_MODE");
        std::env::set_var("STARWEAVER_GATEWAY_ENV", "production");
        assert_eq!(
            GatewayConfig::from_env().dependency_probe_mode,
            DependencyProbeMode::Live
        );
    }

    #[tokio::test]
    async fn readyz_can_require_published_snapshot() {
        let state = AppState::new(
            GatewayConfig {
                require_published_snapshot: true,
                ..GatewayConfig::default()
            },
            InMemoryGatewayStore::default(),
        );
        let response = match router(state)
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("ready request should complete: {error}"),
        };

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn readyz_reports_ready_after_config_publication() {
        let store = InMemoryGatewayStore::default();
        match publish_config_snapshot(
            &store,
            PublishConfigSnapshotRequest {
                tenant_id: "ten_test".to_owned(),
                resource_versions: Vec::new(),
                payload: json!({ "resources": [] }),
                created_by: "usr_test".to_owned(),
            },
            chrono::Utc::now(),
        ) {
            Ok(_) => {}
            Err(error) => panic!("config snapshot should publish: {error}"),
        }
        let state = AppState::new(
            GatewayConfig {
                require_published_snapshot: true,
                ..GatewayConfig::default()
            },
            store,
        );
        let response = match router(state)
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("ready request should complete: {error}"),
        };

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn production_profile_rejects_unsafe_startup_config() {
        let error = match validate_gateway_config(&GatewayConfig {
            environment: "production".to_owned(),
            ..GatewayConfig::default()
        }) {
            Ok(()) => panic!("unsafe production profile should be rejected"),
            Err(error) => error,
        };

        assert!(error
            .to_string()
            .contains("database_url_required,redis_url_required"));
        assert!(error
            .to_string()
            .contains("durable_secret_backend_required"));
        assert!(error.to_string().contains("telemetry_required"));
        assert!(error.to_string().contains("published_snapshot_required"));
        assert!(error.to_string().contains("live_dependency_probe_required"));
    }

    #[tokio::test]
    async fn readyz_reports_live_dependency_failures() {
        let state = AppState::new(
            GatewayConfig {
                environment: "production".to_owned(),
                database_url: Some("not-a-postgres-url".to_owned()),
                redis_url: Some("not-a-redis-url".to_owned()),
                secret_backend_profile: "gcp-secret-manager".to_owned(),
                telemetry_profile: "otlp".to_owned(),
                dependency_probe_mode: DependencyProbeMode::Live,
                readiness_probe_timeout_ms: 50,
                require_published_snapshot: true,
                ..GatewayConfig::default()
            },
            InMemoryGatewayStore::default(),
        );
        let response = match router(state)
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("ready request should complete: {error}"),
        };
        let status = response.status();
        let body = response_json(response).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["reason"], "dependency_unready");
        assert_eq!(body["profile"]["production_profile"], true);
        assert_eq!(body["profile"]["production_profile_valid"], true);
        assert_eq!(body["profile"]["dependency_probe_mode"], "live");
        assert_eq!(body["dependencies"]["database"], "unavailable");
        assert_eq!(body["dependencies"]["database_migrations"], "unavailable");
        assert_eq!(
            body["dependencies"]["database_missing_migrations"]
                .as_array()
                .map_or(usize::MAX, Vec::len),
            0
        );
        assert_eq!(body["dependencies"]["hot_state"], "invalid");
        assert_eq!(body["dependencies"]["secret_backend"], "profile_configured");
        assert_eq!(
            body["dependencies"]["secret_backend_profile"],
            "gcp-secret-manager"
        );
        assert_eq!(body["dependencies"]["telemetry"], "profile_configured");
        assert_eq!(body["dependencies"]["telemetry_profile"], "otlp");
        assert_eq!(body["dependencies"]["otel_exporter"], "not_configured");
        assert_eq!(
            body["dependencies"]["published_snapshot_requirement"],
            "required"
        );
        assert_eq!(body["dependencies"]["published_snapshot"], "missing");
        assert_eq!(body["diagnostics"].as_array().map_or(0, Vec::len), 0);
    }

    #[tokio::test]
    async fn readyz_reports_configured_dependency_probe_mode() {
        let state = AppState::new(
            GatewayConfig {
                database_url: Some("postgres://gateway.example/starweaver".to_owned()),
                redis_url: Some("redis://redis.example/0".to_owned()),
                dependency_probe_mode: DependencyProbeMode::Configured,
                ..GatewayConfig::default()
            },
            InMemoryGatewayStore::default(),
        );
        let response = match router(state)
            .oneshot(
                Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("ready request should complete: {error}"),
        };
        let status = response.status();
        let body = response_json(response).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["profile"]["dependency_probe_mode"], "configured");
        assert_eq!(body["dependencies"]["database"], "configured");
        assert_eq!(body["dependencies"]["database_migrations"], "not_checked");
        assert_eq!(body["dependencies"]["hot_state"], "configured");
        assert_eq!(body["dependencies"]["secret_backend"], "memory");
        assert_eq!(body["dependencies"]["telemetry"], "disabled");
    }

    #[tokio::test]
    async fn realtime_overview_reads_hot_state_without_metrics_backend() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        publish_catalog_snapshot(&store, catalog_payload());
        let now = chrono::Utc::now();
        store.set_endpoint_health(EndpointHealthRecord {
            tenant_id: TEST_TENANT_ID.to_owned(),
            provider_endpoint_id: endpoint_id,
            config_version: 1,
            state: EndpointHealthState::Degraded,
            observed_at: now,
            expires_at: now + Duration::seconds(60),
        });

        let response = get_admin(store, &raw_session, "/admin/v1/realtime/overview").await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schema"], "gateway.admin.realtime_overview.v1");
        assert_eq!(body["source"]["metrics_backend_queried"], false);
        assert_eq!(body["providers"]["endpoint_count"], 1);
        assert_eq!(body["providers"]["health_counts"]["degraded"], 1);
        assert_eq!(body["providers"]["freshness_status"], "fresh");
        assert_eq!(body["budgets"]["hot_state_status"], "unavailable");
        assert_eq!(body["quotas"]["hot_state_status"], "unavailable");
        assert_eq!(
            body["config"]["publication"]["source"],
            "durable_publication_pointer"
        );
        assert_eq!(body["workers"]["reload_evidence"], "not_connected");
    }

    #[tokio::test]
    async fn realtime_overview_reports_worker_polling_convergence_after_missed_invalidation() {
        let (store, raw_session) = gateway_store_with_admin_session();
        publish_catalog_snapshot(&store, catalog_payload());
        let first_invalidation = store
            .config_invalidation_events_for_tenant(TEST_TENANT_ID)
            .pop()
            .unwrap_or_else(|| panic!("first invalidation should be present"));
        let first_reload = store
            .reload_config_worker_from_invalidation(
                TEST_TENANT_ID,
                "gateway-runtime",
                &first_invalidation.invalidation_id,
                first_invalidation.published_at,
            )
            .unwrap_or_else(|error| panic!("first reload should record: {error}"));
        assert_eq!(first_reload.loaded_version, 1);

        let mut next_payload = catalog_payload();
        next_payload["resources"] = json!(["updated-route-config"]);
        publish_catalog_snapshot(&store, next_payload);
        let latest_publication = store
            .config_publication(TEST_TENANT_ID)
            .unwrap_or_else(|| panic!("latest publication should be present"));
        let polled_reload = store
            .reload_config_worker_by_polling(
                TEST_TENANT_ID,
                "gateway-runtime",
                latest_publication.published_at + Duration::milliseconds(25),
            )
            .unwrap_or_else(|error| panic!("polling reload should record: {error}"));
        assert_eq!(polled_reload.loaded_version, 2);
        assert_eq!(polled_reload.missed_invalidation_count, 1);

        let response = get_admin(store, &raw_session, "/admin/v1/realtime/overview").await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["config"]["loaded_config_version"], 2);
        assert_eq!(body["config"]["publication"]["version"], 2);
        assert_eq!(body["workers"]["reload_evidence"], "converged");
        assert_eq!(body["workers"]["heartbeat_status"], "fresh");
        assert_eq!(body["workers"]["loaded_config_version"], 2);
        assert_eq!(body["workers"]["last_reload_source"], "polling");
        assert_eq!(body["workers"]["missed_invalidation_count"], 1);
        assert_eq!(body["workers"]["publication_lag_ms"], 25);
        assert_eq!(body["workers"]["workers"].as_array().map_or(0, Vec::len), 1);
    }

    #[tokio::test]
    async fn scoped_dashboards_read_route_evidence_inside_tenant_boundary() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let runtime_response = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let runtime_status = runtime_response.status();
        let runtime_body = response_json(runtime_response).await;
        assert_eq!(runtime_status, StatusCode::OK, "{runtime_body:?}");
        store.record_route_decision(RouteDecisionRecord {
            route_decision_id: "rd_cross_tenant".to_owned(),
            tenant_id: "ten_other".to_owned(),
            organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
            project_id: Some(TEST_PROJECT_ID.to_owned()),
            principal_id: Some(TEST_USER_ID.to_owned()),
            api_key_id: None,
            actor_id: TEST_USER_ID.to_owned(),
            actor_kind: ActorKind::User,
            request_id: "req_cross_tenant".to_owned(),
            protocol_family: ProtocolFamily::OpenAiResponses,
            config_snapshot_id: None,
            config_version: None,
            model_alias_id: Some("ma_cross_tenant".to_owned()),
            alias_name: "gpt-test".to_owned(),
            route_policy_id: None,
            routing_group_id: None,
            model_target_id: None,
            provider_endpoint_id: None,
            upstream_credential_id: None,
            filtered_summary: Vec::new(),
            status: RouteDecisionStatus::Blocked,
            reason: "cross_tenant_probe".to_owned(),
            occurred_at: chrono::Utc::now(),
        });
        record_cross_tenant_usage_probe(&store);

        for (uri, schema, scope_kind, scope_id) in [
            (
                "/admin/v1/dashboards/tenant/overview",
                "gateway.admin.dashboard.tenant_overview.v1",
                "tenant",
                TEST_TENANT_ID,
            ),
            (
                "/admin/v1/dashboards/organizations/org_test",
                "gateway.admin.dashboard.organization_overview.v1",
                "organization",
                TEST_ORGANIZATION_ID,
            ),
            (
                "/admin/v1/dashboards/projects/prj_test",
                "gateway.admin.dashboard.project_overview.v1",
                "project",
                TEST_PROJECT_ID,
            ),
            (
                "/admin/v1/dashboards/project-members/pm_test",
                "gateway.admin.dashboard.project_member_overview.v1",
                "project_member",
                "pm_test",
            ),
        ] {
            let response = get_admin(store.clone(), &raw_session, uri).await;
            let status = response.status();
            let body = response_json(response).await;
            assert_eq!(status, StatusCode::OK, "{uri}: {body:?}");
            assert_eq!(body["schema"], schema);
            assert_eq!(body["scope"]["kind"], scope_kind);
            assert_eq!(body["scope"]["id"], scope_id);
            assert_eq!(body["measures"]["request_count"], 1);
            assert_eq!(body["measures"]["success_count"], 1);
            assert_eq!(body["measures"]["attempt_count"], 1);
            assert_eq!(body["measures"]["blocked_count"], 0);
            assert_eq!(body["measures"]["input_tokens"], 1);
            assert_eq!(body["measures"]["output_tokens"], 2);
            assert_eq!(body["measures"]["estimated_cost"], 0);
            assert_eq!(body["measures"]["usage_missing_count"], 0);
            assert_eq!(body["sources"]["route_evidence"], "durable");
            assert_eq!(
                body["sources"]["usage_ledger_rollups"],
                "durable_ledger_buckets"
            );
            assert!(body["freshness"]["partial_data"].as_bool().unwrap_or(false));
        }
    }

    #[tokio::test]
    async fn model_and_credential_dashboards_read_route_evidence_inside_tenant_boundary() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        let graph = create_admin_graph_for_dashboards(store.clone(), &raw_session).await;
        publish_catalog_snapshot(&store, catalog_payload_for_admin_graph(&graph));
        let runtime_response =
            post_responses_request(store.clone(), &raw_key, &graph.alias_name).await;
        let runtime_status = runtime_response.status();
        let runtime_body = response_json(runtime_response).await;
        assert_eq!(runtime_status, StatusCode::OK, "{runtime_body:?}");
        let api_key_id = recorded_api_key_id(&store);
        record_cross_tenant_dashboard_probe(&store, &graph, &api_key_id);

        for (uri, schema, scope_kind, scope_id) in [
            (
                format!("/admin/v1/dashboards/api-keys/{api_key_id}"),
                "gateway.admin.dashboard.api_key_overview.v1",
                "api_key",
                api_key_id.as_str(),
            ),
            (
                format!("/admin/v1/models/aliases/{}/dashboard", graph.alias_id),
                "gateway.admin.dashboard.model_alias_overview.v1",
                "model_alias",
                graph.alias_id.as_str(),
            ),
            (
                format!("/admin/v1/models/targets/{}/dashboard", graph.target_id),
                "gateway.admin.dashboard.model_target_overview.v1",
                "model_target",
                graph.target_id.as_str(),
            ),
            (
                format!(
                    "/admin/v1/provider-endpoints/{}/observability/usage",
                    graph.endpoint_id
                ),
                "gateway.admin.observability.provider_endpoint_usage.v1",
                "provider_endpoint",
                graph.endpoint_id.as_str(),
            ),
        ] {
            assert_dashboard_scope(
                store.clone(),
                &raw_session,
                &uri,
                schema,
                scope_kind,
                scope_id,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn request_id_header_is_preserved_when_safe() {
        let response = match router(AppState::default())
            .oneshot(
                Request::builder()
                    .uri("/version")
                    .header(REQUEST_ID_HEADER, "req_test")
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("version request should complete: {error}"),
        };

        let header = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok());
        assert_eq!(header, Some("req_test"));
    }

    #[test]
    fn authenticate_request_preserves_request_id_and_records_last_used() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        let state = AppState::new(GatewayConfig::default(), store.clone());
        let mut headers = HeaderMap::new();
        let authorization = HeaderValue::from_str(&format!("Bearer {raw_key}"))
            .unwrap_or_else(|error| panic!("authorization header should build: {error}"));
        headers.insert(header::AUTHORIZATION, authorization);
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("req_auth"));

        let actor = match authenticate_request(&state, &headers, chrono::Utc::now()) {
            Ok(actor) => actor,
            Err(error) => panic!("request should authenticate: {error}"),
        };

        let last_used_updates = store.api_key_last_used_updates();
        assert_eq!(actor.request_id, "req_auth");
        assert_eq!(last_used_updates.len(), 1);
        assert_eq!(last_used_updates[0].request_id, "req_auth");
        assert_eq!(last_used_updates[0].tenant_id, "ten_test");
    }

    #[test]
    fn authenticate_request_rejects_malformed_bearer_without_side_effects() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        let state = AppState::new(GatewayConfig::default(), store.clone());
        let mut headers = HeaderMap::new();
        let authorization = HeaderValue::from_str(&format!("Basic {raw_key}"))
            .unwrap_or_else(|error| panic!("authorization header should build: {error}"));
        headers.insert(header::AUTHORIZATION, authorization);
        headers.insert(REQUEST_ID_HEADER, HeaderValue::from_static("req_bad_auth"));

        let Err(error) = authenticate_request(&state, &headers, chrono::Utc::now()) else {
            panic!("malformed bearer should not authenticate");
        };

        assert!(matches!(error, GatewayError::Authentication));
        assert!(store.api_key_last_used_updates().is_empty());
        assert!(store.authorization_decisions().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_replays_every_foundation_protocol_over_http() {
        for case in foundation_route_replay_cases() {
            let (store, raw_key) = gateway_store_with_runtime_access(true);
            let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
                .oneshot(
                    Request::builder()
                        .method(case.method.clone())
                        .uri(case.ingress_path)
                        .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                        .header(REQUEST_ID_HEADER, "req_ingress")
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Body::from(json!({"model": "ma_test"}).to_string()))
                        .unwrap_or_else(|error| panic!("request should build: {error}")),
                )
                .await
            {
                Ok(response) => response,
                Err(error) => panic!("case {} request should complete: {error}", case.name),
            };

            let status = response.status();
            let body = response_json(response).await;
            let decisions = store.authorization_decisions();
            assert_eq!(
                decisions.len(),
                1,
                "case {} should record one authorization decision",
                case.name
            );
            assert_eq!(decisions[0].request_id, "req_ingress");

            if case.requires_native_grant {
                assert_eq!(status, StatusCode::FORBIDDEN, "case {}", case.name);
                assert_eq!(
                    body["error"]["code"], "gateway.auth.authorization_denied",
                    "case {}",
                    case.name
                );
                assert!(!decisions[0].allowed, "case {}", case.name);
                assert_eq!(decisions[0].reason, "native_route_grant_required");
            } else {
                assert_eq!(status, StatusCode::OK, "case {}", case.name);
                assert_eq!(
                    body["protocol_family"],
                    case.protocol_family.as_str(),
                    "case {}",
                    case.name
                );
                assert_eq!(body["authorization"]["allowed"], true, "case {}", case.name);
                assert_provider_shape(case.protocol_family, &body["body"]);
                assert!(decisions[0].allowed, "case {}", case.name);
            }
        }
    }

    #[tokio::test]
    async fn model_ingress_replays_catalog_routes_for_every_protocol_over_http() {
        for case in foundation_route_replay_cases() {
            let (store, raw_key) = gateway_store_with_runtime_access(false);
            publish_catalog_snapshot(&store, protocol_replay_catalog_payload());
            seed_protocol_replay_action_grants(&store);
            let response = post_replay_case_over_http(
                store.clone(),
                &raw_key,
                case,
                &protocol_replay_request_body(case),
            )
            .await;
            let status = response.status();
            let body = response_json(response).await;
            let route_decisions = store.route_decisions();
            let authorization_decisions = store.authorization_decisions();

            assert_eq!(route_decisions.len(), 1, "case {}", case.name);
            assert_eq!(
                route_decisions[0].status,
                RouteDecisionStatus::Selected,
                "case {}",
                case.name
            );
            assert_catalog_replay_route(case, &route_decisions[0]);
            assert_eq!(authorization_decisions.len(), 1, "case {}", case.name);

            if case.requires_native_grant {
                assert_catalog_replay_native_denial(case, status, &body, &store);
            } else {
                assert_catalog_replay_success(case, status, &body, &store);
            }
        }
    }

    #[tokio::test]
    async fn model_ingress_rejects_missing_api_key_before_authorization() {
        let (store, _) = gateway_store_with_runtime_access(true);
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"model": "ma_test"}).to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(store.authorization_decisions().is_empty());
        assert!(store.api_key_last_used_updates().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_authenticates_before_reading_invalid_body() {
        let (store, _) = gateway_store_with_runtime_access(true);
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"]["code"], "gateway.auth.authentication_failed");
        assert!(store.authorization_decisions().is_empty());
        assert!(store.api_key_last_used_updates().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_rejects_missing_action_grant_with_evidence() {
        let (store, raw_key) = gateway_store_with_runtime_access(false);
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"model": "ma_test"}).to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let status = response.status();
        let body = response_json(response).await;
        let decisions = store.authorization_decisions();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "gateway.auth.authorization_denied");
        assert_eq!(decisions.len(), 1);
        assert!(!decisions[0].allowed);
        assert_eq!(decisions[0].reason, "principal_action_not_granted");
    }

    #[tokio::test]
    async fn model_ingress_rejects_invalid_json_before_authorization() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from("{"))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(store.authorization_decisions().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_uses_published_catalog_alias_and_target() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        publish_catalog_snapshot(&store, catalog_payload());
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"model": "gpt-test"}).to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let response_request_id = response
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_else(|| panic!("response request id should be present"))
            .to_owned();
        let status = response.status();
        let body = response_json(response).await;
        let decisions = store.authorization_decisions();
        let route_decisions = store.route_decisions();
        let route_attempts = store.route_attempts();
        let last_used_updates = store.api_key_last_used_updates();
        let usage_events = store.usage_events_for_tenant(TEST_TENANT_ID);
        let ledger_buckets = store.ledger_buckets_for_tenant(TEST_TENANT_ID);
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["body"]["model"], "gpt-4.1-mini");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].resource_id, "ma_test");
        assert!(decisions[0].allowed);
        assert_eq!(route_decisions.len(), 1);
        assert_eq!(route_decisions[0].status, RouteDecisionStatus::Selected);
        assert_eq!(
            route_decisions[0].model_alias_id.as_deref(),
            Some("ma_test")
        );
        assert_eq!(
            route_decisions[0].model_target_id.as_deref(),
            Some("mt_openai")
        );
        assert_eq!(
            route_decisions[0].provider_endpoint_id.as_deref(),
            Some("pep_openai")
        );
        assert_eq!(route_attempts.len(), 1);
        assert_eq!(
            route_attempts[0].route_decision_id,
            route_decisions[0].route_decision_id
        );
        assert_eq!(route_attempts[0].status, RouteAttemptStatus::Completed);
        assert_eq!(last_used_updates.len(), 1);
        assert_eq!(last_used_updates[0].request_id, response_request_id);
        assert_eq!(route_decisions[0].request_id, response_request_id);
        assert_eq!(usage_events.len(), 1);
        assert_eq!(usage_events[0].request_id, response_request_id);
        assert_eq!(
            usage_events[0].route_decision_id.as_deref(),
            Some(route_decisions[0].route_decision_id.as_str())
        );
        assert_eq!(usage_events[0].usage_payload["input_tokens"], 1);
        assert_eq!(usage_events[0].usage_payload["output_tokens"], 2);
        assert_eq!(usage_events[0].usage_confidence, "exact");
        assert_eq!(
            usage_events[0].project_member_id.as_deref(),
            Some("pm_test")
        );
        assert_eq!(
            ledger_buckets
                .iter()
                .filter(|bucket| bucket.bucket_kind == "event")
                .map(|bucket| bucket.request_count)
                .sum::<i64>(),
            1
        );
        store.record_usage_event(usage_events[0].clone());
        assert_eq!(store.usage_events_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(
            store
                .ledger_buckets_for_tenant(TEST_TENANT_ID)
                .iter()
                .filter(|bucket| bucket.bucket_kind == "event")
                .map(|bucket| bucket.request_count)
                .sum::<i64>(),
            1
        );
    }

    #[tokio::test]
    async fn admin_usage_analytics_reads_events_timeseries_and_breakdowns() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let second = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);

        let summary = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/summary?scope_kind=project&scope_id=prj_test",
        )
        .await;
        let summary_status = summary.status();
        let summary_body = response_json(summary).await;
        let timeseries = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/timeseries?scope_kind=project&scope_id=prj_test&bucket_kind=day",
        )
        .await;
        let timeseries_status = timeseries.status();
        let timeseries_body = response_json(timeseries).await;
        let events = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/events?scope_kind=project&scope_id=prj_test&limit=1",
        )
        .await;
        let events_status = events.status();
        let events_body = response_json(events).await;
        let by_project = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/breakdown/by-project",
        )
        .await;
        let by_project_body = response_json(by_project).await;
        let by_project_member = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/breakdown/by-project-member?scope_kind=project&scope_id=prj_test",
        )
        .await;
        let by_project_member_body = response_json(by_project_member).await;
        let by_model = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/breakdown/by-model?scope_kind=project&scope_id=prj_test",
        )
        .await;
        let by_model_body = response_json(by_model).await;
        let by_endpoint = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/usage/breakdown/by-provider-endpoint?scope_kind=project&scope_id=prj_test",
        )
        .await;
        let by_endpoint_body = response_json(by_endpoint).await;
        let invalid = get_admin(
            store,
            &raw_session,
            "/admin/v1/usage/events?scope_kind=project&scope_id=prj_test&limit=201",
        )
        .await;

        assert_eq!(summary_status, StatusCode::OK);
        assert_eq!(summary_body["schema"], "gateway.admin.usage_summary.v1");
        assert_eq!(summary_body["scope"]["kind"], "project");
        assert_eq!(summary_body["measures"]["request_count"], 2);
        assert_eq!(summary_body["measures"]["input_tokens"], 2);
        assert_eq!(summary_body["measures"]["output_tokens"], 4);
        assert_eq!(summary_body["sources"]["metrics_backend_queried"], false);
        assert_eq!(timeseries_status, StatusCode::OK);
        assert_eq!(timeseries_body["bucket_kind"], "day");
        assert_eq!(timeseries_body["points"][0]["measures"]["request_count"], 2);
        assert_eq!(events_status, StatusCode::OK);
        assert_eq!(events_body["events"].as_array().map_or(0, Vec::len), 1);
        assert!(events_body["next_cursor"].as_str().is_some());
        assert_eq!(events_body["events"][0]["project_member_id"], "pm_test");
        assert_eq!(
            events_body["events"][0]["protocol_family"],
            "openai_responses"
        );
        assert!(events_body["events"][0]
            .as_object()
            .is_some_and(|event| !event.contains_key("upstream_credential_id")));
        assert_eq!(by_project_body["rows"][0]["group_id"], "prj_test");
        assert_eq!(by_project_member_body["rows"][0]["group_id"], "pm_test");
        assert_eq!(by_model_body["rows"][0]["group_kind"], "model_alias");
        assert_eq!(by_model_body["rows"][0]["group_id"], "ma_test");
        assert_eq!(by_endpoint_body["rows"][0]["group_id"], "pep_openai");
        assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn admin_export_jobs_create_usage_manifest_with_pagination() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let second = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(second.status(), StatusCode::OK);

        let api_key_attempt = post_admin_json_with_bearer(
            store.clone(),
            &raw_key,
            "/admin/v1/exports/jobs",
            json!({
                "idempotency_key": "idem_usage_export_api_key_denied",
                "export_kind": "usage",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID
            }),
        )
        .await;
        assert_eq!(api_key_attempt.status(), StatusCode::FORBIDDEN);

        let usage_export = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/exports/jobs",
            json!({
                "idempotency_key": "idem_usage_export",
                "export_kind": "usage",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "limit": 1,
                "retention_days": 7
            }),
        )
        .await;
        let usage_status = usage_export.status();
        let usage_body = response_json(usage_export).await;
        assert_eq!(usage_status, StatusCode::OK, "{usage_body:?}");
        assert_usage_export_manifest_body(&usage_body);

        let usage_job_id = usage_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("usage export job id should be present"))
            .to_owned();
        let usage_manifest_id = usage_body["manifest"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("usage export manifest id should be present"))
            .to_owned();
        let replay = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/exports/jobs",
            json!({
                "idempotency_key": "idem_usage_export",
                "export_kind": "usage",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "limit": 1,
                "retention_days": 7
            }),
        )
        .await;
        let replay_body = response_json(replay).await;
        assert_eq!(replay_body["idempotency_replayed"], true);
        assert_eq!(replay_body["resource"]["id"], usage_job_id);

        let list = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/exports/jobs?limit=1",
        )
        .await;
        let list_body = response_json(list).await;
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        let get_job = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/exports/jobs/{usage_job_id}"),
        )
        .await;
        let get_job_body = response_json(get_job).await;
        assert_eq!(get_job_body["resource"]["manifest_id"], usage_manifest_id);
        let get_manifest = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/exports/jobs/{usage_job_id}/manifest"),
        )
        .await;
        let get_manifest_body = response_json(get_manifest).await;
        assert_eq!(get_manifest_body["resource"]["id"], usage_manifest_id);
    }

    #[tokio::test]
    async fn admin_export_jobs_create_audit_manifest_with_redaction() {
        let (store, raw_session, _) = gateway_store_with_admin_session_and_runtime_access();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;
        let audit_export = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/exports/jobs",
            json!({
                "idempotency_key": "idem_audit_export",
                "export_kind": "audit",
                "scope_kind": "tenant",
                "scope_id": TEST_TENANT_ID,
                "limit": 10,
                "retention_days": 30
            }),
        )
        .await;
        let audit_status = audit_export.status();
        let audit_body = response_json(audit_export).await;
        assert_eq!(audit_status, StatusCode::OK, "{audit_body:?}");
        assert_eq!(audit_body["resource"]["export_kind"], "audit");
        assert!(audit_body["manifest"]["record_count"].as_i64().unwrap_or(0) >= 1);
        assert!(audit_body["manifest"]["manifest"]["rows"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["kind"] == "audit_event")));
        let audit_text = audit_body.to_string();
        assert!(!audit_text.contains("sec_openai"));
    }

    #[tokio::test]
    async fn admin_emergency_disable_provider_endpoint_is_strong_auth_idempotent_and_audited() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let expires_at = (chrono::Utc::now() + Duration::minutes(30)).to_rfc3339();

        let denied = post_admin_json_with_bearer(
            store.clone(),
            &raw_key,
            &format!("/admin/v1/emergency/provider-endpoints/{endpoint_id}/disable"),
            json!({
                "idempotency_key": "idem_emergency_endpoint_api_key_denied",
                "expected_version": 1,
                "reason": "Provider incident.",
                "expires_at": expires_at
            }),
        )
        .await;
        let denied_status = denied.status();
        let denied_body = response_json(denied).await;
        assert_eq!(denied_status, StatusCode::FORBIDDEN, "{denied_body:?}");

        let request = json!({
            "idempotency_key": "idem_emergency_endpoint_disable",
            "expected_version": 1,
            "reason": "Provider incident.",
            "expires_at": expires_at
        });
        let first = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/emergency/provider-endpoints/{endpoint_id}/disable"),
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/emergency/provider-endpoints/{endpoint_id}/disable"),
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let operation_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("emergency operation id should be present"))
            .to_owned();

        assert_eq!(first_status, StatusCode::OK, "{first_body:?}");
        assert_eq!(second_status, StatusCode::OK, "{second_body:?}");
        assert_eq!(
            first_body["resource"]["operation_kind"],
            "disable_provider_endpoint"
        );
        assert_eq!(first_body["resource"]["target_resource_id"], endpoint_id);
        assert_eq!(first_body["affected_resource"]["status"], "disabled");
        assert_eq!(first_body["affected_resource"]["version"], 2);
        assert_eq!(
            first_body["resource"]["operator_alert"]["alert_required"],
            true
        );
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(second_body["resource"]["id"], operation_id);
        assert_eq!(
            store
                .provider_endpoint(&endpoint_id)
                .unwrap_or_else(|| panic!("provider endpoint should exist"))
                .status,
            ResourceStatus::Disabled
        );

        let list = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/emergency/operations?operation_kind=disable_provider_endpoint&limit=1",
        )
        .await;
        let list_body = response_json(list).await;
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/emergency/operations/{operation_id}"),
        )
        .await;
        let get_body = response_json(get).await;
        assert_eq!(get_body["resource"]["id"], operation_id);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.emergency.disable"
        );
        assert_eq!(store.audit_events()[1].resource_kind, "EmergencyOperation");
    }

    #[tokio::test]
    async fn admin_emergency_disable_credential_and_drain_routing_group() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;
        let routing_group_id = create_routing_group_over_http(store.clone(), &raw_session).await;
        let expires_at = (chrono::Utc::now() + Duration::minutes(30)).to_rfc3339();

        let disable_credential = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/emergency/upstream-credentials/{credential_id}/disable"),
            json!({
                "idempotency_key": "idem_emergency_credential_disable",
                "expected_version": 1,
                "reason": "Credential leak.",
                "expires_at": expires_at
            }),
        )
        .await;
        let disable_status = disable_credential.status();
        let disable_body = response_json(disable_credential).await;
        let drain_group = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/emergency/routing-groups/{routing_group_id}/drain"),
            json!({
                "idempotency_key": "idem_emergency_group_drain",
                "expected_version": 1,
                "reason": "Provider outage.",
                "expires_at": expires_at
            }),
        )
        .await;
        let drain_status = drain_group.status();
        let drain_body = response_json(drain_group).await;

        assert_eq!(disable_status, StatusCode::OK, "{disable_body:?}");
        assert_eq!(drain_status, StatusCode::OK, "{drain_body:?}");
        assert_eq!(
            disable_body["resource"]["operation_kind"],
            "disable_upstream_credential"
        );
        assert_eq!(disable_body["affected_resource"]["status"], "disabled");
        assert_eq!(
            drain_body["resource"]["operation_kind"],
            "drain_routing_group"
        );
        assert_eq!(drain_body["affected_resource"]["status"], "draining");
        assert_eq!(
            store
                .upstream_credential(&credential_id)
                .unwrap_or_else(|| panic!("upstream credential should exist"))
                .status,
            UpstreamCredentialStatus::Disabled
        );
        assert_eq!(
            store
                .routing_group(&routing_group_id)
                .unwrap_or_else(|| panic!("routing group should exist"))
                .status,
            ResourceStatus::Draining
        );
        let operations = get_admin(store, &raw_session, "/admin/v1/emergency/operations").await;
        let operations_body = response_json(operations).await;
        assert_eq!(
            operations_body["resources"].as_array().map_or(0, Vec::len),
            2
        );
    }

    #[tokio::test]
    async fn admin_emergency_freeze_config_blocks_non_emergency_mutations() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let expires_at = (chrono::Utc::now() + Duration::minutes(30)).to_rfc3339();

        let freeze = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/emergency/config/freeze",
            json!({
                "idempotency_key": "idem_emergency_config_freeze",
                "reason": "Investigate unsafe config publication.",
                "expires_at": expires_at
            }),
        )
        .await;
        let freeze_status = freeze.status();
        let freeze_body = response_json(freeze).await;
        assert_eq!(freeze_status, StatusCode::OK, "{freeze_body:?}");
        assert_eq!(freeze_body["resource"]["operation_kind"], "freeze_config");
        assert_eq!(freeze_body["affected_resource"]["status"], "frozen");

        let blocked = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-endpoints",
            json!({
                "idempotency_key": "idem_provider_endpoint_during_freeze",
                "organization_id": TEST_ORGANIZATION_ID,
                "provider_kind": "openai",
                "display_name": "Blocked endpoint",
                "protocol_families": ["openai_responses"],
                "upstream_base_url": "https://api.openai.example"
            }),
        )
        .await;
        let blocked_status = blocked.status();
        let blocked_body = response_json(blocked).await;
        assert_eq!(blocked_status, StatusCode::BAD_REQUEST, "{blocked_body:?}");
        assert!(blocked_body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("config_frozen")));

        let emergency_after_freeze = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/emergency/provider-endpoints/{endpoint_id}/disable"),
            json!({
                "idempotency_key": "idem_emergency_endpoint_after_freeze",
                "expected_version": 1,
                "reason": "Disable during freeze.",
                "expires_at": expires_at
            }),
        )
        .await;
        let emergency_status = emergency_after_freeze.status();
        let emergency_body = response_json(emergency_after_freeze).await;
        assert_eq!(emergency_status, StatusCode::OK, "{emergency_body:?}");
        assert_eq!(
            emergency_body["resource"]["operation_kind"],
            "disable_provider_endpoint"
        );
    }

    #[tokio::test]
    async fn model_ingress_blocks_after_project_request_budget_hard_limit() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let create_policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/budget-policies",
            json!({
                "idempotency_key": "idem_runtime_project_budget",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "period": "calendar_month",
                "limit_kind": "requests",
                "hard_limit": 1,
                "reset_policy": "calendar_month",
                "overage_mode": "block_new_requests",
                "consistency_mode": "eventual"
            }),
        )
        .await;
        assert_eq!(create_policy.status(), StatusCode::OK);

        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        assert_eq!(first_status, StatusCode::OK, "{first_body:?}");

        let second = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second_body["error"]["code"], "gateway.budget.exceeded");
        assert_eq!(store.usage_events_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.route_attempts().len(), 1);
        assert!(store.route_decisions().iter().any(|decision| {
            decision.status == RouteDecisionStatus::Blocked && decision.reason == "budget_exceeded"
        }));
    }

    #[tokio::test]
    async fn runtime_request_budget_reservation_blocks_overlapping_preflight() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let create_policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/budget-policies",
            json!({
                "idempotency_key": "idem_runtime_project_budget_reservation",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "period": "calendar_month",
                "limit_kind": "requests",
                "hard_limit": 1,
                "reset_policy": "calendar_month",
                "overage_mode": "block_new_requests",
                "consistency_mode": "strong_terminal"
            }),
        )
        .await;
        assert_eq!(create_policy.status(), StatusCode::OK);
        let now = chrono::Utc::now();
        let state = AppState::new(GatewayConfig::default(), store.clone());
        let actor = verify_api_key(&store, &raw_key, "req_budget_reservation_1".to_owned(), now)
            .unwrap_or_else(|error| panic!("api key should verify: {error}"));
        let replay_cases = foundation_route_replay_cases();
        let replay_case = replay_cases
            .iter()
            .find(|case| case.protocol_family == ProtocolFamily::OpenAiResponses && !case.streaming)
            .unwrap_or_else(|| panic!("openai responses replay case should exist"));
        let route_target = runtime_route_target(&state, &actor, replay_case, "gpt-test")
            .unwrap_or_else(|error| panic!("route target should resolve: {error}"));
        let selected = route_target
            .selected_route
            .as_ref()
            .unwrap_or_else(|| panic!("route should be selected"));
        let policy = store
            .budget_policies_for_tenant(TEST_TENANT_ID)
            .into_iter()
            .find(|policy| policy.limit_kind == "requests")
            .unwrap_or_else(|| panic!("budget policy should exist"));
        let reservation_key = runtime_budget_reservation_key(&policy, now);

        let first =
            enforce_runtime_policy_preflight(&state, &actor, replay_case, Some(selected), 32, now)
                .unwrap_or_else(|error| panic!("first preflight should reserve: {error}"));
        let second =
            enforce_runtime_policy_preflight(&state, &actor, replay_case, Some(selected), 32, now);

        assert!(matches!(
            second,
            Err(GatewayError::BudgetExceeded {
                reason: "hard_limit_reserved"
            })
        ));
        assert_eq!(store.runtime_policy_counter(&reservation_key), 1);
        release_runtime_policy_reservations(&state, &first);
        assert_eq!(store.runtime_policy_counter(&reservation_key), 0);

        let third =
            enforce_runtime_policy_preflight(&state, &actor, replay_case, Some(selected), 32, now)
                .unwrap_or_else(|error| panic!("released reservation should free budget: {error}"));
        release_runtime_policy_reservations(&state, &third);
    }

    #[tokio::test]
    async fn runtime_concurrent_request_quota_reservation_blocks_overlapping_preflight() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let create_policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            json!({
                "idempotency_key": "idem_runtime_concurrent_request_quota",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "counter_kind": "concurrent_request",
                "limit": 1,
                "window": "request_lifetime",
                "increment_source": "preflight_acquire",
                "loss_behavior": "fail_closed"
            }),
        )
        .await;
        assert_eq!(create_policy.status(), StatusCode::OK);
        let now = chrono::Utc::now();
        let state = AppState::new(GatewayConfig::default(), store.clone());
        let actor = verify_api_key(&store, &raw_key, "req_quota_reservation_1".to_owned(), now)
            .unwrap_or_else(|error| panic!("api key should verify: {error}"));
        let replay_cases = foundation_route_replay_cases();
        let replay_case = replay_cases
            .iter()
            .find(|case| case.protocol_family == ProtocolFamily::OpenAiResponses && !case.streaming)
            .unwrap_or_else(|| panic!("openai responses replay case should exist"));
        let route_target = runtime_route_target(&state, &actor, replay_case, "gpt-test")
            .unwrap_or_else(|error| panic!("route target should resolve: {error}"));
        let selected = route_target
            .selected_route
            .as_ref()
            .unwrap_or_else(|| panic!("route should be selected"));
        let policy = store
            .quota_policies_for_tenant(TEST_TENANT_ID)
            .into_iter()
            .find(|policy| policy.counter_kind == "concurrent_request")
            .unwrap_or_else(|| panic!("quota policy should exist"));
        let reservation_key = runtime_quota_counter_key(&policy, now);

        let first =
            enforce_runtime_policy_preflight(&state, &actor, replay_case, Some(selected), 32, now)
                .unwrap_or_else(|error| panic!("first preflight should reserve: {error}"));
        let second =
            enforce_runtime_policy_preflight(&state, &actor, replay_case, Some(selected), 32, now);

        assert!(matches!(
            second,
            Err(GatewayError::QuotaExceeded {
                reason: "concurrent_request_limit_reached"
            })
        ));
        assert_eq!(store.runtime_policy_counter(&reservation_key), 1);
        release_runtime_policy_reservations(&state, &first);
        assert_eq!(store.runtime_policy_counter(&reservation_key), 0);

        let third =
            enforce_runtime_policy_preflight(&state, &actor, replay_case, Some(selected), 32, now)
                .unwrap_or_else(|error| panic!("released reservation should free quota: {error}"));
        release_runtime_policy_reservations(&state, &third);
    }

    #[tokio::test]
    async fn model_ingress_blocks_after_project_request_rate_quota_limit() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let create_policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            json!({
                "idempotency_key": "idem_runtime_project_quota",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "counter_kind": "request_rate",
                "limit": 1,
                "window": "fixed",
                "increment_source": "accepted_preflight_request",
                "loss_behavior": "fail_closed"
            }),
        )
        .await;
        assert_eq!(create_policy.status(), StatusCode::OK);
        wait_for_quota_fixed_window_margin().await;

        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        assert_eq!(first_status, StatusCode::OK, "{first_body:?}");

        let second = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second_body["error"]["code"], "gateway.quota.exceeded");
        assert_eq!(second_body["error"]["retryable"], true);
        assert_eq!(store.usage_events_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.route_attempts().len(), 1);
        assert!(store.route_decisions().iter().any(|decision| {
            decision.status == RouteDecisionStatus::Blocked && decision.reason == "quota_exceeded"
        }));
    }

    #[tokio::test]
    async fn model_ingress_blocks_after_terminal_token_actual_rate_limit() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let create_policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            json!({
                "idempotency_key": "idem_runtime_token_actual_quota",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "counter_kind": "token_actual_rate",
                "limit": 3,
                "window": "ledger_bucket",
                "increment_source": "terminal_usage_event",
                "loss_behavior": "fail_closed"
            }),
        )
        .await;
        assert_eq!(create_policy.status(), StatusCode::OK);

        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        assert_eq!(first_status, StatusCode::OK, "{first_body:?}");

        let policy = store
            .quota_policies_for_tenant(TEST_TENANT_ID)
            .into_iter()
            .find(|policy| policy.counter_kind == "token_actual_rate")
            .unwrap_or_else(|| panic!("quota policy should exist"));
        let counter_key = runtime_quota_counter_key(&policy, chrono::Utc::now());
        assert_eq!(store.runtime_policy_counter(&counter_key), 3);

        let second = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        assert_eq!(second_status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(second_body["error"]["code"], "gateway.quota.exceeded");
        assert_eq!(store.usage_events_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.route_attempts().len(), 1);
        assert!(store.route_decisions().iter().any(|decision| {
            decision.status == RouteDecisionStatus::Blocked && decision.reason == "quota_exceeded"
        }));
    }

    #[tokio::test]
    async fn model_ingress_blocks_request_body_bytes_quota_before_usage() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let create_policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            json!({
                "idempotency_key": "idem_runtime_body_quota",
                "scope_kind": "protocol_family",
                "scope_id": "openai_responses",
                "counter_kind": "request_body_bytes",
                "limit": 8,
                "window": "fixed",
                "increment_source": "request_body_bytes",
                "loss_behavior": "fail_closed"
            }),
        )
        .await;
        assert_eq!(create_policy.status(), StatusCode::OK);

        let response = post_responses_request_with_body(
            store.clone(),
            &raw_key,
            json!({
                "model": "gpt-test",
                "input": "this request body is larger than the quota"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "gateway.quota.exceeded");
        assert!(store.usage_events_for_tenant(TEST_TENANT_ID).is_empty());
        assert!(store.route_attempts().is_empty());
        assert!(store.route_decisions().iter().any(|decision| {
            decision.status == RouteDecisionStatus::Blocked && decision.reason == "quota_exceeded"
        }));
    }

    #[tokio::test]
    async fn model_ingress_uses_cedar_policy_from_published_snapshot() {
        let (store, raw_key) = gateway_store_with_runtime_access(false);
        publish_catalog_snapshot(
            &store,
            catalog_payload_with_cedar_policy(
                r#"
                permit (
                    principal is Gateway::ApiKey,
                    action == Gateway::Action::"gateway.model.invoke",
                    resource is Gateway::ModelAlias
                );
                "#,
            ),
        );

        let response = post_responses_request(store.clone(), &raw_key, "gpt-test").await;

        let status = response.status();
        let body = response_json(response).await;
        let decisions = store.authorization_decisions();
        let snapshots = store.config_snapshots();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["body"]["model"], "gpt-4.1-mini");
        assert_eq!(decisions.len(), 1);
        assert!(decisions[0].allowed);
        assert_eq!(
            decisions[0].policy_snapshot_id.as_deref(),
            Some(snapshots[0].metadata.snapshot_id.as_str())
        );
    }

    #[tokio::test]
    async fn model_ingress_denies_with_cedar_policy_from_published_snapshot() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        publish_catalog_snapshot(
            &store,
            catalog_payload_with_cedar_policy(
                r#"
                permit (
                    principal is Gateway::ApiKey,
                    action == Gateway::Action::"gateway.model.invoke",
                    resource == Gateway::ModelAlias::"ma_other"
                );
                "#,
            ),
        );

        let response = post_responses_request(store.clone(), &raw_key, "gpt-test").await;

        let status = response.status();
        let body = response_json(response).await;
        let decisions = store.authorization_decisions();
        let snapshots = store.config_snapshots();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "gateway.auth.authorization_denied");
        assert_eq!(decisions.len(), 1);
        assert!(!decisions[0].allowed);
        assert_eq!(decisions[0].reason, "cedar_policy_denied");
        assert_eq!(
            decisions[0].policy_snapshot_id.as_deref(),
            Some(snapshots[0].metadata.snapshot_id.as_str())
        );
        assert!(store.route_attempts().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_rejects_catalog_protocol_mismatch_before_authorization() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        publish_catalog_snapshot(&store, catalog_payload());
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"model": "gpt-test"}).to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("protocol_mismatch")));
        assert!(store.authorization_decisions().is_empty());
        assert!(store.route_decisions().is_empty());
        assert!(store.route_attempts().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_records_blocked_route_when_provider_grant_denies() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        let mut payload = catalog_payload();
        payload["provider_grants"] = json!([]);
        publish_catalog_snapshot(&store, payload);
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"model": "gpt-test"}).to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let body = response_json(response).await;
        let route_decisions = store.route_decisions();
        assert_eq!(body["error"]["code"], "gateway.auth.authorization_denied");
        assert_eq!(route_decisions.len(), 1);
        assert_eq!(route_decisions[0].status, RouteDecisionStatus::Blocked);
        assert_eq!(route_decisions[0].reason, "provider_grant_denied");
        assert_eq!(
            route_decisions[0].filtered_summary[0].reason,
            RouteFilterReason::ProviderGrantDenied
        );
        assert!(store.authorization_decisions().is_empty());
        assert!(store.route_attempts().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_records_no_route_when_targets_are_filtered() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        let mut payload = catalog_payload();
        payload["model_targets"][0]["status"] = json!("disabled");
        publish_catalog_snapshot(&store, payload);
        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"model": "gpt-test"}).to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let body = response_json(response).await;
        let route_decisions = store.route_decisions();
        assert_eq!(body["error"]["code"], "gateway.route.no_route");
        assert_eq!(route_decisions.len(), 1);
        assert_eq!(route_decisions[0].status, RouteDecisionStatus::NoRoute);
        assert_eq!(route_decisions[0].reason, "no_eligible_model_target");
        assert_eq!(
            route_decisions[0].filtered_summary[0].reason,
            RouteFilterReason::TargetInactive
        );
        assert!(store.authorization_decisions().is_empty());
        assert!(store.route_attempts().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_filters_fresh_endpoint_drain_hot_state() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        publish_catalog_snapshot(&store, catalog_payload());
        let now = chrono::Utc::now();
        store.set_endpoint_drain(EndpointDrainRecord {
            tenant_id: "ten_test".to_owned(),
            provider_endpoint_id: "pep_openai".to_owned(),
            config_version: 1,
            reason: "maintenance".to_owned(),
            created_at: now,
            expires_at: now + Duration::seconds(60),
        });

        let response = post_responses_request(store.clone(), &raw_key, "gpt-test").await;

        let status = response.status();
        let body = response_json(response).await;
        let route_decisions = store.route_decisions();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "gateway.route.no_route");
        assert_eq!(route_decisions.len(), 1);
        assert_eq!(route_decisions[0].status, RouteDecisionStatus::NoRoute);
        assert_eq!(
            route_decisions[0].filtered_summary[0].reason,
            RouteFilterReason::EndpointDrained
        );
        assert!(store.authorization_decisions().is_empty());
        assert!(store.route_attempts().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_filters_blocked_endpoint_health_hot_state() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        publish_catalog_snapshot(&store, catalog_payload());
        let now = chrono::Utc::now();
        store.set_endpoint_health(EndpointHealthRecord {
            tenant_id: "ten_test".to_owned(),
            provider_endpoint_id: "pep_openai".to_owned(),
            config_version: 1,
            state: EndpointHealthState::Blocked,
            observed_at: now,
            expires_at: now + Duration::seconds(60),
        });

        let response = post_responses_request(store.clone(), &raw_key, "gpt-test").await;

        let status = response.status();
        let body = response_json(response).await;
        let route_decisions = store.route_decisions();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["error"]["code"], "gateway.route.no_route");
        assert_eq!(route_decisions.len(), 1);
        assert_eq!(route_decisions[0].status, RouteDecisionStatus::NoRoute);
        assert_eq!(
            route_decisions[0].filtered_summary[0].reason,
            RouteFilterReason::EndpointHealthBlocked
        );
        assert!(store.authorization_decisions().is_empty());
        assert!(store.route_attempts().is_empty());
    }

    #[tokio::test]
    async fn model_ingress_ignores_hot_state_from_stale_config_version() {
        let (store, raw_key) = gateway_store_with_runtime_access(true);
        publish_catalog_snapshot(&store, catalog_payload());
        let now = chrono::Utc::now();
        store.set_endpoint_drain(EndpointDrainRecord {
            tenant_id: "ten_test".to_owned(),
            provider_endpoint_id: "pep_openai".to_owned(),
            config_version: 0,
            reason: "old_maintenance".to_owned(),
            created_at: now,
            expires_at: now + Duration::seconds(60),
        });
        store.set_endpoint_health(EndpointHealthRecord {
            tenant_id: "ten_test".to_owned(),
            provider_endpoint_id: "pep_openai".to_owned(),
            config_version: 0,
            state: EndpointHealthState::Unhealthy,
            observed_at: now,
            expires_at: now + Duration::seconds(60),
        });

        let response = post_responses_request(store.clone(), &raw_key, "gpt-test").await;

        let status = response.status();
        let body = response_json(response).await;
        let route_decisions = store.route_decisions();
        let route_attempts = store.route_attempts();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["body"]["model"], "gpt-4.1-mini");
        assert_eq!(route_decisions.len(), 1);
        assert_eq!(route_decisions[0].status, RouteDecisionStatus::Selected);
        assert!(route_decisions[0].filtered_summary.is_empty());
        assert_eq!(route_attempts.len(), 1);
        assert_eq!(store.authorization_decisions().len(), 1);
    }

    #[tokio::test]
    async fn admin_publish_config_snapshot_rejects_api_key_strong_auth() {
        let (store, raw_key) = gateway_store_with_runtime_access(false);
        seed_tenant_owner_grants(&store);

        let response = match router(AppState::new(GatewayConfig::default(), store.clone()))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/admin/v1/config/snapshots:publish")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({
                            "idempotency_key": "idem_publish_api_key",
                            "resource_versions": [],
                            "payload": {"resources": []}
                        })
                        .to_string(),
                    ))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        };

        let status = response.status();
        let body = response_json(response).await;
        let decisions = store.authorization_decisions();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"]["code"], "gateway.auth.authorization_denied");
        assert_eq!(decisions.len(), 1);
        assert_eq!(decisions[0].reason, "api_key_not_allowed_for_route");
        assert!(store.config_snapshots().is_empty());
    }

    #[tokio::test]
    async fn admin_publish_config_snapshot_is_idempotent_and_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_publish_snapshot",
            "resource_versions": [{
                "resource_kind": "ModelAlias",
                "resource_id": "ma_test",
                "version": 1
            }],
            "payload": {"resources": []}
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/config/snapshots:publish",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/config/snapshots:publish",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first_body["snapshot"]["metadata"]["version"], 1);
        assert_eq!(
            first_body["snapshot"]["metadata"]["snapshot_id"],
            second_body["snapshot"]["metadata"]["snapshot_id"]
        );
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(store.config_snapshots().len(), 1);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(store.audit_events()[0].event_type, "gateway.config.publish");
        assert_eq!(store.authorization_decisions().len(), 2);
        assert!(store
            .authorization_decisions()
            .iter()
            .all(|decision| decision.allowed));
    }

    #[tokio::test]
    async fn admin_rollback_config_snapshot_publishes_new_version() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let original = match publish_config_snapshot(
            &store,
            PublishConfigSnapshotRequest {
                tenant_id: TEST_TENANT_ID.to_owned(),
                resource_versions: Vec::new(),
                payload: json!({"resources": [{"kind": "model_alias", "id": "ma_test"}]}),
                created_by: TEST_USER_ID.to_owned(),
            },
            chrono::Utc::now(),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("snapshot should publish: {error}"),
        };

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/config/snapshots:rollback",
            json!({
                "idempotency_key": "idem_rollback_snapshot",
                "source_snapshot_id": original.metadata.snapshot_id,
                "reason": "Restore known good routing config."
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        let snapshots = store.config_snapshots();
        let audit_events = store.audit_events();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["snapshot"]["metadata"]["version"], 2);
        assert_eq!(
            body["snapshot"]["document"]["rollback_of"],
            original.metadata.snapshot_id
        );
        assert_eq!(snapshots.len(), 2);
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].event_type, "gateway.config.rollback");
        assert_eq!(audit_events[0].before_version, Some(1));
        assert_eq!(audit_events[0].after_version, Some(2));
    }

    #[tokio::test]
    async fn admin_validate_config_snapshot_reports_errors_without_publishing() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/config/snapshots:validate",
            json!({
                "payload": {
                    "cedar_policy_bundle": "permit (principal, action == Gateway::Action::\"gateway.unknown\", resource);"
                }
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert!(body["validation_id"]
            .as_str()
            .is_some_and(|validation_id| validation_id.starts_with("vdiag_")));
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 1);
        let validation_id = body["validation_id"]
            .as_str()
            .unwrap_or_else(|| panic!("validation id should be present"));
        let diagnostics = store.validation_diagnostics_for_tenant(TEST_TENANT_ID);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].validation_id, validation_id);
        assert_eq!(diagnostics[0].resource_kind, "ConfigSnapshot");
        assert_eq!(diagnostics[0].scope_kind, "tenant");
        assert_eq!(diagnostics[0].scope_id, TEST_TENANT_ID);
        assert!(!diagnostics[0].valid);
        assert_eq!(diagnostics[0].errors.as_array().map_or(0, Vec::len), 1);
        assert!(store.config_snapshots().is_empty());
        assert!(store.audit_events().is_empty());
        assert_eq!(store.authorization_decisions().len(), 1);
    }

    #[tokio::test]
    async fn admin_validation_diagnostics_list_and_realtime_summary_are_tenant_scoped() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let now = chrono::Utc::now();
        store.record_validation_diagnostic(ValidationDiagnosticRecord {
            validation_id: "vdiag_other".to_owned(),
            tenant_id: "ten_other".to_owned(),
            organization_id: Some("org_other".to_owned()),
            project_id: Some("prj_other".to_owned()),
            resource_kind: "ConfigSnapshot".to_owned(),
            scope_kind: "tenant".to_owned(),
            scope_id: "ten_other".to_owned(),
            valid: false,
            errors: json!([{"field": "tenant_id", "reason": "other_tenant"}]),
            warnings: json!([]),
            affected_resources: json!([]),
            publication_plan: None,
            route_simulation: None,
            budget_simulation: None,
            created_by: TEST_USER_ID.to_owned(),
            created_at: now - Duration::seconds(30),
        });

        let validation_response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-endpoints:validate",
            json!({
                "idempotency_key": "idem_provider_endpoint_validation_diagnostic",
                "organization_id": TEST_ORGANIZATION_ID,
                "provider_kind": "",
                "display_name": "",
                "protocol_families": [],
                "upstream_base_url": "http://bad host"
            }),
        )
        .await;
        let validation_status = validation_response.status();
        let validation_body = response_json(validation_response).await;
        let validation_id = validation_body["validation_id"]
            .as_str()
            .unwrap_or_else(|| panic!("validation id should be present"))
            .to_owned();

        let diagnostics_response = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/config/validation-diagnostics",
        )
        .await;
        let diagnostics_status = diagnostics_response.status();
        let diagnostics_body = response_json(diagnostics_response).await;
        let diagnostics = diagnostics_body["diagnostics"]
            .as_array()
            .unwrap_or_else(|| panic!("diagnostics should be an array"));
        let overview_response = get_admin(store, &raw_session, "/admin/v1/realtime/overview").await;
        let overview_status = overview_response.status();
        let overview_body = response_json(overview_response).await;

        assert_eq!(validation_status, StatusCode::OK);
        assert_eq!(
            validation_body["schema"],
            "gateway.admin.provider_endpoint_validation.v1"
        );
        assert_eq!(validation_body["valid"], false);
        assert_eq!(validation_body["errors"].as_array().map_or(0, Vec::len), 4);
        assert_eq!(diagnostics_status, StatusCode::OK);
        assert_eq!(
            diagnostics_body["schema"],
            "gateway.admin.config_validation_diagnostic_list.v1"
        );
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0]["validation_id"], validation_id);
        assert_eq!(diagnostics[0]["tenant_id"], TEST_TENANT_ID);
        assert_eq!(diagnostics[0]["resource_kind"], "ProviderEndpoint");
        assert_eq!(diagnostics[0]["valid"], false);
        assert_eq!(overview_status, StatusCode::OK);
        assert_eq!(overview_body["validation"]["diagnostic_count"], 1);
        assert_eq!(overview_body["validation"]["failed_count"], 1);
        assert_eq!(
            overview_body["validation"]["latest_validation_id"],
            validation_body["validation_id"]
        );
        assert_eq!(
            overview_body["validation"]["source"],
            "durable_validation_diagnostics"
        );
    }

    #[tokio::test]
    async fn admin_list_and_get_config_snapshots_are_tenant_scoped() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let snapshot = match publish_config_snapshot(
            &store,
            PublishConfigSnapshotRequest {
                tenant_id: TEST_TENANT_ID.to_owned(),
                resource_versions: Vec::new(),
                payload: json!({"resources": []}),
                created_by: TEST_USER_ID.to_owned(),
            },
            chrono::Utc::now(),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("snapshot should publish: {error}"),
        };

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/config/snapshots").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/config/snapshots/{}",
                snapshot.metadata.snapshot_id
            ),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(list_body["snapshots"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            get_body["snapshot"]["metadata"]["snapshot_id"],
            snapshot.metadata.snapshot_id
        );
        assert_eq!(store.authorization_decisions().len(), 2);
    }

    #[tokio::test]
    async fn admin_project_list_and_get_use_resource_envelopes() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/projects").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(store.clone(), &raw_session, "/admin/v1/projects/prj_test").await;
        let get_status = get.status();
        let get_body = response_json(get).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            list_body["resources"][0]["schema"],
            "gateway.admin.resource.v1"
        );
        assert_eq!(list_body["resources"][0]["resource"]["kind"], "project");
        assert_eq!(get_body["resource"]["kind"], "project");
        assert_eq!(get_body["resource"]["id"], "prj_test");
        assert_eq!(store.authorization_decisions().len(), 2);
    }

    #[tokio::test]
    async fn admin_project_status_update_uses_optimistic_concurrency_and_audit() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = patch_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test",
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable inactive project."
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        let project = store
            .project("prj_test")
            .unwrap_or_else(|| panic!("project should exist"));
        let audit_events = store.audit_events();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"]["version"], 2);
        assert_eq!(body["resource"]["status"], "disabled");
        assert_eq!(project.status, DirectoryStatus::Disabled);
        assert_eq!(project.resource_version, 2);
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].event_type, "gateway.project.update");
        assert_eq!(audit_events[0].before_version, Some(1));
        assert_eq!(audit_events[0].after_version, Some(2));
        assert_eq!(store.authorization_decisions().len(), 1);
    }

    #[tokio::test]
    async fn admin_project_status_update_rejects_stale_version() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = patch_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test",
            json!({
                "expected_version": 99,
                "status": "disabled",
                "reason": "Stale update should fail."
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        let project = store
            .project("prj_test")
            .unwrap_or_else(|| panic!("project should exist"));
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"]["code"], "gateway.request.invalid");
        assert_eq!(project.status, DirectoryStatus::Active);
        assert_eq!(project.resource_version, 1);
        assert!(store.audit_events().is_empty());
        assert_eq!(store.authorization_decisions().len(), 1);
    }

    #[tokio::test]
    async fn admin_organization_list_get_and_update_use_resource_envelopes() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/organizations").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/organizations/org_test",
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/organizations/org_test",
            json!({
                "expected_version": 1,
                "status": "suspended",
                "reason": "Suspend organization access."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;
        let organization = store
            .organization("org_test")
            .unwrap_or_else(|| panic!("organization should exist"));

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            list_body["resources"][0]["resource"]["kind"],
            "organization"
        );
        assert_eq!(get_body["resource"]["id"], "org_test");
        assert_eq!(update_body["resource"]["status"], "suspended");
        assert_eq!(organization.status, DirectoryStatus::Suspended);
        assert_eq!(organization.resource_version, 2);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.organization.update"
        );
    }

    #[tokio::test]
    async fn admin_organization_member_list_get_and_update_are_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let list = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/organizations/org_test/members",
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/organizations/org_test/members/om_test",
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/organizations/org_test/members/om_test",
            json!({
                "expected_version": 1,
                "status": "suspended",
                "reason": "Suspend organization member."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;
        let member = store
            .organization_member("om_test")
            .unwrap_or_else(|| panic!("organization member should exist"));
        let project_member = store
            .project_member("pm_test")
            .unwrap_or_else(|| panic!("project member should exist"));

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            list_body["resources"][0]["resource"]["kind"],
            "organization_member"
        );
        assert_eq!(get_body["resource"]["id"], "om_test");
        assert_eq!(update_body["resource"]["status"], "suspended");
        assert_eq!(update_body["cascaded_project_member_count"], 1);
        assert_eq!(member.status, MembershipStatus::Suspended);
        assert_eq!(member.resource_version, 2);
        assert_eq!(project_member.status, MembershipStatus::Suspended);
        assert_eq!(project_member.resource_version, 2);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.organization_member.update"
        );
        assert_eq!(
            store.audit_events()[0].redacted_diff["cascaded_project_member_count"],
            1
        );
    }

    #[tokio::test]
    async fn admin_project_member_list_get_and_update_are_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let list = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test/members",
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test/members/pm_test",
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test/members/pm_test",
            json!({
                "expected_version": 1,
                "status": "removed",
                "reason": "Remove stale project member."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;
        let member = store
            .project_member("pm_test")
            .unwrap_or_else(|| panic!("project member should exist"));

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            list_body["resources"][0]["resource"]["kind"],
            "project_member"
        );
        assert_eq!(get_body["resource"]["id"], "pm_test");
        assert_eq!(update_body["resource"]["status"], "removed");
        assert_eq!(member.status, MembershipStatus::Removed);
        assert_eq!(member.resource_version, 2);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.project_member.update"
        );
    }

    #[tokio::test]
    async fn admin_project_member_create_requires_parent_organization_membership() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let created = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test/members",
            json!({
                "idempotency_key": "idem_project_member_create",
                "principal_id": TEST_USER_ID,
                "organization_member_id": "om_test"
            }),
        )
        .await;
        let created_status = created.status();
        let created_body = response_json(created).await;
        let replay = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test/members",
            json!({
                "idempotency_key": "idem_project_member_create",
                "principal_id": TEST_USER_ID,
                "organization_member_id": "om_test"
            }),
        )
        .await;
        let replay_status = replay.status();
        let replay_body = response_json(replay).await;
        let invalid_parent = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/projects/prj_test/members",
            json!({
                "idempotency_key": "idem_project_member_invalid_parent",
                "principal_id": TEST_USER_ID,
                "organization_member_id": "om_missing"
            }),
        )
        .await;
        let invalid_parent_status = invalid_parent.status();
        let invalid_parent_body = response_json(invalid_parent).await;

        assert_eq!(created_status, StatusCode::OK, "{created_body:?}");
        assert_eq!(created_body["resource"]["id"], "pm_test");
        assert_eq!(created_body["resource"]["principal_id"], TEST_USER_ID);
        assert_eq!(created_body["resource"]["project_id"], TEST_PROJECT_ID);
        assert_eq!(created_body["resource"]["status"], "active");
        assert_eq!(created_body["idempotency_replayed"], false);
        assert_eq!(replay_status, StatusCode::OK, "{replay_body:?}");
        assert_eq!(replay_body["idempotency_replayed"], true);
        assert_eq!(invalid_parent_status, StatusCode::NOT_FOUND);
        assert_eq!(
            invalid_parent_body["error"]["code"],
            "gateway.resource.not_found"
        );
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.project_member.create"
        );
    }

    #[tokio::test]
    async fn admin_service_account_create_list_get_update_and_dashboard() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let service_account_id =
            create_service_account_over_http(store.clone(), &raw_session).await;
        record_service_account_route_evidence(&store, &service_account_id);

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/service-accounts").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/service-accounts/{service_account_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let dashboard = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/dashboards/service-accounts/{service_account_id}"),
        )
        .await;
        let dashboard_status = dashboard.status();
        let dashboard_body = response_json(dashboard).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/service-accounts/{service_account_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable automation owner."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(dashboard_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            list_body["resources"][0]["resource"]["kind"],
            "service_account"
        );
        assert_eq!(get_body["resource"]["id"], service_account_id);
        assert_eq!(
            dashboard_body["schema"],
            "gateway.admin.dashboard.service_account_overview.v1"
        );
        assert_eq!(dashboard_body["scope"]["kind"], "service_account");
        assert_eq!(dashboard_body["scope"]["id"], service_account_id);
        assert_eq!(dashboard_body["measures"]["request_count"], 1);
        assert_eq!(dashboard_body["measures"]["success_count"], 1);
        assert_eq!(dashboard_body["measures"]["attempt_count"], 1);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(
            store
                .service_account(&service_account_id)
                .map(|account| account.status),
            Some(DirectoryStatus::Disabled)
        );
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.service_account.create"
        );
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.service_account.update"
        );
    }

    #[tokio::test]
    async fn admin_provider_endpoint_validate_is_dry_run() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-endpoints:validate",
            json!({
                "idempotency_key": "idem_provider_validate",
                "organization_id": "org_test",
                "provider_kind": "openai",
                "display_name": "OpenAI",
                "protocol_families": [],
                "upstream_base_url": "ftp://provider.example"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 2);
        assert!(store
            .provider_endpoints_for_tenant(TEST_TENANT_ID)
            .is_empty());
        assert!(store.audit_events().is_empty());
    }

    #[tokio::test]
    async fn admin_provider_endpoint_create_is_idempotent_and_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_provider_create",
            "organization_id": "org_test",
            "provider_kind": "openai",
            "display_name": "OpenAI",
            "protocol_families": ["openai_responses", "openai_chat"],
            "upstream_base_url": "https://api.openai.example/v1"
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-endpoints",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-endpoints",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let endpoint_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("endpoint id should be present"));

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "provider_endpoint");
        assert_eq!(first_body["resource"]["version"], 1);
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(second_body["resource"]["id"], endpoint_id);
        assert_eq!(store.provider_endpoints_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.provider_endpoint.create"
        );
        assert!(!store.audit_events()[0].redacted_diff["upstream_base_url"]
            .as_str()
            .unwrap_or_default()
            .contains("token="));
    }

    #[tokio::test]
    async fn admin_provider_endpoint_list_get_and_update_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/provider-endpoints").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/provider-endpoints/{endpoint_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/provider-endpoints/{endpoint_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable provider endpoint."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], endpoint_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.provider_endpoint.update"
        );
    }

    #[tokio::test]
    async fn admin_secret_ref_create_lists_and_reads_locator_without_secret_material() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        let request = valid_secret_ref_request("idem_secret_ref_create", "super-secret-value-1234");

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/secret-refs",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/secret-refs",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let secret_ref_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("secret ref id should be present"))
            .to_owned();
        let list = get_admin(store.clone(), &raw_session, "/admin/v1/secret-refs").await;
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/secret-refs/{secret_ref_id}"),
        )
        .await;
        let get_body = response_json(get).await;
        let locator = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/secret-refs/{secret_ref_id}/locator"),
        )
        .await;
        let locator_status = locator.status();
        let locator_body = response_json(locator).await;
        let api_key_locator = get_public_with_bearer(
            store.clone(),
            &raw_key,
            &format!("/admin/v1/secret-refs/{secret_ref_id}/locator"),
        )
        .await;
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert!(secret_ref_id.starts_with("sec_"));
        assert_eq!(first_body["resource"]["kind"], "secret_ref");
        assert_eq!(first_body["resource"]["display_mask"], "****1234");
        assert!(first_body["resource"]["fingerprint"]
            .as_str()
            .is_some_and(|fingerprint| fingerprint.starts_with("sha256:")));
        assert!(first_body["resource"].get("secret_value").is_none());
        assert!(first_body["resource"].get("backend_locator").is_none());
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], secret_ref_id);
        assert!(get_body["resource"].get("backend_locator").is_none());
        assert_eq!(locator_status, StatusCode::OK);
        assert_eq!(locator_body["resource"]["id"], secret_ref_id);
        assert_eq!(locator_body["resource"]["backend_kind"], "memory");
        assert!(locator_body["resource"]["backend_locator"]
            .as_str()
            .is_some_and(|locator| locator.starts_with("memory://gateway-secrets/sec_")));
        assert!(locator_body["resource"].get("secret_value").is_none());
        assert_eq!(api_key_locator.status(), StatusCode::FORBIDDEN);
        assert_eq!(store.secret_refs_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(
            store
                .secret_value(&secret_ref_id)
                .map(|value| value.expose_secret().to_owned()),
            Some("super-secret-value-1234".to_owned())
        );
        assert!(!audit_text.contains("super-secret-value-1234"));
        assert!(!first_body.to_string().contains("super-secret-value-1234"));
        assert!(!locator_body.to_string().contains("super-secret-value-1234"));
    }

    #[tokio::test]
    async fn admin_upstream_credential_validate_is_dry_run() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/upstream-credentials:validate",
            json!({
                "idempotency_key": "idem_credential_validate",
                "organization_id": "org_test",
                "provider_endpoint_id": "pep_missing",
                "credential_kind": "",
                "secret_ref_id": "raw_secret"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 3);
        assert!(store
            .upstream_credentials_for_tenant(TEST_TENANT_ID)
            .is_empty());
        assert!(store.audit_events().is_empty());
    }

    #[tokio::test]
    async fn admin_upstream_credential_rejects_missing_secret_ref() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let request = json!({
            "idempotency_key": "idem_credential_missing_secret",
            "organization_id": TEST_ORGANIZATION_ID,
            "provider_endpoint_id": endpoint_id,
            "credential_kind": "api_key",
            "secret_ref_id": "sec_missing_provider_key"
        });

        let validation = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/upstream-credentials:validate",
            request.clone(),
        )
        .await;
        let validation_body = response_json(validation).await;
        let create = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/upstream-credentials",
            request,
        )
        .await;

        assert_eq!(validation_body["valid"], false);
        assert!(validation_body["errors"].as_array().is_some_and(|errors| {
            errors.iter().any(|error| {
                error["field"] == "secret_ref_id" && error["reason"] == "unknown_secret_ref"
            })
        }));
        assert_eq!(create.status(), StatusCode::BAD_REQUEST);
        assert!(store
            .upstream_credentials_for_tenant(TEST_TENANT_ID)
            .is_empty());
    }

    #[tokio::test]
    async fn admin_upstream_credential_create_redacts_secret_material() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            None,
            "upstream provider credential",
            "provider-api-key-value",
        );
        let request = json!({
            "idempotency_key": "idem_credential_create",
            "organization_id": "org_test",
            "provider_endpoint_id": endpoint_id,
            "credential_kind": "api_key",
            "secret_ref_id": &secret_ref_id
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/upstream-credentials",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/upstream-credentials",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let credential_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("credential id should be present"));
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/upstream-credentials/{credential_id}"),
        )
        .await;
        let get_body = response_json(get).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "upstream_credential");
        assert_eq!(first_body["resource"]["secret_ref_id"], secret_ref_id);
        assert!(first_body["resource"].get("secret").is_none());
        assert!(first_body["resource"].get("raw_secret").is_none());
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(get_body["resource"]["id"], credential_id);
        assert_eq!(
            store.upstream_credentials_for_tenant(TEST_TENANT_ID).len(),
            1
        );
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.upstream_credential.create"
        );
        assert_eq!(
            store.audit_events()[1].redacted_diff["secret_ref_id"],
            "sec_***"
        );
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));
        assert!(!audit_text.contains("provider-api-key-value"));
    }

    #[tokio::test]
    async fn admin_audit_event_list_requires_strong_auth_and_redacts_diffs() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;

        let api_key_response =
            get_admin(store.clone(), &raw_key, "/admin/v1/audit/events?limit=1").await;
        let api_key_status = api_key_response.status();
        let api_key_body = response_json(api_key_response).await;
        let session_response = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/audit/events?event_type=gateway.upstream_credential.create&limit=10",
        )
        .await;
        let session_status = session_response.status();
        let session_body = response_json(session_response).await;
        let response_text = serde_json::to_string(&session_body)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));

        assert_eq!(api_key_status, StatusCode::FORBIDDEN);
        assert_eq!(
            api_key_body["error"]["code"],
            "gateway.auth.authorization_denied"
        );
        assert_eq!(session_status, StatusCode::OK);
        assert_eq!(session_body["schema"], "gateway.admin.audit_event_list.v1");
        assert_eq!(session_body["events"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            session_body["events"][0]["event_type"],
            "gateway.upstream_credential.create"
        );
        assert_eq!(session_body["events"][0]["resource_id"], credential_id);
        assert_eq!(
            session_body["events"][0]["redacted_diff"]["secret_ref_id"],
            "sec_***"
        );
        assert!(!response_text.contains("sec_openai"));
        assert!(store.authorization_decisions().iter().any(|decision| {
            !decision.allowed && decision.reason == "api_key_not_allowed_for_route"
        }));
    }

    #[tokio::test]
    async fn admin_audit_event_list_paginates_and_filters() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;

        let first_page = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/audit/events?limit=1",
        )
        .await;
        let first_status = first_page.status();
        let first_body = response_json(first_page).await;
        let next_cursor = first_body["next_cursor"]
            .as_str()
            .unwrap_or_else(|| panic!("next cursor should be present"))
            .to_owned();
        let second_page = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/audit/events?limit=1&cursor={next_cursor}"),
        )
        .await;
        let second_status = second_page.status();
        let second_body = response_json(second_page).await;
        let filtered = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/audit/events?resource_kind=ProviderEndpoint",
        )
        .await;
        let filtered_status = filtered.status();
        let filtered_body = response_json(filtered).await;
        let invalid_limit =
            get_admin(store, &raw_session, "/admin/v1/audit/events?limit=201").await;
        let invalid_limit_status = invalid_limit.status();

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(filtered_status, StatusCode::OK);
        assert_eq!(invalid_limit_status, StatusCode::BAD_REQUEST);
        assert_eq!(first_body["events"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(second_body["events"].as_array().map_or(0, Vec::len), 1);
        assert_ne!(
            first_body["events"][0]["id"],
            second_body["events"][0]["id"]
        );
        assert!(filtered_body["events"]
            .as_array()
            .unwrap_or_else(|| panic!("events should be an array"))
            .iter()
            .all(|event| event["resource_kind"] == "ProviderEndpoint"));
    }

    #[tokio::test]
    async fn admin_upstream_credential_status_update_uses_version() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;

        let response = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/upstream-credentials/{credential_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable stale credential."
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"]["status"], "disabled");
        assert_eq!(body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 3);
        assert_eq!(
            store.audit_events()[2].event_type,
            "gateway.upstream_credential.update"
        );
    }

    #[tokio::test]
    async fn admin_model_target_validate_catches_protocol_and_credential_errors() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/model-targets:validate",
            json!({
                "idempotency_key": "idem_model_target_validate",
                "organization_id": "org_test",
                "provider_endpoint_id": endpoint_id,
                "upstream_credential_id": "upc_missing",
                "protocol_family": "anthropic_messages",
                "upstream_model_id": "",
                "supports_streaming": true
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 3);
        assert!(store.model_targets_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_model_target_create_is_idempotent_and_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;
        let request = json!({
            "idempotency_key": "idem_model_target_create",
            "organization_id": "org_test",
            "provider_endpoint_id": endpoint_id,
            "upstream_credential_id": credential_id,
            "protocol_family": "openai_responses",
            "upstream_model_id": "gpt-4.1-mini",
            "supports_streaming": true
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/model-targets",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/model-targets",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "model_target");
        assert_eq!(first_body["resource"]["upstream_model_id"], "gpt-4.1-mini");
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(store.model_targets_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.audit_events().len(), 3);
        assert_eq!(
            store.audit_events()[2].event_type,
            "gateway.model_target.create"
        );
    }

    #[tokio::test]
    async fn admin_model_target_list_get_and_update_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;
        let target_id = create_model_target_over_http(
            store.clone(),
            &raw_session,
            &endpoint_id,
            &credential_id,
        )
        .await;

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/model-targets").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/model-targets/{target_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/model-targets/{target_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable model target."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], target_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 4);
        assert_eq!(
            store.audit_events()[3].event_type,
            "gateway.model_target.update"
        );
    }

    #[tokio::test]
    async fn admin_model_alias_validate_catches_draft_binding_errors() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/model-aliases:validate",
            json!({
                "idempotency_key": "idem_model_alias_validate",
                "organization_id": "org_test",
                "project_id": "prj_missing",
                "alias_name": "",
                "protocol_family": "openai_responses",
                "route_policy_id": "rp_missing"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 3);
        assert!(store.model_aliases_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_model_alias_create_is_idempotent_and_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_model_alias_create",
            "organization_id": "org_test",
            "project_id": "prj_test",
            "alias_name": "gpt-primary",
            "protocol_family": "openai_responses"
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/model-aliases",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/model-aliases",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "model_alias");
        assert_eq!(first_body["resource"]["alias_name"], "gpt-primary");
        assert_eq!(
            first_body["resource"]["route_policy_id"],
            serde_json::Value::Null
        );
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(store.model_aliases_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.model_alias.create"
        );
    }

    #[tokio::test]
    async fn admin_pricing_sku_validate_catches_invalid_document() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/pricing-skus:validate",
            json!({
                "idempotency_key": "idem_pricing_sku_validate",
                "organization_id": "org_test",
                "name": "Invalid document",
                "currency": "USD",
                "unit": "micro_usd",
                "model_id_patterns": ["gpt-4.1-mini"],
                "pricing_document": {
                    "schema": "gateway.pricing.v0",
                    "currency": "USD",
                    "unit": "micro_usd"
                }
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 2);
        assert!(store.pricing_skus_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_pricing_sku_create_is_idempotent_and_updates_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_pricing_sku_create",
            "organization_id": "org_test",
            "name": "OpenAI GPT primary micro USD",
            "currency": "USD",
            "unit": "micro_usd",
            "model_id_patterns": ["gpt-4.1-mini"],
            "provider_endpoint_patterns": ["pe_*"],
            "pricing_document": pricing_document_fixture()
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/pricing-skus",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/pricing-skus",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let pricing_sku_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("pricing SKU id should be present"))
            .to_owned();
        let list = get_admin(store.clone(), &raw_session, "/admin/v1/pricing-skus").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/pricing-skus/{pricing_sku_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/pricing-skus/{pricing_sku_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable stale pricing."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "pricing_sku");
        assert_eq!(first_body["resource"]["pricing_version"], 1);
        assert_eq!(first_body["resource"]["currency"], "USD");
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], pricing_sku_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.pricing_sku.update"
        );
    }

    #[tokio::test]
    async fn admin_budget_policy_validate_catches_invalid_cost_policy() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/budget-policies:validate",
            json!({
                "idempotency_key": "idem_budget_policy_validate",
                "scope_kind": "project",
                "scope_id": "prj_missing",
                "period": "weekly",
                "limit_kind": "cost",
                "hard_limit": -1,
                "soft_limit": 100,
                "thresholds": [-1],
                "reset_policy": "",
                "overage_mode": "notify_only",
                "consistency_mode": "eventual"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 7);
        assert!(store.budget_policies_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_budget_policy_create_is_idempotent_and_updates_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_budget_policy_create",
            "scope_kind": "project",
            "scope_id": "prj_test",
            "currency": "USD",
            "period": "calendar_month",
            "limit_kind": "cost",
            "hard_limit": 1_000_000,
            "soft_limit": 800_000,
            "thresholds": [500_000, 900_000],
            "reset_policy": "periodic_window_reset",
            "overage_mode": "block_new_requests",
            "consistency_mode": "eventual"
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/budget-policies",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/budget-policies",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let budget_policy_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("budget policy id should be present"))
            .to_owned();
        let list = get_admin(store.clone(), &raw_session, "/admin/v1/budget-policies").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/budget-policies/{budget_policy_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/budget-policies/{budget_policy_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable stale budget."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "budget_policy");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["project_id"], "prj_test");
        assert_eq!(first_body["resource"]["hard_limit"], 1_000_000);
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], budget_policy_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.budget_policy.update"
        );
    }

    #[tokio::test]
    async fn admin_quota_policy_validate_catches_invalid_shape() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies:validate",
            json!({
                "idempotency_key": "idem_quota_policy_validate",
                "scope_kind": "endpoint",
                "scope_id": "ep_missing",
                "counter_kind": "request_rate",
                "limit": -1,
                "window": "request_lifetime",
                "increment_source": "stream_start",
                "loss_behavior": "fail_limited"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        let errors = body["errors"]
            .as_array()
            .unwrap_or_else(|| panic!("validation errors should be an array"));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert!(errors.iter().any(|error| {
            error["field"] == "scope_id" && error["reason"] == "unknown_endpoint"
        }));
        assert!(errors
            .iter()
            .any(|error| { error["field"] == "limit" && error["reason"] == "positive_required" }));
        assert!(errors.iter().any(|error| {
            error["field"] == "scope_kind" && error["reason"] == "unsupported_counter_scope"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "window" && error["reason"] == "unsupported_counter_window"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "increment_source"
                && error["reason"] == "unsupported_increment_source"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "burst_limit" && error["reason"] == "required_for_fail_limited"
        }));
        assert!(store.quota_policies_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_quota_policy_create_is_idempotent_and_updates_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_quota_policy_create",
            "scope_kind": "project",
            "scope_id": "prj_test",
            "counter_kind": "request_rate",
            "limit": 60,
            "window": "fixed",
            "increment_source": "accepted_preflight_request",
            "loss_behavior": "fail_closed"
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let quota_policy_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("quota policy id should be present"))
            .to_owned();
        let list = get_admin(store.clone(), &raw_session, "/admin/v1/quota-policies").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/quota-policies/{quota_policy_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/quota-policies/{quota_policy_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable stale quota."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "quota_policy");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["project_id"], "prj_test");
        assert_eq!(first_body["resource"]["counter_kind"], "request_rate");
        assert_eq!(first_body["resource"]["limit"], 60);
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], quota_policy_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.quota_policy.update"
        );
    }

    #[tokio::test]
    async fn admin_quota_policy_accepts_protocol_family_body_limit_scope() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/quota-policies",
            json!({
                "idempotency_key": "idem_quota_policy_protocol_family",
                "scope_kind": "protocol_family",
                "scope_id": "openai_responses",
                "counter_kind": "request_body_bytes",
                "limit": 1_048_576,
                "burst_limit": 2_097_152,
                "window": "sliding",
                "increment_source": "request_body_bytes",
                "loss_behavior": "fail_limited"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"]["kind"], "quota_policy");
        assert_eq!(body["resource"]["scope_kind"], "protocol_family");
        assert_eq!(body["resource"]["scope_id"], "openai_responses");
        assert_eq!(body["resource"]["organization_id"], serde_json::Value::Null);
        assert_eq!(body["resource"]["project_id"], serde_json::Value::Null);
        assert_eq!(body["resource"]["loss_behavior"], "fail_limited");
        assert_eq!(store.quota_policies_for_tenant(TEST_TENANT_ID).len(), 1);
    }

    #[tokio::test]
    async fn admin_otel_export_config_validate_catches_secret_and_cardinality_risks() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/observability/otel-export/configs/otel_candidate/validate",
            json!({
                "idempotency_key": "idem_otel_validate",
                "project_id": "prj_test",
                "endpoint_url": "http://collector.example/v1/metrics?token=raw",
                "protocol": "otlp_http",
                "header_refs": [{
                    "name": "Authorization",
                    "secret_ref_id": "raw_collector_token"
                }],
                "enabled_signals": ["metrics", "logs"],
                "resource_attributes": [{
                    "key": "request.id",
                    "value": "req_123"
                }],
                "export_interval_seconds": 10,
                "timeout_seconds": 10
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        let errors = body["errors"]
            .as_array()
            .unwrap_or_else(|| panic!("validation errors should be an array"));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert!(errors.iter().any(|error| {
            error["field"] == "endpoint_url" && error["reason"] == "invalid_endpoint_url"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "header_refs.secret_ref_id" && error["reason"] == "invalid_secret_ref"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "enabled_signals" && error["reason"] == "unsupported_signal"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "resource_attributes.key"
                && error["reason"] == "forbidden_attribute_key"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "timeout_seconds" && error["reason"] == "invalid_timeout"
        }));
        assert!(store
            .otel_export_configs_for_tenant(TEST_TENANT_ID)
            .is_empty());
    }

    #[tokio::test]
    async fn admin_otel_and_notification_validate_missing_secret_refs() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let otel = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/observability/otel-export/configs/otel_candidate/validate",
            valid_otel_export_config_request_with_secret(
                "idem_otel_missing_secret",
                "sec_missing_otel_collector",
            ),
        )
        .await;
        let otel_body = response_json(otel).await;
        let notification = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/notification/sinks:validate",
            valid_notification_sink_request_with_secret(
                "idem_notification_missing_secret",
                "sec_missing_notification_signing",
            ),
        )
        .await;
        let notification_body = response_json(notification).await;

        assert_eq!(otel_body["valid"], false);
        assert!(otel_body["errors"].as_array().is_some_and(|errors| {
            errors.iter().any(|error| {
                error["field"] == "header_refs.secret_ref_id"
                    && error["reason"] == "unknown_secret_ref"
            })
        }));
        assert_eq!(notification_body["valid"], false);
        assert!(notification_body["errors"]
            .as_array()
            .is_some_and(|errors| errors.iter().any(|error| {
                error["field"] == "signing_secret_ref_id" && error["reason"] == "unknown_secret_ref"
            })));
    }

    #[tokio::test]
    async fn admin_otel_export_config_create_is_idempotent_and_redacted() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "otel collector authorization",
            "otel-collector-token-value",
        );
        let request =
            valid_otel_export_config_request_with_secret("idem_otel_create", &secret_ref_id);

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/observability/otel-export/configs",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/observability/otel-export/configs",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let response_text = serde_json::to_string(&first_body)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));
        let otel_export_config_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("otel export config id should be present"))
            .to_owned();
        let list = get_admin(
            store.clone(),
            &raw_session,
            "/admin/v1/observability/otel-export/configs",
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "otel_export_config");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["project_id"], "prj_test");
        assert_eq!(first_body["resource"]["endpoint_host"], "otel.example");
        assert_eq!(
            first_body["resource"]["header_refs"][0]["secret_ref_id"],
            "sec_***"
        );
        assert!(!response_text.contains(&secret_ref_id));
        assert!(!response_text.contains("otel-collector-token-value"));
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], otel_export_config_id);
        assert_eq!(store.audit_events().len(), 1);
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));
        assert!(!audit_text.contains(&secret_ref_id));
        assert!(!audit_text.contains("otel-collector-token-value"));
    }

    #[tokio::test]
    async fn admin_otel_export_config_update_and_disable_redacts_secret_refs() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let otel_export_config_id =
            create_otel_export_config_over_http(store.clone(), &raw_session).await;
        let rotated_secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "otel collector rotated authorization",
            "otel-rotated-token-value",
        );

        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}"),
            json!({
                "expected_version": 1,
                "endpoint_url": "https://collector.example/v1/metrics",
                "header_refs": [{
                    "name": "x-otlp-api-key",
                    "secret_ref_id": &rotated_secret_ref_id
                }],
                "resource_attributes": [{
                    "key": "deployment.environment",
                    "value": "staging"
                }],
                "reason": "Rotate collector endpoint."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;
        let update_text = serde_json::to_string(&update_body)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));
        let disable = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}/disable"),
            json!({
                "expected_version": 2,
                "reason": "Disable collector export."
            }),
        )
        .await;
        let disable_status = disable.status();
        let disable_body = response_json(disable).await;

        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(disable_status, StatusCode::OK);
        assert_eq!(
            update_body["resource"]["endpoint_host"],
            "collector.example"
        );
        assert_eq!(
            update_body["resource"]["header_refs"][0]["secret_ref_id"],
            "sec_***"
        );
        assert!(!update_text.contains(&rotated_secret_ref_id));
        assert!(!update_text.contains("otel-rotated-token-value"));
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(disable_body["resource"]["status"], "disabled");
        assert_eq!(disable_body["resource"]["version"], 3);
        assert_eq!(
            store
                .otel_export_configs_for_tenant(TEST_TENANT_ID)
                .first()
                .map(|config| config.header_refs[0].secret_ref_id.as_str()),
            Some(rotated_secret_ref_id.as_str())
        );
        assert_eq!(store.audit_events().len(), 3);
        assert_eq!(
            store.audit_events()[2].event_type,
            "gateway.observability_export.disable"
        );
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));
        assert!(!audit_text.contains(&rotated_secret_ref_id));
        assert!(!audit_text.contains("otel-rotated-token-value"));
    }

    #[tokio::test]
    async fn otel_exporter_worker_records_success_and_realtime_health() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let runtime = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        assert_eq!(runtime.status(), StatusCode::OK);
        let otel_export_config_id =
            create_otel_export_config_over_http(store.clone(), &raw_session).await;

        let summary = run_otel_exporter_once(
            &store,
            TEST_TENANT_ID,
            "otel_worker_test",
            chrono::Utc::now(),
        )
        .unwrap_or_else(|error| panic!("otel exporter tick should succeed: {error}"));
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let overview = get_admin(store.clone(), &raw_session, "/admin/v1/realtime/overview").await;
        let overview_status = overview.status();
        let overview_body = response_json(overview).await;
        let readiness = get_public(store.clone(), "/readyz").await;
        let readiness_body = response_json(readiness).await;

        assert_eq!(summary.attempted_config_count, 1);
        assert_eq!(summary.succeeded_count, 1);
        assert!(summary.exported_metric_count > 0);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(get_body["resource"]["exporter_health_status"], "succeeded");
        assert_eq!(get_body["resource"]["exporter_failure_count"], 0);
        assert!(get_body["resource"]["exported_metric_count"]
            .as_i64()
            .is_some_and(|count| count > 0));
        assert_ne!(
            get_body["resource"]["last_successful_export_at"],
            serde_json::Value::Null
        );
        assert_eq!(overview_status, StatusCode::OK);
        assert_eq!(overview_body["otel_exporter"]["status"], "healthy");
        assert_eq!(overview_body["otel_exporter"]["healthy_count"], 1);
        assert_eq!(overview_body["otel_exporter"]["dropped_metric_count"], 0);
        assert_eq!(readiness_body["dependencies"]["otel_exporter"], "ready");
    }

    #[tokio::test]
    async fn otel_exporter_outage_records_drops_without_blocking_model_requests() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        let secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "otel collector authorization",
            "otel-collector-token-value",
        );
        let mut request =
            valid_otel_export_config_request_with_secret("idem_otel_unreachable", &secret_ref_id);
        request["endpoint_url"] = json!("https://unreachable.example/v1/metrics");
        let create = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/observability/otel-export/configs",
            request,
        )
        .await;
        assert_eq!(create.status(), StatusCode::OK);
        let create_body = response_json(create).await;
        let otel_export_config_id = create_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("otel export config id should be present"))
            .to_owned();

        let summary = run_otel_exporter_once(
            &store,
            TEST_TENANT_ID,
            "otel_worker_test",
            chrono::Utc::now(),
        )
        .unwrap_or_else(|error| panic!("otel exporter tick should record outage: {error}"));
        publish_catalog_snapshot(&store, catalog_payload());
        let runtime = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}"),
        )
        .await;
        let get_body = response_json(get).await;
        let readiness = get_public(store.clone(), "/readyz").await;
        let readiness_body = response_json(readiness).await;

        assert_eq!(summary.failed_count, 1);
        assert!(summary.dropped_metric_count > 0);
        assert_eq!(runtime.status(), StatusCode::OK);
        assert_eq!(
            get_body["resource"]["exporter_health_status"],
            "retryable_failed"
        );
        assert_eq!(get_body["resource"]["exporter_failure_count"], 1);
        assert!(get_body["resource"]["dropped_metric_count"]
            .as_i64()
            .is_some_and(|count| count > 0));
        assert_eq!(
            get_body["resource"]["last_export_error"],
            "collector_unavailable"
        );
        assert_eq!(readiness_body["dependencies"]["otel_exporter"], "degraded");
    }

    #[tokio::test]
    async fn otel_exporter_worker_records_disabled_configs() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let otel_export_config_id =
            create_otel_export_config_over_http(store.clone(), &raw_session).await;
        let disable = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}/disable"),
            json!({
                "expected_version": 1,
                "reason": "Disable collector export."
            }),
        )
        .await;
        assert_eq!(disable.status(), StatusCode::OK);

        let summary = run_otel_exporter_once(
            &store,
            TEST_TENANT_ID,
            "otel_worker_test",
            chrono::Utc::now(),
        )
        .unwrap_or_else(|error| {
            panic!("otel exporter tick should record disabled config: {error}")
        });
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/observability/otel-export/configs/{otel_export_config_id}"),
        )
        .await;
        let get_body = response_json(get).await;
        let readiness = get_public(store.clone(), "/readyz").await;
        let readiness_body = response_json(readiness).await;

        assert_eq!(summary.disabled_count, 1);
        assert_eq!(get_body["resource"]["exporter_health_status"], "disabled");
        assert_eq!(get_body["resource"]["exporter_failure_count"], 0);
        assert_eq!(get_body["resource"]["dropped_metric_count"], 0);
        assert_eq!(readiness_body["dependencies"]["otel_exporter"], "disabled");
    }

    #[tokio::test]
    async fn admin_notification_sink_validate_catches_unsafe_webhook_shape() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/notification/sinks:validate",
            json!({
                "idempotency_key": "idem_notification_sink_validate",
                "name": "",
                "sink_kind": "webhook",
                "endpoint_config": {
                    "url": "http://hooks.example/gateway?token=raw",
                    "headers": {"Authorization": "Bearer raw"}
                },
                "signing_secret_ref_id": "raw_webhook_secret"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        let errors = body["errors"]
            .as_array()
            .unwrap_or_else(|| panic!("validation errors should be an array"));
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert!(errors
            .iter()
            .any(|error| error["field"] == "name" && error["reason"] == "invalid_name"));
        assert!(errors.iter().any(|error| {
            error["field"] == "endpoint_config" && error["reason"] == "sensitive_endpoint_config"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "endpoint_config.url" && error["reason"] == "invalid_url"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "signing_secret_ref_id" && error["reason"] == "required_secret_ref"
        }));
        assert!(store
            .notification_sinks_for_tenant(TEST_TENANT_ID)
            .is_empty());
    }

    #[tokio::test]
    async fn admin_notification_sink_create_is_idempotent_and_redacted() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let signing_secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "notification webhook signing",
            "notification-webhook-secret-value",
        );
        let request = valid_notification_sink_request_with_secret(
            "idem_notification_sink_create",
            &signing_secret_ref_id,
        );

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/notification/sinks",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/notification/sinks",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let response_text = serde_json::to_string(&first_body)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));
        let notification_sink_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("notification sink id should be present"))
            .to_owned();
        let list = get_admin(store.clone(), &raw_session, "/admin/v1/notification/sinks").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable webhook."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "notification_sink");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["project_id"], "prj_test");
        assert_eq!(
            first_body["resource"]["endpoint_config"]["url_host"],
            "hooks.example"
        );
        assert_eq!(first_body["resource"]["signing_secret_ref_id"], "sec_***");
        assert!(!response_text.contains(&signing_secret_ref_id));
        assert!(!response_text.contains("notification-webhook-secret-value"));
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], notification_sink_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(
            store
                .notification_sinks_for_tenant(TEST_TENANT_ID)
                .first()
                .and_then(|sink| sink.signing_secret_ref_id.as_deref()),
            Some(signing_secret_ref_id.as_str())
        );
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));
        assert!(!audit_text.contains(&signing_secret_ref_id));
        assert!(!audit_text.contains("notification-webhook-secret-value"));
    }

    #[tokio::test]
    async fn admin_notification_subscription_create_is_idempotent_and_updates_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let notification_sink_id =
            create_notification_sink_over_http(store.clone(), &raw_session).await;

        let invalid = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}/subscriptions:validate"),
            json!({
                "idempotency_key": "idem_notification_subscription_validate",
                "event_family": "billing",
                "filter_document": {"prompt": "raw"}
            }),
        )
        .await;
        let invalid_status = invalid.status();
        let invalid_body = response_json(invalid).await;
        let request = json!({
            "idempotency_key": "idem_notification_subscription_create",
            "event_family": "usage",
            "filter_document": {"project_id": "prj_test"}
        });
        let first = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}/subscriptions"),
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}/subscriptions"),
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let subscription_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("notification subscription id should be present"))
            .to_owned();
        let list = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}/subscriptions"),
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/notification/sinks/{notification_sink_id}/subscriptions/{subscription_id}"
            ),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/notification/sinks/{notification_sink_id}/subscriptions/{subscription_id}"
            ),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable usage subscription."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(invalid_status, StatusCode::OK);
        assert_eq!(invalid_body["valid"], false);
        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "notification_subscription");
        assert_eq!(first_body["resource"]["event_family"], "usage");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["project_id"], "prj_test");
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], subscription_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_notification_subscription_audit_events(&store);
    }

    #[tokio::test]
    async fn admin_login_provider_validate_catches_secret_and_invalid_oidc_shape() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let invalid_shape = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/identity-providers:validate",
            json!({
                "idempotency_key": "idem_login_provider_invalid_shape",
                "provider_kind": "oidc",
                "display_name": "",
                "config_document": {
                    "client_id": "",
                    "client_secret_ref": "raw_secret",
                    "redirect_uri": "http://app.example/auth/callback?token=raw",
                    "issuer": "http://login.example",
                    "scopes": [""]
                }
            }),
        )
        .await;
        let invalid_status = invalid_shape.status();
        let invalid_body = response_json(invalid_shape).await;
        let errors = invalid_body["errors"]
            .as_array()
            .unwrap_or_else(|| panic!("validation errors should be an array"));

        let secret_value = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/identity-providers:validate",
            json!({
                "idempotency_key": "idem_login_provider_raw_secret",
                "provider_kind": "github_oauth_app",
                "display_name": "GitHub",
                "config_document": {
                    "client_id": "github_client",
                    "client_secret": "raw secret",
                    "client_secret_ref": "sec_login_github_secret",
                    "redirect_uri": "https://app.example/auth/github/callback"
                }
            }),
        )
        .await;
        let secret_status = secret_value.status();
        let secret_body = response_json(secret_value).await;

        assert_eq!(invalid_status, StatusCode::OK);
        assert_eq!(invalid_body["valid"], false);
        assert!(errors.iter().any(|error| {
            error["field"] == "display_name" && error["reason"] == "invalid_display_name"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "config_document.client_id" && error["reason"] == "invalid_client_id"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "config_document.client_secret_ref"
                && error["reason"] == "invalid_secret_ref"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "config_document.redirect_uri"
                && error["reason"] == "invalid_redirect_uri"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "config_document.issuer" && error["reason"] == "invalid_issuer"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "config_document.authorization_url"
                && error["reason"] == "invalid_authorization_url"
        }));
        assert!(errors.iter().any(|error| {
            error["field"] == "config_document.scopes" && error["reason"] == "invalid_scopes"
        }));
        assert_eq!(secret_status, StatusCode::OK);
        assert_eq!(secret_body["valid"], false);
        assert_eq!(
            secret_body["errors"][0]["field"],
            serde_json::Value::String("config_document".to_owned())
        );
        assert!(store.login_providers_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_login_provider_create_is_idempotent_redacted_and_public_discoverable() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = valid_github_login_provider_request("idem_login_provider_create");

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/identity-providers",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/identity-providers",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let response_text = serde_json::to_string(&first_body)
            .unwrap_or_else(|error| panic!("response should serialize: {error}"));
        let login_provider_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("login provider id should be present"))
            .to_owned();
        let admin_list =
            get_admin(store.clone(), &raw_session, "/admin/v1/identity-providers").await;
        let admin_list_status = admin_list.status();
        let admin_list_body = response_json(admin_list).await;
        let public_list = get_public(
            store.clone(),
            &format!("/auth/v1/providers?tenant_id={TEST_TENANT_ID}"),
        )
        .await;
        let public_list_status = public_list.status();
        let public_list_body = response_json(public_list).await;
        let public_get = get_public(
            store.clone(),
            &format!("/auth/v1/providers/{login_provider_id}"),
        )
        .await;
        let public_get_status = public_get.status();
        let public_get_body = response_json(public_get).await;
        let start = get_public(
            store.clone(),
            &format!("/auth/v1/providers/{login_provider_id}/login"),
        )
        .await;
        let start_status = start.status();
        let start_body = response_json(start).await;
        let public_text = serde_json::to_string(&public_list_body)
            .unwrap_or_else(|error| panic!("public response should serialize: {error}"));
        let start_text = serde_json::to_string(&start_body)
            .unwrap_or_else(|error| panic!("start response should serialize: {error}"));

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(admin_list_status, StatusCode::OK);
        assert_eq!(public_list_status, StatusCode::OK);
        assert_eq!(public_get_status, StatusCode::OK);
        assert_eq!(start_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "identity_provider");
        assert_eq!(first_body["resource"]["provider_kind"], "github_oauth_app");
        assert_eq!(
            first_body["resource"]["config_document"]["client_secret_ref"],
            "sec_***"
        );
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(
            admin_list_body["resources"][0]["resource"]["id"],
            login_provider_id
        );
        assert_eq!(
            public_list_body["resources"].as_array().map_or(0, Vec::len),
            1
        );
        assert_eq!(public_get_body["resource"]["id"], login_provider_id);
        assert_eq!(
            public_get_body["resource"]["login_url"],
            format!("/auth/v1/providers/{login_provider_id}/login")
        );
        assert_github_login_start_response(&start_body, &login_provider_id);
        assert!(!response_text.contains("sec_login_github_secret"));
        assert!(!public_text.contains("sec_login_github_secret"));
        assert!(!start_text.contains("sec_login_github_secret"));
        assert!(!start_text.contains("code_verifier"));
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));
        assert!(!audit_text.contains("sec_login_github_secret"));
    }

    #[tokio::test]
    async fn organization_invitation_create_preview_and_accept_are_redacted() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let created_body = create_organization_invitation_over_http(
            store.clone(),
            &raw_session,
            "idem_org_invite_create",
            Some(TEST_PROJECT_ID),
        )
        .await;
        let invitation_token = invitation_token_from_body(&created_body);
        let invitation_id = resource_id_from_body(&created_body);

        let replay = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/organizations/{TEST_ORGANIZATION_ID}/invitations"),
            json!({
                "idempotency_key": "idem_org_invite_create",
                "invited_principal_id": TEST_USER_ID,
                "project_id": TEST_PROJECT_ID,
                "role_id": "organization_member"
            }),
        )
        .await;
        let replay_body = response_json(replay).await;
        let list = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/organizations/{TEST_ORGANIZATION_ID}/invitations"),
        )
        .await;
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/organizations/{TEST_ORGANIZATION_ID}/invitations/{invitation_id}"),
        )
        .await;
        let get_body = response_json(get).await;
        let preview = get_public(
            store.clone(),
            &format!("/auth/v1/invitations/{invitation_token}/preview"),
        )
        .await;
        let preview_body = response_json(preview).await;
        let accepted = post_public_with_bearer(
            store.clone(),
            &raw_session,
            &format!("/auth/v1/invitations/{invitation_token}/accept"),
        )
        .await;
        let accepted_body = response_json(accepted).await;
        let accepted_again = post_public_with_bearer(
            store.clone(),
            &raw_session,
            &format!("/auth/v1/invitations/{invitation_token}/accept"),
        )
        .await;
        let accepted_again_status = accepted_again.status();
        let combined_text = serde_json::to_string(&json!({
            "replay": replay_body,
            "list": list_body,
            "get": get_body,
            "preview": preview_body,
            "accepted": accepted_body
        }))
        .unwrap_or_else(|error| panic!("response bodies should serialize: {error}"));

        assert_eq!(accepted_again_status, StatusCode::BAD_REQUEST);
        assert!(invitation_token.starts_with("gwinv_"));
        assert_eq!(replay_body["idempotency_replayed"], true);
        assert!(replay_body.get("invitation_token").is_none());
        assert_eq!(preview_body["resource"]["status"], "pending");
        assert_eq!(accepted_body["resource"]["status"], "accepted");
        assert_eq!(
            accepted_body["session"]["session"]["active_organization_id"],
            TEST_ORGANIZATION_ID
        );
        assert_eq!(
            accepted_body["session"]["session"]["active_project_id"],
            TEST_PROJECT_ID
        );
        assert!(!combined_text.contains(&invitation_token));
        assert!(!combined_text.contains("invitation_token_hash"));
        assert!(store
            .project_membership(TEST_USER_ID, TEST_PROJECT_ID)
            .is_some());
        assert!(store.audit_events().iter().any(|event| {
            event.event_type == "gateway.organization_invite.accept"
                && event.resource_id == invitation_id
        }));
    }

    #[tokio::test]
    async fn organization_invitation_revoke_marks_pending_invite_revoked() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let created_body = create_organization_invitation_over_http(
            store.clone(),
            &raw_session,
            "idem_org_invite_revoke",
            None,
        )
        .await;
        let invitation_token = invitation_token_from_body(&created_body);
        let invitation_id = resource_id_from_body(&created_body);
        let invitation_version = created_body["resource"]["version"]
            .as_i64()
            .unwrap_or_else(|| panic!("version should be present"));

        let revoked = post_admin_json(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/organizations/{TEST_ORGANIZATION_ID}/invitations/{invitation_id}/revoke"
            ),
            json!({
                "expected_version": invitation_version,
                "reason": "No longer needed"
            }),
        )
        .await;
        let revoked_status = revoked.status();
        let revoked_body = response_json(revoked).await;
        let preview = get_public(
            store,
            &format!("/auth/v1/invitations/{invitation_token}/preview"),
        )
        .await;
        let preview_body = response_json(preview).await;

        assert_eq!(revoked_status, StatusCode::OK);
        assert_eq!(revoked_body["resource"]["status"], "revoked");
        assert_eq!(preview_body["resource"]["status"], "revoked");
        assert!(!revoked_body.to_string().contains(&invitation_token));
    }

    #[tokio::test]
    async fn admin_user_disable_revokes_active_sessions() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/users").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/users/{TEST_USER_ID}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let user_version = get_body["resource"]["version"]
            .as_i64()
            .unwrap_or_else(|| panic!("user version should be present"));

        let disabled = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/users/{TEST_USER_ID}"),
            json!({
                "expected_version": user_version,
                "status": "disabled",
                "reason": "Security response"
            }),
        )
        .await;
        let disabled_status = disabled.status();
        let disabled_body = response_json(disabled).await;
        let session_after_disable =
            get_public_with_bearer(store.clone(), &raw_session, "/auth/v1/session").await;
        let session_after_disable_status = session_after_disable.status();

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(disabled_status, StatusCode::OK);
        assert_eq!(session_after_disable_status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            list_body["resources"][0]["resource"]["id"],
            serde_json::Value::String(TEST_USER_ID.to_owned())
        );
        assert_eq!(disabled_body["resource"]["status"], "disabled");
        assert_eq!(disabled_body["revoked_session_count"], 1);
        assert!(store.audit_events().iter().any(|event| {
            event.event_type == "gateway.user.disable" && event.resource_id == TEST_USER_ID
        }));
    }

    #[tokio::test]
    async fn admin_user_session_list_and_revoke_are_scoped_and_redacted() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let (target_raw_session, target_session_id) = insert_admin_session_with_id(&store);

        let list = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/users/{TEST_USER_ID}/sessions"),
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let list_text = list_body.to_string();
        let listed_resources = list_body["resources"]
            .as_array()
            .unwrap_or_else(|| panic!("session list should include resources"));
        let freeze = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/emergency/config/freeze",
            json!({
                "idempotency_key": "idem_session_revoke_during_freeze",
                "reason": "Freeze config while responding to an auth incident.",
                "expires_at": (chrono::Utc::now() + Duration::minutes(30)).to_rfc3339()
            }),
        )
        .await;
        let freeze_status = freeze.status();
        let freeze_body = response_json(freeze).await;

        let revoked = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/users/{TEST_USER_ID}/sessions/{target_session_id}/revoke"),
            json!({
                "reason": "Compromised browser"
            }),
        )
        .await;
        let revoked_status = revoked.status();
        let revoked_body = response_json(revoked).await;
        let revoked_text = revoked_body.to_string();
        let target_after_revoke =
            get_public_with_bearer(store.clone(), &target_raw_session, "/auth/v1/session").await;
        let admin_after_revoke =
            get_public_with_bearer(store.clone(), &raw_session, "/auth/v1/session").await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(freeze_status, StatusCode::OK, "{freeze_body:?}");
        assert_eq!(listed_resources.len(), 2);
        assert!(listed_resources.iter().any(|resource| {
            resource["resource"]["id"] == serde_json::Value::String(target_session_id.clone())
        }));
        assert!(!list_text.contains(&target_raw_session));
        assert!(!list_text.contains("session_hash"));
        assert_eq!(revoked_status, StatusCode::OK);
        assert_eq!(revoked_body["resource"]["id"], target_session_id);
        assert_eq!(revoked_body["resource"]["status"], "revoked");
        assert!(!revoked_text.contains(&target_raw_session));
        assert!(!revoked_text.contains("session_hash"));
        assert_eq!(target_after_revoke.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(admin_after_revoke.status(), StatusCode::OK);
        assert!(store.audit_events().iter().any(|event| {
            event.event_type == "gateway.session.revoke"
                && event.resource_kind == "AuthSession"
                && event.resource_id == target_session_id
        }));
    }

    #[tokio::test]
    async fn admin_user_external_identity_list_get_and_unlink_are_redacted() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let external_identity_id = insert_external_identity(&store, "Admin@Example.COM");

        let list = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/users/{TEST_USER_ID}/external-identities"),
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let list_text = list_body.to_string();
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/users/{TEST_USER_ID}/external-identities/{external_identity_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let get_text = get_body.to_string();
        let freeze = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/emergency/config/freeze",
            json!({
                "idempotency_key": "idem_external_identity_unlink_during_freeze",
                "reason": "Freeze config while unlinking an external identity.",
                "expires_at": (chrono::Utc::now() + Duration::minutes(30)).to_rfc3339()
            }),
        )
        .await;
        let freeze_status = freeze.status();
        let freeze_body = response_json(freeze).await;

        let unlinked = post_admin_json(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/users/{TEST_USER_ID}/external-identities/{external_identity_id}/unlink"
            ),
            json!({
                "reason": "Account link removed by admin"
            }),
        )
        .await;
        let unlinked_status = unlinked.status();
        let unlinked_body = response_json(unlinked).await;
        let unlinked_text = unlinked_body.to_string();

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(freeze_status, StatusCode::OK, "{freeze_body:?}");
        assert_eq!(unlinked_status, StatusCode::OK);
        assert_eq!(
            list_body["resources"][0]["resource"]["id"],
            serde_json::Value::String(external_identity_id.clone())
        );
        assert_eq!(get_body["resource"]["id"], external_identity_id);
        assert_eq!(get_body["resource"]["email_verified"], true);
        assert!(get_body["resource"]["email_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(!list_text.contains("Admin@Example.COM"));
        assert!(!list_text.contains("admin@example.com"));
        assert!(!get_text.contains("Admin@Example.COM"));
        assert!(!get_text.contains("admin@example.com"));
        assert_eq!(unlinked_body["resource"]["status"], "deleted");
        assert!(!unlinked_text.contains("Admin@Example.COM"));
        assert!(!unlinked_text.contains("admin@example.com"));
        assert!(store.audit_events().iter().any(|event| {
            event.event_type == "gateway.external_identity.unlink"
                && event.resource_kind == "ExternalIdentity"
                && event.resource_id == external_identity_id
        }));
    }

    #[tokio::test]
    async fn single_user_provider_is_hidden_until_credentials_are_configured() {
        let store = InMemoryGatewayStore::default();

        let providers = get_public(store.clone(), "/auth/v1/providers").await;
        let provider_status = providers.status();
        let provider_body = response_json(providers).await;
        let direct_provider =
            get_public(store.clone(), "/auth/v1/providers/local_single_user").await;
        let direct_provider_status = direct_provider.status();
        let provider_login_start =
            get_public(store.clone(), "/auth/v1/providers/local_single_user/login").await;
        let provider_login_start_status = provider_login_start.status();
        let login = post_public_json_with_config(
            store,
            GatewayConfig::default(),
            "/auth/v1/single-user/login",
            json!({
                "username": "admin",
                "password": "password"
            }),
        )
        .await;
        let login_status = login.status();
        let login_body = response_json(login).await;

        assert_eq!(provider_status, StatusCode::OK);
        assert_eq!(provider_body["resources"].as_array().map_or(0, Vec::len), 0);
        assert_eq!(direct_provider_status, StatusCode::NOT_FOUND);
        assert_eq!(provider_login_start_status, StatusCode::NOT_FOUND);
        assert_eq!(login_status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(login_body["error"]["code"], "gateway.runtime.not_ready");
    }

    #[tokio::test]
    async fn single_user_login_bootstraps_default_project_and_session() {
        let store = InMemoryGatewayStore::default();
        let config = gateway_config_with_single_user();

        let providers =
            get_public_with_config(store.clone(), config.clone(), "/auth/v1/providers").await;
        let provider_status = providers.status();
        let provider_body = response_json(providers).await;
        let direct_provider = get_public_with_config(
            store.clone(),
            config.clone(),
            "/auth/v1/providers/local_single_user",
        )
        .await;
        let direct_provider_status = direct_provider.status();
        let provider_login_start = get_public_with_config(
            store.clone(),
            config.clone(),
            "/auth/v1/providers/local_single_user/login",
        )
        .await;
        let provider_login_start_status = provider_login_start.status();
        let failed = post_public_json_with_config(
            store.clone(),
            config.clone(),
            "/auth/v1/single-user/login",
            json!({
                "username": "admin",
                "password": "wrong-password"
            }),
        )
        .await;
        let failed_status = failed.status();
        let success = post_public_json_with_config(
            store.clone(),
            config,
            "/auth/v1/single-user/login",
            json!({
                "username": "admin",
                "password": "correct horse battery staple"
            }),
        )
        .await;
        let success_status = success.status();
        let success_body = response_json(success).await;
        let success_text = serde_json::to_string(&success_body)
            .unwrap_or_else(|error| panic!("success response should serialize: {error}"));
        let session_token = success_body["session"]["session_token"]
            .as_str()
            .unwrap_or_else(|| panic!("session token should be present"))
            .to_owned();
        let admin_projects = get_admin_with_project(
            store.clone(),
            &session_token,
            SINGLE_USER_PROJECT_ID,
            "/admin/v1/projects",
        )
        .await;
        let admin_projects_status = admin_projects.status();
        let admin_projects_body = response_json(admin_projects).await;
        let admin_projects_without_header =
            get_admin_without_project(store.clone(), &session_token, "/admin/v1/projects").await;
        let admin_projects_without_header_status = admin_projects_without_header.status();

        assert_eq!(provider_status, StatusCode::OK);
        assert_eq!(direct_provider_status, StatusCode::OK);
        assert_eq!(provider_login_start_status, StatusCode::BAD_REQUEST);
        assert_eq!(failed_status, StatusCode::UNAUTHORIZED);
        assert_eq!(success_status, StatusCode::OK);
        assert_eq!(provider_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(
            provider_body["resources"][0]["id"],
            serde_json::Value::String(SINGLE_USER_PROVIDER_ID.to_owned())
        );
        assert_eq!(
            provider_body["resources"][0]["provider_kind"],
            "single_user_password"
        );
        assert!(session_token.starts_with(SESSION_TOKEN_PREFIX));
        assert_eq!(success_body["tenant"]["id"], SINGLE_USER_TENANT_ID);
        assert_eq!(success_body["project"]["id"], SINGLE_USER_PROJECT_ID);
        assert!(!success_text.contains("correct horse battery staple"));
        assert!(store
            .project_membership(SINGLE_USER_ID, SINGLE_USER_PROJECT_ID)
            .is_some());
        assert!(store.action_grants().iter().any(|grant| {
            grant.tenant_id == SINGLE_USER_TENANT_ID && grant.principal_id == SINGLE_USER_ID
        }));
        assert_eq!(admin_projects_status, StatusCode::OK);
        assert_eq!(admin_projects_without_header_status, StatusCode::OK);
        assert_eq!(
            admin_projects_body["resources"]
                .as_array()
                .map_or(0, Vec::len),
            1
        );
    }

    #[tokio::test]
    async fn auth_session_read_and_logout_revoke_current_session() {
        let store = InMemoryGatewayStore::default();
        let config = gateway_config_with_single_user();
        let login = post_public_json_with_config(
            store.clone(),
            config,
            "/auth/v1/single-user/login",
            json!({
                "username": "admin",
                "password": "correct horse battery staple"
            }),
        )
        .await;
        let login_status = login.status();
        let login_body = response_json(login).await;
        let session_token = login_body["session"]["session_token"]
            .as_str()
            .unwrap_or_else(|| panic!("session token should be present"))
            .to_owned();

        let session =
            get_public_with_bearer(store.clone(), &session_token, "/auth/v1/session").await;
        let session_status = session.status();
        let session_body = response_json(session).await;
        let session_text = serde_json::to_string(&session_body)
            .unwrap_or_else(|error| panic!("session response should serialize: {error}"));
        let logout =
            post_public_with_bearer(store.clone(), &session_token, "/auth/v1/logout").await;
        let logout_status = logout.status();
        let logout_body = response_json(logout).await;
        let revoked_session =
            get_public_with_bearer(store.clone(), &session_token, "/auth/v1/session").await;
        let revoked_session_status = revoked_session.status();
        let admin_after_logout =
            get_admin(store.clone(), &session_token, "/admin/v1/projects").await;
        let admin_after_logout_status = admin_after_logout.status();

        assert_eq!(login_status, StatusCode::OK);
        assert_eq!(session_status, StatusCode::OK);
        assert_eq!(session_body["schema"], "gateway.auth.session.v1");
        assert_eq!(session_body["session"]["kind"], "auth_session");
        assert_eq!(session_body["session"]["principal_id"], SINGLE_USER_ID);
        assert_eq!(
            session_body["session"]["active_organization_id"],
            SINGLE_USER_ORGANIZATION_ID
        );
        assert_eq!(
            session_body["session"]["active_project_id"],
            SINGLE_USER_PROJECT_ID
        );
        assert_eq!(session_body["session"]["status"], "active");
        assert_eq!(session_body["user"]["id"], SINGLE_USER_ID);
        assert_eq!(
            session_body["user"]["default_organization_id"],
            SINGLE_USER_ORGANIZATION_ID
        );
        assert_eq!(
            session_body["user"]["default_project_id"],
            SINGLE_USER_PROJECT_ID
        );
        assert_eq!(
            session_body["organization_memberships"][0]["organization_id"],
            SINGLE_USER_ORGANIZATION_ID
        );
        assert_eq!(
            session_body["project_memberships"][0]["project_id"],
            SINGLE_USER_PROJECT_ID
        );
        assert!(!session_text.contains(&session_token));
        assert!(!session_text.contains("session_hash"));
        assert_eq!(logout_status, StatusCode::OK);
        assert_eq!(logout_body["schema"], "gateway.auth.logout.v1");
        assert_eq!(logout_body["session"]["status"], "revoked");
        assert_eq!(revoked_session_status, StatusCode::UNAUTHORIZED);
        assert_eq!(admin_after_logout_status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_session_context_update_endpoints_validate_memberships() {
        let store = InMemoryGatewayStore::default();
        let config = gateway_config_with_single_user();
        let login = post_public_json_with_config(
            store.clone(),
            config,
            "/auth/v1/single-user/login",
            json!({
                "username": "admin",
                "password": "correct horse battery staple"
            }),
        )
        .await;
        let login_body = response_json(login).await;
        let session_token = login_body["session"]["session_token"]
            .as_str()
            .unwrap_or_else(|| panic!("session token should be present"))
            .to_owned();

        let active_project = post_public_json_with_bearer(
            store.clone(),
            &session_token,
            "/auth/v1/session/active-project",
            json!({
                "project_id": SINGLE_USER_PROJECT_ID
            }),
        )
        .await;
        let active_project_status = active_project.status();
        let active_project_body = response_json(active_project).await;
        let active_organization = post_public_json_with_bearer(
            store.clone(),
            &session_token,
            "/auth/v1/session/active-organization",
            json!({
                "organization_id": SINGLE_USER_ORGANIZATION_ID
            }),
        )
        .await;
        let active_organization_status = active_organization.status();
        let active_organization_body = response_json(active_organization).await;
        let default_organization = post_public_json_with_bearer(
            store.clone(),
            &session_token,
            "/auth/v1/session/default-organization",
            json!({
                "organization_id": SINGLE_USER_ORGANIZATION_ID,
                "project_id": SINGLE_USER_PROJECT_ID
            }),
        )
        .await;
        let default_organization_status = default_organization.status();
        let default_organization_body = response_json(default_organization).await;
        let missing_project = post_public_json_with_bearer(
            store,
            &session_token,
            "/auth/v1/session/active-project",
            json!({
                "project_id": "prj_missing"
            }),
        )
        .await;
        let missing_project_status = missing_project.status();

        assert_eq!(active_project_status, StatusCode::OK);
        assert_eq!(active_organization_status, StatusCode::OK);
        assert_eq!(default_organization_status, StatusCode::OK);
        assert_eq!(missing_project_status, StatusCode::NOT_FOUND);
        assert_eq!(
            active_project_body["session"]["active_organization_id"],
            SINGLE_USER_ORGANIZATION_ID
        );
        assert_eq!(
            active_project_body["session"]["active_project_id"],
            SINGLE_USER_PROJECT_ID
        );
        assert_eq!(
            active_organization_body["session"]["active_project_id"],
            SINGLE_USER_PROJECT_ID
        );
        assert_eq!(
            default_organization_body["user"]["default_organization_id"],
            SINGLE_USER_ORGANIZATION_ID
        );
        assert_eq!(
            default_organization_body["user"]["default_project_id"],
            SINGLE_USER_PROJECT_ID
        );
        assert!(!default_organization_body
            .to_string()
            .contains(&session_token));
        assert!(!default_organization_body
            .to_string()
            .contains("session_hash"));
    }

    #[tokio::test]
    async fn oidc_login_provider_start_uses_oidc_defaults_and_nonce() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let login_provider_id =
            create_oidc_login_provider_over_http(store.clone(), &raw_session).await;

        let start = get_public(
            store.clone(),
            &format!("/auth/v1/providers/{login_provider_id}/login"),
        )
        .await;
        let status = start.status();
        let body = response_json(start).await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["provider"]["provider_kind"], "oidc");
        assert!(body["authorization"]["nonce"]
            .as_str()
            .is_some_and(|nonce| nonce.starts_with("gwnc_")));
        assert!(body["authorization"]["authorization_url"]
            .as_str()
            .is_some_and(|url| {
                url.starts_with("https://login.example/oauth2/v1/authorize?")
                    && url.contains("scope=openid%20email%20profile")
                    && url.contains("nonce=gwnc_")
                    && url.contains("code_challenge_method=S256")
            }));
        assert!(!body.to_string().contains("sec_login_oidc_secret"));
    }

    #[tokio::test]
    async fn runtime_budget_block_enqueues_redacted_notification_outbox_event() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let notification_sink_id =
            create_stdout_notification_sink_over_http(store.clone(), &raw_session).await;
        let subscription = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}/subscriptions"),
            json!({
                "idempotency_key": "idem_budget_notification_subscription",
                "event_family": "budget",
                "filter_document": {
                    "event_types": ["gateway.budget.hard_block"],
                    "scope_kind": "project",
                    "scope_id": TEST_PROJECT_ID
                }
            }),
        )
        .await;
        assert_eq!(subscription.status(), StatusCode::OK);
        let policy = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/budget-policies",
            json!({
                "idempotency_key": "idem_budget_notification_policy",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "period": "calendar_month",
                "limit_kind": "requests",
                "hard_limit": 1,
                "reset_policy": "calendar_month",
                "overage_mode": "block_new_requests",
                "consistency_mode": "eventual"
            }),
        )
        .await;
        assert_eq!(policy.status(), StatusCode::OK);
        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        assert_eq!(first.status(), StatusCode::OK);

        let blocked = post_responses_request_with_body(
            store.clone(),
            &raw_key,
            json!({
                "model": "gpt-test",
                "input": "prompt text that must not enter notification payload"
            }),
        )
        .await;

        let status = blocked.status();
        let body = response_json(blocked).await;
        let events = store.notification_outbox_events_for_tenant(TEST_TENANT_ID);
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body["error"]["code"], "gateway.budget.exceeded");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_kind, "gateway.budget.hard_block");
        assert_eq!(events[0].status, "pending");
        assert_eq!(
            events[0].notification_sink_id.as_deref(),
            Some(notification_sink_id.as_str())
        );
        assert_eq!(events[0].payload_document["scope"]["id"], TEST_PROJECT_ID);
        assert_eq!(
            events[0].payload_document["redaction"]["request_body_included"],
            false
        );
        let payload_text = events[0].payload_document.to_string();
        assert!(!payload_text.contains("prompt text"));
        assert!(!payload_text.contains("sec_"));

        let attempts = deliver_due_notifications(
            &AppState::new(GatewayConfig::default(), store.clone()),
            TEST_TENANT_ID,
            chrono::Utc::now(),
            10,
        );

        let delivered = store.notification_outbox_events_for_tenant(TEST_TENANT_ID);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].status, "succeeded");
        assert_eq!(delivered[0].status, "delivered");
        assert_eq!(delivered[0].attempt_count, 1);
    }

    #[tokio::test]
    async fn notification_delivery_retry_failure_does_not_block_runtime_requests() {
        let (store, raw_session, raw_key) = gateway_store_with_admin_session_and_runtime_access();
        publish_catalog_snapshot(&store, catalog_payload());
        let notification_sink_id = create_webhook_notification_sink_over_http(
            store.clone(),
            &raw_session,
            "idem_quota_notification_retry_sink",
            "quota-retry-webhook",
            "https://retry.example/gateway",
        )
        .await;
        create_quota_notification_subscription_and_policy(
            store.clone(),
            &raw_session,
            &notification_sink_id,
        )
        .await;
        let first = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        assert_eq!(first.status(), StatusCode::OK);
        let blocked = post_responses_request(store.clone(), &raw_key, "gpt-test").await;
        assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

        let first_attempt = deliver_first_due_notification(store.clone(), chrono::Utc::now());
        let events = store.notification_outbox_events_for_tenant(TEST_TENANT_ID);
        assert_retryable_webhook_attempt(&first_attempt, "notification_webhook_retryable_failure");
        assert_eq!(events[0].status, "retryable_failed");
        assert_eq!(events[0].attempt_count, 1);
        assert!(events[0].next_attempt_at.is_some());
        assert_eq!(store.usage_events_for_tenant(TEST_TENANT_ID).len(), 1);

        let second_due_at = events[0]
            .next_attempt_at
            .unwrap_or_else(|| panic!("retryable event should have next attempt"));
        let second_attempt = deliver_first_due_notification(store.clone(), second_due_at);
        let retried = store.notification_outbox_events_for_tenant(TEST_TENANT_ID);
        assert_retryable_webhook_attempt(&second_attempt, "notification_webhook_retryable_failure");
        assert_eq!(retried[0].status, "retryable_failed");
        assert_eq!(retried[0].attempt_count, 2);

        let third_due_at = retried[0]
            .next_attempt_at
            .unwrap_or_else(|| panic!("second retryable event should have next attempt"));
        let dead_letter_attempt = deliver_first_due_notification(store.clone(), third_due_at);
        let dead_lettered = store.notification_outbox_events_for_tenant(TEST_TENANT_ID);
        assert_eq!(dead_letter_attempt.status, "dead_lettered");
        assert_eq!(
            dead_letter_attempt.error_message.as_deref(),
            Some("notification_webhook_retry_exhausted")
        );
        assert_eq!(dead_lettered[0].status, "dead_lettered");
        assert_eq!(dead_lettered[0].attempt_count, 3);
        assert!(dead_lettered[0].next_attempt_at.is_none());
        assert!(deliver_due_notifications(
            &AppState::new(GatewayConfig::default(), store.clone()),
            TEST_TENANT_ID,
            third_due_at + chrono::Duration::seconds(60),
            10,
        )
        .is_empty());
    }

    #[tokio::test]
    async fn notification_webhook_delivery_signs_payload_and_uses_rotated_secret() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let notification_sink_id =
            create_notification_sink_over_http(store.clone(), &raw_session).await;
        let first_signing_secret_ref_id = store
            .notification_sink(&notification_sink_id)
            .and_then(|sink| sink.signing_secret_ref_id)
            .unwrap_or_else(|| panic!("notification sink should have signing secret"));
        let first_event_id = append_synthetic_notification_event(
            &store,
            &notification_sink_id,
            "notification_webhook_delivery_first",
            "synthetic",
        );
        let first_attempt = deliver_first_due_notification(store.clone(), chrono::Utc::now());
        let first_signature_sha256 = assert_signed_webhook_attempt(
            &first_attempt,
            &first_event_id,
            &first_signing_secret_ref_id,
        );
        let rotated_signing_secret_ref_id = create_secret_ref_over_http(
            store.clone(),
            &raw_session,
            "notification-webhook-rotated-secret-value",
        )
        .await;
        rotate_notification_sink_signing_secret(
            store.clone(),
            &raw_session,
            &notification_sink_id,
            &rotated_signing_secret_ref_id,
        )
        .await;
        let rotated_event_id = append_synthetic_notification_event(
            &store,
            &notification_sink_id,
            "notification_webhook_delivery_rotated",
            "rotated",
        );
        let rotated_attempt = deliver_first_due_notification(
            store.clone(),
            chrono::Utc::now() + Duration::seconds(1),
        );
        let rotated_signature_sha256 = assert_signed_webhook_attempt(
            &rotated_attempt,
            &rotated_event_id,
            &rotated_signing_secret_ref_id,
        );

        assert_ne!(rotated_signature_sha256, first_signature_sha256);
        let audit_text = serde_json::to_string(&store.audit_events())
            .unwrap_or_else(|error| panic!("audit events should serialize: {error}"));
        assert!(!audit_text.contains("notification-webhook-rotated-secret-value"));
        assert!(store.audit_events().iter().any(|event| {
            event.event_type == "gateway.notification_sink.update"
                && event.redacted_diff["signing_secret_ref_id"]["after"] == "sec_***"
        }));
    }

    #[tokio::test]
    async fn notification_webhook_delivery_records_permanent_failure_without_retry() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let signing_secret_ref_id = create_secret_ref_over_http(
            store.clone(),
            &raw_session,
            "notification-webhook-permanent-secret-value",
        )
        .await;
        let sink = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/notification/sinks",
            json!({
                "idempotency_key": "idem_permanent_notification_sink",
                "project_id": "prj_test",
                "name": "permanent-webhook",
                "sink_kind": "webhook",
                "endpoint_config": {
                    "url": "https://permanent.example/gateway",
                    "retry_policy": {
                        "max_attempts": 3,
                        "max_duration_seconds": 3600
                    },
                    "batching": false
                },
                "signing_secret_ref_id": signing_secret_ref_id
            }),
        )
        .await;
        assert_eq!(sink.status(), StatusCode::OK);
        let sink_body = response_json(sink).await;
        let notification_sink_id = sink_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("notification sink id should be present"))
            .to_owned();
        store.append_notification_outbox_event(
            CreateNotificationOutboxEventRequest {
                tenant_id: TEST_TENANT_ID.to_owned(),
                organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
                project_id: Some(TEST_PROJECT_ID.to_owned()),
                notification_subscription_id: None,
                notification_sink_id: Some(notification_sink_id),
                event_kind: "gateway.delivery.synthetic".to_owned(),
                dedupe_key: "notification_webhook_delivery_permanent".to_owned(),
                payload_document: json!({
                    "schema": "gateway.notification.synthetic.v1",
                    "event": {"kind": "permanent"}
                }),
                next_attempt_at: None,
            },
            chrono::Utc::now(),
        );

        let attempts = deliver_due_notifications(
            &AppState::new(GatewayConfig::default(), store.clone()),
            TEST_TENANT_ID,
            chrono::Utc::now(),
            10,
        );
        let events = store.notification_outbox_events_for_tenant(TEST_TENANT_ID);

        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0].status, "permanent_failed");
        assert_eq!(attempts[0].response_status, Some(410));
        assert_eq!(
            attempts[0].error_message.as_deref(),
            Some("notification_webhook_permanent_failure")
        );
        assert_eq!(events[0].status, "permanent_failed");
        assert_eq!(events[0].attempt_count, 1);
        assert!(events[0].next_attempt_at.is_none());
        assert!(deliver_due_notifications(
            &AppState::new(GatewayConfig::default(), store.clone()),
            TEST_TENANT_ID,
            chrono::Utc::now() + Duration::seconds(60),
            10,
        )
        .is_empty());
    }

    #[tokio::test]
    async fn admin_route_policy_validate_catches_missing_graph_refs() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/route-policies:validate",
            json!({
                "idempotency_key": "idem_route_policy_validate",
                "name": "",
                "model_alias_id": "ma_missing",
                "routing_group_id": "rg_missing"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 3);
        assert!(store.route_policies_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_route_policy_create_and_bind_model_alias() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;
        let model_target_id = create_model_target_over_http(
            store.clone(),
            &raw_session,
            &endpoint_id,
            &credential_id,
        )
        .await;
        let routing_group_id = create_routing_group_over_http(store.clone(), &raw_session).await;
        create_routing_group_target_over_http(
            store.clone(),
            &raw_session,
            &routing_group_id,
            &model_target_id,
        )
        .await;
        let model_alias_id = create_model_alias_over_http(store.clone(), &raw_session).await;
        let route_policy_id = create_route_policy_over_http(
            store.clone(),
            &raw_session,
            &model_alias_id,
            &routing_group_id,
        )
        .await;

        let route_policy_list =
            get_admin(store.clone(), &raw_session, "/admin/v1/route-policies").await;
        let route_policy_list_status = route_policy_list.status();
        let route_policy_list_body = response_json(route_policy_list).await;
        let route_policy_get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/route-policies/{route_policy_id}"),
        )
        .await;
        let route_policy_get_status = route_policy_get.status();
        let route_policy_get_body = response_json(route_policy_get).await;
        let alias_update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/model-aliases/{model_alias_id}"),
            json!({
                "expected_version": 1,
                "route_policy_id": route_policy_id,
                "reason": "Bind default route policy."
            }),
        )
        .await;
        let alias_update_status = alias_update.status();
        let alias_update_body = response_json(alias_update).await;
        let route_policy_update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/route-policies/{route_policy_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable route policy."
            }),
        )
        .await;
        let route_policy_update_status = route_policy_update.status();
        let route_policy_update_body = response_json(route_policy_update).await;

        assert_eq!(route_policy_list_status, StatusCode::OK);
        assert_eq!(route_policy_get_status, StatusCode::OK);
        assert_eq!(alias_update_status, StatusCode::OK);
        assert_eq!(route_policy_update_status, StatusCode::OK);
        assert_eq!(
            route_policy_list_body["resources"]
                .as_array()
                .map_or(0, Vec::len),
            1
        );
        assert_eq!(route_policy_get_body["resource"]["id"], route_policy_id);
        assert_eq!(
            alias_update_body["resource"]["route_policy_id"],
            route_policy_id
        );
        assert_eq!(alias_update_body["resource"]["version"], 2);
        assert_eq!(route_policy_update_body["resource"]["status"], "disabled");
        assert_eq!(route_policy_update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 9);
        assert_eq!(
            store.audit_events()[7].event_type,
            "gateway.model_alias.update"
        );
        assert_eq!(
            store.audit_events()[8].event_type,
            "gateway.route_policy.update"
        );
    }

    #[tokio::test]
    async fn admin_provider_grant_validate_catches_invalid_shape() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-grants:validate",
            json!({
                "idempotency_key": "idem_provider_grant_validate",
                "scope_kind": "tenant",
                "scope_id": TEST_TENANT_ID,
                "resource_kind": "pricing_sku",
                "resource_id": "psku_missing",
                "effect": "allow",
                "closure_mode": "deny_descendants"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 3);
        assert!(store.provider_grants_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_provider_grant_create_is_idempotent_and_updates_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let model_alias_id = create_model_alias_over_http(store.clone(), &raw_session).await;
        let request = json!({
            "idempotency_key": "idem_provider_grant_create",
            "scope_kind": "project",
            "scope_id": "prj_test",
            "resource_kind": "model_alias",
            "resource_id": model_alias_id,
            "effect": "allow",
            "closure_mode": "include_descendants"
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-grants",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-grants",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;
        let provider_grant_id = first_body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("provider grant id should be present"))
            .to_owned();
        let list = get_admin(store.clone(), &raw_session, "/admin/v1/provider-grants").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/provider-grants/{provider_grant_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/provider-grants/{provider_grant_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable provider grant."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "provider_grant");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["project_id"], "prj_test");
        assert_eq!(first_body["resource"]["effect"], "allow");
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], provider_grant_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 3);
        assert_eq!(
            store.audit_events()[2].event_type,
            "gateway.provider_grant.update"
        );
    }

    #[tokio::test]
    async fn admin_provider_grant_allows_pricing_sku_resource() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let pricing_sku_id = create_pricing_sku_over_http(store.clone(), &raw_session).await;

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/provider-grants",
            json!({
                "idempotency_key": "idem_provider_grant_pricing_sku",
                "scope_kind": "organization",
                "scope_id": "org_test",
                "resource_kind": "pricing_sku",
                "resource_id": pricing_sku_id,
                "effect": "allow",
                "closure_mode": "self_only"
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"]["resource_kind"], "pricing_sku");
        assert_eq!(body["resource"]["organization_id"], "org_test");
        assert_eq!(body["resource"]["project_id"], serde_json::Value::Null);
        assert_eq!(store.provider_grants_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.provider_grant.create"
        );
    }

    #[tokio::test]
    async fn admin_routing_group_validate_catches_unknown_organization() {
        let (store, raw_session) = gateway_store_with_admin_session();

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/routing-groups:validate",
            json!({
                "idempotency_key": "idem_routing_group_validate",
                "organization_id": "org_missing",
                "name": "primary-openai",
                "protocol_family": "openai_responses",
                "purpose": "Primary OpenAI-compatible pool."
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 1);
        assert!(store.routing_groups_for_tenant(TEST_TENANT_ID).is_empty());
    }

    #[tokio::test]
    async fn admin_routing_group_create_is_idempotent_and_audited() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let request = json!({
            "idempotency_key": "idem_routing_group_create",
            "organization_id": "org_test",
            "name": "primary-openai",
            "protocol_family": "openai_responses",
            "purpose": "Primary OpenAI-compatible pool."
        });

        let first = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/routing-groups",
            request.clone(),
        )
        .await;
        let first_status = first.status();
        let first_body = response_json(first).await;
        let second = post_admin_json(
            store.clone(),
            &raw_session,
            "/admin/v1/routing-groups",
            request,
        )
        .await;
        let second_status = second.status();
        let second_body = response_json(second).await;

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first_body["resource"]["kind"], "routing_group");
        assert_eq!(first_body["resource"]["organization_id"], "org_test");
        assert_eq!(first_body["resource"]["name"], "primary-openai");
        assert_eq!(
            first_body["resource"]["protocol_family"],
            "openai_responses"
        );
        assert_eq!(second_body["idempotency_replayed"], true);
        assert_eq!(store.routing_groups_for_tenant(TEST_TENANT_ID).len(), 1);
        assert_eq!(store.audit_events().len(), 1);
        assert_eq!(
            store.audit_events()[0].event_type,
            "gateway.routing_group.create"
        );
    }

    #[tokio::test]
    async fn admin_routing_group_list_get_and_update_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let routing_group_id = create_routing_group_over_http(store.clone(), &raw_session).await;

        let list = get_admin(store.clone(), &raw_session, "/admin/v1/routing-groups").await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/routing-groups/{routing_group_id}"),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/routing-groups/{routing_group_id}"),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable routing group."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], routing_group_id);
        assert_eq!(update_body["resource"]["status"], "disabled");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 2);
        assert_eq!(
            store.audit_events()[1].event_type,
            "gateway.routing_group.update"
        );
    }

    #[tokio::test]
    async fn admin_routing_group_target_validate_catches_missing_target() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let routing_group_id = create_routing_group_over_http(store.clone(), &raw_session).await;

        let response = post_admin_json(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/routing-groups/{routing_group_id}/targets:validate"),
            json!({
                "idempotency_key": "idem_routing_group_target_validate",
                "model_target_id": "mt_missing",
                "weight": 0,
                "priority": 10
            }),
        )
        .await;

        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["valid"], false);
        assert_eq!(body["errors"].as_array().map_or(0, Vec::len), 2);
        assert!(store
            .routing_group_targets_for_group(TEST_TENANT_ID, &routing_group_id)
            .is_empty());
    }

    #[tokio::test]
    async fn admin_routing_group_target_create_list_get_and_update_status() {
        let (store, raw_session) = gateway_store_with_admin_session();
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), &raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), &raw_session, &endpoint_id).await;
        let model_target_id = create_model_target_over_http(
            store.clone(),
            &raw_session,
            &endpoint_id,
            &credential_id,
        )
        .await;
        let routing_group_id = create_routing_group_over_http(store.clone(), &raw_session).await;
        let routing_group_target_id = create_routing_group_target_over_http(
            store.clone(),
            &raw_session,
            &routing_group_id,
            &model_target_id,
        )
        .await;

        let list = get_admin(
            store.clone(),
            &raw_session,
            &format!("/admin/v1/routing-groups/{routing_group_id}/targets"),
        )
        .await;
        let list_status = list.status();
        let list_body = response_json(list).await;
        let get = get_admin(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/routing-groups/{routing_group_id}/targets/{routing_group_target_id}"
            ),
        )
        .await;
        let get_status = get.status();
        let get_body = response_json(get).await;
        let update = patch_admin_json(
            store.clone(),
            &raw_session,
            &format!(
                "/admin/v1/routing-groups/{routing_group_id}/targets/{routing_group_target_id}"
            ),
            json!({
                "expected_version": 1,
                "status": "draining",
                "reason": "Drain target before maintenance."
            }),
        )
        .await;
        let update_status = update.status();
        let update_body = response_json(update).await;

        assert_eq!(list_status, StatusCode::OK);
        assert_eq!(get_status, StatusCode::OK);
        assert_eq!(update_status, StatusCode::OK);
        assert_eq!(list_body["resources"].as_array().map_or(0, Vec::len), 1);
        assert_eq!(get_body["resource"]["id"], routing_group_target_id);
        assert_eq!(update_body["resource"]["status"], "draining");
        assert_eq!(update_body["resource"]["version"], 2);
        assert_eq!(store.audit_events().len(), 6);
        assert_eq!(
            store.audit_events()[5].event_type,
            "gateway.routing_group_target.update"
        );
    }

    fn gateway_store_with_runtime_access(include_grants: bool) -> (InMemoryGatewayStore, String) {
        let fixture = FoundationTestFixture::runtime_access(include_grants);
        (fixture.store, fixture.raw_api_key)
    }

    fn gateway_store_with_admin_session() -> (InMemoryGatewayStore, String) {
        let fixture = FoundationTestFixture::runtime_access(false);
        let store = fixture.store;
        let raw_session = insert_admin_session(&store);
        seed_tenant_owner_grants(&store);
        (store, raw_session)
    }

    fn gateway_store_with_admin_session_and_runtime_access(
    ) -> (InMemoryGatewayStore, String, String) {
        let fixture = FoundationTestFixture::runtime_access(true);
        let store = fixture.store;
        let raw_key = fixture.raw_api_key;
        let raw_session = insert_admin_session(&store);
        seed_tenant_owner_grants(&store);
        (store, raw_session, raw_key)
    }

    struct AdminGraphFixture {
        endpoint_id: String,
        credential_id: String,
        target_id: String,
        alias_id: String,
        alias_name: String,
        routing_group_id: String,
        routing_group_target_id: String,
        route_policy_id: String,
    }

    async fn create_admin_graph_for_dashboards(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> AdminGraphFixture {
        let endpoint_id = create_provider_endpoint_over_http(store.clone(), raw_session).await;
        let credential_id =
            create_upstream_credential_over_http(store.clone(), raw_session, &endpoint_id).await;
        let target_id =
            create_model_target_over_http(store.clone(), raw_session, &endpoint_id, &credential_id)
                .await;
        let alias_id = create_model_alias_over_http(store.clone(), raw_session).await;
        let routing_group_id = create_routing_group_over_http(store.clone(), raw_session).await;
        let route_policy_id =
            create_route_policy_over_http(store.clone(), raw_session, &alias_id, &routing_group_id)
                .await;
        let routing_group_target_id = create_routing_group_target_over_http(
            store.clone(),
            raw_session,
            &routing_group_id,
            &target_id,
        )
        .await;
        let alias_name = store.model_alias(&alias_id).map_or_else(
            || panic!("model alias should exist"),
            |alias| alias.alias_name,
        );
        AdminGraphFixture {
            endpoint_id,
            credential_id,
            target_id,
            alias_id,
            alias_name,
            routing_group_id,
            routing_group_target_id,
            route_policy_id,
        }
    }

    fn recorded_api_key_id(store: &InMemoryGatewayStore) -> String {
        store
            .route_decisions()
            .into_iter()
            .find(|decision| decision.tenant_id == TEST_TENANT_ID)
            .and_then(|decision| decision.api_key_id)
            .unwrap_or_else(|| panic!("API key id should be recorded"))
    }

    fn record_cross_tenant_dashboard_probe(
        store: &InMemoryGatewayStore,
        graph: &AdminGraphFixture,
        api_key_id: &str,
    ) {
        store.record_route_decision(RouteDecisionRecord {
            route_decision_id: "rd_cross_tenant_dashboard_scope".to_owned(),
            tenant_id: "ten_other".to_owned(),
            organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
            project_id: Some(TEST_PROJECT_ID.to_owned()),
            principal_id: Some(TEST_USER_ID.to_owned()),
            api_key_id: Some(api_key_id.to_owned()),
            actor_id: TEST_USER_ID.to_owned(),
            actor_kind: ActorKind::User,
            request_id: "req_cross_tenant_dashboard_scope".to_owned(),
            protocol_family: ProtocolFamily::OpenAiResponses,
            config_snapshot_id: None,
            config_version: None,
            model_alias_id: Some(graph.alias_id.clone()),
            alias_name: graph.alias_name.clone(),
            route_policy_id: Some(graph.route_policy_id.clone()),
            routing_group_id: Some(graph.routing_group_id.clone()),
            model_target_id: Some(graph.target_id.clone()),
            provider_endpoint_id: Some(graph.endpoint_id.clone()),
            upstream_credential_id: Some(graph.credential_id.clone()),
            filtered_summary: Vec::new(),
            status: RouteDecisionStatus::Blocked,
            reason: "cross_tenant_probe".to_owned(),
            occurred_at: chrono::Utc::now(),
        });
    }

    fn record_cross_tenant_usage_probe(store: &InMemoryGatewayStore) {
        store.record_usage_event(UsageEventRecord {
            usage_event_id: "use_cross_tenant_dashboard_scope".to_owned(),
            tenant_id: "ten_other".to_owned(),
            organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
            project_id: Some(TEST_PROJECT_ID.to_owned()),
            principal_id: Some(TEST_USER_ID.to_owned()),
            project_member_id: Some("pm_test".to_owned()),
            service_account_id: None,
            api_key_id: None,
            request_id: "req_cross_tenant_usage".to_owned(),
            protocol_family: ProtocolFamily::OpenAiResponses,
            route_decision_id: None,
            model_alias_id: Some("ma_test".to_owned()),
            model_target_id: Some("mt_openai".to_owned()),
            route_policy_id: Some("rp_test".to_owned()),
            routing_group_id: Some("rg_test".to_owned()),
            provider_endpoint_id: Some("pep_openai".to_owned()),
            upstream_credential_id: Some("upc_openai".to_owned()),
            usage_confidence: "exact".to_owned(),
            latency_ms: Some(10),
            time_to_first_token_ms: None,
            status: "success".to_owned(),
            usage_payload: json!({
                "input_tokens": 99,
                "output_tokens": 99,
                "total_tokens": 198,
                "reasoning_tokens": 0,
                "image_input_units": 0,
                "image_output_units": 0,
                "audio_input_units": 0,
                "audio_output_units": 0,
                "request_units": 0
            }),
            cost_payload: json!({
                "currency": "USD",
                "unit": "micro_usd",
                "total_cost": 9900,
                "pricing_version": "test"
            }),
            occurred_at: chrono::Utc::now(),
        });
    }

    fn record_service_account_route_evidence(
        store: &InMemoryGatewayStore,
        service_account_id: &str,
    ) {
        let route_decision_id = "rd_service_account_dashboard".to_owned();
        let now = chrono::Utc::now();
        store.record_route_decision(RouteDecisionRecord {
            route_decision_id: route_decision_id.clone(),
            tenant_id: TEST_TENANT_ID.to_owned(),
            organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
            project_id: Some(TEST_PROJECT_ID.to_owned()),
            principal_id: Some(service_account_id.to_owned()),
            api_key_id: None,
            actor_id: service_account_id.to_owned(),
            actor_kind: ActorKind::ServiceAccount,
            request_id: "req_service_account_dashboard".to_owned(),
            protocol_family: ProtocolFamily::OpenAiResponses,
            config_snapshot_id: None,
            config_version: Some(1),
            model_alias_id: Some("ma_test".to_owned()),
            alias_name: "gpt-test".to_owned(),
            route_policy_id: Some("rp_test".to_owned()),
            routing_group_id: Some("rg_test".to_owned()),
            model_target_id: Some("mt_openai".to_owned()),
            provider_endpoint_id: Some("pep_openai".to_owned()),
            upstream_credential_id: Some("upc_openai".to_owned()),
            filtered_summary: Vec::new(),
            status: RouteDecisionStatus::Selected,
            reason: "selected".to_owned(),
            occurred_at: now,
        });
        store.record_route_decision(RouteDecisionRecord {
            route_decision_id: "rd_cross_tenant_service_account_dashboard".to_owned(),
            tenant_id: "ten_other".to_owned(),
            organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
            project_id: Some(TEST_PROJECT_ID.to_owned()),
            principal_id: Some(service_account_id.to_owned()),
            api_key_id: None,
            actor_id: service_account_id.to_owned(),
            actor_kind: ActorKind::ServiceAccount,
            request_id: "req_cross_tenant_service_account_dashboard".to_owned(),
            protocol_family: ProtocolFamily::OpenAiResponses,
            config_snapshot_id: None,
            config_version: Some(1),
            model_alias_id: Some("ma_test".to_owned()),
            alias_name: "gpt-test".to_owned(),
            route_policy_id: Some("rp_test".to_owned()),
            routing_group_id: Some("rg_test".to_owned()),
            model_target_id: Some("mt_openai".to_owned()),
            provider_endpoint_id: Some("pep_openai".to_owned()),
            upstream_credential_id: Some("upc_openai".to_owned()),
            filtered_summary: Vec::new(),
            status: RouteDecisionStatus::Blocked,
            reason: "cross_tenant_probe".to_owned(),
            occurred_at: now,
        });
        store.record_route_attempt(RouteAttemptRecord {
            route_attempt_event_id: "rae_service_account_dashboard".to_owned(),
            route_decision_id,
            attempt_index: 0,
            routing_group_id: "rg_test".to_owned(),
            model_target_id: "mt_openai".to_owned(),
            provider_endpoint_id: "pep_openai".to_owned(),
            status: RouteAttemptStatus::Completed,
            started_at: now,
            ended_at: Some(now + Duration::milliseconds(10)),
        });
    }

    async fn assert_dashboard_scope(
        store: InMemoryGatewayStore,
        raw_session: &str,
        uri: &str,
        schema: &str,
        scope_kind: &str,
        scope_id: &str,
    ) {
        let response = get_admin(store, raw_session, uri).await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{uri}: {body:?}");
        assert_eq!(body["schema"], schema);
        assert_eq!(body["scope"]["kind"], scope_kind);
        assert_eq!(body["scope"]["id"], scope_id);
        assert_eq!(body["measures"]["request_count"], 1);
        assert_eq!(body["measures"]["success_count"], 1);
        assert_eq!(body["measures"]["attempt_count"], 1);
        assert_eq!(body["measures"]["blocked_count"], 0);
        assert_eq!(body["measures"]["input_tokens"], 1);
        assert_eq!(body["measures"]["output_tokens"], 2);
        assert_eq!(body["measures"]["estimated_cost"], 0);
        assert_eq!(body["measures"]["usage_missing_count"], 0);
        assert_eq!(body["sources"]["route_evidence"], "durable");
        assert_eq!(
            body["sources"]["usage_ledger_rollups"],
            "durable_ledger_buckets"
        );
    }

    fn assert_usage_export_manifest_body(body: &serde_json::Value) {
        assert_eq!(body["resource"]["export_kind"], "usage");
        assert_eq!(body["resource"]["record_count"], 1);
        assert_eq!(body["manifest"]["record_count"], 1);
        assert!(body["manifest"]["checksum"]
            .as_str()
            .is_some_and(|checksum| checksum.starts_with("sha256:")));
        assert!(body["manifest"]["object_ref"]
            .as_str()
            .is_some_and(|object_ref| object_ref.starts_with("memory://gateway-exports/")));
        assert!(body["manifest"]["manifest"]["next_cursor"]
            .as_str()
            .is_some());
        assert_eq!(
            body["manifest"]["manifest"]["object"]["object_storage_connected"],
            false
        );
        assert_eq!(
            body["manifest"]["manifest"]["redaction"]["secret_material_included"],
            false
        );
        assert!(body["manifest"]["manifest"]["rows"][0]
            .as_object()
            .is_some_and(|row| !row.contains_key("upstream_credential_id")));
        let response_text = body.to_string();
        assert!(!response_text.contains("prompt text"));
        assert!(!response_text.contains("sec_openai"));
    }

    fn assert_github_login_start_response(body: &serde_json::Value, login_provider_id: &str) {
        assert_eq!(body["provider"]["id"], login_provider_id);
        assert_eq!(body["authorization"]["nonce"], serde_json::Value::Null);
        assert_eq!(
            body["authorization"]["pkce"]["code_challenge_method"],
            "S256"
        );
        assert!(body["authorization"]["state"]
            .as_str()
            .is_some_and(|state| state.starts_with("gwst_")));
        assert!(body["authorization"]["authorization_url"]
            .as_str()
            .is_some_and(|url| {
                url.starts_with("https://github.com/login/oauth/authorize?")
                    && url.contains("client_id=github_client")
                    && url.contains(
                        "redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fgithub%2Fcallback",
                    )
                    && url.contains("scope=read%3Auser%20user%3Aemail")
                    && url.contains("code_challenge_method=S256")
            }));
    }

    fn insert_admin_session(store: &InMemoryGatewayStore) -> String {
        insert_admin_session_with_id(store).0
    }

    fn insert_admin_session_with_id(store: &InMemoryGatewayStore) -> (String, String) {
        let now = chrono::Utc::now();
        let session = create_auth_session(
            CreateAuthSessionRequest {
                tenant_id: TEST_TENANT_ID.to_owned(),
                principal_id: TEST_USER_ID.to_owned(),
                active_organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
                active_project_id: Some(TEST_PROJECT_ID.to_owned()),
                expires_at: now + Duration::hours(1),
            },
            now,
        );
        let raw_session = session.raw_token.expose_secret().to_owned();
        let auth_session_id = session.record.auth_session_id.clone();
        store.insert_auth_session(session.record);
        (raw_session, auth_session_id)
    }

    fn insert_external_identity(store: &InMemoryGatewayStore, email: &str) -> String {
        let now = chrono::Utc::now();
        let external_identity_id = new_prefixed_id("xid");
        store.insert_external_identity(ExternalIdentityRecord {
            external_identity_id: external_identity_id.clone(),
            tenant_id: TEST_TENANT_ID.to_owned(),
            principal_id: TEST_USER_ID.to_owned(),
            login_provider_id: Some("lp_github".to_owned()),
            provider_kind: "github_oauth_app".to_owned(),
            provider_subject: "github-user-123".to_owned(),
            email: Some(email.to_owned()),
            email_verified: true,
            status: ResourceStatus::Active,
            created_at: now,
            updated_at: now,
        });
        external_identity_id
    }

    fn seed_tenant_owner_grants(store: &InMemoryGatewayStore) {
        for grant in ActionGrant::for_builtin_role(
            TEST_TENANT_ID,
            None::<String>,
            None::<String>,
            TEST_USER_ID,
            BuiltInRole::TenantOwner,
        ) {
            store.insert_action_grant(grant);
        }
    }

    fn publish_catalog_snapshot(store: &InMemoryGatewayStore, payload: serde_json::Value) {
        match publish_config_snapshot(
            store,
            PublishConfigSnapshotRequest {
                tenant_id: "ten_test".to_owned(),
                resource_versions: Vec::new(),
                payload,
                created_by: "usr_test".to_owned(),
            },
            chrono::Utc::now(),
        ) {
            Ok(_) => {}
            Err(error) => panic!("catalog snapshot should publish: {error}"),
        }
    }

    fn seed_protocol_replay_action_grants(store: &InMemoryGatewayStore) {
        for case in foundation_route_replay_cases() {
            let route = foundation_routes()
                .iter()
                .find(|route| {
                    route.protocol_family == Some(case.protocol_family)
                        && route.action == case.action
                })
                .unwrap_or_else(|| panic!("case {} should have route metadata", case.name));
            store.insert_action_grant(ActionGrant::project(
                TEST_TENANT_ID,
                TEST_ORGANIZATION_ID,
                TEST_PROJECT_ID,
                TEST_USER_ID,
                case.action,
                route.resource(protocol_replay_id("ma", case.protocol_family)),
            ));
        }
    }

    fn pricing_document_fixture() -> serde_json::Value {
        json!({
            "schema": "gateway.pricing.v1",
            "currency": "USD",
            "unit": "micro_usd",
            "rounding": "ceil_per_event",
            "tokens": {
                "input_per_million": 3000,
                "output_per_million": 15000
            },
            "flat_request_cost": 0,
            "discount_multiplier": "1.0"
        })
    }

    fn valid_otel_export_config_request_with_secret(
        idempotency_key: &str,
        secret_ref_id: &str,
    ) -> serde_json::Value {
        json!({
            "idempotency_key": idempotency_key,
            "project_id": "prj_test",
            "endpoint_url": "https://otel.example/v1/metrics",
            "protocol": "otlp_http",
            "header_refs": [{
                "name": "Authorization",
                "secret_ref_id": secret_ref_id
            }],
            "enabled_signals": ["metrics"],
            "resource_attributes": [{
                "key": "service.namespace",
                "value": "starweaver"
            }],
            "export_interval_seconds": 60,
            "timeout_seconds": 10
        })
    }

    fn gateway_config_with_single_user() -> GatewayConfig {
        GatewayConfig {
            single_user_auth: Some(SingleUserAuthConfig {
                user_primary_email: Some("admin@example.com".to_owned()),
                ..SingleUserAuthConfig::new("admin", "correct horse battery staple")
            }),
            ..GatewayConfig::default()
        }
    }

    fn valid_secret_ref_request(idempotency_key: &str, secret_value: &str) -> serde_json::Value {
        json!({
            "idempotency_key": idempotency_key,
            "organization_id": TEST_ORGANIZATION_ID,
            "project_id": TEST_PROJECT_ID,
            "purpose": "notification webhook signing",
            "backend_kind": "memory",
            "secret_value": secret_value
        })
    }

    fn valid_notification_sink_request_with_secret(
        idempotency_key: &str,
        signing_secret_ref_id: &str,
    ) -> serde_json::Value {
        json!({
            "idempotency_key": idempotency_key,
            "project_id": "prj_test",
            "name": "usage-webhook",
            "sink_kind": "webhook",
            "endpoint_config": {
                "url": "https://hooks.example/gateway",
                "retry_policy": {
                    "max_attempts": 5,
                    "max_duration_seconds": 3600
                },
                "batching": false
            },
            "signing_secret_ref_id": signing_secret_ref_id
        })
    }

    fn valid_github_login_provider_request(idempotency_key: &str) -> serde_json::Value {
        json!({
            "idempotency_key": idempotency_key,
            "provider_kind": "github_oauth_app",
            "display_name": "GitHub",
            "config_document": {
                "client_id": "github_client",
                "client_secret_ref": "sec_login_github_secret",
                "redirect_uri": "https://app.example/auth/github/callback",
                "scopes": ["read:user", "user:email"]
            }
        })
    }

    fn valid_oidc_login_provider_request(idempotency_key: &str) -> serde_json::Value {
        json!({
            "idempotency_key": idempotency_key,
            "provider_kind": "oidc",
            "display_name": "Example OIDC",
            "config_document": {
                "issuer": "https://login.example",
                "authorization_url": "https://login.example/oauth2/v1/authorize",
                "token_url": "https://login.example/oauth2/v1/token",
                "client_id": "oidc_client",
                "client_secret_ref": "sec_login_oidc_secret",
                "redirect_uri": "https://app.example/auth/oidc/callback"
            }
        })
    }

    fn valid_stdout_notification_sink_request(idempotency_key: &str) -> serde_json::Value {
        json!({
            "idempotency_key": idempotency_key,
            "project_id": "prj_test",
            "name": "runtime-policy-stdout",
            "sink_kind": "stdout",
            "endpoint_config": {
                "stream": "stdout"
            }
        })
    }

    fn catalog_payload() -> serde_json::Value {
        json!({
            "provider_endpoints": [{
                "provider_endpoint_id": "pep_openai",
                "tenant_id": "ten_test",
                "name": "OpenAI",
                "provider_kind": "openai",
                "protocol_families": ["openai_responses", "openai_chat"],
                "upstream_base_url": "https://api.openai.example",
                "status": "active"
            }],
            "upstream_credentials": [{
                "upstream_credential_id": "upc_openai",
                "tenant_id": "ten_test",
                "provider_endpoint_id": "pep_openai",
                "credential_kind": "api_key",
                "secret_ref_id": "sec_openai",
                "status": "active"
            }],
            "model_targets": [{
                "model_target_id": "mt_openai",
                "tenant_id": "ten_test",
                "provider_endpoint_id": "pep_openai",
                "upstream_credential_id": "upc_openai",
                "protocol_family": "openai_responses",
                "upstream_model_id": "gpt-4.1-mini",
                "status": "active",
                "supports_streaming": true
            }],
            "model_aliases": [{
                "model_alias_id": "ma_test",
                "tenant_id": "ten_test",
                "organization_id": "org_test",
                "project_id": "prj_test",
                "alias_name": "gpt-test",
                "protocol_family": "openai_responses",
                "route_policy_id": "rp_test",
                "status": "active"
            }],
            "routing_groups": [{
                "routing_group_id": "rg_test",
                "tenant_id": "ten_test",
                "status": "active"
            }],
            "routing_group_targets": [{
                "routing_group_target_id": "rgt_test",
                "routing_group_id": "rg_test",
                "model_target_id": "mt_openai",
                "weight": 1,
                "priority": 10,
                "status": "active"
            }],
            "route_policies": [{
                "route_policy_id": "rp_test",
                "tenant_id": "ten_test",
                "model_alias_id": "ma_test",
                "routing_group_id": "rg_test",
                "status": "active"
            }],
            "provider_grants": [{
                "provider_grant_id": "pg_test",
                "tenant_id": "ten_test",
                "organization_id": "org_test",
                "project_id": "prj_test",
                "principal_id": "usr_test",
                "provider_endpoint_id": "pep_openai",
                "model_target_id": "mt_openai",
                "status": "active"
            }]
        })
    }

    fn protocol_replay_catalog_payload() -> serde_json::Value {
        let cases = foundation_route_replay_cases();
        json!({
            "provider_endpoints": cases
                .iter()
                .map(|case| protocol_replay_provider_endpoint(case.protocol_family))
                .collect::<Vec<_>>(),
            "upstream_credentials": cases
                .iter()
                .map(|case| protocol_replay_upstream_credential(case.protocol_family))
                .collect::<Vec<_>>(),
            "model_targets": cases
                .iter()
                .map(|case| protocol_replay_model_target(case.protocol_family))
                .collect::<Vec<_>>(),
            "model_aliases": cases
                .iter()
                .map(|case| protocol_replay_model_alias(case.protocol_family))
                .collect::<Vec<_>>(),
            "routing_groups": cases
                .iter()
                .map(|case| protocol_replay_routing_group(case.protocol_family))
                .collect::<Vec<_>>(),
            "routing_group_targets": cases
                .iter()
                .map(|case| protocol_replay_routing_group_target(case.protocol_family))
                .collect::<Vec<_>>(),
            "route_policies": cases
                .iter()
                .map(|case| protocol_replay_route_policy(case.protocol_family))
                .collect::<Vec<_>>(),
            "provider_grants": cases
                .iter()
                .map(|case| protocol_replay_provider_grant(case.protocol_family))
                .collect::<Vec<_>>()
        })
    }

    fn protocol_replay_provider_endpoint(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "provider_endpoint_id": protocol_replay_id("pep", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "name": protocol_replay_provider_kind(protocol_family),
            "provider_kind": protocol_replay_provider_kind(protocol_family),
            "protocol_families": [protocol_family.as_str()],
            "upstream_base_url": format!(
                "https://{}.example",
                protocol_replay_provider_kind(protocol_family)
            ),
            "status": "active"
        })
    }

    fn protocol_replay_upstream_credential(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "upstream_credential_id": protocol_replay_id("upc", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "provider_endpoint_id": protocol_replay_id("pep", protocol_family),
            "credential_kind": "api_key",
            "secret_ref_id": protocol_replay_id("sec", protocol_family),
            "status": "active"
        })
    }

    fn protocol_replay_model_target(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "model_target_id": protocol_replay_id("mt", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "provider_endpoint_id": protocol_replay_id("pep", protocol_family),
            "upstream_credential_id": protocol_replay_id("upc", protocol_family),
            "protocol_family": protocol_family.as_str(),
            "upstream_model_id": protocol_replay_upstream_model(protocol_family),
            "status": "active",
            "supports_streaming": protocol_family != ProtocolFamily::ProviderNative
        })
    }

    fn protocol_replay_model_alias(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "model_alias_id": protocol_replay_id("ma", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "organization_id": TEST_ORGANIZATION_ID,
            "project_id": TEST_PROJECT_ID,
            "alias_name": protocol_replay_alias_name(protocol_family),
            "protocol_family": protocol_family.as_str(),
            "route_policy_id": protocol_replay_id("rp", protocol_family),
            "status": "active"
        })
    }

    fn protocol_replay_routing_group(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "routing_group_id": protocol_replay_id("rg", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "status": "active"
        })
    }

    fn protocol_replay_routing_group_target(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "routing_group_target_id": protocol_replay_id("rgt", protocol_family),
            "routing_group_id": protocol_replay_id("rg", protocol_family),
            "model_target_id": protocol_replay_id("mt", protocol_family),
            "weight": 1,
            "priority": 10,
            "status": "active"
        })
    }

    fn protocol_replay_route_policy(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "route_policy_id": protocol_replay_id("rp", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "model_alias_id": protocol_replay_id("ma", protocol_family),
            "routing_group_id": protocol_replay_id("rg", protocol_family),
            "status": "active"
        })
    }

    fn protocol_replay_provider_grant(protocol_family: ProtocolFamily) -> serde_json::Value {
        json!({
            "provider_grant_id": protocol_replay_id("pg", protocol_family),
            "tenant_id": TEST_TENANT_ID,
            "organization_id": TEST_ORGANIZATION_ID,
            "project_id": TEST_PROJECT_ID,
            "principal_id": TEST_USER_ID,
            "provider_endpoint_id": protocol_replay_id("pep", protocol_family),
            "model_target_id": protocol_replay_id("mt", protocol_family),
            "status": "active"
        })
    }

    fn protocol_replay_request_body(case: &GatewayReplayCase) -> serde_json::Value {
        match case.protocol_family {
            ProtocolFamily::OpenAiResponses => json!({
                "model": protocol_replay_alias_name(case.protocol_family),
                "input": "hello"
            }),
            ProtocolFamily::OpenAiChat => json!({
                "model": protocol_replay_alias_name(case.protocol_family),
                "stream": true,
                "messages": [{"role": "user", "content": "hello"}]
            }),
            ProtocolFamily::AnthropicMessages => json!({
                "model": protocol_replay_alias_name(case.protocol_family),
                "max_tokens": 16,
                "messages": [{"role": "user", "content": "hello"}]
            }),
            ProtocolFamily::GeminiGenerateContent => json!({
                "contents": [{"role": "user", "parts": [{"text": "hello"}]}]
            }),
            ProtocolFamily::BedrockConverse => json!({
                "messages": [{"role": "user", "content": [{"text": "hello"}]}]
            }),
            ProtocolFamily::ProviderNative => json!({
                "payload": {"hello": "world"}
            }),
        }
    }

    fn protocol_replay_alias_name(protocol_family: ProtocolFamily) -> &'static str {
        match protocol_family {
            ProtocolFamily::OpenAiResponses => "replay-openai-responses",
            ProtocolFamily::OpenAiChat => "replay-openai-chat",
            ProtocolFamily::AnthropicMessages => "replay-anthropic-messages",
            ProtocolFamily::GeminiGenerateContent => "gemini-pro",
            ProtocolFamily::BedrockConverse => "anthropic.claude-3-sonnet",
            ProtocolFamily::ProviderNative => "custom_native:invoke",
        }
    }

    fn protocol_replay_upstream_model(protocol_family: ProtocolFamily) -> &'static str {
        match protocol_family {
            ProtocolFamily::OpenAiResponses => "upstream-openai-responses",
            ProtocolFamily::OpenAiChat => "upstream-openai-chat",
            ProtocolFamily::AnthropicMessages => "upstream-anthropic-messages",
            ProtocolFamily::GeminiGenerateContent => "upstream-gemini-generate-content",
            ProtocolFamily::BedrockConverse => "upstream-bedrock-converse",
            ProtocolFamily::ProviderNative => "upstream-provider-native",
        }
    }

    fn protocol_replay_provider_kind(protocol_family: ProtocolFamily) -> &'static str {
        match protocol_family {
            ProtocolFamily::OpenAiResponses | ProtocolFamily::OpenAiChat => "openai",
            ProtocolFamily::AnthropicMessages => "anthropic",
            ProtocolFamily::GeminiGenerateContent => "gemini",
            ProtocolFamily::BedrockConverse => "bedrock",
            ProtocolFamily::ProviderNative => "provider-native",
        }
    }

    fn protocol_replay_id(prefix: &str, protocol_family: ProtocolFamily) -> String {
        format!("{prefix}_{}", protocol_family.as_str())
    }

    fn catalog_payload_with_cedar_policy(policy: &str) -> serde_json::Value {
        let mut payload = catalog_payload();
        payload["cedar_policy_bundle"] = json!(policy);
        payload
    }

    fn catalog_payload_for_admin_graph(graph: &AdminGraphFixture) -> serde_json::Value {
        json!({
            "provider_endpoints": [{
                "provider_endpoint_id": graph.endpoint_id.as_str(),
                "tenant_id": TEST_TENANT_ID,
                "name": "OpenAI",
                "provider_kind": "openai",
                "protocol_families": ["openai_responses", "openai_chat"],
                "upstream_base_url": "https://api.openai.example",
                "status": "active"
            }],
            "upstream_credentials": [{
                "upstream_credential_id": graph.credential_id.as_str(),
                "tenant_id": TEST_TENANT_ID,
                "provider_endpoint_id": graph.endpoint_id.as_str(),
                "credential_kind": "api_key",
                "secret_ref_id": "sec_openai",
                "status": "active"
            }],
            "model_targets": [{
                "model_target_id": graph.target_id.as_str(),
                "tenant_id": TEST_TENANT_ID,
                "provider_endpoint_id": graph.endpoint_id.as_str(),
                "upstream_credential_id": graph.credential_id.as_str(),
                "protocol_family": "openai_responses",
                "upstream_model_id": "gpt-4.1-mini",
                "status": "active",
                "supports_streaming": true
            }],
            "model_aliases": [{
                "model_alias_id": graph.alias_id.as_str(),
                "tenant_id": TEST_TENANT_ID,
                "organization_id": TEST_ORGANIZATION_ID,
                "project_id": TEST_PROJECT_ID,
                "alias_name": graph.alias_name.as_str(),
                "protocol_family": "openai_responses",
                "route_policy_id": graph.route_policy_id.as_str(),
                "status": "active"
            }],
            "routing_groups": [{
                "routing_group_id": graph.routing_group_id.as_str(),
                "tenant_id": TEST_TENANT_ID,
                "status": "active"
            }],
            "routing_group_targets": [{
                "routing_group_target_id": graph.routing_group_target_id.as_str(),
                "routing_group_id": graph.routing_group_id.as_str(),
                "model_target_id": graph.target_id.as_str(),
                "weight": 1,
                "priority": 10,
                "status": "active"
            }],
            "route_policies": [{
                "route_policy_id": graph.route_policy_id.as_str(),
                "tenant_id": TEST_TENANT_ID,
                "model_alias_id": graph.alias_id.as_str(),
                "routing_group_id": graph.routing_group_id.as_str(),
                "status": "active"
            }],
            "provider_grants": [{
                "provider_grant_id": "pg_dynamic",
                "tenant_id": TEST_TENANT_ID,
                "organization_id": TEST_ORGANIZATION_ID,
                "project_id": TEST_PROJECT_ID,
                "principal_id": TEST_USER_ID,
                "provider_endpoint_id": graph.endpoint_id.as_str(),
                "model_target_id": graph.target_id.as_str(),
                "status": "active"
            }]
        })
    }

    async fn post_responses_request(
        store: InMemoryGatewayStore,
        raw_key: &str,
        model: &str,
    ) -> Response<Body> {
        post_responses_request_with_body(store, raw_key, json!({"model": model})).await
    }

    async fn wait_for_quota_fixed_window_margin() {
        const MIN_REMAINING_SECONDS: i64 = 10;
        let elapsed_seconds = chrono::Utc::now().timestamp().rem_euclid(60);
        let remaining_seconds = 60 - elapsed_seconds;
        if remaining_seconds < MIN_REMAINING_SECONDS {
            let wait_seconds = u64::try_from(remaining_seconds + 1)
                .unwrap_or_else(|error| panic!("wait duration should fit u64: {error}"));
            tokio::time::sleep(std::time::Duration::from_secs(wait_seconds)).await;
        }
    }

    async fn post_responses_request_with_body(
        store: InMemoryGatewayStore,
        raw_key: &str,
        body: serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/responses")
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn post_replay_case_over_http(
        store: InMemoryGatewayStore,
        raw_key: &str,
        case: &GatewayReplayCase,
        body: &serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method(case.method.clone())
                    .uri(case.ingress_path)
                    .header(header::AUTHORIZATION, format!("Bearer {raw_key}"))
                    .header(REQUEST_ID_HEADER, format!("req_catalog_{}", case.name))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("case {} should complete: {error}", case.name),
        }
    }

    async fn post_admin_json(
        store: InMemoryGatewayStore,
        raw_session: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {raw_session}"))
                    .header(PROJECT_ID_HEADER, TEST_PROJECT_ID)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn post_admin_json_with_bearer(
        store: InMemoryGatewayStore,
        bearer: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .header(PROJECT_ID_HEADER, TEST_PROJECT_ID)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn patch_admin_json(
        store: InMemoryGatewayStore,
        raw_session: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {raw_session}"))
                    .header(PROJECT_ID_HEADER, TEST_PROJECT_ID)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn get_admin(
        store: InMemoryGatewayStore,
        raw_session: &str,
        uri: &str,
    ) -> Response<Body> {
        get_admin_with_project(store, raw_session, TEST_PROJECT_ID, uri).await
    }

    async fn get_admin_with_project(
        store: InMemoryGatewayStore,
        raw_session: &str,
        project_id: &str,
        uri: &str,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {raw_session}"))
                    .header(PROJECT_ID_HEADER, project_id)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn get_admin_without_project(
        store: InMemoryGatewayStore,
        raw_session: &str,
        uri: &str,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {raw_session}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn get_public(store: InMemoryGatewayStore, uri: &str) -> Response<Body> {
        get_public_with_config(store, GatewayConfig::default(), uri).await
    }

    async fn get_public_with_config(
        store: InMemoryGatewayStore,
        config: GatewayConfig,
        uri: &str,
    ) -> Response<Body> {
        match router(AppState::new(config, store))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn get_public_with_bearer(
        store: InMemoryGatewayStore,
        bearer: &str,
        uri: &str,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn post_public_with_bearer(
        store: InMemoryGatewayStore,
        bearer: &str,
        uri: &str,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .body(Body::empty())
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn post_public_json_with_bearer(
        store: InMemoryGatewayStore,
        bearer: &str,
        uri: &str,
        body: serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(GatewayConfig::default(), store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn post_public_json_with_config(
        store: InMemoryGatewayStore,
        config: GatewayConfig,
        uri: &str,
        body: serde_json::Value,
    ) -> Response<Body> {
        match router(AppState::new(config, store))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap_or_else(|error| panic!("request should build: {error}")),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => panic!("request should complete: {error}"),
        }
    }

    async fn create_otel_export_config_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "otel collector authorization",
            "otel-collector-token-value",
        );
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/observability/otel-export/configs",
            valid_otel_export_config_request_with_secret(&new_prefixed_id("idem"), &secret_ref_id),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("otel export config id should be present"))
            .to_owned()
    }

    async fn create_secret_ref_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        secret_value: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/secret-refs",
            valid_secret_ref_request(&new_prefixed_id("idem"), secret_value),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("secret ref id should be present"))
            .to_owned()
    }

    fn seed_secret_ref_for_test(
        store: &InMemoryGatewayStore,
        organization_id: Option<&str>,
        project_id: Option<&str>,
        purpose: &str,
        secret_value: &str,
    ) -> String {
        let record = store
            .create_secret_ref(
                CreateSecretRefRequest {
                    tenant_id: TEST_TENANT_ID.to_owned(),
                    organization_id: organization_id.map(str::to_owned),
                    project_id: project_id.map(str::to_owned),
                    purpose: purpose.to_owned(),
                    backend_kind: "memory".to_owned(),
                    secret_value: secrecy::SecretString::from(secret_value.to_owned()),
                    created_by: TEST_USER_ID.to_owned(),
                },
                chrono::Utc::now(),
            )
            .unwrap_or_else(|error| panic!("test secret ref should be seeded: {error}"));
        record.secret_ref_id
    }

    async fn create_notification_sink_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let idempotency_key = new_prefixed_id("idem");
        let signing_secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "notification webhook signing",
            "notification-webhook-secret-value",
        );
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/notification/sinks",
            valid_notification_sink_request_with_secret(&idempotency_key, &signing_secret_ref_id),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("notification sink id should be present"))
            .to_owned()
    }

    async fn create_webhook_notification_sink_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        idempotency_key: &str,
        name: &str,
        url: &str,
    ) -> String {
        let signing_secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            Some(TEST_PROJECT_ID),
            "notification webhook signing",
            "notification-webhook-secret-value",
        );
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/notification/sinks",
            json!({
                "idempotency_key": idempotency_key,
                "project_id": TEST_PROJECT_ID,
                "name": name,
                "sink_kind": "webhook",
                "endpoint_config": {
                    "url": url,
                    "retry_policy": {
                        "max_attempts": 3,
                        "max_duration_seconds": 3600
                    },
                    "batching": false
                },
                "signing_secret_ref_id": signing_secret_ref_id
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("notification sink id should be present"))
            .to_owned()
    }

    async fn create_stdout_notification_sink_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let idempotency_key = new_prefixed_id("idem");
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/notification/sinks",
            valid_stdout_notification_sink_request(&idempotency_key),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("notification sink id should be present"))
            .to_owned()
    }

    async fn create_quota_notification_subscription_and_policy(
        store: InMemoryGatewayStore,
        raw_session: &str,
        notification_sink_id: &str,
    ) {
        let subscription = post_admin_json(
            store.clone(),
            raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}/subscriptions"),
            json!({
                "idempotency_key": "idem_quota_notification_subscription",
                "event_family": "quota",
                "filter_document": {"event_types": ["gateway.quota.limit_exceeded"]}
            }),
        )
        .await;
        assert_eq!(subscription.status(), StatusCode::OK);
        let policy = post_admin_json(
            store,
            raw_session,
            "/admin/v1/quota-policies",
            json!({
                "idempotency_key": "idem_quota_notification_policy",
                "scope_kind": "project",
                "scope_id": TEST_PROJECT_ID,
                "counter_kind": "request_rate",
                "limit": 1,
                "window": "fixed",
                "increment_source": "accepted_preflight_request",
                "loss_behavior": "fail_closed"
            }),
        )
        .await;
        assert_eq!(policy.status(), StatusCode::OK);
    }

    fn append_synthetic_notification_event(
        store: &InMemoryGatewayStore,
        notification_sink_id: &str,
        dedupe_key: &str,
        kind: &str,
    ) -> String {
        let event = store.append_notification_outbox_event(
            CreateNotificationOutboxEventRequest {
                tenant_id: TEST_TENANT_ID.to_owned(),
                organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
                project_id: Some(TEST_PROJECT_ID.to_owned()),
                notification_subscription_id: None,
                notification_sink_id: Some(notification_sink_id.to_owned()),
                event_kind: "gateway.delivery.synthetic".to_owned(),
                dedupe_key: dedupe_key.to_owned(),
                payload_document: json!({
                    "schema": "gateway.notification.synthetic.v1",
                    "redaction": {
                        "request_body_included": false,
                        "provider_body_included": false
                    },
                    "event": {"kind": kind}
                }),
                next_attempt_at: None,
            },
            chrono::Utc::now(),
        );
        event.notification_outbox_event_id
    }

    fn deliver_first_due_notification(
        store: InMemoryGatewayStore,
        now: chrono::DateTime<chrono::Utc>,
    ) -> NotificationDeliveryAttemptRecord {
        let attempts = deliver_due_notifications(
            &AppState::new(GatewayConfig::default(), store),
            TEST_TENANT_ID,
            now,
            10,
        );
        assert_eq!(attempts.len(), 1);
        attempts
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("delivery attempt should exist"))
    }

    fn assert_retryable_webhook_attempt(
        attempt: &NotificationDeliveryAttemptRecord,
        error_message: &str,
    ) {
        assert_eq!(attempt.status, "retryable_failed");
        assert_eq!(attempt.error_message.as_deref(), Some(error_message));
        assert_eq!(attempt.response_status, Some(503));
        assert!(attempt
            .request_body_sha256
            .as_deref()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert!(attempt
            .signing_secret_ref_id
            .as_deref()
            .is_some_and(|value| value.starts_with("sec_")));
        assert!(attempt
            .signature_sha256
            .as_deref()
            .is_some_and(|value| value.starts_with("sha256:")));
    }

    fn assert_notification_subscription_audit_events(store: &InMemoryGatewayStore) {
        let audit_events = store.audit_events();
        assert_eq!(audit_events.len(), 3);
        assert_eq!(
            audit_events.last().map(|event| event.event_type.as_str()),
            Some("gateway.notification_subscription.update")
        );
    }

    fn assert_signed_webhook_attempt(
        attempt: &NotificationDeliveryAttemptRecord,
        expected_event_id: &str,
        expected_signing_secret_ref_id: &str,
    ) -> String {
        let signature_sha256 = attempt
            .signature_sha256
            .clone()
            .unwrap_or_else(|| panic!("signature checksum should be present"));
        let delivery_headers = attempt.delivery_headers.to_string();
        assert_eq!(attempt.notification_outbox_event_id, expected_event_id);
        assert_eq!(attempt.status, "succeeded");
        assert_eq!(attempt.response_status, Some(204));
        assert_eq!(
            attempt.signing_secret_ref_id.as_deref(),
            Some(expected_signing_secret_ref_id)
        );
        assert!(attempt
            .request_body_sha256
            .as_deref()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert!(signature_sha256.starts_with("sha256:"));
        assert!(delivery_headers.contains("hmac-sha256:***"));
        assert!(delivery_headers.contains("sec_***"));
        assert!(!delivery_headers.contains(expected_signing_secret_ref_id));
        assert!(!delivery_headers.contains("synthetic"));
        signature_sha256
    }

    async fn rotate_notification_sink_signing_secret(
        store: InMemoryGatewayStore,
        raw_session: &str,
        notification_sink_id: &str,
        signing_secret_ref_id: &str,
    ) {
        let response = patch_admin_json(
            store,
            raw_session,
            &format!("/admin/v1/notification/sinks/{notification_sink_id}"),
            json!({
                "expected_version": 1,
                "signing_secret_ref_id": signing_secret_ref_id,
                "reason": "Rotate webhook signing secret."
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        let response_text = body.to_string();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["resource"]["signing_secret_ref_id"], "sec_***");
        assert!(!response_text.contains(signing_secret_ref_id));
    }

    async fn create_oidc_login_provider_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/identity-providers",
            valid_oidc_login_provider_request(&new_prefixed_id("idem")),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("login provider id should be present"))
            .to_owned()
    }

    async fn create_organization_invitation_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        idempotency_key: &str,
        project_id: Option<&str>,
    ) -> serde_json::Value {
        let mut request = json!({
            "idempotency_key": idempotency_key,
            "invited_principal_id": TEST_USER_ID,
            "role_id": "organization_member"
        });
        if let Some(project_id) = project_id {
            request["project_id"] = json!(project_id);
        }
        let response = post_admin_json(
            store,
            raw_session,
            &format!("/admin/v1/organizations/{TEST_ORGANIZATION_ID}/invitations"),
            request,
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body
    }

    fn invitation_token_from_body(body: &serde_json::Value) -> String {
        body["invitation_token"]
            .as_str()
            .unwrap_or_else(|| panic!("invitation token should be returned once"))
            .to_owned()
    }

    fn resource_id_from_body(body: &serde_json::Value) -> String {
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("resource id should be returned"))
            .to_owned()
    }

    async fn create_service_account_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/service-accounts",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": TEST_ORGANIZATION_ID,
                "project_id": TEST_PROJECT_ID,
                "display_name": "CI automation"
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("service account id should be present"))
            .to_owned()
    }

    async fn create_provider_endpoint_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/provider-endpoints",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": "org_test",
                "provider_kind": "openai",
                "display_name": "OpenAI",
                "protocol_families": ["openai_responses", "openai_chat"],
                "upstream_base_url": "https://api.openai.example/v1"
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("provider endpoint id should be present"))
            .to_owned()
    }

    async fn create_upstream_credential_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        provider_endpoint_id: &str,
    ) -> String {
        let secret_ref_id = seed_secret_ref_for_test(
            &store,
            Some(TEST_ORGANIZATION_ID),
            None,
            "upstream provider credential",
            "provider-api-key-value",
        );
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/upstream-credentials",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": "org_test",
                "provider_endpoint_id": provider_endpoint_id,
                "credential_kind": "api_key",
                "secret_ref_id": &secret_ref_id
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("upstream credential id should be present"))
            .to_owned()
    }

    async fn create_model_target_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        provider_endpoint_id: &str,
        upstream_credential_id: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/model-targets",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": "org_test",
                "provider_endpoint_id": provider_endpoint_id,
                "upstream_credential_id": upstream_credential_id,
                "protocol_family": "openai_responses",
                "upstream_model_id": "gpt-4.1-mini",
                "supports_streaming": true
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("model target id should be present"))
            .to_owned()
    }

    async fn create_model_alias_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/model-aliases",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": "org_test",
                "project_id": "prj_test",
                "alias_name": new_prefixed_id("gpt-primary"),
                "protocol_family": "openai_responses"
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("model alias id should be present"))
            .to_owned()
    }

    async fn create_pricing_sku_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/pricing-skus",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": "org_test",
                "name": new_prefixed_id("openai-gpt-primary"),
                "currency": "USD",
                "unit": "micro_usd",
                "model_id_patterns": ["gpt-4.1-mini"],
                "provider_endpoint_patterns": ["pe_*"],
                "pricing_document": pricing_document_fixture()
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("pricing SKU id should be present"))
            .to_owned()
    }

    async fn create_route_policy_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        model_alias_id: &str,
        routing_group_id: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/route-policies",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "name": new_prefixed_id("primary-policy"),
                "model_alias_id": model_alias_id,
                "routing_group_id": routing_group_id
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("route policy id should be present"))
            .to_owned()
    }

    async fn create_routing_group_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            "/admin/v1/routing-groups",
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "organization_id": "org_test",
                "name": new_prefixed_id("primary-openai"),
                "protocol_family": "openai_responses",
                "purpose": "Primary OpenAI-compatible pool."
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("routing group id should be present"))
            .to_owned()
    }

    async fn create_routing_group_target_over_http(
        store: InMemoryGatewayStore,
        raw_session: &str,
        routing_group_id: &str,
        model_target_id: &str,
    ) -> String {
        let response = post_admin_json(
            store,
            raw_session,
            &format!("/admin/v1/routing-groups/{routing_group_id}/targets"),
            json!({
                "idempotency_key": new_prefixed_id("idem"),
                "model_target_id": model_target_id,
                "weight": 100,
                "priority": 10
            }),
        )
        .await;
        let status = response.status();
        let body = response_json(response).await;
        assert_eq!(status, StatusCode::OK);
        body["resource"]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("routing group target id should be present"))
            .to_owned()
    }

    async fn response_json(response: Response<Body>) -> serde_json::Value {
        let bytes = match to_bytes(response.into_body(), 1024 * 1024).await {
            Ok(bytes) => bytes,
            Err(error) => panic!("response body should read: {error}"),
        };
        match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(value) => value,
            Err(error) => panic!("response body should be JSON: {error}"),
        }
    }

    fn assert_catalog_replay_route(case: &GatewayReplayCase, decision: &RouteDecisionRecord) {
        let alias_id = protocol_replay_id("ma", case.protocol_family);
        let target_id = protocol_replay_id("mt", case.protocol_family);
        let endpoint_id = protocol_replay_id("pep", case.protocol_family);
        assert_eq!(decision.protocol_family, case.protocol_family);
        assert_eq!(
            decision.alias_name,
            protocol_replay_alias_name(case.protocol_family)
        );
        assert_eq!(decision.model_alias_id.as_deref(), Some(alias_id.as_str()));
        assert_eq!(
            decision.model_target_id.as_deref(),
            Some(target_id.as_str())
        );
        assert_eq!(
            decision.provider_endpoint_id.as_deref(),
            Some(endpoint_id.as_str())
        );
        assert_eq!(
            decision.upstream_credential_id.as_deref(),
            Some(protocol_replay_id("upc", case.protocol_family).as_str())
        );
        assert!(decision.config_snapshot_id.is_some());
        assert!(decision.config_version.is_some());
    }

    fn assert_catalog_replay_success(
        case: &GatewayReplayCase,
        status: StatusCode,
        body: &serde_json::Value,
        store: &InMemoryGatewayStore,
    ) {
        let route_decisions = store.route_decisions();
        let route_attempts = store.route_attempts();
        let usage_events = store.usage_events_for_tenant(TEST_TENANT_ID);
        assert_eq!(status, StatusCode::OK, "case {}", case.name);
        assert_eq!(
            body["protocol_family"],
            case.protocol_family.as_str(),
            "case {}",
            case.name
        );
        assert_eq!(body["authorization"]["allowed"], true, "case {}", case.name);
        assert_eq!(body["streaming"], case.streaming, "case {}", case.name);
        assert_provider_shape(case.protocol_family, &body["body"]);
        assert_catalog_provider_model(case.protocol_family, &body["body"]);
        assert_eq!(route_attempts.len(), 1, "case {}", case.name);
        assert_eq!(
            route_attempts[0].route_decision_id, route_decisions[0].route_decision_id,
            "case {}",
            case.name
        );
        assert_eq!(route_attempts[0].status, RouteAttemptStatus::Completed);
        assert_eq!(usage_events.len(), 1, "case {}", case.name);
        assert_eq!(
            usage_events[0].route_decision_id.as_deref(),
            Some(route_decisions[0].route_decision_id.as_str())
        );
        assert_eq!(
            usage_events[0].model_alias_id.as_deref(),
            Some(protocol_replay_id("ma", case.protocol_family).as_str())
        );
        assert_eq!(
            usage_events[0].usage_confidence,
            expected_protocol_replay_usage_confidence(case)
        );
        assert_eq!(
            usage_events[0].time_to_first_token_ms.is_some(),
            case.streaming
        );
    }

    fn assert_catalog_replay_native_denial(
        case: &GatewayReplayCase,
        status: StatusCode,
        body: &serde_json::Value,
        store: &InMemoryGatewayStore,
    ) {
        let authorization_decisions = store.authorization_decisions();
        assert_eq!(status, StatusCode::FORBIDDEN, "case {}", case.name);
        assert_eq!(
            body["error"]["code"], "gateway.auth.authorization_denied",
            "case {}",
            case.name
        );
        assert!(!authorization_decisions[0].allowed);
        assert_eq!(
            authorization_decisions[0].reason,
            "native_route_grant_required"
        );
        assert!(store.route_attempts().is_empty());
        assert!(store.usage_events_for_tenant(TEST_TENANT_ID).is_empty());
    }

    fn assert_catalog_provider_model(protocol_family: ProtocolFamily, body: &serde_json::Value) {
        let upstream_model = protocol_replay_upstream_model(protocol_family);
        match protocol_family {
            ProtocolFamily::OpenAiResponses
            | ProtocolFamily::OpenAiChat
            | ProtocolFamily::AnthropicMessages => {
                assert_eq!(body["model"], upstream_model);
            }
            ProtocolFamily::GeminiGenerateContent => {
                assert_eq!(body["modelVersion"], upstream_model);
            }
            ProtocolFamily::BedrockConverse | ProtocolFamily::ProviderNative => {}
        }
    }

    fn expected_protocol_replay_usage_confidence(case: &GatewayReplayCase) -> &'static str {
        if case.streaming {
            "missing"
        } else {
            "exact"
        }
    }

    fn assert_provider_shape(protocol_family: ProtocolFamily, body: &serde_json::Value) {
        match protocol_family {
            ProtocolFamily::OpenAiResponses => {
                assert_eq!(body["object"], "response");
            }
            ProtocolFamily::OpenAiChat => {
                assert_eq!(body["object"], "chat.completion.chunk");
            }
            ProtocolFamily::AnthropicMessages => {
                assert_eq!(body["type"], "message");
            }
            ProtocolFamily::GeminiGenerateContent => {
                assert!(body.get("candidates").is_some());
            }
            ProtocolFamily::BedrockConverse => {
                assert!(body.get("output").is_some());
            }
            ProtocolFamily::ProviderNative => {
                assert_eq!(body["provider_native"], true);
            }
        }
    }
}
