//! Canonical gateway action registry and authorization request types.

use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::domain::{
    new_prefixed_id, ActorKind, AuthenticatedActor, OrganizationId, ProjectId, TenantId,
};

/// Canonical action definition used by policy, route metadata, and docs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDefinition {
    /// Type-safe action value.
    pub action: GatewayAction,
    /// Stable action id.
    pub action_id: &'static str,
    /// Canonical authorization resource kind.
    pub resource_kind: &'static str,
}

/// Scope kind accepted by a built-in gateway role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RoleScopeKind {
    /// Tenant-wide role.
    Tenant,
    /// Organization-scoped role.
    Organization,
    /// Project-scoped role.
    Project,
    /// Role can be bound at tenant, organization, or project scope.
    Any,
}

impl RoleScopeKind {
    /// Returns the stable role scope id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Organization => "organization",
            Self::Project => "project",
            Self::Any => "any",
        }
    }
}

/// Built-in gateway role id.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BuiltInRole {
    /// Full tenant administration role.
    TenantOwner,
    /// Tenant administration without break-glass ownership.
    TenantAdmin,
    /// Credential, secret, and redaction administration.
    SecurityAdmin,
    /// Operational health and routing administration.
    GatewayOperator,
    /// Organization-level administration.
    OrganizationAdmin,
    /// Baseline organization membership role.
    OrganizationMember,
    /// Project-level administration.
    ProjectAdmin,
    /// Project developer role.
    ProjectDeveloper,
    /// Project read-only role.
    ProjectViewer,
    /// Usage and cost reporting role.
    UsageViewer,
    /// Audit and route evidence inspection role.
    Auditor,
}

impl BuiltInRole {
    /// Returns every built-in role.
    #[must_use]
    pub const fn built_ins() -> &'static [Self] {
        &[
            Self::TenantOwner,
            Self::TenantAdmin,
            Self::SecurityAdmin,
            Self::GatewayOperator,
            Self::OrganizationAdmin,
            Self::OrganizationMember,
            Self::ProjectAdmin,
            Self::ProjectDeveloper,
            Self::ProjectViewer,
            Self::UsageViewer,
            Self::Auditor,
        ]
    }

    /// Returns the stable role id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantOwner => "tenant_owner",
            Self::TenantAdmin => "tenant_admin",
            Self::SecurityAdmin => "security_admin",
            Self::GatewayOperator => "gateway_operator",
            Self::OrganizationAdmin => "organization_admin",
            Self::OrganizationMember => "organization_member",
            Self::ProjectAdmin => "project_admin",
            Self::ProjectDeveloper => "project_developer",
            Self::ProjectViewer => "project_viewer",
            Self::UsageViewer => "usage_viewer",
            Self::Auditor => "auditor",
        }
    }

    /// Returns the role scope kind.
    #[must_use]
    pub const fn scope_kind(self) -> RoleScopeKind {
        match self {
            Self::TenantOwner | Self::TenantAdmin | Self::SecurityAdmin | Self::GatewayOperator => {
                RoleScopeKind::Tenant
            }
            Self::OrganizationAdmin | Self::OrganizationMember => RoleScopeKind::Organization,
            Self::ProjectAdmin | Self::ProjectDeveloper | Self::ProjectViewer => {
                RoleScopeKind::Project
            }
            Self::UsageViewer | Self::Auditor => RoleScopeKind::Any,
        }
    }

    /// Returns the actions granted by the role.
    #[must_use]
    pub const fn actions(self) -> &'static [GatewayAction] {
        match self {
            Self::TenantOwner => GatewayAction::canonical_actions(),
            Self::TenantAdmin => TENANT_ADMIN_ACTIONS,
            Self::SecurityAdmin => SECURITY_ADMIN_ACTIONS,
            Self::GatewayOperator => GATEWAY_OPERATOR_ACTIONS,
            Self::OrganizationAdmin => ORGANIZATION_ADMIN_ACTIONS,
            Self::OrganizationMember => ORGANIZATION_MEMBER_ACTIONS,
            Self::ProjectAdmin => PROJECT_ADMIN_ACTIONS,
            Self::ProjectDeveloper => PROJECT_DEVELOPER_ACTIONS,
            Self::ProjectViewer => PROJECT_VIEWER_ACTIONS,
            Self::UsageViewer => USAGE_VIEWER_ACTIONS,
            Self::Auditor => AUDITOR_ACTIONS,
        }
    }
}

macro_rules! gateway_actions {
    ($(($variant:ident, $action_id:literal, $resource_kind:literal)),+ $(,)?) => {
        /// Stable gateway action id.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum GatewayAction {
            $(
                #[doc = concat!("Gateway action `", $action_id, "`.")]
                $variant,
            )+
        }

        impl GatewayAction {
            /// Returns the stable action id used by policy and `OpenAPI`.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $action_id,)+
                }
            }

            /// Returns the canonical authorization resource kind.
            #[must_use]
            pub const fn resource_kind(self) -> &'static str {
                match self {
                    $(Self::$variant => $resource_kind,)+
                }
            }

            /// Parses a stable action id.
            #[must_use]
            pub fn from_action_id(value: &str) -> Option<Self> {
                match value {
                    $($action_id => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// Returns every canonical gateway action.
            #[must_use]
            pub const fn canonical_actions() -> &'static [Self] {
                &[$(Self::$variant,)+]
            }

            /// Returns every action implemented by the initial gateway foundation.
            #[must_use]
            pub const fn foundation_actions() -> &'static [Self] {
                Self::canonical_actions()
            }

            /// Returns every canonical action definition.
            #[must_use]
            pub const fn canonical_definitions() -> &'static [ActionDefinition] {
                &[
                    $(ActionDefinition {
                        action: Self::$variant,
                        action_id: $action_id,
                        resource_kind: $resource_kind,
                    },)+
                ]
            }
        }

        impl Serialize for GatewayAction {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for GatewayAction {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = <&str>::deserialize(deserializer)?;
                Self::from_action_id(value).ok_or_else(|| {
                    de::Error::unknown_variant(value, &[$($action_id,)+])
                })
            }
        }
    };
}

gateway_actions!(
    (TenantRead, "gateway.tenant.read", "Tenant"),
    (TenantWrite, "gateway.tenant.write", "Tenant"),
    (
        IdentityProviderRead,
        "gateway.identity_provider.read",
        "IdentityProvider"
    ),
    (
        IdentityProviderWrite,
        "gateway.identity_provider.write",
        "IdentityProvider"
    ),
    (UserRead, "gateway.user.read", "UserPrincipal"),
    (UserWrite, "gateway.user.write", "UserPrincipal"),
    (UserDisable, "gateway.user.disable", "UserPrincipal"),
    (
        ExternalIdentityRead,
        "gateway.external_identity.read",
        "ExternalIdentity"
    ),
    (
        ExternalIdentityUnlink,
        "gateway.external_identity.unlink",
        "ExternalIdentity"
    ),
    (SessionRead, "gateway.session.read", "AuthSession"),
    (SessionRevoke, "gateway.session.revoke", "AuthSession"),
    (SessionUpdate, "gateway.session.update", "AuthSession"),
    (
        ServiceAccountRead,
        "gateway.service_account.read",
        "ServiceAccount"
    ),
    (
        ServiceAccountWrite,
        "gateway.service_account.write",
        "ServiceAccount"
    ),
    (
        ServiceAccountDisable,
        "gateway.service_account.disable",
        "ServiceAccount"
    ),
    (
        OrganizationRead,
        "gateway.organization.read",
        "Organization"
    ),
    (
        OrganizationWrite,
        "gateway.organization.write",
        "Organization"
    ),
    (
        OrganizationMemberRead,
        "gateway.organization_member.read",
        "OrganizationMember"
    ),
    (
        OrganizationMemberWrite,
        "gateway.organization_member.write",
        "OrganizationMember"
    ),
    (
        OrganizationInviteRead,
        "gateway.organization_invite.read",
        "OrganizationInvite"
    ),
    (
        OrganizationInviteCreate,
        "gateway.organization_invite.create",
        "OrganizationInvite"
    ),
    (
        OrganizationInviteManage,
        "gateway.organization_invite.manage",
        "OrganizationInvite"
    ),
    (
        OrganizationInviteAccept,
        "gateway.organization_invite.accept",
        "OrganizationInvite"
    ),
    (ProjectRead, "gateway.project.read", "Project"),
    (ProjectWrite, "gateway.project.write", "Project"),
    (
        ProjectMemberRead,
        "gateway.project_member.read",
        "ProjectMember"
    ),
    (
        ProjectMemberWrite,
        "gateway.project_member.write",
        "ProjectMember"
    ),
    (
        CallerCredentialRead,
        "gateway.caller_credential.read",
        "CallerCredential"
    ),
    (
        CallerCredentialDisable,
        "gateway.caller_credential.disable",
        "CallerCredential"
    ),
    (ActionGrantRead, "gateway.action_grant.read", "ActionGrant"),
    (
        ActionGrantWrite,
        "gateway.action_grant.write",
        "ActionGrant"
    ),
    (
        ProviderEndpointRead,
        "gateway.provider_endpoint.read",
        "ProviderEndpoint"
    ),
    (
        ProviderEndpointWrite,
        "gateway.provider_endpoint.write",
        "ProviderEndpoint"
    ),
    (
        UpstreamCredentialRead,
        "gateway.upstream_credential.read",
        "UpstreamCredential"
    ),
    (
        UpstreamCredentialWrite,
        "gateway.upstream_credential.write",
        "UpstreamCredential"
    ),
    (
        UpstreamCredentialRotate,
        "gateway.upstream_credential.rotate",
        "UpstreamCredential"
    ),
    (SecretRefRead, "gateway.secret_ref.read", "SecretRef"),
    (SecretRefWrite, "gateway.secret_ref.write", "SecretRef"),
    (
        SecretRefLocatorRead,
        "gateway.secret_ref.locator.read",
        "SecretRef"
    ),
    (
        CodexOAuthConnectionRead,
        "gateway.codex_oauth_connection.read",
        "CodexOAuthConnection"
    ),
    (
        CodexOAuthConnectionWrite,
        "gateway.codex_oauth_connection.write",
        "CodexOAuthConnection"
    ),
    (
        CodexOAuthSessionRead,
        "gateway.codex_oauth_session.read",
        "CodexOAuthSession"
    ),
    (
        CodexOAuthSessionStart,
        "gateway.codex_oauth_session.start",
        "CodexOAuthSession"
    ),
    (
        CodexOAuthSessionRevoke,
        "gateway.codex_oauth_session.revoke",
        "CodexOAuthSession"
    ),
    (
        CodexOAuthRefreshRead,
        "gateway.codex_oauth_refresh.read",
        "CodexOAuthRefreshStatus"
    ),
    (ModelTargetRead, "gateway.model_target.read", "ModelTarget"),
    (
        ModelTargetWrite,
        "gateway.model_target.write",
        "ModelTarget"
    ),
    (ModelAliasRead, "gateway.model_alias.read", "ModelAlias"),
    (ModelAliasWrite, "gateway.model_alias.write", "ModelAlias"),
    (PricingSkuRead, "gateway.pricing_sku.read", "PricingSku"),
    (PricingSkuWrite, "gateway.pricing_sku.write", "PricingSku"),
    (
        RoutingGroupRead,
        "gateway.routing_group.read",
        "RoutingGroup"
    ),
    (
        RoutingGroupWrite,
        "gateway.routing_group.write",
        "RoutingGroup"
    ),
    (RoutePolicyRead, "gateway.route_policy.read", "RoutePolicy"),
    (
        RoutePolicyWrite,
        "gateway.route_policy.write",
        "RoutePolicy"
    ),
    (
        ProviderGrantRead,
        "gateway.provider_grant.read",
        "ProviderGrant"
    ),
    (
        ProviderGrantWrite,
        "gateway.provider_grant.write",
        "ProviderGrant"
    ),
    (QuotaPolicyRead, "gateway.quota_policy.read", "QuotaPolicy"),
    (
        QuotaPolicyWrite,
        "gateway.quota_policy.write",
        "QuotaPolicy"
    ),
    (
        AdmissionPolicyRead,
        "gateway.admission_policy.read",
        "AdmissionPolicy"
    ),
    (
        AdmissionPolicyWrite,
        "gateway.admission_policy.write",
        "AdmissionPolicy"
    ),
    (
        RedactionPolicyRead,
        "gateway.redaction_policy.read",
        "RedactionPolicy"
    ),
    (
        RedactionPolicyWrite,
        "gateway.redaction_policy.write",
        "RedactionPolicy"
    ),
    (ApiKeyCreate, "gateway.api_key.create", "ApiKey"),
    (ApiKeyRead, "gateway.api_key.read", "ApiKey"),
    (ApiKeyRotate, "gateway.api_key.rotate", "ApiKey"),
    (ApiKeyDisable, "gateway.api_key.disable", "ApiKey"),
    (RoleRead, "gateway.role.read", "RoleDefinition"),
    (RoleWrite, "gateway.role.write", "RoleDefinition"),
    (RoleBindingRead, "gateway.role_binding.read", "RoleBinding"),
    (
        RoleBindingWrite,
        "gateway.role_binding.write",
        "RoleBinding"
    ),
    (PolicyRead, "gateway.policy.read", "PolicyAttachment"),
    (PolicyWrite, "gateway.policy.write", "PolicyAttachment"),
    (
        BudgetPolicyRead,
        "gateway.budget_policy.read",
        "BudgetPolicy"
    ),
    (
        BudgetPolicyWrite,
        "gateway.budget_policy.write",
        "BudgetPolicy"
    ),
    (ConfigRead, "gateway.config.read", "ConfigSnapshot"),
    (ConfigApply, "gateway.config.apply", "ConfigBundle"),
    (ConfigPublish, "gateway.config.publish", "ConfigSnapshot"),
    (ConfigRollback, "gateway.config.rollback", "ConfigSnapshot"),
    (
        RouteSimulationRun,
        "gateway.route_simulation.run",
        "RouteSimulation"
    ),
    (
        CatalogImportCreate,
        "gateway.catalog_import.create",
        "CatalogImport"
    ),
    (
        CatalogImportRead,
        "gateway.catalog_import.read",
        "CatalogImport"
    ),
    (
        MaintenanceWindowRead,
        "gateway.maintenance_window.read",
        "MaintenanceWindow"
    ),
    (
        MaintenanceWindowWrite,
        "gateway.maintenance_window.write",
        "MaintenanceWindow"
    ),
    (ModelInvoke, "gateway.model.invoke", "ModelAlias"),
    (ModelStream, "gateway.model.stream", "ModelAlias"),
    (
        ModelNative,
        "gateway.model.native",
        "ProviderNativeEndpoint"
    ),
    (RouteDebugRead, "gateway.route.debug.read", "RouteDecision"),
    (UsageRead, "gateway.usage.read", "UsageScope"),
    (UsageSummaryRead, "gateway.usage.summary.read", "UsageScope"),
    (UsageEventRead, "gateway.usage.event.read", "UsageEvent"),
    (
        RealtimeDashboardRead,
        "gateway.realtime_dashboard.read",
        "RealtimeDashboard"
    ),
    (
        DashboardTenantRead,
        "gateway.dashboard.tenant.read",
        "TenantDashboard"
    ),
    (
        DashboardOrganizationRead,
        "gateway.dashboard.organization.read",
        "OrganizationDashboard"
    ),
    (
        DashboardProjectRead,
        "gateway.dashboard.project.read",
        "ProjectDashboard"
    ),
    (
        DashboardProjectMemberRead,
        "gateway.dashboard.project_member.read",
        "ProjectMemberDashboard"
    ),
    (
        DashboardApiKeyRead,
        "gateway.dashboard.api_key.read",
        "ApiKeyDashboard"
    ),
    (
        DashboardServiceAccountRead,
        "gateway.dashboard.service_account.read",
        "ServiceAccountDashboard"
    ),
    (
        ModelObservabilityRead,
        "gateway.model_observability.read",
        "ModelObservability"
    ),
    (
        ProviderObservabilityRead,
        "gateway.provider_observability.read",
        "ProviderEndpoint"
    ),
    (
        BudgetDashboardRead,
        "gateway.budget_dashboard.read",
        "BudgetDashboard"
    ),
    (
        QuotaDashboardRead,
        "gateway.quota_dashboard.read",
        "QuotaDashboard"
    ),
    (AuditRead, "gateway.audit.read", "AuditEvent"),
    (ExportRead, "gateway.export.read", "ExportManifest"),
    (ExportCreate, "gateway.export.create", "ExportJob"),
    (
        NotificationRead,
        "gateway.notification.read",
        "NotificationSink"
    ),
    (
        NotificationWrite,
        "gateway.notification.write",
        "NotificationSink"
    ),
    (
        NotificationOutboxWrite,
        "gateway.notification_outbox.write",
        "NotificationOutboxEvent"
    ),
    (
        ObservabilityExportRead,
        "gateway.observability_export.read",
        "OpenTelemetryExportConfig"
    ),
    (
        ObservabilityExportWrite,
        "gateway.observability_export.write",
        "OpenTelemetryExportConfig"
    ),
    (HealthRead, "gateway.health.read", "RuntimeHealth"),
    (
        ProviderHealthOverride,
        "gateway.provider_health.override",
        "ProviderEndpoint"
    ),
    (
        EmergencyDisable,
        "gateway.emergency.disable",
        "EmergencyOperation"
    ),
    (
        DebugCaptureEnable,
        "gateway.debug_capture.enable",
        "DebugCapturePolicy"
    ),
);

const TENANT_ADMIN_ACTIONS: &[GatewayAction] = &[
    GatewayAction::TenantRead,
    GatewayAction::TenantWrite,
    GatewayAction::IdentityProviderRead,
    GatewayAction::IdentityProviderWrite,
    GatewayAction::UserRead,
    GatewayAction::UserWrite,
    GatewayAction::ServiceAccountRead,
    GatewayAction::ServiceAccountWrite,
    GatewayAction::OrganizationRead,
    GatewayAction::OrganizationWrite,
    GatewayAction::OrganizationMemberRead,
    GatewayAction::OrganizationMemberWrite,
    GatewayAction::OrganizationInviteRead,
    GatewayAction::OrganizationInviteCreate,
    GatewayAction::OrganizationInviteManage,
    GatewayAction::ProjectRead,
    GatewayAction::ProjectWrite,
    GatewayAction::ProjectMemberRead,
    GatewayAction::ProjectMemberWrite,
    GatewayAction::ActionGrantRead,
    GatewayAction::ActionGrantWrite,
    GatewayAction::ProviderEndpointRead,
    GatewayAction::ProviderEndpointWrite,
    GatewayAction::ProviderGrantRead,
    GatewayAction::ProviderGrantWrite,
    GatewayAction::ModelTargetRead,
    GatewayAction::ModelTargetWrite,
    GatewayAction::ModelAliasRead,
    GatewayAction::ModelAliasWrite,
    GatewayAction::RoutingGroupRead,
    GatewayAction::RoutingGroupWrite,
    GatewayAction::RoutePolicyRead,
    GatewayAction::RoutePolicyWrite,
    GatewayAction::BudgetPolicyRead,
    GatewayAction::BudgetPolicyWrite,
    GatewayAction::QuotaPolicyRead,
    GatewayAction::QuotaPolicyWrite,
    GatewayAction::AdmissionPolicyRead,
    GatewayAction::AdmissionPolicyWrite,
    GatewayAction::RoleRead,
    GatewayAction::RoleWrite,
    GatewayAction::RoleBindingRead,
    GatewayAction::RoleBindingWrite,
    GatewayAction::PolicyRead,
    GatewayAction::PolicyWrite,
    GatewayAction::ConfigRead,
    GatewayAction::ConfigApply,
    GatewayAction::ConfigPublish,
    GatewayAction::ConfigRollback,
    GatewayAction::RouteSimulationRun,
    GatewayAction::CatalogImportCreate,
    GatewayAction::CatalogImportRead,
    GatewayAction::MaintenanceWindowRead,
    GatewayAction::MaintenanceWindowWrite,
];

const SECURITY_ADMIN_ACTIONS: &[GatewayAction] = &[
    GatewayAction::CallerCredentialRead,
    GatewayAction::CallerCredentialDisable,
    GatewayAction::UpstreamCredentialRead,
    GatewayAction::UpstreamCredentialWrite,
    GatewayAction::UpstreamCredentialRotate,
    GatewayAction::SecretRefRead,
    GatewayAction::SecretRefWrite,
    GatewayAction::SecretRefLocatorRead,
    GatewayAction::CodexOAuthConnectionRead,
    GatewayAction::CodexOAuthConnectionWrite,
    GatewayAction::CodexOAuthSessionRead,
    GatewayAction::CodexOAuthSessionStart,
    GatewayAction::CodexOAuthSessionRevoke,
    GatewayAction::CodexOAuthRefreshRead,
    GatewayAction::RedactionPolicyRead,
    GatewayAction::RedactionPolicyWrite,
    GatewayAction::ApiKeyRead,
    GatewayAction::ApiKeyDisable,
    GatewayAction::AuditRead,
    GatewayAction::EmergencyDisable,
];

const GATEWAY_OPERATOR_ACTIONS: &[GatewayAction] = &[
    GatewayAction::ConfigRead,
    GatewayAction::RealtimeDashboardRead,
    GatewayAction::ModelObservabilityRead,
    GatewayAction::ProviderObservabilityRead,
    GatewayAction::ObservabilityExportRead,
    GatewayAction::HealthRead,
    GatewayAction::ProviderHealthOverride,
    GatewayAction::RouteDebugRead,
    GatewayAction::RouteSimulationRun,
    GatewayAction::NotificationRead,
    GatewayAction::NotificationOutboxWrite,
    GatewayAction::MaintenanceWindowRead,
    GatewayAction::MaintenanceWindowWrite,
    GatewayAction::EmergencyDisable,
];

const ORGANIZATION_ADMIN_ACTIONS: &[GatewayAction] = &[
    GatewayAction::OrganizationRead,
    GatewayAction::OrganizationWrite,
    GatewayAction::OrganizationMemberRead,
    GatewayAction::OrganizationMemberWrite,
    GatewayAction::OrganizationInviteRead,
    GatewayAction::OrganizationInviteCreate,
    GatewayAction::OrganizationInviteManage,
    GatewayAction::ProjectRead,
    GatewayAction::ProjectWrite,
    GatewayAction::ProjectMemberRead,
    GatewayAction::ProjectMemberWrite,
    GatewayAction::ProviderGrantRead,
    GatewayAction::ProviderGrantWrite,
    GatewayAction::ActionGrantRead,
    GatewayAction::ActionGrantWrite,
    GatewayAction::RoleBindingRead,
    GatewayAction::RoleBindingWrite,
    GatewayAction::DashboardOrganizationRead,
    GatewayAction::DashboardProjectRead,
    GatewayAction::UsageSummaryRead,
];

const ORGANIZATION_MEMBER_ACTIONS: &[GatewayAction] = &[
    GatewayAction::OrganizationRead,
    GatewayAction::OrganizationMemberRead,
    GatewayAction::ProjectRead,
    GatewayAction::DashboardOrganizationRead,
    GatewayAction::DashboardProjectRead,
];

const PROJECT_ADMIN_ACTIONS: &[GatewayAction] = &[
    GatewayAction::ProjectRead,
    GatewayAction::ProjectWrite,
    GatewayAction::ProjectMemberRead,
    GatewayAction::ProjectMemberWrite,
    GatewayAction::ApiKeyCreate,
    GatewayAction::ApiKeyRead,
    GatewayAction::ApiKeyRotate,
    GatewayAction::ApiKeyDisable,
    GatewayAction::ModelAliasRead,
    GatewayAction::ModelAliasWrite,
    GatewayAction::BudgetPolicyRead,
    GatewayAction::BudgetPolicyWrite,
    GatewayAction::QuotaPolicyRead,
    GatewayAction::QuotaPolicyWrite,
    GatewayAction::AdmissionPolicyRead,
    GatewayAction::AdmissionPolicyWrite,
    GatewayAction::ModelInvoke,
    GatewayAction::ModelStream,
    GatewayAction::UsageRead,
    GatewayAction::UsageSummaryRead,
    GatewayAction::UsageEventRead,
    GatewayAction::DashboardProjectRead,
    GatewayAction::DashboardApiKeyRead,
    GatewayAction::BudgetDashboardRead,
    GatewayAction::QuotaDashboardRead,
];

const PROJECT_DEVELOPER_ACTIONS: &[GatewayAction] = &[
    GatewayAction::ProjectRead,
    GatewayAction::ModelAliasRead,
    GatewayAction::ModelInvoke,
    GatewayAction::ModelStream,
    GatewayAction::UsageSummaryRead,
    GatewayAction::DashboardProjectRead,
    GatewayAction::ModelObservabilityRead,
];

const PROJECT_VIEWER_ACTIONS: &[GatewayAction] = &[
    GatewayAction::ProjectRead,
    GatewayAction::ModelAliasRead,
    GatewayAction::UsageSummaryRead,
    GatewayAction::DashboardProjectRead,
    GatewayAction::BudgetDashboardRead,
    GatewayAction::QuotaDashboardRead,
    GatewayAction::ModelObservabilityRead,
];

const USAGE_VIEWER_ACTIONS: &[GatewayAction] = &[
    GatewayAction::UsageRead,
    GatewayAction::UsageSummaryRead,
    GatewayAction::UsageEventRead,
    GatewayAction::DashboardTenantRead,
    GatewayAction::DashboardOrganizationRead,
    GatewayAction::DashboardProjectRead,
    GatewayAction::DashboardProjectMemberRead,
    GatewayAction::DashboardApiKeyRead,
    GatewayAction::DashboardServiceAccountRead,
    GatewayAction::BudgetDashboardRead,
    GatewayAction::QuotaDashboardRead,
    GatewayAction::ExportRead,
    GatewayAction::ExportCreate,
];

const AUDITOR_ACTIONS: &[GatewayAction] = &[
    GatewayAction::AuditRead,
    GatewayAction::RouteDebugRead,
    GatewayAction::ConfigRead,
    GatewayAction::UsageEventRead,
    GatewayAction::ExportRead,
];

/// Authorization resource descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceRef {
    /// Resource kind, such as `ModelAlias` or `ApiKey`.
    pub kind: String,
    /// Resource id or wildcard scope id.
    pub id: String,
}

impl ResourceRef {
    /// Creates a model alias resource reference.
    #[must_use]
    pub fn model_alias(id: impl Into<String>) -> Self {
        Self {
            kind: "ModelAlias".to_owned(),
            id: id.into(),
        }
    }
}

/// Authorization decision request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthorizationRequest {
    /// Authenticated actor.
    pub actor: AuthenticatedActor,
    /// Requested action.
    pub action: GatewayAction,
    /// Protected resource.
    pub resource: ResourceRef,
}

/// Foundation action grant used before Cedar policy snapshots are wired.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionGrant {
    /// Tenant boundary for the grant.
    pub tenant_id: String,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Principal receiving the grant.
    pub principal_id: String,
    /// Granted action.
    pub action: GatewayAction,
    /// Granted resource kind.
    pub resource_kind: String,
    /// Granted resource id or wildcard.
    pub resource_id: String,
}

impl ActionGrant {
    /// Creates a project-scoped action grant.
    #[must_use]
    pub fn project(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        principal_id: impl Into<String>,
        action: GatewayAction,
        resource: ResourceRef,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            organization_id: Some(organization_id.into()),
            project_id: Some(project_id.into()),
            principal_id: principal_id.into(),
            action,
            resource_kind: resource.kind,
            resource_id: resource.id,
        }
    }

    /// Expands a built-in role binding into action grants.
    #[must_use]
    pub fn for_builtin_role(
        tenant_id: impl Into<String>,
        organization_id: Option<impl Into<String>>,
        project_id: Option<impl Into<String>>,
        principal_id: impl Into<String>,
        role: BuiltInRole,
    ) -> Vec<Self> {
        let tenant_id = tenant_id.into();
        let organization_id = organization_id.map(Into::into);
        let project_id = project_id.map(Into::into);
        let principal_id = principal_id.into();
        role.actions()
            .iter()
            .map(|action| Self {
                tenant_id: tenant_id.clone(),
                organization_id: organization_id.clone(),
                project_id: project_id.clone(),
                principal_id: principal_id.clone(),
                action: *action,
                resource_kind: action.resource_kind().to_owned(),
                resource_id: "*".to_owned(),
            })
            .collect()
    }
}

/// Authorization decision result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorizationDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Stable denial or allow reason.
    pub reason: &'static str,
}

/// Durable authorization decision evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuthorizationDecisionRecord {
    /// Stable authorization decision id.
    pub authz_decision_id: String,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<OrganizationId>,
    /// Optional project boundary.
    pub project_id: Option<ProjectId>,
    /// Authenticated actor id.
    pub actor_id: String,
    /// Authenticated actor kind.
    pub actor_kind: ActorKind,
    /// Requested action.
    pub action: GatewayAction,
    /// Protected resource kind.
    pub resource_kind: String,
    /// Protected resource id.
    pub resource_id: String,
    /// Whether the request was allowed.
    pub allowed: bool,
    /// Stable decision reason.
    pub reason: String,
    /// Policy snapshot id when available.
    pub policy_snapshot_id: Option<String>,
    /// Gateway request id.
    pub request_id: String,
    /// Decision timestamp.
    pub occurred_at: DateTime<Utc>,
}

/// Item plus resource identity for list authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizableItem<T> {
    /// Protected item resource.
    pub resource: ResourceRef,
    /// Item payload.
    pub item: T,
}

/// Result of item-level list authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedItemList<T> {
    /// Items allowed by the policy engine.
    pub items: Vec<T>,
    /// Number of items filtered by item policy.
    pub filtered_count: usize,
}

impl AuthorizationDecisionRecord {
    /// Creates durable evidence from an authorization request and decision.
    #[must_use]
    pub fn from_decision(
        request: &AuthorizationRequest,
        decision: &AuthorizationDecision,
        policy_snapshot_id: Option<String>,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            authz_decision_id: new_prefixed_id("azd"),
            tenant_id: request.actor.tenant_id.clone(),
            organization_id: request.actor.organization_id.clone(),
            project_id: request.actor.project_id.clone(),
            actor_id: request.actor.actor_id.clone(),
            actor_kind: request.actor.actor_kind.clone(),
            action: request.action,
            resource_kind: request.resource.kind.clone(),
            resource_id: request.resource.id.clone(),
            allowed: decision.allowed,
            reason: decision.reason.to_owned(),
            policy_snapshot_id,
            request_id: request.actor.request_id.clone(),
            occurred_at,
        }
    }

    /// Returns the SQL decision label.
    #[must_use]
    pub const fn decision_label(&self) -> &'static str {
        if self.allowed {
            "allowed"
        } else {
            "denied"
        }
    }
}

/// Repository boundary for authorization decision evidence.
pub trait AuthorizationEvidenceSink: Send + Sync {
    /// Records authorization decision evidence.
    fn record_authorization_decision(&self, record: AuthorizationDecisionRecord);
}

impl AuthorizationDecision {
    /// Creates an allowed decision.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allowed: true,
            reason: "allowed",
        }
    }

    /// Creates a denied decision.
    #[must_use]
    pub const fn deny(reason: &'static str) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }
}

/// Authorization engine boundary.
pub trait AuthorizationEngine: Send + Sync {
    /// Authorizes a gateway operation.
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision;
}

/// Authorizes a request and writes redacted decision evidence.
pub fn authorize_with_evidence(
    engine: &dyn AuthorizationEngine,
    sink: &dyn AuthorizationEvidenceSink,
    request: &AuthorizationRequest,
    policy_snapshot_id: Option<String>,
    occurred_at: DateTime<Utc>,
) -> AuthorizationDecision {
    let decision = engine.authorize(request);
    sink.record_authorization_decision(AuthorizationDecisionRecord::from_decision(
        request,
        &decision,
        policy_snapshot_id,
        occurred_at,
    ));
    decision
}

/// Filters a list through item-level authorization.
#[must_use]
pub fn authorize_item_list<T>(
    engine: &dyn AuthorizationEngine,
    actor: &AuthenticatedActor,
    action: GatewayAction,
    items: impl IntoIterator<Item = AuthorizableItem<T>>,
) -> AuthorizedItemList<T> {
    let mut allowed_items = Vec::new();
    let mut filtered_count = 0;
    for item in items {
        let decision = engine.authorize(&AuthorizationRequest {
            actor: actor.clone(),
            action,
            resource: item.resource,
        });
        if decision.allowed {
            allowed_items.push(item.item);
        } else {
            filtered_count += 1;
        }
    }
    AuthorizedItemList {
        items: allowed_items,
        filtered_count,
    }
}

/// Foundation policy engine used before Cedar policies are wired.
#[derive(Debug, Default)]
pub struct FoundationAuthorizationEngine {
    grants: Vec<ActionGrant>,
}

impl FoundationAuthorizationEngine {
    /// Creates a foundation engine from explicit action grants.
    #[must_use]
    pub const fn new(grants: Vec<ActionGrant>) -> Self {
        Self { grants }
    }
}

impl AuthorizationEngine for FoundationAuthorizationEngine {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        if let Some(decision) = gateway_preflight_decision(request) {
            return decision;
        }
        if request.action == GatewayAction::ModelNative {
            return AuthorizationDecision::deny("native_route_grant_required");
        }
        if !self.grants.iter().any(|grant| grant_allows(grant, request)) {
            return AuthorizationDecision::deny("principal_action_not_granted");
        }
        AuthorizationDecision::allow()
    }
}

/// Applies non-policy authorization gates shared by all gateway policy engines.
#[must_use]
pub(crate) fn gateway_preflight_decision(
    request: &AuthorizationRequest,
) -> Option<AuthorizationDecision> {
    if request.actor.api_key_id.is_some()
        && matches!(
            request.action,
            GatewayAction::ConfigPublish
                | GatewayAction::ConfigRollback
                | GatewayAction::ObservabilityExportWrite
        )
    {
        return Some(AuthorizationDecision::deny("api_key_strong_auth_required"));
    }
    if request.actor.api_key_id.is_some()
        && !api_key_allows_action(&request.actor.api_key_allowed_actions, request.action)
    {
        return Some(AuthorizationDecision::deny("api_key_action_not_granted"));
    }
    if request.actor.api_key_id.is_some()
        && !api_key_allows_resource(&request.actor.api_key_allowed_resources, &request.resource)
    {
        return Some(AuthorizationDecision::deny("api_key_resource_not_granted"));
    }
    None
}

fn grant_allows(grant: &ActionGrant, request: &AuthorizationRequest) -> bool {
    let Some(principal_id) = request.actor.principal_id.as_deref() else {
        return false;
    };
    grant.tenant_id == request.actor.tenant_id
        && optional_scope_match(
            grant.organization_id.as_deref(),
            request.actor.organization_id.as_deref(),
        )
        && optional_scope_match(
            grant.project_id.as_deref(),
            request.actor.project_id.as_deref(),
        )
        && grant.principal_id == principal_id
        && grant.action == request.action
        && resource_matches(grant, &request.resource)
}

fn optional_scope_match(grant_scope: Option<&str>, actor_scope: Option<&str>) -> bool {
    grant_scope.is_none_or(|grant_scope| Some(grant_scope) == actor_scope)
}

fn resource_matches(grant: &ActionGrant, resource: &ResourceRef) -> bool {
    grant.resource_kind == resource.kind
        && (grant.resource_id == "*" || grant.resource_id == resource.id)
}

fn api_key_allows_action(allowed_actions: &[String], action: GatewayAction) -> bool {
    allowed_actions.is_empty()
        || allowed_actions
            .iter()
            .any(|allowed| allowed == action.as_str() || allowed == "*")
}

fn api_key_allows_resource(allowed_resources: &[String], resource: &ResourceRef) -> bool {
    allowed_resources.is_empty()
        || allowed_resources.iter().any(|allowed| {
            allowed == "*"
                || allowed == &resource.id
                || allowed == &format!("{}:{}", resource.kind, resource.id)
                || allowed == &format!("{}:*", resource.kind)
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::action::{
        authorize_item_list, authorize_with_evidence, ActionGrant, AuthorizableItem,
        AuthorizationEngine, AuthorizationRequest, BuiltInRole, FoundationAuthorizationEngine,
        GatewayAction, ResourceRef,
    };
    use crate::domain::{ActorKind, AuthenticatedActor, CredentialKind};
    use crate::storage::InMemoryGatewayStore;

    fn api_key_actor() -> AuthenticatedActor {
        AuthenticatedActor {
            actor_id: "ak_test".to_owned(),
            actor_kind: ActorKind::ApiKey,
            tenant_id: "ten_test".to_owned(),
            organization_id: Some("org_test".to_owned()),
            project_id: Some("prj_test".to_owned()),
            principal_id: Some("usr_test".to_owned()),
            api_key_id: Some("ak_test".to_owned()),
            credential_kind: CredentialKind::ApiKey,
            auth_strength: 50,
            expires_at: None,
            api_key_allowed_actions: Vec::new(),
            api_key_allowed_resources: Vec::new(),
            request_id: "req_test".to_owned(),
        }
    }

    fn engine_with_model_grant() -> FoundationAuthorizationEngine {
        FoundationAuthorizationEngine::new(vec![ActionGrant::project(
            "ten_test",
            "org_test",
            "prj_test",
            "usr_test",
            GatewayAction::ModelInvoke,
            ResourceRef::model_alias("ma_test"),
        )])
    }

    fn request(action: GatewayAction, resource_id: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            actor: api_key_actor(),
            action,
            resource: ResourceRef {
                kind: action.resource_kind().to_owned(),
                id: resource_id.to_owned(),
            },
        }
    }

    #[test]
    fn canonical_action_definitions_are_unique_and_namespaced() {
        let mut ids = HashSet::new();
        for definition in GatewayAction::canonical_definitions() {
            assert!(definition.action_id.starts_with("gateway."));
            assert!(!definition.resource_kind.is_empty());
            assert_eq!(definition.action.as_str(), definition.action_id);
            assert_eq!(definition.action.resource_kind(), definition.resource_kind);
            assert!(ids.insert(definition.action_id), "duplicate action id");
        }
    }

    #[test]
    fn canonical_actions_cover_authorization_spec() {
        let code_actions = GatewayAction::canonical_actions()
            .iter()
            .map(|action| action.as_str())
            .collect::<HashSet<_>>();

        assert_eq!(code_actions, spec_action_ids());
    }

    #[test]
    fn gateway_action_serializes_as_stable_action_id() {
        let encoded = match serde_json::to_string(&GatewayAction::ModelInvoke) {
            Ok(value) => value,
            Err(error) => panic!("action should serialize: {error}"),
        };
        let decoded = match serde_json::from_str::<GatewayAction>(&encoded) {
            Ok(value) => value,
            Err(error) => panic!("action should deserialize: {error}"),
        };
        let unknown = serde_json::from_str::<GatewayAction>("\"gateway.unknown\"");

        assert_eq!(encoded, "\"gateway.model.invoke\"");
        assert_eq!(decoded, GatewayAction::ModelInvoke);
        assert!(unknown.is_err());
    }

    #[test]
    fn built_in_roles_are_unique_and_documented_in_spec() {
        let spec = include_str!("../../../spec/gateway/02-tenancy-access.md");
        let mut ids = HashSet::new();
        for role in BuiltInRole::built_ins() {
            assert!(ids.insert(role.as_str()), "duplicate built-in role");
            assert!(
                spec.contains(&format!("`{}`", role.as_str())),
                "role {} missing from tenancy spec",
                role.as_str()
            );
            assert!(!role.scope_kind().as_str().is_empty());
        }
    }

    #[test]
    fn built_in_role_actions_are_registered_and_nonempty() {
        for role in BuiltInRole::built_ins() {
            let mut actions = HashSet::new();
            assert!(
                !role.actions().is_empty(),
                "role {} has no actions",
                role.as_str()
            );
            for action in role.actions() {
                assert!(
                    GatewayAction::canonical_actions().contains(action),
                    "role {} uses unregistered action {}",
                    role.as_str(),
                    action.as_str()
                );
                assert!(
                    actions.insert(action.as_str()),
                    "role {} repeats action {}",
                    role.as_str(),
                    action.as_str()
                );
            }
        }
    }

    #[test]
    fn tenant_owner_role_grants_every_canonical_action() {
        assert_eq!(
            BuiltInRole::TenantOwner.actions(),
            GatewayAction::canonical_actions()
        );
    }

    #[test]
    fn api_keys_need_stronger_auth_for_sensitive_admin_actions() {
        let engine = FoundationAuthorizationEngine::default();
        for action in [
            GatewayAction::ConfigPublish,
            GatewayAction::ConfigRollback,
            GatewayAction::ObservabilityExportWrite,
        ] {
            let decision = engine.authorize(&AuthorizationRequest {
                actor: api_key_actor(),
                action,
                resource: ResourceRef {
                    kind: "ConfigSnapshot".to_owned(),
                    id: "cfg_test".to_owned(),
                },
            });
            assert!(!decision.allowed);
            assert_eq!(decision.reason, "api_key_strong_auth_required");
        }
    }

    #[test]
    fn native_model_routes_are_denied_by_default() {
        let engine = FoundationAuthorizationEngine::default();
        let decision = engine.authorize(&AuthorizationRequest {
            actor: api_key_actor(),
            action: GatewayAction::ModelNative,
            resource: ResourceRef::model_alias("ma_test"),
        });

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "native_route_grant_required");
    }

    #[test]
    fn api_key_action_prefilter_narrows_owner_policy() {
        let engine = engine_with_model_grant();
        let mut actor = api_key_actor();
        actor
            .api_key_allowed_actions
            .push(GatewayAction::UsageSummaryRead.as_str().to_owned());

        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: GatewayAction::ModelInvoke,
            resource: ResourceRef::model_alias("ma_test"),
        });

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "api_key_action_not_granted");
    }

    #[test]
    fn api_key_resource_prefilter_narrows_owner_policy() {
        let engine = engine_with_model_grant();
        let mut actor = api_key_actor();
        actor
            .api_key_allowed_resources
            .push("ModelAlias:ma_allowed".to_owned());

        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: GatewayAction::ModelInvoke,
            resource: ResourceRef::model_alias("ma_denied"),
        });

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "api_key_resource_not_granted");
    }

    #[test]
    fn missing_owner_grant_is_denied_by_default() {
        let engine = FoundationAuthorizationEngine::default();
        let decision = engine.authorize(&AuthorizationRequest {
            actor: api_key_actor(),
            action: GatewayAction::ModelInvoke,
            resource: ResourceRef::model_alias("ma_test"),
        });

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "principal_action_not_granted");
    }

    #[test]
    fn tenant_scoped_role_grant_inherits_to_project_actor() {
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            "ten_test",
            Option::<String>::None,
            Option::<String>::None,
            "usr_test",
            BuiltInRole::TenantOwner,
        ));

        let decision = engine.authorize(&request(GatewayAction::ProjectRead, "prj_test"));

        assert!(decision.allowed);
        assert_eq!(decision.reason, "allowed");
    }

    #[test]
    fn project_scoped_role_grant_does_not_cross_project() {
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            "ten_test",
            Some("org_test"),
            Some("prj_other"),
            "usr_test",
            BuiltInRole::ProjectAdmin,
        ));

        let decision = engine.authorize(&request(GatewayAction::ApiKeyCreate, "ak_new"));

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "principal_action_not_granted");
    }

    #[test]
    fn api_key_rest_action_requires_owner_grant_and_key_grant() {
        let mut actor = api_key_actor();
        actor
            .api_key_allowed_actions
            .push(GatewayAction::ApiKeyCreate.as_str().to_owned());
        let no_owner_grant =
            FoundationAuthorizationEngine::default().authorize(&AuthorizationRequest {
                actor: actor.clone(),
                action: GatewayAction::ApiKeyCreate,
                resource: ResourceRef {
                    kind: "ApiKey".to_owned(),
                    id: "ak_new".to_owned(),
                },
            });
        assert!(!no_owner_grant.allowed);
        assert_eq!(no_owner_grant.reason, "principal_action_not_granted");

        actor.api_key_allowed_actions.clear();
        actor
            .api_key_allowed_actions
            .push(GatewayAction::ModelInvoke.as_str().to_owned());
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            "ten_test",
            Some("org_test"),
            Some("prj_test"),
            "usr_test",
            BuiltInRole::ProjectAdmin,
        ));
        let key_not_granted = engine.authorize(&AuthorizationRequest {
            actor: actor.clone(),
            action: GatewayAction::ApiKeyCreate,
            resource: ResourceRef {
                kind: "ApiKey".to_owned(),
                id: "ak_new".to_owned(),
            },
        });
        assert!(!key_not_granted.allowed);
        assert_eq!(key_not_granted.reason, "api_key_action_not_granted");

        actor.api_key_allowed_actions.clear();
        actor
            .api_key_allowed_actions
            .push(GatewayAction::ApiKeyCreate.as_str().to_owned());
        let allowed = engine.authorize(&AuthorizationRequest {
            actor,
            action: GatewayAction::ApiKeyCreate,
            resource: ResourceRef {
                kind: "ApiKey".to_owned(),
                id: "ak_new".to_owned(),
            },
        });
        assert!(allowed.allowed);
        assert_eq!(allowed.reason, "allowed");
    }

    #[test]
    fn item_level_authorization_filters_denied_items() {
        let engine = FoundationAuthorizationEngine::new(vec![ActionGrant::project(
            "ten_test",
            "org_test",
            "prj_test",
            "usr_test",
            GatewayAction::ModelAliasRead,
            ResourceRef::model_alias("ma_allowed"),
        )]);
        let items = [
            AuthorizableItem {
                resource: ResourceRef::model_alias("ma_allowed"),
                item: "allowed",
            },
            AuthorizableItem {
                resource: ResourceRef::model_alias("ma_denied"),
                item: "denied",
            },
        ];

        let authorized = authorize_item_list(
            &engine,
            &api_key_actor(),
            GatewayAction::ModelAliasRead,
            items,
        );

        assert_eq!(authorized.items, vec!["allowed"]);
        assert_eq!(authorized.filtered_count, 1);
    }

    #[test]
    fn item_level_authorization_applies_api_key_resource_prefilter() {
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            "ten_test",
            Some("org_test"),
            Some("prj_test"),
            "usr_test",
            BuiltInRole::ProjectViewer,
        ));
        let mut actor = api_key_actor();
        actor
            .api_key_allowed_resources
            .push("ModelAlias:ma_allowed".to_owned());
        let items = [
            AuthorizableItem {
                resource: ResourceRef::model_alias("ma_allowed"),
                item: "allowed",
            },
            AuthorizableItem {
                resource: ResourceRef::model_alias("ma_denied"),
                item: "denied",
            },
        ];

        let authorized = authorize_item_list(&engine, &actor, GatewayAction::ModelAliasRead, items);

        assert_eq!(authorized.items, vec!["allowed"]);
        assert_eq!(authorized.filtered_count, 1);
    }

    #[test]
    fn owner_grant_allows_api_key_when_key_does_not_widen_scope() {
        let engine = engine_with_model_grant();
        let decision = engine.authorize(&AuthorizationRequest {
            actor: api_key_actor(),
            action: GatewayAction::ModelInvoke,
            resource: ResourceRef::model_alias("ma_test"),
        });

        assert!(decision.allowed);
        assert_eq!(decision.reason, "allowed");
    }

    #[test]
    fn authorization_decision_evidence_is_recorded_for_denials() {
        let engine = FoundationAuthorizationEngine::default();
        let store = InMemoryGatewayStore::default();
        let request = AuthorizationRequest {
            actor: api_key_actor(),
            action: GatewayAction::ModelInvoke,
            resource: ResourceRef::model_alias("ma_test"),
        };

        let decision = authorize_with_evidence(&engine, &store, &request, None, chrono::Utc::now());

        assert!(!decision.allowed);
        let records = store.authorization_decisions();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].reason, "principal_action_not_granted");
        assert_eq!(records[0].decision_label(), "denied");
    }

    fn spec_action_ids() -> HashSet<&'static str> {
        include_str!("../../../spec/gateway/10-authorization-api-keys.md")
            .split(|character: char| {
                !(character.is_ascii_alphanumeric() || character == '_' || character == '.')
            })
            .filter(|token| token.starts_with("gateway."))
            .collect()
    }
}
