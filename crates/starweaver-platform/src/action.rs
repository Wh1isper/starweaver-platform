//! Platform-local action registry and authorization request types.

/// Canonical platform action definition used by policy and route metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionDefinition {
    /// Type-safe action value.
    pub action: PlatformAction,
    /// Stable action id.
    pub action_id: &'static str,
    /// Canonical authorization resource kind.
    pub resource_kind: &'static str,
}

/// Authenticated platform actor kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    /// Human user principal.
    User,
    /// Automation or integration principal.
    ServiceAccount,
    /// Internal system worker principal.
    System,
}

/// Authenticated actor context passed to platform authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedActor {
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional active organization id.
    pub organization_id: Option<String>,
    /// Optional active project id.
    pub project_id: Option<String>,
    /// Principal id, such as a user or service account id.
    pub principal_id: String,
    /// Actor kind.
    pub actor_kind: ActorKind,
}

impl AuthenticatedActor {
    /// Builds a user actor inside a project.
    #[must_use]
    pub fn project_user(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        principal_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            organization_id: Some(organization_id.into()),
            project_id: Some(project_id.into()),
            principal_id: principal_id.into(),
            actor_kind: ActorKind::User,
        }
    }

    /// Builds a service-account actor inside a project.
    #[must_use]
    pub fn project_service_account(
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        principal_id: impl Into<String>,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            organization_id: Some(organization_id.into()),
            project_id: Some(project_id.into()),
            principal_id: principal_id.into(),
            actor_kind: ActorKind::ServiceAccount,
        }
    }
}

/// Authorization resource reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceRef {
    /// Resource kind, such as `Run` or `EnvironmentAttachment`.
    pub kind: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional owning organization id.
    pub organization_id: Option<String>,
    /// Optional owning project id.
    pub project_id: Option<String>,
    /// Stable resource id.
    pub resource_id: String,
}

impl ResourceRef {
    /// Builds a project-scoped resource reference.
    #[must_use]
    pub fn project(
        kind: impl Into<String>,
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            tenant_id: tenant_id.into(),
            organization_id: Some(organization_id.into()),
            project_id: Some(project_id.into()),
            resource_id: resource_id.into(),
        }
    }

    /// Builds a tenant-scoped resource reference.
    #[must_use]
    pub fn tenant(
        kind: impl Into<String>,
        tenant_id: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            tenant_id: tenant_id.into(),
            organization_id: None,
            project_id: None,
            resource_id: resource_id.into(),
        }
    }
}

/// Scope kind accepted by a built-in platform role.
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

/// Built-in platform role id.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BuiltInRole {
    /// Full tenant administration role.
    TenantOwner,
    /// Tenant-level platform operator.
    PlatformOperator,
    /// Organization-level administration role.
    OrganizationAdmin,
    /// Project-level administration role.
    ProjectAdmin,
    /// Project developer role.
    ProjectDeveloper,
    /// Project read-only role.
    ProjectViewer,
    /// Audit and evidence inspection role.
    Auditor,
}

impl BuiltInRole {
    /// Returns every built-in platform role.
    #[must_use]
    pub const fn built_ins() -> &'static [Self] {
        &[
            Self::TenantOwner,
            Self::PlatformOperator,
            Self::OrganizationAdmin,
            Self::ProjectAdmin,
            Self::ProjectDeveloper,
            Self::ProjectViewer,
            Self::Auditor,
        ]
    }

    /// Returns the stable role id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TenantOwner => "tenant_owner",
            Self::PlatformOperator => "platform_operator",
            Self::OrganizationAdmin => "organization_admin",
            Self::ProjectAdmin => "project_admin",
            Self::ProjectDeveloper => "project_developer",
            Self::ProjectViewer => "project_viewer",
            Self::Auditor => "auditor",
        }
    }

    /// Returns the role scope kind.
    #[must_use]
    pub const fn scope_kind(self) -> RoleScopeKind {
        match self {
            Self::TenantOwner | Self::PlatformOperator => RoleScopeKind::Tenant,
            Self::OrganizationAdmin => RoleScopeKind::Organization,
            Self::ProjectAdmin | Self::ProjectDeveloper | Self::ProjectViewer => {
                RoleScopeKind::Project
            }
            Self::Auditor => RoleScopeKind::Any,
        }
    }

    /// Returns the actions granted by the role.
    #[must_use]
    pub const fn actions(self) -> &'static [PlatformAction] {
        match self {
            Self::TenantOwner => PlatformAction::canonical_actions(),
            Self::PlatformOperator => PLATFORM_OPERATOR_ACTIONS,
            Self::OrganizationAdmin => ORGANIZATION_ADMIN_ACTIONS,
            Self::ProjectAdmin => PROJECT_ADMIN_ACTIONS,
            Self::ProjectDeveloper => PROJECT_DEVELOPER_ACTIONS,
            Self::ProjectViewer => PROJECT_VIEWER_ACTIONS,
            Self::Auditor => AUDITOR_ACTIONS,
        }
    }
}

macro_rules! platform_actions {
    ($(($variant:ident, $action_id:literal, $resource_kind:literal, $requires_user:literal)),+ $(,)?) => {
        /// Stable platform action id.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum PlatformAction {
            $(
                #[doc = concat!("Platform action `", $action_id, "`.")]
                $variant,
            )+
        }

        impl PlatformAction {
            /// Returns the stable action id used by policy and route metadata.
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

            /// Returns whether the action requires a human user actor.
            #[must_use]
            pub const fn requires_user_actor(self) -> bool {
                match self {
                    $(Self::$variant => $requires_user,)+
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

            /// Returns every canonical platform action.
            #[must_use]
            pub const fn canonical_actions() -> &'static [Self] {
                &[$(Self::$variant,)+]
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
    };
}

platform_actions!(
    (
        ConversationCreate,
        "platform.conversation.create",
        "Conversation",
        false
    ),
    (
        ConversationRead,
        "platform.conversation.read",
        "Conversation",
        false
    ),
    (
        ConversationUpdate,
        "platform.conversation.update",
        "Conversation",
        true
    ),
    (
        SessionCreate,
        "platform.session.create",
        "AgentSession",
        false
    ),
    (SessionRead, "platform.session.read", "AgentSession", false),
    (RunCreate, "platform.run.create", "Run", false),
    (RunRead, "platform.run.read", "Run", false),
    (RunCancel, "platform.run.cancel", "Run", true),
    (RunSteer, "platform.run.steer", "Run", true),
    (RunEventRead, "platform.run_event.read", "RunEvent", false),
    (ApprovalRead, "platform.approval.read", "Approval", true),
    (ApprovalDecide, "platform.approval.decide", "Approval", true),
    (
        DeferredToolRead,
        "platform.deferred_tool.read",
        "DeferredTool",
        false
    ),
    (
        DeferredToolResume,
        "platform.deferred_tool.resume",
        "DeferredTool",
        true
    ),
    (
        EnvironmentAttachmentCreate,
        "platform.environment_attachment.create",
        "EnvironmentAttachment",
        false
    ),
    (
        EnvironmentAttachmentRead,
        "platform.environment_attachment.read",
        "EnvironmentAttachment",
        false
    ),
    (
        EnvironmentAttachmentRelease,
        "platform.environment_attachment.release",
        "EnvironmentAttachment",
        true
    ),
    (
        EnvironmentAttachmentHealthRead,
        "platform.environment_attachment.health.read",
        "EnvironmentAttachment",
        false
    ),
    (
        EvidenceArchiveRead,
        "platform.evidence_archive.read",
        "EvidenceArchive",
        false
    ),
    (
        EvidenceArchiveDebugRead,
        "platform.evidence_archive.debug.read",
        "EvidenceArchive",
        true
    ),
);

const PLATFORM_OPERATOR_ACTIONS: &[PlatformAction] = &[
    PlatformAction::ConversationRead,
    PlatformAction::SessionRead,
    PlatformAction::RunRead,
    PlatformAction::RunEventRead,
    PlatformAction::EnvironmentAttachmentRead,
    PlatformAction::EnvironmentAttachmentHealthRead,
    PlatformAction::EvidenceArchiveRead,
];

const ORGANIZATION_ADMIN_ACTIONS: &[PlatformAction] = &[
    PlatformAction::ConversationCreate,
    PlatformAction::ConversationRead,
    PlatformAction::ConversationUpdate,
    PlatformAction::SessionCreate,
    PlatformAction::SessionRead,
    PlatformAction::RunCreate,
    PlatformAction::RunRead,
    PlatformAction::RunCancel,
    PlatformAction::RunEventRead,
    PlatformAction::ApprovalRead,
    PlatformAction::ApprovalDecide,
    PlatformAction::DeferredToolRead,
    PlatformAction::DeferredToolResume,
    PlatformAction::EnvironmentAttachmentCreate,
    PlatformAction::EnvironmentAttachmentRead,
    PlatformAction::EnvironmentAttachmentRelease,
    PlatformAction::EnvironmentAttachmentHealthRead,
    PlatformAction::EvidenceArchiveRead,
];

const PROJECT_ADMIN_ACTIONS: &[PlatformAction] = ORGANIZATION_ADMIN_ACTIONS;

const PROJECT_DEVELOPER_ACTIONS: &[PlatformAction] = &[
    PlatformAction::ConversationCreate,
    PlatformAction::ConversationRead,
    PlatformAction::SessionCreate,
    PlatformAction::SessionRead,
    PlatformAction::RunCreate,
    PlatformAction::RunRead,
    PlatformAction::RunCancel,
    PlatformAction::RunSteer,
    PlatformAction::RunEventRead,
    PlatformAction::ApprovalRead,
    PlatformAction::ApprovalDecide,
    PlatformAction::DeferredToolRead,
    PlatformAction::DeferredToolResume,
    PlatformAction::EnvironmentAttachmentCreate,
    PlatformAction::EnvironmentAttachmentRead,
    PlatformAction::EnvironmentAttachmentRelease,
    PlatformAction::EnvironmentAttachmentHealthRead,
    PlatformAction::EvidenceArchiveRead,
];

const PROJECT_VIEWER_ACTIONS: &[PlatformAction] = &[
    PlatformAction::ConversationRead,
    PlatformAction::SessionRead,
    PlatformAction::RunRead,
    PlatformAction::RunEventRead,
    PlatformAction::ApprovalRead,
    PlatformAction::DeferredToolRead,
    PlatformAction::EnvironmentAttachmentRead,
    PlatformAction::EnvironmentAttachmentHealthRead,
    PlatformAction::EvidenceArchiveRead,
];

const AUDITOR_ACTIONS: &[PlatformAction] = &[
    PlatformAction::RunRead,
    PlatformAction::RunEventRead,
    PlatformAction::EvidenceArchiveRead,
    PlatformAction::EvidenceArchiveDebugRead,
];

/// Platform authorization grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionGrant {
    /// Owning tenant id.
    pub tenant_id: String,
    /// Principal id that receives the grant.
    pub principal_id: String,
    /// Granted action.
    pub action: PlatformAction,
    /// Resource kind this grant applies to.
    pub resource_kind: String,
    /// Scope kind for the grant.
    pub scope_kind: RoleScopeKind,
    /// Scope id matching the scope kind.
    pub scope_id: String,
}

impl ActionGrant {
    /// Builds a grant for one action at project scope.
    #[must_use]
    pub fn project(
        tenant_id: impl Into<String>,
        project_id: impl Into<String>,
        principal_id: impl Into<String>,
        action: PlatformAction,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            principal_id: principal_id.into(),
            action,
            resource_kind: action.resource_kind().to_owned(),
            scope_kind: RoleScopeKind::Project,
            scope_id: project_id.into(),
        }
    }

    /// Builds every action grant for a built-in role.
    #[must_use]
    pub fn for_builtin_role(
        tenant_id: impl Into<String>,
        scope_id: impl Into<String>,
        principal_id: impl Into<String>,
        role: BuiltInRole,
    ) -> Vec<Self> {
        let tenant_id = tenant_id.into();
        let scope_id = scope_id.into();
        let principal_id = principal_id.into();
        role.actions()
            .iter()
            .map(|action| Self {
                tenant_id: tenant_id.clone(),
                principal_id: principal_id.clone(),
                action: *action,
                resource_kind: action.resource_kind().to_owned(),
                scope_kind: role.scope_kind(),
                scope_id: scope_id.clone(),
            })
            .collect()
    }
}

/// Authorization request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationRequest {
    /// Authenticated actor.
    pub actor: AuthenticatedActor,
    /// Requested action.
    pub action: PlatformAction,
    /// Requested resource.
    pub resource: ResourceRef,
}

/// Authorization decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Stable reason code.
    pub reason: &'static str,
}

impl AuthorizationDecision {
    /// Returns an allow decision.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allowed: true,
            reason: "allow",
        }
    }

    /// Returns a deny decision with a stable reason code.
    #[must_use]
    pub const fn deny(reason: &'static str) -> Self {
        Self {
            allowed: false,
            reason,
        }
    }
}

/// Platform authorization engine.
pub trait AuthorizationEngine {
    /// Authorizes one request.
    #[must_use]
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision;
}

/// Authorizable list item with a resource reference.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizableItem<T> {
    /// Item value.
    pub value: T,
    /// Authorization resource reference for the item.
    pub resource: ResourceRef,
}

/// Filters a list through the authorization engine.
#[must_use]
pub fn authorize_item_list<T>(
    engine: &dyn AuthorizationEngine,
    actor: &AuthenticatedActor,
    action: PlatformAction,
    items: impl IntoIterator<Item = AuthorizableItem<T>>,
) -> Vec<T> {
    items
        .into_iter()
        .filter_map(|item| {
            let decision = engine.authorize(&AuthorizationRequest {
                actor: actor.clone(),
                action,
                resource: item.resource,
            });
            decision.allowed.then_some(item.value)
        })
        .collect()
}

/// Foundation in-memory authorization engine for early platform service code.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FoundationAuthorizationEngine {
    grants: Vec<ActionGrant>,
}

impl FoundationAuthorizationEngine {
    /// Creates an engine from explicit grants.
    #[must_use]
    pub const fn new(grants: Vec<ActionGrant>) -> Self {
        Self { grants }
    }
}

impl AuthorizationEngine for FoundationAuthorizationEngine {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        if request.resource.tenant_id != request.actor.tenant_id {
            return AuthorizationDecision::deny("tenant_mismatch");
        }
        if request.resource.kind != request.action.resource_kind() {
            return AuthorizationDecision::deny("resource_kind_mismatch");
        }
        if request.action.requires_user_actor() && request.actor.actor_kind != ActorKind::User {
            return AuthorizationDecision::deny("user_actor_required");
        }
        if self.grants.iter().any(|grant| grant_allows(grant, request)) {
            AuthorizationDecision::allow()
        } else {
            AuthorizationDecision::deny("missing_action_grant")
        }
    }
}

fn grant_allows(grant: &ActionGrant, request: &AuthorizationRequest) -> bool {
    grant.tenant_id == request.actor.tenant_id
        && grant.principal_id == request.actor.principal_id
        && grant.action == request.action
        && grant.resource_kind == request.resource.kind
        && grant_scope_matches(grant, &request.resource)
}

fn grant_scope_matches(grant: &ActionGrant, resource: &ResourceRef) -> bool {
    match grant.scope_kind {
        RoleScopeKind::Tenant => grant.scope_id == resource.tenant_id,
        RoleScopeKind::Organization => {
            resource.organization_id.as_deref() == Some(grant.scope_id.as_str())
        }
        RoleScopeKind::Project => resource.project_id.as_deref() == Some(grant.scope_id.as_str()),
        RoleScopeKind::Any => {
            grant.scope_id == resource.tenant_id
                || resource.organization_id.as_deref() == Some(grant.scope_id.as_str())
                || resource.project_id.as_deref() == Some(grant.scope_id.as_str())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        authorize_item_list, ActionGrant, AuthenticatedActor, AuthorizationEngine,
        AuthorizationRequest, BuiltInRole, FoundationAuthorizationEngine, PlatformAction,
        ResourceRef,
    };

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const OTHER_PROJECT_ID: &str = "prj_other";
    const USER_ID: &str = "usr_test";
    const SERVICE_ACCOUNT_ID: &str = "svc_test";

    fn project_actor() -> AuthenticatedActor {
        AuthenticatedActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID)
    }

    fn run_resource(project_id: &str) -> ResourceRef {
        ResourceRef::project("Run", TENANT_ID, ORGANIZATION_ID, project_id, "run_test")
    }

    #[test]
    fn canonical_platform_actions_are_namespaced_and_unique() {
        let mut action_ids = HashSet::new();
        for definition in PlatformAction::canonical_definitions() {
            assert!(definition.action_id.starts_with("platform."));
            assert!(action_ids.insert(definition.action_id));
            assert_eq!(definition.action.as_str(), definition.action_id);
            assert_eq!(definition.action.resource_kind(), definition.resource_kind);
            assert_eq!(
                PlatformAction::from_action_id(definition.action_id),
                Some(definition.action)
            );
        }
        assert!(PlatformAction::from_action_id("gateway.model.invoke").is_none());
    }

    #[test]
    fn built_in_roles_are_nonempty_and_scope_bound() {
        for role in BuiltInRole::built_ins() {
            assert!(!role.as_str().is_empty());
            assert!(!role.scope_kind().as_str().is_empty());
            assert!(!role.actions().is_empty());
        }
    }

    #[test]
    fn project_role_grant_allows_project_run_creation() {
        let actor = project_actor();
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectDeveloper,
        ));
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::RunCreate,
            resource: run_resource(PROJECT_ID),
        });
        assert!(decision.allowed, "{decision:?}");
    }

    #[test]
    fn project_scoped_role_does_not_cross_project() {
        let actor = project_actor();
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectDeveloper,
        ));
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::RunCreate,
            resource: run_resource(OTHER_PROJECT_ID),
        });
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "missing_action_grant");
    }

    #[test]
    fn organization_role_grant_inherits_to_project_resources() {
        let actor = project_actor();
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            ORGANIZATION_ID,
            USER_ID,
            BuiltInRole::OrganizationAdmin,
        ));
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::EnvironmentAttachmentCreate,
            resource: ResourceRef::project(
                "EnvironmentAttachment",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
                "envatt_test",
            ),
        });
        assert!(decision.allowed, "{decision:?}");
    }

    #[test]
    fn service_account_cannot_use_user_only_approval_permission() {
        let actor = AuthenticatedActor::project_service_account(
            TENANT_ID,
            ORGANIZATION_ID,
            PROJECT_ID,
            SERVICE_ACCOUNT_ID,
        );
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            TENANT_ID,
            SERVICE_ACCOUNT_ID,
            BuiltInRole::TenantOwner,
        ));
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::ApprovalDecide,
            resource: ResourceRef::project(
                "Approval",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
                "appr_test",
            ),
        });
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "user_actor_required");
    }

    #[test]
    fn action_resource_kind_mismatch_is_denied_before_grants() {
        let actor = project_actor();
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectAdmin,
        ));
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::RunRead,
            resource: ResourceRef::project(
                "Approval",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
                "appr_test",
            ),
        });
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "resource_kind_mismatch");
    }

    #[test]
    fn item_level_authorization_filters_denied_items() {
        let actor = project_actor();
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectViewer,
        ));
        let authorized = authorize_item_list(
            &engine,
            &actor,
            PlatformAction::RunRead,
            [
                super::AuthorizableItem {
                    value: "allowed",
                    resource: run_resource(PROJECT_ID),
                },
                super::AuthorizableItem {
                    value: "denied",
                    resource: run_resource(OTHER_PROJECT_ID),
                },
            ],
        );
        assert_eq!(authorized, vec!["allowed"]);
    }
}
