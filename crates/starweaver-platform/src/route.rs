//! Platform route metadata for authorization and handler wiring.

use crate::action::PlatformAction;

/// HTTP method used by platform route metadata.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpMethod {
    /// HTTP `DELETE`.
    Delete,
    /// HTTP `GET`.
    Get,
    /// HTTP `POST`.
    Post,
}

impl HttpMethod {
    /// Returns the stable method string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "DELETE",
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// Access boundary used by platform route metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteAccess {
    /// Route can be called before authentication, such as login discovery.
    Public,
    /// Route requires an authenticated user session but is not action-authorized.
    Session,
    /// Route requires the canonical authorization engine.
    Authorized,
}

impl RouteAccess {
    /// Returns the stable access class string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Session => "session",
            Self::Authorized => "authorized",
        }
    }
}

/// Static route metadata used before route handlers read or mutate resources.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RouteMetadata {
    /// HTTP method.
    pub method: HttpMethod,
    /// Stable path pattern.
    pub path_pattern: &'static str,
    /// Authorization action.
    pub action: PlatformAction,
    /// Authorization resource kind.
    pub resource_kind: &'static str,
    /// Path parameter that identifies the resource when present.
    pub resource_id_path_param: Option<&'static str>,
    /// Path parameters that help resolve resource scope.
    pub scope_path_params: &'static [&'static str],
    /// Request access boundary for this route.
    pub access: RouteAccess,
    /// Whether the route requires a human user actor.
    pub user_actor_required: bool,
}

impl RouteMetadata {
    /// Creates route metadata from a method, path, action, and resource id param.
    #[must_use]
    pub const fn new(
        method: HttpMethod,
        path_pattern: &'static str,
        action: PlatformAction,
        resource_id_path_param: Option<&'static str>,
        scope_path_params: &'static [&'static str],
    ) -> Self {
        Self {
            method,
            path_pattern,
            action,
            resource_kind: action.resource_kind(),
            resource_id_path_param,
            scope_path_params,
            access: RouteAccess::Authorized,
            user_actor_required: action.requires_user_actor(),
        }
    }

    /// Creates route metadata with an explicit access boundary.
    #[must_use]
    pub const fn with_access(
        method: HttpMethod,
        path_pattern: &'static str,
        action: PlatformAction,
        resource_id_path_param: Option<&'static str>,
        scope_path_params: &'static [&'static str],
        access: RouteAccess,
    ) -> Self {
        Self {
            method,
            path_pattern,
            action,
            resource_kind: action.resource_kind(),
            resource_id_path_param,
            scope_path_params,
            access,
            user_actor_required: action.requires_user_actor(),
        }
    }
}

const PLATFORM_ROUTES: &[RouteMetadata] = &[
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/conversations",
        PlatformAction::ConversationCreate,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/conversations/{conversation_id}",
        PlatformAction::ConversationRead,
        Some("conversation_id"),
        &["conversation_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/conversations/{conversation_id}/sessions",
        PlatformAction::SessionRead,
        Some("conversation_id"),
        &["conversation_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/runs",
        PlatformAction::RunCreate,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/runs/{run_id}",
        PlatformAction::RunRead,
        Some("run_id"),
        &["run_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/runs/{run_id}:cancel",
        PlatformAction::RunCancel,
        Some("run_id"),
        &["run_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/runs/{run_id}:steer",
        PlatformAction::RunSteer,
        Some("run_id"),
        &["run_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/runs/{run_id}/events",
        PlatformAction::RunEventRead,
        Some("run_id"),
        &["run_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/approvals/{approval_id}:decide",
        PlatformAction::ApprovalDecide,
        Some("approval_id"),
        &["approval_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/deferred-tools",
        PlatformAction::DeferredToolRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/deferred-tools/{deferred_tool_id}:resume",
        PlatformAction::DeferredToolResume,
        Some("deferred_tool_id"),
        &["deferred_tool_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/v1/environment-attachments",
        PlatformAction::EnvironmentAttachmentCreate,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/environment-attachments",
        PlatformAction::EnvironmentAttachmentRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/environment-attachments/{attachment_lease_id}/health",
        PlatformAction::EnvironmentAttachmentHealthRead,
        Some("attachment_lease_id"),
        &["attachment_lease_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Delete,
        "/v1/environment-attachments/{attachment_lease_id}",
        PlatformAction::EnvironmentAttachmentRelease,
        Some("attachment_lease_id"),
        &["attachment_lease_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/evidence-archives/{evidence_archive_id}",
        PlatformAction::EvidenceArchiveRead,
        Some("evidence_archive_id"),
        &["evidence_archive_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/v1/evidence-archives/{evidence_archive_id}/debug",
        PlatformAction::EvidenceArchiveDebugRead,
        Some("evidence_archive_id"),
        &["evidence_archive_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/identity-providers",
        PlatformAction::IdentityProviderWrite,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/identity-providers",
        PlatformAction::IdentityProviderRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/identity-providers/{identity_provider_id}",
        PlatformAction::IdentityProviderRead,
        Some("identity_provider_id"),
        &["identity_provider_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/users",
        PlatformAction::UserRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/users/{user_id}",
        PlatformAction::UserRead,
        Some("user_id"),
        &["user_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/users/{user_id}/status",
        PlatformAction::UserWrite,
        Some("user_id"),
        &["user_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/users/{user_id}/sessions",
        PlatformAction::AuthSessionRead,
        None,
        &["user_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/users/{user_id}/sessions/{auth_session_id}/revoke",
        PlatformAction::AuthSessionRevoke,
        Some("auth_session_id"),
        &["user_id", "auth_session_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/users/{user_id}/external-identities",
        PlatformAction::ExternalIdentityRead,
        None,
        &["user_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/users/{user_id}/external-identities/{external_identity_id}",
        PlatformAction::ExternalIdentityRead,
        Some("external_identity_id"),
        &["user_id", "external_identity_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/users/{user_id}/external-identities/{external_identity_id}/unlink",
        PlatformAction::ExternalIdentityUnlink,
        Some("external_identity_id"),
        &["user_id", "external_identity_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/role-bindings",
        PlatformAction::RoleBindingRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/role-bindings",
        PlatformAction::RoleBindingWrite,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/role-bindings/{role_binding_id}",
        PlatformAction::RoleBindingRead,
        Some("role_binding_id"),
        &["role_binding_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/role-bindings/{role_binding_id}/status",
        PlatformAction::RoleBindingWrite,
        Some("role_binding_id"),
        &["role_binding_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/audit-events",
        PlatformAction::AuditEventRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/organizations/{organization_id}/members",
        PlatformAction::OrganizationMemberRead,
        None,
        &["organization_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/organizations/{organization_id}/members",
        PlatformAction::OrganizationMemberWrite,
        None,
        &["organization_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/organizations/{organization_id}/members/{organization_member_id}",
        PlatformAction::OrganizationMemberRead,
        Some("organization_member_id"),
        &["organization_id", "organization_member_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/organizations/{organization_id}/members/{organization_member_id}/status",
        PlatformAction::OrganizationMemberWrite,
        Some("organization_member_id"),
        &["organization_id", "organization_member_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/organizations/{organization_id}/members/{organization_member_id}/remove",
        PlatformAction::OrganizationMemberWrite,
        Some("organization_member_id"),
        &["organization_id", "organization_member_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/organizations/{organization_id}/invitations",
        PlatformAction::OrganizationInvitationRead,
        None,
        &["organization_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/organizations/{organization_id}/invitations",
        PlatformAction::OrganizationInvitationCreate,
        None,
        &["organization_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/organizations/{organization_id}/invitations/{invitation_id}",
        PlatformAction::OrganizationInvitationRead,
        Some("invitation_id"),
        &["organization_id", "invitation_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/organizations/{organization_id}/invitations/{invitation_id}/revoke",
        PlatformAction::OrganizationInvitationManage,
        Some("invitation_id"),
        &["organization_id", "invitation_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/projects/{project_id}/members",
        PlatformAction::ProjectMemberRead,
        None,
        &["project_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/projects/{project_id}/members",
        PlatformAction::ProjectMemberWrite,
        None,
        &["project_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/projects/{project_id}/members/{project_member_id}",
        PlatformAction::ProjectMemberRead,
        Some("project_member_id"),
        &["project_id", "project_member_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/projects/{project_id}/members/{project_member_id}/status",
        PlatformAction::ProjectMemberWrite,
        Some("project_member_id"),
        &["project_id", "project_member_id"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/admin/v1/secret-refs",
        PlatformAction::SecretRefWrite,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/secret-refs",
        PlatformAction::SecretRefRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/admin/v1/secret-refs/{secret_ref_id}",
        PlatformAction::SecretRefRead,
        Some("secret_ref_id"),
        &["secret_ref_id"],
    ),
    RouteMetadata::with_access(
        HttpMethod::Get,
        "/auth/v1/providers",
        PlatformAction::IdentityProviderRead,
        None,
        &[],
        RouteAccess::Public,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/providers/{identity_provider_id}/start",
        PlatformAction::IdentityProviderRead,
        None,
        &["identity_provider_id"],
        RouteAccess::Public,
    ),
    RouteMetadata::with_access(
        HttpMethod::Get,
        "/auth/v1/providers/{identity_provider_id}/login",
        PlatformAction::IdentityProviderRead,
        None,
        &["identity_provider_id"],
        RouteAccess::Public,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/providers/{identity_provider_id}/callback",
        PlatformAction::AuthSessionCreate,
        None,
        &["identity_provider_id"],
        RouteAccess::Public,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/single-user/login",
        PlatformAction::AuthSessionCreate,
        None,
        &[],
        RouteAccess::Public,
    ),
    RouteMetadata::with_access(
        HttpMethod::Get,
        "/auth/v1/invitations/{invitation_token}/preview",
        PlatformAction::OrganizationInvitationRead,
        Some("invitation_token"),
        &["invitation_token"],
        RouteAccess::Public,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/invitations/{invitation_token}/accept",
        PlatformAction::OrganizationInvitationAccept,
        Some("invitation_token"),
        &["invitation_token"],
        RouteAccess::Session,
    ),
    RouteMetadata::with_access(
        HttpMethod::Get,
        "/auth/v1/session",
        PlatformAction::AuthSessionRead,
        None,
        &[],
        RouteAccess::Session,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/session/active-organization",
        PlatformAction::AuthSessionUpdate,
        None,
        &[],
        RouteAccess::Session,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/session/active-project",
        PlatformAction::AuthSessionUpdate,
        None,
        &[],
        RouteAccess::Session,
    ),
    RouteMetadata::with_access(
        HttpMethod::Post,
        "/auth/v1/logout",
        PlatformAction::AuthSessionRevoke,
        None,
        &[],
        RouteAccess::Session,
    ),
];

/// Returns every foundation platform route.
#[must_use]
pub const fn foundation_routes() -> &'static [RouteMetadata] {
    PLATFORM_ROUTES
}

/// Finds route metadata by method and stable path pattern.
#[must_use]
pub fn route_metadata(method: HttpMethod, path_pattern: &str) -> Option<&'static RouteMetadata> {
    foundation_routes()
        .iter()
        .find(|route| route.method == method && route.path_pattern == path_pattern)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{foundation_routes, route_metadata, HttpMethod, RouteAccess};
    use crate::action::PlatformAction;

    #[test]
    fn route_matrix_has_unique_method_patterns() {
        let mut routes = HashSet::new();
        for route in foundation_routes() {
            assert!(routes.insert((route.method.as_str(), route.path_pattern)));
        }
    }

    #[test]
    fn route_matrix_uses_platform_actions_and_matching_resources() {
        for route in foundation_routes() {
            assert!(route.action.as_str().starts_with("platform."));
            assert_eq!(route.resource_kind, route.action.resource_kind());
            assert_eq!(
                route.user_actor_required,
                route.action.requires_user_actor()
            );
            assert!(!route.access.as_str().is_empty());
        }
        assert!(PlatformAction::from_action_id("gateway.model.invoke").is_none());
    }

    const REQUIRED_FOUNDATION_ROUTES: &[(HttpMethod, &str)] = &[
        (HttpMethod::Post, "/v1/conversations"),
        (HttpMethod::Get, "/v1/conversations/{conversation_id}"),
        (
            HttpMethod::Get,
            "/v1/conversations/{conversation_id}/sessions",
        ),
        (HttpMethod::Post, "/v1/runs"),
        (HttpMethod::Get, "/v1/runs/{run_id}"),
        (HttpMethod::Post, "/v1/runs/{run_id}:cancel"),
        (HttpMethod::Post, "/v1/runs/{run_id}:steer"),
        (HttpMethod::Get, "/v1/runs/{run_id}/events"),
        (HttpMethod::Post, "/v1/approvals/{approval_id}:decide"),
        (HttpMethod::Get, "/v1/deferred-tools"),
        (
            HttpMethod::Post,
            "/v1/deferred-tools/{deferred_tool_id}:resume",
        ),
        (HttpMethod::Post, "/v1/environment-attachments"),
        (HttpMethod::Get, "/v1/environment-attachments"),
        (
            HttpMethod::Get,
            "/v1/environment-attachments/{attachment_lease_id}/health",
        ),
        (
            HttpMethod::Delete,
            "/v1/environment-attachments/{attachment_lease_id}",
        ),
    ];

    const REQUIRED_ADMIN_AUTH_ROUTES: &[(HttpMethod, &str)] = &[
        (HttpMethod::Post, "/admin/v1/identity-providers"),
        (HttpMethod::Get, "/admin/v1/identity-providers"),
        (
            HttpMethod::Get,
            "/admin/v1/identity-providers/{identity_provider_id}",
        ),
        (HttpMethod::Get, "/admin/v1/users"),
        (HttpMethod::Get, "/admin/v1/users/{user_id}"),
        (HttpMethod::Post, "/admin/v1/users/{user_id}/status"),
        (HttpMethod::Get, "/admin/v1/users/{user_id}/sessions"),
        (
            HttpMethod::Post,
            "/admin/v1/users/{user_id}/sessions/{auth_session_id}/revoke",
        ),
        (
            HttpMethod::Get,
            "/admin/v1/users/{user_id}/external-identities",
        ),
        (
            HttpMethod::Get,
            "/admin/v1/users/{user_id}/external-identities/{external_identity_id}",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/users/{user_id}/external-identities/{external_identity_id}/unlink",
        ),
        (HttpMethod::Get, "/admin/v1/role-bindings"),
        (HttpMethod::Post, "/admin/v1/role-bindings"),
        (HttpMethod::Get, "/admin/v1/role-bindings/{role_binding_id}"),
        (
            HttpMethod::Post,
            "/admin/v1/role-bindings/{role_binding_id}/status",
        ),
        (HttpMethod::Get, "/admin/v1/audit-events"),
        (
            HttpMethod::Get,
            "/admin/v1/organizations/{organization_id}/members",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/organizations/{organization_id}/members",
        ),
        (
            HttpMethod::Get,
            "/admin/v1/organizations/{organization_id}/members/{organization_member_id}",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/organizations/{organization_id}/members/{organization_member_id}/status",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/organizations/{organization_id}/members/{organization_member_id}/remove",
        ),
        (
            HttpMethod::Get,
            "/admin/v1/organizations/{organization_id}/invitations",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/organizations/{organization_id}/invitations",
        ),
        (
            HttpMethod::Get,
            "/admin/v1/organizations/{organization_id}/invitations/{invitation_id}",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/organizations/{organization_id}/invitations/{invitation_id}/revoke",
        ),
        (HttpMethod::Get, "/admin/v1/projects/{project_id}/members"),
        (HttpMethod::Post, "/admin/v1/projects/{project_id}/members"),
        (
            HttpMethod::Get,
            "/admin/v1/projects/{project_id}/members/{project_member_id}",
        ),
        (
            HttpMethod::Post,
            "/admin/v1/projects/{project_id}/members/{project_member_id}/status",
        ),
        (HttpMethod::Post, "/admin/v1/secret-refs"),
        (HttpMethod::Get, "/admin/v1/secret-refs"),
        (HttpMethod::Get, "/admin/v1/secret-refs/{secret_ref_id}"),
    ];

    const REQUIRED_AUTH_ROUTES: &[(HttpMethod, &str)] = &[
        (HttpMethod::Get, "/auth/v1/providers"),
        (
            HttpMethod::Post,
            "/auth/v1/providers/{identity_provider_id}/start",
        ),
        (
            HttpMethod::Get,
            "/auth/v1/providers/{identity_provider_id}/login",
        ),
        (
            HttpMethod::Post,
            "/auth/v1/providers/{identity_provider_id}/callback",
        ),
        (HttpMethod::Post, "/auth/v1/single-user/login"),
        (
            HttpMethod::Get,
            "/auth/v1/invitations/{invitation_token}/preview",
        ),
        (
            HttpMethod::Post,
            "/auth/v1/invitations/{invitation_token}/accept",
        ),
        (HttpMethod::Get, "/auth/v1/session"),
        (HttpMethod::Post, "/auth/v1/session/active-organization"),
        (HttpMethod::Post, "/auth/v1/session/active-project"),
        (HttpMethod::Post, "/auth/v1/logout"),
    ];

    #[test]
    fn route_matrix_covers_candidate_platform_api_surface() {
        assert_routes_exist(REQUIRED_FOUNDATION_ROUTES);
        assert_routes_exist(REQUIRED_ADMIN_AUTH_ROUTES);
        assert_routes_exist(REQUIRED_AUTH_ROUTES);
    }

    fn assert_routes_exist(required: &[(HttpMethod, &str)]) {
        for (method, path_pattern) in required {
            assert!(
                route_metadata(*method, path_pattern).is_some(),
                "missing route metadata for {} {path_pattern}",
                method.as_str()
            );
        }
    }

    #[test]
    fn route_lookup_returns_stable_action_and_resource_param() {
        let route = route_metadata(HttpMethod::Post, "/v1/runs/{run_id}:cancel")
            .unwrap_or_else(|| panic!("cancel route metadata should exist"));
        assert_eq!(route.action, PlatformAction::RunCancel);
        assert_eq!(route.resource_kind, "Run");
        assert_eq!(route.resource_id_path_param, Some("run_id"));
        assert_eq!(route.access, RouteAccess::Authorized);
        assert!(route.user_actor_required);
    }

    #[test]
    fn auth_route_matrix_distinguishes_public_and_session_boundaries() {
        for (method, path_pattern) in REQUIRED_AUTH_ROUTES {
            let route = route_metadata(*method, path_pattern).unwrap_or_else(|| {
                panic!(
                    "auth route metadata should exist for {} {path_pattern}",
                    method.as_str()
                )
            });
            match *path_pattern {
                "/auth/v1/providers"
                | "/auth/v1/providers/{identity_provider_id}/start"
                | "/auth/v1/providers/{identity_provider_id}/login"
                | "/auth/v1/providers/{identity_provider_id}/callback"
                | "/auth/v1/single-user/login"
                | "/auth/v1/invitations/{invitation_token}/preview" => {
                    assert_eq!(route.access, RouteAccess::Public);
                    assert!(!route.user_actor_required);
                }
                _ => {
                    assert_eq!(route.access, RouteAccess::Session);
                    assert!(route.user_actor_required);
                }
            }
        }

        let callback = route_metadata(
            HttpMethod::Post,
            "/auth/v1/providers/{identity_provider_id}/callback",
        )
        .unwrap_or_else(|| panic!("OIDC callback metadata should exist"));
        assert_eq!(callback.action, PlatformAction::AuthSessionCreate);
        assert_eq!(callback.scope_path_params, &["identity_provider_id"]);
        assert_eq!(callback.resource_id_path_param, None);
    }
}
