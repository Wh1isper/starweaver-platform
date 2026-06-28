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
    RouteMetadata::new(
        HttpMethod::Get,
        "/auth/v1/invitations/{invitation_token}/preview",
        PlatformAction::OrganizationInvitationRead,
        Some("invitation_token"),
        &["invitation_token"],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/auth/v1/invitations/{invitation_token}/accept",
        PlatformAction::OrganizationInvitationAccept,
        Some("invitation_token"),
        &["invitation_token"],
    ),
    RouteMetadata::new(
        HttpMethod::Get,
        "/auth/v1/session",
        PlatformAction::AuthSessionRead,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/auth/v1/session/active-organization",
        PlatformAction::AuthSessionUpdate,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/auth/v1/session/active-project",
        PlatformAction::AuthSessionUpdate,
        None,
        &[],
    ),
    RouteMetadata::new(
        HttpMethod::Post,
        "/auth/v1/logout",
        PlatformAction::AuthSessionRevoke,
        None,
        &[],
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

    use super::{foundation_routes, route_metadata, HttpMethod};
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
        }
        assert!(PlatformAction::from_action_id("gateway.model.invoke").is_none());
    }

    #[test]
    fn route_matrix_covers_candidate_platform_api_surface() {
        let required = [
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
            (HttpMethod::Post, "/admin/v1/identity-providers"),
            (HttpMethod::Get, "/admin/v1/identity-providers"),
            (
                HttpMethod::Get,
                "/admin/v1/identity-providers/{identity_provider_id}",
            ),
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
        for (method, path_pattern) in required {
            assert!(
                route_metadata(method, path_pattern).is_some(),
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
        assert!(route.user_actor_required);
    }
}
