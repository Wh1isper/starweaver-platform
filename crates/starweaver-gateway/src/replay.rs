//! Replay case metadata for protocol and gateway-route validation.

use http::Method;
use serde::Serialize;

use crate::ProtocolFamily;
use crate::action::GatewayAction;

/// Replay case for a gateway ingress route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewayReplayCase {
    /// Stable case name.
    pub name: &'static str,
    /// Protocol family exercised by the case.
    pub protocol_family: ProtocolFamily,
    /// Client-facing HTTP method.
    #[serde(with = "http_method_serde")]
    pub method: Method,
    /// Client-facing route path.
    pub ingress_path: &'static str,
    /// Required gateway action.
    pub action: GatewayAction,
    /// Whether the route is streaming.
    pub streaming: bool,
    /// Whether provider-native grant is required.
    pub requires_native_grant: bool,
}

/// Returns the foundation route replay cases. These are metadata cases used
/// before cassette-backed replay is wired.
#[must_use]
pub const fn foundation_route_replay_cases() -> &'static [GatewayReplayCase] {
    &[
        GatewayReplayCase {
            name: "openai_responses_non_stream",
            protocol_family: ProtocolFamily::OpenAiResponses,
            method: Method::POST,
            ingress_path: "/v1/responses",
            action: GatewayAction::ModelInvoke,
            streaming: false,
            requires_native_grant: false,
        },
        GatewayReplayCase {
            name: "openai_chat_stream",
            protocol_family: ProtocolFamily::OpenAiChat,
            method: Method::POST,
            ingress_path: "/v1/chat/completions",
            action: GatewayAction::ModelStream,
            streaming: true,
            requires_native_grant: false,
        },
        GatewayReplayCase {
            name: "anthropic_messages_non_stream",
            protocol_family: ProtocolFamily::AnthropicMessages,
            method: Method::POST,
            ingress_path: "/v1/messages",
            action: GatewayAction::ModelInvoke,
            streaming: false,
            requires_native_grant: false,
        },
        GatewayReplayCase {
            name: "gemini_generate_content_non_stream",
            protocol_family: ProtocolFamily::GeminiGenerateContent,
            method: Method::POST,
            ingress_path: "/v1beta/models/gemini-pro:generateContent",
            action: GatewayAction::ModelInvoke,
            streaming: false,
            requires_native_grant: false,
        },
        GatewayReplayCase {
            name: "bedrock_converse_non_stream",
            protocol_family: ProtocolFamily::BedrockConverse,
            method: Method::POST,
            ingress_path: "/model/anthropic.claude-3-sonnet/converse",
            action: GatewayAction::ModelInvoke,
            streaming: false,
            requires_native_grant: false,
        },
        GatewayReplayCase {
            name: "provider_native_denied_by_default",
            protocol_family: ProtocolFamily::ProviderNative,
            method: Method::POST,
            ingress_path: "/native/custom_native/invoke",
            action: GatewayAction::ModelNative,
            streaming: false,
            requires_native_grant: true,
        },
    ]
}

/// Classifies a gateway ingress route into a protocol family.
#[must_use]
pub fn classify_ingress(method: &Method, path: &str) -> Option<ProtocolFamily> {
    if method != Method::POST {
        return None;
    }
    if path == "/v1/responses" {
        return Some(ProtocolFamily::OpenAiResponses);
    }
    if path == "/v1/chat/completions" {
        return Some(ProtocolFamily::OpenAiChat);
    }
    if path == "/v1/messages" {
        return Some(ProtocolFamily::AnthropicMessages);
    }
    if path.contains(":generateContent") || path.contains(":streamGenerateContent") {
        return Some(ProtocolFamily::GeminiGenerateContent);
    }
    if path.contains("/converse") || path.contains("/converse-stream") {
        return Some(ProtocolFamily::BedrockConverse);
    }
    if path.starts_with("/native/") {
        return Some(ProtocolFamily::ProviderNative);
    }
    None
}

mod http_method_serde {
    use http::Method;
    use serde::Serializer;

    pub(super) fn serialize<S>(method: &Method, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(method.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use http::Method;

    use super::{classify_ingress, foundation_route_replay_cases};
    use crate::ProtocolFamily;
    use crate::action::{ActionGrant, FoundationAuthorizationEngine};
    use crate::domain::{ActorKind, AuthenticatedActor, CredentialKind};
    use crate::route::{authorize_route_with_evidence, foundation_routes};
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
            trace_id: "tr_test".to_owned(),
        }
    }

    #[test]
    fn foundation_replay_covers_every_protocol_family() {
        let covered = foundation_route_replay_cases()
            .iter()
            .map(|case| case.protocol_family)
            .collect::<HashSet<_>>();
        let expected = ProtocolFamily::all()
            .iter()
            .copied()
            .collect::<HashSet<_>>();

        assert_eq!(covered, expected);
    }

    #[test]
    fn replay_case_paths_classify_to_declared_family() {
        for case in foundation_route_replay_cases() {
            assert_eq!(
                classify_ingress(&case.method, case.ingress_path),
                Some(case.protocol_family),
                "case {} should classify",
                case.name
            );
        }
    }

    #[test]
    fn replay_cases_have_route_authorization_metadata() {
        for case in foundation_route_replay_cases() {
            assert!(
                foundation_routes()
                    .iter()
                    .any(|route| route.protocol_family == Some(case.protocol_family)
                        && route.action == case.action),
                "case {} should have route metadata",
                case.name
            );
        }
    }

    #[test]
    fn replay_cases_exercise_authorization_decisions() {
        for case in foundation_route_replay_cases() {
            let route = foundation_routes()
                .iter()
                .find(|route| {
                    route.protocol_family == Some(case.protocol_family)
                        && route.action == case.action
                })
                .unwrap_or_else(|| panic!("case {} should have route metadata", case.name));
            let store = InMemoryGatewayStore::default();
            let missing_grant = authorize_route_with_evidence(
                route,
                &FoundationAuthorizationEngine::default(),
                &store,
                api_key_actor(),
                "ma_test",
                None,
                chrono::Utc::now(),
            );
            assert!(!missing_grant.allowed);

            let engine = FoundationAuthorizationEngine::new(vec![ActionGrant::project(
                "ten_test",
                "org_test",
                "prj_test",
                "usr_test",
                case.action,
                route.resource("ma_test"),
            )]);
            let with_grant = authorize_route_with_evidence(
                route,
                &engine,
                &store,
                api_key_actor(),
                "ma_test",
                None,
                chrono::Utc::now(),
            );
            if case.requires_native_grant {
                assert_eq!(with_grant.reason, "native_route_grant_required");
                assert!(!with_grant.allowed);
            } else {
                assert!(with_grant.allowed, "case {} should allow", case.name);
            }
        }
    }

    #[test]
    fn non_post_routes_do_not_classify() {
        assert_eq!(classify_ingress(&Method::GET, "/v1/responses"), None);
    }
}
