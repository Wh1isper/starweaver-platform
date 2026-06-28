//! Runtime ingress foundation with deterministic fake provider responses.

use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

use crate::action::{AuthorizationDecision, AuthorizationEngine, AuthorizationEvidenceSink};
use crate::domain::{AuthenticatedActor, ProviderEndpoint};
use crate::error::{GatewayError, Result};
use crate::replay::{classify_ingress, GatewayReplayCase};
use crate::route::{authorize_route_with_evidence, foundation_routes, RouteMetadata};
use crate::ProtocolFamily;

/// Runtime request used by protocol replay and fake-provider tests.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RuntimeIngressRequest {
    /// Client-facing path.
    pub path: String,
    /// Request body.
    pub body: Value,
    /// Model alias or native route resource id selected by the caller.
    pub resource_id: String,
}

/// Runtime response produced by the fake provider harness.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeIngressResponse {
    /// Protocol family selected for this request.
    pub protocol_family: ProtocolFamily,
    /// Authorization decision.
    pub authorization: AuthorizationDecision,
    /// Fake provider response body.
    pub body: Value,
    /// Whether the response represents a stream.
    pub streaming: bool,
}

/// Selected fake-provider target with separate auth and upstream model ids.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeProviderReplayTarget {
    /// Resource id used for gateway authorization.
    pub alias_resource_id: String,
    /// Provider model id used in the fake upstream response.
    pub upstream_model_id: String,
}

/// Authorization evidence context for fake-provider replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeProviderReplayEvidence {
    /// Optional config snapshot that supplied the authorization policy.
    pub policy_snapshot_id: Option<String>,
    /// Decision timestamp recorded in authorization evidence.
    pub occurred_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderAdapterTarget {
    pub(crate) protocol_family: ProtocolFamily,
    pub(crate) provider_endpoint: ProviderEndpoint,
    pub(crate) upstream_model_id: String,
    pub(crate) upstream_credential: Option<ProviderAdapterCredential>,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderAdapterCredential {
    pub(crate) upstream_credential_id: String,
    pub(crate) credential_kind: String,
    pub(crate) secret_value: SecretString,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderAdapterRequest {
    pub(crate) protocol_family: ProtocolFamily,
    pub(crate) method: &'static str,
    pub(crate) url: String,
    pub(crate) headers: Vec<ProviderAdapterHeader>,
    pub(crate) body: Value,
    pub(crate) safe_metadata: ProviderAdapterRequestMetadata,
}

#[derive(Clone, Debug)]
pub(crate) struct ProviderAdapterHeader {
    pub(crate) name: &'static str,
    pub(crate) value: SecretString,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ProviderAdapterRequestMetadata {
    pub(crate) protocol_family: ProtocolFamily,
    pub(crate) provider_endpoint_id: String,
    pub(crate) provider_kind: String,
    pub(crate) upstream_model_id: String,
    pub(crate) upstream_credential_id: Option<String>,
    pub(crate) credential_kind: Option<String>,
    pub(crate) url_origin: String,
    pub(crate) url_path: String,
}

/// Deterministic fake-provider outcome used by replay and harness tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FakeProviderReplayOutcome {
    /// Provider returned a protocol-compatible success response.
    Success,
    /// Provider returned a non-retryable upstream error.
    ProviderError,
    /// Provider rejected the request with a retryable throttle signal.
    Throttled,
    /// Gateway timed out waiting for the provider.
    Timeout,
    /// Provider returned malformed streaming bytes before completion.
    MalformedStream,
    /// Client disconnected before the fake provider completed.
    ClientDisconnected,
}

impl FakeProviderReplayOutcome {
    /// Stable outcome id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::ProviderError => "provider_error",
            Self::Throttled => "throttled",
            Self::Timeout => "timeout",
            Self::MalformedStream => "malformed_stream",
            Self::ClientDisconnected => "client_disconnected",
        }
    }

    /// Whether this outcome represents a retryable provider-side failure.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::Throttled | Self::Timeout | Self::MalformedStream
        )
    }
}

/// Request for running a deterministic fake-provider replay with an outcome.
pub struct FakeProviderReplayOutcomeRequest<'a> {
    /// Replay case metadata.
    pub replay_case: &'a GatewayReplayCase,
    /// Authorization engine used by the route.
    pub engine: &'a dyn AuthorizationEngine,
    /// Evidence sink used to record authorization decisions.
    pub sink: &'a dyn AuthorizationEvidenceSink,
    /// Authenticated actor.
    pub actor: AuthenticatedActor,
    /// Selected fake-provider target.
    pub target: &'a FakeProviderReplayTarget,
    /// Request body.
    pub body: &'a Value,
    /// Authorization evidence context.
    pub evidence: FakeProviderReplayEvidence,
    /// Provider outcome to apply after authorization.
    pub outcome: FakeProviderReplayOutcome,
}

/// Authorization result for a replay target before the provider is invoked.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FakeProviderAuthorization {
    /// Protocol family selected for this request.
    pub protocol_family: ProtocolFamily,
    /// Authorization decision recorded for the route.
    pub authorization: AuthorizationDecision,
    /// Whether the request is expected to stream.
    pub streaming: bool,
}

pub(crate) fn build_provider_adapter_request(
    target: &ProviderAdapterTarget,
    body: &Value,
) -> Result<ProviderAdapterRequest> {
    let mut upstream_body = body.clone();
    rewrite_provider_model(
        &mut upstream_body,
        target.protocol_family,
        &target.upstream_model_id,
    );
    let url = provider_request_url(
        &target.provider_endpoint.upstream_base_url,
        target.protocol_family,
        &target.upstream_model_id,
    )?;
    let safe_metadata = ProviderAdapterRequestMetadata {
        protocol_family: target.protocol_family,
        provider_endpoint_id: target.provider_endpoint.provider_endpoint_id.clone(),
        provider_kind: target.provider_endpoint.provider_kind.clone(),
        upstream_model_id: target.upstream_model_id.clone(),
        upstream_credential_id: target
            .upstream_credential
            .as_ref()
            .map(|credential| credential.upstream_credential_id.clone()),
        credential_kind: target
            .upstream_credential
            .as_ref()
            .map(|credential| credential.credential_kind.clone()),
        url_origin: url_origin(&url),
        url_path: url.path().to_owned(),
    };
    Ok(ProviderAdapterRequest {
        protocol_family: target.protocol_family,
        method: "POST",
        url: url.to_string(),
        headers: provider_adapter_headers(target),
        body: upstream_body,
        safe_metadata,
    })
}

/// Runs a deterministic fake-provider request through route authorization.
pub fn run_fake_provider_replay(
    replay_case: &GatewayReplayCase,
    engine: &dyn AuthorizationEngine,
    sink: &dyn AuthorizationEvidenceSink,
    actor: AuthenticatedActor,
    resource_id: impl Into<String>,
    body: &Value,
    now: DateTime<Utc>,
) -> Result<RuntimeIngressResponse> {
    let resource_id = resource_id.into();
    let target = FakeProviderReplayTarget {
        alias_resource_id: resource_id.clone(),
        upstream_model_id: resource_id,
    };
    run_fake_provider_replay_for_target(
        replay_case,
        engine,
        sink,
        actor,
        &target,
        body,
        FakeProviderReplayEvidence {
            policy_snapshot_id: None,
            occurred_at: now,
        },
    )
}

/// Runs a deterministic fake-provider request with separate alias and target ids.
pub fn run_fake_provider_replay_for_target(
    replay_case: &GatewayReplayCase,
    engine: &dyn AuthorizationEngine,
    sink: &dyn AuthorizationEvidenceSink,
    actor: AuthenticatedActor,
    target: &FakeProviderReplayTarget,
    body: &Value,
    evidence: FakeProviderReplayEvidence,
) -> Result<RuntimeIngressResponse> {
    run_fake_provider_replay_for_target_with_outcome(FakeProviderReplayOutcomeRequest {
        replay_case,
        engine,
        sink,
        actor,
        target,
        body,
        evidence,
        outcome: FakeProviderReplayOutcome::Success,
    })
}

/// Runs a deterministic fake-provider request with an explicit provider outcome.
pub fn run_fake_provider_replay_for_target_with_outcome(
    request: FakeProviderReplayOutcomeRequest<'_>,
) -> Result<RuntimeIngressResponse> {
    let authorization = authorize_fake_provider_replay_target(
        request.replay_case,
        request.engine,
        request.sink,
        request.actor,
        request.target,
        request.evidence,
    )?;
    Ok(fake_provider_response_for_authorization_with_outcome(
        &authorization,
        request.target,
        request.body,
        request.outcome,
    ))
}

/// Records route authorization before a fake provider attempt is made.
pub fn authorize_fake_provider_replay_target(
    replay_case: &GatewayReplayCase,
    engine: &dyn AuthorizationEngine,
    sink: &dyn AuthorizationEvidenceSink,
    actor: AuthenticatedActor,
    target: &FakeProviderReplayTarget,
    evidence: FakeProviderReplayEvidence,
) -> Result<FakeProviderAuthorization> {
    let protocol_family = classify_ingress(&replay_case.method, replay_case.ingress_path)
        .ok_or_else(|| GatewayError::BadRequest {
            message: format!("unsupported replay route: {}", replay_case.ingress_path),
        })?;
    let route = route_for_replay(replay_case, protocol_family)?;
    let authorization = authorize_route_with_evidence(
        route,
        engine,
        sink,
        actor,
        target.alias_resource_id.clone(),
        evidence.policy_snapshot_id,
        evidence.occurred_at,
    );
    Ok(FakeProviderAuthorization {
        protocol_family,
        authorization,
        streaming: replay_case.streaming,
    })
}

/// Builds the fake provider response after authorization and runtime policy gates.
#[must_use]
pub fn fake_provider_response_for_authorization(
    authorization: &FakeProviderAuthorization,
    target: &FakeProviderReplayTarget,
    body: &Value,
) -> RuntimeIngressResponse {
    fake_provider_response_for_authorization_with_outcome(
        authorization,
        target,
        body,
        FakeProviderReplayOutcome::Success,
    )
}

/// Builds the fake provider response for an explicit deterministic outcome.
#[must_use]
pub fn fake_provider_response_for_authorization_with_outcome(
    authorization: &FakeProviderAuthorization,
    target: &FakeProviderReplayTarget,
    body: &Value,
    outcome: FakeProviderReplayOutcome,
) -> RuntimeIngressResponse {
    if !authorization.authorization.allowed {
        let reason = authorization.authorization.reason;
        return RuntimeIngressResponse {
            protocol_family: authorization.protocol_family,
            authorization: authorization.authorization.clone(),
            body: json!({
                "error": {
                    "code": "gateway.auth.authorization_denied",
                    "reason": reason
                }
            }),
            streaming: authorization.streaming,
        };
    }

    if outcome != FakeProviderReplayOutcome::Success {
        return RuntimeIngressResponse {
            protocol_family: authorization.protocol_family,
            authorization: authorization.authorization.clone(),
            body: fake_provider_error_body(outcome, authorization.streaming),
            streaming: authorization.streaming,
        };
    }

    RuntimeIngressResponse {
        protocol_family: authorization.protocol_family,
        authorization: authorization.authorization.clone(),
        body: fake_provider_body(
            authorization.protocol_family,
            &target.upstream_model_id,
            body,
            authorization.streaming,
        ),
        streaming: authorization.streaming,
    }
}

fn fake_provider_error_body(outcome: FakeProviderReplayOutcome, streaming: bool) -> Value {
    json!({
        "error": {
            "code": format!("gateway.fake_provider.{}", outcome.as_str()),
            "outcome": outcome.as_str(),
            "retryable": outcome.retryable(),
            "streaming": streaming
        }
    })
}

fn provider_adapter_headers(target: &ProviderAdapterTarget) -> Vec<ProviderAdapterHeader> {
    let Some(credential) = target.upstream_credential.as_ref() else {
        return Vec::new();
    };
    match credential.credential_kind.as_str() {
        "api_key" | "bearer_token" | "upstream_api_key" | "codex_oauth" => {
            vec![ProviderAdapterHeader {
                name: "authorization",
                value: SecretString::from(format!(
                    "Bearer {}",
                    credential.secret_value.expose_secret()
                )),
            }]
        }
        _ => Vec::new(),
    }
}

fn provider_request_url(
    upstream_base_url: &str,
    protocol_family: ProtocolFamily,
    upstream_model_id: &str,
) -> Result<Url> {
    let base = Url::parse(upstream_base_url).map_err(|error| GatewayError::BadRequest {
        message: format!("invalid upstream_base_url: {error}"),
    })?;
    let path = provider_request_path(protocol_family, upstream_model_id);
    provider_base_dir(base)
        .join(&path)
        .map_err(|error| GatewayError::BadRequest {
            message: format!("invalid provider request path: {error}"),
        })
}

fn provider_base_dir(mut base: Url) -> Url {
    if !base.path().ends_with('/') {
        let path = format!("{}/", base.path());
        base.set_path(&path);
    }
    base
}

fn provider_request_path(protocol_family: ProtocolFamily, upstream_model_id: &str) -> String {
    match protocol_family {
        ProtocolFamily::OpenAiResponses => "responses".to_owned(),
        ProtocolFamily::OpenAiChat => "chat/completions".to_owned(),
        ProtocolFamily::AnthropicMessages => "messages".to_owned(),
        ProtocolFamily::GeminiGenerateContent => {
            format!(
                "models/{}:generateContent",
                percent_encode_path_segment(upstream_model_id)
            )
        }
        ProtocolFamily::BedrockConverse => "model/invoke".to_owned(),
        ProtocolFamily::ProviderNative => "native/invoke".to_owned(),
    }
}

fn rewrite_provider_model(
    body: &mut Value,
    protocol_family: ProtocolFamily,
    upstream_model_id: &str,
) {
    match protocol_family {
        ProtocolFamily::OpenAiResponses
        | ProtocolFamily::OpenAiChat
        | ProtocolFamily::AnthropicMessages
        | ProtocolFamily::ProviderNative => {
            if let Some(object) = body.as_object_mut() {
                object.insert("model".to_owned(), json!(upstream_model_id));
            }
        }
        ProtocolFamily::GeminiGenerateContent | ProtocolFamily::BedrockConverse => {}
    }
}

fn percent_encode_path_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(hex_digit(byte >> 4)));
            encoded.push(char::from(hex_digit(byte & 0x0f)));
        }
    }
    encoded
}

const fn hex_digit(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + (value - 10),
    }
}

fn url_origin(url: &Url) -> String {
    let Some(host) = url.host_str() else {
        return url.scheme().to_owned();
    };
    url.port().map_or_else(
        || format!("{}://{}", url.scheme(), host),
        |port| format!("{}://{}:{}", url.scheme(), host, port),
    )
}

fn route_for_replay(
    replay_case: &GatewayReplayCase,
    protocol_family: ProtocolFamily,
) -> Result<&'static RouteMetadata> {
    foundation_routes()
        .iter()
        .find(|route| {
            route.protocol_family == Some(protocol_family) && route.action == replay_case.action
        })
        .ok_or_else(|| GatewayError::Internal {
            message: format!(
                "missing route metadata for replay case {}",
                replay_case.name
            ),
        })
}

fn fake_provider_body(
    protocol_family: ProtocolFamily,
    resource_id: &str,
    request_body: &Value,
    streaming: bool,
) -> Value {
    match protocol_family {
        ProtocolFamily::OpenAiResponses => json!({
            "id": "resp_fake",
            "object": "response",
            "model": resource_id,
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": "fake response"}
                    ]
                }
            ],
            "usage": fake_usage()
        }),
        ProtocolFamily::OpenAiChat => {
            if streaming {
                json!({
                    "object": "chat.completion.chunk",
                    "model": resource_id,
                    "choices": [
                        {"index": 0, "delta": {"content": "fake stream"}, "finish_reason": null}
                    ]
                })
            } else {
                json!({
                    "object": "chat.completion",
                    "model": resource_id,
                    "choices": [
                        {"index": 0, "message": {"role": "assistant", "content": "fake chat"}, "finish_reason": "stop"}
                    ],
                    "usage": fake_usage()
                })
            }
        }
        ProtocolFamily::AnthropicMessages => json!({
            "id": "msg_fake",
            "type": "message",
            "role": "assistant",
            "model": resource_id,
            "content": [
                {"type": "text", "text": "fake anthropic message"}
            ],
            "usage": {
                "input_tokens": 1,
                "output_tokens": 2
            }
        }),
        ProtocolFamily::GeminiGenerateContent => json!({
            "modelVersion": resource_id,
            "candidates": [
                {
                    "content": {
                        "role": "model",
                        "parts": [{"text": "fake gemini content"}]
                    },
                    "finishReason": "STOP"
                }
            ],
            "usageMetadata": {
                "promptTokenCount": 1,
                "candidatesTokenCount": 2,
                "totalTokenCount": 3
            }
        }),
        ProtocolFamily::BedrockConverse => json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "fake bedrock converse"}]
                }
            },
            "usage": {
                "inputTokens": 1,
                "outputTokens": 2,
                "totalTokens": 3
            }
        }),
        ProtocolFamily::ProviderNative => json!({
            "provider_native": true,
            "model": resource_id,
            "echo": request_body
        }),
    }
}

fn fake_usage() -> Value {
    json!({
        "input_tokens": 1,
        "output_tokens": 2,
        "total_tokens": 3
    })
}

#[cfg(test)]
mod tests {
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::json;

    use crate::action::{ActionGrant, FoundationAuthorizationEngine};
    use crate::domain::{
        ActorKind, AuthenticatedActor, CredentialKind, ProviderEndpoint, ResourceStatus,
    };
    use crate::replay::foundation_route_replay_cases;
    use crate::route::foundation_routes;
    use crate::runtime::{
        build_provider_adapter_request, run_fake_provider_replay,
        run_fake_provider_replay_for_target_with_outcome, FakeProviderReplayEvidence,
        FakeProviderReplayOutcome, FakeProviderReplayOutcomeRequest, FakeProviderReplayTarget,
        ProviderAdapterCredential, ProviderAdapterTarget,
    };
    use crate::storage::InMemoryGatewayStore;
    use crate::ProtocolFamily;

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

    fn engine_for_case(case: &crate::replay::GatewayReplayCase) -> FoundationAuthorizationEngine {
        let route = foundation_routes()
            .iter()
            .find(|route| {
                route.protocol_family == Some(case.protocol_family) && route.action == case.action
            })
            .unwrap_or_else(|| panic!("case {} should have route", case.name));
        FoundationAuthorizationEngine::new(vec![ActionGrant::project(
            "ten_test",
            "org_test",
            "prj_test",
            "usr_test",
            case.action,
            route.resource("ma_test"),
        )])
    }

    #[test]
    fn every_replay_case_runs_through_fake_provider_runtime() {
        for case in foundation_route_replay_cases() {
            let store = InMemoryGatewayStore::default();
            let response = match run_fake_provider_replay(
                case,
                &engine_for_case(case),
                &store,
                api_key_actor(),
                "ma_test",
                &json!({"model": "ma_test"}),
                chrono::Utc::now(),
            ) {
                Ok(response) => response,
                Err(error) => panic!("case {} should run: {error}", case.name),
            };

            assert_eq!(response.protocol_family, case.protocol_family);
            assert_eq!(response.streaming, case.streaming);
            assert_eq!(store.authorization_decisions().len(), 1);
            if case.requires_native_grant {
                assert!(!response.authorization.allowed);
            } else {
                assert!(
                    response.authorization.allowed,
                    "case {} should allow",
                    case.name
                );
                assert_provider_shape(case.protocol_family, &response.body);
            }
        }
    }

    #[test]
    fn missing_grant_replay_returns_authorization_error_body() {
        let case = &foundation_route_replay_cases()[0];
        let store = InMemoryGatewayStore::default();
        let response = match run_fake_provider_replay(
            case,
            &FoundationAuthorizationEngine::default(),
            &store,
            api_key_actor(),
            "ma_test",
            &json!({"model": "ma_test"}),
            chrono::Utc::now(),
        ) {
            Ok(response) => response,
            Err(error) => panic!("replay should return denied response: {error}"),
        };

        assert!(!response.authorization.allowed);
        assert_eq!(
            response.body["error"]["code"],
            "gateway.auth.authorization_denied"
        );
        assert_eq!(store.authorization_decisions().len(), 1);
    }

    #[test]
    fn fake_provider_negative_outcomes_are_protocol_authorized_errors() {
        let case = foundation_route_replay_cases()
            .iter()
            .find(|case| case.protocol_family == ProtocolFamily::OpenAiChat)
            .unwrap_or_else(|| panic!("openai chat replay case should exist"));
        for outcome in [
            FakeProviderReplayOutcome::ProviderError,
            FakeProviderReplayOutcome::Throttled,
            FakeProviderReplayOutcome::Timeout,
            FakeProviderReplayOutcome::MalformedStream,
            FakeProviderReplayOutcome::ClientDisconnected,
        ] {
            let store = InMemoryGatewayStore::default();
            let target = FakeProviderReplayTarget {
                alias_resource_id: "ma_test".to_owned(),
                upstream_model_id: "upstream_test".to_owned(),
            };
            let body = json!({"model": "ma_test", "stream": true});
            let response = match run_fake_provider_replay_for_target_with_outcome(
                FakeProviderReplayOutcomeRequest {
                    replay_case: case,
                    engine: &engine_for_case(case),
                    sink: &store,
                    actor: api_key_actor(),
                    target: &target,
                    body: &body,
                    evidence: FakeProviderReplayEvidence {
                        policy_snapshot_id: Some("cfg_test".to_owned()),
                        occurred_at: chrono::Utc::now(),
                    },
                    outcome,
                },
            ) {
                Ok(response) => response,
                Err(error) => panic!("negative replay should return an error body: {error}"),
            };

            assert!(response.authorization.allowed);
            assert_eq!(response.protocol_family, ProtocolFamily::OpenAiChat);
            assert_eq!(response.body["error"]["outcome"], outcome.as_str());
            assert_eq!(response.body["error"]["retryable"], outcome.retryable());
            assert_eq!(response.body["error"]["streaming"], true);
            assert_eq!(store.authorization_decisions().len(), 1);
            assert!(store.authorization_decisions()[0]
                .policy_snapshot_id
                .is_some());
        }
    }

    #[test]
    fn provider_adapter_request_builds_openai_responses_boundary() {
        let request = match build_provider_adapter_request(
            &ProviderAdapterTarget {
                protocol_family: ProtocolFamily::OpenAiResponses,
                provider_endpoint: provider_endpoint("https://api.openai.example/v1"),
                upstream_model_id: "gpt-4.1-mini".to_owned(),
                upstream_credential: Some(ProviderAdapterCredential {
                    upstream_credential_id: "upc_openai".to_owned(),
                    credential_kind: "api_key".to_owned(),
                    secret_value: SecretString::from("sk-test-secret"),
                }),
            },
            &json!({
                "model": "alias-chat",
                "input": "hello"
            }),
        ) {
            Ok(request) => request,
            Err(error) => panic!("provider request should build: {error}"),
        };

        assert_eq!(request.protocol_family, ProtocolFamily::OpenAiResponses);
        assert_eq!(request.method, "POST");
        assert_eq!(request.url, "https://api.openai.example/v1/responses");
        assert_eq!(request.body["model"], "gpt-4.1-mini");
        assert_eq!(request.headers[0].name, "authorization");
        assert_eq!(
            request.headers[0].value.expose_secret(),
            "Bearer sk-test-secret"
        );
        assert_eq!(
            request.safe_metadata.url_origin,
            "https://api.openai.example"
        );
        assert_eq!(request.safe_metadata.url_path, "/v1/responses");
        assert_eq!(
            request.safe_metadata.upstream_credential_id.as_deref(),
            Some("upc_openai")
        );
        assert!(!format!("{request:?}").contains("sk-test-secret"));
        assert!(!serde_json::to_string(&request.safe_metadata)
            .unwrap_or_else(|error| panic!("metadata should serialize: {error}"))
            .contains("sk-test-secret"));
    }

    #[test]
    fn provider_adapter_request_preserves_gateway_mount_paths() {
        let request = match build_provider_adapter_request(
            &ProviderAdapterTarget {
                protocol_family: ProtocolFamily::OpenAiChat,
                provider_endpoint: provider_endpoint("https://proxy.example/gateway/openai/v1"),
                upstream_model_id: "gpt-4.1-mini".to_owned(),
                upstream_credential: None,
            },
            &json!({
                "model": "alias-chat",
                "messages": []
            }),
        ) {
            Ok(request) => request,
            Err(error) => panic!("provider request should build: {error}"),
        };

        assert_eq!(
            request.url,
            "https://proxy.example/gateway/openai/v1/chat/completions"
        );
        assert_eq!(
            request.safe_metadata.url_path,
            "/gateway/openai/v1/chat/completions"
        );
        assert!(request.headers.is_empty());
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

    fn provider_endpoint(upstream_base_url: &str) -> ProviderEndpoint {
        ProviderEndpoint {
            provider_endpoint_id: "pe_openai".to_owned(),
            tenant_id: "tenant_test".to_owned(),
            name: "OpenAI".to_owned(),
            provider_kind: "openai".to_owned(),
            protocol_families: vec![ProtocolFamily::OpenAiResponses, ProtocolFamily::OpenAiChat],
            upstream_base_url: upstream_base_url.to_owned(),
            status: ResourceStatus::Active,
        }
    }
}
