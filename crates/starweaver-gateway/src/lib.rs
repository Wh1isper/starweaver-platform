#![doc = "Model egress-plane crate for Starweaver Platform."]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod action;
pub mod auth;
pub mod catalog;
pub mod config;
pub mod domain;
pub mod error;
#[cfg(test)]
pub(crate) mod fixtures;
pub mod hot_state;
pub mod migrations;
pub mod policy;
pub mod redis_hot_state;
pub mod replay;
pub mod route;
pub mod routing;
pub mod runtime;
pub mod service;
pub mod storage;

/// Stable service identifier used in logs, metrics, and deployment metadata.
pub const SERVICE_NAME: &str = "starweaver-gateway";

/// Returns the stable LLM gateway service name.
#[must_use]
pub const fn service_name() -> &'static str {
    SERVICE_NAME
}

/// Client-facing protocol family selected for a gateway route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Deserialize, serde::Serialize)]
pub enum ProtocolFamily {
    /// `OpenAI` Responses-compatible request and stream shape.
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
    /// `OpenAI` Chat Completions-compatible request and stream shape.
    #[serde(rename = "openai_chat")]
    OpenAiChat,
    /// Anthropic Messages-compatible request and stream shape.
    #[serde(rename = "anthropic_messages")]
    AnthropicMessages,
    /// Gemini-compatible request and stream shape.
    #[serde(rename = "gemini_generate_content")]
    GeminiGenerateContent,
    /// AWS Bedrock Converse-compatible request and stream shape.
    #[serde(rename = "bedrock_converse")]
    BedrockConverse,
    /// Provider-native request shape enabled only through explicit grants.
    #[serde(rename = "provider_native")]
    ProviderNative,
}

impl ProtocolFamily {
    /// Returns the canonical protocol family id used by config and evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAiResponses => "openai_responses",
            Self::OpenAiChat => "openai_chat",
            Self::AnthropicMessages => "anthropic_messages",
            Self::GeminiGenerateContent => "gemini_generate_content",
            Self::BedrockConverse => "bedrock_converse",
            Self::ProviderNative => "provider_native",
        }
    }

    /// Returns every reserved protocol family.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::OpenAiResponses,
            Self::OpenAiChat,
            Self::AnthropicMessages,
            Self::GeminiGenerateContent,
            Self::BedrockConverse,
            Self::ProviderNative,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::{service_name, ProtocolFamily, SERVICE_NAME};

    #[test]
    fn service_name_is_stable() {
        assert_eq!(service_name(), SERVICE_NAME);
    }

    #[test]
    fn protocol_family_ids_are_stable() {
        let ids = ProtocolFamily::all()
            .iter()
            .map(|family| family.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "openai_responses",
                "openai_chat",
                "anthropic_messages",
                "gemini_generate_content",
                "bedrock_converse",
                "provider_native"
            ]
        );
    }

    #[test]
    fn protocol_family_serializes_to_stable_ids() {
        for family in ProtocolFamily::all() {
            let serialized = match serde_json::to_value(family) {
                Ok(value) => value,
                Err(error) => panic!("protocol family should serialize: {error}"),
            };
            assert_eq!(serialized, serde_json::json!(family.as_str()));
        }
    }
}
