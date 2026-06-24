#![doc = "Model egress-plane crate for Starweaver Platform."]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Stable service identifier used in logs, metrics, and deployment metadata.
pub const SERVICE_NAME: &str = "starweaver-gateway";

/// Returns the stable LLM gateway service name.
#[must_use]
pub const fn service_name() -> &'static str {
    SERVICE_NAME
}

/// Client-facing protocol family selected for a gateway route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolFamily {
    /// `OpenAI` Responses-compatible request and stream shape.
    OpenAiResponses,
    /// `OpenAI` Chat Completions-compatible request and stream shape.
    OpenAiChat,
    /// Anthropic Messages-compatible request and stream shape.
    AnthropicMessages,
    /// Gemini-compatible request and stream shape.
    Gemini,
    /// AWS Bedrock native request and stream shape.
    BedrockNative,
}

#[cfg(test)]
mod tests {
    use super::{service_name, SERVICE_NAME};

    #[test]
    fn service_name_is_stable() {
        assert_eq!(service_name(), SERVICE_NAME);
    }
}
