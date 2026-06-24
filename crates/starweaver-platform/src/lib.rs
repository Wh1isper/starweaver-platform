#![doc = "Agent control-plane crate for Starweaver Platform."]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Stable service identifier used in logs, metrics, and deployment metadata.
pub const SERVICE_NAME: &str = "starweaver-platform";

/// Returns the stable agent platform service name.
#[must_use]
pub const fn service_name() -> &'static str {
    SERVICE_NAME
}

/// High-level planes owned or coordinated by the agent platform service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformPlane {
    /// HTTP resources, auth, tenancy, run lifecycle, cancellation, and approvals.
    AgentControl,
    /// Queryable metadata plus archive manifests for ordered run evidence.
    DurableEvidence,
    /// Host-managed environment leases and readiness summaries.
    EnvironmentAttachment,
}

#[cfg(test)]
mod tests {
    use super::{service_name, SERVICE_NAME};

    #[test]
    fn service_name_is_stable() {
        assert_eq!(service_name(), SERVICE_NAME);
    }
}
