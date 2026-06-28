#![doc = "Agent control-plane crate for Starweaver Platform."]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

/// Stable service identifier used in logs, metrics, and deployment metadata.
pub const SERVICE_NAME: &str = "starweaver-platform";

/// Platform-local authorization primitives.
pub mod action;

/// Platform-local authentication primitives.
pub mod auth;

/// Platform startup configuration.
pub mod config;

/// Platform-local identity provider contracts.
pub mod identity;

/// Platform-local organization invitation contracts.
pub mod invitation;

/// Platform-local membership contracts.
pub mod membership;

/// Platform route metadata.
pub mod route;

/// Platform business resource records.
pub mod resource;

/// Platform-local secret reference contracts.
pub mod secret;

/// Platform database migration entry points.
pub mod migrations;

/// Platform PostgreSQL repository adapters.
pub mod postgres;

/// Platform HTTP service foundation.
pub mod service;

/// Platform-local storage boundaries.
pub mod storage;

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
