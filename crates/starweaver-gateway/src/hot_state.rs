//! Redis-compatible hot-state boundaries for routing decisions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use async_trait::async_trait;

/// Provider endpoint health state derived from hot routing windows.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointHealthState {
    /// No fresh health value is available.
    Unknown,
    /// Endpoint is within policy thresholds.
    Healthy,
    /// Endpoint is new and receiving bounded exploration traffic.
    Warmup,
    /// Endpoint is usable but showing elevated latency or errors.
    Degraded,
    /// Endpoint should not receive normal traffic.
    Unhealthy,
    /// Endpoint is blocked by operator or policy hot state.
    Blocked,
}

impl EndpointHealthState {
    /// Returns the stable health state id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Warmup => "warmup",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Blocked => "blocked",
        }
    }
}

/// Hot health record for one provider endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointHealthRecord {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Provider endpoint id.
    pub provider_endpoint_id: String,
    /// Config version that produced this value.
    pub config_version: i64,
    /// Observed health state.
    pub state: EndpointHealthState,
    /// Observation timestamp.
    pub observed_at: DateTime<Utc>,
    /// TTL expiry timestamp.
    pub expires_at: DateTime<Utc>,
}

impl EndpointHealthRecord {
    /// Returns whether the record applies to the active config and time.
    #[must_use]
    pub fn is_fresh_for(&self, config_version: Option<i64>, now: DateTime<Utc>) -> bool {
        config_version == Some(self.config_version) && self.expires_at > now
    }
}

/// Hot drain lock for one provider endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EndpointDrainRecord {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Provider endpoint id.
    pub provider_endpoint_id: String,
    /// Config version that produced this value.
    pub config_version: i64,
    /// Safe drain reason.
    pub reason: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// TTL expiry timestamp.
    pub expires_at: DateTime<Utc>,
}

impl EndpointDrainRecord {
    /// Returns whether the record applies to the active config and time.
    #[must_use]
    pub fn is_fresh_for(&self, config_version: Option<i64>, now: DateTime<Utc>) -> bool {
        config_version == Some(self.config_version) && self.expires_at > now
    }
}

/// Sticky route mapping for one affinity key and model alias.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StickyRouteRecord {
    /// Tenant boundary.
    pub tenant_id: String,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Model alias id.
    pub model_alias_id: String,
    /// Hash of the caller-provided affinity key.
    pub affinity_hash: String,
    /// Routing group selected when the mapping was written.
    pub routing_group_id: String,
    /// Model target selected when the mapping was written.
    pub model_target_id: String,
    /// Provider endpoint selected when the mapping was written.
    pub provider_endpoint_id: String,
    /// Config version that produced this value.
    pub config_version: i64,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
    /// TTL expiry timestamp.
    pub expires_at: DateTime<Utc>,
}

impl StickyRouteRecord {
    /// Returns whether the record applies to the active config and time.
    #[must_use]
    pub fn is_fresh_for(&self, config_version: Option<i64>, now: DateTime<Utc>) -> bool {
        config_version == Some(self.config_version) && self.expires_at > now
    }
}

/// Hot-state boundary used by route selection.
#[async_trait]
pub trait RouteHotState: Send + Sync {
    /// Returns endpoint health, or `Unknown` when hot state is missing or stale.
    async fn endpoint_health_state(
        &self,
        tenant_id: &str,
        provider_endpoint_id: &str,
        config_version: Option<i64>,
        now: DateTime<Utc>,
    ) -> EndpointHealthState;

    /// Returns whether a fresh endpoint drain lock exists.
    async fn endpoint_is_drained(
        &self,
        tenant_id: &str,
        provider_endpoint_id: &str,
        config_version: Option<i64>,
        now: DateTime<Utc>,
    ) -> bool;

    /// Returns a fresh sticky route mapping when one exists.
    async fn sticky_route(
        &self,
        tenant_id: &str,
        project_id: Option<&str>,
        model_alias_id: &str,
        affinity_hash: &str,
        config_version: Option<i64>,
        now: DateTime<Utc>,
    ) -> Option<StickyRouteRecord>;

    /// Writes or replaces endpoint health state.
    async fn set_endpoint_health(&self, record: EndpointHealthRecord);

    /// Writes or replaces an endpoint drain lock.
    async fn set_endpoint_drain(&self, record: EndpointDrainRecord);

    /// Writes or replaces a sticky route mapping.
    async fn set_sticky_route(&self, record: StickyRouteRecord);
}

/// Null hot-state implementation used when the backend is unavailable.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullRouteHotState;

#[async_trait]
impl RouteHotState for NullRouteHotState {
    async fn endpoint_health_state(
        &self,
        _tenant_id: &str,
        _provider_endpoint_id: &str,
        _config_version: Option<i64>,
        _now: DateTime<Utc>,
    ) -> EndpointHealthState {
        EndpointHealthState::Unknown
    }

    async fn endpoint_is_drained(
        &self,
        _tenant_id: &str,
        _provider_endpoint_id: &str,
        _config_version: Option<i64>,
        _now: DateTime<Utc>,
    ) -> bool {
        false
    }

    async fn sticky_route(
        &self,
        _tenant_id: &str,
        _project_id: Option<&str>,
        _model_alias_id: &str,
        _affinity_hash: &str,
        _config_version: Option<i64>,
        _now: DateTime<Utc>,
    ) -> Option<StickyRouteRecord> {
        None
    }

    async fn set_endpoint_health(&self, _record: EndpointHealthRecord) {}

    async fn set_endpoint_drain(&self, _record: EndpointDrainRecord) {}

    async fn set_sticky_route(&self, _record: StickyRouteRecord) {}
}

/// Returns the Redis-compatible endpoint health key shape.
#[must_use]
pub fn endpoint_health_key(tenant_id: &str, provider_endpoint_id: &str) -> String {
    format!("gateway:endpoint_health:{tenant_id}:{provider_endpoint_id}")
}

/// Returns the Redis-compatible drain key shape.
#[must_use]
pub fn endpoint_drain_key(tenant_id: &str, provider_endpoint_id: &str) -> String {
    format!("gateway:drain:{tenant_id}:{provider_endpoint_id}")
}

/// Returns the Redis-compatible sticky route key shape.
#[must_use]
pub fn sticky_route_key(
    tenant_id: &str,
    project_id: Option<&str>,
    model_alias_id: &str,
    affinity_hash: &str,
) -> String {
    format!(
        "gateway:sticky:{tenant_id}:{}:{model_alias_id}:{affinity_hash}",
        project_id.unwrap_or("_")
    )
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use crate::hot_state::{
        EndpointHealthRecord, EndpointHealthState, StickyRouteRecord, endpoint_drain_key,
        endpoint_health_key, sticky_route_key,
    };

    #[test]
    fn route_hot_state_keys_are_namespaced() {
        assert_eq!(
            endpoint_health_key("ten_test", "pep_test"),
            "gateway:endpoint_health:ten_test:pep_test"
        );
        assert_eq!(
            endpoint_drain_key("ten_test", "pep_test"),
            "gateway:drain:ten_test:pep_test"
        );
        assert_eq!(
            sticky_route_key("ten_test", Some("prj_test"), "ma_test", "sha256:test"),
            "gateway:sticky:ten_test:prj_test:ma_test:sha256:test"
        );
        assert_eq!(
            sticky_route_key("ten_test", None, "ma_test", "sha256:test"),
            "gateway:sticky:ten_test:_:ma_test:sha256:test"
        );
    }

    #[test]
    fn endpoint_health_record_requires_fresh_matching_config() {
        let now = chrono::Utc::now();
        let record = EndpointHealthRecord {
            tenant_id: "ten_test".to_owned(),
            provider_endpoint_id: "pep_test".to_owned(),
            config_version: 7,
            state: EndpointHealthState::Healthy,
            observed_at: now,
            expires_at: now + Duration::seconds(30),
        };

        assert!(record.is_fresh_for(Some(7), now));
        assert!(!record.is_fresh_for(Some(8), now));
        assert!(!record.is_fresh_for(Some(7), now + Duration::seconds(31)));
    }

    #[test]
    fn sticky_route_record_requires_fresh_matching_config() {
        let now = chrono::Utc::now();
        let record = StickyRouteRecord {
            tenant_id: "ten_test".to_owned(),
            project_id: Some("prj_test".to_owned()),
            model_alias_id: "ma_test".to_owned(),
            affinity_hash: "sha256:test".to_owned(),
            routing_group_id: "rg_test".to_owned(),
            model_target_id: "mt_test".to_owned(),
            provider_endpoint_id: "pep_test".to_owned(),
            config_version: 7,
            created_at: now,
            expires_at: now + Duration::seconds(30),
        };

        assert!(record.is_fresh_for(Some(7), now));
        assert!(!record.is_fresh_for(Some(8), now));
        assert!(!record.is_fresh_for(Some(7), now + Duration::seconds(31)));
    }
}
