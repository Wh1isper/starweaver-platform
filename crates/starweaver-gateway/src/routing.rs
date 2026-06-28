//! Route decision and attempt evidence for runtime routing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{new_prefixed_id, ActorKind, AuthenticatedActor, TenantId};
use crate::ProtocolFamily;

/// Route target filter reason.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteFilterReason {
    /// Routing group target entry is inactive.
    GroupTargetInactive,
    /// Model target is missing from the snapshot.
    TargetMissing,
    /// Model target is inactive.
    TargetInactive,
    /// Model target protocol does not match ingress.
    ProtocolMismatch,
    /// Streaming was requested but target does not support it.
    StreamingUnsupported,
    /// Provider endpoint is missing from the snapshot.
    EndpointMissing,
    /// Provider endpoint is inactive.
    EndpointInactive,
    /// Provider endpoint does not support the ingress protocol.
    EndpointProtocolMismatch,
    /// Provider endpoint has a fresh drain lock.
    EndpointDrained,
    /// Provider endpoint health is unhealthy.
    EndpointUnhealthy,
    /// Provider endpoint health is blocked.
    EndpointHealthBlocked,
    /// Upstream credential is missing from the snapshot.
    CredentialMissing,
    /// Upstream credential is not usable.
    CredentialUnusable,
    /// Provider grant does not allow this endpoint or target.
    ProviderGrantDenied,
}

impl RouteFilterReason {
    /// Returns the stable reason id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GroupTargetInactive => "group_target_inactive",
            Self::TargetMissing => "target_missing",
            Self::TargetInactive => "target_inactive",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::StreamingUnsupported => "streaming_unsupported",
            Self::EndpointMissing => "endpoint_missing",
            Self::EndpointInactive => "endpoint_inactive",
            Self::EndpointProtocolMismatch => "endpoint_protocol_mismatch",
            Self::EndpointDrained => "endpoint_drained",
            Self::EndpointUnhealthy => "endpoint_unhealthy",
            Self::EndpointHealthBlocked => "endpoint_health_blocked",
            Self::CredentialMissing => "credential_missing",
            Self::CredentialUnusable => "credential_unusable",
            Self::ProviderGrantDenied => "provider_grant_denied",
        }
    }
}

/// Count of filtered route targets by reason.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteFilterSummary {
    /// Stable filter reason.
    pub reason: RouteFilterReason,
    /// Number of candidates filtered by this reason.
    pub count: u32,
}

/// Terminal or intermediate route decision status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDecisionStatus {
    /// Decision was started.
    Started,
    /// A route was selected.
    Selected,
    /// Routing was blocked by policy or grants.
    Blocked,
    /// No eligible route exists.
    NoRoute,
    /// Request completed through the selected route.
    Completed,
    /// Request failed after route selection.
    Failed,
}

impl RouteDecisionStatus {
    /// Returns the SQL status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Selected => "selected",
            Self::Blocked => "blocked",
            Self::NoRoute => "no_route",
            Self::Completed => "completed",
            Self::Failed => "failed",
        }
    }
}

/// Route attempt status.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAttemptStatus {
    /// Attempt has started.
    Started,
    /// Attempt completed successfully.
    Completed,
    /// Attempt failed before a response could be returned.
    Failed,
    /// Client disconnected while the attempt was active.
    ClientDisconnected,
}

impl RouteAttemptStatus {
    /// Returns the SQL status label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::ClientDisconnected => "client_disconnected",
        }
    }
}

/// Route decision evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteDecisionRecord {
    /// Stable decision id.
    pub route_decision_id: String,
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Optional organization boundary.
    pub organization_id: Option<String>,
    /// Optional project boundary.
    pub project_id: Option<String>,
    /// Principal that initiated the request.
    pub principal_id: Option<String>,
    /// API key used for authentication when present.
    pub api_key_id: Option<String>,
    /// Actor id.
    pub actor_id: String,
    /// Actor kind.
    pub actor_kind: ActorKind,
    /// Request id.
    pub request_id: String,
    /// Ingress protocol family.
    pub protocol_family: ProtocolFamily,
    /// Config snapshot id.
    pub config_snapshot_id: Option<String>,
    /// Config snapshot version.
    pub config_version: Option<i64>,
    /// Model alias id when known.
    pub model_alias_id: Option<String>,
    /// Model alias name requested by the client.
    pub alias_name: String,
    /// Route policy id when known.
    pub route_policy_id: Option<String>,
    /// Routing group id when known.
    pub routing_group_id: Option<String>,
    /// Selected model target id when known.
    pub model_target_id: Option<String>,
    /// Selected provider endpoint id when known.
    pub provider_endpoint_id: Option<String>,
    /// Selected upstream credential id when known.
    pub upstream_credential_id: Option<String>,
    /// Counts of candidates filtered during selection.
    pub filtered_summary: Vec<RouteFilterSummary>,
    /// Decision status.
    pub status: RouteDecisionStatus,
    /// Safe status reason.
    pub reason: String,
    /// Decision timestamp.
    pub occurred_at: DateTime<Utc>,
}

impl RouteDecisionRecord {
    /// Builds selected route decision evidence.
    #[must_use]
    pub fn selected(
        actor: &AuthenticatedActor,
        request: RouteDecisionRequest,
        selected: SelectedRouteEvidence,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            route_decision_id: new_prefixed_id("rd"),
            tenant_id: actor.tenant_id.clone(),
            organization_id: actor.organization_id.clone(),
            project_id: actor.project_id.clone(),
            principal_id: actor.principal_id.clone(),
            api_key_id: actor.api_key_id.clone(),
            actor_id: actor.actor_id.clone(),
            actor_kind: actor.actor_kind.clone(),
            request_id: actor.request_id.clone(),
            protocol_family: request.protocol_family,
            config_snapshot_id: request.config_snapshot_id,
            config_version: request.config_version,
            model_alias_id: Some(selected.model_alias_id),
            alias_name: request.alias_name,
            route_policy_id: Some(selected.route_policy_id),
            routing_group_id: Some(selected.routing_group_id),
            model_target_id: Some(selected.model_target_id),
            provider_endpoint_id: Some(selected.provider_endpoint_id),
            upstream_credential_id: selected.upstream_credential_id,
            filtered_summary: selected.filtered_summary,
            status: RouteDecisionStatus::Selected,
            reason: "selected".to_owned(),
            occurred_at,
        }
    }

    /// Builds blocked or no-route decision evidence.
    #[must_use]
    pub fn terminal(
        actor: &AuthenticatedActor,
        request: RouteDecisionRequest,
        status: RouteDecisionStatus,
        reason: impl Into<String>,
        filtered_summary: Vec<RouteFilterSummary>,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            route_decision_id: new_prefixed_id("rd"),
            tenant_id: actor.tenant_id.clone(),
            organization_id: actor.organization_id.clone(),
            project_id: actor.project_id.clone(),
            principal_id: actor.principal_id.clone(),
            api_key_id: actor.api_key_id.clone(),
            actor_id: actor.actor_id.clone(),
            actor_kind: actor.actor_kind.clone(),
            request_id: actor.request_id.clone(),
            protocol_family: request.protocol_family,
            config_snapshot_id: request.config_snapshot_id,
            config_version: request.config_version,
            model_alias_id: None,
            alias_name: request.alias_name,
            route_policy_id: None,
            routing_group_id: None,
            model_target_id: None,
            provider_endpoint_id: None,
            upstream_credential_id: None,
            filtered_summary,
            status,
            reason: reason.into(),
            occurred_at,
        }
    }
}

/// Route decision request context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteDecisionRequest {
    /// Ingress protocol family.
    pub protocol_family: ProtocolFamily,
    /// Client-requested alias name.
    pub alias_name: String,
    /// Config snapshot id.
    pub config_snapshot_id: Option<String>,
    /// Config snapshot version.
    pub config_version: Option<i64>,
}

/// Selected route fields included in decision evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedRouteEvidence {
    /// Model alias id.
    pub model_alias_id: String,
    /// Route policy id.
    pub route_policy_id: String,
    /// Routing group id.
    pub routing_group_id: String,
    /// Model target id.
    pub model_target_id: String,
    /// Provider endpoint id.
    pub provider_endpoint_id: String,
    /// Upstream credential id.
    pub upstream_credential_id: Option<String>,
    /// Filtered candidate summary.
    pub filtered_summary: Vec<RouteFilterSummary>,
}

/// Route attempt evidence.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteAttemptRecord {
    /// Stable attempt event id.
    pub route_attempt_event_id: String,
    /// Parent route decision id.
    pub route_decision_id: String,
    /// Zero-based attempt index.
    pub attempt_index: u32,
    /// Routing group attempted.
    pub routing_group_id: String,
    /// Model target attempted.
    pub model_target_id: String,
    /// Provider endpoint attempted.
    pub provider_endpoint_id: String,
    /// Attempt status.
    pub status: RouteAttemptStatus,
    /// Attempt start timestamp.
    pub started_at: DateTime<Utc>,
    /// Attempt end timestamp.
    pub ended_at: Option<DateTime<Utc>>,
}

impl RouteAttemptRecord {
    /// Builds a completed attempt event.
    #[must_use]
    pub fn completed(
        route_decision_id: impl Into<String>,
        selected: &SelectedRouteEvidence,
        started_at: DateTime<Utc>,
        ended_at: DateTime<Utc>,
    ) -> Self {
        Self {
            route_attempt_event_id: new_prefixed_id("rae"),
            route_decision_id: route_decision_id.into(),
            attempt_index: 0,
            routing_group_id: selected.routing_group_id.clone(),
            model_target_id: selected.model_target_id.clone(),
            provider_endpoint_id: selected.provider_endpoint_id.clone(),
            status: RouteAttemptStatus::Completed,
            started_at,
            ended_at: Some(ended_at),
        }
    }
}

/// Repository boundary for route evidence.
pub trait RouteEvidenceSink: Send + Sync {
    /// Records route decision evidence.
    fn record_route_decision(&self, record: RouteDecisionRecord);

    /// Records route attempt evidence.
    fn record_route_attempt(&self, record: RouteAttemptRecord);
}

/// Adds one filter reason to a summary vector.
pub fn add_filter_reason(summary: &mut Vec<RouteFilterSummary>, reason: RouteFilterReason) {
    if let Some(existing) = summary.iter_mut().find(|entry| entry.reason == reason) {
        existing.count += 1;
    } else {
        summary.push(RouteFilterSummary { reason, count: 1 });
    }
}

#[cfg(test)]
mod tests {
    use crate::routing::{add_filter_reason, RouteFilterReason};

    #[test]
    fn filter_summary_accumulates_by_reason() {
        let mut summary = Vec::new();
        add_filter_reason(&mut summary, RouteFilterReason::ProviderGrantDenied);
        add_filter_reason(&mut summary, RouteFilterReason::ProviderGrantDenied);
        add_filter_reason(&mut summary, RouteFilterReason::EndpointInactive);

        assert_eq!(summary.len(), 2);
        assert_eq!(summary[0].reason, RouteFilterReason::ProviderGrantDenied);
        assert_eq!(summary[0].count, 2);
        assert_eq!(summary[1].reason, RouteFilterReason::EndpointInactive);
        assert_eq!(summary[1].count, 1);
    }
}
