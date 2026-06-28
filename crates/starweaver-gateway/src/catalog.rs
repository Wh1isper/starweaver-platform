//! Runtime-safe provider catalog snapshot parsing and route selection.

use std::cmp::Reverse;
use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::domain::{AuthenticatedActor, ProviderEndpoint, ResourceStatus};
use crate::error::{GatewayError, Result};
use crate::hot_state::{EndpointHealthState, NullRouteHotState, RouteHotState};
use crate::routing::{add_filter_reason, RouteFilterReason, RouteFilterSummary};
use crate::ProtocolFamily;

/// Runtime-safe gateway catalog compiled into a config snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GatewayCatalogSnapshot {
    /// Provider endpoints available to runtime routing.
    #[serde(default)]
    pub provider_endpoints: Vec<ProviderEndpoint>,
    /// Upstream credential metadata. Raw secrets are not present.
    #[serde(default)]
    pub upstream_credentials: Vec<UpstreamCredentialConfig>,
    /// Provider model targets.
    #[serde(default)]
    pub model_targets: Vec<ModelTargetConfig>,
    /// Client-visible model aliases.
    #[serde(default)]
    pub model_aliases: Vec<ModelAliasConfig>,
    /// Routing groups.
    #[serde(default)]
    pub routing_groups: Vec<RoutingGroupConfig>,
    /// Routing group target entries.
    #[serde(default)]
    pub routing_group_targets: Vec<RoutingGroupTargetConfig>,
    /// Route policies.
    #[serde(default)]
    pub route_policies: Vec<RoutePolicyConfig>,
    /// Provider grants controlling endpoint and target eligibility.
    #[serde(default)]
    pub provider_grants: Vec<ProviderGrantConfig>,
}

impl GatewayCatalogSnapshot {
    /// Parses a runtime-safe catalog from a config payload.
    pub fn from_payload(payload: &Value) -> Result<Option<Self>> {
        if !payload_has_catalog(payload) {
            return Ok(None);
        }
        let catalog = serde_json::from_value::<Self>(payload.clone()).map_err(|error| {
            GatewayError::BadRequest {
                message: format!("invalid catalog snapshot payload: {error}"),
            }
        })?;
        catalog.validate()?;
        Ok(Some(catalog))
    }

    /// Validates catalog references and protocol compatibility.
    pub fn validate(&self) -> Result<()> {
        let endpoints = index_endpoints(&self.provider_endpoints)?;
        let credentials = index_credentials(&self.upstream_credentials)?;
        let targets = index_targets(&self.model_targets)?;
        let aliases = index_aliases(&self.model_aliases)?;
        let groups = index_groups(&self.routing_groups)?;
        let group_targets = group_targets_by_group(&self.routing_group_targets);
        let policies = index_policies(&self.route_policies)?;

        validate_endpoints(&self.provider_endpoints)?;
        validate_credentials(&self.upstream_credentials, &endpoints)?;
        validate_targets(&self.model_targets, &endpoints, &credentials)?;
        validate_policies(&self.route_policies, &groups, &group_targets)?;
        validate_provider_grants(
            &self.provider_grants,
            &aliases,
            &policies,
            &groups,
            &targets,
            &endpoints,
        )?;
        validate_aliases(&self.model_aliases, &policies, &targets, &group_targets)
    }

    /// Selects a runtime route for an authenticated model request.
    pub fn select_runtime_route(
        &self,
        actor: &AuthenticatedActor,
        protocol_family: ProtocolFamily,
        alias_name: &str,
        streaming: bool,
    ) -> Result<RouteSelection> {
        match self
            .plan_runtime_route(actor, protocol_family, alias_name, streaming)?
            .outcome
        {
            RoutePlanOutcome::Selected(selection) => Ok(*selection),
            RoutePlanOutcome::ProviderGrantDenied => Err(GatewayError::Authorization {
                reason: "provider_grant_denied",
            }),
            RoutePlanOutcome::NoRoute => Err(GatewayError::NoRoute {
                reason: "no_eligible_model_target",
            }),
        }
    }

    /// Plans a runtime route and returns filtered candidate evidence.
    pub fn plan_runtime_route(
        &self,
        actor: &AuthenticatedActor,
        protocol_family: ProtocolFamily,
        alias_name: &str,
        streaming: bool,
    ) -> Result<RoutePlan> {
        self.plan_runtime_route_with_hot_state(&RoutePlanRequest {
            actor,
            protocol_family,
            alias_name,
            streaming,
            hot_state: &NullRouteHotState,
            config_version: None,
            now: Utc::now(),
        })
    }

    /// Plans a runtime route using Redis-compatible hot-state hints.
    pub fn plan_runtime_route_with_hot_state(
        &self,
        request: &RoutePlanRequest<'_>,
    ) -> Result<RoutePlan> {
        let alias = self.resolve_alias(request.actor, request.alias_name)?;
        if alias.protocol_family != request.protocol_family {
            return Err(GatewayError::BadRequest {
                message: format!(
                    "protocol_mismatch: alias {} is {}, ingress is {}",
                    alias.alias_name,
                    alias.protocol_family.as_str(),
                    request.protocol_family.as_str()
                ),
            });
        }
        if !alias.status.is_active() {
            return Err(GatewayError::NotFound {
                resource: format!("model alias {}", request.alias_name),
            });
        }

        let policy = self
            .route_policies
            .iter()
            .find(|policy| policy.route_policy_id == alias.route_policy_id)
            .ok_or(GatewayError::NotReady)?;
        if !policy.status.is_active() {
            return Err(GatewayError::NotReady);
        }

        let group = self
            .routing_groups
            .iter()
            .find(|group| group.routing_group_id == policy.routing_group_id)
            .ok_or(GatewayError::NotReady)?;
        if !group.status.is_active() {
            return Err(GatewayError::NotReady);
        }

        let endpoints = index_endpoints(&self.provider_endpoints)?;
        let credentials = index_credentials(&self.upstream_credentials)?;
        let targets = index_targets(&self.model_targets)?;
        let mut candidates = self
            .routing_group_targets
            .iter()
            .filter(|candidate| candidate.routing_group_id == group.routing_group_id)
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| right.weight.cmp(&left.weight))
                .then_with(|| left.model_target_id.cmp(&right.model_target_id))
        });

        let context = RouteCandidateContext {
            actor: request.actor,
            protocol_family: request.protocol_family,
            streaming: request.streaming,
            alias,
            policy,
            group,
            endpoints: &endpoints,
            credentials: &credentials,
            targets: &targets,
            hot_state: request.hot_state,
            config_version: request.config_version,
            now: request.now,
        };
        let mut filtered_summary = Vec::new();
        let mut provider_grant_denied = false;
        for candidate in candidates {
            match self.evaluate_candidate(candidate, &context) {
                CandidateEvaluation::Selected { target, endpoint } => {
                    let selection = RouteSelection {
                        model_alias_id: alias.model_alias_id.clone(),
                        alias_name: alias.alias_name.clone(),
                        route_policy_id: policy.route_policy_id.clone(),
                        routing_group_id: group.routing_group_id.clone(),
                        model_target_id: target.model_target_id.clone(),
                        upstream_model_id: target.upstream_model_id.clone(),
                        provider_endpoint: (*endpoint).clone(),
                        upstream_credential_id: target.upstream_credential_id.clone(),
                        filtered_summary: filtered_summary.clone(),
                    };
                    return Ok(RoutePlan {
                        outcome: RoutePlanOutcome::Selected(Box::new(selection)),
                        filtered_summary,
                    });
                }
                CandidateEvaluation::Filtered(reason) => {
                    if reason == RouteFilterReason::ProviderGrantDenied {
                        provider_grant_denied = true;
                    }
                    add_filter_reason(&mut filtered_summary, reason);
                }
            }
        }

        if provider_grant_denied {
            return Ok(RoutePlan {
                outcome: RoutePlanOutcome::ProviderGrantDenied,
                filtered_summary,
            });
        }
        Ok(RoutePlan {
            outcome: RoutePlanOutcome::NoRoute,
            filtered_summary,
        })
    }

    fn resolve_alias(
        &self,
        actor: &AuthenticatedActor,
        alias_name: &str,
    ) -> Result<&ModelAliasConfig> {
        let mut scoped = self
            .model_aliases
            .iter()
            .filter(|alias| alias.tenant_id == actor.tenant_id && alias.alias_name == alias_name)
            .filter_map(|alias| alias_scope_score(alias, actor).map(|score| (score, alias)))
            .collect::<Vec<_>>();
        scoped.sort_by_key(|(score, _)| Reverse(*score));

        let Some((best_score, best_alias)) = scoped.first().copied() else {
            return Err(GatewayError::NotFound {
                resource: format!("model alias {alias_name}"),
            });
        };
        if scoped.iter().skip(1).any(|(score, _)| *score == best_score) {
            return Err(GatewayError::BadRequest {
                message: format!("ambiguous model alias {alias_name}"),
            });
        }
        Ok(best_alias)
    }

    fn provider_grant_allows(
        &self,
        context: &RouteCandidateContext<'_>,
        endpoint: &ProviderEndpoint,
        target: &ModelTargetConfig,
    ) -> bool {
        if !self.has_spec_provider_grants(context.actor) {
            return self.legacy_provider_grant_allows(context.actor, endpoint, target);
        }
        self.spec_provider_grant_allows(context, endpoint, target)
    }

    fn has_spec_provider_grants(&self, actor: &AuthenticatedActor) -> bool {
        self.provider_grants.iter().any(|grant| {
            grant.status.is_active() && grant.tenant_id == actor.tenant_id && grant.is_spec_shape()
        })
    }

    fn legacy_provider_grant_allows(
        &self,
        actor: &AuthenticatedActor,
        endpoint: &ProviderEndpoint,
        target: &ModelTargetConfig,
    ) -> bool {
        self.provider_grants.iter().any(|grant| {
            grant.status.is_active()
                && grant.tenant_id == actor.tenant_id
                && optional_match(
                    grant.organization_id.as_deref(),
                    actor.organization_id.as_deref(),
                )
                && optional_match(grant.project_id.as_deref(), actor.project_id.as_deref())
                && optional_match(grant.principal_id.as_deref(), actor.principal_id.as_deref())
                && grant.provider_endpoint_id.as_deref()
                    == Some(endpoint.provider_endpoint_id.as_str())
                && grant
                    .model_target_id
                    .as_deref()
                    .is_none_or(|model_target_id| model_target_id == target.model_target_id)
        })
    }

    fn spec_provider_grant_allows(
        &self,
        context: &RouteCandidateContext<'_>,
        endpoint: &ProviderEndpoint,
        target: &ModelTargetConfig,
    ) -> bool {
        let path = ProviderGrantPath::new(
            context.alias,
            context.policy,
            context.group,
            target,
            endpoint,
        );
        let Some(organization_id) = context.actor.organization_id.as_deref() else {
            return false;
        };
        if !self.scope_allows_all_path_nodes(
            context.actor,
            ProviderGrantScopeKind::Organization,
            organization_id,
            &path,
        ) {
            return false;
        }
        let Some(project_id) = context.actor.project_id.as_deref() else {
            return true;
        };
        self.project_scope_inherits_or_narrows(context.actor, project_id, &path)
    }

    fn scope_allows_all_path_nodes(
        &self,
        actor: &AuthenticatedActor,
        scope_kind: ProviderGrantScopeKind,
        scope_id: &str,
        path: &ProviderGrantPath<'_>,
    ) -> bool {
        path.nodes().iter().all(|node| {
            self.spec_scope_allows_node(actor, scope_kind, scope_id, path, node)
                && !self.spec_scope_denies_node(actor, scope_kind, scope_id, path, node)
        })
    }

    fn project_scope_inherits_or_narrows(
        &self,
        actor: &AuthenticatedActor,
        project_id: &str,
        path: &ProviderGrantPath<'_>,
    ) -> bool {
        for node in path.nodes() {
            if self.spec_scope_denies_node(
                actor,
                ProviderGrantScopeKind::Project,
                project_id,
                path,
                &node,
            ) {
                return false;
            }
            if self.project_has_allow_for_kind(actor, project_id, node.kind)
                && !self.spec_scope_allows_node(
                    actor,
                    ProviderGrantScopeKind::Project,
                    project_id,
                    path,
                    &node,
                )
            {
                return false;
            }
        }
        true
    }

    fn project_has_allow_for_kind(
        &self,
        actor: &AuthenticatedActor,
        project_id: &str,
        resource_kind: ProviderGrantResourceKind,
    ) -> bool {
        self.provider_grants.iter().any(|grant| {
            grant.status.is_active()
                && grant.effect == ProviderGrantEffect::Allow
                && grant_matches_scope(grant, actor, ProviderGrantScopeKind::Project, project_id)
                && grant.resource_kind == Some(resource_kind)
        })
    }

    fn spec_scope_allows_node(
        &self,
        actor: &AuthenticatedActor,
        scope_kind: ProviderGrantScopeKind,
        scope_id: &str,
        path: &ProviderGrantPath<'_>,
        node: &ProviderGrantPathNode<'_>,
    ) -> bool {
        self.provider_grants.iter().any(|grant| {
            grant.status.is_active()
                && grant.effect == ProviderGrantEffect::Allow
                && grant_matches_scope(grant, actor, scope_kind, scope_id)
                && grant_applies_to_node(grant, path, node)
        })
    }

    fn spec_scope_denies_node(
        &self,
        actor: &AuthenticatedActor,
        scope_kind: ProviderGrantScopeKind,
        scope_id: &str,
        path: &ProviderGrantPath<'_>,
        node: &ProviderGrantPathNode<'_>,
    ) -> bool {
        self.provider_grants.iter().any(|grant| {
            grant.status.is_active()
                && grant.effect == ProviderGrantEffect::Deny
                && grant_matches_scope(grant, actor, scope_kind, scope_id)
                && grant_applies_to_node(grant, path, node)
        })
    }

    fn evaluate_candidate<'a>(
        &self,
        candidate: &'a RoutingGroupTargetConfig,
        context: &'a RouteCandidateContext<'a>,
    ) -> CandidateEvaluation<'a> {
        if !candidate.status.is_active() {
            return CandidateEvaluation::Filtered(RouteFilterReason::GroupTargetInactive);
        }
        let Some(target) = context.targets.get(candidate.model_target_id.as_str()) else {
            return CandidateEvaluation::Filtered(RouteFilterReason::TargetMissing);
        };
        if !target.status.is_active() {
            return CandidateEvaluation::Filtered(RouteFilterReason::TargetInactive);
        }
        if target.protocol_family != context.protocol_family {
            return CandidateEvaluation::Filtered(RouteFilterReason::ProtocolMismatch);
        }
        if context.streaming && !target.supports_streaming {
            return CandidateEvaluation::Filtered(RouteFilterReason::StreamingUnsupported);
        }
        let Some(endpoint) = context.endpoints.get(target.provider_endpoint_id.as_str()) else {
            return CandidateEvaluation::Filtered(RouteFilterReason::EndpointMissing);
        };
        if !endpoint.status.is_active() {
            return CandidateEvaluation::Filtered(RouteFilterReason::EndpointInactive);
        }
        if !endpoint
            .protocol_families
            .contains(&context.protocol_family)
        {
            return CandidateEvaluation::Filtered(RouteFilterReason::EndpointProtocolMismatch);
        }
        if context.hot_state.endpoint_is_drained(
            &endpoint.tenant_id,
            &endpoint.provider_endpoint_id,
            context.config_version,
            context.now,
        ) {
            return CandidateEvaluation::Filtered(RouteFilterReason::EndpointDrained);
        }
        match context.hot_state.endpoint_health_state(
            &endpoint.tenant_id,
            &endpoint.provider_endpoint_id,
            context.config_version,
            context.now,
        ) {
            EndpointHealthState::Blocked => {
                return CandidateEvaluation::Filtered(RouteFilterReason::EndpointHealthBlocked);
            }
            EndpointHealthState::Unhealthy => {
                return CandidateEvaluation::Filtered(RouteFilterReason::EndpointUnhealthy);
            }
            EndpointHealthState::Unknown
            | EndpointHealthState::Healthy
            | EndpointHealthState::Warmup
            | EndpointHealthState::Degraded => {}
        }
        if let Some(credential_id) = target.upstream_credential_id.as_deref() {
            let Some(credential) = context.credentials.get(credential_id) else {
                return CandidateEvaluation::Filtered(RouteFilterReason::CredentialMissing);
            };
            if !credential.status.is_usable() {
                return CandidateEvaluation::Filtered(RouteFilterReason::CredentialUnusable);
            }
        }
        if !self.provider_grant_allows(context, endpoint, target) {
            return CandidateEvaluation::Filtered(RouteFilterReason::ProviderGrantDenied);
        }
        CandidateEvaluation::Selected { target, endpoint }
    }
}

/// Route planning request with immutable context and hot-state inputs.
pub struct RoutePlanRequest<'a> {
    /// Authenticated actor requesting the model alias.
    pub actor: &'a AuthenticatedActor,
    /// Ingress protocol family.
    pub protocol_family: ProtocolFamily,
    /// Client-visible model alias name.
    pub alias_name: &'a str,
    /// Whether the request needs a streaming-capable target.
    pub streaming: bool,
    /// Redis-compatible hot-state reader.
    pub hot_state: &'a dyn RouteHotState,
    /// Active config snapshot version for hot-state freshness checks.
    pub config_version: Option<i64>,
    /// Routing decision timestamp.
    pub now: DateTime<Utc>,
}

/// Upstream credential metadata included in runtime config snapshots.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UpstreamCredentialConfig {
    /// Stable upstream credential id.
    pub upstream_credential_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Referenced provider endpoint.
    pub provider_endpoint_id: String,
    /// Credential kind. Raw credential material is not included.
    pub credential_kind: String,
    /// Secret reference id.
    pub secret_ref_id: String,
    /// Credential status.
    pub status: CredentialStatus,
}

/// Upstream credential status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStatus {
    /// Credential can be used.
    Active,
    /// Credential can be used while rotation is in progress.
    Rotating,
    /// Credential is disabled.
    Disabled,
    /// Credential is expired.
    Expired,
    /// Credential has a safe operational error.
    Error,
    /// Credential is deleted.
    Deleted,
}

impl CredentialStatus {
    /// Returns whether runtime may use the credential.
    #[must_use]
    pub const fn is_usable(&self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

/// Runtime model target configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelTargetConfig {
    /// Stable target id.
    pub model_target_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Provider endpoint id.
    pub provider_endpoint_id: String,
    /// Optional upstream credential id.
    pub upstream_credential_id: Option<String>,
    /// Target protocol family.
    pub protocol_family: ProtocolFamily,
    /// Provider model id sent upstream.
    pub upstream_model_id: String,
    /// Target lifecycle status.
    pub status: ResourceStatus,
    /// Whether this target can serve streaming requests.
    #[serde(default = "default_true")]
    pub supports_streaming: bool,
}

/// Runtime model alias configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelAliasConfig {
    /// Stable alias id.
    pub model_alias_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Optional organization scope.
    pub organization_id: Option<String>,
    /// Optional project scope.
    pub project_id: Option<String>,
    /// Client-visible alias name.
    pub alias_name: String,
    /// Alias protocol family.
    pub protocol_family: ProtocolFamily,
    /// Route policy id.
    pub route_policy_id: String,
    /// Alias lifecycle status.
    pub status: ResourceStatus,
}

/// Runtime routing group configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingGroupConfig {
    /// Stable routing group id.
    pub routing_group_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Group lifecycle status.
    pub status: ResourceStatus,
}

/// Runtime routing group target configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingGroupTargetConfig {
    /// Stable routing group target id.
    pub routing_group_target_id: String,
    /// Routing group id.
    pub routing_group_id: String,
    /// Model target id.
    pub model_target_id: String,
    /// Selection weight.
    pub weight: u32,
    /// Lower priority is tried first.
    pub priority: u32,
    /// Entry lifecycle status.
    pub status: ResourceStatus,
}

/// Runtime route policy configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutePolicyConfig {
    /// Stable route policy id.
    pub route_policy_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Model alias id.
    pub model_alias_id: String,
    /// Routing group id.
    pub routing_group_id: String,
    /// Policy lifecycle status.
    pub status: ResourceStatus,
}

/// Runtime provider grant configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderGrantConfig {
    /// Stable provider grant id.
    pub provider_grant_id: String,
    /// Owning tenant.
    pub tenant_id: String,
    /// Scope kind from the provider grant closure spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_kind: Option<ProviderGrantScopeKind>,
    /// Scope id from the provider grant closure spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    /// Optional organization scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    /// Optional project scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_id: Option<String>,
    /// Optional principal scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id: Option<String>,
    /// Grantable resource kind from the provider grant closure spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_kind: Option<ProviderGrantResourceKind>,
    /// Grantable resource id from the provider grant closure spec.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    /// Grant effect.
    #[serde(default = "default_provider_grant_effect")]
    pub effect: ProviderGrantEffect,
    /// Closure mode used for route graph expansion.
    #[serde(default = "default_provider_grant_closure_mode")]
    pub closure_mode: ProviderGrantClosureMode,
    /// Legacy granted provider endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_endpoint_id: Option<String>,
    /// Optional granted target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_target_id: Option<String>,
    /// Grant lifecycle status.
    pub status: ResourceStatus,
}

impl ProviderGrantConfig {
    fn is_spec_shape(&self) -> bool {
        self.scope_kind.is_some()
            || self.scope_id.is_some()
            || self.resource_kind.is_some()
            || self.resource_id.is_some()
            || self.effect != ProviderGrantEffect::Allow
            || self.closure_mode != ProviderGrantClosureMode::SelfOnly
    }
}

/// Provider grant scope kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGrantScopeKind {
    /// Organization-scoped provider grant.
    Organization,
    /// Project-scoped provider grant.
    Project,
}

/// Provider grant resource kind.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGrantResourceKind {
    /// Client-visible model alias.
    ModelAlias,
    /// Route policy node reached from a model alias.
    RoutePolicy,
    /// Routing group containing model targets.
    RoutingGroup,
    /// Provider model target.
    ModelTarget,
    /// Provider endpoint.
    ProviderEndpoint,
    /// Pricing SKU visible for reporting.
    PricingSku,
}

/// Provider grant effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGrantEffect {
    /// Allow the resource.
    Allow,
    /// Deny the resource.
    Deny,
}

/// Provider grant closure mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderGrantClosureMode {
    /// Apply only to the named resource.
    SelfOnly,
    /// Apply to the named resource and route graph descendants.
    IncludeDescendants,
    /// Deny the named resource and route graph descendants.
    DenyDescendants,
}

/// Selected runtime route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RouteSelection {
    /// Authorized model alias id.
    pub model_alias_id: String,
    /// Client-visible alias name.
    pub alias_name: String,
    /// Route policy id.
    pub route_policy_id: String,
    /// Routing group id.
    pub routing_group_id: String,
    /// Selected model target id.
    pub model_target_id: String,
    /// Provider model id sent upstream.
    pub upstream_model_id: String,
    /// Selected provider endpoint safe metadata.
    pub provider_endpoint: ProviderEndpoint,
    /// Selected credential id. Secret material is not included.
    pub upstream_credential_id: Option<String>,
    /// Counts of candidates filtered before this selection.
    pub filtered_summary: Vec<RouteFilterSummary>,
}

/// Route planning result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    /// Planning outcome.
    pub outcome: RoutePlanOutcome,
    /// Counts of candidates filtered during planning.
    pub filtered_summary: Vec<RouteFilterSummary>,
}

/// Route planning outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RoutePlanOutcome {
    /// A target was selected.
    Selected(Box<RouteSelection>),
    /// Candidate targets existed but provider grants denied them.
    ProviderGrantDenied,
    /// No eligible target exists.
    NoRoute,
}

struct RouteCandidateContext<'a> {
    actor: &'a AuthenticatedActor,
    protocol_family: ProtocolFamily,
    streaming: bool,
    alias: &'a ModelAliasConfig,
    policy: &'a RoutePolicyConfig,
    group: &'a RoutingGroupConfig,
    endpoints: &'a HashMap<&'a str, &'a ProviderEndpoint>,
    credentials: &'a HashMap<&'a str, &'a UpstreamCredentialConfig>,
    targets: &'a HashMap<&'a str, &'a ModelTargetConfig>,
    hot_state: &'a dyn RouteHotState,
    config_version: Option<i64>,
    now: DateTime<Utc>,
}

enum CandidateEvaluation<'a> {
    Selected {
        target: &'a ModelTargetConfig,
        endpoint: &'a ProviderEndpoint,
    },
    Filtered(RouteFilterReason),
}

struct ProviderGrantPath<'a> {
    alias: &'a ModelAliasConfig,
    policy: &'a RoutePolicyConfig,
    group: &'a RoutingGroupConfig,
    target: &'a ModelTargetConfig,
    endpoint: &'a ProviderEndpoint,
}

impl<'a> ProviderGrantPath<'a> {
    const fn new(
        alias: &'a ModelAliasConfig,
        policy: &'a RoutePolicyConfig,
        group: &'a RoutingGroupConfig,
        target: &'a ModelTargetConfig,
        endpoint: &'a ProviderEndpoint,
    ) -> Self {
        Self {
            alias,
            policy,
            group,
            target,
            endpoint,
        }
    }

    fn nodes(&self) -> [ProviderGrantPathNode<'a>; 5] {
        [
            ProviderGrantPathNode {
                kind: ProviderGrantResourceKind::ModelAlias,
                id: &self.alias.model_alias_id,
            },
            ProviderGrantPathNode {
                kind: ProviderGrantResourceKind::RoutePolicy,
                id: &self.policy.route_policy_id,
            },
            ProviderGrantPathNode {
                kind: ProviderGrantResourceKind::RoutingGroup,
                id: &self.group.routing_group_id,
            },
            ProviderGrantPathNode {
                kind: ProviderGrantResourceKind::ModelTarget,
                id: &self.target.model_target_id,
            },
            ProviderGrantPathNode {
                kind: ProviderGrantResourceKind::ProviderEndpoint,
                id: &self.endpoint.provider_endpoint_id,
            },
        ]
    }

    fn position(&self, kind: ProviderGrantResourceKind, id: &str) -> Option<usize> {
        self.nodes()
            .iter()
            .position(|node| node.kind == kind && node.id == id)
    }
}

#[derive(Clone, Copy)]
struct ProviderGrantPathNode<'a> {
    kind: ProviderGrantResourceKind,
    id: &'a str,
}

fn payload_has_catalog(payload: &Value) -> bool {
    [
        "provider_endpoints",
        "upstream_credentials",
        "model_targets",
        "model_aliases",
        "routing_groups",
        "routing_group_targets",
        "route_policies",
        "provider_grants",
    ]
    .iter()
    .any(|key| payload.get(*key).is_some())
}

fn validate_endpoint(endpoint: &ProviderEndpoint) -> Result<()> {
    if endpoint.protocol_families.is_empty() {
        return invalid_catalog(format!(
            "provider endpoint {} has no protocol families",
            endpoint.provider_endpoint_id
        ));
    }
    let uri = endpoint
        .upstream_base_url
        .parse::<http::Uri>()
        .map_err(|error| GatewayError::BadRequest {
            message: format!(
                "provider endpoint {} has invalid upstream_base_url: {error}",
                endpoint.provider_endpoint_id
            ),
        })?;
    let scheme = uri.scheme_str();
    if !matches!(scheme, Some("http" | "https")) || uri.authority().is_none() {
        return invalid_catalog(format!(
            "provider endpoint {} upstream_base_url must be absolute http or https",
            endpoint.provider_endpoint_id
        ));
    }
    Ok(())
}

fn validate_credential_kind(
    endpoint: &ProviderEndpoint,
    credential: &UpstreamCredentialConfig,
) -> Result<()> {
    if credential.secret_ref_id.is_empty() {
        return invalid_catalog(format!(
            "upstream credential {} has empty secret_ref_id",
            credential.upstream_credential_id
        ));
    }
    if credential.credential_kind == "codex_oauth" && endpoint.provider_kind != "codex" {
        return invalid_catalog(format!(
            "upstream credential {} uses codex_oauth outside codex provider",
            credential.upstream_credential_id
        ));
    }
    if credential.credential_kind.ends_with("oauth") && credential.credential_kind != "codex_oauth"
    {
        return invalid_catalog(format!(
            "upstream credential {} uses unsupported generic upstream OAuth",
            credential.upstream_credential_id
        ));
    }
    Ok(())
}

fn validate_endpoints(endpoints: &[ProviderEndpoint]) -> Result<()> {
    for endpoint in endpoints {
        validate_endpoint(endpoint)?;
    }
    Ok(())
}

fn validate_credentials(
    credentials: &[UpstreamCredentialConfig],
    endpoints: &HashMap<&str, &ProviderEndpoint>,
) -> Result<()> {
    for credential in credentials {
        let Some(endpoint) = endpoints.get(credential.provider_endpoint_id.as_str()) else {
            return invalid_catalog(format!(
                "upstream credential {} references missing provider endpoint {}",
                credential.upstream_credential_id, credential.provider_endpoint_id
            ));
        };
        validate_credential_kind(endpoint, credential)?;
    }
    Ok(())
}

fn validate_targets(
    targets: &[ModelTargetConfig],
    endpoints: &HashMap<&str, &ProviderEndpoint>,
    credentials: &HashMap<&str, &UpstreamCredentialConfig>,
) -> Result<()> {
    for target in targets {
        let Some(endpoint) = endpoints.get(target.provider_endpoint_id.as_str()) else {
            return invalid_catalog(format!(
                "model target {} references missing provider endpoint {}",
                target.model_target_id, target.provider_endpoint_id
            ));
        };
        validate_target_endpoint(target, endpoint)?;
        validate_target_credential(target, credentials)?;
    }
    Ok(())
}

fn validate_target_endpoint(target: &ModelTargetConfig, endpoint: &ProviderEndpoint) -> Result<()> {
    if !endpoint.protocol_families.contains(&target.protocol_family) {
        return invalid_catalog(format!(
            "model target {} protocol {} is not supported by provider endpoint {}",
            target.model_target_id,
            target.protocol_family.as_str(),
            endpoint.provider_endpoint_id
        ));
    }
    Ok(())
}

fn validate_target_credential(
    target: &ModelTargetConfig,
    credentials: &HashMap<&str, &UpstreamCredentialConfig>,
) -> Result<()> {
    let Some(credential_id) = target.upstream_credential_id.as_deref() else {
        return Ok(());
    };
    let Some(credential) = credentials.get(credential_id) else {
        return invalid_catalog(format!(
            "model target {} references missing upstream credential {}",
            target.model_target_id, credential_id
        ));
    };
    if credential.provider_endpoint_id != target.provider_endpoint_id {
        return invalid_catalog(format!(
            "model target {} credential {} belongs to another endpoint",
            target.model_target_id, credential_id
        ));
    }
    if !credential.status.is_usable() {
        return invalid_catalog(format!(
            "model target {} references unusable upstream credential {}",
            target.model_target_id, credential_id
        ));
    }
    Ok(())
}

fn validate_policies(
    policies: &[RoutePolicyConfig],
    groups: &HashMap<&str, &RoutingGroupConfig>,
    group_targets: &HashMap<&str, Vec<&RoutingGroupTargetConfig>>,
) -> Result<()> {
    for policy in policies {
        if !groups.contains_key(policy.routing_group_id.as_str()) {
            return invalid_catalog(format!(
                "route policy {} references missing routing group {}",
                policy.route_policy_id, policy.routing_group_id
            ));
        }
        if !group_targets.contains_key(policy.routing_group_id.as_str()) {
            return invalid_catalog(format!(
                "route policy {} references empty routing group {}",
                policy.route_policy_id, policy.routing_group_id
            ));
        }
    }
    Ok(())
}

fn validate_aliases(
    aliases: &[ModelAliasConfig],
    policies: &HashMap<&str, &RoutePolicyConfig>,
    targets: &HashMap<&str, &ModelTargetConfig>,
    group_targets: &HashMap<&str, Vec<&RoutingGroupTargetConfig>>,
) -> Result<()> {
    for alias in aliases {
        let Some(policy) = policies.get(alias.route_policy_id.as_str()) else {
            return invalid_catalog(format!(
                "model alias {} references missing route policy {}",
                alias.model_alias_id, alias.route_policy_id
            ));
        };
        validate_alias_policy(alias, policy)?;
        validate_alias_targets(alias, policy, targets, group_targets)?;
    }
    Ok(())
}

fn validate_alias_policy(alias: &ModelAliasConfig, policy: &RoutePolicyConfig) -> Result<()> {
    if policy.model_alias_id != alias.model_alias_id {
        return invalid_catalog(format!(
            "model alias {} route policy {} points at another alias",
            alias.model_alias_id, policy.route_policy_id
        ));
    }
    Ok(())
}

fn validate_alias_targets(
    alias: &ModelAliasConfig,
    policy: &RoutePolicyConfig,
    targets: &HashMap<&str, &ModelTargetConfig>,
    group_targets: &HashMap<&str, Vec<&RoutingGroupTargetConfig>>,
) -> Result<()> {
    for group_target in group_targets
        .get(policy.routing_group_id.as_str())
        .into_iter()
        .flatten()
    {
        let Some(target) = targets.get(group_target.model_target_id.as_str()) else {
            return invalid_catalog(format!(
                "routing group target {} references missing model target {}",
                group_target.routing_group_target_id, group_target.model_target_id
            ));
        };
        if target.protocol_family != alias.protocol_family {
            return invalid_catalog(format!(
                "model alias {} protocol {} does not match target {} protocol {}",
                alias.model_alias_id,
                alias.protocol_family.as_str(),
                target.model_target_id,
                target.protocol_family.as_str()
            ));
        }
    }
    Ok(())
}

fn validate_provider_grants(
    grants: &[ProviderGrantConfig],
    aliases: &HashMap<&str, &ModelAliasConfig>,
    policies: &HashMap<&str, &RoutePolicyConfig>,
    groups: &HashMap<&str, &RoutingGroupConfig>,
    targets: &HashMap<&str, &ModelTargetConfig>,
    endpoints: &HashMap<&str, &ProviderEndpoint>,
) -> Result<()> {
    for grant in grants {
        if grant.is_spec_shape() {
            validate_spec_provider_grant(grant, aliases, policies, groups, targets, endpoints)?;
        } else {
            validate_legacy_provider_grant(grant, targets, endpoints)?;
        }
    }
    Ok(())
}

fn validate_legacy_provider_grant(
    grant: &ProviderGrantConfig,
    targets: &HashMap<&str, &ModelTargetConfig>,
    endpoints: &HashMap<&str, &ProviderEndpoint>,
) -> Result<()> {
    let Some(endpoint_id) = grant.provider_endpoint_id.as_deref() else {
        return invalid_catalog(format!(
            "provider grant {} missing provider_endpoint_id",
            grant.provider_grant_id
        ));
    };
    if !endpoints.contains_key(endpoint_id) {
        return invalid_catalog(format!(
            "provider grant {} references missing provider endpoint {}",
            grant.provider_grant_id, endpoint_id
        ));
    }
    if let Some(target_id) = grant.model_target_id.as_deref() {
        let Some(target) = targets.get(target_id) else {
            return invalid_catalog(format!(
                "provider grant {} references missing model target {}",
                grant.provider_grant_id, target_id
            ));
        };
        if target.provider_endpoint_id != endpoint_id {
            return invalid_catalog(format!(
                "provider grant {} target {} belongs to another endpoint",
                grant.provider_grant_id, target_id
            ));
        }
    }
    Ok(())
}

fn validate_spec_provider_grant(
    grant: &ProviderGrantConfig,
    aliases: &HashMap<&str, &ModelAliasConfig>,
    policies: &HashMap<&str, &RoutePolicyConfig>,
    groups: &HashMap<&str, &RoutingGroupConfig>,
    targets: &HashMap<&str, &ModelTargetConfig>,
    endpoints: &HashMap<&str, &ProviderEndpoint>,
) -> Result<()> {
    if grant_scope_kind(grant).is_none() || grant_scope_id(grant).is_none() {
        return invalid_catalog(format!(
            "provider grant {} missing scope_kind or scope_id",
            grant.provider_grant_id
        ));
    }
    let Some(resource_kind) = grant.resource_kind else {
        return invalid_catalog(format!(
            "provider grant {} missing resource_kind",
            grant.provider_grant_id
        ));
    };
    let Some(resource_id) = grant.resource_id.as_deref() else {
        return invalid_catalog(format!(
            "provider grant {} missing resource_id",
            grant.provider_grant_id
        ));
    };
    validate_provider_grant_closure_mode(grant)?;
    match resource_kind {
        ProviderGrantResourceKind::ModelAlias if !aliases.contains_key(resource_id) => {
            invalid_catalog(format!(
                "provider grant {} references missing model alias {}",
                grant.provider_grant_id, resource_id
            ))
        }
        ProviderGrantResourceKind::RoutePolicy if !policies.contains_key(resource_id) => {
            invalid_catalog(format!(
                "provider grant {} references missing route policy {}",
                grant.provider_grant_id, resource_id
            ))
        }
        ProviderGrantResourceKind::RoutingGroup if !groups.contains_key(resource_id) => {
            invalid_catalog(format!(
                "provider grant {} references missing routing group {}",
                grant.provider_grant_id, resource_id
            ))
        }
        ProviderGrantResourceKind::ModelTarget if !targets.contains_key(resource_id) => {
            invalid_catalog(format!(
                "provider grant {} references missing model target {}",
                grant.provider_grant_id, resource_id
            ))
        }
        ProviderGrantResourceKind::ProviderEndpoint if !endpoints.contains_key(resource_id) => {
            invalid_catalog(format!(
                "provider grant {} references missing provider endpoint {}",
                grant.provider_grant_id, resource_id
            ))
        }
        _ => Ok(()),
    }
}

fn validate_provider_grant_closure_mode(grant: &ProviderGrantConfig) -> Result<()> {
    if grant.effect == ProviderGrantEffect::Allow
        && grant.closure_mode == ProviderGrantClosureMode::DenyDescendants
    {
        return invalid_catalog(format!(
            "provider grant {} cannot allow with deny_descendants",
            grant.provider_grant_id
        ));
    }
    if grant.effect == ProviderGrantEffect::Deny
        && grant.closure_mode == ProviderGrantClosureMode::IncludeDescendants
    {
        return invalid_catalog(format!(
            "provider grant {} cannot deny with include_descendants",
            grant.provider_grant_id
        ));
    }
    Ok(())
}

fn grant_matches_scope(
    grant: &ProviderGrantConfig,
    actor: &AuthenticatedActor,
    scope_kind: ProviderGrantScopeKind,
    scope_id: &str,
) -> bool {
    let same_tenant = grant.tenant_id == actor.tenant_id;
    let same_scope_kind = grant_scope_kind(grant).is_some_and(|kind| kind == scope_kind);
    let same_scope_id = grant_scope_id(grant).is_some_and(|id| id == scope_id);
    let same_principal =
        optional_match(grant.principal_id.as_deref(), actor.principal_id.as_deref());
    same_tenant && same_scope_kind && same_scope_id && same_principal
}

fn grant_scope_kind(grant: &ProviderGrantConfig) -> Option<ProviderGrantScopeKind> {
    grant.scope_kind.or_else(|| {
        if grant.project_id.is_some() {
            Some(ProviderGrantScopeKind::Project)
        } else if grant.organization_id.is_some() {
            Some(ProviderGrantScopeKind::Organization)
        } else {
            None
        }
    })
}

fn grant_scope_id(grant: &ProviderGrantConfig) -> Option<&str> {
    grant.scope_id.as_deref().or_else(|| {
        grant
            .project_id
            .as_deref()
            .or(grant.organization_id.as_deref())
    })
}

fn grant_applies_to_node(
    grant: &ProviderGrantConfig,
    path: &ProviderGrantPath<'_>,
    node: &ProviderGrantPathNode<'_>,
) -> bool {
    let Some(grant_kind) = grant.resource_kind else {
        return false;
    };
    let Some(grant_resource_id) = grant.resource_id.as_deref() else {
        return false;
    };
    let exact_match = node.kind == grant_kind && node.id == grant_resource_id;
    match grant.closure_mode {
        ProviderGrantClosureMode::SelfOnly => exact_match,
        ProviderGrantClosureMode::IncludeDescendants => {
            grant.effect == ProviderGrantEffect::Allow
                && grant_is_ancestor_or_self(path, grant_kind, grant_resource_id, node)
        }
        ProviderGrantClosureMode::DenyDescendants => {
            grant.effect == ProviderGrantEffect::Deny
                && grant_is_ancestor_or_self(path, grant_kind, grant_resource_id, node)
        }
    }
}

fn grant_is_ancestor_or_self(
    path: &ProviderGrantPath<'_>,
    grant_kind: ProviderGrantResourceKind,
    grant_resource_id: &str,
    node: &ProviderGrantPathNode<'_>,
) -> bool {
    let Some(grant_position) = path.position(grant_kind, grant_resource_id) else {
        return false;
    };
    let Some(node_position) = path.position(node.kind, node.id) else {
        return false;
    };
    grant_position <= node_position
}

fn alias_scope_score(alias: &ModelAliasConfig, actor: &AuthenticatedActor) -> Option<u8> {
    if alias.project_id.as_deref() == actor.project_id.as_deref()
        && alias.organization_id.as_deref() == actor.organization_id.as_deref()
        && alias.project_id.is_some()
    {
        return Some(3);
    }
    if alias.project_id.is_none()
        && alias.organization_id.as_deref() == actor.organization_id.as_deref()
        && alias.organization_id.is_some()
    {
        return Some(2);
    }
    if alias.project_id.is_none() && alias.organization_id.is_none() {
        return Some(1);
    }
    None
}

fn optional_match(expected: Option<&str>, actual: Option<&str>) -> bool {
    expected.is_none_or(|expected| Some(expected) == actual)
}

fn index_endpoints(endpoints: &[ProviderEndpoint]) -> Result<HashMap<&str, &ProviderEndpoint>> {
    let mut index = HashMap::new();
    for endpoint in endpoints {
        if index
            .insert(endpoint.provider_endpoint_id.as_str(), endpoint)
            .is_some()
        {
            return invalid_catalog(format!(
                "duplicate provider endpoint {}",
                endpoint.provider_endpoint_id
            ));
        }
    }
    Ok(index)
}

fn index_credentials(
    credentials: &[UpstreamCredentialConfig],
) -> Result<HashMap<&str, &UpstreamCredentialConfig>> {
    let mut index = HashMap::new();
    for credential in credentials {
        if index
            .insert(credential.upstream_credential_id.as_str(), credential)
            .is_some()
        {
            return invalid_catalog(format!(
                "duplicate upstream credential {}",
                credential.upstream_credential_id
            ));
        }
    }
    Ok(index)
}

fn index_targets(targets: &[ModelTargetConfig]) -> Result<HashMap<&str, &ModelTargetConfig>> {
    let mut index = HashMap::new();
    for target in targets {
        if index
            .insert(target.model_target_id.as_str(), target)
            .is_some()
        {
            return invalid_catalog(format!("duplicate model target {}", target.model_target_id));
        }
    }
    Ok(index)
}

fn index_aliases(aliases: &[ModelAliasConfig]) -> Result<HashMap<&str, &ModelAliasConfig>> {
    let mut index = HashMap::new();
    for alias in aliases {
        if index.insert(alias.model_alias_id.as_str(), alias).is_some() {
            return invalid_catalog(format!("duplicate model alias {}", alias.model_alias_id));
        }
    }
    Ok(index)
}

fn index_groups(groups: &[RoutingGroupConfig]) -> Result<HashMap<&str, &RoutingGroupConfig>> {
    let mut index = HashMap::new();
    for group in groups {
        if index
            .insert(group.routing_group_id.as_str(), group)
            .is_some()
        {
            return invalid_catalog(format!(
                "duplicate routing group {}",
                group.routing_group_id
            ));
        }
    }
    Ok(index)
}

fn index_policies(policies: &[RoutePolicyConfig]) -> Result<HashMap<&str, &RoutePolicyConfig>> {
    let mut index = HashMap::new();
    for policy in policies {
        if index
            .insert(policy.route_policy_id.as_str(), policy)
            .is_some()
        {
            return invalid_catalog(format!("duplicate route policy {}", policy.route_policy_id));
        }
    }
    Ok(index)
}

fn group_targets_by_group(
    group_targets: &[RoutingGroupTargetConfig],
) -> HashMap<&str, Vec<&RoutingGroupTargetConfig>> {
    let mut index: HashMap<&str, Vec<&RoutingGroupTargetConfig>> = HashMap::new();
    for group_target in group_targets {
        index
            .entry(group_target.routing_group_id.as_str())
            .or_default()
            .push(group_target);
    }
    index
}

const fn invalid_catalog<T>(message: String) -> Result<T> {
    Err(GatewayError::BadRequest { message })
}

const fn default_true() -> bool {
    true
}

const fn default_provider_grant_effect() -> ProviderGrantEffect {
    ProviderGrantEffect::Allow
}

const fn default_provider_grant_closure_mode() -> ProviderGrantClosureMode {
    ProviderGrantClosureMode::SelfOnly
}

impl ResourceStatus {
    /// Returns whether the resource is active.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::catalog::GatewayCatalogSnapshot;
    use crate::domain::{ActorKind, AuthenticatedActor, CredentialKind};
    use crate::ProtocolFamily;

    fn actor() -> AuthenticatedActor {
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
        }
    }

    fn catalog_payload() -> Value {
        json!({
            "provider_endpoints": [{
                "provider_endpoint_id": "pep_openai",
                "tenant_id": "ten_test",
                "name": "OpenAI",
                "provider_kind": "openai",
                "protocol_families": ["openai_responses", "openai_chat"],
                "upstream_base_url": "https://api.openai.example",
                "status": "active"
            }],
            "upstream_credentials": [{
                "upstream_credential_id": "upc_openai",
                "tenant_id": "ten_test",
                "provider_endpoint_id": "pep_openai",
                "credential_kind": "api_key",
                "secret_ref_id": "sec_openai",
                "status": "active"
            }],
            "model_targets": [{
                "model_target_id": "mt_openai",
                "tenant_id": "ten_test",
                "provider_endpoint_id": "pep_openai",
                "upstream_credential_id": "upc_openai",
                "protocol_family": "openai_responses",
                "upstream_model_id": "gpt-4.1-mini",
                "status": "active",
                "supports_streaming": true
            }],
            "model_aliases": [{
                "model_alias_id": "ma_test",
                "tenant_id": "ten_test",
                "organization_id": "org_test",
                "project_id": "prj_test",
                "alias_name": "gpt-test",
                "protocol_family": "openai_responses",
                "route_policy_id": "rp_test",
                "status": "active"
            }],
            "routing_groups": [{
                "routing_group_id": "rg_test",
                "tenant_id": "ten_test",
                "status": "active"
            }],
            "routing_group_targets": [{
                "routing_group_target_id": "rgt_test",
                "routing_group_id": "rg_test",
                "model_target_id": "mt_openai",
                "weight": 1,
                "priority": 10,
                "status": "active"
            }],
            "route_policies": [{
                "route_policy_id": "rp_test",
                "tenant_id": "ten_test",
                "model_alias_id": "ma_test",
                "routing_group_id": "rg_test",
                "status": "active"
            }],
            "provider_grants": [{
                "provider_grant_id": "pg_test",
                "tenant_id": "ten_test",
                "organization_id": "org_test",
                "project_id": "prj_test",
                "principal_id": "usr_test",
                "provider_endpoint_id": "pep_openai",
                "model_target_id": "mt_openai",
                "status": "active"
            }]
        })
    }

    fn catalog_with_spec_provider_grants(grants: Value) -> GatewayCatalogSnapshot {
        let mut payload = catalog_payload();
        payload["provider_grants"] = grants;
        match GatewayCatalogSnapshot::from_payload(&payload) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => panic!("catalog should be present"),
            Err(error) => panic!("catalog should parse: {error}"),
        }
    }

    fn select_test_route(catalog: &GatewayCatalogSnapshot) -> crate::error::Result<()> {
        catalog
            .select_runtime_route(&actor(), ProtocolFamily::OpenAiResponses, "gpt-test", false)
            .map(|_| ())
    }

    fn org_alias_allow_grant() -> Value {
        json!({
            "provider_grant_id": "pg_org_alias",
            "tenant_id": "ten_test",
            "scope_kind": "organization",
            "scope_id": "org_test",
            "resource_kind": "model_alias",
            "resource_id": "ma_test",
            "effect": "allow",
            "closure_mode": "include_descendants",
            "status": "active"
        })
    }

    #[test]
    fn payload_without_catalog_is_ignored() {
        let parsed = match GatewayCatalogSnapshot::from_payload(&json!({"resources": []})) {
            Ok(parsed) => parsed,
            Err(error) => panic!("payload without catalog should parse: {error}"),
        };
        assert!(parsed.is_none());
    }

    #[test]
    fn catalog_selects_project_scoped_alias_target_and_endpoint() {
        let catalog = match GatewayCatalogSnapshot::from_payload(&catalog_payload()) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => panic!("catalog should be present"),
            Err(error) => panic!("catalog should parse: {error}"),
        };
        let selection = match catalog.select_runtime_route(
            &actor(),
            ProtocolFamily::OpenAiResponses,
            "gpt-test",
            false,
        ) {
            Ok(selection) => selection,
            Err(error) => panic!("route should select: {error}"),
        };

        assert_eq!(selection.model_alias_id, "ma_test");
        assert_eq!(selection.model_target_id, "mt_openai");
        assert_eq!(selection.upstream_model_id, "gpt-4.1-mini");
        assert_eq!(
            selection.provider_endpoint.provider_endpoint_id,
            "pep_openai"
        );
        assert_eq!(
            selection.upstream_credential_id.as_deref(),
            Some("upc_openai")
        );
    }

    #[test]
    fn catalog_rejects_protocol_mismatch_before_route_selection() {
        let catalog = match GatewayCatalogSnapshot::from_payload(&catalog_payload()) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => panic!("catalog should be present"),
            Err(error) => panic!("catalog should parse: {error}"),
        };
        let Err(error) = catalog.select_runtime_route(
            &actor(),
            ProtocolFamily::AnthropicMessages,
            "gpt-test",
            false,
        ) else {
            panic!("protocol mismatch should fail");
        };

        assert_eq!(error.code(), "gateway.request.invalid");
    }

    #[test]
    fn catalog_rejects_unusable_credential_reference() {
        let mut payload = catalog_payload();
        payload["upstream_credentials"][0]["status"] = json!("disabled");

        let Err(error) = GatewayCatalogSnapshot::from_payload(&payload) else {
            panic!("disabled credential reference should fail validation");
        };

        assert_eq!(error.code(), "gateway.request.invalid");
        assert!(error.to_string().contains("unusable upstream credential"));
    }

    #[test]
    fn catalog_rejects_endpoint_protocol_mismatch() {
        let mut payload = catalog_payload();
        payload["provider_endpoints"][0]["protocol_families"] = json!(["openai_chat"]);

        let Err(error) = GatewayCatalogSnapshot::from_payload(&payload) else {
            panic!("endpoint protocol mismatch should fail validation");
        };

        assert_eq!(error.code(), "gateway.request.invalid");
        assert!(error.to_string().contains("is not supported"));
    }

    #[test]
    fn catalog_denies_missing_provider_grant() {
        let mut payload = catalog_payload();
        payload["provider_grants"] = json!([]);
        let catalog = match GatewayCatalogSnapshot::from_payload(&payload) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => panic!("catalog should be present"),
            Err(error) => panic!("catalog should parse: {error}"),
        };
        let Err(error) = catalog.select_runtime_route(
            &actor(),
            ProtocolFamily::OpenAiResponses,
            "gpt-test",
            false,
        ) else {
            panic!("missing provider grant should fail");
        };

        assert_eq!(error.code(), "gateway.auth.authorization_denied");
    }

    #[test]
    fn catalog_allows_org_alias_grant_with_descendant_closure() {
        let catalog = catalog_with_spec_provider_grants(json!([org_alias_allow_grant()]));

        if let Err(error) = select_test_route(&catalog) {
            panic!("org alias closure grant should select route: {error}");
        }
    }

    #[test]
    fn catalog_provider_grant_deny_has_precedence_over_org_allow() {
        let catalog = catalog_with_spec_provider_grants(json!([
            org_alias_allow_grant(),
            {
                "provider_grant_id": "pg_project_deny_group",
                "tenant_id": "ten_test",
                "scope_kind": "project",
                "scope_id": "prj_test",
                "resource_kind": "routing_group",
                "resource_id": "rg_test",
                "effect": "deny",
                "closure_mode": "deny_descendants",
                "status": "active"
            }
        ]));

        let Err(error) = select_test_route(&catalog) else {
            panic!("project deny closure should block route");
        };

        assert_eq!(error.code(), "gateway.auth.authorization_denied");
    }

    #[test]
    fn catalog_project_provider_endpoint_allowlist_narrows_org_grant() {
        let mut payload = catalog_payload();
        payload["provider_endpoints"]
            .as_array_mut()
            .unwrap_or_else(|| panic!("provider_endpoints should be an array"))
            .push(json!({
                "provider_endpoint_id": "pep_other",
                "tenant_id": "ten_test",
                "name": "Other",
                "provider_kind": "openai",
                "protocol_families": ["openai_responses"],
                "upstream_base_url": "https://other.example",
                "status": "active"
            }));
        payload["provider_grants"] = json!([
            org_alias_allow_grant(),
            {
                "provider_grant_id": "pg_project_endpoint_other",
                "tenant_id": "ten_test",
                "scope_kind": "project",
                "scope_id": "prj_test",
                "resource_kind": "provider_endpoint",
                "resource_id": "pep_other",
                "effect": "allow",
                "closure_mode": "self_only",
                "status": "active"
            }
        ]);
        let catalog = match GatewayCatalogSnapshot::from_payload(&payload) {
            Ok(Some(catalog)) => catalog,
            Ok(None) => panic!("catalog should be present"),
            Err(error) => panic!("catalog should parse: {error}"),
        };

        let Err(error) = select_test_route(&catalog) else {
            panic!("project endpoint allowlist should block unlisted endpoint");
        };

        assert_eq!(error.code(), "gateway.auth.authorization_denied");
    }

    #[test]
    fn catalog_rejects_invalid_spec_provider_grant_reference() {
        let mut payload = catalog_payload();
        payload["provider_grants"] = json!([{
            "provider_grant_id": "pg_missing_alias",
            "tenant_id": "ten_test",
            "scope_kind": "organization",
            "scope_id": "org_test",
            "resource_kind": "model_alias",
            "resource_id": "ma_missing",
            "effect": "allow",
            "closure_mode": "include_descendants",
            "status": "active"
        }]);

        let Err(error) = GatewayCatalogSnapshot::from_payload(&payload) else {
            panic!("missing grant resource should fail validation");
        };

        assert!(error.to_string().contains("references missing model alias"));
    }
}
