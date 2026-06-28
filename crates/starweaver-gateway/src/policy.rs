//! Cedar policy schema and validation boundary.

use std::collections::{BTreeSet, HashSet};
use std::fmt::Write as _;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request as CedarRequest, Schema, ValidationMode, Validator,
};

use crate::action::{
    gateway_preflight_decision, AuthorizationDecision, AuthorizationEngine, AuthorizationRequest,
    GatewayAction,
};
use crate::domain::ActorKind;
use crate::error::{GatewayError, Result};

/// Cedar namespace for gateway policies.
pub const CEDAR_NAMESPACE: &str = "Gateway";

const CEDAR_PRINCIPAL_TYPES: &[&str] = &[
    "User",
    "ServiceAccount",
    "ApiKey",
    "InternalService",
    "System",
];

/// Policy validation summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyValidationReport {
    /// Number of validation warnings produced by Cedar.
    pub warning_count: usize,
}

/// Cedar-backed authorization engine for validated gateway policy bundles.
#[derive(Debug)]
pub struct CedarAuthorizationEngine {
    policy_set: PolicySet,
    schema: Schema,
    authorizer: Authorizer,
}

impl CedarAuthorizationEngine {
    /// Builds a Cedar authorization engine from a validated policy bundle.
    pub fn from_policy_source(policy_source: &str) -> Result<Self> {
        let schema = parse_canonical_schema()?;
        let policy_set = parse_policy_set(policy_source)?;
        validate_policy_set(schema.clone(), &policy_set)?;
        Ok(Self {
            policy_set,
            schema,
            authorizer: Authorizer::new(),
        })
    }
}

impl AuthorizationEngine for CedarAuthorizationEngine {
    fn authorize(&self, request: &AuthorizationRequest) -> AuthorizationDecision {
        if let Some(decision) = gateway_preflight_decision(request) {
            return decision;
        }
        let Ok(cedar_request) = cedar_request(request, &self.schema) else {
            return AuthorizationDecision::deny("cedar_request_invalid");
        };
        let Ok(entities) = cedar_entities(request, &self.schema) else {
            return AuthorizationDecision::deny("cedar_entities_invalid");
        };
        let response = self
            .authorizer
            .is_authorized(&cedar_request, &self.policy_set, &entities);
        if response.diagnostics().errors().next().is_some() {
            return AuthorizationDecision::deny("cedar_policy_error");
        }
        match response.decision() {
            Decision::Allow => AuthorizationDecision::allow(),
            Decision::Deny => AuthorizationDecision::deny("cedar_policy_denied"),
        }
    }
}

/// Returns the canonical Cedar schema source derived from the action registry.
#[must_use]
pub fn canonical_cedar_schema_source() -> String {
    let mut source = String::from("namespace Gateway {\n");
    for principal_type in CEDAR_PRINCIPAL_TYPES {
        writeln!(source, "  entity {principal_type};")
            .unwrap_or_else(|error| unreachable!("writing String should not fail: {error}"));
    }
    for resource_kind in canonical_resource_kinds() {
        writeln!(source, "  entity {resource_kind};")
            .unwrap_or_else(|error| unreachable!("writing String should not fail: {error}"));
    }
    let principal_list = CEDAR_PRINCIPAL_TYPES.join(", ");
    for definition in GatewayAction::canonical_definitions() {
        writeln!(
            source,
            "  action \"{}\" appliesTo {{ principal: [{}], resource: [{}], context: {{}} }};",
            definition.action_id, principal_list, definition.resource_kind
        )
        .unwrap_or_else(|error| unreachable!("writing String should not fail: {error}"));
    }
    source.push_str("}\n");
    source
}

/// Validates a Cedar policy bundle against the canonical gateway schema.
pub fn validate_cedar_policy_bundle(policy_source: &str) -> Result<PolicyValidationReport> {
    let schema = parse_canonical_schema()?;
    let policy_set = parse_policy_set(policy_source)?;
    validate_policy_set(schema, &policy_set)
}

fn validate_policy_set(schema: Schema, policy_set: &PolicySet) -> Result<PolicyValidationReport> {
    let validation = Validator::new(schema).validate(policy_set, ValidationMode::Strict);
    if !validation.validation_passed() {
        let errors = validation
            .validation_errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ");
        return Err(GatewayError::BadRequest {
            message: format!("cedar policy bundle validation failed: {errors}"),
        });
    }
    Ok(PolicyValidationReport {
        warning_count: validation.validation_warnings().count(),
    })
}

fn parse_policy_set(policy_source: &str) -> Result<PolicySet> {
    PolicySet::from_str(policy_source).map_err(|error| GatewayError::BadRequest {
        message: format!("cedar policy bundle parse failed: {error}"),
    })
}

fn parse_canonical_schema() -> Result<Schema> {
    Schema::from_cedarschema_str(&canonical_cedar_schema_source())
        .map(|(schema, _warnings)| schema)
        .map_err(|error| GatewayError::Internal {
            message: format!("canonical cedar schema is invalid: {error}"),
        })
}

fn canonical_resource_kinds() -> BTreeSet<&'static str> {
    GatewayAction::canonical_definitions()
        .iter()
        .map(|definition| definition.resource_kind)
        .filter(|resource_kind| !CEDAR_PRINCIPAL_TYPES.contains(resource_kind))
        .collect()
}

fn cedar_request(request: &AuthorizationRequest, schema: &Schema) -> Result<CedarRequest> {
    CedarRequest::new(
        cedar_entity_uid(
            cedar_actor_type(&request.actor.actor_kind),
            &request.actor.actor_id,
        )?,
        cedar_entity_uid("Action", request.action.as_str())?,
        cedar_entity_uid(&request.resource.kind, &request.resource.id)?,
        Context::empty(),
        Some(schema),
    )
    .map_err(|error| GatewayError::Internal {
        message: format!("cedar request build failed: {error}"),
    })
}

fn cedar_entities(request: &AuthorizationRequest, schema: &Schema) -> Result<Entities> {
    let principal_uid = cedar_entity_uid(
        cedar_actor_type(&request.actor.actor_kind),
        &request.actor.actor_id,
    )?;
    let resource_uid = cedar_entity_uid(&request.resource.kind, &request.resource.id)?;
    let mut seen = HashSet::new();
    let mut entities = Vec::new();
    for uid in [principal_uid, resource_uid] {
        if seen.insert(uid.clone()) {
            entities.push(Entity::with_uid(uid));
        }
    }
    Entities::from_entities(entities, Some(schema)).map_err(|error| GatewayError::Internal {
        message: format!("cedar entities build failed: {error}"),
    })
}

fn cedar_entity_uid(entity_type: &str, entity_id: &str) -> Result<EntityUid> {
    let type_name = EntityTypeName::from_str(&format!("{CEDAR_NAMESPACE}::{entity_type}"))
        .map_err(|error| GatewayError::Internal {
            message: format!("cedar entity type is invalid: {error}"),
        })?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(entity_id),
    ))
}

const fn cedar_actor_type(actor_kind: &ActorKind) -> &'static str {
    match actor_kind {
        ActorKind::User => "User",
        ActorKind::ServiceAccount => "ServiceAccount",
        ActorKind::ApiKey => "ApiKey",
        ActorKind::InternalService => "InternalService",
        ActorKind::System => "System",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_cedar_schema_source, validate_cedar_policy_bundle, CedarAuthorizationEngine,
        CEDAR_NAMESPACE,
    };
    use crate::action::{AuthorizationEngine, AuthorizationRequest, GatewayAction, ResourceRef};
    use crate::domain::{ActorKind, AuthenticatedActor, CredentialKind};

    #[test]
    fn canonical_cedar_schema_parses_and_declares_every_action() {
        let source = canonical_cedar_schema_source();

        validate_cedar_policy_bundle(valid_model_policy())
            .unwrap_or_else(|error| panic!("valid model policy should pass: {error}"));
        assert!(source.contains(&format!("namespace {CEDAR_NAMESPACE}")));
        for definition in GatewayAction::canonical_definitions() {
            assert!(
                source.contains(&format!("action \"{}\"", definition.action_id)),
                "missing action {}",
                definition.action_id
            );
            assert!(
                source.contains(&format!("resource: [{}]", definition.resource_kind)),
                "missing resource kind {}",
                definition.resource_kind
            );
        }
    }

    #[test]
    fn cedar_policy_validation_rejects_unknown_action() {
        let Err(error) = validate_cedar_policy_bundle(
            r#"
            permit (
                principal is Gateway::ApiKey,
                action == Gateway::Action::"gateway.unknown",
                resource is Gateway::ModelAlias
            );
            "#,
        ) else {
            panic!("unknown action should fail validation");
        };

        assert!(error
            .to_string()
            .contains("cedar policy bundle validation failed"));
    }

    #[test]
    fn cedar_policy_validation_rejects_action_resource_mismatch() {
        let Err(error) = validate_cedar_policy_bundle(
            r#"
            permit (
                principal is Gateway::ApiKey,
                action == Gateway::Action::"gateway.model.invoke",
                resource is Gateway::ProviderEndpoint
            );
            "#,
        ) else {
            panic!("action/resource mismatch should fail validation");
        };

        assert!(error
            .to_string()
            .contains("cedar policy bundle validation failed"));
    }

    #[test]
    fn cedar_policy_validation_accepts_canonical_model_policy() {
        let report = validate_cedar_policy_bundle(valid_model_policy())
            .unwrap_or_else(|error| panic!("valid model policy should pass: {error}"));

        assert_eq!(report.warning_count, 0);
    }

    #[test]
    fn cedar_authorization_engine_allows_matching_policy() {
        let engine = CedarAuthorizationEngine::from_policy_source(valid_model_policy())
            .unwrap_or_else(|error| panic!("valid model policy should build: {error}"));

        let decision = engine.authorize(&model_request("ma_allowed"));

        assert!(decision.allowed);
        assert_eq!(decision.reason, "allowed");
    }

    #[test]
    fn cedar_authorization_engine_denies_without_matching_policy() {
        let engine = CedarAuthorizationEngine::from_policy_source(resource_specific_model_policy())
            .unwrap_or_else(|error| panic!("resource-specific model policy should build: {error}"));

        let decision = engine.authorize(&model_request("ma_denied"));

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "cedar_policy_denied");
    }

    #[test]
    fn cedar_authorization_engine_rejects_action_resource_mismatch() {
        let engine = CedarAuthorizationEngine::from_policy_source(valid_model_policy())
            .unwrap_or_else(|error| panic!("valid model policy should build: {error}"));
        let mut request = model_request("provider_endpoint");
        request.resource = ResourceRef {
            kind: "ProviderEndpoint".to_owned(),
            id: "provider_endpoint".to_owned(),
        };

        let decision = engine.authorize(&request);

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "cedar_request_invalid");
    }

    #[test]
    fn cedar_authorization_engine_applies_api_key_prefilters() {
        let engine = CedarAuthorizationEngine::from_policy_source(valid_model_policy())
            .unwrap_or_else(|error| panic!("valid model policy should build: {error}"));
        let mut request = model_request("ma_denied");
        request.actor.api_key_allowed_resources = vec!["ModelAlias:ma_allowed".to_owned()];

        let decision = engine.authorize(&request);

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "api_key_resource_not_granted");
    }

    fn valid_model_policy() -> &'static str {
        r#"
        permit (
            principal is Gateway::ApiKey,
            action == Gateway::Action::"gateway.model.invoke",
            resource is Gateway::ModelAlias
        );
        "#
    }

    fn resource_specific_model_policy() -> &'static str {
        r#"
        permit (
            principal is Gateway::ApiKey,
            action == Gateway::Action::"gateway.model.invoke",
            resource == Gateway::ModelAlias::"ma_allowed"
        );
        "#
    }

    fn model_request(resource_id: &str) -> AuthorizationRequest {
        AuthorizationRequest {
            actor: api_key_actor(),
            action: GatewayAction::ModelInvoke,
            resource: ResourceRef::model_alias(resource_id),
        }
    }

    fn api_key_actor() -> AuthenticatedActor {
        AuthenticatedActor {
            actor_id: "ak_test".to_owned(),
            actor_kind: ActorKind::ApiKey,
            tenant_id: "tenant_test".to_owned(),
            organization_id: Some("org_test".to_owned()),
            project_id: Some("proj_test".to_owned()),
            principal_id: Some("user_test".to_owned()),
            api_key_id: Some("ak_test".to_owned()),
            credential_kind: CredentialKind::ApiKey,
            auth_strength: 50,
            expires_at: None,
            api_key_allowed_actions: Vec::new(),
            api_key_allowed_resources: Vec::new(),
            request_id: "req_test".to_owned(),
        }
    }
}
