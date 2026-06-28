//! Cross-service auth/authz contract tests for the Stage 13 layering gate.

use std::collections::BTreeSet;

use starweaver_gateway::action::{
    ActionGrant as GatewayActionGrant, AuthorizationEngine as GatewayAuthorizationEngine,
    AuthorizationRequest as GatewayAuthorizationRequest, BuiltInRole as GatewayBuiltInRole,
    FoundationAuthorizationEngine as GatewayAuthorization, GatewayAction,
    ResourceRef as GatewayResourceRef, RoleScopeKind as GatewayRoleScopeKind,
};
use starweaver_gateway::domain::{
    ActorKind as GatewayActorKind, AuthenticatedActor as GatewayActor,
    CredentialKind as GatewayCredentialKind,
};
use starweaver_platform::action::{
    ActionGrant as PlatformActionGrant, AuthenticatedActor as PlatformActor,
    AuthorizationEngine as PlatformAuthorizationEngine,
    AuthorizationRequest as PlatformAuthorizationRequest, BuiltInRole as PlatformBuiltInRole,
    FoundationAuthorizationEngine as PlatformAuthorization, PlatformAction,
    ResourceRef as PlatformResourceRef, RoleScopeKind as PlatformRoleScopeKind,
};

const TENANT_ID: &str = "ten_contract";
const ORGANIZATION_ID: &str = "org_contract";
const PROJECT_ID: &str = "prj_contract";
const USER_ID: &str = "usr_contract";
const SERVICE_ACCOUNT_ID: &str = "svc_contract";

#[test]
fn action_namespaces_remain_service_local() {
    let gateway_action_ids = GatewayAction::canonical_definitions()
        .iter()
        .map(|definition| definition.action_id)
        .collect::<BTreeSet<_>>();
    let platform_action_ids = PlatformAction::canonical_definitions()
        .iter()
        .map(|definition| definition.action_id)
        .collect::<BTreeSet<_>>();

    assert!(gateway_action_ids.is_disjoint(&platform_action_ids));
    for action_id in &gateway_action_ids {
        assert!(action_id.starts_with("gateway."));
        assert!(PlatformAction::from_action_id(action_id).is_none());
    }
    for action_id in &platform_action_ids {
        assert!(action_id.starts_with("platform."));
        assert!(GatewayAction::from_action_id(action_id).is_none());
    }
}

#[test]
fn shared_scope_contract_keeps_service_specific_actors_compatible() {
    let gateway_actor = gateway_project_api_key_actor();
    let platform_actor =
        PlatformActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID);

    assert_eq!(
        GatewayRoleScopeKind::Tenant.as_str(),
        PlatformRoleScopeKind::Tenant.as_str()
    );
    assert_eq!(
        GatewayRoleScopeKind::Organization.as_str(),
        PlatformRoleScopeKind::Organization.as_str()
    );
    assert_eq!(
        GatewayRoleScopeKind::Project.as_str(),
        PlatformRoleScopeKind::Project.as_str()
    );
    assert_eq!(
        GatewayRoleScopeKind::Any.as_str(),
        PlatformRoleScopeKind::Any.as_str()
    );

    assert_eq!(gateway_actor.tenant_id, platform_actor.tenant_id);
    assert_eq!(
        gateway_actor.organization_id.as_deref(),
        platform_actor.organization_id.as_deref()
    );
    assert_eq!(
        gateway_actor.project_id.as_deref(),
        platform_actor.project_id.as_deref()
    );
    assert_eq!(
        gateway_actor.principal_id.as_deref(),
        Some(platform_actor.principal_id.as_str())
    );
}

#[test]
fn credential_specific_strong_auth_and_user_actor_gates_do_not_widen() {
    let platform_actor = PlatformActor::project_service_account(
        TENANT_ID,
        ORGANIZATION_ID,
        PROJECT_ID,
        SERVICE_ACCOUNT_ID,
    );
    let platform_engine = PlatformAuthorization::new(PlatformActionGrant::for_builtin_role(
        TENANT_ID,
        TENANT_ID,
        SERVICE_ACCOUNT_ID,
        PlatformBuiltInRole::TenantOwner,
    ));
    let platform_decision = platform_engine.authorize(&PlatformAuthorizationRequest {
        actor: platform_actor,
        action: PlatformAction::ApprovalDecide,
        resource: PlatformResourceRef::project(
            "Approval",
            TENANT_ID,
            ORGANIZATION_ID,
            PROJECT_ID,
            "appr_contract",
        ),
    });
    assert!(!platform_decision.allowed);
    assert_eq!(platform_decision.reason, "user_actor_required");

    let gateway_engine = GatewayAuthorization::new(vec![GatewayActionGrant::project(
        TENANT_ID,
        ORGANIZATION_ID,
        PROJECT_ID,
        USER_ID,
        GatewayAction::ConfigPublish,
        GatewayResourceRef {
            kind: "ConfigSnapshot".to_owned(),
            id: "cfg_contract".to_owned(),
        },
    )]);
    let gateway_decision = gateway_engine.authorize(&GatewayAuthorizationRequest {
        actor: gateway_project_api_key_actor(),
        action: GatewayAction::ConfigPublish,
        resource: GatewayResourceRef {
            kind: "ConfigSnapshot".to_owned(),
            id: "cfg_contract".to_owned(),
        },
    });
    assert!(!gateway_decision.allowed);
    assert_eq!(gateway_decision.reason, "api_key_strong_auth_required");
}

#[test]
fn resource_kind_compatibility_is_enforced_in_both_services() {
    let platform_engine = PlatformAuthorization::new(PlatformActionGrant::for_builtin_role(
        TENANT_ID,
        PROJECT_ID,
        USER_ID,
        PlatformBuiltInRole::ProjectViewer,
    ));
    let platform_decision = platform_engine.authorize(&PlatformAuthorizationRequest {
        actor: PlatformActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID),
        action: PlatformAction::RunRead,
        resource: PlatformResourceRef::project(
            "ModelAlias",
            TENANT_ID,
            ORGANIZATION_ID,
            PROJECT_ID,
            "ma_contract",
        ),
    });
    assert!(!platform_decision.allowed);
    assert_eq!(platform_decision.reason, "resource_kind_mismatch");

    let gateway_engine = GatewayAuthorization::new(vec![GatewayActionGrant::project(
        TENANT_ID,
        ORGANIZATION_ID,
        PROJECT_ID,
        USER_ID,
        GatewayAction::ModelInvoke,
        GatewayResourceRef::model_alias("ma_contract"),
    )]);
    let gateway_decision = gateway_engine.authorize(&GatewayAuthorizationRequest {
        actor: gateway_project_api_key_actor(),
        action: GatewayAction::ModelInvoke,
        resource: GatewayResourceRef {
            kind: "Run".to_owned(),
            id: "run_contract".to_owned(),
        },
    });
    assert!(!gateway_decision.allowed);
    assert_eq!(gateway_decision.reason, "principal_action_not_granted");
}

#[test]
fn built_in_roles_expand_to_service_namespaced_actions_only() {
    for action in GatewayBuiltInRole::TenantOwner.actions() {
        assert!(action.as_str().starts_with("gateway."));
        assert!(PlatformAction::from_action_id(action.as_str()).is_none());
    }
    for action in PlatformBuiltInRole::TenantOwner.actions() {
        assert!(action.as_str().starts_with("platform."));
        assert!(GatewayAction::from_action_id(action.as_str()).is_none());
    }
}

fn gateway_project_api_key_actor() -> GatewayActor {
    GatewayActor {
        actor_id: "ak_contract".to_owned(),
        actor_kind: GatewayActorKind::ApiKey,
        tenant_id: TENANT_ID.to_owned(),
        organization_id: Some(ORGANIZATION_ID.to_owned()),
        project_id: Some(PROJECT_ID.to_owned()),
        principal_id: Some(USER_ID.to_owned()),
        api_key_id: Some("ak_contract".to_owned()),
        credential_kind: GatewayCredentialKind::ApiKey,
        auth_strength: 50,
        expires_at: None,
        api_key_allowed_actions: Vec::new(),
        api_key_allowed_resources: Vec::new(),
        request_id: "req_contract".to_owned(),
        trace_id: "tr_contract".to_owned(),
    }
}
