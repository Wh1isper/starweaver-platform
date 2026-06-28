//! Shared test fixtures for the gateway foundation.

use secrecy::ExposeSecret;

use crate::action::ActionGrant;
use crate::auth::{CreateApiKeyRequest, create_api_key};
use crate::replay::foundation_route_replay_cases;
use crate::route::foundation_routes;
use crate::storage::{
    BootstrapDefaultProjectRequest, InMemoryGatewayStore, TenancyBootstrapRepository,
};

/// Test tenant id used by foundation fixtures.
pub const TEST_TENANT_ID: &str = "ten_test";
/// Test organization id used by foundation fixtures.
pub const TEST_ORGANIZATION_ID: &str = "org_test";
/// Test project id used by foundation fixtures.
pub const TEST_PROJECT_ID: &str = "prj_test";
/// Test user principal id used by foundation fixtures.
pub const TEST_USER_ID: &str = "usr_test";
/// Test organization membership id used by foundation fixtures.
pub const TEST_ORGANIZATION_MEMBER_ID: &str = "om_test";

/// Seeded gateway foundation state for runtime and authorization tests.
#[derive(Clone, Debug)]
pub struct FoundationTestFixture {
    /// In-memory store seeded with project membership, API key, and optional grants.
    pub store: InMemoryGatewayStore,
    /// One-time raw API key value for the seeded API key.
    pub raw_api_key: String,
}

impl FoundationTestFixture {
    /// Creates a project-scoped API-key fixture for model runtime tests.
    pub fn runtime_access(include_grants: bool) -> Self {
        let store = InMemoryGatewayStore::default();
        let now = chrono::Utc::now();
        match store.bootstrap_default_project(bootstrap_request(), now) {
            Ok(_) => {}
            Err(error) => panic!("foundation tenancy seed should bootstrap: {error}"),
        }
        let created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: TEST_TENANT_ID.to_owned(),
                organization_id: Some(TEST_ORGANIZATION_ID.to_owned()),
                project_id: Some(TEST_PROJECT_ID.to_owned()),
                owner_principal_id: TEST_USER_ID.to_owned(),
                name: "runtime test key".to_owned(),
                created_by: TEST_USER_ID.to_owned(),
                expires_at: None,
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should create: {error}"),
        };
        let raw_api_key = created.raw_key.expose_secret().to_owned();
        store.insert_api_key(created.record);

        if include_grants {
            seed_foundation_route_grants(&store);
        }

        Self { store, raw_api_key }
    }
}

/// Returns a reusable request for the default project graph.
pub fn bootstrap_request() -> BootstrapDefaultProjectRequest {
    BootstrapDefaultProjectRequest {
        tenant_id: TEST_TENANT_ID.to_owned(),
        tenant_display_name: "Test Tenant".to_owned(),
        organization_id: TEST_ORGANIZATION_ID.to_owned(),
        organization_display_name: "Test Organization".to_owned(),
        project_id: TEST_PROJECT_ID.to_owned(),
        project_display_name: "Test Project".to_owned(),
        user_id: TEST_USER_ID.to_owned(),
        user_display_name: "Test User".to_owned(),
        user_primary_email: Some("user@example.com".to_owned()),
        organization_member_id: TEST_ORGANIZATION_MEMBER_ID.to_owned(),
        project_member_id: "pm_test".to_owned(),
        created_by: TEST_USER_ID.to_owned(),
    }
}

fn seed_foundation_route_grants(store: &InMemoryGatewayStore) {
    for case in foundation_route_replay_cases() {
        let route = foundation_routes()
            .iter()
            .find(|route| {
                route.protocol_family == Some(case.protocol_family) && route.action == case.action
            })
            .unwrap_or_else(|| panic!("case {} should have route metadata", case.name));
        store.insert_action_grant(ActionGrant::project(
            TEST_TENANT_ID,
            TEST_ORGANIZATION_ID,
            TEST_PROJECT_ID,
            TEST_USER_ID,
            case.action,
            route.resource("ma_test"),
        ));
    }
}

#[cfg(test)]
mod tests {
    use crate::fixtures::FoundationTestFixture;
    use crate::storage::{ApiKeyRepository, TenancyRepository};

    #[test]
    fn foundation_fixture_seeds_project_api_key_and_grants() {
        let fixture = FoundationTestFixture::runtime_access(true);
        let prefix = &fixture.raw_api_key[..16];

        assert_eq!(fixture.store.candidates_by_prefix(prefix).len(), 1);
        assert!(
            fixture
                .store
                .project_membership("usr_test", "prj_test")
                .is_some()
        );
        assert!(!fixture.store.action_grants().is_empty());
    }
}
