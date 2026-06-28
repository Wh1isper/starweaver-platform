//! Platform-local storage ownership boundaries.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::action::ResourceRef;

/// Result type used by platform storage boundaries.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Storage boundary error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StoreError {
    /// Resource kind is empty.
    EmptyResourceKind,
    /// Resource id is empty.
    EmptyResourceId,
    /// Tenant id is empty.
    EmptyTenantId,
    /// A project-scoped resource must also have an organization id.
    ProjectWithoutOrganization,
}

impl StoreError {
    /// Returns a stable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyResourceKind => "resource_kind_empty",
            Self::EmptyResourceId => "resource_id_empty",
            Self::EmptyTenantId => "tenant_id_empty",
            Self::ProjectWithoutOrganization => "project_without_organization",
        }
    }
}

/// Stored ownership information for one platform resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceOwnerRecord {
    /// Resource kind, such as `Run` or `EvidenceArchive`.
    pub resource_kind: String,
    /// Stable resource id.
    pub resource_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional owning organization id.
    pub organization_id: Option<String>,
    /// Optional owning project id.
    pub project_id: Option<String>,
}

impl ResourceOwnerRecord {
    /// Builds a project-scoped owner record.
    #[must_use]
    pub fn project(
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
        tenant_id: impl Into<String>,
        organization_id: impl Into<String>,
        project_id: impl Into<String>,
    ) -> Self {
        Self {
            resource_kind: resource_kind.into(),
            resource_id: resource_id.into(),
            tenant_id: tenant_id.into(),
            organization_id: Some(organization_id.into()),
            project_id: Some(project_id.into()),
        }
    }

    /// Builds a tenant-scoped owner record.
    #[must_use]
    pub fn tenant(
        resource_kind: impl Into<String>,
        resource_id: impl Into<String>,
        tenant_id: impl Into<String>,
    ) -> Self {
        Self {
            resource_kind: resource_kind.into(),
            resource_id: resource_id.into(),
            tenant_id: tenant_id.into(),
            organization_id: None,
            project_id: None,
        }
    }

    /// Converts ownership metadata into an authorization resource reference.
    #[must_use]
    pub fn to_resource_ref(&self) -> ResourceRef {
        ResourceRef {
            kind: self.resource_kind.clone(),
            tenant_id: self.tenant_id.clone(),
            organization_id: self.organization_id.clone(),
            project_id: self.project_id.clone(),
            resource_id: self.resource_id.clone(),
        }
    }
}

/// Storage boundary for resolving authorization ownership before handler logic.
pub trait ResourceOwnerRepository {
    /// Records or replaces ownership metadata for one resource.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError`] when the owner record is missing required ownership
    /// fields or has an invalid project/organization shape.
    fn record_resource_owner(&self, record: ResourceOwnerRecord) -> Result<()>;

    /// Loads ownership metadata by resource kind and id.
    #[must_use]
    fn resource_owner(&self, resource_kind: &str, resource_id: &str)
    -> Option<ResourceOwnerRecord>;
}

/// In-memory platform resource ownership store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryResourceOwnerStore {
    owners: Arc<RwLock<BTreeMap<ResourceOwnerKey, ResourceOwnerRecord>>>,
}

impl InMemoryResourceOwnerStore {
    /// Creates an empty ownership store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every owner record sorted by key.
    #[must_use]
    pub fn resource_owners(&self) -> Vec<ResourceOwnerRecord> {
        read_lock(&self.owners).values().cloned().collect()
    }
}

impl ResourceOwnerRepository for InMemoryResourceOwnerStore {
    fn record_resource_owner(&self, record: ResourceOwnerRecord) -> Result<()> {
        validate_owner_record(&record)?;
        let key = ResourceOwnerKey {
            resource_kind: record.resource_kind.clone(),
            resource_id: record.resource_id.clone(),
        };
        write_lock(&self.owners).insert(key, record);
        Ok(())
    }

    fn resource_owner(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Option<ResourceOwnerRecord> {
        read_lock(&self.owners)
            .get(&ResourceOwnerKey {
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
            })
            .cloned()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceOwnerKey {
    resource_kind: String,
    resource_id: String,
}

fn validate_owner_record(record: &ResourceOwnerRecord) -> Result<()> {
    if record.resource_kind.trim().is_empty() {
        return Err(StoreError::EmptyResourceKind);
    }
    if record.resource_id.trim().is_empty() {
        return Err(StoreError::EmptyResourceId);
    }
    if record.tenant_id.trim().is_empty() {
        return Err(StoreError::EmptyTenantId);
    }
    if record.project_id.is_some() && record.organization_id.is_none() {
        return Err(StoreError::ProjectWithoutOrganization);
    }
    Ok(())
}

fn read_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    lock.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn write_lock<T>(lock: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    lock.write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use crate::action::{
        ActionGrant, AuthenticatedActor, AuthorizationEngine, AuthorizationRequest, BuiltInRole,
        FoundationAuthorizationEngine, PlatformAction,
    };
    use crate::route::{HttpMethod, route_metadata};
    use crate::storage::{
        InMemoryResourceOwnerStore, ResourceOwnerRecord, ResourceOwnerRepository, StoreError,
    };

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const OTHER_PROJECT_ID: &str = "prj_other";
    const USER_ID: &str = "usr_test";

    #[test]
    fn owner_store_records_and_resolves_project_resource() {
        let store = InMemoryResourceOwnerStore::new();
        let record =
            ResourceOwnerRecord::project("Run", "run_test", TENANT_ID, ORGANIZATION_ID, PROJECT_ID);
        assert_eq!(store.record_resource_owner(record.clone()), Ok(()));

        let stored = store.resource_owner("Run", "run_test");
        assert_eq!(stored, Some(record.clone()));
        assert_eq!(
            record.to_resource_ref().project_id.as_deref(),
            Some(PROJECT_ID)
        );
    }

    #[test]
    fn owner_store_keys_by_kind_and_id() {
        let store = InMemoryResourceOwnerStore::new();
        assert_eq!(
            store.record_resource_owner(ResourceOwnerRecord::project(
                "Run",
                "shared_id",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            )),
            Ok(())
        );
        assert_eq!(
            store.record_resource_owner(ResourceOwnerRecord::project(
                "Approval",
                "shared_id",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            )),
            Ok(())
        );

        assert!(store.resource_owner("Run", "shared_id").is_some());
        assert!(store.resource_owner("Approval", "shared_id").is_some());
        assert!(
            store
                .resource_owner("EvidenceArchive", "shared_id")
                .is_none()
        );
        assert_eq!(store.resource_owners().len(), 2);
    }

    #[test]
    fn owner_store_rejects_invalid_ownership_shape() {
        let store = InMemoryResourceOwnerStore::new();
        assert_eq!(
            store.record_resource_owner(ResourceOwnerRecord {
                resource_kind: "Run".to_owned(),
                resource_id: "run_test".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: None,
                project_id: Some(PROJECT_ID.to_owned()),
            }),
            Err(StoreError::ProjectWithoutOrganization)
        );
        assert_eq!(
            StoreError::ProjectWithoutOrganization.as_str(),
            "project_without_organization"
        );
    }

    #[test]
    fn route_metadata_owner_resolution_feeds_authorization() {
        let store = InMemoryResourceOwnerStore::new();
        assert_eq!(
            store.record_resource_owner(ResourceOwnerRecord::project(
                "Run",
                "run_test",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            )),
            Ok(())
        );
        let actor =
            AuthenticatedActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID);
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectViewer,
        ));
        let Some(route) = route_metadata(HttpMethod::Get, "/v1/runs/{run_id}") else {
            panic!("run read route metadata should exist");
        };
        let Some(owner) = store.resource_owner(route.resource_kind, "run_test") else {
            panic!("run owner should exist");
        };
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: route.action,
            resource: owner.to_resource_ref(),
        });
        assert!(decision.allowed, "{decision:?}");
        assert_eq!(route.action, PlatformAction::RunRead);
    }

    #[test]
    fn resolved_owner_scope_blocks_cross_project_access() {
        let store = InMemoryResourceOwnerStore::new();
        assert_eq!(
            store.record_resource_owner(ResourceOwnerRecord::project(
                "Run",
                "run_other",
                TENANT_ID,
                ORGANIZATION_ID,
                OTHER_PROJECT_ID,
            )),
            Ok(())
        );
        let actor =
            AuthenticatedActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID);
        let engine = FoundationAuthorizationEngine::new(ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectViewer,
        ));
        let Some(owner) = store.resource_owner("Run", "run_other") else {
            panic!("run owner should exist");
        };
        let decision = engine.authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::RunRead,
            resource: owner.to_resource_ref(),
        });
        assert!(!decision.allowed);
        assert_eq!(decision.reason, "missing_action_grant");
    }
}
