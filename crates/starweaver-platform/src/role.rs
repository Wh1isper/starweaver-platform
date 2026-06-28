//! Platform-local role binding contracts.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::action::{BuiltInRole, RoleScopeKind};

/// Platform role-binding lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformRoleBindingStatus {
    /// Role binding can grant actions.
    Active,
    /// Role binding is temporarily disabled.
    Disabled,
    /// Role binding is deleted and retained only for audit history.
    Deleted,
}

impl PlatformRoleBindingStatus {
    /// Returns the durable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    /// Parses a durable status id.
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }
}

/// Durable platform role binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformRoleBindingRecord {
    /// Stable role binding id.
    pub role_binding_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional organization scope.
    pub organization_id: Option<String>,
    /// Optional project scope.
    pub project_id: Option<String>,
    /// Principal receiving the role.
    pub principal_id: String,
    /// Built-in role id.
    pub role_id: String,
    /// Binding lifecycle status.
    pub status: PlatformRoleBindingStatus,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

impl PlatformRoleBindingRecord {
    /// Returns the built-in role for this binding.
    #[must_use]
    pub fn built_in_role(&self) -> Option<BuiltInRole> {
        BuiltInRole::from_id(&self.role_id)
    }
}

/// Role binding repository error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformRoleBindingError {
    /// Role binding id is malformed.
    InvalidRoleBindingId,
    /// Tenant id is malformed.
    InvalidTenantId,
    /// Organization id is malformed.
    InvalidOrganizationId,
    /// Project id is malformed.
    InvalidProjectId,
    /// Principal id is malformed.
    InvalidPrincipalId,
    /// Role id is unsupported.
    InvalidRoleId,
    /// Scope shape does not match the role.
    InvalidScope,
    /// Binding status is unsupported.
    InvalidStatus,
    /// Resource version is stale.
    StaleResourceVersion,
}

impl PlatformRoleBindingError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRoleBindingId => "role_binding_id_invalid",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::InvalidOrganizationId => "organization_id_invalid",
            Self::InvalidProjectId => "project_id_invalid",
            Self::InvalidPrincipalId => "principal_id_invalid",
            Self::InvalidRoleId => "role_id_invalid",
            Self::InvalidScope => "role_binding_scope_invalid",
            Self::InvalidStatus => "role_binding_status_invalid",
            Self::StaleResourceVersion => "stale_resource_version",
        }
    }
}

/// Request to create or reactivate a role binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformRoleBindingUpsert<'a> {
    /// Role binding id to create when no equivalent binding exists.
    pub role_binding_id: &'a str,
    /// Owning tenant id.
    pub tenant_id: &'a str,
    /// Optional organization scope.
    pub organization_id: Option<&'a str>,
    /// Optional project scope.
    pub project_id: Option<&'a str>,
    /// Principal receiving the role.
    pub principal_id: &'a str,
    /// Built-in role id.
    pub role_id: &'a str,
}

/// In-memory platform role binding store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformRoleBindingStore {
    role_bindings: Arc<RwLock<BTreeMap<String, PlatformRoleBindingRecord>>>,
}

impl InMemoryPlatformRoleBindingStore {
    /// Creates an empty role binding store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records or replaces a role binding.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRoleBindingError`] when the record shape is invalid.
    pub fn record_role_binding(
        &self,
        record: PlatformRoleBindingRecord,
    ) -> Result<(), PlatformRoleBindingError> {
        validate_role_binding(&record)?;
        write_lock(&self.role_bindings).insert(record.role_binding_id.clone(), record);
        Ok(())
    }

    /// Lists non-deleted role bindings for one tenant.
    #[must_use]
    pub fn role_bindings_for_tenant(&self, tenant_id: &str) -> Vec<PlatformRoleBindingRecord> {
        let mut records = read_lock(&self.role_bindings)
            .values()
            .filter(|record| {
                record.tenant_id == tenant_id && record.status != PlatformRoleBindingStatus::Deleted
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.role_binding_id.cmp(&right.role_binding_id));
        records
    }

    /// Lists active role bindings for one principal.
    #[must_use]
    pub fn active_role_bindings_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Vec<PlatformRoleBindingRecord> {
        let mut records = read_lock(&self.role_bindings)
            .values()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && record.principal_id == principal_id
                    && record.status == PlatformRoleBindingStatus::Active
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.role_binding_id.cmp(&right.role_binding_id));
        records
    }

    /// Loads a role binding by id.
    #[must_use]
    pub fn role_binding(&self, role_binding_id: &str) -> Option<PlatformRoleBindingRecord> {
        read_lock(&self.role_bindings).get(role_binding_id).cloned()
    }

    /// Creates or reactivates a role binding.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRoleBindingError`] when the request shape is invalid.
    pub fn upsert_role_binding(
        &self,
        request: PlatformRoleBindingUpsert<'_>,
    ) -> Result<PlatformRoleBindingRecord, PlatformRoleBindingError> {
        let mut records = write_lock(&self.role_bindings);
        let existing_id = records
            .values()
            .find(|record| {
                record.tenant_id == request.tenant_id
                    && record.organization_id.as_deref() == request.organization_id
                    && record.project_id.as_deref() == request.project_id
                    && record.principal_id == request.principal_id
                    && record.role_id == request.role_id
            })
            .map(|record| record.role_binding_id.clone());
        let record = if let Some(existing_id) = existing_id {
            let record = records
                .get_mut(&existing_id)
                .ok_or(PlatformRoleBindingError::InvalidRoleBindingId)?;
            if record.status != PlatformRoleBindingStatus::Active {
                record.status = PlatformRoleBindingStatus::Active;
                record.resource_version += 1;
            }
            record.clone()
        } else {
            let record = PlatformRoleBindingRecord {
                role_binding_id: request.role_binding_id.to_owned(),
                tenant_id: request.tenant_id.to_owned(),
                organization_id: request.organization_id.map(ToOwned::to_owned),
                project_id: request.project_id.map(ToOwned::to_owned),
                principal_id: request.principal_id.to_owned(),
                role_id: request.role_id.to_owned(),
                status: PlatformRoleBindingStatus::Active,
                resource_version: 1,
            };
            validate_role_binding(&record)?;
            records.insert(record.role_binding_id.clone(), record.clone());
            record
        };
        drop(records);
        validate_role_binding(&record)?;
        Ok(record)
    }

    /// Updates a role binding status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformRoleBindingError::StaleResourceVersion`] when the
    /// expected resource version does not match.
    pub fn update_role_binding_status(
        &self,
        role_binding_id: &str,
        expected_resource_version: i64,
        status: PlatformRoleBindingStatus,
    ) -> Result<PlatformRoleBindingRecord, PlatformRoleBindingError> {
        let mut records = write_lock(&self.role_bindings);
        let record = records
            .get_mut(role_binding_id)
            .ok_or(PlatformRoleBindingError::InvalidRoleBindingId)?;
        if record.resource_version != expected_resource_version {
            return Err(PlatformRoleBindingError::StaleResourceVersion);
        }
        record.status = status;
        record.resource_version += 1;
        let updated = record.clone();
        drop(records);
        validate_role_binding(&updated)?;
        Ok(updated)
    }

    /// Deletes active role bindings under one organization for a principal.
    #[must_use]
    pub fn delete_role_bindings_for_organization_principal(
        &self,
        tenant_id: &str,
        organization_id: &str,
        principal_id: &str,
    ) -> usize {
        let mut updated_count = 0_usize;
        for record in write_lock(&self.role_bindings)
            .values_mut()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && record.organization_id.as_deref() == Some(organization_id)
                    && record.principal_id == principal_id
                    && record.status == PlatformRoleBindingStatus::Active
            })
        {
            record.status = PlatformRoleBindingStatus::Deleted;
            record.resource_version += 1;
            updated_count += 1;
        }
        updated_count
    }

    /// Deletes active project role bindings for one project principal.
    #[must_use]
    pub fn delete_role_bindings_for_project_principal(
        &self,
        tenant_id: &str,
        project_id: &str,
        principal_id: &str,
    ) -> usize {
        let mut updated_count = 0_usize;
        for record in write_lock(&self.role_bindings)
            .values_mut()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && record.project_id.as_deref() == Some(project_id)
                    && record.principal_id == principal_id
                    && record.status == PlatformRoleBindingStatus::Active
            })
        {
            record.status = PlatformRoleBindingStatus::Deleted;
            record.resource_version += 1;
            updated_count += 1;
        }
        updated_count
    }
}

/// Validates role binding metadata.
///
/// # Errors
///
/// Returns [`PlatformRoleBindingError`] when ids, role, scope, status, or version
/// are invalid.
pub fn validate_role_binding(
    record: &PlatformRoleBindingRecord,
) -> Result<(), PlatformRoleBindingError> {
    validate_prefixed(
        &record.role_binding_id,
        "rb_",
        PlatformRoleBindingError::InvalidRoleBindingId,
    )?;
    validate_prefixed(
        &record.tenant_id,
        "ten_",
        PlatformRoleBindingError::InvalidTenantId,
    )?;
    validate_principal_id(&record.principal_id)?;
    if let Some(organization_id) = record.organization_id.as_deref() {
        validate_prefixed(
            organization_id,
            "org_",
            PlatformRoleBindingError::InvalidOrganizationId,
        )?;
    }
    if let Some(project_id) = record.project_id.as_deref() {
        validate_prefixed(
            project_id,
            "prj_",
            PlatformRoleBindingError::InvalidProjectId,
        )?;
    }
    let role = record
        .built_in_role()
        .ok_or(PlatformRoleBindingError::InvalidRoleId)?;
    validate_scope_shape(
        role,
        record.organization_id.as_deref(),
        record.project_id.as_deref(),
    )?;
    if record.resource_version <= 0 {
        return Err(PlatformRoleBindingError::StaleResourceVersion);
    }
    Ok(())
}

const fn validate_scope_shape(
    role: BuiltInRole,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<(), PlatformRoleBindingError> {
    match role.scope_kind() {
        RoleScopeKind::Tenant => match (organization_id, project_id) {
            (None, None) => Ok(()),
            _ => Err(PlatformRoleBindingError::InvalidScope),
        },
        RoleScopeKind::Organization => match (organization_id, project_id) {
            (Some(_), None) => Ok(()),
            _ => Err(PlatformRoleBindingError::InvalidScope),
        },
        RoleScopeKind::Project => match (organization_id, project_id) {
            (Some(_), Some(_)) => Ok(()),
            _ => Err(PlatformRoleBindingError::InvalidScope),
        },
        RoleScopeKind::Any => match (organization_id, project_id) {
            (None, Some(_)) => Err(PlatformRoleBindingError::InvalidScope),
            _ => Ok(()),
        },
    }
}

fn validate_principal_id(value: &str) -> Result<(), PlatformRoleBindingError> {
    if value.starts_with("usr_") || value.starts_with("svc_") {
        Ok(())
    } else {
        Err(PlatformRoleBindingError::InvalidPrincipalId)
    }
}

fn validate_prefixed(
    value: &str,
    prefix: &str,
    error: PlatformRoleBindingError,
) -> Result<(), PlatformRoleBindingError> {
    if value.starts_with(prefix) && value.len() > prefix.len() {
        Ok(())
    } else {
        Err(error)
    }
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
    use super::{
        validate_role_binding, InMemoryPlatformRoleBindingStore, PlatformRoleBindingError,
        PlatformRoleBindingRecord, PlatformRoleBindingStatus, PlatformRoleBindingUpsert,
    };

    #[test]
    fn role_binding_store_upserts_and_removes_by_scope() {
        let store = InMemoryPlatformRoleBindingStore::new();
        let created = store
            .upsert_role_binding(PlatformRoleBindingUpsert {
                role_binding_id: "rb_project_admin",
                tenant_id: "ten_test",
                organization_id: Some("org_test"),
                project_id: Some("prj_test"),
                principal_id: "usr_test",
                role_id: "project_admin",
            })
            .unwrap_or_else(|error| panic!("role binding should upsert: {error:?}"));
        assert_eq!(created.status, PlatformRoleBindingStatus::Active);

        let replay = store
            .upsert_role_binding(PlatformRoleBindingUpsert {
                role_binding_id: "rb_replay",
                tenant_id: "ten_test",
                organization_id: Some("org_test"),
                project_id: Some("prj_test"),
                principal_id: "usr_test",
                role_id: "project_admin",
            })
            .unwrap_or_else(|error| panic!("equivalent binding should replay: {error:?}"));
        assert_eq!(replay.role_binding_id, "rb_project_admin");

        assert_eq!(
            store
                .active_role_bindings_for_principal("ten_test", "usr_test")
                .len(),
            1
        );
        assert_eq!(
            store.delete_role_bindings_for_project_principal("ten_test", "prj_test", "usr_test"),
            1
        );
        assert!(store
            .active_role_bindings_for_principal("ten_test", "usr_test")
            .is_empty());
    }

    #[test]
    fn role_binding_validation_enforces_scope_shape() {
        let valid = PlatformRoleBindingRecord {
            role_binding_id: "rb_org".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: Some("org_test".to_owned()),
            project_id: None,
            principal_id: "usr_test".to_owned(),
            role_id: "organization_admin".to_owned(),
            status: PlatformRoleBindingStatus::Active,
            resource_version: 1,
        };
        assert_eq!(validate_role_binding(&valid), Ok(()));
        assert_eq!(
            validate_role_binding(&PlatformRoleBindingRecord {
                project_id: Some("prj_test".to_owned()),
                ..valid
            }),
            Err(PlatformRoleBindingError::InvalidScope)
        );
    }
}
