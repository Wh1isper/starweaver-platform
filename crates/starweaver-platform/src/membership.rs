//! Platform-local organization and project membership contracts.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Organization or project membership lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMembershipStatus {
    /// Active membership can access scoped resources.
    Active,
    /// Suspended membership cannot access scoped resources.
    Suspended,
    /// Removed membership cannot access scoped resources.
    Removed,
}

impl PlatformMembershipStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Removed => "removed",
        }
    }

    /// Parses a stable status id.
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "suspended" => Some(Self::Suspended),
            "removed" => Some(Self::Removed),
            _ => None,
        }
    }

    /// Returns whether the membership can access scoped resources.
    #[must_use]
    pub const fn accepts_access(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Durable organization membership metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformOrganizationMembershipRecord {
    /// Stable organization membership id.
    pub organization_member_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Owning organization id.
    pub organization_id: String,
    /// Principal receiving membership.
    pub principal_id: String,
    /// Membership kind, such as `user` or `service_account`.
    pub membership_kind: String,
    /// Membership status.
    pub status: PlatformMembershipStatus,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

/// Durable project membership metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformProjectMembershipRecord {
    /// Stable project membership id.
    pub project_member_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Owning organization id.
    pub organization_id: String,
    /// Owning project id.
    pub project_id: String,
    /// Principal receiving membership.
    pub principal_id: String,
    /// Parent organization membership id.
    pub organization_member_id: Option<String>,
    /// Membership kind, such as `user` or `service_account`.
    pub membership_kind: String,
    /// Membership status.
    pub status: PlatformMembershipStatus,
    /// Optimistic concurrency version.
    pub resource_version: i64,
}

impl PlatformProjectMembershipRecord {
    /// Returns whether the membership can access project resources.
    #[must_use]
    pub const fn accepts_access(&self) -> bool {
        self.status.accepts_access()
    }
}

/// Request to create or reactivate an organization membership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformOrganizationMembershipUpsert<'a> {
    /// Organization membership id to create when no existing membership exists.
    pub organization_member_id: &'a str,
    /// Owning tenant id.
    pub tenant_id: &'a str,
    /// Owning organization id.
    pub organization_id: &'a str,
    /// Principal receiving membership.
    pub principal_id: &'a str,
    /// Membership kind.
    pub membership_kind: &'a str,
    /// Principal id that created or reactivated the membership.
    pub created_by: &'a str,
}

/// Request to create or reactivate a project membership from an invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformInvitedProjectMembershipUpsert<'a> {
    /// Project membership id to create when no existing membership exists.
    pub project_member_id: &'a str,
    /// Owning tenant id.
    pub tenant_id: &'a str,
    /// Owning organization id.
    pub organization_id: &'a str,
    /// Owning project id.
    pub project_id: &'a str,
    /// Principal receiving membership.
    pub principal_id: &'a str,
    /// Parent organization membership id.
    pub organization_member_id: &'a str,
    /// Membership kind.
    pub membership_kind: &'a str,
}

/// Request to create or reactivate a project membership from an admin mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformProjectMembershipUpsert<'a> {
    /// Project membership id to create when no existing membership exists.
    pub project_member_id: &'a str,
    /// Owning tenant id.
    pub tenant_id: &'a str,
    /// Owning organization id.
    pub organization_id: &'a str,
    /// Owning project id.
    pub project_id: &'a str,
    /// Principal receiving membership.
    pub principal_id: &'a str,
    /// Parent organization membership id.
    pub organization_member_id: &'a str,
    /// Membership kind.
    pub membership_kind: &'a str,
    /// Principal id that created or reactivated the membership.
    pub created_by: &'a str,
}

/// Membership repository error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMembershipError {
    /// Membership id is malformed.
    InvalidMembershipId,
    /// Tenant id is malformed.
    InvalidTenantId,
    /// Organization id is malformed.
    InvalidOrganizationId,
    /// Project id is malformed.
    InvalidProjectId,
    /// Principal id is malformed.
    InvalidPrincipalId,
    /// Membership kind is unsupported.
    InvalidMembershipKind,
    /// Membership status is unsupported.
    InvalidStatus,
    /// Resource version is stale.
    StaleResourceVersion,
}

impl PlatformMembershipError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidMembershipId => "membership_id_invalid",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::InvalidOrganizationId => "organization_id_invalid",
            Self::InvalidProjectId => "project_id_invalid",
            Self::InvalidPrincipalId => "principal_id_invalid",
            Self::InvalidMembershipKind => "membership_kind_invalid",
            Self::InvalidStatus => "membership_status_invalid",
            Self::StaleResourceVersion => "stale_resource_version",
        }
    }
}

/// In-memory platform membership store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformMembershipStore {
    organization_members: Arc<RwLock<BTreeMap<String, PlatformOrganizationMembershipRecord>>>,
    project_members: Arc<RwLock<BTreeMap<String, PlatformProjectMembershipRecord>>>,
}

impl InMemoryPlatformMembershipStore {
    /// Creates an empty membership store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records or replaces an organization membership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError`] when the record shape is invalid.
    pub fn record_organization_member(
        &self,
        record: PlatformOrganizationMembershipRecord,
    ) -> Result<(), PlatformMembershipError> {
        validate_organization_member(&record)?;
        write_lock(&self.organization_members)
            .insert(record.organization_member_id.clone(), record);
        Ok(())
    }

    /// Records or replaces a project membership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError`] when the record shape is invalid.
    pub fn record_project_member(
        &self,
        record: PlatformProjectMembershipRecord,
    ) -> Result<(), PlatformMembershipError> {
        validate_project_member(&record)?;
        write_lock(&self.project_members).insert(record.project_member_id.clone(), record);
        Ok(())
    }

    /// Lists organization memberships for one organization.
    #[must_use]
    pub fn organization_members_for_organization(
        &self,
        organization_id: &str,
    ) -> Vec<PlatformOrganizationMembershipRecord> {
        let mut records = read_lock(&self.organization_members)
            .values()
            .filter(|record| record.organization_id == organization_id)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.organization_member_id
                .cmp(&right.organization_member_id)
        });
        records
    }

    /// Loads an organization membership by id.
    #[must_use]
    pub fn organization_member(
        &self,
        organization_member_id: &str,
    ) -> Option<PlatformOrganizationMembershipRecord> {
        read_lock(&self.organization_members)
            .get(organization_member_id)
            .cloned()
    }

    /// Lists project memberships for one project.
    #[must_use]
    pub fn project_members_for_project(
        &self,
        project_id: &str,
    ) -> Vec<PlatformProjectMembershipRecord> {
        let mut records = read_lock(&self.project_members)
            .values()
            .filter(|record| record.project_id == project_id)
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.project_member_id.cmp(&right.project_member_id));
        records
    }

    /// Loads a project membership by id.
    #[must_use]
    pub fn project_member(
        &self,
        project_member_id: &str,
    ) -> Option<PlatformProjectMembershipRecord> {
        read_lock(&self.project_members)
            .get(project_member_id)
            .cloned()
    }

    /// Updates an organization membership status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError::StaleResourceVersion`] when the
    /// expected resource version does not match.
    pub fn update_organization_member_status(
        &self,
        organization_member_id: &str,
        expected_resource_version: i64,
        status: PlatformMembershipStatus,
    ) -> Result<PlatformOrganizationMembershipRecord, PlatformMembershipError> {
        let mut records = write_lock(&self.organization_members);
        let record = records
            .get_mut(organization_member_id)
            .ok_or(PlatformMembershipError::InvalidMembershipId)?;
        if record.resource_version != expected_resource_version {
            return Err(PlatformMembershipError::StaleResourceVersion);
        }
        record.status = status;
        record.resource_version += 1;
        let updated = record.clone();
        drop(records);
        Ok(updated)
    }

    /// Updates a project membership status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError::StaleResourceVersion`] when the
    /// expected resource version does not match.
    pub fn update_project_member_status(
        &self,
        project_member_id: &str,
        expected_resource_version: i64,
        status: PlatformMembershipStatus,
    ) -> Result<PlatformProjectMembershipRecord, PlatformMembershipError> {
        let mut records = write_lock(&self.project_members);
        let record = records
            .get_mut(project_member_id)
            .ok_or(PlatformMembershipError::InvalidMembershipId)?;
        if record.resource_version != expected_resource_version {
            return Err(PlatformMembershipError::StaleResourceVersion);
        }
        record.status = status;
        record.resource_version += 1;
        let updated = record.clone();
        drop(records);
        Ok(updated)
    }

    /// Creates or reactivates an organization membership for an accepted invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError`] when the requested record shape is invalid.
    pub fn upsert_invited_organization_member(
        &self,
        organization_member_id: &str,
        tenant_id: &str,
        organization_id: &str,
        principal_id: &str,
        membership_kind: &str,
    ) -> Result<PlatformOrganizationMembershipRecord, PlatformMembershipError> {
        self.upsert_organization_member(PlatformOrganizationMembershipUpsert {
            organization_member_id,
            tenant_id,
            organization_id,
            principal_id,
            membership_kind,
            created_by: principal_id,
        })
    }

    /// Creates or reactivates an organization membership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError`] when the requested record shape is invalid.
    pub fn upsert_organization_member(
        &self,
        request: PlatformOrganizationMembershipUpsert<'_>,
    ) -> Result<PlatformOrganizationMembershipRecord, PlatformMembershipError> {
        let mut records = write_lock(&self.organization_members);
        let existing_id = records
            .values()
            .find(|record| {
                record.tenant_id == request.tenant_id
                    && record.organization_id == request.organization_id
                    && record.principal_id == request.principal_id
            })
            .map(|record| record.organization_member_id.clone());
        let record = if let Some(existing_id) = existing_id {
            let record = records
                .get_mut(&existing_id)
                .ok_or(PlatformMembershipError::InvalidMembershipId)?;
            if record.status != PlatformMembershipStatus::Active
                || record.membership_kind != request.membership_kind
            {
                record.status = PlatformMembershipStatus::Active;
                request
                    .membership_kind
                    .clone_into(&mut record.membership_kind);
                record.resource_version += 1;
            }
            record.clone()
        } else {
            let record = PlatformOrganizationMembershipRecord {
                organization_member_id: request.organization_member_id.to_owned(),
                tenant_id: request.tenant_id.to_owned(),
                organization_id: request.organization_id.to_owned(),
                principal_id: request.principal_id.to_owned(),
                membership_kind: request.membership_kind.to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            };
            validate_organization_member(&record)?;
            records.insert(record.organization_member_id.clone(), record.clone());
            record
        };
        drop(records);
        validate_organization_member(&record)?;
        Ok(record)
    }

    /// Creates or reactivates a project membership for an accepted invitation.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError`] when the requested record shape is invalid.
    pub fn upsert_invited_project_member(
        &self,
        request: PlatformInvitedProjectMembershipUpsert<'_>,
    ) -> Result<PlatformProjectMembershipRecord, PlatformMembershipError> {
        self.upsert_project_member(PlatformProjectMembershipUpsert {
            project_member_id: request.project_member_id,
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            principal_id: request.principal_id,
            organization_member_id: request.organization_member_id,
            membership_kind: request.membership_kind,
            created_by: request.principal_id,
        })
    }

    /// Creates or reactivates a project membership.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformMembershipError`] when the requested record shape is invalid.
    pub fn upsert_project_member(
        &self,
        request: PlatformProjectMembershipUpsert<'_>,
    ) -> Result<PlatformProjectMembershipRecord, PlatformMembershipError> {
        let mut records = write_lock(&self.project_members);
        let existing_id = records
            .values()
            .find(|record| {
                record.project_id == request.project_id
                    && record.principal_id == request.principal_id
            })
            .map(|record| record.project_member_id.clone());
        let record = if let Some(existing_id) = existing_id {
            let record = records
                .get_mut(&existing_id)
                .ok_or(PlatformMembershipError::InvalidMembershipId)?;
            let status_changed = record.status != PlatformMembershipStatus::Active;
            let kind_changed = record.membership_kind != request.membership_kind;
            let organization_member_changed =
                record.organization_member_id.as_deref() != Some(request.organization_member_id);
            if status_changed {
                record.status = PlatformMembershipStatus::Active;
            }
            if kind_changed {
                request
                    .membership_kind
                    .clone_into(&mut record.membership_kind);
            }
            if organization_member_changed {
                record.organization_member_id = Some(request.organization_member_id.to_owned());
            }
            if status_changed || kind_changed || organization_member_changed {
                record.resource_version += 1;
            }
            record.clone()
        } else {
            let record = PlatformProjectMembershipRecord {
                project_member_id: request.project_member_id.to_owned(),
                tenant_id: request.tenant_id.to_owned(),
                organization_id: request.organization_id.to_owned(),
                project_id: request.project_id.to_owned(),
                principal_id: request.principal_id.to_owned(),
                organization_member_id: Some(request.organization_member_id.to_owned()),
                membership_kind: request.membership_kind.to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            };
            validate_project_member(&record)?;
            records.insert(record.project_member_id.clone(), record.clone());
            record
        };
        drop(records);
        validate_project_member(&record)?;
        Ok(record)
    }

    /// Cascades a non-active organization membership status to child projects.
    #[must_use]
    pub fn cascade_project_memberships_for_organization_member(
        &self,
        organization_member: &PlatformOrganizationMembershipRecord,
        status: PlatformMembershipStatus,
    ) -> usize {
        if status == PlatformMembershipStatus::Active {
            return 0;
        }
        let mut updated_count = 0_usize;
        for record in write_lock(&self.project_members)
            .values_mut()
            .filter(|record| {
                record.tenant_id == organization_member.tenant_id
                    && record.organization_id == organization_member.organization_id
                    && record.principal_id == organization_member.principal_id
            })
        {
            let should_update = match status {
                PlatformMembershipStatus::Active => false,
                PlatformMembershipStatus::Suspended => {
                    record.status == PlatformMembershipStatus::Active
                }
                PlatformMembershipStatus::Removed => {
                    record.status != PlatformMembershipStatus::Removed
                }
            };
            if should_update {
                record.status = status;
                record.resource_version += 1;
                updated_count += 1;
            }
        }
        updated_count
    }
}

/// Validates organization membership metadata.
///
/// # Errors
///
/// Returns [`PlatformMembershipError`] when ids, kind, status, or version are invalid.
pub fn validate_organization_member(
    record: &PlatformOrganizationMembershipRecord,
) -> Result<(), PlatformMembershipError> {
    validate_prefixed(
        &record.organization_member_id,
        "om_",
        PlatformMembershipError::InvalidMembershipId,
    )?;
    validate_prefixed(
        &record.tenant_id,
        "ten_",
        PlatformMembershipError::InvalidTenantId,
    )?;
    validate_prefixed(
        &record.organization_id,
        "org_",
        PlatformMembershipError::InvalidOrganizationId,
    )?;
    validate_principal_id(&record.principal_id)?;
    validate_membership_kind(&record.membership_kind)?;
    if record.resource_version <= 0 {
        return Err(PlatformMembershipError::StaleResourceVersion);
    }
    Ok(())
}

/// Validates project membership metadata.
///
/// # Errors
///
/// Returns [`PlatformMembershipError`] when ids, kind, status, or version are invalid.
pub fn validate_project_member(
    record: &PlatformProjectMembershipRecord,
) -> Result<(), PlatformMembershipError> {
    validate_prefixed(
        &record.project_member_id,
        "pm_",
        PlatformMembershipError::InvalidMembershipId,
    )?;
    validate_prefixed(
        &record.tenant_id,
        "ten_",
        PlatformMembershipError::InvalidTenantId,
    )?;
    validate_prefixed(
        &record.organization_id,
        "org_",
        PlatformMembershipError::InvalidOrganizationId,
    )?;
    validate_prefixed(
        &record.project_id,
        "prj_",
        PlatformMembershipError::InvalidProjectId,
    )?;
    validate_principal_id(&record.principal_id)?;
    if let Some(organization_member_id) = record.organization_member_id.as_deref() {
        validate_prefixed(
            organization_member_id,
            "om_",
            PlatformMembershipError::InvalidMembershipId,
        )?;
    }
    validate_membership_kind(&record.membership_kind)?;
    if record.resource_version <= 0 {
        return Err(PlatformMembershipError::StaleResourceVersion);
    }
    Ok(())
}

fn validate_membership_kind(value: &str) -> Result<(), PlatformMembershipError> {
    match value {
        "user" | "service_account" => Ok(()),
        _ => Err(PlatformMembershipError::InvalidMembershipKind),
    }
}

fn validate_principal_id(value: &str) -> Result<(), PlatformMembershipError> {
    if value.starts_with("usr_") || value.starts_with("svc_") {
        Ok(())
    } else {
        Err(PlatformMembershipError::InvalidPrincipalId)
    }
}

fn validate_prefixed(
    value: &str,
    prefix: &str,
    error: PlatformMembershipError,
) -> Result<(), PlatformMembershipError> {
    if value.starts_with(prefix) {
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
        InMemoryPlatformMembershipStore, PlatformInvitedProjectMembershipUpsert,
        PlatformMembershipError, PlatformMembershipStatus, PlatformOrganizationMembershipRecord,
        PlatformProjectMembershipRecord,
    };

    #[test]
    fn membership_status_ids_are_stable() {
        assert_eq!(PlatformMembershipStatus::Active.as_str(), "active");
        assert_eq!(
            PlatformMembershipStatus::from_id("suspended"),
            Some(PlatformMembershipStatus::Suspended)
        );
        assert!(PlatformMembershipStatus::Active.accepts_access());
        assert!(!PlatformMembershipStatus::Removed.accepts_access());
    }

    #[test]
    fn membership_store_updates_and_cascades_status() {
        let store = InMemoryPlatformMembershipStore::new();
        store
            .record_organization_member(org_member(PlatformMembershipStatus::Active, 1))
            .unwrap_or_else(|error| panic!("organization member should be valid: {error:?}"));
        store
            .record_project_member(project_member(PlatformMembershipStatus::Active, 1))
            .unwrap_or_else(|error| panic!("project member should be valid: {error:?}"));

        let updated = store
            .update_organization_member_status("om_test", 1, PlatformMembershipStatus::Suspended)
            .unwrap_or_else(|error| panic!("organization member update should succeed: {error:?}"));
        let cascaded =
            store.cascade_project_memberships_for_organization_member(&updated, updated.status);
        let project_member = store
            .project_member("pm_test")
            .unwrap_or_else(|| panic!("project member should exist"));

        assert_eq!(updated.resource_version, 2);
        assert_eq!(cascaded, 1);
        assert_eq!(project_member.status, PlatformMembershipStatus::Suspended);
        assert_eq!(project_member.resource_version, 2);
    }

    #[test]
    fn membership_store_rejects_stale_versions() {
        let store = InMemoryPlatformMembershipStore::new();
        store
            .record_project_member(project_member(PlatformMembershipStatus::Active, 1))
            .unwrap_or_else(|error| panic!("project member should be valid: {error:?}"));

        assert_eq!(
            store.update_project_member_status("pm_test", 2, PlatformMembershipStatus::Removed,),
            Err(PlatformMembershipError::StaleResourceVersion)
        );
    }

    #[test]
    fn membership_store_upserts_invited_memberships() {
        let store = InMemoryPlatformMembershipStore::new();
        let organization_member = store
            .upsert_invited_organization_member(
                "om_invited",
                "ten_test",
                "org_test",
                "usr_invited",
                "user",
            )
            .unwrap_or_else(|error| panic!("organization member should upsert: {error:?}"));
        let project_member = store
            .upsert_invited_project_member(PlatformInvitedProjectMembershipUpsert {
                project_member_id: "pm_invited",
                tenant_id: "ten_test",
                organization_id: "org_test",
                project_id: "prj_test",
                principal_id: "usr_invited",
                organization_member_id: &organization_member.organization_member_id,
                membership_kind: "user",
            })
            .unwrap_or_else(|error| panic!("project member should upsert: {error:?}"));

        assert_eq!(organization_member.status, PlatformMembershipStatus::Active);
        assert_eq!(project_member.status, PlatformMembershipStatus::Active);
        assert_eq!(
            project_member.organization_member_id.as_deref(),
            Some("om_invited")
        );

        let second = store
            .upsert_invited_organization_member(
                "om_unused",
                "ten_test",
                "org_test",
                "usr_invited",
                "user",
            )
            .unwrap_or_else(|error| panic!("organization member should be idempotent: {error:?}"));
        assert_eq!(second.organization_member_id, "om_invited");
        assert_eq!(second.resource_version, 1);
    }

    fn org_member(
        status: PlatformMembershipStatus,
        resource_version: i64,
    ) -> PlatformOrganizationMembershipRecord {
        PlatformOrganizationMembershipRecord {
            organization_member_id: "om_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: "org_test".to_owned(),
            principal_id: "usr_test".to_owned(),
            membership_kind: "user".to_owned(),
            status,
            resource_version,
        }
    }

    fn project_member(
        status: PlatformMembershipStatus,
        resource_version: i64,
    ) -> PlatformProjectMembershipRecord {
        PlatformProjectMembershipRecord {
            project_member_id: "pm_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: "org_test".to_owned(),
            project_id: "prj_test".to_owned(),
            principal_id: "usr_test".to_owned(),
            organization_member_id: Some("om_test".to_owned()),
            membership_kind: "user".to_owned(),
            status,
            resource_version,
        }
    }
}
