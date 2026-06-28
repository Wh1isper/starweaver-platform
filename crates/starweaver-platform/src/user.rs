//! Platform-local user contracts.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// Platform user status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformUserStatus {
    /// User can authenticate and access authorized resources.
    Active,
    /// User is disabled and active sessions should be disabled.
    Disabled,
    /// User has been deleted and should not appear in normal lists.
    Deleted,
}

impl PlatformUserStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    /// Parses a stable status id.
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            "deleted" => Some(Self::Deleted),
            _ => None,
        }
    }

    /// Returns whether the status allows authentication.
    #[must_use]
    pub const fn accepts_access(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Platform user validation and store error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformUserError {
    /// User id is malformed.
    InvalidUserId,
    /// Tenant id is malformed.
    InvalidTenantId,
    /// Organization id is malformed.
    InvalidOrganizationId,
    /// Project id is malformed.
    InvalidProjectId,
    /// Primary email is malformed.
    InvalidEmail,
    /// Display name is missing.
    InvalidDisplayName,
    /// User status is invalid.
    InvalidStatus,
    /// Resource version is invalid.
    InvalidResourceVersion,
    /// Expected resource version does not match the stored user.
    StaleResourceVersion,
    /// User is not known to the store.
    UnknownUser,
}

impl PlatformUserError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidUserId => "user_id_invalid",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::InvalidOrganizationId => "organization_id_invalid",
            Self::InvalidProjectId => "project_id_invalid",
            Self::InvalidEmail => "user_email_invalid",
            Self::InvalidDisplayName => "user_display_name_invalid",
            Self::InvalidStatus => "user_status_invalid",
            Self::InvalidResourceVersion => "resource_version_invalid",
            Self::StaleResourceVersion => "stale_resource_version",
            Self::UnknownUser => "user_not_found",
        }
    }
}

/// Stored platform user metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformUserRecord {
    /// Stable user id.
    pub user_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Default organization id used after login.
    pub default_organization_id: Option<String>,
    /// Default project id used after login.
    pub default_project_id: Option<String>,
    /// Optional primary email.
    pub primary_email: Option<String>,
    /// Operator-facing display name.
    pub display_name: String,
    /// User status.
    pub status: PlatformUserStatus,
    /// Optimistic resource version.
    pub resource_version: i64,
}

/// In-memory platform user store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformUserStore {
    users: Arc<RwLock<BTreeMap<String, PlatformUserRecord>>>,
}

impl InMemoryPlatformUserStore {
    /// Creates an empty user store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records or replaces a user.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformUserError`] when the user shape is invalid.
    pub fn record_user(&self, record: PlatformUserRecord) -> Result<(), PlatformUserError> {
        validate_platform_user_record(&record)?;
        write_lock(&self.users).insert(record.user_id.clone(), record);
        Ok(())
    }

    /// Lists non-deleted users for one tenant.
    #[must_use]
    pub fn users_for_tenant(&self, tenant_id: &str) -> Vec<PlatformUserRecord> {
        read_lock(&self.users)
            .values()
            .filter(|user| {
                user.tenant_id == tenant_id && user.status != PlatformUserStatus::Deleted
            })
            .cloned()
            .collect()
    }

    /// Loads a non-deleted user by id.
    #[must_use]
    pub fn user(&self, user_id: &str) -> Option<PlatformUserRecord> {
        read_lock(&self.users)
            .get(user_id)
            .filter(|user| user.status != PlatformUserStatus::Deleted)
            .cloned()
    }

    /// Loads a user by id, including deleted users.
    #[must_use]
    pub fn user_including_deleted(&self, user_id: &str) -> Option<PlatformUserRecord> {
        read_lock(&self.users).get(user_id).cloned()
    }

    /// Updates a user's status with optimistic concurrency.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformUserError`] when the user is unknown, deleted, invalid,
    /// or the expected resource version does not match.
    pub fn update_user_status(
        &self,
        user_id: &str,
        expected_version: i64,
        status: PlatformUserStatus,
    ) -> Result<PlatformUserRecord, PlatformUserError> {
        if expected_version < 1 {
            return Err(PlatformUserError::InvalidResourceVersion);
        }
        let mut users = write_lock(&self.users);
        let user = users
            .get_mut(user_id)
            .ok_or(PlatformUserError::UnknownUser)?;
        if user.status == PlatformUserStatus::Deleted {
            return Err(PlatformUserError::UnknownUser);
        }
        if user.resource_version != expected_version {
            return Err(PlatformUserError::StaleResourceVersion);
        }
        user.status = status;
        user.resource_version += 1;
        validate_platform_user_record(user)?;
        let updated = user.clone();
        drop(users);
        Ok(updated)
    }
}

/// Validates a platform user record.
///
/// # Errors
///
/// Returns [`PlatformUserError`] when a required id, status, email, or display
/// value is invalid.
pub fn validate_platform_user_record(record: &PlatformUserRecord) -> Result<(), PlatformUserError> {
    validate_prefixed_id(&record.user_id, "usr_", PlatformUserError::InvalidUserId)?;
    validate_prefixed_id(
        &record.tenant_id,
        "ten_",
        PlatformUserError::InvalidTenantId,
    )?;
    if let Some(organization_id) = record.default_organization_id.as_deref() {
        validate_prefixed_id(
            organization_id,
            "org_",
            PlatformUserError::InvalidOrganizationId,
        )?;
    }
    if let Some(project_id) = record.default_project_id.as_deref() {
        validate_prefixed_id(project_id, "prj_", PlatformUserError::InvalidProjectId)?;
    }
    if let Some(email) = record.primary_email.as_deref()
        && !valid_email(email)
    {
        return Err(PlatformUserError::InvalidEmail);
    }
    if record.display_name.trim().is_empty() {
        return Err(PlatformUserError::InvalidDisplayName);
    }
    if record.resource_version < 1 {
        return Err(PlatformUserError::InvalidResourceVersion);
    }
    Ok(())
}

fn validate_prefixed_id(
    value: &str,
    prefix: &str,
    error: PlatformUserError,
) -> Result<(), PlatformUserError> {
    let value = value.trim();
    if value.len() <= prefix.len() || !value.starts_with(prefix) {
        return Err(error);
    }
    Ok(())
}

fn valid_email(value: &str) -> bool {
    let value = value.trim();
    value.contains('@') && !value.starts_with('@') && !value.ends_with('@')
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
        InMemoryPlatformUserStore, PlatformUserError, PlatformUserRecord, PlatformUserStatus,
        validate_platform_user_record,
    };

    #[test]
    fn user_store_lists_non_deleted_tenant_users() {
        let store = InMemoryPlatformUserStore::new();
        assert_eq!(store.record_user(user("usr_one", "ten_test")), Ok(()));
        assert_eq!(
            store.record_user(PlatformUserRecord {
                user_id: "usr_deleted".to_owned(),
                status: PlatformUserStatus::Deleted,
                ..user("usr_deleted", "ten_test")
            }),
            Ok(())
        );
        assert_eq!(store.record_user(user("usr_other", "ten_other")), Ok(()));

        let users = store.users_for_tenant("ten_test");

        assert_eq!(users.len(), 1);
        assert_eq!(users[0].user_id, "usr_one");
    }

    #[test]
    fn user_status_updates_are_versioned() {
        let store = InMemoryPlatformUserStore::new();
        assert_eq!(store.record_user(user("usr_one", "ten_test")), Ok(()));

        let updated = store
            .update_user_status("usr_one", 1, PlatformUserStatus::Disabled)
            .unwrap_or_else(|error| panic!("user status update should succeed: {error:?}"));

        assert_eq!(updated.status, PlatformUserStatus::Disabled);
        assert_eq!(updated.resource_version, 2);
        assert_eq!(
            store.update_user_status("usr_one", 1, PlatformUserStatus::Active),
            Err(PlatformUserError::StaleResourceVersion)
        );
    }

    #[test]
    fn invalid_user_records_are_rejected() {
        assert_eq!(
            validate_platform_user_record(&PlatformUserRecord {
                user_id: "bad".to_owned(),
                ..user("usr_one", "ten_test")
            }),
            Err(PlatformUserError::InvalidUserId)
        );
        assert_eq!(
            validate_platform_user_record(&PlatformUserRecord {
                primary_email: Some("invalid".to_owned()),
                ..user("usr_one", "ten_test")
            }),
            Err(PlatformUserError::InvalidEmail)
        );
        assert_eq!(
            PlatformUserStatus::from_id("disabled"),
            Some(PlatformUserStatus::Disabled)
        );
        assert_eq!(PlatformUserStatus::Active.as_str(), "active");
        assert!(PlatformUserStatus::Active.accepts_access());
    }

    fn user(user_id: &str, tenant_id: &str) -> PlatformUserRecord {
        PlatformUserRecord {
            user_id: user_id.to_owned(),
            tenant_id: tenant_id.to_owned(),
            default_organization_id: Some("org_test".to_owned()),
            default_project_id: Some("prj_test".to_owned()),
            primary_email: Some(format!("{user_id}@example.com")),
            display_name: user_id.to_owned(),
            status: PlatformUserStatus::Active,
            resource_version: 1,
        }
    }
}
