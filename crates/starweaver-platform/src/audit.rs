//! Platform-local audit event contracts.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use crate::action::ActorKind;

/// Stable redaction profile for platform audit events.
pub const PLATFORM_AUDIT_REDACTION_PROFILE: &str = "platform.audit.redaction.v1";

/// Platform audit validation and store error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformAuditError {
    /// Audit event id is malformed.
    InvalidAuditEventId,
    /// Tenant id is malformed.
    InvalidTenantId,
    /// Organization id is malformed.
    InvalidOrganizationId,
    /// Project id is malformed.
    InvalidProjectId,
    /// Principal id is malformed.
    InvalidPrincipalId,
    /// Action id is missing.
    InvalidActionId,
    /// Resource kind is missing.
    InvalidResourceKind,
    /// Resource id is missing.
    InvalidResourceId,
    /// Event type is missing.
    InvalidEventType,
    /// Reason is present but empty.
    InvalidReason,
    /// Redaction profile is missing.
    InvalidRedaction,
    /// Timestamp is invalid.
    InvalidTimestamp,
}

impl PlatformAuditError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidAuditEventId => "audit_event_id_invalid",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::InvalidOrganizationId => "organization_id_invalid",
            Self::InvalidProjectId => "project_id_invalid",
            Self::InvalidPrincipalId => "principal_id_invalid",
            Self::InvalidActionId => "audit_action_id_invalid",
            Self::InvalidResourceKind => "audit_resource_kind_invalid",
            Self::InvalidResourceId => "audit_resource_id_invalid",
            Self::InvalidEventType => "audit_event_type_invalid",
            Self::InvalidReason => "audit_reason_invalid",
            Self::InvalidRedaction => "audit_redaction_invalid",
            Self::InvalidTimestamp => "audit_timestamp_invalid",
        }
    }
}

/// Stored platform audit event metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformAuditEventRecord {
    /// Stable audit event id.
    pub audit_event_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional organization scope.
    pub organization_id: Option<String>,
    /// Optional project scope.
    pub project_id: Option<String>,
    /// Actor principal id.
    pub actor_principal_id: String,
    /// Actor kind.
    pub actor_kind: ActorKind,
    /// Stable platform action id.
    pub action_id: String,
    /// Resource kind affected by this event.
    pub resource_kind: String,
    /// Resource id affected by this event.
    pub resource_id: String,
    /// Stable event type.
    pub event_type: String,
    /// Optional operator reason.
    pub reason: Option<String>,
    /// Redaction profile used before storage.
    pub redaction: String,
    /// Creation time as Unix seconds.
    pub created_at_unix: i64,
}

/// In-memory platform audit event store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformAuditStore {
    events: Arc<RwLock<BTreeMap<String, PlatformAuditEventRecord>>>,
}

impl InMemoryPlatformAuditStore {
    /// Creates an empty audit event store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records or replaces an audit event.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformAuditError`] when the event shape is invalid.
    pub fn record_audit_event(
        &self,
        record: PlatformAuditEventRecord,
    ) -> Result<(), PlatformAuditError> {
        validate_platform_audit_event_record(&record)?;
        write_lock(&self.events).insert(record.audit_event_id.clone(), record);
        Ok(())
    }

    /// Lists audit events for one tenant.
    #[must_use]
    pub fn audit_events_for_tenant(&self, tenant_id: &str) -> Vec<PlatformAuditEventRecord> {
        read_lock(&self.events)
            .values()
            .filter(|event| event.tenant_id == tenant_id)
            .cloned()
            .collect()
    }
}

/// Validates a platform audit event record.
///
/// # Errors
///
/// Returns [`PlatformAuditError`] when required ids, event fields, redaction, or
/// timestamps are invalid.
pub fn validate_platform_audit_event_record(
    record: &PlatformAuditEventRecord,
) -> Result<(), PlatformAuditError> {
    validate_prefixed_id(
        &record.audit_event_id,
        "audit_",
        PlatformAuditError::InvalidAuditEventId,
    )?;
    validate_prefixed_id(
        &record.tenant_id,
        "ten_",
        PlatformAuditError::InvalidTenantId,
    )?;
    if let Some(organization_id) = record.organization_id.as_deref() {
        validate_prefixed_id(
            organization_id,
            "org_",
            PlatformAuditError::InvalidOrganizationId,
        )?;
    }
    if let Some(project_id) = record.project_id.as_deref() {
        validate_prefixed_id(project_id, "prj_", PlatformAuditError::InvalidProjectId)?;
        if record.organization_id.is_none() {
            return Err(PlatformAuditError::InvalidProjectId);
        }
    }
    validate_principal_id(&record.actor_principal_id)?;
    validate_non_empty(&record.action_id, PlatformAuditError::InvalidActionId)?;
    validate_non_empty(
        &record.resource_kind,
        PlatformAuditError::InvalidResourceKind,
    )?;
    validate_non_empty(&record.resource_id, PlatformAuditError::InvalidResourceId)?;
    validate_non_empty(&record.event_type, PlatformAuditError::InvalidEventType)?;
    if let Some(reason) = record.reason.as_deref() {
        validate_non_empty(reason, PlatformAuditError::InvalidReason)?;
    }
    validate_non_empty(&record.redaction, PlatformAuditError::InvalidRedaction)?;
    if record.created_at_unix <= 0 {
        return Err(PlatformAuditError::InvalidTimestamp);
    }
    Ok(())
}

fn validate_principal_id(value: &str) -> Result<(), PlatformAuditError> {
    let value = value.trim();
    if value.len() <= 4
        || !(value.starts_with("usr_") || value.starts_with("svc_") || value.starts_with("sys_"))
    {
        return Err(PlatformAuditError::InvalidPrincipalId);
    }
    Ok(())
}

fn validate_prefixed_id(
    value: &str,
    prefix: &str,
    error: PlatformAuditError,
) -> Result<(), PlatformAuditError> {
    let value = value.trim();
    if value.len() <= prefix.len() || !value.starts_with(prefix) {
        return Err(error);
    }
    Ok(())
}

fn validate_non_empty(value: &str, error: PlatformAuditError) -> Result<(), PlatformAuditError> {
    if value.trim().is_empty() {
        return Err(error);
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
    use crate::action::ActorKind;
    use crate::audit::{
        validate_platform_audit_event_record, InMemoryPlatformAuditStore, PlatformAuditError,
        PlatformAuditEventRecord, PLATFORM_AUDIT_REDACTION_PROFILE,
    };

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const USER_ID: &str = "usr_test";

    #[test]
    fn audit_event_record_validation_accepts_redacted_event_shape() {
        let record = valid_event();

        assert_eq!(validate_platform_audit_event_record(&record), Ok(()));
    }

    #[test]
    fn audit_event_record_validation_rejects_missing_sensitive_fields() {
        assert_eq!(
            validate_platform_audit_event_record(&PlatformAuditEventRecord {
                audit_event_id: "evt_test".to_owned(),
                ..valid_event()
            }),
            Err(PlatformAuditError::InvalidAuditEventId)
        );
        assert_eq!(
            validate_platform_audit_event_record(&PlatformAuditEventRecord {
                project_id: Some(PROJECT_ID.to_owned()),
                organization_id: None,
                ..valid_event()
            }),
            Err(PlatformAuditError::InvalidProjectId)
        );
        assert_eq!(
            validate_platform_audit_event_record(&PlatformAuditEventRecord {
                actor_principal_id: "acct_test".to_owned(),
                ..valid_event()
            }),
            Err(PlatformAuditError::InvalidPrincipalId)
        );
        assert_eq!(
            validate_platform_audit_event_record(&PlatformAuditEventRecord {
                reason: Some(" ".to_owned()),
                ..valid_event()
            }),
            Err(PlatformAuditError::InvalidReason)
        );
        assert_eq!(
            validate_platform_audit_event_record(&PlatformAuditEventRecord {
                created_at_unix: 0,
                ..valid_event()
            }),
            Err(PlatformAuditError::InvalidTimestamp)
        );
    }

    #[test]
    fn in_memory_audit_store_filters_by_tenant() {
        let store = InMemoryPlatformAuditStore::new();
        store
            .record_audit_event(valid_event())
            .unwrap_or_else(|error| panic!("valid audit event should record: {error:?}"));
        store
            .record_audit_event(PlatformAuditEventRecord {
                audit_event_id: "audit_other".to_owned(),
                tenant_id: "ten_other".to_owned(),
                organization_id: Some("org_other".to_owned()),
                project_id: Some("prj_other".to_owned()),
                ..valid_event()
            })
            .unwrap_or_else(|error| panic!("valid other audit event should record: {error:?}"));

        let events = store.audit_events_for_tenant(TENANT_ID);

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].audit_event_id, "audit_test");
        assert_eq!(events[0].redaction, PLATFORM_AUDIT_REDACTION_PROFILE);
    }

    fn valid_event() -> PlatformAuditEventRecord {
        PlatformAuditEventRecord {
            audit_event_id: "audit_test".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: Some(ORGANIZATION_ID.to_owned()),
            project_id: Some(PROJECT_ID.to_owned()),
            actor_principal_id: USER_ID.to_owned(),
            actor_kind: ActorKind::User,
            action_id: "platform.user.write".to_owned(),
            resource_kind: "User".to_owned(),
            resource_id: "usr_target".to_owned(),
            event_type: "platform.user.status.update".to_owned(),
            reason: Some("Operator confirmed request.".to_owned()),
            redaction: PLATFORM_AUDIT_REDACTION_PROFILE.to_owned(),
            created_at_unix: 1_700_000_000,
        }
    }
}
