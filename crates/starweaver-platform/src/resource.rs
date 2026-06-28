//! Platform business resource records exposed after authorization.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde_json::{json, Value};

use crate::storage::ResourceOwnerRecord;

/// Result type used by platform resource repositories.
pub type Result<T> = std::result::Result<T, PlatformResourceError>;

/// Platform resource repository error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformResourceError {
    /// Resource owner kind does not match the business record kind.
    ResourceKindMismatch,
    /// Resource owner id is empty.
    EmptyResourceId,
    /// Resource owner kind is empty.
    EmptyResourceKind,
}

impl PlatformResourceError {
    /// Returns a stable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ResourceKindMismatch => "resource_kind_mismatch",
            Self::EmptyResourceId => "resource_id_empty",
            Self::EmptyResourceKind => "resource_kind_empty",
        }
    }
}

/// Stored platform business resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformResourceRecord {
    /// Authorization ownership metadata for the resource.
    pub owner: ResourceOwnerRecord,
    /// Safe business projection.
    pub data: PlatformResourceData,
}

impl PlatformResourceRecord {
    /// Builds a business resource record.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformResourceError`] when the owner kind/id shape is empty
    /// or does not match the typed business data.
    pub fn new(owner: ResourceOwnerRecord, data: PlatformResourceData) -> Result<Self> {
        let record = Self { owner, data };
        validate_resource_record(&record)?;
        Ok(record)
    }

    /// Returns the safe JSON body for this resource.
    #[must_use]
    pub fn to_safe_json(&self) -> Value {
        json!({
            "kind": self.owner.resource_kind,
            "resource_id": self.owner.resource_id,
            "tenant_id": self.owner.tenant_id,
            "organization_id": self.owner.organization_id,
            "project_id": self.owner.project_id,
            "data": self.data.to_safe_json(),
        })
    }
}

/// Safe platform business data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlatformResourceData {
    /// Conversation metadata.
    Conversation(ConversationRecord),
    /// Run metadata.
    Run(RunRecord),
    /// Approval metadata.
    Approval(ApprovalRecord),
    /// Deferred tool metadata.
    DeferredTool(DeferredToolRecord),
    /// Environment attachment metadata.
    EnvironmentAttachment(EnvironmentAttachmentRecord),
    /// Evidence archive metadata.
    EvidenceArchive(EvidenceArchiveRecord),
}

impl PlatformResourceData {
    /// Returns the platform authorization resource kind for this data.
    #[must_use]
    pub const fn resource_kind(&self) -> &'static str {
        match self {
            Self::Conversation(_) => "Conversation",
            Self::Run(_) => "Run",
            Self::Approval(_) => "Approval",
            Self::DeferredTool(_) => "DeferredTool",
            Self::EnvironmentAttachment(_) => "EnvironmentAttachment",
            Self::EvidenceArchive(_) => "EvidenceArchive",
        }
    }

    /// Returns the safe JSON body for this resource data.
    #[must_use]
    pub fn to_safe_json(&self) -> Value {
        match self {
            Self::Conversation(record) => record.to_safe_json(),
            Self::Run(record) => record.to_safe_json(),
            Self::Approval(record) => record.to_safe_json(),
            Self::DeferredTool(record) => record.to_safe_json(),
            Self::EnvironmentAttachment(record) => record.to_safe_json(),
            Self::EvidenceArchive(record) => record.to_safe_json(),
        }
    }
}

/// Conversation resource projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConversationRecord {
    /// Operator-visible title.
    pub title: String,
    /// Stable status id.
    pub status: String,
}

impl ConversationRecord {
    fn to_safe_json(&self) -> Value {
        json!({
            "title": self.title,
            "status": self.status,
        })
    }
}

/// Run resource projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunRecord {
    /// Parent conversation id.
    pub conversation_id: String,
    /// Stable status id.
    pub status: String,
    /// Model egress route hint.
    pub model_alias: String,
}

impl RunRecord {
    fn to_safe_json(&self) -> Value {
        json!({
            "conversation_id": self.conversation_id,
            "status": self.status,
            "model_alias": self.model_alias,
        })
    }
}

/// Approval resource projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalRecord {
    /// Parent run id.
    pub run_id: String,
    /// Stable approval status id.
    pub status: String,
    /// Requested approval action.
    pub requested_action: String,
}

impl ApprovalRecord {
    fn to_safe_json(&self) -> Value {
        json!({
            "run_id": self.run_id,
            "status": self.status,
            "requested_action": self.requested_action,
        })
    }
}

/// Deferred tool resource projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferredToolRecord {
    /// Parent run id.
    pub run_id: String,
    /// Stable tool name.
    pub tool_name: String,
    /// Stable status id.
    pub status: String,
}

impl DeferredToolRecord {
    fn to_safe_json(&self) -> Value {
        json!({
            "run_id": self.run_id,
            "tool_name": self.tool_name,
            "status": self.status,
        })
    }
}

/// Environment attachment resource projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentAttachmentRecord {
    /// Provider-neutral lease id.
    pub lease_id: String,
    /// Stable status id.
    pub status: String,
    /// Readiness summary.
    pub readiness: String,
}

impl EnvironmentAttachmentRecord {
    fn to_safe_json(&self) -> Value {
        json!({
            "lease_id": self.lease_id,
            "status": self.status,
            "readiness": self.readiness,
        })
    }
}

/// Evidence archive resource projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceArchiveRecord {
    /// Safe object manifest URI or locator.
    pub manifest_uri: String,
    /// Stable retention class id.
    pub retention_class: String,
    /// Whether debug payloads are available to privileged readers.
    pub debug_available: bool,
}

impl EvidenceArchiveRecord {
    fn to_safe_json(&self) -> Value {
        json!({
            "manifest_uri": self.manifest_uri,
            "retention_class": self.retention_class,
            "debug_available": self.debug_available,
        })
    }
}

/// Platform business resource repository.
pub trait PlatformResourceRepository {
    /// Records or replaces a business resource.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformResourceError`] when the resource owner shape is empty
    /// or does not match the typed resource data.
    fn record_platform_resource(&self, record: PlatformResourceRecord) -> Result<()>;

    /// Loads a business resource by kind and id.
    #[must_use]
    fn platform_resource(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Option<PlatformResourceRecord>;
}

/// In-memory platform business resource store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformResourceStore {
    resources: Arc<RwLock<BTreeMap<PlatformResourceKey, PlatformResourceRecord>>>,
}

impl InMemoryPlatformResourceStore {
    /// Creates an empty business resource store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every business resource sorted by kind and id.
    #[must_use]
    pub fn platform_resources(&self) -> Vec<PlatformResourceRecord> {
        read_lock(&self.resources).values().cloned().collect()
    }
}

impl PlatformResourceRepository for InMemoryPlatformResourceStore {
    fn record_platform_resource(&self, record: PlatformResourceRecord) -> Result<()> {
        validate_resource_record(&record)?;
        write_lock(&self.resources).insert(
            PlatformResourceKey {
                resource_kind: record.owner.resource_kind.clone(),
                resource_id: record.owner.resource_id.clone(),
            },
            record,
        );
        Ok(())
    }

    fn platform_resource(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Option<PlatformResourceRecord> {
        read_lock(&self.resources)
            .get(&PlatformResourceKey {
                resource_kind: resource_kind.to_owned(),
                resource_id: resource_id.to_owned(),
            })
            .cloned()
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PlatformResourceKey {
    resource_kind: String,
    resource_id: String,
}

fn validate_resource_record(record: &PlatformResourceRecord) -> Result<()> {
    if record.owner.resource_kind.trim().is_empty() {
        return Err(PlatformResourceError::EmptyResourceKind);
    }
    if record.owner.resource_id.trim().is_empty() {
        return Err(PlatformResourceError::EmptyResourceId);
    }
    if record.owner.resource_kind != record.data.resource_kind() {
        return Err(PlatformResourceError::ResourceKindMismatch);
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
    use crate::resource::{
        ConversationRecord, InMemoryPlatformResourceStore, PlatformResourceData,
        PlatformResourceError, PlatformResourceRecord, PlatformResourceRepository, RunRecord,
    };
    use crate::storage::ResourceOwnerRecord;

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";

    #[test]
    fn resource_store_records_and_loads_business_resource() {
        let store = InMemoryPlatformResourceStore::new();
        let record = run_resource("run_test");

        assert_eq!(store.record_platform_resource(record.clone()), Ok(()));
        assert_eq!(store.platform_resource("Run", "run_test"), Some(record));
        assert_eq!(store.platform_resources().len(), 1);
    }

    #[test]
    fn resource_record_rejects_kind_mismatch() {
        let result = PlatformResourceRecord::new(
            ResourceOwnerRecord::project(
                "Run",
                "conv_test",
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            ),
            PlatformResourceData::Conversation(ConversationRecord {
                title: "Test".to_owned(),
                status: "active".to_owned(),
            }),
        );

        assert_eq!(result, Err(PlatformResourceError::ResourceKindMismatch));
        assert_eq!(
            PlatformResourceError::ResourceKindMismatch.as_str(),
            "resource_kind_mismatch"
        );
    }

    #[test]
    fn safe_json_uses_owner_scope_and_business_data() {
        let json = run_resource("run_test").to_safe_json();

        assert_eq!(json["kind"], "Run");
        assert_eq!(json["resource_id"], "run_test");
        assert_eq!(json["project_id"], PROJECT_ID);
        assert_eq!(json["data"]["status"], "running");
        assert_eq!(json["data"]["model_alias"], "default-agent");
    }

    fn run_resource(resource_id: &str) -> PlatformResourceRecord {
        PlatformResourceRecord::new(
            ResourceOwnerRecord::project(
                "Run",
                resource_id,
                TENANT_ID,
                ORGANIZATION_ID,
                PROJECT_ID,
            ),
            PlatformResourceData::Run(RunRecord {
                conversation_id: "conv_test".to_owned(),
                status: "running".to_owned(),
                model_alias: "default-agent".to_owned(),
            }),
        )
        .unwrap_or_else(|error| panic!("run resource should be valid: {error:?}"))
    }
}
