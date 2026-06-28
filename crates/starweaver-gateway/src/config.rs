//! Config snapshot publication and rollback foundation.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::domain::{new_prefixed_id, ConfigSnapshot, ConfigSnapshotStatus, TenantId};
use crate::error::{GatewayError, Result};
use crate::policy::validate_cedar_policy_bundle;
use crate::storage::ConfigSnapshotStore;

/// Immutable config snapshot document consumed by runtime workers.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConfigSnapshotDocument {
    /// Schema id for snapshot documents.
    pub schema: String,
    /// Resource version map included in the snapshot.
    pub resource_versions: Vec<ResourceVersion>,
    /// Validated config payload.
    pub payload: Value,
    /// Source snapshot id when this snapshot was produced by rollback.
    pub rollback_of: Option<String>,
}

/// Resource version included in an immutable config snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceVersion {
    /// Resource kind.
    pub resource_kind: String,
    /// Resource id.
    pub resource_id: String,
    /// Resource version.
    pub version: i64,
}

/// Published config snapshot metadata plus immutable document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishedConfigSnapshot {
    /// Snapshot metadata.
    pub metadata: ConfigSnapshot,
    /// Immutable snapshot document.
    pub document: ConfigSnapshotDocument,
    /// Actor that created the snapshot.
    pub created_by: String,
    /// Publication timestamp.
    pub published_at: DateTime<Utc>,
}

/// Request to publish a validated config document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublishConfigSnapshotRequest {
    /// Tenant boundary.
    pub tenant_id: TenantId,
    /// Resource version map included in the snapshot.
    pub resource_versions: Vec<ResourceVersion>,
    /// Validated config payload.
    pub payload: Value,
    /// Actor creating the snapshot.
    pub created_by: String,
}

/// Publishes a new config snapshot with the next tenant version.
pub fn publish_config_snapshot(
    store: &dyn ConfigSnapshotStore,
    request: PublishConfigSnapshotRequest,
    now: DateTime<Utc>,
) -> Result<PublishedConfigSnapshot> {
    validate_config_snapshot_payload(&request.payload)?;
    let document = ConfigSnapshotDocument {
        schema: "gateway.config_snapshot.v1".to_owned(),
        resource_versions: request.resource_versions,
        payload: request.payload,
        rollback_of: None,
    };
    publish_document(store, request.tenant_id, document, request.created_by, now)
}

/// Publishes rollback content as a new snapshot version.
pub fn rollback_config_snapshot(
    store: &dyn ConfigSnapshotStore,
    tenant_id: TenantId,
    source_snapshot_id: &str,
    created_by: String,
    now: DateTime<Utc>,
) -> Result<PublishedConfigSnapshot> {
    let source =
        store
            .config_snapshot(source_snapshot_id)
            .ok_or_else(|| GatewayError::NotFound {
                resource: format!("config snapshot {source_snapshot_id}"),
            })?;
    if source.metadata.tenant_id != tenant_id {
        return Err(GatewayError::Authorization {
            reason: "snapshot_tenant_mismatch",
        });
    }
    let mut document = source.document;
    document.rollback_of = Some(source_snapshot_id.to_owned());
    publish_document(store, tenant_id, document, created_by, now)
}

/// Validates a config snapshot payload without publishing it.
pub fn validate_config_snapshot_payload(payload: &Value) -> Result<()> {
    if let Some(policy_bundle) = payload.get("cedar_policy_bundle") {
        let Some(policy_bundle) = policy_bundle.as_str() else {
            return Err(GatewayError::BadRequest {
                message: "cedar_policy_bundle must be a string".to_owned(),
            });
        };
        validate_cedar_policy_bundle(policy_bundle)?;
    }
    Ok(())
}

fn publish_document(
    store: &dyn ConfigSnapshotStore,
    tenant_id: TenantId,
    document: ConfigSnapshotDocument,
    created_by: String,
    now: DateTime<Utc>,
) -> Result<PublishedConfigSnapshot> {
    let version = store
        .latest_published_snapshot_for_tenant(&tenant_id)
        .map_or(1, |snapshot| snapshot.version + 1);
    let snapshot = PublishedConfigSnapshot {
        metadata: ConfigSnapshot {
            snapshot_id: new_prefixed_id("cfg"),
            tenant_id,
            version,
            checksum: snapshot_checksum(&document)?,
            status: ConfigSnapshotStatus::Published,
            compiled_at: now,
        },
        document,
        created_by,
        published_at: now,
    };
    store.insert_config_snapshot(snapshot.clone());
    Ok(snapshot)
}

fn snapshot_checksum(document: &ConfigSnapshotDocument) -> Result<String> {
    let bytes = serde_json::to_vec(document).map_err(|error| GatewayError::Internal {
        message: format!("failed to encode config snapshot: {error}"),
    })?;
    let digest = Sha256::digest(bytes);
    Ok(format!("sha256:{digest:x}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::config::{
        publish_config_snapshot, rollback_config_snapshot, PublishConfigSnapshotRequest,
        ResourceVersion,
    };
    use crate::domain::ConfigReloadSource;
    use crate::storage::{ConfigPublicationRepository, InMemoryGatewayStore};

    fn request() -> PublishConfigSnapshotRequest {
        PublishConfigSnapshotRequest {
            tenant_id: "ten_test".to_owned(),
            resource_versions: vec![ResourceVersion {
                resource_kind: "ModelAlias".to_owned(),
                resource_id: "ma_test".to_owned(),
                version: 7,
            }],
            payload: json!({
                "model_aliases": [
                    {"id": "ma_test", "name": "gpt-test"}
                ]
            }),
            created_by: "usr_test".to_owned(),
        }
    }

    #[test]
    fn publishing_snapshot_increments_versions() {
        let store = InMemoryGatewayStore::default();
        let first = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("first snapshot should publish: {error}"),
        };
        let second = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("second snapshot should publish: {error}"),
        };

        assert_eq!(first.metadata.version, 1);
        assert_eq!(second.metadata.version, 2);
        assert_ne!(first.metadata.snapshot_id, second.metadata.snapshot_id);
        assert_eq!(store.config_snapshots().len(), 2);
    }

    #[test]
    fn publication_writes_pointer_and_invalidation_event() {
        let store = InMemoryGatewayStore::default();
        let snapshot = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("snapshot should publish: {error}"),
        };

        let pointer = store
            .config_publication("ten_test")
            .unwrap_or_else(|| panic!("publication pointer should be present"));
        let invalidations = store.config_invalidation_events_for_tenant("ten_test");

        assert_eq!(pointer.snapshot_id, snapshot.metadata.snapshot_id);
        assert_eq!(pointer.version, 1);
        assert_eq!(pointer.checksum, snapshot.metadata.checksum);
        assert_eq!(invalidations.len(), 1);
        assert_eq!(invalidations[0].snapshot_id, snapshot.metadata.snapshot_id);
        assert_eq!(invalidations[0].version, 1);
        assert_eq!(invalidations[0].invalidation_id, pointer.invalidation_id);
    }

    #[test]
    fn worker_polling_converges_after_missed_invalidation() {
        let store = InMemoryGatewayStore::default();
        let first = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("first snapshot should publish: {error}"),
        };
        let first_invalidation = store
            .config_invalidation_events_for_tenant("ten_test")
            .pop()
            .unwrap_or_else(|| panic!("first invalidation should be present"));
        let initial_reload = match store.reload_config_worker_from_invalidation(
            "ten_test",
            "gateway-runtime",
            &first_invalidation.invalidation_id,
            first.published_at,
        ) {
            Ok(record) => record,
            Err(error) => panic!("initial reload should record: {error}"),
        };
        assert_eq!(initial_reload.loaded_version, 1);
        assert_eq!(
            initial_reload.reload_source,
            ConfigReloadSource::Invalidation
        );

        let second = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("second snapshot should publish: {error}"),
        };
        let polled_reload = match store.reload_config_worker_by_polling(
            "ten_test",
            "gateway-runtime",
            second.published_at + chrono::Duration::milliseconds(37),
        ) {
            Ok(record) => record,
            Err(error) => panic!("polling reload should record: {error}"),
        };

        assert_eq!(polled_reload.snapshot_id, second.metadata.snapshot_id);
        assert_eq!(polled_reload.loaded_version, 2);
        assert_eq!(polled_reload.reload_source, ConfigReloadSource::Polling);
        assert_eq!(polled_reload.missed_invalidation_count, 1);
        assert_eq!(polled_reload.publication_lag_ms, 37);
        assert_eq!(polled_reload.last_known_good_version, 2);
    }

    #[test]
    fn rollback_creates_new_snapshot_version() {
        let store = InMemoryGatewayStore::default();
        let first = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("snapshot should publish: {error}"),
        };
        let rollback = match rollback_config_snapshot(
            &store,
            "ten_test".to_owned(),
            &first.metadata.snapshot_id,
            "usr_test".to_owned(),
            chrono::Utc::now(),
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("rollback should publish: {error}"),
        };

        assert_eq!(rollback.metadata.version, 2);
        assert_eq!(
            rollback.document.rollback_of.as_deref(),
            Some(first.metadata.snapshot_id.as_str())
        );
        assert_eq!(
            store
                .config_publication("ten_test")
                .map(|pointer| pointer.snapshot_id),
            Some(rollback.metadata.snapshot_id)
        );
    }

    #[test]
    fn equivalent_snapshot_documents_have_stable_checksum() {
        let left_store = InMemoryGatewayStore::default();
        let right_store = InMemoryGatewayStore::default();

        let left = match publish_config_snapshot(&left_store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("left snapshot should publish: {error}"),
        };
        let right = match publish_config_snapshot(&right_store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("right snapshot should publish: {error}"),
        };

        assert_eq!(left.metadata.checksum, right.metadata.checksum);
        assert!(left.metadata.checksum.starts_with("sha256:"));
    }

    #[test]
    fn publishing_snapshot_validates_cedar_policy_bundle() {
        let store = InMemoryGatewayStore::default();
        let mut request = request();
        request.payload["cedar_policy_bundle"] = json!(
            r#"
            permit (
                principal is Gateway::ApiKey,
                action == Gateway::Action::"gateway.model.invoke",
                resource is Gateway::ModelAlias
            );
            "#
        );

        let snapshot = match publish_config_snapshot(&store, request, chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("valid policy bundle should publish: {error}"),
        };

        assert_eq!(snapshot.metadata.version, 1);
        assert_eq!(store.config_snapshots().len(), 1);
    }

    #[test]
    fn publishing_snapshot_rejects_invalid_cedar_policy_bundle() {
        let store = InMemoryGatewayStore::default();
        let mut request = request();
        request.payload["cedar_policy_bundle"] = json!(
            r#"
            permit (
                principal is Gateway::ApiKey,
                action == Gateway::Action::"gateway.unknown",
                resource is Gateway::ModelAlias
            );
            "#
        );

        let Err(error) = publish_config_snapshot(&store, request, chrono::Utc::now()) else {
            panic!("invalid policy bundle should not publish");
        };

        assert!(error
            .to_string()
            .contains("cedar policy bundle validation failed"));
        assert!(store.config_snapshots().is_empty());
    }

    #[test]
    fn publishing_snapshot_rejects_non_string_cedar_policy_bundle() {
        let store = InMemoryGatewayStore::default();
        let mut request = request();
        request.payload["cedar_policy_bundle"] = json!({});

        let Err(error) = publish_config_snapshot(&store, request, chrono::Utc::now()) else {
            panic!("non-string policy bundle should not publish");
        };

        assert!(error
            .to_string()
            .contains("cedar_policy_bundle must be a string"));
        assert!(store.config_snapshots().is_empty());
    }

    #[test]
    fn rollback_rejects_cross_tenant_source_snapshot() {
        let store = InMemoryGatewayStore::default();
        let first = match publish_config_snapshot(&store, request(), chrono::Utc::now()) {
            Ok(snapshot) => snapshot,
            Err(error) => panic!("snapshot should publish: {error}"),
        };

        assert!(rollback_config_snapshot(
            &store,
            "ten_other".to_owned(),
            &first.metadata.snapshot_id,
            "usr_test".to_owned(),
            chrono::Utc::now(),
        )
        .is_err());
    }
}
