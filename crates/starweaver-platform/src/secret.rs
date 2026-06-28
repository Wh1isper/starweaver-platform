//! Platform-local secret reference contracts.

use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

/// Stable backend id for process-environment backed secrets.
pub const ENVIRONMENT_SECRET_BACKEND: &str = "environment";

/// Stable backend id for in-memory test secrets.
pub const IN_MEMORY_SECRET_BACKEND: &str = "in_memory";

/// Secret reference lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformSecretRefStatus {
    /// Secret reference can be resolved.
    Active,
    /// Secret reference is in a rotation window and can still be resolved.
    Rotating,
    /// Secret reference is administratively disabled.
    Disabled,
    /// Secret reference was soft-deleted.
    Deleted,
}

impl PlatformSecretRefStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Rotating => "rotating",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }

    /// Returns whether this status can resolve raw secret material.
    #[must_use]
    pub const fn can_resolve(self) -> bool {
        matches!(self, Self::Active | Self::Rotating)
    }
}

/// Safe secret-reference metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformSecretRefRecord {
    /// Stable secret reference id.
    pub secret_ref_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional owning organization id.
    pub organization_id: Option<String>,
    /// Optional owning project id.
    pub project_id: Option<String>,
    /// Operator-visible purpose.
    pub purpose: String,
    /// Secret backend kind.
    pub backend_kind: String,
    /// Backend locator. For environment-backed secrets this is the variable name.
    pub backend_locator: String,
    /// Safe display mask derived from the secret value.
    pub display_mask: String,
    /// Stable non-secret fingerprint derived from the secret value.
    pub fingerprint: String,
    /// Lifecycle status.
    pub status: PlatformSecretRefStatus,
}

/// Request used to create or replace safe secret-reference metadata.
pub struct CreatePlatformSecretRefRequest {
    /// Stable secret reference id.
    pub secret_ref_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Optional owning organization id.
    pub organization_id: Option<String>,
    /// Optional owning project id.
    pub project_id: Option<String>,
    /// Operator-visible purpose.
    pub purpose: String,
    /// Secret backend kind.
    pub backend_kind: String,
    /// Backend locator. For environment-backed secrets this is the variable name.
    pub backend_locator: String,
    /// Raw secret value used only by the in-memory backend.
    pub in_memory_secret_value: Option<String>,
    /// Creating principal id.
    pub created_by: String,
}

impl Debug for CreatePlatformSecretRefRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreatePlatformSecretRefRequest")
            .field("secret_ref_id", &self.secret_ref_id)
            .field("tenant_id", &self.tenant_id)
            .field("organization_id", &self.organization_id)
            .field("project_id", &self.project_id)
            .field("purpose", &self.purpose)
            .field("backend_kind", &self.backend_kind)
            .field("backend_locator", &self.backend_locator)
            .field("in_memory_secret_value", &"<redacted>")
            .field("created_by", &self.created_by)
            .finish()
    }
}

/// Resolved raw secret value.
#[derive(Clone, Eq, PartialEq)]
pub struct PlatformSecretValue {
    value: String,
}

impl PlatformSecretValue {
    /// Builds a secret value from raw material.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
        }
    }

    /// Exposes raw secret material for immediate provider calls.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }
}

impl Debug for PlatformSecretValue {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PlatformSecretValue(<redacted>)")
    }
}

/// Secret repository error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformSecretError {
    /// Secret reference id is empty.
    EmptySecretRefId,
    /// Secret reference id does not use the `sec_` prefix.
    InvalidSecretRefId,
    /// Tenant id is empty.
    EmptyTenantId,
    /// Tenant id does not use the `ten_` prefix.
    InvalidTenantId,
    /// Purpose is empty.
    EmptyPurpose,
    /// Backend kind is empty.
    EmptyBackendKind,
    /// Backend kind is not supported by this repository.
    UnsupportedBackendKind,
    /// Backend locator is empty.
    EmptyBackendLocator,
    /// Environment variable locator is invalid.
    InvalidEnvironmentVariable,
    /// Raw secret material is empty.
    EmptySecretValue,
    /// Secret reference is unknown.
    UnknownSecretRef,
    /// Secret reference is disabled or deleted.
    SecretRefInactive,
    /// Environment-backed secret is missing.
    EnvironmentSecretMissing,
    /// Environment-backed secret no longer matches the stored fingerprint.
    SecretFingerprintMismatch,
}

impl PlatformSecretError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptySecretRefId => "secret_ref_id_empty",
            Self::InvalidSecretRefId => "secret_ref_id_invalid",
            Self::EmptyTenantId => "tenant_id_empty",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::EmptyPurpose => "secret_purpose_empty",
            Self::EmptyBackendKind => "secret_backend_kind_empty",
            Self::UnsupportedBackendKind => "secret_backend_kind_unsupported",
            Self::EmptyBackendLocator => "secret_backend_locator_empty",
            Self::InvalidEnvironmentVariable => "secret_environment_variable_invalid",
            Self::EmptySecretValue => "secret_value_empty",
            Self::UnknownSecretRef => "secret_ref_unknown",
            Self::SecretRefInactive => "secret_ref_inactive",
            Self::EnvironmentSecretMissing => "secret_environment_value_missing",
            Self::SecretFingerprintMismatch => "secret_fingerprint_mismatch",
        }
    }
}

impl Display for PlatformSecretError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PlatformSecretError {}

/// Validates safe secret-reference metadata.
///
/// # Errors
///
/// Returns [`PlatformSecretError`] when the metadata shape is invalid.
pub fn validate_secret_ref_record(
    record: &PlatformSecretRefRecord,
) -> Result<(), PlatformSecretError> {
    validate_secret_ref_id(&record.secret_ref_id)?;
    validate_tenant_id(&record.tenant_id)?;
    if record.project_id.is_some() && record.organization_id.is_none() {
        return Err(PlatformSecretError::InvalidSecretRefId);
    }
    if record.purpose.trim().is_empty() {
        return Err(PlatformSecretError::EmptyPurpose);
    }
    validate_secret_backend(&record.backend_kind, &record.backend_locator)?;
    if record.display_mask.trim().is_empty() || record.fingerprint.trim().is_empty() {
        return Err(PlatformSecretError::EmptySecretValue);
    }
    Ok(())
}

/// Validates a stable secret reference id.
///
/// # Errors
///
/// Returns [`PlatformSecretError`] when the id is empty or not a `sec_` id.
pub fn validate_secret_ref_id(secret_ref_id: &str) -> Result<(), PlatformSecretError> {
    let value = secret_ref_id.trim();
    if value.is_empty() {
        return Err(PlatformSecretError::EmptySecretRefId);
    }
    if !value.starts_with("sec_") {
        return Err(PlatformSecretError::InvalidSecretRefId);
    }
    Ok(())
}

/// Creates safe metadata for a process-environment secret.
///
/// # Errors
///
/// Returns [`PlatformSecretError`] when the request is invalid or the environment
/// variable is missing.
pub fn environment_secret_ref_record(
    request: &CreatePlatformSecretRefRequest,
) -> Result<PlatformSecretRefRecord, PlatformSecretError> {
    validate_create_secret_ref_request(request, ENVIRONMENT_SECRET_BACKEND)?;
    let value = std::env::var(request.backend_locator.trim())
        .map_err(|_| PlatformSecretError::EnvironmentSecretMissing)?;
    if value.trim().is_empty() {
        return Err(PlatformSecretError::EmptySecretValue);
    }
    Ok(secret_ref_record_from_value(request, &value))
}

/// Creates safe metadata for an in-memory secret.
///
/// # Errors
///
/// Returns [`PlatformSecretError`] when the request is invalid or the raw value is
/// empty.
pub fn in_memory_secret_ref_record(
    request: &CreatePlatformSecretRefRequest,
) -> Result<(PlatformSecretRefRecord, PlatformSecretValue), PlatformSecretError> {
    validate_create_secret_ref_request(request, IN_MEMORY_SECRET_BACKEND)?;
    let value = request
        .in_memory_secret_value
        .as_deref()
        .ok_or(PlatformSecretError::EmptySecretValue)?;
    if value.trim().is_empty() {
        return Err(PlatformSecretError::EmptySecretValue);
    }
    Ok((
        secret_ref_record_from_value(request, value),
        PlatformSecretValue::new(value.to_owned()),
    ))
}

/// Resolves an environment-backed secret from safe metadata.
///
/// # Errors
///
/// Returns [`PlatformSecretError`] when the ref is inactive, unsupported, missing,
/// or no longer matches the recorded fingerprint.
pub fn resolve_environment_secret(
    record: &PlatformSecretRefRecord,
) -> Result<PlatformSecretValue, PlatformSecretError> {
    validate_secret_ref_record(record)?;
    if !record.status.can_resolve() {
        return Err(PlatformSecretError::SecretRefInactive);
    }
    if record.backend_kind != ENVIRONMENT_SECRET_BACKEND {
        return Err(PlatformSecretError::UnsupportedBackendKind);
    }
    let value = std::env::var(record.backend_locator.trim())
        .map_err(|_| PlatformSecretError::EnvironmentSecretMissing)?;
    if value.trim().is_empty() {
        return Err(PlatformSecretError::EmptySecretValue);
    }
    if secret_fingerprint(&value) != record.fingerprint {
        return Err(PlatformSecretError::SecretFingerprintMismatch);
    }
    Ok(PlatformSecretValue::new(value))
}

/// In-memory secret repository for deterministic local and test flows.
#[derive(Clone, Default)]
pub struct InMemoryPlatformSecretStore {
    records: Arc<RwLock<BTreeMap<String, InMemorySecretEntry>>>,
}

impl Debug for InMemoryPlatformSecretStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InMemoryPlatformSecretStore")
            .field("records", &read_lock(&self.records).len())
            .finish()
    }
}

impl InMemoryPlatformSecretStore {
    /// Creates an empty in-memory secret store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates or replaces one in-memory secret reference.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformSecretError`] when the request is invalid.
    pub fn create_secret_ref(
        &self,
        request: &CreatePlatformSecretRefRequest,
    ) -> Result<PlatformSecretRefRecord, PlatformSecretError> {
        let (record, value) = in_memory_secret_ref_record(request)?;
        write_lock(&self.records).insert(
            record.secret_ref_id.clone(),
            InMemorySecretEntry {
                record: record.clone(),
                value,
            },
        );
        Ok(record)
    }

    /// Records safe environment-backed metadata without storing raw material.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformSecretError`] when the request or environment value is
    /// invalid.
    pub fn create_environment_secret_ref(
        &self,
        request: &CreatePlatformSecretRefRequest,
    ) -> Result<PlatformSecretRefRecord, PlatformSecretError> {
        let record = environment_secret_ref_record(request)?;
        write_lock(&self.records).insert(
            record.secret_ref_id.clone(),
            InMemorySecretEntry {
                record: record.clone(),
                value: PlatformSecretValue::new(String::new()),
            },
        );
        Ok(record)
    }

    /// Loads safe secret-reference metadata.
    #[must_use]
    pub fn secret_ref(&self, secret_ref_id: &str) -> Option<PlatformSecretRefRecord> {
        read_lock(&self.records)
            .get(secret_ref_id)
            .map(|entry| entry.record.clone())
    }

    /// Lists safe secret-reference metadata for a tenant.
    #[must_use]
    pub fn secret_refs_for_tenant(&self, tenant_id: &str) -> Vec<PlatformSecretRefRecord> {
        read_lock(&self.records)
            .values()
            .filter(|entry| entry.record.tenant_id == tenant_id)
            .map(|entry| entry.record.clone())
            .collect()
    }

    /// Resolves raw secret material.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformSecretError`] when the secret ref is unknown, inactive, or
    /// not resolvable.
    pub fn resolve_secret(
        &self,
        secret_ref_id: &str,
    ) -> Result<PlatformSecretValue, PlatformSecretError> {
        let entry = read_lock(&self.records)
            .get(secret_ref_id)
            .cloned()
            .ok_or(PlatformSecretError::UnknownSecretRef)?;
        if !entry.record.status.can_resolve() {
            return Err(PlatformSecretError::SecretRefInactive);
        }
        match entry.record.backend_kind.as_str() {
            IN_MEMORY_SECRET_BACKEND => Ok(entry.value),
            ENVIRONMENT_SECRET_BACKEND => resolve_environment_secret(&entry.record),
            _ => Err(PlatformSecretError::UnsupportedBackendKind),
        }
    }
}

#[derive(Clone)]
struct InMemorySecretEntry {
    record: PlatformSecretRefRecord,
    value: PlatformSecretValue,
}

fn validate_create_secret_ref_request(
    request: &CreatePlatformSecretRefRequest,
    expected_backend: &str,
) -> Result<(), PlatformSecretError> {
    validate_secret_ref_id(&request.secret_ref_id)?;
    validate_tenant_id(&request.tenant_id)?;
    if request.project_id.is_some() && request.organization_id.is_none() {
        return Err(PlatformSecretError::InvalidSecretRefId);
    }
    if request.purpose.trim().is_empty() {
        return Err(PlatformSecretError::EmptyPurpose);
    }
    validate_secret_backend(&request.backend_kind, &request.backend_locator)?;
    if request.backend_kind != expected_backend {
        return Err(PlatformSecretError::UnsupportedBackendKind);
    }
    if request.created_by.trim().is_empty() {
        return Err(PlatformSecretError::EmptyTenantId);
    }
    Ok(())
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), PlatformSecretError> {
    let value = tenant_id.trim();
    if value.is_empty() {
        return Err(PlatformSecretError::EmptyTenantId);
    }
    if !value.starts_with("ten_") {
        return Err(PlatformSecretError::InvalidTenantId);
    }
    Ok(())
}

fn validate_secret_backend(
    backend_kind: &str,
    backend_locator: &str,
) -> Result<(), PlatformSecretError> {
    if backend_kind.trim().is_empty() {
        return Err(PlatformSecretError::EmptyBackendKind);
    }
    if backend_locator.trim().is_empty() {
        return Err(PlatformSecretError::EmptyBackendLocator);
    }
    match backend_kind {
        ENVIRONMENT_SECRET_BACKEND => validate_environment_variable_name(backend_locator),
        IN_MEMORY_SECRET_BACKEND => Ok(()),
        _ => Err(PlatformSecretError::UnsupportedBackendKind),
    }
}

fn validate_environment_variable_name(value: &str) -> Result<(), PlatformSecretError> {
    let value = value.trim();
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(PlatformSecretError::EmptyBackendLocator);
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(PlatformSecretError::InvalidEnvironmentVariable);
    }
    if chars.any(|value| !(value == '_' || value.is_ascii_alphanumeric())) {
        return Err(PlatformSecretError::InvalidEnvironmentVariable);
    }
    Ok(())
}

fn secret_ref_record_from_value(
    request: &CreatePlatformSecretRefRequest,
    value: &str,
) -> PlatformSecretRefRecord {
    PlatformSecretRefRecord {
        secret_ref_id: request.secret_ref_id.trim().to_owned(),
        tenant_id: request.tenant_id.trim().to_owned(),
        organization_id: request
            .organization_id
            .as_ref()
            .map(|value| value.trim().to_owned()),
        project_id: request
            .project_id
            .as_ref()
            .map(|value| value.trim().to_owned()),
        purpose: request.purpose.trim().to_owned(),
        backend_kind: request.backend_kind.trim().to_owned(),
        backend_locator: request.backend_locator.trim().to_owned(),
        display_mask: secret_display_mask(value),
        fingerprint: secret_fingerprint(value),
        status: PlatformSecretRefStatus::Active,
    }
}

fn secret_display_mask(value: &str) -> String {
    let value = value.trim();
    let suffix: String = value
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("***{suffix}")
}

fn secret_fingerprint(value: &str) -> String {
    let digest = Sha256::digest(value.trim().as_bytes());
    let mut output = String::with_capacity("sha256:".len() + 64);
    output.push_str("sha256:");
    push_lower_hex(&mut output, &digest);
    output
}

fn push_lower_hex(output: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
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
        CreatePlatformSecretRefRequest, InMemoryPlatformSecretStore, PlatformSecretError,
        ENVIRONMENT_SECRET_BACKEND, IN_MEMORY_SECRET_BACKEND,
    };

    #[test]
    fn in_memory_secret_store_redacts_debug_and_resolves_values() {
        let store = InMemoryPlatformSecretStore::new();
        let record = store
            .create_secret_ref(&CreatePlatformSecretRefRequest {
                secret_ref_id: "sec_oidc_client".to_owned(),
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                purpose: "OIDC client secret".to_owned(),
                backend_kind: IN_MEMORY_SECRET_BACKEND.to_owned(),
                backend_locator: "memory://oidc/client".to_owned(),
                in_memory_secret_value: Some("client-secret-value".to_owned()),
                created_by: "usr_test".to_owned(),
            })
            .unwrap_or_else(|error| panic!("secret ref should be valid: {error}"));

        assert_eq!(record.display_mask, "***alue");
        assert!(record.fingerprint.starts_with("sha256:"));
        assert_eq!(
            store
                .resolve_secret("sec_oidc_client")
                .unwrap_or_else(|error| panic!("secret should resolve: {error}"))
                .expose(),
            "client-secret-value"
        );
        assert!(!format!("{store:?}").contains("client-secret-value"));
    }

    #[test]
    fn environment_secret_records_verify_fingerprint_on_resolve() {
        std::env::set_var("STARWEAVER_PLATFORM_TEST_OIDC_SECRET", "environment-secret");
        let store = InMemoryPlatformSecretStore::new();
        let record = store
            .create_environment_secret_ref(&CreatePlatformSecretRefRequest {
                secret_ref_id: "sec_environment_oidc".to_owned(),
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                purpose: "OIDC client secret".to_owned(),
                backend_kind: ENVIRONMENT_SECRET_BACKEND.to_owned(),
                backend_locator: "STARWEAVER_PLATFORM_TEST_OIDC_SECRET".to_owned(),
                in_memory_secret_value: None,
                created_by: "usr_test".to_owned(),
            })
            .unwrap_or_else(|error| panic!("environment secret ref should be valid: {error}"));

        assert_eq!(
            store
                .resolve_secret(&record.secret_ref_id)
                .unwrap_or_else(|error| panic!("environment secret should resolve: {error}"))
                .expose(),
            "environment-secret"
        );
        std::env::set_var("STARWEAVER_PLATFORM_TEST_OIDC_SECRET", "changed-secret");
        let Err(error) = store.resolve_secret(&record.secret_ref_id) else {
            panic!("changed environment value should fail fingerprint check");
        };
        assert_eq!(error, PlatformSecretError::SecretFingerprintMismatch);
        std::env::remove_var("STARWEAVER_PLATFORM_TEST_OIDC_SECRET");
    }

    #[test]
    fn secret_ref_ids_must_use_secret_prefix() {
        let store = InMemoryPlatformSecretStore::new();
        let Err(error) = store.create_secret_ref(&CreatePlatformSecretRefRequest {
            secret_ref_id: "raw_secret".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: None,
            project_id: None,
            purpose: "OIDC client secret".to_owned(),
            backend_kind: IN_MEMORY_SECRET_BACKEND.to_owned(),
            backend_locator: "memory://oidc/client".to_owned(),
            in_memory_secret_value: Some("client-secret-value".to_owned()),
            created_by: "usr_test".to_owned(),
        }) else {
            panic!("raw-looking secret refs should be rejected");
        };
        assert_eq!(error, PlatformSecretError::InvalidSecretRefId);
    }
}
