//! Platform-local authentication primitives.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use sha2::{Digest, Sha256};

use crate::action::AuthenticatedActor;

/// Result type used by platform authentication boundaries.
pub type Result<T> = std::result::Result<T, AuthError>;

/// Platform authentication error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthError {
    /// Session id is empty.
    EmptySessionId,
    /// Session token hash is empty.
    EmptyTokenHash,
    /// Bearer credential id is empty.
    EmptyCredentialId,
    /// Bearer credential token hash is empty.
    EmptyCredentialTokenHash,
    /// Bearer token is empty.
    EmptyBearerToken,
    /// mTLS identity id is empty.
    EmptyMtlsIdentityId,
    /// mTLS subject is empty.
    EmptyMtlsSubject,
    /// Session token does not match an active session.
    SessionNotFound,
    /// Bearer credential token does not match an active credential.
    CredentialNotFound,
    /// mTLS subject does not match an active identity.
    MtlsIdentityNotFound,
    /// Session has been revoked.
    SessionRevoked,
    /// Bearer credential has been revoked.
    CredentialRevoked,
    /// mTLS identity has been revoked.
    MtlsIdentityRevoked,
    /// Session has expired.
    SessionExpired,
    /// Bearer credential has expired.
    CredentialExpired,
    /// mTLS identity has expired.
    MtlsIdentityExpired,
    /// Bearer credential is disabled.
    CredentialDisabled,
    /// mTLS identity is disabled.
    MtlsIdentityDisabled,
    /// Principal has been disabled.
    PrincipalDisabled,
}

impl AuthError {
    /// Returns a stable error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::EmptySessionId => "session_id_empty",
            Self::EmptyTokenHash => "session_token_hash_empty",
            Self::EmptyCredentialId => "credential_id_empty",
            Self::EmptyCredentialTokenHash => "credential_token_hash_empty",
            Self::EmptyBearerToken => "bearer_token_empty",
            Self::EmptyMtlsIdentityId => "mtls_identity_id_empty",
            Self::EmptyMtlsSubject => "mtls_subject_empty",
            Self::SessionNotFound => "auth_session_not_found",
            Self::CredentialNotFound => "bearer_credential_not_found",
            Self::MtlsIdentityNotFound => "mtls_identity_not_found",
            Self::SessionRevoked => "auth_session_revoked",
            Self::CredentialRevoked => "bearer_credential_revoked",
            Self::MtlsIdentityRevoked => "mtls_identity_revoked",
            Self::SessionExpired => "auth_session_expired",
            Self::CredentialExpired => "bearer_credential_expired",
            Self::MtlsIdentityExpired => "mtls_identity_expired",
            Self::CredentialDisabled => "bearer_credential_disabled",
            Self::MtlsIdentityDisabled => "mtls_identity_disabled",
            Self::PrincipalDisabled => "principal_disabled",
        }
    }
}

/// Platform auth session status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformAuthSessionStatus {
    /// Session can authenticate requests.
    Active,
    /// Session was explicitly revoked.
    Revoked,
    /// Session exceeded its validity window.
    Expired,
    /// Session principal is disabled.
    PrincipalDisabled,
}

impl PlatformAuthSessionStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::PrincipalDisabled => "principal_disabled",
        }
    }
}

/// Platform bearer credential kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformBearerCredentialKind {
    /// API key credential.
    ApiKey,
    /// Internal service token credential.
    ServiceToken,
}

impl PlatformBearerCredentialKind {
    /// Returns the stable credential kind id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApiKey => "api_key",
            Self::ServiceToken => "service_token",
        }
    }
}

/// Platform bearer credential status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformBearerCredentialStatus {
    /// Credential can authenticate requests.
    Active,
    /// Credential is disabled.
    Disabled,
    /// Credential was explicitly revoked.
    Revoked,
    /// Credential exceeded its validity window.
    Expired,
    /// Credential principal is disabled.
    PrincipalDisabled,
}

impl PlatformBearerCredentialStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::PrincipalDisabled => "principal_disabled",
        }
    }
}

/// Platform mTLS identity status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformMtlsIdentityStatus {
    /// Identity can authenticate requests.
    Active,
    /// Identity is disabled.
    Disabled,
    /// Identity was explicitly revoked.
    Revoked,
    /// Identity exceeded its validity window.
    Expired,
    /// Identity principal is disabled.
    PrincipalDisabled,
}

impl PlatformMtlsIdentityStatus {
    /// Returns the stable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::PrincipalDisabled => "principal_disabled",
        }
    }
}

/// Stored platform bearer credential metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformBearerCredentialRecord {
    /// Stable credential id.
    pub credential_id: String,
    /// Credential kind.
    pub credential_kind: PlatformBearerCredentialKind,
    /// Hash of the raw bearer credential.
    pub token_hash: String,
    /// Actor resolved by this credential.
    pub actor: AuthenticatedActor,
    /// Credential status.
    pub status: PlatformBearerCredentialStatus,
}

impl PlatformBearerCredentialRecord {
    /// Builds an active API key credential from a raw bearer token.
    #[must_use]
    pub fn active_api_key(
        credential_id: impl Into<String>,
        raw_token: &str,
        actor: AuthenticatedActor,
    ) -> Self {
        Self::active(
            credential_id,
            PlatformBearerCredentialKind::ApiKey,
            raw_token,
            actor,
        )
    }

    /// Builds an active service token credential from a raw bearer token.
    #[must_use]
    pub fn active_service_token(
        credential_id: impl Into<String>,
        raw_token: &str,
        actor: AuthenticatedActor,
    ) -> Self {
        Self::active(
            credential_id,
            PlatformBearerCredentialKind::ServiceToken,
            raw_token,
            actor,
        )
    }

    /// Builds an active bearer credential from a raw bearer token.
    #[must_use]
    pub fn active(
        credential_id: impl Into<String>,
        credential_kind: PlatformBearerCredentialKind,
        raw_token: &str,
        actor: AuthenticatedActor,
    ) -> Self {
        Self {
            credential_id: credential_id.into(),
            credential_kind,
            token_hash: hash_bearer_credential_token(raw_token),
            actor,
            status: PlatformBearerCredentialStatus::Active,
        }
    }

    /// Returns a copy of this credential with a different status.
    #[must_use]
    pub const fn with_status(mut self, status: PlatformBearerCredentialStatus) -> Self {
        self.status = status;
        self
    }
}

/// Stored platform auth session metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformAuthSessionRecord {
    /// Stable session id.
    pub session_id: String,
    /// Hash of the raw bearer token.
    pub token_hash: String,
    /// Actor resolved by this session.
    pub actor: AuthenticatedActor,
    /// Session status.
    pub status: PlatformAuthSessionStatus,
}

impl PlatformAuthSessionRecord {
    /// Builds an active session record from a raw bearer token.
    #[must_use]
    pub fn active(
        session_id: impl Into<String>,
        raw_token: &str,
        actor: AuthenticatedActor,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            token_hash: hash_session_token(raw_token),
            actor,
            status: PlatformAuthSessionStatus::Active,
        }
    }

    /// Returns a copy of this session with a different status.
    #[must_use]
    pub const fn with_status(mut self, status: PlatformAuthSessionStatus) -> Self {
        self.status = status;
        self
    }
}

/// Stored platform mTLS identity metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformMtlsIdentityRecord {
    /// Stable mTLS identity id.
    pub identity_id: String,
    /// Verified client certificate subject or SPIFFE id.
    pub subject: String,
    /// Actor resolved by this identity.
    pub actor: AuthenticatedActor,
    /// Identity status.
    pub status: PlatformMtlsIdentityStatus,
}

impl PlatformMtlsIdentityRecord {
    /// Builds an active mTLS identity from a verified subject.
    #[must_use]
    pub fn active(
        identity_id: impl Into<String>,
        subject: impl Into<String>,
        actor: AuthenticatedActor,
    ) -> Self {
        Self {
            identity_id: identity_id.into(),
            subject: subject.into(),
            actor,
            status: PlatformMtlsIdentityStatus::Active,
        }
    }

    /// Returns a copy of this identity with a different status.
    #[must_use]
    pub const fn with_status(mut self, status: PlatformMtlsIdentityStatus) -> Self {
        self.status = status;
        self
    }
}

/// Authentication session repository.
pub trait PlatformAuthSessionRepository {
    /// Records or replaces an auth session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the session id or token hash is missing.
    fn record_auth_session(&self, record: PlatformAuthSessionRecord) -> Result<()>;

    /// Resolves a raw bearer token to an authenticated actor.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the bearer token is missing, unknown, revoked,
    /// expired, or tied to a disabled principal.
    fn authenticated_actor_for_bearer(&self, raw_bearer: &str) -> Result<AuthenticatedActor>;
}

/// Bearer credential repository.
pub trait PlatformBearerCredentialRepository {
    /// Records or replaces a bearer credential.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the credential id or token hash is missing.
    fn record_bearer_credential(&self, record: PlatformBearerCredentialRecord) -> Result<()>;

    /// Resolves a raw bearer token to an authenticated actor.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the bearer token is missing, unknown, revoked,
    /// disabled, expired, or tied to a disabled principal.
    fn authenticated_actor_for_bearer_credential(
        &self,
        raw_bearer: &str,
    ) -> Result<AuthenticatedActor>;
}

/// mTLS identity repository.
pub trait PlatformMtlsIdentityRepository {
    /// Records or replaces an mTLS identity.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the identity id or subject is missing.
    fn record_mtls_identity(&self, record: PlatformMtlsIdentityRecord) -> Result<()>;

    /// Resolves a verified mTLS subject to an authenticated actor.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the subject is missing, unknown, revoked,
    /// disabled, expired, or tied to a disabled principal.
    fn authenticated_actor_for_mtls_subject(&self, subject: &str) -> Result<AuthenticatedActor>;
}

/// In-memory platform auth session store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformAuthSessionStore {
    sessions: Arc<RwLock<BTreeMap<String, PlatformAuthSessionRecord>>>,
}

impl InMemoryPlatformAuthSessionStore {
    /// Creates an empty auth session store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every session sorted by token hash.
    #[must_use]
    pub fn auth_sessions(&self) -> Vec<PlatformAuthSessionRecord> {
        read_lock(&self.sessions).values().cloned().collect()
    }

    /// Resolves a raw bearer token to an active auth session record.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the bearer token is missing, unknown, revoked,
    /// expired, or tied to a disabled principal.
    pub fn auth_session_for_bearer(&self, raw_bearer: &str) -> Result<PlatformAuthSessionRecord> {
        let raw_bearer = raw_bearer.trim();
        if raw_bearer.is_empty() {
            return Err(AuthError::EmptyBearerToken);
        }
        let token_hash = hash_session_token(raw_bearer);
        let Some(record) = read_lock(&self.sessions).get(&token_hash).cloned() else {
            return Err(AuthError::SessionNotFound);
        };
        active_session_record(record)
    }

    /// Revokes an active auth session by raw bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the bearer token does not resolve to an active
    /// session.
    pub fn revoke_auth_session_by_bearer(
        &self,
        raw_bearer: &str,
    ) -> Result<PlatformAuthSessionRecord> {
        let raw_bearer = raw_bearer.trim();
        if raw_bearer.is_empty() {
            return Err(AuthError::EmptyBearerToken);
        }
        let token_hash = hash_session_token(raw_bearer);
        let mut sessions = write_lock(&self.sessions);
        let record = sessions
            .get_mut(&token_hash)
            .ok_or(AuthError::SessionNotFound)?;
        match record.status {
            PlatformAuthSessionStatus::Active => {
                record.status = PlatformAuthSessionStatus::Revoked;
                let revoked = record.clone();
                drop(sessions);
                Ok(revoked)
            }
            PlatformAuthSessionStatus::Revoked => Err(AuthError::SessionRevoked),
            PlatformAuthSessionStatus::Expired => Err(AuthError::SessionExpired),
            PlatformAuthSessionStatus::PrincipalDisabled => Err(AuthError::PrincipalDisabled),
        }
    }

    /// Updates an active session's organization and project context.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError`] when the bearer token does not resolve to an active
    /// session.
    pub fn update_auth_session_context_by_bearer(
        &self,
        raw_bearer: &str,
        organization_id: Option<String>,
        project_id: Option<String>,
    ) -> Result<PlatformAuthSessionRecord> {
        let raw_bearer = raw_bearer.trim();
        if raw_bearer.is_empty() {
            return Err(AuthError::EmptyBearerToken);
        }
        let token_hash = hash_session_token(raw_bearer);
        let mut sessions = write_lock(&self.sessions);
        let record = sessions
            .get_mut(&token_hash)
            .ok_or(AuthError::SessionNotFound)?;
        match record.status {
            PlatformAuthSessionStatus::Active => {
                record.actor.organization_id = organization_id;
                record.actor.project_id = project_id;
                let updated = record.clone();
                drop(sessions);
                Ok(updated)
            }
            PlatformAuthSessionStatus::Revoked => Err(AuthError::SessionRevoked),
            PlatformAuthSessionStatus::Expired => Err(AuthError::SessionExpired),
            PlatformAuthSessionStatus::PrincipalDisabled => Err(AuthError::PrincipalDisabled),
        }
    }
}

impl PlatformAuthSessionRepository for InMemoryPlatformAuthSessionStore {
    fn record_auth_session(&self, record: PlatformAuthSessionRecord) -> Result<()> {
        validate_session_record(&record)?;
        write_lock(&self.sessions).insert(record.token_hash.clone(), record);
        Ok(())
    }

    fn authenticated_actor_for_bearer(&self, raw_bearer: &str) -> Result<AuthenticatedActor> {
        self.auth_session_for_bearer(raw_bearer)
            .map(|record| record.actor)
    }
}

/// In-memory platform bearer credential store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformBearerCredentialStore {
    credentials: Arc<RwLock<BTreeMap<String, PlatformBearerCredentialRecord>>>,
}

impl InMemoryPlatformBearerCredentialStore {
    /// Creates an empty bearer credential store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every bearer credential sorted by token hash.
    #[must_use]
    pub fn bearer_credentials(&self) -> Vec<PlatformBearerCredentialRecord> {
        read_lock(&self.credentials).values().cloned().collect()
    }
}

impl PlatformBearerCredentialRepository for InMemoryPlatformBearerCredentialStore {
    fn record_bearer_credential(&self, record: PlatformBearerCredentialRecord) -> Result<()> {
        validate_bearer_credential_record(&record)?;
        write_lock(&self.credentials).insert(record.token_hash.clone(), record);
        Ok(())
    }

    fn authenticated_actor_for_bearer_credential(
        &self,
        raw_bearer: &str,
    ) -> Result<AuthenticatedActor> {
        let raw_bearer = raw_bearer.trim();
        if raw_bearer.is_empty() {
            return Err(AuthError::EmptyBearerToken);
        }
        let token_hash = hash_bearer_credential_token(raw_bearer);
        let Some(record) = read_lock(&self.credentials).get(&token_hash).cloned() else {
            return Err(AuthError::CredentialNotFound);
        };
        match record.status {
            PlatformBearerCredentialStatus::Active => Ok(record.actor),
            PlatformBearerCredentialStatus::Disabled => Err(AuthError::CredentialDisabled),
            PlatformBearerCredentialStatus::Revoked => Err(AuthError::CredentialRevoked),
            PlatformBearerCredentialStatus::Expired => Err(AuthError::CredentialExpired),
            PlatformBearerCredentialStatus::PrincipalDisabled => Err(AuthError::PrincipalDisabled),
        }
    }
}

/// In-memory platform mTLS identity store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformMtlsIdentityStore {
    identities: Arc<RwLock<BTreeMap<String, PlatformMtlsIdentityRecord>>>,
}

impl InMemoryPlatformMtlsIdentityStore {
    /// Creates an empty mTLS identity store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns every mTLS identity sorted by subject.
    #[must_use]
    pub fn mtls_identities(&self) -> Vec<PlatformMtlsIdentityRecord> {
        read_lock(&self.identities).values().cloned().collect()
    }
}

impl PlatformMtlsIdentityRepository for InMemoryPlatformMtlsIdentityStore {
    fn record_mtls_identity(&self, record: PlatformMtlsIdentityRecord) -> Result<()> {
        validate_mtls_identity_record(&record)?;
        write_lock(&self.identities).insert(record.subject.clone(), record);
        Ok(())
    }

    fn authenticated_actor_for_mtls_subject(&self, subject: &str) -> Result<AuthenticatedActor> {
        let subject = subject.trim();
        if subject.is_empty() {
            return Err(AuthError::EmptyMtlsSubject);
        }
        let Some(record) = read_lock(&self.identities).get(subject).cloned() else {
            return Err(AuthError::MtlsIdentityNotFound);
        };
        match record.status {
            PlatformMtlsIdentityStatus::Active => Ok(record.actor),
            PlatformMtlsIdentityStatus::Disabled => Err(AuthError::MtlsIdentityDisabled),
            PlatformMtlsIdentityStatus::Revoked => Err(AuthError::MtlsIdentityRevoked),
            PlatformMtlsIdentityStatus::Expired => Err(AuthError::MtlsIdentityExpired),
            PlatformMtlsIdentityStatus::PrincipalDisabled => Err(AuthError::PrincipalDisabled),
        }
    }
}

/// Hashes a raw platform session token for storage or lookup.
#[must_use]
pub fn hash_session_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"starweaver-platform-session-v1\0");
    hasher.update(raw_token.as_bytes());
    lower_hex(&hasher.finalize())
}

/// Hashes a raw platform API key or service token for storage or lookup.
#[must_use]
pub fn hash_bearer_credential_token(raw_token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"starweaver-platform-bearer-credential-v1\0");
    hasher.update(raw_token.as_bytes());
    lower_hex(&hasher.finalize())
}

fn validate_session_record(record: &PlatformAuthSessionRecord) -> Result<()> {
    if record.session_id.trim().is_empty() {
        return Err(AuthError::EmptySessionId);
    }
    if record.token_hash.trim().is_empty() {
        return Err(AuthError::EmptyTokenHash);
    }
    Ok(())
}

fn active_session_record(record: PlatformAuthSessionRecord) -> Result<PlatformAuthSessionRecord> {
    match record.status {
        PlatformAuthSessionStatus::Active => Ok(record),
        PlatformAuthSessionStatus::Revoked => Err(AuthError::SessionRevoked),
        PlatformAuthSessionStatus::Expired => Err(AuthError::SessionExpired),
        PlatformAuthSessionStatus::PrincipalDisabled => Err(AuthError::PrincipalDisabled),
    }
}

fn validate_bearer_credential_record(record: &PlatformBearerCredentialRecord) -> Result<()> {
    if record.credential_id.trim().is_empty() {
        return Err(AuthError::EmptyCredentialId);
    }
    if record.token_hash.trim().is_empty() {
        return Err(AuthError::EmptyCredentialTokenHash);
    }
    Ok(())
}

fn validate_mtls_identity_record(record: &PlatformMtlsIdentityRecord) -> Result<()> {
    if record.identity_id.trim().is_empty() {
        return Err(AuthError::EmptyMtlsIdentityId);
    }
    if record.subject.trim().is_empty() {
        return Err(AuthError::EmptyMtlsSubject);
    }
    Ok(())
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
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
    use crate::action::AuthenticatedActor;
    use crate::auth::{
        hash_bearer_credential_token, hash_session_token, AuthError,
        InMemoryPlatformAuthSessionStore, InMemoryPlatformBearerCredentialStore,
        InMemoryPlatformMtlsIdentityStore, PlatformAuthSessionRecord,
        PlatformAuthSessionRepository, PlatformAuthSessionStatus, PlatformBearerCredentialKind,
        PlatformBearerCredentialRecord, PlatformBearerCredentialRepository,
        PlatformBearerCredentialStatus, PlatformMtlsIdentityRecord, PlatformMtlsIdentityRepository,
        PlatformMtlsIdentityStatus,
    };

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const USER_ID: &str = "usr_test";
    const SERVICE_ACCOUNT_ID: &str = "svc_test";
    const RAW_TOKEN: &str = "platform-session-token";
    const API_KEY_TOKEN: &str = "platform-api-key-token";
    const SERVICE_TOKEN: &str = "platform-service-token";
    const MTLS_SUBJECT: &str = "spiffe://platform.test/ns/default/sa/platform-worker";

    #[test]
    fn auth_session_hashes_raw_token_for_storage() {
        let actor = actor();
        let record = PlatformAuthSessionRecord::active("sess_test", RAW_TOKEN, actor);

        assert_ne!(record.token_hash, RAW_TOKEN);
        assert_eq!(record.token_hash.len(), 64);
        assert!(record
            .token_hash
            .chars()
            .all(|character| character.is_ascii_hexdigit()));
        assert_eq!(record.token_hash, hash_session_token(RAW_TOKEN));
    }

    #[test]
    fn active_session_resolves_actor_from_bearer_token() {
        let store = InMemoryPlatformAuthSessionStore::new();
        let actor = actor();
        assert_eq!(
            store.record_auth_session(PlatformAuthSessionRecord::active(
                "sess_test",
                RAW_TOKEN,
                actor.clone(),
            )),
            Ok(())
        );

        assert_eq!(store.authenticated_actor_for_bearer(RAW_TOKEN), Ok(actor));
        assert_eq!(store.auth_sessions().len(), 1);
    }

    #[test]
    fn unknown_or_revoked_session_is_rejected() {
        let store = InMemoryPlatformAuthSessionStore::new();
        assert_eq!(
            store.record_auth_session(
                PlatformAuthSessionRecord::active("sess_test", RAW_TOKEN, actor())
                    .with_status(PlatformAuthSessionStatus::Revoked),
            ),
            Ok(())
        );

        assert_eq!(
            store.authenticated_actor_for_bearer("different-token"),
            Err(AuthError::SessionNotFound)
        );
        assert_eq!(
            store.authenticated_actor_for_bearer(RAW_TOKEN),
            Err(AuthError::SessionRevoked)
        );
    }

    #[test]
    fn invalid_session_records_are_rejected() {
        let store = InMemoryPlatformAuthSessionStore::new();
        assert_eq!(
            store.record_auth_session(PlatformAuthSessionRecord {
                session_id: String::new(),
                token_hash: hash_session_token(RAW_TOKEN),
                actor: actor(),
                status: PlatformAuthSessionStatus::Active,
            }),
            Err(AuthError::EmptySessionId)
        );
        assert_eq!(AuthError::EmptySessionId.as_str(), "session_id_empty");
        assert_eq!(PlatformAuthSessionStatus::Active.as_str(), "active");
    }

    #[test]
    fn bearer_credentials_hash_raw_token_for_storage() {
        let record =
            PlatformBearerCredentialRecord::active_api_key("apikey_test", API_KEY_TOKEN, actor());

        assert_ne!(record.token_hash, API_KEY_TOKEN);
        assert_eq!(record.token_hash.len(), 64);
        assert_eq!(
            record.token_hash,
            hash_bearer_credential_token(API_KEY_TOKEN)
        );
        assert_ne!(record.token_hash, hash_session_token(API_KEY_TOKEN));
        assert_eq!(record.credential_kind, PlatformBearerCredentialKind::ApiKey);
        assert_eq!(record.credential_kind.as_str(), "api_key");
    }

    #[test]
    fn api_key_credential_resolves_actor_from_bearer_token() {
        let store = InMemoryPlatformBearerCredentialStore::new();
        let actor = actor();
        assert_eq!(
            store.record_bearer_credential(PlatformBearerCredentialRecord::active_api_key(
                "apikey_test",
                API_KEY_TOKEN,
                actor.clone(),
            )),
            Ok(())
        );

        assert_eq!(
            store.authenticated_actor_for_bearer_credential(API_KEY_TOKEN),
            Ok(actor)
        );
        assert_eq!(store.bearer_credentials().len(), 1);
    }

    #[test]
    fn service_token_credential_resolves_service_account_actor() {
        let store = InMemoryPlatformBearerCredentialStore::new();
        let actor = service_account_actor();
        assert_eq!(
            store.record_bearer_credential(PlatformBearerCredentialRecord::active_service_token(
                "svctok_test",
                SERVICE_TOKEN,
                actor.clone(),
            )),
            Ok(())
        );

        assert_eq!(
            store.authenticated_actor_for_bearer_credential(SERVICE_TOKEN),
            Ok(actor)
        );
    }

    #[test]
    fn disabled_or_unknown_bearer_credential_is_rejected() {
        let store = InMemoryPlatformBearerCredentialStore::new();
        assert_eq!(
            store.record_bearer_credential(
                PlatformBearerCredentialRecord::active(
                    "svctok_test",
                    PlatformBearerCredentialKind::ServiceToken,
                    SERVICE_TOKEN,
                    service_account_actor(),
                )
                .with_status(PlatformBearerCredentialStatus::Disabled),
            ),
            Ok(())
        );

        assert_eq!(
            store.authenticated_actor_for_bearer_credential("different-token"),
            Err(AuthError::CredentialNotFound)
        );
        assert_eq!(
            store.authenticated_actor_for_bearer_credential(SERVICE_TOKEN),
            Err(AuthError::CredentialDisabled)
        );
        assert_eq!(PlatformBearerCredentialStatus::Active.as_str(), "active");
    }

    #[test]
    fn invalid_bearer_credential_records_are_rejected() {
        let store = InMemoryPlatformBearerCredentialStore::new();
        assert_eq!(
            store.record_bearer_credential(PlatformBearerCredentialRecord {
                credential_id: String::new(),
                credential_kind: PlatformBearerCredentialKind::ApiKey,
                token_hash: hash_bearer_credential_token(API_KEY_TOKEN),
                actor: actor(),
                status: PlatformBearerCredentialStatus::Active,
            }),
            Err(AuthError::EmptyCredentialId)
        );
        assert_eq!(AuthError::EmptyCredentialId.as_str(), "credential_id_empty");
    }

    #[test]
    fn active_mtls_identity_resolves_actor_from_verified_subject() {
        let store = InMemoryPlatformMtlsIdentityStore::new();
        let actor = service_account_actor();
        assert_eq!(
            store.record_mtls_identity(PlatformMtlsIdentityRecord::active(
                "mtls_test",
                MTLS_SUBJECT,
                actor.clone(),
            )),
            Ok(())
        );

        assert_eq!(
            store.authenticated_actor_for_mtls_subject(MTLS_SUBJECT),
            Ok(actor)
        );
        assert_eq!(store.mtls_identities().len(), 1);
    }

    #[test]
    fn disabled_or_unknown_mtls_identity_is_rejected() {
        let store = InMemoryPlatformMtlsIdentityStore::new();
        assert_eq!(
            store.record_mtls_identity(
                PlatformMtlsIdentityRecord::active(
                    "mtls_test",
                    MTLS_SUBJECT,
                    service_account_actor(),
                )
                .with_status(PlatformMtlsIdentityStatus::Revoked),
            ),
            Ok(())
        );

        assert_eq!(
            store.authenticated_actor_for_mtls_subject("spiffe://platform.test/unknown"),
            Err(AuthError::MtlsIdentityNotFound)
        );
        assert_eq!(
            store.authenticated_actor_for_mtls_subject(MTLS_SUBJECT),
            Err(AuthError::MtlsIdentityRevoked)
        );
        assert_eq!(PlatformMtlsIdentityStatus::Active.as_str(), "active");
    }

    #[test]
    fn invalid_mtls_identity_records_are_rejected() {
        let store = InMemoryPlatformMtlsIdentityStore::new();
        assert_eq!(
            store.record_mtls_identity(PlatformMtlsIdentityRecord {
                identity_id: String::new(),
                subject: MTLS_SUBJECT.to_owned(),
                actor: service_account_actor(),
                status: PlatformMtlsIdentityStatus::Active,
            }),
            Err(AuthError::EmptyMtlsIdentityId)
        );
        assert_eq!(
            store.authenticated_actor_for_mtls_subject(" "),
            Err(AuthError::EmptyMtlsSubject)
        );
        assert_eq!(AuthError::EmptyMtlsSubject.as_str(), "mtls_subject_empty");
    }

    fn actor() -> AuthenticatedActor {
        AuthenticatedActor::project_user(TENANT_ID, ORGANIZATION_ID, PROJECT_ID, USER_ID)
    }

    fn service_account_actor() -> AuthenticatedActor {
        AuthenticatedActor::project_service_account(
            TENANT_ID,
            ORGANIZATION_ID,
            PROJECT_ID,
            SERVICE_ACCOUNT_ID,
        )
    }
}
