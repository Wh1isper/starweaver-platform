//! Platform-local identity provider contracts.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};

use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Generic `OIDC` login provider status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcLoginProviderStatus {
    /// Provider can start and complete login attempts.
    Active,
    /// Provider is disabled.
    Disabled,
    /// Provider has been deleted.
    Deleted,
}

impl OidcLoginProviderStatus {
    /// Returns the durable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
            Self::Deleted => "deleted",
        }
    }
}

/// Durable `OIDC` login-attempt status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcLoginAttemptStatus {
    /// Login attempt can still complete.
    Active,
    /// Login attempt completed successfully.
    Consumed,
    /// Login attempt exceeded its validity window.
    Expired,
    /// Login attempt was abandoned or superseded.
    Abandoned,
}

impl OidcLoginAttemptStatus {
    /// Returns the durable status id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Consumed => "consumed",
            Self::Expired => "expired",
            Self::Abandoned => "abandoned",
        }
    }
}

/// Token endpoint authentication method for generic `OIDC` login providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OidcTokenEndpointAuthMethod {
    /// Public client with no client secret.
    None,
    /// Confidential client using HTTP Basic authentication.
    ClientSecretBasic,
    /// Confidential client sending `client_secret` in the form body.
    ClientSecretPost,
}

impl OidcTokenEndpointAuthMethod {
    /// Returns the stable method id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
        }
    }

    /// Parses a stable method id.
    #[must_use]
    pub fn from_id(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "client_secret_basic" => Some(Self::ClientSecretBasic),
            "client_secret_post" => Some(Self::ClientSecretPost),
            _ => None,
        }
    }

    /// Returns whether the method requires a client secret.
    #[must_use]
    pub const fn requires_client_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }
}

/// Tenant-owned generic `OIDC` login provider configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLoginProviderRecord {
    /// Stable identity provider id.
    pub identity_provider_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Operator-facing display name.
    pub display_name: String,
    /// Expected issuer URL.
    pub issuer_url: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// JWKS endpoint URL.
    pub jwks_uri: String,
    /// `OIDC` client id.
    pub client_id: String,
    /// Optional secret reference for confidential clients.
    pub client_secret_ref: Option<String>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: OidcTokenEndpointAuthMethod,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Requested OAuth scopes.
    pub requested_scopes: Vec<String>,
    /// Accepted `OIDC` audiences.
    pub accepted_audiences: Vec<String>,
    /// Provider status.
    pub status: OidcLoginProviderStatus,
}

/// `OIDC` discovery metadata document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct OidcDiscoveryDocument {
    /// Issuer URL advertised by discovery.
    pub issuer: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// JWKS endpoint URL.
    pub jwks_uri: String,
    /// Supported ID-token signing algorithms.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

/// Resolved `OIDC` provider metadata used by login start and callback flows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcResolvedProviderMetadata {
    /// Stable identity provider id.
    pub identity_provider_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Expected issuer URL.
    pub issuer_url: String,
    /// Authorization endpoint URL.
    pub authorization_endpoint: String,
    /// Token endpoint URL.
    pub token_endpoint: String,
    /// JWKS endpoint URL.
    pub jwks_uri: String,
    /// `OIDC` client id.
    pub client_id: String,
    /// Optional secret reference for confidential clients.
    pub client_secret_ref: Option<String>,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: OidcTokenEndpointAuthMethod,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Accepted `OIDC` audiences.
    pub accepted_audiences: Vec<String>,
    /// Accepted asymmetric ID-token signing algorithms.
    pub supported_id_token_algorithms: Vec<String>,
}

/// Transient raw values used to start an `OIDC` login attempt.
///
/// This type intentionally does not implement [`Debug`] because it carries raw
/// state, nonce, and `PKCE` verifier material. Persist only
/// [`OidcLoginAttemptRecord`].
#[derive(Clone, Eq, PartialEq)]
pub struct OidcLoginAttemptStart {
    /// Stable login attempt id.
    pub login_attempt_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Owning identity provider id.
    pub identity_provider_id: String,
    /// Raw OAuth state value.
    pub raw_state: String,
    /// Raw `OIDC` nonce value.
    pub raw_nonce: String,
    /// Raw `PKCE` code verifier value.
    pub raw_pkce_verifier: String,
    /// Redirect URI used for this login attempt.
    pub redirect_uri: String,
    /// Expiration time as a Unix timestamp in seconds.
    pub expires_at_unix: i64,
}

/// Durable `OIDC` login attempt metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLoginAttemptRecord {
    /// Stable login attempt id.
    pub login_attempt_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Owning identity provider id.
    pub identity_provider_id: String,
    /// Hash of the raw OAuth state value.
    pub state_hash: String,
    /// Hash of the raw `OIDC` nonce value.
    pub nonce_hash: String,
    /// Hash of the raw `PKCE` code verifier value.
    pub pkce_verifier_hash: String,
    /// Redirect URI used for this login attempt.
    pub redirect_uri: String,
    /// Login attempt status.
    pub status: OidcLoginAttemptStatus,
    /// Expiration time as a Unix timestamp in seconds.
    pub expires_at_unix: i64,
    /// Completion time as a Unix timestamp in seconds.
    pub consumed_at_unix: Option<i64>,
}

impl OidcLoginAttemptRecord {
    /// Builds an active durable attempt from raw transient login values.
    ///
    /// # Errors
    ///
    /// Returns [`OidcValidationError`] when raw state, nonce, verifier, ids, or
    /// redirect metadata are invalid.
    pub fn active(start: OidcLoginAttemptStart) -> Result<Self, OidcValidationError> {
        validate_raw_secret(&start.raw_state, OidcValidationError::EmptyState)?;
        validate_raw_secret(&start.raw_nonce, OidcValidationError::EmptyNonce)?;
        validate_raw_secret(
            &start.raw_pkce_verifier,
            OidcValidationError::EmptyPkceVerifier,
        )?;
        let record = Self {
            login_attempt_id: start.login_attempt_id,
            tenant_id: start.tenant_id,
            identity_provider_id: start.identity_provider_id,
            state_hash: hash_oidc_login_state(&start.raw_state),
            nonce_hash: hash_oidc_login_nonce(&start.raw_nonce),
            pkce_verifier_hash: hash_oidc_pkce_verifier(&start.raw_pkce_verifier),
            redirect_uri: start.redirect_uri,
            status: OidcLoginAttemptStatus::Active,
            expires_at_unix: start.expires_at_unix,
            consumed_at_unix: None,
        };
        validate_oidc_login_attempt_record(&record)?;
        Ok(record)
    }

    /// Returns a copy of this attempt with a different status.
    #[must_use]
    pub const fn with_status(mut self, status: OidcLoginAttemptStatus) -> Self {
        self.status = status;
        self
    }

    /// Returns a copy of this attempt marked consumed.
    #[must_use]
    pub const fn consumed(mut self, consumed_at_unix: i64) -> Self {
        self.status = OidcLoginAttemptStatus::Consumed;
        self.consumed_at_unix = Some(consumed_at_unix);
        self
    }
}

/// Verified `OIDC` claims after signature validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcVerifiedClaims {
    /// Issuer claim.
    pub issuer: String,
    /// Subject claim.
    pub subject: String,
    /// Audience claims.
    pub audiences: Vec<String>,
    /// Nonce claim.
    pub nonce: String,
    /// Expiration time as a Unix timestamp in seconds.
    pub expires_at_unix: i64,
    /// Optional email claim.
    pub email: Option<String>,
    /// Whether the email was provider-verified.
    pub email_verified: bool,
    /// Optional display name claim.
    pub display_name: Option<String>,
}

/// Platform-local external identity lifecycle status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformExternalIdentityStatus {
    /// Identity can authenticate the linked principal.
    Active,
    /// Identity is temporarily disabled.
    Disabled,
    /// Identity has been unlinked or deleted.
    Deleted,
}

impl PlatformExternalIdentityStatus {
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

/// Platform-local external identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformExternalIdentityRecord {
    /// Stable external identity id.
    pub external_identity_id: String,
    /// Owning tenant id.
    pub tenant_id: String,
    /// Local principal linked to the provider subject.
    pub principal_id: String,
    /// Login identity provider id.
    pub identity_provider_id: String,
    /// Provider kind, such as `oidc` or `single_user`.
    pub provider_kind: String,
    /// Provider-local subject.
    pub provider_subject: String,
    /// Optional normalized email observed from the provider.
    pub email: Option<String>,
    /// Whether the provider asserted the email as verified.
    pub email_verified: bool,
    /// Link lifecycle status.
    pub status: PlatformExternalIdentityStatus,
}

/// Platform external identity repository error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlatformExternalIdentityError {
    /// External identity id is malformed.
    InvalidExternalIdentityId,
    /// Tenant id is malformed.
    InvalidTenantId,
    /// Principal id is malformed.
    InvalidPrincipalId,
    /// Identity provider id is malformed.
    InvalidProviderId,
    /// Provider kind is unsupported.
    InvalidProviderKind,
    /// Provider subject is empty.
    SubjectRequired,
    /// Email shape is invalid.
    InvalidEmail,
    /// Status is unsupported.
    InvalidStatus,
    /// Existing provider subject is linked to another principal.
    PrincipalMismatch,
}

impl PlatformExternalIdentityError {
    /// Returns the stable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidExternalIdentityId => "external_identity_id_invalid",
            Self::InvalidTenantId => "tenant_id_invalid",
            Self::InvalidPrincipalId => "principal_id_invalid",
            Self::InvalidProviderId => "identity_provider_id_invalid",
            Self::InvalidProviderKind => "provider_kind_invalid",
            Self::SubjectRequired => "provider_subject_required",
            Self::InvalidEmail => "email_invalid",
            Self::InvalidStatus => "external_identity_status_invalid",
            Self::PrincipalMismatch => "external_identity_principal_mismatch",
        }
    }
}

impl Display for PlatformExternalIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for PlatformExternalIdentityError {}

/// In-memory external identity store.
#[derive(Clone, Debug, Default)]
pub struct InMemoryPlatformExternalIdentityStore {
    external_identities: Arc<RwLock<BTreeMap<String, PlatformExternalIdentityRecord>>>,
}

impl InMemoryPlatformExternalIdentityStore {
    /// Creates an empty external identity store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records or replaces an external identity.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformExternalIdentityError`] when the record shape is invalid.
    pub fn record_external_identity(
        &self,
        record: PlatformExternalIdentityRecord,
    ) -> Result<(), PlatformExternalIdentityError> {
        validate_external_identity(&record)?;
        write_lock(&self.external_identities).insert(record.external_identity_id.clone(), record);
        Ok(())
    }

    /// Creates or reactivates an external identity for the same provider subject.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformExternalIdentityError::PrincipalMismatch`] if the
    /// provider subject is already linked to a different principal.
    pub fn upsert_external_identity(
        &self,
        record: PlatformExternalIdentityRecord,
    ) -> Result<PlatformExternalIdentityRecord, PlatformExternalIdentityError> {
        validate_external_identity(&record)?;
        let mut records = write_lock(&self.external_identities);
        let existing_id = records
            .values()
            .find(|existing| {
                existing.tenant_id == record.tenant_id
                    && existing.identity_provider_id == record.identity_provider_id
                    && existing.provider_subject == record.provider_subject
            })
            .map(|existing| existing.external_identity_id.clone());

        let upserted = if let Some(existing_id) = existing_id {
            let existing = records
                .get_mut(&existing_id)
                .ok_or(PlatformExternalIdentityError::InvalidExternalIdentityId)?;
            if existing.principal_id != record.principal_id {
                return Err(PlatformExternalIdentityError::PrincipalMismatch);
            }
            existing.provider_kind = record.provider_kind;
            existing.email = record.email;
            existing.email_verified = record.email_verified;
            existing.status = PlatformExternalIdentityStatus::Active;
            existing.clone()
        } else {
            records.insert(record.external_identity_id.clone(), record.clone());
            record
        };
        drop(records);
        validate_external_identity(&upserted)?;
        Ok(upserted)
    }

    /// Lists non-deleted external identities for one principal.
    #[must_use]
    pub fn external_identities_for_principal(
        &self,
        tenant_id: &str,
        principal_id: &str,
    ) -> Vec<PlatformExternalIdentityRecord> {
        let mut records = read_lock(&self.external_identities)
            .values()
            .filter(|record| {
                record.tenant_id == tenant_id
                    && record.principal_id == principal_id
                    && record.status != PlatformExternalIdentityStatus::Deleted
            })
            .cloned()
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.external_identity_id.cmp(&right.external_identity_id));
        records
    }

    /// Loads an external identity by id.
    #[must_use]
    pub fn external_identity(
        &self,
        external_identity_id: &str,
    ) -> Option<PlatformExternalIdentityRecord> {
        read_lock(&self.external_identities)
            .get(external_identity_id)
            .cloned()
    }

    /// Marks an external identity deleted.
    ///
    /// # Errors
    ///
    /// Returns [`PlatformExternalIdentityError::InvalidExternalIdentityId`] when
    /// the identity is unknown.
    pub fn unlink_external_identity(
        &self,
        external_identity_id: &str,
    ) -> Result<PlatformExternalIdentityRecord, PlatformExternalIdentityError> {
        let mut records = write_lock(&self.external_identities);
        let record = records
            .get_mut(external_identity_id)
            .ok_or(PlatformExternalIdentityError::InvalidExternalIdentityId)?;
        record.status = PlatformExternalIdentityStatus::Deleted;
        let unlinked = record.clone();
        drop(records);
        validate_external_identity(&unlinked)?;
        Ok(unlinked)
    }
}

#[derive(Clone, Debug, Deserialize)]
struct OidcIdTokenClaims {
    iss: String,
    sub: String,
    aud: OidcAudience,
    exp: i64,
    nonce: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: bool,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum OidcAudience {
    Single(String),
    Multiple(Vec<String>),
}

impl OidcAudience {
    fn values(&self) -> Vec<String> {
        match self {
            Self::Single(audience) => vec![audience.clone()],
            Self::Multiple(audiences) => audiences.clone(),
        }
    }
}

/// `OIDC` validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OidcValidationError {
    /// Identity provider id is empty or malformed.
    InvalidProviderId,
    /// Tenant id is empty or malformed.
    InvalidTenantId,
    /// Login attempt id is empty or malformed.
    InvalidLoginAttemptId,
    /// Organization id is empty or malformed.
    InvalidOrganizationId,
    /// Project id is empty or malformed.
    InvalidProjectId,
    /// User id is empty or malformed.
    InvalidUserId,
    /// External identity id is empty or malformed.
    InvalidExternalIdentityId,
    /// Membership id is empty or malformed.
    InvalidMembershipId,
    /// Role binding id is empty or malformed.
    InvalidRoleBindingId,
    /// Display name is empty.
    DisplayNameRequired,
    /// Issuer URL is missing or unsafe.
    InvalidIssuerUrl,
    /// Authorization endpoint URL is missing or unsafe.
    InvalidAuthorizationEndpoint,
    /// Token endpoint URL is missing or unsafe.
    InvalidTokenEndpoint,
    /// JWKS URI is missing or unsafe.
    InvalidJwksUri,
    /// Discovery issuer does not match the configured issuer.
    DiscoveryIssuerMismatch,
    /// Discovery metadata did not advertise a usable asymmetric signing algorithm.
    UnsupportedSigningAlgorithm,
    /// ID token signing key is missing or ambiguous.
    SigningKeyNotFound,
    /// ID token cannot be decoded or verified.
    InvalidIdToken,
    /// Client id is empty.
    ClientIdRequired,
    /// Client secret reference is empty when present.
    InvalidClientSecretRef,
    /// Token endpoint authentication method is unsupported or inconsistent.
    InvalidTokenEndpointAuthMethod,
    /// Redirect URI is missing or unsafe.
    InvalidRedirectUri,
    /// Requested scopes must include `openid`.
    OpenIdScopeRequired,
    /// Accepted audiences are empty.
    AudienceRequired,
    /// Provider is not active.
    ProviderInactive,
    /// Raw state value is empty.
    EmptyState,
    /// Raw nonce value is empty.
    EmptyNonce,
    /// Raw `PKCE` verifier value is empty.
    EmptyPkceVerifier,
    /// Stored state hash is missing or malformed.
    InvalidStateHash,
    /// Stored nonce hash is missing or malformed.
    InvalidNonceHash,
    /// Stored `PKCE` verifier hash is missing or malformed.
    InvalidPkceVerifierHash,
    /// Login attempt expiry is missing or invalid.
    InvalidAttemptExpiry,
    /// Consumed login attempts must include a completion timestamp.
    ConsumedAtRequired,
    /// Unconsumed login attempts must not include a completion timestamp.
    ConsumedAtUnexpected,
    /// Claim issuer does not match the provider.
    IssuerMismatch,
    /// Claim subject is empty.
    SubjectRequired,
    /// Claim audiences do not match accepted provider audiences.
    AudienceMismatch,
    /// Claim nonce does not match the login attempt.
    NonceMismatch,
    /// Claim is expired.
    TokenExpired,
}

impl OidcValidationError {
    /// Returns the stable validation error code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidProviderId => "oidc_provider_id_invalid",
            Self::InvalidTenantId => "oidc_tenant_id_invalid",
            Self::InvalidLoginAttemptId => "oidc_login_attempt_id_invalid",
            Self::InvalidOrganizationId => "oidc_organization_id_invalid",
            Self::InvalidProjectId => "oidc_project_id_invalid",
            Self::InvalidUserId => "oidc_user_id_invalid",
            Self::InvalidExternalIdentityId => "oidc_external_identity_id_invalid",
            Self::InvalidMembershipId => "oidc_membership_id_invalid",
            Self::InvalidRoleBindingId => "oidc_role_binding_id_invalid",
            Self::DisplayNameRequired => "oidc_display_name_required",
            Self::InvalidIssuerUrl => "oidc_issuer_url_invalid",
            Self::InvalidAuthorizationEndpoint => "oidc_authorization_endpoint_invalid",
            Self::InvalidTokenEndpoint => "oidc_token_endpoint_invalid",
            Self::InvalidJwksUri => "oidc_jwks_uri_invalid",
            Self::DiscoveryIssuerMismatch => "oidc_discovery_issuer_mismatch",
            Self::UnsupportedSigningAlgorithm => "oidc_signing_algorithm_unsupported",
            Self::SigningKeyNotFound => "oidc_signing_key_not_found",
            Self::InvalidIdToken => "oidc_id_token_invalid",
            Self::ClientIdRequired => "oidc_client_id_required",
            Self::InvalidClientSecretRef => "oidc_client_secret_ref_invalid",
            Self::InvalidTokenEndpointAuthMethod => "oidc_token_endpoint_auth_method_invalid",
            Self::InvalidRedirectUri => "oidc_redirect_uri_invalid",
            Self::OpenIdScopeRequired => "oidc_openid_scope_required",
            Self::AudienceRequired => "oidc_audience_required",
            Self::ProviderInactive => "oidc_provider_inactive",
            Self::EmptyState => "oidc_state_empty",
            Self::EmptyNonce => "oidc_nonce_empty",
            Self::EmptyPkceVerifier => "oidc_pkce_verifier_empty",
            Self::InvalidStateHash => "oidc_state_hash_invalid",
            Self::InvalidNonceHash => "oidc_nonce_hash_invalid",
            Self::InvalidPkceVerifierHash => "oidc_pkce_verifier_hash_invalid",
            Self::InvalidAttemptExpiry => "oidc_attempt_expiry_invalid",
            Self::ConsumedAtRequired => "oidc_consumed_at_required",
            Self::ConsumedAtUnexpected => "oidc_consumed_at_unexpected",
            Self::IssuerMismatch => "oidc_issuer_mismatch",
            Self::SubjectRequired => "oidc_subject_required",
            Self::AudienceMismatch => "oidc_audience_mismatch",
            Self::NonceMismatch => "oidc_nonce_mismatch",
            Self::TokenExpired => "oidc_token_expired",
        }
    }
}

impl Display for OidcValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for OidcValidationError {}

/// Validates a tenant-owned generic `OIDC` login provider configuration.
///
/// # Errors
///
/// Returns [`OidcValidationError`] when required provider fields are missing,
/// malformed, or inactive.
pub fn validate_oidc_login_provider(
    provider: &OidcLoginProviderRecord,
) -> Result<(), OidcValidationError> {
    if !provider.identity_provider_id.starts_with("idp_") {
        return Err(OidcValidationError::InvalidProviderId);
    }
    if !provider.tenant_id.starts_with("ten_") {
        return Err(OidcValidationError::InvalidTenantId);
    }
    if provider.display_name.trim().is_empty() {
        return Err(OidcValidationError::DisplayNameRequired);
    }
    validate_https_url(&provider.issuer_url, OidcValidationError::InvalidIssuerUrl)?;
    validate_https_url(
        &provider.authorization_endpoint,
        OidcValidationError::InvalidAuthorizationEndpoint,
    )?;
    validate_https_url(
        &provider.token_endpoint,
        OidcValidationError::InvalidTokenEndpoint,
    )?;
    validate_https_url(&provider.jwks_uri, OidcValidationError::InvalidJwksUri)?;
    if provider.client_id.trim().is_empty() {
        return Err(OidcValidationError::ClientIdRequired);
    }
    validate_optional_client_secret_ref(provider.client_secret_ref.as_deref())?;
    validate_token_endpoint_auth_method(provider)?;
    validate_https_url(
        &provider.redirect_uri,
        OidcValidationError::InvalidRedirectUri,
    )?;
    if !provider
        .requested_scopes
        .iter()
        .any(|scope| scope == "openid")
    {
        return Err(OidcValidationError::OpenIdScopeRequired);
    }
    if provider
        .accepted_audiences
        .iter()
        .all(|audience| audience.trim().is_empty())
    {
        return Err(OidcValidationError::AudienceRequired);
    }
    if provider.status != OidcLoginProviderStatus::Active {
        return Err(OidcValidationError::ProviderInactive);
    }
    Ok(())
}

/// Resolves configured and discovered `OIDC` provider metadata.
///
/// Explicit provider endpoints take precedence. A discovery document can supply
/// missing authorization, token, or JWKS endpoints, but its issuer must match
/// the configured issuer.
///
/// # Errors
///
/// Returns [`OidcValidationError`] when base provider fields are invalid,
/// discovery issuer does not match, resolved endpoints are unsafe, or no
/// asymmetric ID-token signing algorithm is usable.
pub fn resolve_oidc_provider_metadata(
    provider: &OidcLoginProviderRecord,
    discovery: Option<&OidcDiscoveryDocument>,
) -> Result<OidcResolvedProviderMetadata, OidcValidationError> {
    validate_oidc_login_provider_base(provider)?;
    if discovery
        .as_ref()
        .is_some_and(|document| document.issuer != provider.issuer_url)
    {
        return Err(OidcValidationError::DiscoveryIssuerMismatch);
    }

    let authorization_endpoint = resolved_metadata_field(
        &provider.authorization_endpoint,
        discovery.map(|document| document.authorization_endpoint.as_str()),
        OidcValidationError::InvalidAuthorizationEndpoint,
    )?;
    let token_endpoint = resolved_metadata_field(
        &provider.token_endpoint,
        discovery.map(|document| document.token_endpoint.as_str()),
        OidcValidationError::InvalidTokenEndpoint,
    )?;
    let jwks_uri = resolved_metadata_field(
        &provider.jwks_uri,
        discovery.map(|document| document.jwks_uri.as_str()),
        OidcValidationError::InvalidJwksUri,
    )?;
    validate_https_url(
        &authorization_endpoint,
        OidcValidationError::InvalidAuthorizationEndpoint,
    )?;
    validate_https_url(&token_endpoint, OidcValidationError::InvalidTokenEndpoint)?;
    validate_https_url(&jwks_uri, OidcValidationError::InvalidJwksUri)?;
    let supported_id_token_algorithms = supported_oidc_algorithms(discovery)?;

    Ok(OidcResolvedProviderMetadata {
        identity_provider_id: provider.identity_provider_id.clone(),
        tenant_id: provider.tenant_id.clone(),
        issuer_url: provider.issuer_url.clone(),
        authorization_endpoint,
        token_endpoint,
        jwks_uri,
        client_id: provider.client_id.clone(),
        client_secret_ref: provider.client_secret_ref.clone(),
        token_endpoint_auth_method: provider.token_endpoint_auth_method,
        redirect_uri: provider.redirect_uri.clone(),
        accepted_audiences: provider.accepted_audiences.clone(),
        supported_id_token_algorithms,
    })
}

/// Returns the default discovery URL for an issuer.
#[must_use]
pub fn oidc_discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

/// Validates durable `OIDC` login-attempt metadata.
///
/// # Errors
///
/// Returns [`OidcValidationError`] when ids, hashes, redirect metadata, expiry,
/// or consumed-state metadata are invalid.
pub fn validate_oidc_login_attempt_record(
    record: &OidcLoginAttemptRecord,
) -> Result<(), OidcValidationError> {
    if !record.login_attempt_id.starts_with("ola_") {
        return Err(OidcValidationError::InvalidLoginAttemptId);
    }
    if !record.tenant_id.starts_with("ten_") {
        return Err(OidcValidationError::InvalidTenantId);
    }
    if !record.identity_provider_id.starts_with("idp_") {
        return Err(OidcValidationError::InvalidProviderId);
    }
    validate_hash(&record.state_hash, OidcValidationError::InvalidStateHash)?;
    validate_hash(&record.nonce_hash, OidcValidationError::InvalidNonceHash)?;
    validate_hash(
        &record.pkce_verifier_hash,
        OidcValidationError::InvalidPkceVerifierHash,
    )?;
    validate_https_url(
        &record.redirect_uri,
        OidcValidationError::InvalidRedirectUri,
    )?;
    if record.expires_at_unix <= 0 {
        return Err(OidcValidationError::InvalidAttemptExpiry);
    }
    match (record.status, record.consumed_at_unix) {
        (OidcLoginAttemptStatus::Consumed, None) => Err(OidcValidationError::ConsumedAtRequired),
        (OidcLoginAttemptStatus::Consumed, Some(_))
        | (
            OidcLoginAttemptStatus::Active
            | OidcLoginAttemptStatus::Expired
            | OidcLoginAttemptStatus::Abandoned,
            None,
        ) => Ok(()),
        (_, Some(_)) => Err(OidcValidationError::ConsumedAtUnexpected),
    }
}

/// Validates signed `OIDC` claims against provider and login-attempt state.
///
/// # Errors
///
/// Returns [`OidcValidationError`] when the provider is invalid, claims do not
/// match issuer/audience/nonce requirements, or the token is expired.
pub fn validate_oidc_verified_claims(
    provider: &OidcLoginProviderRecord,
    claims: &OidcVerifiedClaims,
    expected_nonce: &str,
    now_unix: i64,
) -> Result<(), OidcValidationError> {
    validate_oidc_login_provider(provider)?;
    if claims.issuer != provider.issuer_url {
        return Err(OidcValidationError::IssuerMismatch);
    }
    if claims.subject.trim().is_empty() {
        return Err(OidcValidationError::SubjectRequired);
    }
    if !claims.audiences.iter().any(|audience| {
        provider
            .accepted_audiences
            .iter()
            .any(|accepted| accepted == audience)
    }) {
        return Err(OidcValidationError::AudienceMismatch);
    }
    if claims.nonce != expected_nonce {
        return Err(OidcValidationError::NonceMismatch);
    }
    if claims.expires_at_unix <= now_unix {
        return Err(OidcValidationError::TokenExpired);
    }
    Ok(())
}

/// Validates an `OIDC` ID token using resolved metadata and a JWKS document.
///
/// # Errors
///
/// Returns [`OidcValidationError`] when the token header, signing algorithm,
/// signing key, signature, issuer, audience, nonce, subject, or expiration are
/// invalid.
pub fn validate_oidc_id_token(
    metadata: &OidcResolvedProviderMetadata,
    jwks: &JwkSet,
    id_token: &str,
    expected_nonce: &str,
    now_unix: i64,
) -> Result<OidcVerifiedClaims, OidcValidationError> {
    let header = decode_header(id_token).map_err(|_| OidcValidationError::InvalidIdToken)?;
    let algorithm = header.alg;
    let supports_algorithm = metadata
        .supported_id_token_algorithms
        .iter()
        .filter_map(|value| oidc_algorithm_from_str(value))
        .any(|supported| supported == algorithm);
    if !supports_algorithm || !oidc_algorithm_is_asymmetric(algorithm) {
        return Err(OidcValidationError::UnsupportedSigningAlgorithm);
    }
    let jwk = select_oidc_jwk(jwks, header.kid.as_deref(), algorithm)?;
    let decoding_key =
        DecodingKey::from_jwk(jwk).map_err(|_| OidcValidationError::InvalidIdToken)?;
    let mut validation = Validation::new(algorithm);
    validation.set_issuer(&[metadata.issuer_url.as_str()]);
    let accepted_audiences = metadata
        .accepted_audiences
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    validation.set_audience(&accepted_audiences);
    validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    validation.validate_exp = false;
    let token = decode::<OidcIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(|_| OidcValidationError::InvalidIdToken)?;
    let claims = OidcVerifiedClaims {
        issuer: token.claims.iss,
        subject: token.claims.sub,
        audiences: token.claims.aud.values(),
        nonce: token.claims.nonce,
        expires_at_unix: token.claims.exp,
        email: token.claims.email,
        email_verified: token.claims.email_verified,
        display_name: token.claims.name.or(token.claims.preferred_username),
    };
    validate_oidc_claims_against_metadata(metadata, &claims, expected_nonce, now_unix)?;
    Ok(claims)
}

/// Hashes a raw OAuth state value for durable `OIDC` login-attempt storage.
#[must_use]
pub fn hash_oidc_login_state(raw_state: &str) -> String {
    hash_oidc_secret(b"starweaver-platform-oidc-state-v1\0", raw_state)
}

/// Hashes a raw `OIDC` nonce value for durable login-attempt storage.
#[must_use]
pub fn hash_oidc_login_nonce(raw_nonce: &str) -> String {
    hash_oidc_secret(b"starweaver-platform-oidc-nonce-v1\0", raw_nonce)
}

/// Hashes a raw `PKCE` code verifier for durable login-attempt storage.
#[must_use]
pub fn hash_oidc_pkce_verifier(raw_pkce_verifier: &str) -> String {
    hash_oidc_secret(
        b"starweaver-platform-oidc-pkce-verifier-v1\0",
        raw_pkce_verifier,
    )
}

/// Validates platform-local external identity metadata.
///
/// # Errors
///
/// Returns [`PlatformExternalIdentityError`] when ids, provider subject, email,
/// provider kind, or status are invalid.
pub fn validate_external_identity(
    record: &PlatformExternalIdentityRecord,
) -> Result<(), PlatformExternalIdentityError> {
    validate_prefixed(
        &record.external_identity_id,
        "xid_",
        PlatformExternalIdentityError::InvalidExternalIdentityId,
    )?;
    validate_prefixed(
        &record.tenant_id,
        "ten_",
        PlatformExternalIdentityError::InvalidTenantId,
    )?;
    validate_prefixed(
        &record.principal_id,
        "usr_",
        PlatformExternalIdentityError::InvalidPrincipalId,
    )?;
    validate_prefixed(
        &record.identity_provider_id,
        "idp_",
        PlatformExternalIdentityError::InvalidProviderId,
    )?;
    match record.provider_kind.as_str() {
        "oidc" | "single_user" => {}
        _ => return Err(PlatformExternalIdentityError::InvalidProviderKind),
    }
    if record.provider_subject.trim().is_empty() {
        return Err(PlatformExternalIdentityError::SubjectRequired);
    }
    if let Some(email) = record.email.as_deref() {
        let email = email.trim();
        if email.is_empty()
            || !email.contains('@')
            || email.starts_with('@')
            || email.ends_with('@')
        {
            return Err(PlatformExternalIdentityError::InvalidEmail);
        }
    }
    Ok(())
}

fn validate_https_url(value: &str, error: OidcValidationError) -> Result<(), OidcValidationError> {
    let value = value.trim();
    if value.starts_with("https://") && value.len() > "https://".len() {
        Ok(())
    } else {
        Err(error)
    }
}

fn validate_optional_client_secret_ref(
    client_secret_ref: Option<&str>,
) -> Result<(), OidcValidationError> {
    if let Some(value) = client_secret_ref {
        let value = value.trim();
        if value.is_empty() || !value.starts_with("sec_") {
            return Err(OidcValidationError::InvalidClientSecretRef);
        }
    }
    Ok(())
}

const fn validate_token_endpoint_auth_method(
    provider: &OidcLoginProviderRecord,
) -> Result<(), OidcValidationError> {
    let has_secret_ref = provider.client_secret_ref.is_some();
    if provider.token_endpoint_auth_method.requires_client_secret() && !has_secret_ref {
        return Err(OidcValidationError::InvalidTokenEndpointAuthMethod);
    }
    if !provider.token_endpoint_auth_method.requires_client_secret() && has_secret_ref {
        return Err(OidcValidationError::InvalidTokenEndpointAuthMethod);
    }
    Ok(())
}

/// Validates tenant-owned `OIDC` provider fields that do not require endpoint resolution.
///
/// # Errors
///
/// Returns [`OidcValidationError`] when ids, issuer, client id, redirect URI,
/// scope, audience, or token endpoint auth configuration are invalid.
pub fn validate_oidc_login_provider_base(
    provider: &OidcLoginProviderRecord,
) -> Result<(), OidcValidationError> {
    if !provider.identity_provider_id.starts_with("idp_") {
        return Err(OidcValidationError::InvalidProviderId);
    }
    if !provider.tenant_id.starts_with("ten_") {
        return Err(OidcValidationError::InvalidTenantId);
    }
    if provider.display_name.trim().is_empty() {
        return Err(OidcValidationError::DisplayNameRequired);
    }
    validate_https_url(&provider.issuer_url, OidcValidationError::InvalidIssuerUrl)?;
    if provider.client_id.trim().is_empty() {
        return Err(OidcValidationError::ClientIdRequired);
    }
    validate_optional_client_secret_ref(provider.client_secret_ref.as_deref())?;
    validate_token_endpoint_auth_method(provider)?;
    validate_https_url(
        &provider.redirect_uri,
        OidcValidationError::InvalidRedirectUri,
    )?;
    if !provider
        .requested_scopes
        .iter()
        .any(|scope| scope == "openid")
    {
        return Err(OidcValidationError::OpenIdScopeRequired);
    }
    if provider
        .accepted_audiences
        .iter()
        .all(|audience| audience.trim().is_empty())
    {
        return Err(OidcValidationError::AudienceRequired);
    }
    Ok(())
}

fn resolved_metadata_field(
    configured: &str,
    discovered: Option<&str>,
    error: OidcValidationError,
) -> Result<String, OidcValidationError> {
    let configured = configured.trim();
    if !configured.is_empty() {
        return Ok(configured.to_owned());
    }
    discovered
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or(error)
}

fn supported_oidc_algorithms(
    discovery: Option<&OidcDiscoveryDocument>,
) -> Result<Vec<String>, OidcValidationError> {
    let Some(discovery) = discovery else {
        return Ok(vec!["RS256".to_owned()]);
    };
    if discovery.id_token_signing_alg_values_supported.is_empty() {
        return Ok(vec!["RS256".to_owned()]);
    }
    let mut algorithms = Vec::new();
    for value in &discovery.id_token_signing_alg_values_supported {
        if let Some(algorithm) = oidc_algorithm_from_str(value) {
            if oidc_algorithm_is_asymmetric(algorithm) && !algorithms.contains(value) {
                algorithms.push(value.clone());
            }
        }
    }
    if algorithms.is_empty() {
        Err(OidcValidationError::UnsupportedSigningAlgorithm)
    } else {
        Ok(algorithms)
    }
}

fn validate_oidc_claims_against_metadata(
    metadata: &OidcResolvedProviderMetadata,
    claims: &OidcVerifiedClaims,
    expected_nonce: &str,
    now_unix: i64,
) -> Result<(), OidcValidationError> {
    if claims.issuer != metadata.issuer_url {
        return Err(OidcValidationError::IssuerMismatch);
    }
    if claims.subject.trim().is_empty() {
        return Err(OidcValidationError::SubjectRequired);
    }
    if !claims.audiences.iter().any(|audience| {
        metadata
            .accepted_audiences
            .iter()
            .any(|accepted| accepted == audience)
    }) {
        return Err(OidcValidationError::AudienceMismatch);
    }
    if claims.nonce != expected_nonce {
        return Err(OidcValidationError::NonceMismatch);
    }
    if claims.expires_at_unix <= now_unix {
        return Err(OidcValidationError::TokenExpired);
    }
    Ok(())
}

fn select_oidc_jwk<'a>(
    jwks: &'a JwkSet,
    kid: Option<&str>,
    algorithm: Algorithm,
) -> Result<&'a Jwk, OidcValidationError> {
    let mut candidates = jwks
        .keys
        .iter()
        .filter(|jwk| oidc_jwk_is_usable(jwk, kid, algorithm))
        .collect::<Vec<_>>();
    if let Some(kid) = kid {
        return candidates
            .into_iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .ok_or(OidcValidationError::SigningKeyNotFound);
    }
    if candidates.len() == 1 {
        Ok(candidates.remove(0))
    } else {
        Err(OidcValidationError::SigningKeyNotFound)
    }
}

fn oidc_jwk_is_usable(jwk: &Jwk, kid: Option<&str>, algorithm: Algorithm) -> bool {
    if jwk
        .common
        .public_key_use
        .as_ref()
        .is_some_and(|key_use| key_use != &PublicKeyUse::Signature)
    {
        return false;
    }
    if kid.is_some() && jwk.common.key_id.as_deref() != kid {
        return false;
    }
    jwk.common
        .key_algorithm
        .as_ref()
        .is_none_or(|key_algorithm| {
            oidc_algorithm_from_str(&key_algorithm.to_string()) == Some(algorithm)
        })
}

fn oidc_algorithm_from_str(value: &str) -> Option<Algorithm> {
    match value {
        "RS256" => Some(Algorithm::RS256),
        "RS384" => Some(Algorithm::RS384),
        "RS512" => Some(Algorithm::RS512),
        "PS256" => Some(Algorithm::PS256),
        "PS384" => Some(Algorithm::PS384),
        "PS512" => Some(Algorithm::PS512),
        "ES256" => Some(Algorithm::ES256),
        "ES384" => Some(Algorithm::ES384),
        "EdDSA" => Some(Algorithm::EdDSA),
        _ => None,
    }
}

const fn oidc_algorithm_is_asymmetric(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

fn validate_raw_secret(value: &str, error: OidcValidationError) -> Result<(), OidcValidationError> {
    if value.trim().is_empty() {
        Err(error)
    } else {
        Ok(())
    }
}

fn validate_hash(value: &str, error: OidcValidationError) -> Result<(), OidcValidationError> {
    if value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        Ok(())
    } else {
        Err(error)
    }
}

fn hash_oidc_secret(domain: &[u8], raw_value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(raw_value.as_bytes());
    lower_hex(&hasher.finalize())
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

fn validate_prefixed(
    value: &str,
    prefix: &str,
    error: PlatformExternalIdentityError,
) -> Result<(), PlatformExternalIdentityError> {
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
    use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::json;

    use super::{
        hash_oidc_login_nonce, hash_oidc_login_state, hash_oidc_pkce_verifier, oidc_discovery_url,
        resolve_oidc_provider_metadata, validate_external_identity, validate_oidc_id_token,
        validate_oidc_login_attempt_record, validate_oidc_login_provider,
        validate_oidc_verified_claims, InMemoryPlatformExternalIdentityStore,
        OidcDiscoveryDocument, OidcLoginAttemptRecord, OidcLoginAttemptStart,
        OidcLoginAttemptStatus, OidcLoginProviderRecord, OidcLoginProviderStatus,
        OidcTokenEndpointAuthMethod, OidcValidationError, OidcVerifiedClaims,
        PlatformExternalIdentityError, PlatformExternalIdentityRecord,
        PlatformExternalIdentityStatus,
    };

    #[test]
    fn external_identity_store_is_subject_unique_and_unlinkable() {
        let store = InMemoryPlatformExternalIdentityStore::new();
        let identity = valid_external_identity("xid_test", "usr_test");
        assert_eq!(validate_external_identity(&identity), Ok(()));
        let upserted = store
            .upsert_external_identity(identity.clone())
            .unwrap_or_else(|error| panic!("identity should upsert: {error:?}"));
        assert_eq!(upserted.external_identity_id, "xid_test");

        let refreshed = store
            .upsert_external_identity(PlatformExternalIdentityRecord {
                email: Some("new@example.com".to_owned()),
                email_verified: true,
                ..identity.clone()
            })
            .unwrap_or_else(|error| panic!("same principal should refresh identity: {error:?}"));
        assert_eq!(refreshed.email.as_deref(), Some("new@example.com"));
        assert!(refreshed.email_verified);

        let mismatch = store.upsert_external_identity(PlatformExternalIdentityRecord {
            external_identity_id: "xid_other".to_owned(),
            principal_id: "usr_other".to_owned(),
            ..identity
        });
        assert_eq!(
            mismatch,
            Err(PlatformExternalIdentityError::PrincipalMismatch)
        );

        let listed = store.external_identities_for_principal("ten_test", "usr_test");
        assert_eq!(listed.len(), 1);
        let unlinked = store
            .unlink_external_identity("xid_test")
            .unwrap_or_else(|error| panic!("identity should unlink: {error:?}"));
        assert_eq!(unlinked.status, PlatformExternalIdentityStatus::Deleted);
        assert!(store
            .external_identities_for_principal("ten_test", "usr_test")
            .is_empty());
    }

    #[test]
    fn generic_oidc_provider_requires_standard_shape() {
        let provider = valid_provider();
        assert_eq!(validate_oidc_login_provider(&provider), Ok(()));

        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                issuer_url: "http://issuer.example".to_owned(),
                ..provider.clone()
            }),
            Err(OidcValidationError::InvalidIssuerUrl)
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                requested_scopes: vec!["email".to_owned()],
                ..provider.clone()
            }),
            Err(OidcValidationError::OpenIdScopeRequired)
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                accepted_audiences: Vec::new(),
                ..provider.clone()
            }),
            Err(OidcValidationError::AudienceRequired)
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                client_secret_ref: Some("raw_secret".to_owned()),
                token_endpoint_auth_method: OidcTokenEndpointAuthMethod::ClientSecretBasic,
                ..provider.clone()
            }),
            Err(OidcValidationError::InvalidClientSecretRef)
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                client_secret_ref: Some("sec_oidc_secret".to_owned()),
                token_endpoint_auth_method: OidcTokenEndpointAuthMethod::None,
                ..provider.clone()
            }),
            Err(OidcValidationError::InvalidTokenEndpointAuthMethod)
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                token_endpoint_auth_method: OidcTokenEndpointAuthMethod::ClientSecretPost,
                ..provider.clone()
            }),
            Err(OidcValidationError::InvalidTokenEndpointAuthMethod)
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                client_secret_ref: Some("sec_oidc_secret".to_owned()),
                token_endpoint_auth_method: OidcTokenEndpointAuthMethod::ClientSecretBasic,
                ..provider.clone()
            }),
            Ok(())
        );
        assert_eq!(
            validate_oidc_login_provider(&OidcLoginProviderRecord {
                status: OidcLoginProviderStatus::Disabled,
                ..provider
            }),
            Err(OidcValidationError::ProviderInactive)
        );
    }

    #[test]
    fn generic_oidc_metadata_resolves_discovery_and_rejects_unsafe_algorithms() {
        let provider = OidcLoginProviderRecord {
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
            ..valid_provider()
        };
        let discovery = valid_discovery();
        let metadata = resolve_oidc_provider_metadata(&provider, Some(&discovery))
            .unwrap_or_else(|error| panic!("discovery metadata should resolve: {error}"));

        assert_eq!(metadata.issuer_url, provider.issuer_url);
        assert_eq!(
            metadata.authorization_endpoint,
            "https://issuer.example/authorize"
        );
        assert_eq!(metadata.token_endpoint, "https://issuer.example/token");
        assert_eq!(metadata.jwks_uri, "https://issuer.example/jwks.json");
        assert_eq!(metadata.supported_id_token_algorithms, vec!["RS256"]);
        assert_eq!(
            oidc_discovery_url("https://issuer.example/"),
            "https://issuer.example/.well-known/openid-configuration"
        );

        assert_eq!(
            resolve_oidc_provider_metadata(
                &provider,
                Some(&OidcDiscoveryDocument {
                    issuer: "https://other.example".to_owned(),
                    ..discovery.clone()
                }),
            ),
            Err(OidcValidationError::DiscoveryIssuerMismatch)
        );
        assert_eq!(
            resolve_oidc_provider_metadata(
                &provider,
                Some(&OidcDiscoveryDocument {
                    id_token_signing_alg_values_supported: vec!["HS256".to_owned()],
                    ..discovery
                }),
            ),
            Err(OidcValidationError::UnsupportedSigningAlgorithm)
        );
    }

    #[test]
    fn generic_oidc_claims_validate_issuer_audience_nonce_and_expiry() {
        let provider = valid_provider();
        let claims = valid_claims();

        assert_eq!(
            validate_oidc_verified_claims(&provider, &claims, "nonce_test", 1_700_000_000),
            Ok(())
        );
        assert_eq!(
            validate_oidc_verified_claims(
                &provider,
                &OidcVerifiedClaims {
                    issuer: "https://other.example".to_owned(),
                    ..claims.clone()
                },
                "nonce_test",
                1_700_000_000,
            ),
            Err(OidcValidationError::IssuerMismatch)
        );
        assert_eq!(
            validate_oidc_verified_claims(
                &provider,
                &OidcVerifiedClaims {
                    audiences: vec!["other_client".to_owned()],
                    ..claims.clone()
                },
                "nonce_test",
                1_700_000_000,
            ),
            Err(OidcValidationError::AudienceMismatch)
        );
        assert_eq!(
            validate_oidc_verified_claims(&provider, &claims, "wrong_nonce", 1_700_000_000),
            Err(OidcValidationError::NonceMismatch)
        );
        assert_eq!(
            validate_oidc_verified_claims(&provider, &claims, "nonce_test", 1_800_000_000),
            Err(OidcValidationError::TokenExpired)
        );
    }

    #[test]
    fn generic_oidc_id_token_validation_uses_jwks_and_claims() {
        let metadata = resolve_oidc_provider_metadata(&valid_provider(), None)
            .unwrap_or_else(|error| panic!("metadata should resolve: {error}"));
        let jwks = test_jwks();
        let now = 1_700_000_000;
        let id_token = signed_oidc_id_token(
            "test-oidc-key",
            "https://issuer.example",
            "oidc_client",
            "nonce_test",
            now + 300,
        );

        let claims = validate_oidc_id_token(&metadata, &jwks, &id_token, "nonce_test", now)
            .unwrap_or_else(|error| panic!("signed ID token should validate: {error}"));
        assert_eq!(claims.subject, "oidc-user-456");
        assert_eq!(claims.audiences, vec!["oidc_client"]);
        assert_eq!(claims.email, Some("owner@example.com".to_owned()));
        assert_eq!(claims.display_name, Some("OIDC Owner".to_owned()));

        let wrong_nonce = signed_oidc_id_token(
            "test-oidc-key",
            "https://issuer.example",
            "oidc_client",
            "wrong_nonce",
            now + 300,
        );
        assert_eq!(
            validate_oidc_id_token(&metadata, &jwks, &wrong_nonce, "nonce_test", now),
            Err(OidcValidationError::NonceMismatch)
        );
        let wrong_audience = signed_oidc_id_token(
            "test-oidc-key",
            "https://issuer.example",
            "other_client",
            "nonce_test",
            now + 300,
        );
        assert_eq!(
            validate_oidc_id_token(&metadata, &jwks, &wrong_audience, "nonce_test", now),
            Err(OidcValidationError::InvalidIdToken)
        );
        let unknown_key = signed_oidc_id_token(
            "missing-key",
            "https://issuer.example",
            "oidc_client",
            "nonce_test",
            now + 300,
        );
        assert_eq!(
            validate_oidc_id_token(&metadata, &jwks, &unknown_key, "nonce_test", now),
            Err(OidcValidationError::SigningKeyNotFound)
        );
    }

    #[test]
    fn generic_oidc_attempt_hashes_transient_login_secrets() {
        let record = valid_attempt();

        assert_eq!(record.state_hash, hash_oidc_login_state("state_secret"));
        assert_eq!(record.nonce_hash, hash_oidc_login_nonce("nonce_secret"));
        assert_eq!(
            record.pkce_verifier_hash,
            hash_oidc_pkce_verifier("pkce_secret")
        );
        assert_ne!(record.state_hash, "state_secret");
        assert_ne!(record.nonce_hash, "nonce_secret");
        assert_ne!(record.pkce_verifier_hash, "pkce_secret");
        for hash in [
            &record.state_hash,
            &record.nonce_hash,
            &record.pkce_verifier_hash,
        ] {
            assert_eq!(hash.len(), 64);
            assert!(hash.chars().all(|character| character.is_ascii_hexdigit()));
        }
        assert_eq!(validate_oidc_login_attempt_record(&record), Ok(()));
    }

    #[test]
    fn generic_oidc_attempt_validation_rejects_unsafe_shape() {
        assert_eq!(
            OidcLoginAttemptRecord::active(OidcLoginAttemptStart {
                raw_state: " ".to_owned(),
                ..valid_attempt_start()
            }),
            Err(OidcValidationError::EmptyState)
        );

        let record = valid_attempt();
        assert_eq!(
            validate_oidc_login_attempt_record(&OidcLoginAttemptRecord {
                login_attempt_id: "attempt_test".to_owned(),
                ..record.clone()
            }),
            Err(OidcValidationError::InvalidLoginAttemptId)
        );
        assert_eq!(
            validate_oidc_login_attempt_record(&OidcLoginAttemptRecord {
                state_hash: "state_secret".to_owned(),
                ..record.clone()
            }),
            Err(OidcValidationError::InvalidStateHash)
        );
        assert_eq!(
            validate_oidc_login_attempt_record(&OidcLoginAttemptRecord {
                status: OidcLoginAttemptStatus::Consumed,
                consumed_at_unix: None,
                ..record.clone()
            }),
            Err(OidcValidationError::ConsumedAtRequired)
        );
        assert_eq!(
            validate_oidc_login_attempt_record(&OidcLoginAttemptRecord {
                consumed_at_unix: Some(1_700_000_010),
                ..record
            }),
            Err(OidcValidationError::ConsumedAtUnexpected)
        );
    }

    fn valid_external_identity(
        external_identity_id: &str,
        principal_id: &str,
    ) -> PlatformExternalIdentityRecord {
        PlatformExternalIdentityRecord {
            external_identity_id: external_identity_id.to_owned(),
            tenant_id: "ten_test".to_owned(),
            principal_id: principal_id.to_owned(),
            identity_provider_id: "idp_oidc".to_owned(),
            provider_kind: "oidc".to_owned(),
            provider_subject: "oidc-subject-123".to_owned(),
            email: Some("owner@example.com".to_owned()),
            email_verified: true,
            status: PlatformExternalIdentityStatus::Active,
        }
    }

    fn valid_provider() -> OidcLoginProviderRecord {
        OidcLoginProviderRecord {
            identity_provider_id: "idp_oidc".to_owned(),
            tenant_id: "ten_test".to_owned(),
            display_name: "Example OIDC".to_owned(),
            issuer_url: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            jwks_uri: "https://issuer.example/jwks.json".to_owned(),
            client_id: "oidc_client".to_owned(),
            client_secret_ref: None,
            token_endpoint_auth_method: OidcTokenEndpointAuthMethod::None,
            redirect_uri: "https://app.example/auth/oidc/callback".to_owned(),
            requested_scopes: vec![
                "openid".to_owned(),
                "email".to_owned(),
                "profile".to_owned(),
            ],
            accepted_audiences: vec!["oidc_client".to_owned()],
            status: OidcLoginProviderStatus::Active,
        }
    }

    fn valid_claims() -> OidcVerifiedClaims {
        OidcVerifiedClaims {
            issuer: "https://issuer.example".to_owned(),
            subject: "user-subject".to_owned(),
            audiences: vec!["oidc_client".to_owned()],
            nonce: "nonce_test".to_owned(),
            expires_at_unix: 1_750_000_000,
            email: Some("user@example.com".to_owned()),
            email_verified: true,
            display_name: Some("User".to_owned()),
        }
    }

    fn valid_discovery() -> OidcDiscoveryDocument {
        OidcDiscoveryDocument {
            issuer: "https://issuer.example".to_owned(),
            authorization_endpoint: "https://issuer.example/authorize".to_owned(),
            token_endpoint: "https://issuer.example/token".to_owned(),
            jwks_uri: "https://issuer.example/jwks.json".to_owned(),
            id_token_signing_alg_values_supported: vec!["RS256".to_owned()],
        }
    }

    fn test_jwks() -> JwkSet {
        let signing_key = test_encoding_key();
        let mut jwk = Jwk::from_encoding_key(&signing_key, Algorithm::RS256)
            .unwrap_or_else(|error| panic!("test JWK should derive from RSA key: {error}"));
        jwk.common.key_id = Some("test-oidc-key".to_owned());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        JwkSet { keys: vec![jwk] }
    }

    fn signed_oidc_id_token(
        key_id: &str,
        issuer: &str,
        audience: &str,
        nonce: &str,
        expires_at_unix: i64,
    ) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key_id.to_owned());
        encode(
            &header,
            &json!({
                "iss": issuer,
                "sub": "oidc-user-456",
                "aud": audience,
                "exp": expires_at_unix,
                "iat": 1_700_000_000,
                "nonce": nonce,
                "email": "owner@example.com",
                "email_verified": true,
                "name": "OIDC Owner"
            }),
            &test_encoding_key(),
        )
        .unwrap_or_else(|error| panic!("test ID token should sign: {error}"))
    }

    fn test_encoding_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .unwrap_or_else(|error| panic!("test RSA key should parse: {error}"))
    }

    fn valid_attempt() -> OidcLoginAttemptRecord {
        OidcLoginAttemptRecord::active(valid_attempt_start())
            .unwrap_or_else(|error| panic!("valid attempt should pass validation: {error}"))
    }

    fn valid_attempt_start() -> OidcLoginAttemptStart {
        OidcLoginAttemptStart {
            login_attempt_id: "ola_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            identity_provider_id: "idp_oidc".to_owned(),
            raw_state: "state_secret".to_owned(),
            raw_nonce: "nonce_secret".to_owned(),
            raw_pkce_verifier: "pkce_secret".to_owned(),
            redirect_uri: "https://app.example/auth/oidc/callback".to_owned(),
            expires_at_unix: 1_750_000_000,
        }
    }

    const TEST_RSA_PRIVATE_KEY_PEM: &str = r"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAyRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTL
UTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXBXd/4LkvcPuUakBoAkfh+eiFVMh2V
rUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8H
oGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBI
Mc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi+yUod+j8MtvIj812dkS4QMiRVN/
by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQIDAQABAoIBAHREk0I0O9DvECKd
WUpAmF3mY7oY9PNQiu44Yaf+AoSuyRpRUGTMIgc3u3eivOE8ALX0BmYUO5JtuRNZ
Dpvt4SAwqCnVUinIf6C+eH/wSurCpapSM0BAHp4aOA7igptyOMgMPYBHNA1e9A7j
E0dCxKWMl3DSWNyjQTk4zeRGEAEfbNjHrq6YCtjHSZSLmWiG80hnfnYos9hOr5Jn
LnyS7ZmFE/5P3XVrxLc/tQ5zum0R4cbrgzHiQP5RgfxGJaEi7XcgherCCOgurJSS
bYH29Gz8u5fFbS+Yg8s+OiCss3cs1rSgJ9/eHZuzGEdUZVARH6hVMjSuwvqVTFaE
8AgtleECgYEA+uLMn4kNqHlJS2A5uAnCkj90ZxEtNm3E8hAxUrhssktY5XSOAPBl
xyf5RuRGIImGtUVIr4HuJSa5TX48n3Vdt9MYCprO/iYl6moNRSPt5qowIIOJmIjY
2mqPDfDt/zw+fcDD3lmCJrFlzcnh0uea1CohxEbQnL3cypeLt+WbU6kCgYEAzSp1
9m1ajieFkqgoB0YTpt/OroDx38vvI5unInJlEeOjQ+oIAQdN2wpxBvTrRorMU6P0
7mFUbt1j+Co6CbNiw+X8HcCaqYLR5clbJOOWNR36PuzOpQLkfK8woupBxzW9B8gZ
mY8rB1mbJ+/WTPrEJy6YGmIEBkWylQ2VpW8O4O0CgYEApdbvvfFBlwD9YxbrcGz7
MeNCFbMz+MucqQntIKoKJ91ImPxvtc0y6e/Rhnv0oyNlaUOwJVu0yNgNG117w0g4
t/+Q38mvVC5xV7/cn7x9UMFk6MkqVir3dYGEqIl/OP1grY2Tq9HtB5iyG9L8NIam
QOLMyUqqMUILxdthHyFmiGkCgYEAn9+PjpjGMPHxL0gj8Q8VbzsFtou6b1deIRRA
2CHmSltltR1gYVTMwXxQeUhPMmgkMqUXzs4/WijgpthY44hK1TaZEKIuoxrS70nJ
4WQLf5a9k1065fDsFZD6yGjdGxvwEmlGMZgTwqV7t1I4X0Ilqhav5hcs5apYL7gn
PYPeRz0CgYALHCj/Ji8XSsDoF/MhVhnGdIs2P99NNdmo3R2Pv0CuZbDKMU559LJH
UvrKS8WkuWRDuKrz1W/EQKApFjDGpdqToZqriUFQzwy7mR3ayIiogzNtHcvbDHx8
oFnGY0OFksX/ye0/XGpy2SFxYRwGU98HPYeBvAQQrVjdkzfy7BmXQQ==
-----END RSA PRIVATE KEY-----";
}
