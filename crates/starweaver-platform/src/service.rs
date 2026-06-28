//! Platform HTTP service foundation.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use jsonwebtoken::jwk::JwkSet;
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;

use crate::action::{
    ActionGrant, ActorKind, AuthenticatedActor, AuthorizationEngine, AuthorizationRequest,
    BuiltInRole, FoundationAuthorizationEngine, PlatformAction, ResourceRef,
};
use crate::audit::{
    InMemoryPlatformAuditStore, PlatformAuditError, PlatformAuditEventRecord,
    PLATFORM_AUDIT_REDACTION_PROFILE,
};
use crate::auth::{
    AuthError, InMemoryPlatformAuthSessionStore, InMemoryPlatformBearerCredentialStore,
    InMemoryPlatformMtlsIdentityStore, PlatformAuthSessionRecord, PlatformAuthSessionRepository,
    PlatformBearerCredentialRepository, PlatformMtlsIdentityRepository,
};
use crate::config::{
    validate_platform_config, PlatformConfig, PlatformConfigError, PlatformSingleUserConfig,
};
use crate::identity::{
    hash_oidc_login_nonce, hash_oidc_login_state, hash_oidc_pkce_verifier, oidc_discovery_url,
    resolve_oidc_provider_metadata, validate_oidc_id_token, InMemoryPlatformExternalIdentityStore,
    OidcDiscoveryDocument, OidcLoginAttemptRecord, OidcLoginAttemptStatus, OidcLoginProviderRecord,
    OidcLoginProviderStatus, OidcResolvedProviderMetadata, OidcTokenEndpointAuthMethod,
    OidcVerifiedClaims, PlatformExternalIdentityError, PlatformExternalIdentityRecord,
    PlatformExternalIdentityStatus,
};
use crate::invitation::{
    hash_platform_invitation_token, AcceptPlatformOrganizationInvitationRequest,
    InMemoryPlatformInvitationStore, PlatformInvitationError, PlatformInvitationStatus,
    PlatformOrganizationInvitationRecord, PLATFORM_INVITATION_TOKEN_PREFIX,
};
use crate::membership::{
    InMemoryPlatformMembershipStore, PlatformInvitedProjectMembershipUpsert,
    PlatformMembershipError, PlatformMembershipStatus, PlatformOrganizationMembershipRecord,
    PlatformOrganizationMembershipUpsert, PlatformProjectMembershipRecord,
    PlatformProjectMembershipUpsert,
};
use crate::migrations::{self, PlatformMigrationError};
use crate::postgres::{
    OidcLoginCompletionRecord, PlatformRepositoryError, PostgresPlatformRepository,
    SingleUserBootstrapRecord,
};
use crate::resource::{
    InMemoryPlatformResourceStore, PlatformResourceRecord, PlatformResourceRepository,
};
use crate::role::{
    InMemoryPlatformRoleBindingStore, PlatformRoleBindingError, PlatformRoleBindingRecord,
    PlatformRoleBindingStatus, PlatformRoleBindingUpsert,
};
use crate::route::{foundation_routes, HttpMethod, RouteMetadata};
use crate::secret::{
    environment_secret_ref_record, CreatePlatformSecretRefRequest, InMemoryPlatformSecretStore,
    PlatformSecretError, PlatformSecretRefRecord, PlatformSecretValue, ENVIRONMENT_SECRET_BACKEND,
    IN_MEMORY_SECRET_BACKEND,
};
use crate::storage::{InMemoryResourceOwnerStore, ResourceOwnerRecord, ResourceOwnerRepository};
use crate::user::{
    InMemoryPlatformUserStore, PlatformUserError, PlatformUserRecord, PlatformUserStatus,
};

const SINGLE_USER_TENANT_ID: &str = "ten_single_user";
const SINGLE_USER_ORGANIZATION_ID: &str = "org_single_user";
const SINGLE_USER_PROJECT_ID: &str = "prj_single_user";
const SINGLE_USER_ID: &str = "usr_single_user";
const SINGLE_USER_IDENTITY_PROVIDER_ID: &str = "idp_single_user";
const SINGLE_USER_EXTERNAL_IDENTITY_ID: &str = "xid_single_user";
const SINGLE_USER_ORGANIZATION_MEMBER_ID: &str = "om_single_user";
const SINGLE_USER_PROJECT_MEMBER_ID: &str = "pm_single_user";
const SINGLE_USER_ROLE_BINDING_ID: &str = "rb_single_user_tenant_owner";
const SINGLE_USER_SESSION_TOKEN_PREFIX: &str = "swp_sess_";
const OIDC_CALLBACK_SESSION_TOKEN_PREFIX: &str = "swp_sess_";
const OIDC_HTTP_TIMEOUT_SECONDS: u64 = 10;
const OIDC_LOGIN_ATTEMPT_TTL_SECONDS: i64 = 600;
const ORGANIZATION_INVITATION_TTL_SECONDS: i64 = 7 * 24 * 60 * 60;

/// HTTP foundation service state.
#[derive(Clone, Debug, Default)]
pub struct PlatformServiceState {
    owners: InMemoryResourceOwnerStore,
    auth_sessions: InMemoryPlatformAuthSessionStore,
    bearer_credentials: InMemoryPlatformBearerCredentialStore,
    mtls_identities: InMemoryPlatformMtlsIdentityStore,
    resources: InMemoryPlatformResourceStore,
    secrets: InMemoryPlatformSecretStore,
    memberships: InMemoryPlatformMembershipStore,
    invitations: InMemoryPlatformInvitationStore,
    external_identities: InMemoryPlatformExternalIdentityStore,
    role_bindings: InMemoryPlatformRoleBindingStore,
    users: InMemoryPlatformUserStore,
    audits: InMemoryPlatformAuditStore,
    oidc_logins: InMemoryOidcLoginStore,
    oidc_http: PlatformOidcHttpClient,
    repository_backend: PlatformRepositoryBackendKind,
    postgres_repository: Option<PostgresPlatformRepository>,
    single_user_auth: Option<PlatformSingleUserConfig>,
    authorization: FoundationAuthorizationEngine,
}

/// Platform service repository backend selected for HTTP request handling.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlatformRepositoryBackendKind {
    /// Use platform-local in-memory foundation stores.
    #[default]
    InMemory,
    /// Use the durable `PostgreSQL` repository adapter.
    Postgres,
}

impl PlatformRepositoryBackendKind {
    /// Returns the stable backend profile id.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InMemory => "in_memory",
            Self::Postgres => "postgres",
        }
    }
}

#[derive(Clone, Debug, Default)]
struct InMemoryOidcLoginStore {
    providers: Arc<RwLock<BTreeMap<String, OidcLoginProviderRecord>>>,
    attempts: Arc<RwLock<BTreeMap<String, OidcLoginAttemptRecord>>>,
}

impl InMemoryOidcLoginStore {
    fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    fn record_provider(&self, provider: OidcLoginProviderRecord) {
        self.upsert_provider(provider);
    }

    fn upsert_provider(&self, provider: OidcLoginProviderRecord) {
        write_lock(&self.providers).insert(provider.identity_provider_id.clone(), provider);
    }

    fn provider(&self, identity_provider_id: &str) -> Option<OidcLoginProviderRecord> {
        read_lock(&self.providers)
            .get(identity_provider_id)
            .cloned()
    }

    fn providers_for_tenant(&self, tenant_id: &str) -> Vec<OidcLoginProviderRecord> {
        read_lock(&self.providers)
            .values()
            .filter(|provider| {
                provider.tenant_id == tenant_id
                    && provider.status != OidcLoginProviderStatus::Deleted
            })
            .cloned()
            .collect()
    }

    fn record_attempt(&self, attempt: OidcLoginAttemptRecord) {
        write_lock(&self.attempts).insert(attempt.state_hash.clone(), attempt);
    }

    fn attempt_for_state(&self, raw_state: &str) -> Option<OidcLoginAttemptRecord> {
        let state_hash = hash_oidc_login_state(raw_state.trim());
        read_lock(&self.attempts).get(&state_hash).cloned()
    }

    fn consume_attempt(&self, completion: &OidcLoginCompletionRecord) -> Result<(), ServiceError> {
        let state_hash = {
            let attempts = read_lock(&self.attempts);
            attempts
                .iter()
                .find(|(_, attempt)| {
                    attempt.login_attempt_id == completion.login_attempt_id
                        && attempt.tenant_id == completion.tenant_id
                        && attempt.identity_provider_id == completion.identity_provider_id
                })
                .map(|(state_hash, _)| state_hash.clone())
        }
        .ok_or(ServiceError::AuthenticationFailed(
            "oidc_login_attempt_unavailable",
        ))?;

        let mut attempts = write_lock(&self.attempts);
        let Some(attempt) = attempts.get_mut(&state_hash) else {
            return Err(ServiceError::AuthenticationFailed(
                "oidc_login_attempt_unavailable",
            ));
        };
        if attempt.status != OidcLoginAttemptStatus::Active
            || attempt.expires_at_unix <= completion.consumed_at_unix
            || !(attempt.login_attempt_id == completion.login_attempt_id
                && attempt.tenant_id == completion.tenant_id
                && attempt.identity_provider_id == completion.identity_provider_id)
        {
            return Err(ServiceError::AuthenticationFailed(
                "oidc_login_attempt_unavailable",
            ));
        }
        *attempt = attempt.clone().consumed(completion.consumed_at_unix);
        drop(attempts);
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum PlatformOidcHttpClient {
    Live(reqwest::Client),
    #[cfg(test)]
    Static(StaticOidcHttpClient),
}

impl Default for PlatformOidcHttpClient {
    fn default() -> Self {
        Self::live()
    }
}

impl PlatformOidcHttpClient {
    fn live() -> Self {
        Self::Live(reqwest::Client::new())
    }

    async fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, ServiceError> {
        match self {
            Self::Live(client) => {
                let response = client
                    .get(url)
                    .timeout(Duration::from_secs(OIDC_HTTP_TIMEOUT_SECONDS))
                    .header(ACCEPT, "application/json")
                    .header(USER_AGENT, crate::SERVICE_NAME)
                    .send()
                    .await
                    .map_err(|_| ServiceError::AuthenticationFailed("oidc_http_request_failed"))?;
                decode_oidc_response(response.status().as_u16(), response.text().await)
            }
            #[cfg(test)]
            Self::Static(client) => client.get_json(url),
        }
    }

    async fn post_form_json<T: DeserializeOwned>(
        &self,
        url: &str,
        form: &[(&str, &str)],
        basic_auth: Option<(&str, &str)>,
    ) -> Result<T, ServiceError> {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form.iter().copied())
            .finish();
        match self {
            Self::Live(client) => {
                let response = client
                    .post(url)
                    .timeout(Duration::from_secs(OIDC_HTTP_TIMEOUT_SECONDS))
                    .header(ACCEPT, "application/json")
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .header(USER_AGENT, crate::SERVICE_NAME)
                    .body(body);
                let response = if let Some((username, password)) = basic_auth {
                    response.basic_auth(username, Some(password))
                } else {
                    response
                }
                .send()
                .await
                .map_err(|_| ServiceError::AuthenticationFailed("oidc_http_request_failed"))?;
                decode_oidc_response(response.status().as_u16(), response.text().await)
            }
            #[cfg(test)]
            Self::Static(client) => client.post_form_json(url, body.as_str(), basic_auth),
        }
    }
}

fn decode_oidc_response<T: DeserializeOwned>(
    status: u16,
    body: Result<String, reqwest::Error>,
) -> Result<T, ServiceError> {
    if !(200..300).contains(&status) {
        return Err(ServiceError::AuthenticationFailed(
            "oidc_http_request_failed",
        ));
    }
    let body = body.map_err(|_| ServiceError::AuthenticationFailed("oidc_response_read_failed"))?;
    serde_json::from_str(&body)
        .map_err(|_| ServiceError::AuthenticationFailed("oidc_response_json_invalid"))
}

#[cfg(test)]
#[derive(Clone, Debug, Default)]
struct StaticOidcHttpClient {
    responses: Arc<RwLock<BTreeMap<StaticOidcHttpKey, StaticOidcHttpResponse>>>,
    requests: Arc<RwLock<Vec<StaticOidcHttpRequest>>>,
}

#[cfg(test)]
impl StaticOidcHttpClient {
    fn new() -> Self {
        Self::default()
    }

    fn respond_json(&self, method: &str, url: &str, status: u16, body: &Value) {
        write_lock(&self.responses).insert(
            StaticOidcHttpKey {
                method: method.to_owned(),
                url: url.to_owned(),
            },
            StaticOidcHttpResponse {
                status,
                body: body.to_string(),
            },
        );
    }

    fn requests(&self) -> Vec<StaticOidcHttpRequest> {
        read_lock(&self.requests).clone()
    }

    fn get_json<T: DeserializeOwned>(&self, url: &str) -> Result<T, ServiceError> {
        self.record_and_decode("GET", url, None, None)
    }

    fn post_form_json<T: DeserializeOwned>(
        &self,
        url: &str,
        body: &str,
        basic_auth: Option<(&str, &str)>,
    ) -> Result<T, ServiceError> {
        let authorization = basic_auth.map(|_| "Basic <redacted>".to_owned());
        self.record_and_decode("POST", url, Some(body.to_owned()), authorization)
    }

    fn record_and_decode<T: DeserializeOwned>(
        &self,
        method: &str,
        url: &str,
        body: Option<String>,
        authorization: Option<String>,
    ) -> Result<T, ServiceError> {
        write_lock(&self.requests).push(StaticOidcHttpRequest {
            method: method.to_owned(),
            url: url.to_owned(),
            body,
            authorization,
        });
        let response = read_lock(&self.responses)
            .get(&StaticOidcHttpKey {
                method: method.to_owned(),
                url: url.to_owned(),
            })
            .cloned()
            .ok_or(ServiceError::AuthenticationFailed(
                "oidc_http_request_failed",
            ))?;
        if !(200..300).contains(&response.status) {
            return Err(ServiceError::AuthenticationFailed(
                "oidc_http_request_failed",
            ));
        }
        serde_json::from_str(&response.body)
            .map_err(|_| ServiceError::AuthenticationFailed("oidc_response_json_invalid"))
    }
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct StaticOidcHttpKey {
    method: String,
    url: String,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticOidcHttpResponse {
    status: u16,
    body: String,
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct StaticOidcHttpRequest {
    method: String,
    url: String,
    body: Option<String>,
    authorization: Option<String>,
}

impl PlatformServiceState {
    /// Creates service state from resource ownership and authorization stores.
    #[must_use]
    pub fn new(
        owners: InMemoryResourceOwnerStore,
        authorization: FoundationAuthorizationEngine,
    ) -> Self {
        Self::with_auth_sessions_and_mtls(
            owners,
            InMemoryPlatformAuthSessionStore::new(),
            InMemoryPlatformBearerCredentialStore::new(),
            InMemoryPlatformMtlsIdentityStore::new(),
            authorization,
        )
    }

    /// Creates service state from explicit resource, auth, and authorization stores.
    #[must_use]
    pub fn with_auth_sessions(
        owners: InMemoryResourceOwnerStore,
        auth_sessions: InMemoryPlatformAuthSessionStore,
        bearer_credentials: InMemoryPlatformBearerCredentialStore,
        authorization: FoundationAuthorizationEngine,
    ) -> Self {
        Self::with_auth_sessions_and_mtls(
            owners,
            auth_sessions,
            bearer_credentials,
            InMemoryPlatformMtlsIdentityStore::new(),
            authorization,
        )
    }

    /// Creates service state from explicit resource, auth, and authorization stores.
    #[must_use]
    pub fn with_auth_sessions_and_mtls(
        owners: InMemoryResourceOwnerStore,
        auth_sessions: InMemoryPlatformAuthSessionStore,
        bearer_credentials: InMemoryPlatformBearerCredentialStore,
        mtls_identities: InMemoryPlatformMtlsIdentityStore,
        authorization: FoundationAuthorizationEngine,
    ) -> Self {
        Self::with_resources_and_mtls(
            owners,
            auth_sessions,
            bearer_credentials,
            mtls_identities,
            InMemoryPlatformResourceStore::new(),
            authorization,
        )
    }

    /// Creates service state from explicit resource, auth, and authorization stores.
    #[must_use]
    pub fn with_resources(
        owners: InMemoryResourceOwnerStore,
        auth_sessions: InMemoryPlatformAuthSessionStore,
        bearer_credentials: InMemoryPlatformBearerCredentialStore,
        resources: InMemoryPlatformResourceStore,
        authorization: FoundationAuthorizationEngine,
    ) -> Self {
        Self::with_resources_and_mtls(
            owners,
            auth_sessions,
            bearer_credentials,
            InMemoryPlatformMtlsIdentityStore::new(),
            resources,
            authorization,
        )
    }

    /// Creates service state from explicit resource, auth, mTLS, and authorization stores.
    #[must_use]
    pub fn with_resources_and_mtls(
        owners: InMemoryResourceOwnerStore,
        auth_sessions: InMemoryPlatformAuthSessionStore,
        bearer_credentials: InMemoryPlatformBearerCredentialStore,
        mtls_identities: InMemoryPlatformMtlsIdentityStore,
        resources: InMemoryPlatformResourceStore,
        authorization: FoundationAuthorizationEngine,
    ) -> Self {
        Self {
            owners,
            auth_sessions,
            bearer_credentials,
            mtls_identities,
            resources,
            secrets: InMemoryPlatformSecretStore::new(),
            memberships: InMemoryPlatformMembershipStore::new(),
            invitations: InMemoryPlatformInvitationStore::new(),
            external_identities: InMemoryPlatformExternalIdentityStore::new(),
            role_bindings: InMemoryPlatformRoleBindingStore::new(),
            users: InMemoryPlatformUserStore::new(),
            audits: InMemoryPlatformAuditStore::new(),
            oidc_logins: InMemoryOidcLoginStore::new(),
            oidc_http: PlatformOidcHttpClient::live(),
            repository_backend: PlatformRepositoryBackendKind::InMemory,
            postgres_repository: None,
            single_user_auth: None,
            authorization,
        }
    }

    /// Creates service state backed by the durable `PostgreSQL` repository adapter.
    #[must_use]
    pub fn with_postgres_repository(
        postgres_repository: PostgresPlatformRepository,
        authorization: FoundationAuthorizationEngine,
    ) -> Self {
        Self {
            owners: InMemoryResourceOwnerStore::new(),
            auth_sessions: InMemoryPlatformAuthSessionStore::new(),
            bearer_credentials: InMemoryPlatformBearerCredentialStore::new(),
            mtls_identities: InMemoryPlatformMtlsIdentityStore::new(),
            resources: InMemoryPlatformResourceStore::new(),
            secrets: InMemoryPlatformSecretStore::new(),
            memberships: InMemoryPlatformMembershipStore::new(),
            invitations: InMemoryPlatformInvitationStore::new(),
            external_identities: InMemoryPlatformExternalIdentityStore::new(),
            role_bindings: InMemoryPlatformRoleBindingStore::new(),
            users: InMemoryPlatformUserStore::new(),
            audits: InMemoryPlatformAuditStore::new(),
            oidc_logins: InMemoryOidcLoginStore::new(),
            oidc_http: PlatformOidcHttpClient::live(),
            repository_backend: PlatformRepositoryBackendKind::Postgres,
            postgres_repository: Some(postgres_repository),
            single_user_auth: None,
            authorization,
        }
    }

    /// Returns a copy of this state with local single-user auth configured.
    #[must_use]
    pub fn with_single_user_auth(
        mut self,
        single_user_auth: Option<PlatformSingleUserConfig>,
    ) -> Self {
        self.single_user_auth = single_user_auth;
        self
    }

    #[cfg(test)]
    fn with_oidc_login_store(mut self, oidc_logins: InMemoryOidcLoginStore) -> Self {
        self.oidc_logins = oidc_logins;
        self
    }

    #[cfg(test)]
    fn with_oidc_http_client(mut self, oidc_http: PlatformOidcHttpClient) -> Self {
        self.oidc_http = oidc_http;
        self
    }

    #[cfg(test)]
    fn with_secret_store(mut self, secrets: InMemoryPlatformSecretStore) -> Self {
        self.secrets = secrets;
        self
    }

    #[cfg(test)]
    fn with_membership_store(mut self, memberships: InMemoryPlatformMembershipStore) -> Self {
        self.memberships = memberships;
        self
    }

    #[cfg(test)]
    fn with_invitation_store(mut self, invitations: InMemoryPlatformInvitationStore) -> Self {
        self.invitations = invitations;
        self
    }

    #[cfg(test)]
    fn with_external_identity_store(
        mut self,
        external_identities: InMemoryPlatformExternalIdentityStore,
    ) -> Self {
        self.external_identities = external_identities;
        self
    }

    #[cfg(test)]
    fn with_role_binding_store(mut self, role_bindings: InMemoryPlatformRoleBindingStore) -> Self {
        self.role_bindings = role_bindings;
        self
    }

    #[cfg(test)]
    fn with_user_store(mut self, users: InMemoryPlatformUserStore) -> Self {
        self.users = users;
        self
    }

    /// Returns the selected repository backend profile.
    #[must_use]
    pub const fn repository_backend(&self) -> PlatformRepositoryBackendKind {
        self.repository_backend
    }

    /// Returns the durable `PostgreSQL` repository when selected.
    #[must_use]
    pub const fn postgres_repository(&self) -> Option<&PostgresPlatformRepository> {
        self.postgres_repository.as_ref()
    }

    /// Returns local single-user auth configuration when enabled.
    #[must_use]
    pub const fn single_user_auth(&self) -> Option<&PlatformSingleUserConfig> {
        self.single_user_auth.as_ref()
    }

    /// Returns the resource owner store.
    #[must_use]
    pub const fn owners(&self) -> &InMemoryResourceOwnerStore {
        &self.owners
    }

    /// Returns the auth session store.
    #[must_use]
    pub const fn auth_sessions(&self) -> &InMemoryPlatformAuthSessionStore {
        &self.auth_sessions
    }

    /// Returns the bearer credential store.
    #[must_use]
    pub const fn bearer_credentials(&self) -> &InMemoryPlatformBearerCredentialStore {
        &self.bearer_credentials
    }

    /// Returns the mTLS identity store.
    #[must_use]
    pub const fn mtls_identities(&self) -> &InMemoryPlatformMtlsIdentityStore {
        &self.mtls_identities
    }

    /// Returns the business resource store.
    #[must_use]
    pub const fn resources(&self) -> &InMemoryPlatformResourceStore {
        &self.resources
    }

    /// Returns the secret reference store.
    #[must_use]
    pub const fn secrets(&self) -> &InMemoryPlatformSecretStore {
        &self.secrets
    }

    /// Returns the in-memory membership store.
    #[must_use]
    pub const fn memberships(&self) -> &InMemoryPlatformMembershipStore {
        &self.memberships
    }

    /// Returns the in-memory invitation store.
    #[must_use]
    pub const fn invitations(&self) -> &InMemoryPlatformInvitationStore {
        &self.invitations
    }

    /// Returns the in-memory external identity store.
    #[must_use]
    pub const fn external_identities(&self) -> &InMemoryPlatformExternalIdentityStore {
        &self.external_identities
    }

    /// Returns the in-memory role binding store.
    #[must_use]
    pub const fn role_bindings(&self) -> &InMemoryPlatformRoleBindingStore {
        &self.role_bindings
    }

    /// Returns the in-memory audit event store.
    #[must_use]
    pub const fn audits(&self) -> &InMemoryPlatformAuditStore {
        &self.audits
    }

    /// Returns the authorization engine.
    #[must_use]
    pub const fn authorization(&self) -> &FoundationAuthorizationEngine {
        &self.authorization
    }
}

/// Result type returned by platform service startup helpers.
pub type PlatformRunResult<T> = std::result::Result<T, PlatformRunError>;

/// Platform service startup error.
#[derive(Debug)]
pub enum PlatformRunError {
    /// Startup configuration is unsafe or incomplete.
    Config(PlatformConfigError),
    /// Durable `PostgreSQL` configuration is missing when required.
    MissingDatabaseUrl,
    /// Durable `PostgreSQL` connection failed.
    DatabaseConnection(String),
    /// Durable repository bootstrap failed.
    DurableBootstrap(PlatformRepositoryError),
    /// Embedded migration execution failed.
    Migration(PlatformMigrationError),
    /// HTTP listener binding failed.
    ListenerBind {
        /// Listen address that failed to bind.
        listen_addr: String,
        /// Operator-facing bind failure message.
        message: String,
    },
    /// HTTP server exited with an error.
    Server(String),
}

impl Display for PlatformRunError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Config(error) => write!(formatter, "{error}"),
            Self::MissingDatabaseUrl => formatter
                .write_str("STARWEAVER_PLATFORM_DATABASE_URL is required for the postgres backend"),
            Self::DatabaseConnection(message) | Self::Server(message) => {
                write!(formatter, "{message}")
            }
            Self::DurableBootstrap(error) => write!(formatter, "{error}"),
            Self::Migration(error) => write!(formatter, "{error}"),
            Self::ListenerBind {
                listen_addr,
                message,
            } => {
                write!(
                    formatter,
                    "failed to bind platform listener {listen_addr}: {message}"
                )
            }
        }
    }
}

impl std::error::Error for PlatformRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::DurableBootstrap(error) => Some(error),
            Self::Migration(error) => Some(error),
            Self::MissingDatabaseUrl
            | Self::DatabaseConnection(_)
            | Self::ListenerBind { .. }
            | Self::Server(_) => None,
        }
    }
}

impl From<PlatformConfigError> for PlatformRunError {
    fn from(error: PlatformConfigError) -> Self {
        Self::Config(error)
    }
}

impl From<PlatformMigrationError> for PlatformRunError {
    fn from(error: PlatformMigrationError) -> Self {
        Self::Migration(error)
    }
}

impl From<PlatformRepositoryError> for PlatformRunError {
    fn from(error: PlatformRepositoryError) -> Self {
        Self::DurableBootstrap(error)
    }
}

/// Builds platform service state from startup configuration.
///
/// # Errors
///
/// Returns [`PlatformRunError`] when configuration is unsafe, a required
/// durable connection is missing, `PostgreSQL` cannot be reached, or embedded
/// migrations fail.
pub async fn build_platform_service_state(
    config: &PlatformConfig,
) -> PlatformRunResult<PlatformServiceState> {
    validate_platform_config(config)?;
    let authorization = platform_authorization_for_config(config);
    match config.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(PlatformServiceState::new(
            InMemoryResourceOwnerStore::new(),
            authorization,
        )
        .with_single_user_auth(config.single_user_auth.clone())),
        PlatformRepositoryBackendKind::Postgres => {
            let database_url = config
                .database_url
                .as_deref()
                .ok_or(PlatformRunError::MissingDatabaseUrl)?;
            let pool = PgPoolOptions::new()
                .connect(database_url)
                .await
                .map_err(|error| {
                    PlatformRunError::DatabaseConnection(format!(
                        "failed to connect platform PostgreSQL repository: {error}"
                    ))
                })?;
            migrations::run(&pool).await?;
            let repository = PostgresPlatformRepository::new(pool);
            if let Some(single_user) = config.single_user_auth.as_ref() {
                repository
                    .bootstrap_single_user(&single_user_bootstrap_record(single_user))
                    .await?;
            }
            Ok(
                PlatformServiceState::with_postgres_repository(repository, authorization)
                    .with_single_user_auth(config.single_user_auth.clone()),
            )
        }
    }
}

fn platform_authorization_for_config(config: &PlatformConfig) -> FoundationAuthorizationEngine {
    let grants = if config.single_user_auth.is_some() {
        ActionGrant::for_builtin_role(
            SINGLE_USER_TENANT_ID,
            SINGLE_USER_TENANT_ID,
            SINGLE_USER_ID,
            crate::action::BuiltInRole::TenantOwner,
        )
    } else {
        Vec::<ActionGrant>::new()
    };
    FoundationAuthorizationEngine::new(grants)
}

fn single_user_bootstrap_record(
    single_user: &PlatformSingleUserConfig,
) -> SingleUserBootstrapRecord {
    SingleUserBootstrapRecord {
        tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
        organization_id: SINGLE_USER_ORGANIZATION_ID.to_owned(),
        project_id: SINGLE_USER_PROJECT_ID.to_owned(),
        user_id: SINGLE_USER_ID.to_owned(),
        identity_provider_id: SINGLE_USER_IDENTITY_PROVIDER_ID.to_owned(),
        external_identity_id: SINGLE_USER_EXTERNAL_IDENTITY_ID.to_owned(),
        organization_member_id: SINGLE_USER_ORGANIZATION_MEMBER_ID.to_owned(),
        project_member_id: SINGLE_USER_PROJECT_MEMBER_ID.to_owned(),
        role_binding_id: SINGLE_USER_ROLE_BINDING_ID.to_owned(),
        username: single_user.username().to_owned(),
        user_display_name: single_user.user_display_name().to_owned(),
        user_primary_email: single_user.user_primary_email().map(ToOwned::to_owned),
        tenant_display_name: "Single User Tenant".to_owned(),
        organization_display_name: "Single User Organization".to_owned(),
        project_display_name: "Single User Project".to_owned(),
    }
}

/// Runs the platform HTTP service until shutdown.
///
/// # Errors
///
/// Returns [`PlatformRunError`] when configuration validation, durable state
/// initialization, listener binding, or HTTP serving fails.
pub async fn run(config: PlatformConfig) -> PlatformRunResult<()> {
    let state = build_platform_service_state(&config).await?;
    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|error| PlatformRunError::ListenerBind {
            listen_addr: config.listen_addr.clone(),
            message: error.to_string(),
        })?;
    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|error| PlatformRunError::Server(format!("platform server failed: {error}")))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let wait_forever = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = wait_forever => {}
    }
}

/// Builds the platform foundation router.
///
/// The current authentication extractor resolves opaque bearer session tokens,
/// API keys, service tokens, and verified mTLS identities through
/// platform-local stores. Production entrypoints can replace the in-memory
/// stores with durable resolvers without changing route ownership authorization.
pub fn router(state: PlatformServiceState) -> Router {
    admin_routes()
        .merge(auth_routes())
        .fallback(dispatch_foundation_request)
        .with_state(state)
}

fn auth_routes() -> Router<PlatformServiceState> {
    Router::new()
        .route("/auth/v1/providers", get(list_auth_providers))
        .route(
            "/auth/v1/providers/{identity_provider_id}/start",
            post(start_oidc_login),
        )
        .route(
            "/auth/v1/providers/{identity_provider_id}/login",
            get(login_oidc_provider),
        )
        .route(
            "/auth/v1/providers/{identity_provider_id}/callback",
            post(oidc_login_callback),
        )
        .route(
            "/auth/v1/invitations/{invitation_token}/preview",
            get(preview_auth_invitation),
        )
        .route(
            "/auth/v1/invitations/{invitation_token}/accept",
            post(accept_auth_invitation),
        )
        .route("/auth/v1/session", get(get_current_auth_session))
        .route(
            "/auth/v1/session/active-organization",
            post(update_current_auth_session_active_organization),
        )
        .route(
            "/auth/v1/session/active-project",
            post(update_current_auth_session_active_project),
        )
        .route("/auth/v1/logout", post(logout_current_auth_session))
        .route("/auth/v1/single-user/login", post(single_user_login))
}

fn admin_routes() -> Router<PlatformServiceState> {
    Router::new()
        .route(
            "/admin/v1/identity-providers",
            get(list_oidc_identity_providers).post(create_oidc_identity_provider),
        )
        .route(
            "/admin/v1/identity-providers/{identity_provider_id}",
            get(get_oidc_identity_provider),
        )
        .route("/admin/v1/users", get(list_platform_users))
        .route("/admin/v1/users/{user_id}", get(get_platform_user))
        .route(
            "/admin/v1/users/{user_id}/status",
            post(update_platform_user_status),
        )
        .route(
            "/admin/v1/users/{user_id}/sessions",
            get(list_user_auth_sessions),
        )
        .route(
            "/admin/v1/users/{user_id}/sessions/{auth_session_id}/revoke",
            post(revoke_user_auth_session),
        )
        .route(
            "/admin/v1/users/{user_id}/external-identities",
            get(list_user_external_identities),
        )
        .route(
            "/admin/v1/users/{user_id}/external-identities/{external_identity_id}",
            get(get_user_external_identity),
        )
        .route(
            "/admin/v1/users/{user_id}/external-identities/{external_identity_id}/unlink",
            post(unlink_user_external_identity),
        )
        .route(
            "/admin/v1/role-bindings",
            get(list_role_bindings).post(create_role_binding),
        )
        .route(
            "/admin/v1/role-bindings/{role_binding_id}",
            get(get_role_binding),
        )
        .route(
            "/admin/v1/role-bindings/{role_binding_id}/status",
            post(update_role_binding_status),
        )
        .route("/admin/v1/audit-events", get(list_platform_audit_events))
        .route(
            "/admin/v1/organizations/{organization_id}/members",
            get(list_organization_members).post(create_organization_member),
        )
        .route(
            "/admin/v1/organizations/{organization_id}/members/{organization_member_id}",
            get(get_organization_member),
        )
        .route(
            "/admin/v1/organizations/{organization_id}/members/{organization_member_id}/status",
            post(update_organization_member_status),
        )
        .route(
            "/admin/v1/organizations/{organization_id}/members/{organization_member_id}/remove",
            post(remove_organization_member),
        )
        .route(
            "/admin/v1/organizations/{organization_id}/invitations",
            get(list_organization_invitations).post(create_organization_invitation),
        )
        .route(
            "/admin/v1/organizations/{organization_id}/invitations/{invitation_id}",
            get(get_organization_invitation),
        )
        .route(
            "/admin/v1/organizations/{organization_id}/invitations/{invitation_id}/revoke",
            post(revoke_organization_invitation),
        )
        .route(
            "/admin/v1/projects/{project_id}/members",
            get(list_project_members).post(create_project_member),
        )
        .route(
            "/admin/v1/projects/{project_id}/members/{project_member_id}",
            get(get_project_member),
        )
        .route(
            "/admin/v1/projects/{project_id}/members/{project_member_id}/status",
            post(update_project_member_status),
        )
        .route(
            "/admin/v1/secret-refs",
            get(list_platform_secret_refs).post(create_platform_secret_ref),
        )
        .route(
            "/admin/v1/secret-refs/{secret_ref_id}",
            get(get_platform_secret_ref),
        )
}

#[derive(Clone, Debug, Deserialize)]
struct AuthProviderDiscoveryQuery {
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OidcLoginStartRequest {
    #[serde(default)]
    tenant_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct OidcLoginCallbackRequest {
    state: String,
    code: String,
    nonce: String,
    code_verifier: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CreateOrganizationMemberRequest {
    #[serde(default)]
    organization_member_id: Option<String>,
    principal_id: String,
    #[serde(default)]
    membership_kind: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct UpdateActiveOrganizationRequest {
    organization_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct UpdateActiveProjectRequest {
    project_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct UpdateMembershipStatusRequest {
    expected_version: i64,
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CreateRoleBindingRequest {
    #[serde(default, rename = "role_binding_id")]
    binding: Option<String>,
    #[serde(default, rename = "tenant_id")]
    tenant: Option<String>,
    #[serde(default, rename = "organization_id")]
    organization: Option<String>,
    #[serde(default, rename = "project_id")]
    project: Option<String>,
    #[serde(rename = "principal_id")]
    principal: String,
    #[serde(rename = "role_id")]
    role: String,
}

#[derive(Clone, Debug, Deserialize)]
struct UpdateRoleBindingStatusRequest {
    expected_version: i64,
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct UpdatePlatformUserStatusRequest {
    expected_version: i64,
    status: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    strong_auth_confirmation: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RevokePlatformAuthSessionRequest {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    strong_auth_confirmation: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct UnlinkPlatformExternalIdentityRequest {
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    strong_auth_confirmation: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ListPlatformAuditEventsQuery {
    #[serde(default)]
    organization_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    event_type: Option<String>,
    #[serde(default)]
    action_id: Option<String>,
    #[serde(default)]
    resource_kind: Option<String>,
    #[serde(default)]
    resource_id: Option<String>,
    #[serde(default)]
    actor_principal_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    strong_auth_confirmation: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RemoveOrganizationMemberRequest {
    expected_version: i64,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CreateOrganizationInvitationRequest {
    #[serde(default)]
    invitation_id: Option<String>,
    #[serde(default)]
    project_id: Option<String>,
    #[serde(default)]
    invited_email: Option<String>,
    #[serde(default)]
    invited_principal_id: Option<String>,
    #[serde(default)]
    role_id: Option<String>,
    #[serde(default)]
    expires_at_unix: Option<i64>,
}

#[derive(Clone, Debug, Deserialize)]
struct RevokeOrganizationInvitationRequest {
    expected_version: i64,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct CreateProjectMemberRequest {
    #[serde(default)]
    project_member_id: Option<String>,
    organization_member_id: String,
}

#[derive(Clone, Debug, Deserialize)]
struct OidcTokenResponse {
    id_token: String,
}

#[derive(Clone, Deserialize)]
struct CreateOidcIdentityProviderRequest {
    #[serde(default)]
    identity_provider_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    display_name: String,
    issuer_url: String,
    #[serde(default)]
    authorization_endpoint: Option<String>,
    #[serde(default)]
    token_endpoint: Option<String>,
    #[serde(default)]
    jwks_uri: Option<String>,
    client_id: String,
    #[serde(default)]
    client_secret_ref: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    token_endpoint_auth_method: Option<String>,
    redirect_uri: String,
    #[serde(default)]
    requested_scopes: Vec<String>,
    #[serde(default)]
    accepted_audiences: Vec<String>,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Clone, Deserialize)]
struct CreateSecretRefHttpRequest {
    #[serde(default)]
    secret_ref_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    purpose: String,
    #[serde(default)]
    backend_kind: Option<String>,
    #[serde(default)]
    backend_locator: Option<String>,
    #[serde(default)]
    environment_variable: Option<String>,
    #[serde(default)]
    secret_value: Option<String>,
}

async fn create_oidc_identity_provider(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreateOidcIdentityProviderRequest>,
) -> Result<Json<Value>, ServiceError> {
    if request.client_secret.is_some() {
        return Err(ServiceError::BadRequest(
            "oidc_client_secret_raw_unsupported",
        ));
    }
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let tenant_id = tenant_from_request_or_actor(request.tenant_id.as_deref(), &actor)?;
    let resource = ResourceRef::tenant("IdentityProvider", &tenant_id, &tenant_id);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::IdentityProviderWrite,
        &resource,
    )
    .await?;
    let provider = oidc_provider_record_from_create_request(request, &tenant_id)?;
    if let Some(secret_ref_id) = provider.client_secret_ref.as_deref() {
        let secret = secret_ref_by_id(&state, secret_ref_id).await?;
        if secret.tenant_id != provider.tenant_id {
            return Err(ServiceError::Forbidden("tenant_mismatch"));
        }
    }
    upsert_oidc_login_provider(&state, &provider, &actor).await?;
    Ok(Json(json!({
        "schema": "platform.admin.identity_provider.v1",
        "resource": oidc_provider_safe_json(&provider),
    })))
}

async fn list_oidc_identity_providers(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = ResourceRef::tenant("IdentityProvider", &actor.tenant_id, &actor.tenant_id);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::IdentityProviderRead,
        &resource,
    )
    .await?;
    let providers = oidc_login_providers_for_tenant(&state, &actor.tenant_id).await?;
    Ok(Json(json!({
        "schema": "platform.admin.identity_provider.list.v1",
        "resources": providers.iter().map(oidc_provider_safe_json).collect::<Vec<_>>(),
    })))
}

async fn get_oidc_identity_provider(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(identity_provider_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let provider = oidc_login_provider(&state, &identity_provider_id).await?;
    let resource = ResourceRef::tenant(
        "IdentityProvider",
        &provider.tenant_id,
        &provider.identity_provider_id,
    );
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::IdentityProviderRead,
        &resource,
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.identity_provider.v1",
        "resource": oidc_provider_safe_json(&provider),
    })))
}

async fn list_platform_users(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = ResourceRef::tenant("User", &actor.tenant_id, &actor.tenant_id);
    authorize_service_action(&state, &actor, PlatformAction::UserRead, &resource).await?;
    let users = platform_users_for_tenant(&state, &actor.tenant_id).await?;
    Ok(Json(json!({
        "schema": "platform.admin.user.list.v1",
        "resources": users.iter().map(platform_user_safe_json).collect::<Vec<_>>(),
    })))
}

async fn get_platform_user(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let user = platform_user_by_id(&state, &user_id).await?;
    ensure_actor_tenant(&actor, &user.tenant_id)?;
    let resource = platform_user_resource(&user);
    authorize_service_action(&state, &actor, PlatformAction::UserRead, &resource).await?;
    Ok(Json(json!({
        "schema": "platform.admin.user.v1",
        "resource": platform_user_safe_json(&user),
    })))
}

async fn update_platform_user_status(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
    Json(request): Json<UpdatePlatformUserStatusRequest>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before = platform_user_by_id(&state, &user_id).await?;
    ensure_actor_tenant(&actor, &before.tenant_id)?;
    let resource = platform_user_resource(&before);
    authorize_service_action(&state, &actor, PlatformAction::UserWrite, &resource).await?;
    require_strong_auth_confirmation(request.strong_auth_confirmation.as_deref())?;
    let status = platform_user_status_from_request(&request.status)?;
    let updated =
        set_platform_user_status(&state, &user_id, request.expected_version, status).await?;
    let disabled_session_count = if updated.status.accepts_access() {
        0
    } else {
        disable_auth_sessions_for_principal(&state, &updated.tenant_id, &updated.user_id).await?
    };
    let audit_event = record_platform_audit_event(
        &state,
        &actor,
        PlatformAction::UserWrite,
        &resource,
        "platform.user.status.update",
        request.reason.as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.user_mutation.v1",
        "resource": platform_user_safe_json(&updated),
        "previous_status": before.status.as_str(),
        "disabled_session_count": disabled_session_count,
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
        "strong_auth_confirmed": true,
        "audit_event_id": audit_event.audit_event_id,
    })))
}

async fn list_user_auth_sessions(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let user = platform_user_by_id(&state, &user_id).await?;
    ensure_actor_tenant(&actor, &user.tenant_id)?;
    let resource = ResourceRef::tenant("AuthSession", &user.tenant_id, &user.user_id);
    authorize_service_action(&state, &actor, PlatformAction::AuthSessionRead, &resource).await?;
    let sessions = auth_sessions_for_principal(&state, &user.tenant_id, &user.user_id).await?;
    Ok(Json(json!({
        "schema": "platform.admin.user_auth_session.list.v1",
        "user_id": user.user_id,
        "resources": sessions.iter().map(auth_session_safe_json).collect::<Vec<_>>(),
    })))
}

async fn revoke_user_auth_session(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((user_id, auth_session_id)): Path<(String, String)>,
    Json(request): Json<RevokePlatformAuthSessionRequest>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let user = platform_user_by_id(&state, &user_id).await?;
    ensure_actor_tenant(&actor, &user.tenant_id)?;
    let resource = ResourceRef::tenant("AuthSession", &user.tenant_id, &auth_session_id);
    authorize_service_action(&state, &actor, PlatformAction::AuthSessionRevoke, &resource).await?;
    require_strong_auth_confirmation(request.strong_auth_confirmation.as_deref())?;
    let before = auth_session_by_id(&state, &auth_session_id).await?;
    ensure_auth_session_belongs_to_user(&before, &user)?;
    let revoked = revoke_auth_session_by_id(&state, &auth_session_id, &user).await?;
    let audit_event = record_platform_audit_event(
        &state,
        &actor,
        PlatformAction::AuthSessionRevoke,
        &resource,
        "platform.auth_session.revoke",
        request.reason.as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.user_auth_session_mutation.v1",
        "resource": auth_session_safe_json(&revoked),
        "previous_status": before.status.as_str(),
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
        "strong_auth_confirmed": true,
        "audit_event_id": audit_event.audit_event_id,
    })))
}

async fn list_platform_audit_events(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Query(query): Query<ListPlatformAuditEventsQuery>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    require_strong_auth_confirmation(query.strong_auth_confirmation.as_deref())?;
    validate_audit_event_list_query(&query)?;
    let resource = audit_event_list_resource(&actor, &query)?;
    authorize_service_action(&state, &actor, PlatformAction::AuditEventRead, &resource).await?;
    let limit = audit_event_list_limit(query.limit)?;
    let offset = audit_event_list_offset(query.cursor.as_deref())?;
    let mut events = platform_audit_events_for_tenant(&state, &actor.tenant_id)
        .await?
        .into_iter()
        .filter(|event| audit_event_matches_query(event, &query))
        .collect::<Vec<_>>();
    events.sort_by(|left, right| {
        right
            .created_at_unix
            .cmp(&left.created_at_unix)
            .then_with(|| right.audit_event_id.cmp(&left.audit_event_id))
    });
    let total_filtered_count = events.len();
    let page = events
        .iter()
        .skip(offset)
        .take(limit)
        .map(audit_event_safe_json)
        .collect::<Vec<_>>();
    let next_offset = offset.saturating_add(page.len());
    let next_cursor = (next_offset < total_filtered_count).then(|| next_offset.to_string());
    Ok(Json(json!({
        "schema": "platform.admin.audit_event.list.v1",
        "resources": page,
        "limit": limit,
        "cursor": query.cursor,
        "next_cursor": next_cursor,
        "total_filtered_count": total_filtered_count,
        "strong_auth_confirmed": true,
    })))
}

async fn list_user_external_identities(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(user_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = ResourceRef::tenant("ExternalIdentity", &actor.tenant_id, &user_id);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::ExternalIdentityRead,
        &resource,
    )
    .await?;
    let identities = external_identities_for_principal(&state, &actor.tenant_id, &user_id).await?;
    Ok(Json(json!({
        "schema": "platform.admin.external_identity.list.v1",
        "user_id": user_id,
        "resources": identities
            .iter()
            .map(external_identity_safe_json)
            .collect::<Vec<_>>(),
    })))
}

async fn get_user_external_identity(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((user_id, external_identity_id)): Path<(String, String)>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let identity =
        external_identity_for_actor(&state, &actor, &user_id, &external_identity_id).await?;
    let resource = external_identity_resource(&identity);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::ExternalIdentityRead,
        &resource,
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.external_identity.v1",
        "resource": external_identity_safe_json(&identity),
    })))
}

async fn unlink_user_external_identity(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((user_id, external_identity_id)): Path<(String, String)>,
    Json(request): Json<UnlinkPlatformExternalIdentityRequest>,
) -> Result<Json<Value>, ServiceError> {
    validate_user_id(&user_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before =
        external_identity_for_actor(&state, &actor, &user_id, &external_identity_id).await?;
    if before.provider_kind == "single_user" {
        return Err(ServiceError::BadRequest(
            "single_user_identity_unlink_forbidden",
        ));
    }
    let resource = external_identity_resource(&before);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::ExternalIdentityUnlink,
        &resource,
    )
    .await?;
    require_strong_auth_confirmation(request.strong_auth_confirmation.as_deref())?;
    let unlinked = unlink_external_identity(&state, &external_identity_id).await?;
    let audit_event = record_platform_audit_event(
        &state,
        &actor,
        PlatformAction::ExternalIdentityUnlink,
        &resource,
        "platform.external_identity.unlink",
        request.reason.as_deref(),
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.external_identity_mutation.v1",
        "resource": external_identity_safe_json(&unlinked),
        "previous_status": before.status.as_str(),
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
        "strong_auth_confirmed": true,
        "audit_event_id": audit_event.audit_event_id,
        "unlinked": unlinked.status == PlatformExternalIdentityStatus::Deleted,
        "raw_tokens_included": false,
    })))
}

async fn list_role_bindings(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = role_binding_collection_resource_for_actor(&actor);
    authorize_service_action(&state, &actor, PlatformAction::RoleBindingRead, &resource).await?;
    let bindings = role_bindings_for_tenant(&state, &actor.tenant_id).await?;
    let resources = bindings
        .iter()
        .filter(|binding| role_binding_visible_in_collection(binding, &resource))
        .map(role_binding_safe_json)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "platform.admin.role_binding.list.v1",
        "resources": resources,
    })))
}

async fn create_role_binding(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreateRoleBindingRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let tenant_id = tenant_from_request_or_actor(request.tenant.as_deref(), &actor)?;
    let candidate = role_binding_record_from_create_request(request, &tenant_id)?;
    let resource = role_binding_resource(&candidate);
    authorize_service_action(&state, &actor, PlatformAction::RoleBindingWrite, &resource).await?;
    let existing = equivalent_role_binding(&state, &candidate).await?;
    let requested = existing.as_ref().unwrap_or(&candidate);
    let binding = upsert_role_binding(&state, requested, &actor).await?;
    Ok(Json(json!({
        "schema": "platform.admin.role_binding_mutation.v1",
        "resource": role_binding_safe_json(&binding),
        "created": existing.is_none(),
    })))
}

async fn get_role_binding(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(role_binding_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let binding = role_binding_by_id(&state, &role_binding_id).await?;
    let resource = role_binding_resource(&binding);
    authorize_service_action(&state, &actor, PlatformAction::RoleBindingRead, &resource).await?;
    Ok(Json(json!({
        "schema": "platform.admin.role_binding.v1",
        "resource": role_binding_safe_json(&binding),
    })))
}

async fn update_role_binding_status(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(role_binding_id): Path<String>,
    Json(request): Json<UpdateRoleBindingStatusRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before = role_binding_by_id(&state, &role_binding_id).await?;
    let resource = role_binding_resource(&before);
    authorize_service_action(&state, &actor, PlatformAction::RoleBindingWrite, &resource).await?;
    let status = role_binding_status_from_request(&request.status)?;
    let updated =
        set_role_binding_status(&state, &role_binding_id, request.expected_version, status).await?;
    Ok(Json(json!({
        "schema": "platform.admin.role_binding_mutation.v1",
        "resource": role_binding_safe_json(&updated),
        "previous_status": before.status.as_str(),
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
    })))
}

async fn list_organization_members(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = organization_scope_resource(&actor, &organization_id, "OrganizationMember")?;
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationMemberRead,
        &resource,
    )
    .await?;
    let members = organization_members_for_organization(&state, &organization_id).await?;
    let resources = members
        .iter()
        .filter(|member| member.tenant_id == actor.tenant_id)
        .map(organization_member_safe_json)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "platform.admin.organization_member.list.v1",
        "organization_id": organization_id,
        "resources": resources,
    })))
}

async fn create_organization_member(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(request): Json<CreateOrganizationMemberRequest>,
) -> Result<Json<Value>, ServiceError> {
    validate_organization_id(&organization_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = organization_scope_resource(&actor, &organization_id, "OrganizationMember")?;
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationMemberWrite,
        &resource,
    )
    .await?;
    let principal_id = request.principal_id.trim();
    let membership_kind = normalized_membership_kind(request.membership_kind)?;
    let existing_members = organization_members_for_organization(&state, &organization_id).await?;
    let existing = existing_members.iter().find(|member| {
        member.tenant_id == actor.tenant_id
            && member.organization_id == organization_id
            && member.principal_id == principal_id
    });
    let organization_member_id = normalized_optional_string(request.organization_member_id)
        .unwrap_or_else(|| {
            existing.map_or_else(
                || new_prefixed_id("om"),
                |member| member.organization_member_id.clone(),
            )
        });
    let member = upsert_organization_member(
        &state,
        &organization_member_id,
        &organization_id,
        principal_id,
        &membership_kind,
        &actor,
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_member_mutation.v1",
        "resource": organization_member_safe_json(&member),
        "created": existing.is_none(),
    })))
}

async fn get_organization_member(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((organization_id, organization_member_id)): Path<(String, String)>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let member =
        organization_member_for_actor(&state, &actor, &organization_id, &organization_member_id)
            .await?;
    let resource = organization_member_resource(&member);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationMemberRead,
        &resource,
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_member.v1",
        "resource": organization_member_safe_json(&member),
    })))
}

async fn update_organization_member_status(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((organization_id, organization_member_id)): Path<(String, String)>,
    Json(request): Json<UpdateMembershipStatusRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before =
        organization_member_for_actor(&state, &actor, &organization_id, &organization_member_id)
            .await?;
    let resource = organization_member_resource(&before);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationMemberWrite,
        &resource,
    )
    .await?;
    let status = membership_status_from_request(&request.status)?;
    let updated = set_organization_member_status(
        &state,
        &organization_member_id,
        request.expected_version,
        status,
    )
    .await?;
    let cascaded_project_member_count =
        cascade_project_memberships_for_organization_member(&state, &updated, status).await?;
    let cascaded_role_binding_count = if status == PlatformMembershipStatus::Removed {
        delete_role_bindings_for_organization_principal(&state, &updated).await?
    } else {
        0
    };
    Ok(Json(json!({
        "schema": "platform.admin.organization_member_mutation.v1",
        "resource": organization_member_safe_json(&updated),
        "previous_status": before.status.as_str(),
        "cascaded_project_member_count": cascaded_project_member_count,
        "cascaded_role_binding_count": cascaded_role_binding_count,
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
    })))
}

async fn remove_organization_member(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((organization_id, organization_member_id)): Path<(String, String)>,
    Json(request): Json<RemoveOrganizationMemberRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before =
        organization_member_for_actor(&state, &actor, &organization_id, &organization_member_id)
            .await?;
    let resource = organization_member_resource(&before);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationMemberWrite,
        &resource,
    )
    .await?;
    let updated = set_organization_member_status(
        &state,
        &organization_member_id,
        request.expected_version,
        PlatformMembershipStatus::Removed,
    )
    .await?;
    let cascaded_project_member_count = cascade_project_memberships_for_organization_member(
        &state,
        &updated,
        PlatformMembershipStatus::Removed,
    )
    .await?;
    let cascaded_role_binding_count =
        delete_role_bindings_for_organization_principal(&state, &updated).await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_member_mutation.v1",
        "resource": organization_member_safe_json(&updated),
        "previous_status": before.status.as_str(),
        "removed": updated.status == PlatformMembershipStatus::Removed,
        "cascaded_project_member_count": cascaded_project_member_count,
        "cascaded_role_binding_count": cascaded_role_binding_count,
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
    })))
}

async fn list_organization_invitations(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = organization_scope_resource(&actor, &organization_id, "OrganizationInvitation")?;
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationInvitationRead,
        &resource,
    )
    .await?;
    let invitations =
        organization_invitations_for_organization(&state, &actor.tenant_id, &organization_id)
            .await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_invitation.list.v1",
        "organization_id": organization_id,
        "resources": invitations
            .iter()
            .map(organization_invitation_safe_json)
            .collect::<Vec<_>>(),
    })))
}

async fn create_organization_invitation(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(organization_id): Path<String>,
    Json(request): Json<CreateOrganizationInvitationRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = organization_scope_resource(&actor, &organization_id, "OrganizationInvitation")?;
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationInvitationCreate,
        &resource,
    )
    .await?;
    let now_unix = current_unix_timestamp();
    let (invitation, raw_token) = organization_invitation_record_from_create_request(
        request,
        &actor,
        &organization_id,
        now_unix,
    )?;
    let created = insert_organization_invitation(&state, &invitation).await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_invitation_mutation.v1",
        "resource": organization_invitation_safe_json(&created),
        "invitation_token": raw_token,
        "invitation_token_returned_once": true,
    })))
}

async fn get_organization_invitation(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(String, String)>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let invitation =
        organization_invitation_for_actor(&state, &actor, &organization_id, &invitation_id).await?;
    let resource = organization_invitation_resource(&invitation);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationInvitationRead,
        &resource,
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_invitation.v1",
        "resource": organization_invitation_safe_json(&invitation),
    })))
}

async fn revoke_organization_invitation(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((organization_id, invitation_id)): Path<(String, String)>,
    Json(request): Json<RevokeOrganizationInvitationRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before =
        organization_invitation_for_actor(&state, &actor, &organization_id, &invitation_id).await?;
    let resource = organization_invitation_resource(&before);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::OrganizationInvitationManage,
        &resource,
    )
    .await?;
    let revoked = revoke_organization_invitation_by_id(
        &state,
        &invitation_id,
        request.expected_version,
        current_unix_timestamp(),
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.organization_invitation_mutation.v1",
        "resource": organization_invitation_safe_json(&revoked),
        "previous_status": before.status.as_str(),
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
    })))
}

async fn list_project_members(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let members = project_members_for_project(&state, &project_id).await?;
    let resource = members.first().map_or_else(
        || project_scope_resource(&actor, &project_id, "ProjectMember"),
        |member| {
            Ok(ResourceRef::project(
                "ProjectMember",
                &member.tenant_id,
                &member.organization_id,
                &member.project_id,
                &member.project_id,
            ))
        },
    )?;
    authorize_service_action(&state, &actor, PlatformAction::ProjectMemberRead, &resource).await?;
    let resources = members
        .iter()
        .filter(|member| member.tenant_id == actor.tenant_id)
        .map(project_member_safe_json)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "schema": "platform.admin.project_member.list.v1",
        "project_id": project_id,
        "resources": resources,
    })))
}

async fn create_project_member(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(project_id): Path<String>,
    Json(request): Json<CreateProjectMemberRequest>,
) -> Result<Json<Value>, ServiceError> {
    validate_project_id(&project_id)?;
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let organization_member =
        active_organization_member_by_id_for_actor(&state, &actor, &request.organization_member_id)
            .await?;
    let existing_project_members = project_members_for_project(&state, &project_id).await?;
    ensure_project_member_create_matches_project_organization(
        &existing_project_members,
        &organization_member,
    )?;
    let resource = ResourceRef::project(
        "ProjectMember",
        &organization_member.tenant_id,
        &organization_member.organization_id,
        &project_id,
        &project_id,
    );
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::ProjectMemberWrite,
        &resource,
    )
    .await?;
    let existing = existing_project_members.iter().find(|member| {
        member.tenant_id == organization_member.tenant_id
            && member.project_id == project_id
            && member.principal_id == organization_member.principal_id
    });
    let project_member_id =
        normalized_optional_string(request.project_member_id).unwrap_or_else(|| {
            existing.map_or_else(
                || new_prefixed_id("pm"),
                |member| member.project_member_id.clone(),
            )
        });
    let created = upsert_project_member_from_organization_member(
        &state,
        &project_member_id,
        &project_id,
        &organization_member,
        &actor,
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.admin.project_member_mutation.v1",
        "resource": project_member_safe_json(&created),
        "created": existing.is_none(),
        "organization_member_required": true,
    })))
}

async fn get_project_member(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((project_id, project_member_id)): Path<(String, String)>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let member = project_member_for_actor(&state, &actor, &project_id, &project_member_id).await?;
    let resource = project_member_resource(&member);
    authorize_service_action(&state, &actor, PlatformAction::ProjectMemberRead, &resource).await?;
    Ok(Json(json!({
        "schema": "platform.admin.project_member.v1",
        "resource": project_member_safe_json(&member),
    })))
}

async fn update_project_member_status(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path((project_id, project_member_id)): Path<(String, String)>,
    Json(request): Json<UpdateMembershipStatusRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let before = project_member_for_actor(&state, &actor, &project_id, &project_member_id).await?;
    let resource = project_member_resource(&before);
    authorize_service_action(
        &state,
        &actor,
        PlatformAction::ProjectMemberWrite,
        &resource,
    )
    .await?;
    let status = membership_status_from_request(&request.status)?;
    let updated =
        set_project_member_status(&state, &project_member_id, request.expected_version, status)
            .await?;
    let cascaded_role_binding_count = if status == PlatformMembershipStatus::Removed {
        delete_role_bindings_for_project_principal(&state, &updated).await?
    } else {
        0
    };
    Ok(Json(json!({
        "schema": "platform.admin.project_member_mutation.v1",
        "resource": project_member_safe_json(&updated),
        "previous_status": before.status.as_str(),
        "cascaded_role_binding_count": cascaded_role_binding_count,
        "reason_recorded": request.reason.as_deref().is_some_and(|value| !value.trim().is_empty()),
    })))
}

async fn create_platform_secret_ref(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Json(request): Json<CreateSecretRefHttpRequest>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let tenant_id = tenant_from_request_or_actor(request.tenant_id.as_deref(), &actor)?;
    let resource = ResourceRef::tenant("SecretRef", &tenant_id, &tenant_id);
    authorize_service_action(&state, &actor, PlatformAction::SecretRefWrite, &resource).await?;
    let secret_ref = secret_ref_record_from_create_request(&state, request, &tenant_id, &actor)?;
    upsert_secret_ref(&state, &secret_ref, &actor).await?;
    Ok(Json(json!({
        "schema": "platform.admin.secret_ref.v1",
        "resource": secret_ref_safe_json(&secret_ref),
    })))
}

async fn list_platform_secret_refs(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let resource = ResourceRef::tenant("SecretRef", &actor.tenant_id, &actor.tenant_id);
    authorize_service_action(&state, &actor, PlatformAction::SecretRefRead, &resource).await?;
    let refs = secret_refs_for_tenant(&state, &actor.tenant_id).await?;
    Ok(Json(json!({
        "schema": "platform.admin.secret_ref.list.v1",
        "resources": refs.iter().map(secret_ref_safe_json).collect::<Vec<_>>(),
    })))
}

async fn get_platform_secret_ref(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(secret_ref_id): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let actor = authenticated_actor_from_headers(&state, &headers).await?;
    let secret_ref = secret_ref_by_id(&state, &secret_ref_id).await?;
    let resource = ResourceRef::tenant(
        "SecretRef",
        &secret_ref.tenant_id,
        &secret_ref.secret_ref_id,
    );
    authorize_service_action(&state, &actor, PlatformAction::SecretRefRead, &resource).await?;
    Ok(Json(json!({
        "schema": "platform.admin.secret_ref.v1",
        "resource": secret_ref_safe_json(&secret_ref),
    })))
}

async fn list_auth_providers(
    State(state): State<PlatformServiceState>,
    Query(query): Query<AuthProviderDiscoveryQuery>,
) -> Result<Json<Value>, ServiceError> {
    let tenant_id = normalized_optional_string(query.tenant_id);
    if let Some(value) = tenant_id.as_deref() {
        validate_tenant_id(value)?;
    }

    let mut providers = Vec::new();
    if state.single_user_auth.is_some()
        && tenant_id
            .as_deref()
            .is_none_or(|value| value == SINGLE_USER_TENANT_ID)
    {
        providers.push(single_user_provider_public_json());
    }
    if let Some(tenant_id) = tenant_id.as_deref() {
        providers.extend(
            oidc_login_providers_for_tenant(&state, tenant_id)
                .await?
                .iter()
                .filter(|provider| provider.status == OidcLoginProviderStatus::Active)
                .map(oidc_provider_public_json),
        );
    }

    Ok(Json(json!({
        "schema": "platform.auth.providers.v1",
        "tenant_id": tenant_id,
        "providers": providers,
    })))
}

async fn start_oidc_login(
    State(state): State<PlatformServiceState>,
    Path(identity_provider_id): Path<String>,
    Json(request): Json<OidcLoginStartRequest>,
) -> Result<Json<Value>, ServiceError> {
    start_oidc_login_for_provider(state, identity_provider_id, request.tenant_id).await
}

async fn login_oidc_provider(
    State(state): State<PlatformServiceState>,
    Path(identity_provider_id): Path<String>,
    Query(query): Query<AuthProviderDiscoveryQuery>,
) -> Result<Json<Value>, ServiceError> {
    start_oidc_login_for_provider(state, identity_provider_id, query.tenant_id).await
}

async fn start_oidc_login_for_provider(
    state: PlatformServiceState,
    identity_provider_id: String,
    tenant_id: Option<String>,
) -> Result<Json<Value>, ServiceError> {
    let tenant_id = normalized_optional_string(tenant_id);
    if let Some(value) = tenant_id.as_deref() {
        validate_tenant_id(value)?;
    }
    let provider = oidc_login_provider(&state, &identity_provider_id).await?;
    if tenant_id
        .as_deref()
        .is_some_and(|value| value != provider.tenant_id)
    {
        return Err(ServiceError::ResourceNotFound);
    }
    if provider.status != OidcLoginProviderStatus::Active {
        return Err(ServiceError::AuthenticationFailed("oidc_provider_inactive"));
    }

    let metadata = oidc_resolved_provider_metadata(&state, &provider).await?;
    let raw_state = generate_base64url_secret(32);
    let raw_nonce = generate_base64url_secret(32);
    let raw_pkce_verifier = generate_base64url_secret(32);
    let now_unix = current_unix_timestamp();
    let attempt = OidcLoginAttemptRecord::active(crate::identity::OidcLoginAttemptStart {
        login_attempt_id: new_prefixed_id("ola"),
        tenant_id: provider.tenant_id.clone(),
        identity_provider_id: provider.identity_provider_id.clone(),
        raw_state: raw_state.clone(),
        raw_nonce: raw_nonce.clone(),
        raw_pkce_verifier: raw_pkce_verifier.clone(),
        redirect_uri: metadata.redirect_uri.clone(),
        expires_at_unix: now_unix + OIDC_LOGIN_ATTEMPT_TTL_SECONDS,
    })
    .map_err(|error| ServiceError::AuthenticationFailed(error.as_str()))?;
    record_oidc_login_attempt(&state, &attempt).await?;
    let authorization_url = oidc_authorization_url(
        &metadata,
        &provider.requested_scopes,
        &raw_state,
        &raw_nonce,
        &raw_pkce_verifier,
    )?;

    Ok(Json(json!({
        "schema": "platform.auth.oidc_login_start.v1",
        "provider": oidc_provider_public_json(&provider),
        "authorization_url": authorization_url,
        "attempt": {
            "login_attempt_id": attempt.login_attempt_id,
            "expires_at_unix": attempt.expires_at_unix,
        },
        "client_state": {
            "state": raw_state,
            "nonce": raw_nonce,
            "code_verifier": raw_pkce_verifier,
        },
        "provider_secret_material_included": false,
        "authorization_code_included": false,
        "raw_tokens_included": false,
    })))
}

async fn oidc_login_callback(
    State(state): State<PlatformServiceState>,
    Path(identity_provider_id): Path<String>,
    Json(request): Json<OidcLoginCallbackRequest>,
) -> Result<Json<Value>, ServiceError> {
    validate_oidc_callback_request(&request)?;
    let now_unix = current_unix_timestamp();
    let provider = oidc_login_provider(&state, &identity_provider_id).await?;
    let attempt = oidc_login_attempt_for_state(&state, &request.state).await?;
    validate_oidc_callback_attempt(&provider, &attempt, &request, now_unix)?;
    let metadata = oidc_resolved_provider_metadata(&state, &provider).await?;
    let client_secret = oidc_client_secret_for_metadata(&state, &metadata).await?;
    let id_token = exchange_oidc_authorization_code(
        &state,
        &metadata,
        &attempt,
        &request,
        client_secret.as_ref(),
    )
    .await?;
    let jwks = state
        .oidc_http
        .get_json::<JwkSet>(&metadata.jwks_uri)
        .await?;
    let claims = validate_oidc_id_token(&metadata, &jwks, &id_token, &request.nonce, now_unix)
        .map_err(|error| ServiceError::AuthenticationFailed(error.as_str()))?;
    let session_token = generate_session_token_with_prefix(OIDC_CALLBACK_SESSION_TOKEN_PREFIX);
    let completion =
        oidc_login_completion_record(&provider, &attempt, &claims, &session_token, now_unix);
    ensure_user_can_login(&state, &completion.user_id).await?;
    complete_oidc_login(&state, &completion).await?;
    Ok(Json(oidc_login_callback_response(
        &provider,
        &claims,
        &completion,
        &session_token,
    )))
}

async fn preview_auth_invitation(
    State(state): State<PlatformServiceState>,
    Path(invitation_token): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let invitation = organization_invitation_by_raw_token(&state, &invitation_token).await?;
    Ok(Json(json!({
        "schema": "platform.auth.invitation_preview.v1",
        "resource": organization_invitation_preview_json(&invitation, current_unix_timestamp()),
    })))
}

async fn accept_auth_invitation(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Path(invitation_token): Path<String>,
) -> Result<Json<Value>, ServiceError> {
    let (_, session) = mutating_auth_session_from_headers(&state, &headers).await?;
    ensure_user_auth_session(&session)?;
    let actor = &session.actor;
    let invitation = organization_invitation_by_raw_token(&state, &invitation_token).await?;
    ensure_actor_matches_invitation(actor, &invitation)?;
    let accepted = accept_organization_invitation_for_actor(
        &state,
        &invitation,
        actor,
        current_unix_timestamp(),
    )
    .await?;
    Ok(Json(json!({
        "schema": "platform.auth.invitation_accept.v1",
        "resource": organization_invitation_safe_json(&accepted.0),
        "organization_member": organization_member_safe_json(&accepted.1),
        "project_member": accepted.2.as_ref().map(project_member_safe_json),
        "invitation_token_included": false,
        "invitation_token_hash_included": false,
    })))
}

async fn get_current_auth_session(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ServiceError> {
    let (_, session) = auth_session_from_headers(&state, &headers).await?;
    ensure_user_auth_session(&session)?;
    Ok(Json(auth_session_response_json(&session)))
}

async fn update_current_auth_session_active_organization(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Json(request): Json<UpdateActiveOrganizationRequest>,
) -> Result<Json<Value>, ServiceError> {
    let organization_id = request.organization_id.trim();
    validate_organization_id(organization_id)?;
    let (raw_bearer, session) = mutating_auth_session_from_headers(&state, &headers).await?;
    ensure_user_auth_session(&session)?;
    let membership =
        active_organization_member_for_actor(&state, &session.actor, organization_id).await?;
    let updated =
        update_auth_session_context(&state, &raw_bearer, Some(&membership.organization_id), None)
            .await?;
    Ok(Json(auth_session_response_json(&updated)))
}

async fn update_current_auth_session_active_project(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    Json(request): Json<UpdateActiveProjectRequest>,
) -> Result<Json<Value>, ServiceError> {
    let project_id = request.project_id.trim();
    validate_project_id(project_id)?;
    let (raw_bearer, session) = mutating_auth_session_from_headers(&state, &headers).await?;
    ensure_user_auth_session(&session)?;
    let membership = active_project_member_for_actor(&state, &session.actor, project_id).await?;
    let updated = update_auth_session_context(
        &state,
        &raw_bearer,
        Some(&membership.organization_id),
        Some(&membership.project_id),
    )
    .await?;
    Ok(Json(auth_session_response_json(&updated)))
}

async fn logout_current_auth_session(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
) -> Result<Json<Value>, ServiceError> {
    let (raw_bearer, session) = mutating_auth_session_from_headers(&state, &headers).await?;
    ensure_user_auth_session(&session)?;
    let revoked = revoke_auth_session(&state, &raw_bearer).await?;
    Ok(Json(json!({
        "schema": "platform.auth.logout.v1",
        "session": auth_session_safe_json(&revoked),
        "previous_status": session.status.as_str(),
        "revoked": revoked.status.as_str() == "revoked",
        "session_token_hash_included": false,
        "raw_session_token_included": false,
    })))
}

async fn single_user_login(
    State(state): State<PlatformServiceState>,
    Json(request): Json<Value>,
) -> Result<Json<Value>, ServiceError> {
    let Some(config) = state.single_user_auth.as_ref() else {
        return Err(ServiceError::RouteNotFound);
    };
    let username = json_string_field(&request, "username")?;
    let password = json_string_field(&request, "password")?;
    if !config.credentials_match(username, password) {
        return Err(ServiceError::AuthenticationFailed(
            "single_user_credentials_invalid",
        ));
    }
    ensure_user_can_login(&state, SINGLE_USER_ID).await?;

    let session_token = generate_session_token();
    let session_id = format!(
        "sess_single_user_{}",
        &session_token
            [SINGLE_USER_SESSION_TOKEN_PREFIX.len()..SINGLE_USER_SESSION_TOKEN_PREFIX.len() + 16]
    );
    let actor = single_user_actor();
    let session_record =
        PlatformAuthSessionRecord::active(&session_id, &session_token, actor.clone());
    record_single_user_session(&state, session_record.clone()).await?;
    record_single_user_memberships(&state)?;

    Ok(Json(json!({
        "schema": "platform.auth.single_user_login.v1",
        "session": {
            "session_id": session_id,
            "token_type": "bearer",
            "access_token": session_token,
        },
        "csrf": csrf_response_json(&session_record),
        "actor": {
            "tenant_id": actor.tenant_id,
            "organization_id": actor.organization_id,
            "project_id": actor.project_id,
            "principal_id": actor.principal_id,
            "actor_kind": actor_kind_name(actor.actor_kind),
        },
        "user": {
            "user_id": SINGLE_USER_ID,
            "username": config.username(),
            "display_name": config.user_display_name(),
            "primary_email": config.user_primary_email(),
            "default_organization_id": SINGLE_USER_ORGANIZATION_ID,
            "default_project_id": SINGLE_USER_PROJECT_ID,
        },
        "organization": {
            "organization_id": SINGLE_USER_ORGANIZATION_ID,
            "display_name": "Single User Organization",
        },
        "project": {
            "project_id": SINGLE_USER_PROJECT_ID,
            "display_name": "Single User Project",
        },
    })))
}

fn tenant_from_request_or_actor(
    requested_tenant_id: Option<&str>,
    actor: &AuthenticatedActor,
) -> Result<String, ServiceError> {
    match requested_tenant_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(tenant_id) if tenant_id == actor.tenant_id => Ok(tenant_id.to_owned()),
        Some(_) => Err(ServiceError::Forbidden("tenant_mismatch")),
        None => Ok(actor.tenant_id.clone()),
    }
}

async fn authorize_service_action(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    action: PlatformAction,
    resource: &ResourceRef,
) -> Result<(), ServiceError> {
    let request = AuthorizationRequest {
        actor: actor.clone(),
        action,
        resource: resource.clone(),
    };
    let decision = state.authorization.authorize(&request);
    if decision.allowed {
        return Ok(());
    }
    if role_binding_authorization_allows(state, actor, action, resource).await? {
        return Ok(());
    }
    Err(ServiceError::Forbidden(decision.reason))
}

async fn role_binding_authorization_allows(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    action: PlatformAction,
    resource: &ResourceRef,
) -> Result<bool, ServiceError> {
    let bindings =
        active_role_bindings_for_principal(state, &actor.tenant_id, &actor.principal_id).await?;
    let mut grants = Vec::new();
    for binding in bindings {
        if role_binding_membership_allows(state, &binding).await? {
            grants.extend(role_binding_action_grants(&binding));
        }
    }
    let engine = FoundationAuthorizationEngine::new(grants);
    Ok(engine
        .authorize(&AuthorizationRequest {
            actor: actor.clone(),
            action,
            resource: resource.clone(),
        })
        .allowed)
}

async fn role_binding_membership_allows(
    state: &PlatformServiceState,
    binding: &PlatformRoleBindingRecord,
) -> Result<bool, ServiceError> {
    if let Some(project_id) = binding.project_id.as_deref() {
        let project_members = project_members_for_project(state, project_id).await?;
        return Ok(project_members.iter().any(|member| {
            member.tenant_id == binding.tenant_id
                && member.principal_id == binding.principal_id
                && member.status.accepts_access()
        }));
    }
    if let Some(organization_id) = binding.organization_id.as_deref() {
        let organization_members =
            organization_members_for_organization(state, organization_id).await?;
        return Ok(organization_members.iter().any(|member| {
            member.tenant_id == binding.tenant_id
                && member.principal_id == binding.principal_id
                && member.status.accepts_access()
        }));
    }
    Ok(true)
}

fn role_binding_action_grants(binding: &PlatformRoleBindingRecord) -> Vec<ActionGrant> {
    let Some(role) = binding.built_in_role() else {
        return Vec::new();
    };
    ActionGrant::for_builtin_role(
        &binding.tenant_id,
        role_binding_scope_id(binding),
        &binding.principal_id,
        role,
    )
}

fn role_binding_scope_id(binding: &PlatformRoleBindingRecord) -> &str {
    binding.project_id.as_deref().unwrap_or_else(|| {
        binding
            .organization_id
            .as_deref()
            .unwrap_or(binding.tenant_id.as_str())
    })
}

fn oidc_provider_record_from_create_request(
    request: CreateOidcIdentityProviderRequest,
    tenant_id: &str,
) -> Result<OidcLoginProviderRecord, ServiceError> {
    let identity_provider_id = request
        .identity_provider_id
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| new_prefixed_id("idp"));
    let client_secret_ref = normalized_optional_string(request.client_secret_ref);
    let token_endpoint_auth_method = token_endpoint_auth_method_from_request(
        request.token_endpoint_auth_method.as_deref(),
        client_secret_ref.is_some(),
    )?;
    let status = oidc_provider_status_from_request(request.status.as_deref())?;
    let record = OidcLoginProviderRecord {
        identity_provider_id,
        tenant_id: tenant_id.to_owned(),
        display_name: request.display_name.trim().to_owned(),
        issuer_url: request.issuer_url.trim().to_owned(),
        authorization_endpoint: request
            .authorization_endpoint
            .map_or_else(String::new, |value| value.trim().to_owned()),
        token_endpoint: request
            .token_endpoint
            .map_or_else(String::new, |value| value.trim().to_owned()),
        jwks_uri: request
            .jwks_uri
            .map_or_else(String::new, |value| value.trim().to_owned()),
        client_id: request.client_id.trim().to_owned(),
        client_secret_ref,
        token_endpoint_auth_method,
        redirect_uri: request.redirect_uri.trim().to_owned(),
        requested_scopes: normalized_string_vec(request.requested_scopes),
        accepted_audiences: normalized_string_vec(request.accepted_audiences),
        status,
    };
    crate::identity::validate_oidc_login_provider_base(&record)
        .map_err(|error| ServiceError::BadRequest(error.as_str()))?;
    Ok(record)
}

fn token_endpoint_auth_method_from_request(
    requested: Option<&str>,
    has_secret_ref: bool,
) -> Result<OidcTokenEndpointAuthMethod, ServiceError> {
    let method = requested
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            OidcTokenEndpointAuthMethod::from_id(value).ok_or(ServiceError::BadRequest(
                "oidc_token_endpoint_auth_method_invalid",
            ))
        })
        .transpose()?
        .unwrap_or(if has_secret_ref {
            OidcTokenEndpointAuthMethod::ClientSecretBasic
        } else {
            OidcTokenEndpointAuthMethod::None
        });
    Ok(method)
}

fn oidc_provider_status_from_request(
    status: Option<&str>,
) -> Result<OidcLoginProviderStatus, ServiceError> {
    match status.map_or("active", str::trim) {
        "active" => Ok(OidcLoginProviderStatus::Active),
        "disabled" => Ok(OidcLoginProviderStatus::Disabled),
        "deleted" => Ok(OidcLoginProviderStatus::Deleted),
        _ => Err(ServiceError::BadRequest("oidc_provider_status_invalid")),
    }
}

fn secret_ref_record_from_create_request(
    state: &PlatformServiceState,
    request: CreateSecretRefHttpRequest,
    tenant_id: &str,
    actor: &AuthenticatedActor,
) -> Result<PlatformSecretRefRecord, ServiceError> {
    let backend_kind = request
        .backend_kind
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(ENVIRONMENT_SECRET_BACKEND);
    let backend_locator = request
        .backend_locator
        .or(request.environment_variable)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::BadRequest("secret_backend_locator_empty"))?;
    let create = CreatePlatformSecretRefRequest {
        secret_ref_id: request
            .secret_ref_id
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| new_prefixed_id("sec")),
        tenant_id: tenant_id.to_owned(),
        organization_id: actor.organization_id.clone(),
        project_id: actor.project_id.clone(),
        purpose: request.purpose.trim().to_owned(),
        backend_kind: backend_kind.to_owned(),
        backend_locator,
        in_memory_secret_value: request.secret_value,
        created_by: actor.principal_id.clone(),
    };
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory
            if create.backend_kind == IN_MEMORY_SECRET_BACKEND =>
        {
            state
                .secrets
                .create_secret_ref(&create)
                .map_err(secret_error_to_service)
        }
        PlatformRepositoryBackendKind::InMemory
            if create.backend_kind == ENVIRONMENT_SECRET_BACKEND =>
        {
            state
                .secrets
                .create_environment_secret_ref(&create)
                .map_err(secret_error_to_service)
        }
        PlatformRepositoryBackendKind::Postgres
            if create.backend_kind == ENVIRONMENT_SECRET_BACKEND =>
        {
            environment_secret_ref_record(&create).map_err(secret_error_to_service)
        }
        PlatformRepositoryBackendKind::Postgres | PlatformRepositoryBackendKind::InMemory => {
            Err(ServiceError::BadRequest("secret_backend_kind_unsupported"))
        }
    }
}

async fn upsert_oidc_login_provider(
    state: &PlatformServiceState,
    provider: &OidcLoginProviderRecord,
    actor: &AuthenticatedActor,
) -> Result<(), ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            state.oidc_logins.upsert_provider(provider.clone());
            state
                .owners
                .record_resource_owner(ResourceOwnerRecord::tenant(
                    "IdentityProvider",
                    &provider.identity_provider_id,
                    &provider.tenant_id,
                ))
                .map_err(|error| ServiceError::Internal(error.as_str()))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .upsert_oidc_login_provider(provider, &actor.principal_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn oidc_login_providers_for_tenant(
    state: &PlatformServiceState,
    tenant_id: &str,
) -> Result<Vec<OidcLoginProviderRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            Ok(state.oidc_logins.providers_for_tenant(tenant_id))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .oidc_login_providers_for_tenant(tenant_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn record_oidc_login_attempt(
    state: &PlatformServiceState,
    attempt: &OidcLoginAttemptRecord,
) -> Result<(), ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            state.oidc_logins.record_attempt(attempt.clone());
            Ok(())
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .record_oidc_login_attempt(attempt)
            .await
            .map_err(auth_repository_error),
    }
}

async fn role_bindings_for_tenant(
    state: &PlatformServiceState,
    tenant_id: &str,
) -> Result<Vec<PlatformRoleBindingRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            Ok(state.role_bindings.role_bindings_for_tenant(tenant_id))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .role_bindings_for_tenant(tenant_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn active_role_bindings_for_principal(
    state: &PlatformServiceState,
    tenant_id: &str,
    principal_id: &str,
) -> Result<Vec<PlatformRoleBindingRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .role_bindings
            .active_role_bindings_for_principal(tenant_id, principal_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .active_role_bindings_for_principal(tenant_id, principal_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn role_binding_by_id(
    state: &PlatformServiceState,
    role_binding_id: &str,
) -> Result<PlatformRoleBindingRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .role_bindings
            .role_binding(role_binding_id)
            .filter(|binding| binding.status != PlatformRoleBindingStatus::Deleted)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .role_binding(role_binding_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn equivalent_role_binding(
    state: &PlatformServiceState,
    candidate: &PlatformRoleBindingRecord,
) -> Result<Option<PlatformRoleBindingRecord>, ServiceError> {
    let bindings = role_bindings_for_tenant(state, &candidate.tenant_id).await?;
    Ok(bindings.into_iter().find(|binding| {
        binding.organization_id == candidate.organization_id
            && binding.project_id == candidate.project_id
            && binding.principal_id == candidate.principal_id
            && binding.role_id == candidate.role_id
    }))
}

async fn upsert_role_binding(
    state: &PlatformServiceState,
    record: &PlatformRoleBindingRecord,
    actor: &AuthenticatedActor,
) -> Result<PlatformRoleBindingRecord, ServiceError> {
    let request = PlatformRoleBindingUpsert {
        role_binding_id: &record.role_binding_id,
        tenant_id: &record.tenant_id,
        organization_id: record.organization_id.as_deref(),
        project_id: record.project_id.as_deref(),
        principal_id: &record.principal_id,
        role_id: &record.role_id,
    };
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .role_bindings
            .upsert_role_binding(request)
            .map_err(role_binding_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .upsert_role_binding(request, &actor.principal_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn set_role_binding_status(
    state: &PlatformServiceState,
    role_binding_id: &str,
    expected_resource_version: i64,
    status: PlatformRoleBindingStatus,
) -> Result<PlatformRoleBindingRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .role_bindings
            .update_role_binding_status(role_binding_id, expected_resource_version, status)
            .map_err(role_binding_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .update_role_binding_status(role_binding_id, expected_resource_version, status)
            .await
            .map_err(data_repository_error),
    }
}

async fn organization_members_for_organization(
    state: &PlatformServiceState,
    organization_id: &str,
) -> Result<Vec<PlatformOrganizationMembershipRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .memberships
            .organization_members_for_organization(organization_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .organization_members_for_organization(organization_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn organization_member_by_id(
    state: &PlatformServiceState,
    organization_member_id: &str,
) -> Result<PlatformOrganizationMembershipRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .memberships
            .organization_member(organization_member_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .organization_member(organization_member_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn upsert_organization_member(
    state: &PlatformServiceState,
    organization_member_id: &str,
    organization_id: &str,
    principal_id: &str,
    membership_kind: &str,
    actor: &AuthenticatedActor,
) -> Result<PlatformOrganizationMembershipRecord, ServiceError> {
    let request = PlatformOrganizationMembershipUpsert {
        organization_member_id,
        tenant_id: &actor.tenant_id,
        organization_id,
        principal_id,
        membership_kind,
        created_by: &actor.principal_id,
    };
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .memberships
            .upsert_organization_member(request)
            .map_err(membership_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .upsert_organization_member(request)
            .await
            .map_err(data_repository_error),
    }
}

async fn set_organization_member_status(
    state: &PlatformServiceState,
    organization_member_id: &str,
    expected_resource_version: i64,
    status: PlatformMembershipStatus,
) -> Result<PlatformOrganizationMembershipRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .memberships
            .update_organization_member_status(
                organization_member_id,
                expected_resource_version,
                status,
            )
            .map_err(membership_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .update_organization_member_status(
                organization_member_id,
                expected_resource_version,
                status,
            )
            .await
            .map_err(data_repository_error),
    }
}

async fn cascade_project_memberships_for_organization_member(
    state: &PlatformServiceState,
    organization_member: &PlatformOrganizationMembershipRecord,
    status: PlatformMembershipStatus,
) -> Result<usize, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .memberships
            .cascade_project_memberships_for_organization_member(organization_member, status)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .cascade_project_memberships_for_organization_member(organization_member, status)
            .await
            .map_err(data_repository_error),
    }
}

async fn delete_role_bindings_for_organization_principal(
    state: &PlatformServiceState,
    organization_member: &PlatformOrganizationMembershipRecord,
) -> Result<usize, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .role_bindings
            .delete_role_bindings_for_organization_principal(
                &organization_member.tenant_id,
                &organization_member.organization_id,
                &organization_member.principal_id,
            )),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .delete_role_bindings_for_organization_principal(
                &organization_member.tenant_id,
                &organization_member.organization_id,
                &organization_member.principal_id,
            )
            .await
            .map_err(data_repository_error),
    }
}

async fn project_members_for_project(
    state: &PlatformServiceState,
    project_id: &str,
) -> Result<Vec<PlatformProjectMembershipRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            Ok(state.memberships.project_members_for_project(project_id))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .project_members_for_project(project_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn delete_role_bindings_for_project_principal(
    state: &PlatformServiceState,
    project_member: &PlatformProjectMembershipRecord,
) -> Result<usize, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .role_bindings
            .delete_role_bindings_for_project_principal(
                &project_member.tenant_id,
                &project_member.project_id,
                &project_member.principal_id,
            )),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .delete_role_bindings_for_project_principal(
                &project_member.tenant_id,
                &project_member.project_id,
                &project_member.principal_id,
            )
            .await
            .map_err(data_repository_error),
    }
}

async fn project_member_by_id(
    state: &PlatformServiceState,
    project_member_id: &str,
) -> Result<PlatformProjectMembershipRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .memberships
            .project_member(project_member_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .project_member(project_member_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn set_project_member_status(
    state: &PlatformServiceState,
    project_member_id: &str,
    expected_resource_version: i64,
    status: PlatformMembershipStatus,
) -> Result<PlatformProjectMembershipRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .memberships
            .update_project_member_status(project_member_id, expected_resource_version, status)
            .map_err(membership_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .update_project_member_status(project_member_id, expected_resource_version, status)
            .await
            .map_err(data_repository_error),
    }
}

async fn active_organization_member_by_id_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    organization_member_id: &str,
) -> Result<PlatformOrganizationMembershipRecord, ServiceError> {
    if !organization_member_id.starts_with("om_") {
        return Err(ServiceError::BadRequest("membership_id_invalid"));
    }
    let member = organization_member_by_id(state, organization_member_id).await?;
    if member.tenant_id != actor.tenant_id {
        return Err(ServiceError::Forbidden("tenant_mismatch"));
    }
    if member.status.accepts_access() {
        Ok(member)
    } else {
        Err(ServiceError::Forbidden("organization_membership_required"))
    }
}

fn ensure_project_member_create_matches_project_organization(
    existing_members: &[PlatformProjectMembershipRecord],
    organization_member: &PlatformOrganizationMembershipRecord,
) -> Result<(), ServiceError> {
    let Some(existing_member) = existing_members.first() else {
        return Ok(());
    };
    if existing_member.tenant_id != organization_member.tenant_id {
        return Err(ServiceError::Forbidden("tenant_mismatch"));
    }
    if existing_member.organization_id == organization_member.organization_id {
        Ok(())
    } else {
        Err(ServiceError::Forbidden("project_organization_mismatch"))
    }
}

async fn upsert_project_member_from_organization_member(
    state: &PlatformServiceState,
    project_member_id: &str,
    project_id: &str,
    organization_member: &PlatformOrganizationMembershipRecord,
    actor: &AuthenticatedActor,
) -> Result<PlatformProjectMembershipRecord, ServiceError> {
    let request = PlatformProjectMembershipUpsert {
        project_member_id,
        tenant_id: &organization_member.tenant_id,
        organization_id: &organization_member.organization_id,
        project_id,
        principal_id: &organization_member.principal_id,
        organization_member_id: &organization_member.organization_member_id,
        membership_kind: &organization_member.membership_kind,
        created_by: &actor.principal_id,
    };
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .memberships
            .upsert_project_member(request)
            .map_err(membership_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .upsert_project_member(request)
            .await
            .map_err(data_repository_error),
    }
}

async fn insert_organization_invitation(
    state: &PlatformServiceState,
    invitation: &PlatformOrganizationInvitationRecord,
) -> Result<PlatformOrganizationInvitationRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .invitations
            .create_organization_invitation(invitation.clone())
            .map_err(invitation_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .create_organization_invitation(invitation)
            .await
            .map_err(data_repository_error),
    }
}

async fn organization_invitations_for_organization(
    state: &PlatformServiceState,
    tenant_id: &str,
    organization_id: &str,
) -> Result<Vec<PlatformOrganizationInvitationRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .invitations
            .organization_invitations(tenant_id, organization_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .organization_invitations(tenant_id, organization_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn organization_invitation_by_id(
    state: &PlatformServiceState,
    invitation_id: &str,
) -> Result<PlatformOrganizationInvitationRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .invitations
            .organization_invitation(invitation_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .organization_invitation(invitation_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn organization_invitation_by_raw_token(
    state: &PlatformServiceState,
    raw_token: &str,
) -> Result<PlatformOrganizationInvitationRecord, ServiceError> {
    if !raw_token
        .trim()
        .starts_with(PLATFORM_INVITATION_TOKEN_PREFIX)
    {
        return Err(ServiceError::ResourceNotFound);
    }
    let token_hash = hash_platform_invitation_token(raw_token.trim());
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .invitations
            .organization_invitation_by_token_hash(&token_hash)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .organization_invitation_by_token_hash(&token_hash)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn revoke_organization_invitation_by_id(
    state: &PlatformServiceState,
    invitation_id: &str,
    expected_resource_version: i64,
    now_unix: i64,
) -> Result<PlatformOrganizationInvitationRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .invitations
            .revoke_organization_invitation(invitation_id, expected_resource_version, now_unix)
            .map_err(invitation_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .revoke_organization_invitation(invitation_id, expected_resource_version, now_unix)
            .await
            .map_err(data_repository_error),
    }
}

async fn accept_organization_invitation_for_actor(
    state: &PlatformServiceState,
    invitation: &PlatformOrganizationInvitationRecord,
    actor: &AuthenticatedActor,
    now_unix: i64,
) -> Result<
    (
        PlatformOrganizationInvitationRecord,
        PlatformOrganizationMembershipRecord,
        Option<PlatformProjectMembershipRecord>,
    ),
    ServiceError,
> {
    let request = AcceptPlatformOrganizationInvitationRequest {
        invitation_id: invitation.invitation_id.clone(),
        principal_id: actor.principal_id.clone(),
        organization_member_id: new_prefixed_id("om"),
        project_member_id: invitation
            .project_id
            .as_ref()
            .map(|_| new_prefixed_id("pm")),
        accepted_at_unix: now_unix,
    };
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            let accepted = state
                .invitations
                .accept_organization_invitation(&request)
                .map_err(invitation_error_to_service)?;
            let organization_member = state
                .memberships
                .upsert_invited_organization_member(
                    &request.organization_member_id,
                    &accepted.tenant_id,
                    &accepted.organization_id,
                    &request.principal_id,
                    "user",
                )
                .map_err(membership_error_to_service)?;
            let project_member = if let Some(project_id) = accepted.project_id.as_deref() {
                Some(
                    state
                        .memberships
                        .upsert_invited_project_member(PlatformInvitedProjectMembershipUpsert {
                            project_member_id: request
                                .project_member_id
                                .as_deref()
                                .ok_or(ServiceError::Internal("project_member_id_missing"))?,
                            tenant_id: &accepted.tenant_id,
                            organization_id: &accepted.organization_id,
                            project_id,
                            principal_id: &request.principal_id,
                            organization_member_id: &organization_member.organization_member_id,
                            membership_kind: "user",
                        })
                        .map_err(membership_error_to_service)?,
                )
            } else {
                None
            };
            Ok((accepted, organization_member, project_member))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .accept_organization_invitation(&request)
            .await
            .map_err(data_repository_error),
    }
}

async fn upsert_secret_ref(
    state: &PlatformServiceState,
    secret_ref: &PlatformSecretRefRecord,
    actor: &AuthenticatedActor,
) -> Result<(), ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .owners
            .record_resource_owner(ResourceOwnerRecord::tenant(
                "SecretRef",
                &secret_ref.secret_ref_id,
                &secret_ref.tenant_id,
            ))
            .map_err(|error| ServiceError::Internal(error.as_str())),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .upsert_secret_ref(secret_ref, &actor.principal_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn secret_ref_by_id(
    state: &PlatformServiceState,
    secret_ref_id: &str,
) -> Result<PlatformSecretRefRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .secrets
            .secret_ref(secret_ref_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .secret_ref(secret_ref_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn secret_refs_for_tenant(
    state: &PlatformServiceState,
    tenant_id: &str,
) -> Result<Vec<PlatformSecretRefRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            Ok(state.secrets.secret_refs_for_tenant(tenant_id))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .secret_refs_for_tenant(tenant_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn external_identities_for_principal(
    state: &PlatformServiceState,
    tenant_id: &str,
    principal_id: &str,
) -> Result<Vec<PlatformExternalIdentityRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .external_identities
            .external_identities_for_principal(tenant_id, principal_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .external_identities_for_principal(tenant_id, principal_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn external_identity_by_id(
    state: &PlatformServiceState,
    external_identity_id: &str,
) -> Result<PlatformExternalIdentityRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .external_identities
            .external_identity(external_identity_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .external_identity(external_identity_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn unlink_external_identity(
    state: &PlatformServiceState,
    external_identity_id: &str,
) -> Result<PlatformExternalIdentityRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .external_identities
            .unlink_external_identity(external_identity_id)
            .map_err(external_identity_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .unlink_external_identity(external_identity_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn resolve_platform_secret(
    state: &PlatformServiceState,
    secret_ref_id: &str,
) -> Result<PlatformSecretValue, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .secrets
            .resolve_secret(secret_ref_id)
            .map_err(secret_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .resolve_secret(secret_ref_id)
            .await
            .map_err(auth_repository_error),
    }
}

fn validate_tenant_id(tenant_id: &str) -> Result<(), ServiceError> {
    if tenant_id.starts_with("ten_") {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("tenant_id_invalid"))
    }
}

fn validate_organization_id(organization_id: &str) -> Result<(), ServiceError> {
    if organization_id.starts_with("org_") {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("organization_id_invalid"))
    }
}

fn validate_user_id(user_id: &str) -> Result<(), ServiceError> {
    if user_id.starts_with("usr_") {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("user_id_invalid"))
    }
}

fn validate_principal_id(principal_id: &str) -> Result<(), ServiceError> {
    if principal_id.starts_with("usr_")
        || principal_id.starts_with("svc_")
        || principal_id.starts_with("sys_")
    {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("principal_id_invalid"))
    }
}

fn validate_project_id(project_id: &str) -> Result<(), ServiceError> {
    if project_id.starts_with("prj_") {
        Ok(())
    } else {
        Err(ServiceError::BadRequest("project_id_invalid"))
    }
}

fn validate_optional_non_empty(
    value: Option<&str>,
    code: &'static str,
) -> Result<(), ServiceError> {
    if value.is_some_and(|value| value.trim().is_empty()) {
        Err(ServiceError::BadRequest(code))
    } else {
        Ok(())
    }
}

fn organization_scope_resource(
    actor: &AuthenticatedActor,
    organization_id: &str,
    resource_kind: &str,
) -> Result<ResourceRef, ServiceError> {
    validate_organization_id(organization_id)?;
    Ok(ResourceRef {
        kind: resource_kind.to_owned(),
        tenant_id: actor.tenant_id.clone(),
        organization_id: Some(organization_id.to_owned()),
        project_id: None,
        resource_id: organization_id.to_owned(),
    })
}

fn project_scope_resource(
    actor: &AuthenticatedActor,
    project_id: &str,
    resource_kind: &str,
) -> Result<ResourceRef, ServiceError> {
    validate_project_id(project_id)?;
    let Some(organization_id) = actor.organization_id.as_deref() else {
        return Err(ServiceError::Forbidden("organization_scope_required"));
    };
    Ok(ResourceRef::project(
        resource_kind,
        &actor.tenant_id,
        organization_id,
        project_id,
        project_id,
    ))
}

fn role_binding_record_from_create_request(
    request: CreateRoleBindingRequest,
    tenant_id: &str,
) -> Result<PlatformRoleBindingRecord, ServiceError> {
    let record = PlatformRoleBindingRecord {
        role_binding_id: normalized_optional_string(request.binding)
            .unwrap_or_else(|| new_prefixed_id("rb")),
        tenant_id: tenant_id.to_owned(),
        organization_id: normalized_optional_string(request.organization),
        project_id: normalized_optional_string(request.project),
        principal_id: request.principal.trim().to_owned(),
        role_id: request.role.trim().to_owned(),
        status: PlatformRoleBindingStatus::Active,
        resource_version: 1,
    };
    crate::role::validate_role_binding(&record).map_err(role_binding_error_to_service)?;
    Ok(record)
}

fn role_binding_status_from_request(
    value: &str,
) -> Result<PlatformRoleBindingStatus, ServiceError> {
    PlatformRoleBindingStatus::from_id(value.trim())
        .ok_or(ServiceError::BadRequest("role_binding_status_invalid"))
}

fn role_binding_collection_resource_for_actor(actor: &AuthenticatedActor) -> ResourceRef {
    if let (Some(organization_id), Some(project_id)) = (
        actor.organization_id.as_deref(),
        actor.project_id.as_deref(),
    ) {
        return ResourceRef::project(
            "RoleBinding",
            &actor.tenant_id,
            organization_id,
            project_id,
            project_id,
        );
    }
    if let Some(organization_id) = actor.organization_id.as_deref() {
        return ResourceRef {
            kind: "RoleBinding".to_owned(),
            tenant_id: actor.tenant_id.clone(),
            organization_id: Some(organization_id.to_owned()),
            project_id: None,
            resource_id: organization_id.to_owned(),
        };
    }
    ResourceRef::tenant("RoleBinding", &actor.tenant_id, &actor.tenant_id)
}

fn role_binding_visible_in_collection(
    binding: &PlatformRoleBindingRecord,
    collection: &ResourceRef,
) -> bool {
    if binding.tenant_id != collection.tenant_id {
        return false;
    }
    if let Some(project_id) = collection.project_id.as_deref() {
        return binding.project_id.as_deref() == Some(project_id);
    }
    if let Some(organization_id) = collection.organization_id.as_deref() {
        return binding.organization_id.as_deref() == Some(organization_id);
    }
    true
}

async fn organization_member_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    organization_id: &str,
    organization_member_id: &str,
) -> Result<PlatformOrganizationMembershipRecord, ServiceError> {
    let member = organization_member_by_id(state, organization_member_id).await?;
    if member.tenant_id == actor.tenant_id && member.organization_id == organization_id {
        Ok(member)
    } else {
        Err(ServiceError::ResourceNotFound)
    }
}

async fn project_member_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    project_id: &str,
    project_member_id: &str,
) -> Result<PlatformProjectMembershipRecord, ServiceError> {
    let member = project_member_by_id(state, project_member_id).await?;
    if member.tenant_id == actor.tenant_id && member.project_id == project_id {
        Ok(member)
    } else {
        Err(ServiceError::ResourceNotFound)
    }
}

async fn external_identity_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    user_id: &str,
    external_identity_id: &str,
) -> Result<PlatformExternalIdentityRecord, ServiceError> {
    let identity = external_identity_by_id(state, external_identity_id).await?;
    if identity.tenant_id == actor.tenant_id && identity.principal_id == user_id {
        Ok(identity)
    } else {
        Err(ServiceError::ResourceNotFound)
    }
}

async fn organization_invitation_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    organization_id: &str,
    invitation_id: &str,
) -> Result<PlatformOrganizationInvitationRecord, ServiceError> {
    let invitation = organization_invitation_by_id(state, invitation_id).await?;
    if invitation.tenant_id == actor.tenant_id && invitation.organization_id == organization_id {
        Ok(invitation)
    } else {
        Err(ServiceError::ResourceNotFound)
    }
}

fn organization_member_resource(member: &PlatformOrganizationMembershipRecord) -> ResourceRef {
    ResourceRef {
        kind: "OrganizationMember".to_owned(),
        tenant_id: member.tenant_id.clone(),
        organization_id: Some(member.organization_id.clone()),
        project_id: None,
        resource_id: member.organization_member_id.clone(),
    }
}

fn project_member_resource(member: &PlatformProjectMembershipRecord) -> ResourceRef {
    ResourceRef::project(
        "ProjectMember",
        &member.tenant_id,
        &member.organization_id,
        &member.project_id,
        &member.project_member_id,
    )
}

fn role_binding_resource(binding: &PlatformRoleBindingRecord) -> ResourceRef {
    if let Some(project_id) = binding.project_id.as_deref() {
        return ResourceRef::project(
            "RoleBinding",
            &binding.tenant_id,
            binding
                .organization_id
                .as_deref()
                .unwrap_or(binding.tenant_id.as_str()),
            project_id,
            &binding.role_binding_id,
        );
    }
    if let Some(organization_id) = binding.organization_id.as_deref() {
        return ResourceRef {
            kind: "RoleBinding".to_owned(),
            tenant_id: binding.tenant_id.clone(),
            organization_id: Some(organization_id.to_owned()),
            project_id: None,
            resource_id: binding.role_binding_id.clone(),
        };
    }
    ResourceRef::tenant("RoleBinding", &binding.tenant_id, &binding.role_binding_id)
}

fn external_identity_resource(identity: &PlatformExternalIdentityRecord) -> ResourceRef {
    ResourceRef::tenant(
        "ExternalIdentity",
        &identity.tenant_id,
        &identity.external_identity_id,
    )
}

fn organization_invitation_resource(
    invitation: &PlatformOrganizationInvitationRecord,
) -> ResourceRef {
    ResourceRef {
        kind: "OrganizationInvitation".to_owned(),
        tenant_id: invitation.tenant_id.clone(),
        organization_id: Some(invitation.organization_id.clone()),
        project_id: invitation.project_id.clone(),
        resource_id: invitation.invitation_id.clone(),
    }
}

fn organization_invitation_record_from_create_request(
    request: CreateOrganizationInvitationRequest,
    actor: &AuthenticatedActor,
    organization_id: &str,
    now_unix: i64,
) -> Result<(PlatformOrganizationInvitationRecord, String), ServiceError> {
    if !organization_id.starts_with("org_") {
        return Err(ServiceError::BadRequest("organization_id_invalid"));
    }
    let invited_email = request
        .invited_email
        .and_then(|value| normalized_email(&value));
    let invited_principal_id = normalized_optional_string(request.invited_principal_id);
    match (invited_email.as_ref(), invited_principal_id.as_ref()) {
        (Some(_), None) | (None, Some(_)) => {}
        (Some(_), Some(_)) | (None, None) => {
            return Err(ServiceError::BadRequest("invitation_target_invalid"));
        }
    }
    if let Some(principal_id) = invited_principal_id.as_deref() {
        if !principal_id.starts_with("usr_") {
            return Err(ServiceError::BadRequest("principal_id_invalid"));
        }
    }
    let project_id = normalized_optional_string(request.project_id);
    if let Some(project_id) = project_id.as_deref() {
        if !project_id.starts_with("prj_") {
            return Err(ServiceError::BadRequest("project_id_invalid"));
        }
    }
    let expires_at_unix = request
        .expires_at_unix
        .unwrap_or(now_unix + ORGANIZATION_INVITATION_TTL_SECONDS);
    if expires_at_unix <= now_unix {
        return Err(ServiceError::BadRequest("invitation_expiry_invalid"));
    }
    let role_id = request
        .role_id
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "organization_member".to_owned());
    let raw_token = generate_invitation_token();
    let invitation = PlatformOrganizationInvitationRecord {
        invitation_id: request
            .invitation_id
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| new_prefixed_id("inv")),
        tenant_id: actor.tenant_id.clone(),
        organization_id: organization_id.to_owned(),
        project_id,
        invited_email,
        invited_principal_id,
        invitation_token_hash: hash_platform_invitation_token(&raw_token),
        role_id,
        status: PlatformInvitationStatus::Pending,
        expires_at_unix,
        accepted_at_unix: None,
        created_by: actor.principal_id.clone(),
        resource_version: 1,
        created_at_unix: now_unix,
        updated_at_unix: now_unix,
    };
    crate::invitation::validate_organization_invitation(&invitation)
        .map_err(invitation_error_to_service)?;
    Ok((invitation, raw_token))
}

fn ensure_actor_matches_invitation(
    actor: &AuthenticatedActor,
    invitation: &PlatformOrganizationInvitationRecord,
) -> Result<(), ServiceError> {
    if actor.tenant_id != invitation.tenant_id {
        return Err(ServiceError::Forbidden("tenant_mismatch"));
    }
    if invitation.invited_principal_id.as_deref() == Some(actor.principal_id.as_str()) {
        Ok(())
    } else {
        Err(ServiceError::Forbidden("invitation_principal_mismatch"))
    }
}

fn single_user_provider_public_json() -> Value {
    json!({
        "identity_provider_id": SINGLE_USER_IDENTITY_PROVIDER_ID,
        "tenant_id": SINGLE_USER_TENANT_ID,
        "provider_kind": "single_user_password",
        "display_name": "Single-user password",
        "login_path": "/auth/v1/single-user/login",
        "status": "active",
        "provider_secret_material_included": false,
    })
}

fn oidc_provider_public_json(provider: &OidcLoginProviderRecord) -> Value {
    json!({
        "identity_provider_id": provider.identity_provider_id,
        "tenant_id": provider.tenant_id,
        "provider_kind": "oidc",
        "display_name": provider.display_name,
        "issuer_url": provider.issuer_url,
        "login_path": format!(
            "/auth/v1/providers/{}/login",
            provider.identity_provider_id
        ),
        "start_path": format!(
            "/auth/v1/providers/{}/start",
            provider.identity_provider_id
        ),
        "requested_scopes": provider.requested_scopes,
        "status": provider.status.as_str(),
        "confidential_client": provider.client_secret_ref.is_some(),
        "provider_secret_material_included": false,
    })
}

fn oidc_authorization_url(
    metadata: &OidcResolvedProviderMetadata,
    requested_scopes: &[String],
    raw_state: &str,
    raw_nonce: &str,
    raw_pkce_verifier: &str,
) -> Result<String, ServiceError> {
    let mut url = url::Url::parse(&metadata.authorization_endpoint)
        .map_err(|_| ServiceError::AuthenticationFailed("oidc_authorization_endpoint_invalid"))?;
    let scope = requested_scopes.join(" ");
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &metadata.client_id)
        .append_pair("redirect_uri", &metadata.redirect_uri)
        .append_pair("scope", &scope)
        .append_pair("state", raw_state)
        .append_pair("nonce", raw_nonce)
        .append_pair("code_challenge", &pkce_s256_challenge(raw_pkce_verifier))
        .append_pair("code_challenge_method", "S256");
    Ok(url.to_string())
}

fn pkce_s256_challenge(raw_pkce_verifier: &str) -> String {
    let digest = Sha256::digest(raw_pkce_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

fn generate_base64url_secret(byte_len: usize) -> String {
    let mut bytes = vec![0_u8; byte_len];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn organization_member_safe_json(member: &PlatformOrganizationMembershipRecord) -> Value {
    json!({
        "kind": "organization_member",
        "id": member.organization_member_id,
        "organization_member_id": member.organization_member_id,
        "tenant_id": member.tenant_id,
        "organization_id": member.organization_id,
        "principal_id": member.principal_id,
        "membership_kind": member.membership_kind,
        "status": member.status.as_str(),
        "resource_version": member.resource_version,
    })
}

fn project_member_safe_json(member: &PlatformProjectMembershipRecord) -> Value {
    json!({
        "kind": "project_member",
        "id": member.project_member_id,
        "project_member_id": member.project_member_id,
        "tenant_id": member.tenant_id,
        "organization_id": member.organization_id,
        "project_id": member.project_id,
        "principal_id": member.principal_id,
        "organization_member_id": member.organization_member_id,
        "membership_kind": member.membership_kind,
        "status": member.status.as_str(),
        "resource_version": member.resource_version,
    })
}

fn role_binding_safe_json(binding: &PlatformRoleBindingRecord) -> Value {
    let scope_kind = if binding.project_id.is_some() {
        "project"
    } else if binding.organization_id.is_some() {
        "organization"
    } else {
        "tenant"
    };
    json!({
        "kind": "role_binding",
        "id": binding.role_binding_id,
        "role_binding_id": binding.role_binding_id,
        "tenant_id": binding.tenant_id,
        "organization_id": binding.organization_id,
        "project_id": binding.project_id,
        "principal_id": binding.principal_id,
        "role_id": binding.role_id,
        "scope_kind": scope_kind,
        "scope_id": role_binding_scope_id(binding),
        "status": binding.status.as_str(),
        "resource_version": binding.resource_version,
    })
}

fn platform_user_safe_json(user: &PlatformUserRecord) -> Value {
    json!({
        "kind": "user",
        "id": user.user_id,
        "user_id": user.user_id,
        "tenant_id": user.tenant_id,
        "default_organization_id": user.default_organization_id,
        "default_project_id": user.default_project_id,
        "primary_email": user.primary_email,
        "display_name": user.display_name,
        "status": user.status.as_str(),
        "resource_version": user.resource_version,
    })
}

fn platform_user_resource(user: &PlatformUserRecord) -> ResourceRef {
    ResourceRef::tenant("User", &user.tenant_id, &user.user_id)
}

fn organization_invitation_safe_json(invitation: &PlatformOrganizationInvitationRecord) -> Value {
    json!({
        "kind": "organization_invitation",
        "id": invitation.invitation_id,
        "invitation_id": invitation.invitation_id,
        "tenant_id": invitation.tenant_id,
        "organization_id": invitation.organization_id,
        "project_id": invitation.project_id,
        "invited_email": invitation.invited_email,
        "invited_principal_id": invitation.invited_principal_id,
        "role_id": invitation.role_id,
        "status": invitation.status.as_str(),
        "effective_status": organization_invitation_effective_status(
            invitation,
            current_unix_timestamp(),
        ),
        "expires_at_unix": invitation.expires_at_unix,
        "accepted_at_unix": invitation.accepted_at_unix,
        "created_by": invitation.created_by,
        "resource_version": invitation.resource_version,
        "created_at_unix": invitation.created_at_unix,
        "updated_at_unix": invitation.updated_at_unix,
        "invitation_token_hash_included": false,
        "raw_invitation_token_included": false,
    })
}

fn organization_invitation_preview_json(
    invitation: &PlatformOrganizationInvitationRecord,
    now_unix: i64,
) -> Value {
    json!({
        "kind": "organization_invitation_preview",
        "id": invitation.invitation_id,
        "invitation_id": invitation.invitation_id,
        "tenant_id": invitation.tenant_id,
        "organization_id": invitation.organization_id,
        "project_id": invitation.project_id,
        "invited_email": invitation.invited_email,
        "role_id": invitation.role_id,
        "status": organization_invitation_effective_status(invitation, now_unix),
        "expires_at_unix": invitation.expires_at_unix,
        "invitation_token_hash_included": false,
        "raw_invitation_token_included": false,
    })
}

fn organization_invitation_effective_status(
    invitation: &PlatformOrganizationInvitationRecord,
    now_unix: i64,
) -> &'static str {
    if invitation
        .status
        .accepts_at(invitation.expires_at_unix, now_unix)
    {
        "pending"
    } else if invitation.status == PlatformInvitationStatus::Pending {
        "expired"
    } else {
        invitation.status.as_str()
    }
}

fn oidc_provider_safe_json(provider: &OidcLoginProviderRecord) -> Value {
    json!({
        "identity_provider_id": provider.identity_provider_id,
        "tenant_id": provider.tenant_id,
        "provider_kind": "oidc",
        "display_name": provider.display_name,
        "issuer_url": provider.issuer_url,
        "authorization_endpoint": provider.authorization_endpoint,
        "token_endpoint": provider.token_endpoint,
        "jwks_uri": provider.jwks_uri,
        "client_id": provider.client_id,
        "client_secret_ref": provider.client_secret_ref.as_deref().map(mask_secret_ref_id),
        "client_secret_ref_configured": provider.client_secret_ref.is_some(),
        "token_endpoint_auth_method": provider.token_endpoint_auth_method.as_str(),
        "redirect_uri": provider.redirect_uri,
        "requested_scopes": provider.requested_scopes,
        "accepted_audiences": provider.accepted_audiences,
        "status": provider.status.as_str(),
        "raw_secret_included": false,
    })
}

fn secret_ref_safe_json(secret_ref: &PlatformSecretRefRecord) -> Value {
    json!({
        "secret_ref_id": secret_ref.secret_ref_id,
        "tenant_id": secret_ref.tenant_id,
        "organization_id": secret_ref.organization_id,
        "project_id": secret_ref.project_id,
        "purpose": secret_ref.purpose,
        "backend_kind": secret_ref.backend_kind,
        "backend_locator": secret_ref.backend_locator,
        "display_mask": secret_ref.display_mask,
        "fingerprint": secret_ref.fingerprint,
        "status": secret_ref.status.as_str(),
        "raw_secret_included": false,
    })
}

fn external_identity_safe_json(identity: &PlatformExternalIdentityRecord) -> Value {
    json!({
        "kind": "external_identity",
        "id": identity.external_identity_id,
        "external_identity_id": identity.external_identity_id,
        "tenant_id": identity.tenant_id,
        "principal_id": identity.principal_id,
        "identity_provider_id": identity.identity_provider_id,
        "provider_kind": identity.provider_kind,
        "provider_subject": identity.provider_subject,
        "email": identity.email,
        "email_verified": identity.email_verified,
        "status": identity.status.as_str(),
        "raw_provider_token_included": false,
        "access_token_included": false,
        "refresh_token_included": false,
        "client_secret_included": false,
    })
}

fn mask_secret_ref_id(secret_ref_id: &str) -> String {
    if secret_ref_id.starts_with("sec_") {
        "sec_***".to_owned()
    } else {
        "***".to_owned()
    }
}

fn normalized_optional_string(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn normalized_email(value: &str) -> Option<String> {
    let email = value.trim().to_ascii_lowercase();
    (email.contains('@') && !email.starts_with('@') && !email.ends_with('@')).then_some(email)
}

fn normalized_string_vec(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .collect()
}

fn generate_invitation_token() -> String {
    format!(
        "{PLATFORM_INVITATION_TOKEN_PREFIX}{}",
        generate_base64url_secret(32)
    )
}

fn membership_status_from_request(value: &str) -> Result<PlatformMembershipStatus, ServiceError> {
    PlatformMembershipStatus::from_id(value.trim())
        .ok_or(ServiceError::BadRequest("membership_status_invalid"))
}

fn platform_user_status_from_request(value: &str) -> Result<PlatformUserStatus, ServiceError> {
    PlatformUserStatus::from_id(value.trim()).ok_or(ServiceError::BadRequest("user_status_invalid"))
}

fn normalized_membership_kind(value: Option<String>) -> Result<String, ServiceError> {
    let membership_kind = normalized_optional_string(value).unwrap_or_else(|| "user".to_owned());
    match membership_kind.as_str() {
        "user" | "service_account" => Ok(membership_kind),
        _ => Err(ServiceError::BadRequest("membership_kind_invalid")),
    }
}

const fn membership_error_to_service(error: PlatformMembershipError) -> ServiceError {
    match error {
        PlatformMembershipError::StaleResourceVersion => {
            ServiceError::BadRequest("stale_resource_version")
        }
        PlatformMembershipError::InvalidMembershipId => ServiceError::ResourceNotFound,
        PlatformMembershipError::InvalidTenantId
        | PlatformMembershipError::InvalidOrganizationId
        | PlatformMembershipError::InvalidProjectId
        | PlatformMembershipError::InvalidPrincipalId
        | PlatformMembershipError::InvalidMembershipKind
        | PlatformMembershipError::InvalidStatus => ServiceError::BadRequest(error.as_str()),
    }
}

const fn invitation_error_to_service(error: PlatformInvitationError) -> ServiceError {
    match error {
        PlatformInvitationError::InvalidInvitationId => ServiceError::ResourceNotFound,
        PlatformInvitationError::InvitationPrincipalMismatch => {
            ServiceError::Forbidden("invitation_principal_mismatch")
        }
        PlatformInvitationError::StaleResourceVersion
        | PlatformInvitationError::InvitationNotPending
        | PlatformInvitationError::InvitationNotAccepting
        | PlatformInvitationError::InvalidTenantId
        | PlatformInvitationError::InvalidOrganizationId
        | PlatformInvitationError::InvalidProjectId
        | PlatformInvitationError::InvalidPrincipalId
        | PlatformInvitationError::InvalidCreatedBy
        | PlatformInvitationError::InvalidTokenHash
        | PlatformInvitationError::InvalidEmail
        | PlatformInvitationError::InvalidRoleId
        | PlatformInvitationError::InvalidStatus
        | PlatformInvitationError::InvalidTimestamp
        | PlatformInvitationError::InvalidTarget => ServiceError::BadRequest(error.as_str()),
    }
}

const fn secret_error_to_service(error: PlatformSecretError) -> ServiceError {
    let code = error.as_str();
    match error {
        PlatformSecretError::UnknownSecretRef => ServiceError::ResourceNotFound,
        PlatformSecretError::SecretRefInactive
        | PlatformSecretError::EnvironmentSecretMissing
        | PlatformSecretError::SecretFingerprintMismatch => {
            ServiceError::AuthenticationFailed(code)
        }
        PlatformSecretError::UnsupportedBackendKind
        | PlatformSecretError::EmptySecretRefId
        | PlatformSecretError::InvalidSecretRefId
        | PlatformSecretError::EmptyTenantId
        | PlatformSecretError::InvalidTenantId
        | PlatformSecretError::EmptyPurpose
        | PlatformSecretError::EmptyBackendKind
        | PlatformSecretError::EmptyBackendLocator
        | PlatformSecretError::InvalidEnvironmentVariable
        | PlatformSecretError::EmptySecretValue => ServiceError::BadRequest(code),
    }
}

const fn external_identity_error_to_service(error: PlatformExternalIdentityError) -> ServiceError {
    match error {
        PlatformExternalIdentityError::InvalidExternalIdentityId => ServiceError::ResourceNotFound,
        PlatformExternalIdentityError::PrincipalMismatch => {
            ServiceError::Forbidden("external_identity_principal_mismatch")
        }
        PlatformExternalIdentityError::InvalidTenantId
        | PlatformExternalIdentityError::InvalidPrincipalId
        | PlatformExternalIdentityError::InvalidProviderId
        | PlatformExternalIdentityError::InvalidProviderKind
        | PlatformExternalIdentityError::SubjectRequired
        | PlatformExternalIdentityError::InvalidEmail
        | PlatformExternalIdentityError::InvalidStatus => ServiceError::BadRequest(error.as_str()),
    }
}

const fn role_binding_error_to_service(error: PlatformRoleBindingError) -> ServiceError {
    match error {
        PlatformRoleBindingError::StaleResourceVersion => {
            ServiceError::BadRequest("stale_resource_version")
        }
        PlatformRoleBindingError::InvalidRoleBindingId
        | PlatformRoleBindingError::InvalidTenantId
        | PlatformRoleBindingError::InvalidOrganizationId
        | PlatformRoleBindingError::InvalidProjectId
        | PlatformRoleBindingError::InvalidPrincipalId
        | PlatformRoleBindingError::InvalidRoleId
        | PlatformRoleBindingError::InvalidScope
        | PlatformRoleBindingError::InvalidStatus => ServiceError::BadRequest(error.as_str()),
    }
}

const fn user_error_to_service(error: PlatformUserError) -> ServiceError {
    match error {
        PlatformUserError::UnknownUser => ServiceError::ResourceNotFound,
        PlatformUserError::StaleResourceVersion => {
            ServiceError::BadRequest("stale_resource_version")
        }
        PlatformUserError::InvalidUserId
        | PlatformUserError::InvalidTenantId
        | PlatformUserError::InvalidOrganizationId
        | PlatformUserError::InvalidProjectId
        | PlatformUserError::InvalidEmail
        | PlatformUserError::InvalidDisplayName
        | PlatformUserError::InvalidStatus
        | PlatformUserError::InvalidResourceVersion => ServiceError::BadRequest(error.as_str()),
    }
}

async fn platform_users_for_tenant(
    state: &PlatformServiceState,
    tenant_id: &str,
) -> Result<Vec<PlatformUserRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state.users.users_for_tenant(tenant_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .users_for_tenant(tenant_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn platform_user_by_id(
    state: &PlatformServiceState,
    user_id: &str,
) -> Result<PlatformUserRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .users
            .user(user_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .user(user_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn platform_user_by_id_including_deleted(
    state: &PlatformServiceState,
    user_id: &str,
) -> Result<Option<PlatformUserRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state.users.user_including_deleted(user_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .user_including_deleted(user_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn ensure_user_can_login(
    state: &PlatformServiceState,
    user_id: &str,
) -> Result<(), ServiceError> {
    let Some(user) = platform_user_by_id_including_deleted(state, user_id).await? else {
        return Ok(());
    };
    if user.status.accepts_access() {
        Ok(())
    } else {
        Err(ServiceError::AuthenticationFailed("principal_disabled"))
    }
}

async fn set_platform_user_status(
    state: &PlatformServiceState,
    user_id: &str,
    expected_version: i64,
    status: PlatformUserStatus,
) -> Result<PlatformUserRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .users
            .update_user_status(user_id, expected_version, status)
            .map_err(user_error_to_service),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .update_user_status(user_id, expected_version, status)
            .await
            .map_err(data_repository_error),
    }
}

async fn auth_sessions_for_principal(
    state: &PlatformServiceState,
    tenant_id: &str,
    principal_id: &str,
) -> Result<Vec<PlatformAuthSessionRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .auth_sessions
            .auth_sessions_for_principal(tenant_id, principal_id)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .auth_sessions_for_principal(tenant_id, principal_id)
            .await
            .map_err(data_repository_error),
    }
}

async fn auth_session_by_id(
    state: &PlatformServiceState,
    auth_session_id: &str,
) -> Result<PlatformAuthSessionRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .auth_sessions
            .auth_session(auth_session_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .auth_session(auth_session_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn revoke_auth_session_by_id(
    state: &PlatformServiceState,
    auth_session_id: &str,
    user: &PlatformUserRecord,
) -> Result<PlatformAuthSessionRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .auth_sessions
            .revoke_auth_session_by_id(auth_session_id)
            .map_err(|error| admin_auth_session_error(&error)),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .revoke_auth_session_by_id(auth_session_id, &user.tenant_id, &user.user_id)
            .await
            .map_err(admin_auth_repository_error),
    }
}

async fn disable_auth_sessions_for_principal(
    state: &PlatformServiceState,
    tenant_id: &str,
    principal_id: &str,
) -> Result<usize, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(state
            .auth_sessions
            .disable_auth_sessions_for_principal(tenant_id, principal_id)),
        PlatformRepositoryBackendKind::Postgres => {
            let count = state
                .postgres_repository()
                .ok_or(ServiceError::Internal("postgres_repository_missing"))?
                .disable_auth_sessions_for_principal(tenant_id, principal_id)
                .await
                .map_err(auth_repository_error)?;
            Ok(usize::try_from(count).unwrap_or(usize::MAX))
        }
    }
}

async fn platform_audit_events_for_tenant(
    state: &PlatformServiceState,
    tenant_id: &str,
) -> Result<Vec<PlatformAuditEventRecord>, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            Ok(state.audits.audit_events_for_tenant(tenant_id))
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .audit_events_for_tenant(tenant_id)
            .await
            .map_err(data_repository_error),
    }
}

fn require_strong_auth_confirmation(value: Option<&str>) -> Result<(), ServiceError> {
    if value.is_some_and(|value| value.trim() == "confirm") {
        Ok(())
    } else {
        Err(ServiceError::Forbidden("strong_auth_confirmation_required"))
    }
}

async fn record_platform_audit_event(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    action: PlatformAction,
    resource: &ResourceRef,
    event_type: &str,
    reason: Option<&str>,
) -> Result<PlatformAuditEventRecord, ServiceError> {
    let record = PlatformAuditEventRecord {
        audit_event_id: new_prefixed_id("audit"),
        tenant_id: resource.tenant_id.clone(),
        organization_id: resource.organization_id.clone(),
        project_id: resource.project_id.clone(),
        actor_principal_id: actor.principal_id.clone(),
        actor_kind: actor.actor_kind,
        action_id: action.as_str().to_owned(),
        resource_kind: resource.kind.clone(),
        resource_id: resource.resource_id.clone(),
        event_type: event_type.to_owned(),
        reason: trimmed_optional(reason),
        redaction: PLATFORM_AUDIT_REDACTION_PROFILE.to_owned(),
        created_at_unix: current_unix_timestamp(),
    };
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .audits
            .record_audit_event(record.clone())
            .map_err(audit_error_to_service)?,
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .record_audit_event(&record)
            .await
            .map_err(data_repository_error)?,
    }
    Ok(record)
}

fn validate_audit_event_list_query(
    query: &ListPlatformAuditEventsQuery,
) -> Result<(), ServiceError> {
    if let Some(organization_id) = query.organization_id.as_deref() {
        validate_organization_id(organization_id)?;
    }
    if let Some(project_id) = query.project_id.as_deref() {
        validate_project_id(project_id)?;
        if query.organization_id.is_none() {
            return Err(ServiceError::BadRequest("organization_id_required"));
        }
    }
    if let Some(principal_id) = query.actor_principal_id.as_deref() {
        validate_principal_id(principal_id)?;
    }
    if let Some(action_id) = query.action_id.as_deref() {
        let action_id = action_id.trim();
        if action_id.is_empty() || PlatformAction::from_action_id(action_id).is_none() {
            return Err(ServiceError::BadRequest("audit_action_id_invalid"));
        }
    }
    validate_optional_non_empty(query.event_type.as_deref(), "audit_event_type_invalid")?;
    validate_optional_non_empty(
        query.resource_kind.as_deref(),
        "audit_resource_kind_invalid",
    )?;
    validate_optional_non_empty(query.resource_id.as_deref(), "audit_resource_id_invalid")?;
    Ok(())
}

fn audit_event_list_resource(
    actor: &AuthenticatedActor,
    query: &ListPlatformAuditEventsQuery,
) -> Result<ResourceRef, ServiceError> {
    if let Some(project_id) = query.project_id.as_deref() {
        let organization_id = query
            .organization_id
            .as_deref()
            .ok_or(ServiceError::BadRequest("organization_id_required"))?;
        validate_project_id(project_id)?;
        return Ok(ResourceRef::project(
            "AuditEvent",
            &actor.tenant_id,
            organization_id,
            project_id,
            project_id,
        ));
    }
    if let Some(organization_id) = query.organization_id.as_deref() {
        return organization_scope_resource(actor, organization_id, "AuditEvent");
    }
    Ok(ResourceRef::tenant(
        "AuditEvent",
        &actor.tenant_id,
        &actor.tenant_id,
    ))
}

fn audit_event_safe_json(record: &PlatformAuditEventRecord) -> Value {
    json!({
        "kind": "audit_event",
        "id": &record.audit_event_id,
        "audit_event_id": &record.audit_event_id,
        "tenant_id": &record.tenant_id,
        "organization_id": &record.organization_id,
        "project_id": &record.project_id,
        "actor_principal_id": &record.actor_principal_id,
        "actor_kind": actor_kind_name(record.actor_kind),
        "action_id": &record.action_id,
        "resource_kind": &record.resource_kind,
        "resource_id": &record.resource_id,
        "event_type": &record.event_type,
        "reason": &record.reason,
        "redaction": &record.redaction,
        "created_at_unix": record.created_at_unix,
    })
}

fn audit_event_matches_query(
    record: &PlatformAuditEventRecord,
    query: &ListPlatformAuditEventsQuery,
) -> bool {
    matches_optional_filter(
        query.organization_id.as_ref(),
        record.organization_id.as_deref(),
    ) && matches_optional_filter(query.project_id.as_ref(), record.project_id.as_deref())
        && matches_optional_filter(query.event_type.as_ref(), Some(record.event_type.as_str()))
        && matches_optional_filter(query.action_id.as_ref(), Some(record.action_id.as_str()))
        && matches_optional_filter(
            query.resource_kind.as_ref(),
            Some(record.resource_kind.as_str()),
        )
        && matches_optional_filter(
            query.resource_id.as_ref(),
            Some(record.resource_id.as_str()),
        )
        && matches_optional_filter(
            query.actor_principal_id.as_ref(),
            Some(record.actor_principal_id.as_str()),
        )
}

fn matches_optional_filter(filter: Option<&String>, value: Option<&str>) -> bool {
    filter.is_none_or(|filter| value == Some(filter.as_str()))
}

fn audit_event_list_limit(limit: Option<usize>) -> Result<usize, ServiceError> {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 200;
    match limit.unwrap_or(DEFAULT_LIMIT) {
        0 => Err(ServiceError::BadRequest(
            "audit_event_limit_must_be_positive",
        )),
        value if value > MAX_LIMIT => Err(ServiceError::BadRequest(
            "audit_event_limit_exceeds_maximum",
        )),
        value => Ok(value),
    }
}

fn audit_event_list_offset(cursor: Option<&str>) -> Result<usize, ServiceError> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    if cursor.trim().is_empty() {
        return Err(ServiceError::BadRequest("audit_event_cursor_invalid"));
    }
    cursor
        .parse::<usize>()
        .map_err(|_| ServiceError::BadRequest("audit_event_cursor_invalid"))
}

fn trimmed_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

const fn audit_error_to_service(error: PlatformAuditError) -> ServiceError {
    match error {
        PlatformAuditError::InvalidAuditEventId
        | PlatformAuditError::InvalidTenantId
        | PlatformAuditError::InvalidOrganizationId
        | PlatformAuditError::InvalidProjectId
        | PlatformAuditError::InvalidPrincipalId
        | PlatformAuditError::InvalidActionId
        | PlatformAuditError::InvalidResourceKind
        | PlatformAuditError::InvalidResourceId
        | PlatformAuditError::InvalidEventType
        | PlatformAuditError::InvalidReason
        | PlatformAuditError::InvalidRedaction
        | PlatformAuditError::InvalidTimestamp => ServiceError::BadRequest(error.as_str()),
    }
}

fn ensure_actor_tenant(actor: &AuthenticatedActor, tenant_id: &str) -> Result<(), ServiceError> {
    if actor.tenant_id == tenant_id {
        Ok(())
    } else {
        Err(ServiceError::Forbidden("tenant_mismatch"))
    }
}

fn ensure_auth_session_belongs_to_user(
    session: &PlatformAuthSessionRecord,
    user: &PlatformUserRecord,
) -> Result<(), ServiceError> {
    if session.actor.tenant_id == user.tenant_id && session.actor.principal_id == user.user_id {
        Ok(())
    } else {
        Err(ServiceError::ResourceNotFound)
    }
}

const fn admin_auth_session_error(error: &AuthError) -> ServiceError {
    match *error {
        AuthError::SessionNotFound | AuthError::EmptySessionId => ServiceError::ResourceNotFound,
        AuthError::SessionRevoked => ServiceError::BadRequest("auth_session_revoked"),
        AuthError::SessionExpired => ServiceError::BadRequest("auth_session_expired"),
        AuthError::PrincipalDisabled => ServiceError::BadRequest("principal_disabled"),
        AuthError::EmptyBearerToken
        | AuthError::EmptyTokenHash
        | AuthError::EmptyCredentialId
        | AuthError::EmptyCredentialTokenHash
        | AuthError::EmptyMtlsIdentityId
        | AuthError::EmptyMtlsSubject
        | AuthError::CredentialNotFound
        | AuthError::MtlsIdentityNotFound
        | AuthError::CredentialRevoked
        | AuthError::MtlsIdentityRevoked
        | AuthError::CredentialExpired
        | AuthError::MtlsIdentityExpired
        | AuthError::CredentialDisabled
        | AuthError::MtlsIdentityDisabled => ServiceError::BadRequest(error.as_str()),
    }
}

fn admin_auth_repository_error(error: PlatformRepositoryError) -> ServiceError {
    match error {
        PlatformRepositoryError::Auth(error) => admin_auth_session_error(&error),
        other => auth_repository_error(other),
    }
}

async fn record_single_user_session(
    state: &PlatformServiceState,
    record: PlatformAuthSessionRecord,
) -> Result<(), ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .auth_sessions
            .record_auth_session(record)
            .map_err(|error| ServiceError::AuthenticationFailed(error.as_str())),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .record_auth_session(&record)
            .await
            .map_err(auth_repository_error),
    }
}

fn record_single_user_memberships(state: &PlatformServiceState) -> Result<(), ServiceError> {
    if state.repository_backend == PlatformRepositoryBackendKind::Postgres {
        return Ok(());
    }
    state
        .users
        .record_user(PlatformUserRecord {
            user_id: SINGLE_USER_ID.to_owned(),
            tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
            default_organization_id: Some(SINGLE_USER_ORGANIZATION_ID.to_owned()),
            default_project_id: Some(SINGLE_USER_PROJECT_ID.to_owned()),
            primary_email: state
                .single_user_auth
                .as_ref()
                .and_then(PlatformSingleUserConfig::user_primary_email)
                .map(ToOwned::to_owned),
            display_name: state.single_user_auth.as_ref().map_or_else(
                || "single-user".to_owned(),
                |config| config.user_display_name().to_owned(),
            ),
            status: PlatformUserStatus::Active,
            resource_version: 1,
        })
        .map_err(user_error_to_service)?;
    state
        .external_identities
        .record_external_identity(PlatformExternalIdentityRecord {
            external_identity_id: SINGLE_USER_EXTERNAL_IDENTITY_ID.to_owned(),
            tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
            principal_id: SINGLE_USER_ID.to_owned(),
            identity_provider_id: SINGLE_USER_IDENTITY_PROVIDER_ID.to_owned(),
            provider_kind: "single_user".to_owned(),
            provider_subject: state.single_user_auth.as_ref().map_or_else(
                || "single_user".to_owned(),
                |config| config.username().to_owned(),
            ),
            email: state
                .single_user_auth
                .as_ref()
                .and_then(PlatformSingleUserConfig::user_primary_email)
                .map(ToOwned::to_owned),
            email_verified: false,
            status: PlatformExternalIdentityStatus::Active,
        })
        .map_err(external_identity_error_to_service)?;
    state
        .memberships
        .record_organization_member(PlatformOrganizationMembershipRecord {
            organization_member_id: SINGLE_USER_ORGANIZATION_MEMBER_ID.to_owned(),
            tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
            organization_id: SINGLE_USER_ORGANIZATION_ID.to_owned(),
            principal_id: SINGLE_USER_ID.to_owned(),
            membership_kind: "user".to_owned(),
            status: PlatformMembershipStatus::Active,
            resource_version: 1,
        })
        .map_err(membership_error_to_service)?;
    state
        .memberships
        .record_project_member(PlatformProjectMembershipRecord {
            project_member_id: SINGLE_USER_PROJECT_MEMBER_ID.to_owned(),
            tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
            organization_id: SINGLE_USER_ORGANIZATION_ID.to_owned(),
            project_id: SINGLE_USER_PROJECT_ID.to_owned(),
            principal_id: SINGLE_USER_ID.to_owned(),
            organization_member_id: Some(SINGLE_USER_ORGANIZATION_MEMBER_ID.to_owned()),
            membership_kind: "user".to_owned(),
            status: PlatformMembershipStatus::Active,
            resource_version: 1,
        })
        .map_err(membership_error_to_service)?;
    state
        .role_bindings
        .record_role_binding(PlatformRoleBindingRecord {
            role_binding_id: SINGLE_USER_ROLE_BINDING_ID.to_owned(),
            tenant_id: SINGLE_USER_TENANT_ID.to_owned(),
            organization_id: None,
            project_id: None,
            principal_id: SINGLE_USER_ID.to_owned(),
            role_id: BuiltInRole::TenantOwner.as_str().to_owned(),
            status: PlatformRoleBindingStatus::Active,
            resource_version: 1,
        })
        .map_err(role_binding_error_to_service)
}

async fn auth_session_from_headers(
    state: &PlatformServiceState,
    headers: &HeaderMap,
) -> Result<(String, PlatformAuthSessionRecord), ServiceError> {
    let authorization = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .ok_or(ServiceError::AuthenticationRequired)?;
    let raw_bearer = bearer_token(authorization).ok_or(ServiceError::AuthenticationFailed(
        "invalid_bearer_authorization",
    ))?;
    let session = match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .auth_sessions
            .auth_session_for_bearer(raw_bearer)
            .map_err(|error| ServiceError::AuthenticationFailed(error.as_str()))?,
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .auth_session_for_bearer(raw_bearer)
            .await
            .map_err(auth_repository_error)?,
    };
    Ok((raw_bearer.to_owned(), session))
}

async fn mutating_auth_session_from_headers(
    state: &PlatformServiceState,
    headers: &HeaderMap,
) -> Result<(String, PlatformAuthSessionRecord), ServiceError> {
    let (raw_bearer, session) = auth_session_from_headers(state, headers).await?;
    let actual = headers
        .get(PLATFORM_CSRF_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ServiceError::AuthenticationFailed("csrf_token_required"))?;
    let expected = platform_csrf_token(&session);
    if !constant_time_bytes_eq(expected.as_bytes(), actual.as_bytes()) {
        return Err(ServiceError::AuthenticationFailed("csrf_token_invalid"));
    }
    Ok((raw_bearer, session))
}

fn ensure_user_auth_session(session: &PlatformAuthSessionRecord) -> Result<(), ServiceError> {
    if session.actor.actor_kind == ActorKind::User {
        Ok(())
    } else {
        Err(ServiceError::Forbidden("user_actor_required"))
    }
}

async fn revoke_auth_session(
    state: &PlatformServiceState,
    raw_bearer: &str,
) -> Result<PlatformAuthSessionRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .auth_sessions
            .revoke_auth_session_by_bearer(raw_bearer)
            .map_err(|error| ServiceError::AuthenticationFailed(error.as_str())),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .revoke_auth_session_by_bearer(raw_bearer)
            .await
            .map_err(auth_repository_error),
    }
}

async fn update_auth_session_context(
    state: &PlatformServiceState,
    raw_bearer: &str,
    organization_id: Option<&str>,
    project_id: Option<&str>,
) -> Result<PlatformAuthSessionRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .auth_sessions
            .update_auth_session_context_by_bearer(
                raw_bearer,
                organization_id.map(str::to_owned),
                project_id.map(str::to_owned),
            )
            .map_err(|error| ServiceError::AuthenticationFailed(error.as_str())),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .update_auth_session_context_by_bearer(raw_bearer, organization_id, project_id)
            .await
            .map_err(auth_repository_error),
    }
}

async fn active_organization_member_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    organization_id: &str,
) -> Result<PlatformOrganizationMembershipRecord, ServiceError> {
    let member = organization_members_for_organization(state, organization_id)
        .await?
        .into_iter()
        .find(|member| {
            member.tenant_id == actor.tenant_id
                && member.principal_id == actor.principal_id
                && member.membership_kind == "user"
        })
        .ok_or(ServiceError::Forbidden("organization_membership_required"))?;
    if member.status.accepts_access() {
        Ok(member)
    } else {
        Err(ServiceError::Forbidden("organization_membership_required"))
    }
}

async fn active_project_member_for_actor(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    project_id: &str,
) -> Result<PlatformProjectMembershipRecord, ServiceError> {
    let member = project_members_for_project(state, project_id)
        .await?
        .into_iter()
        .find(|member| {
            member.tenant_id == actor.tenant_id
                && member.principal_id == actor.principal_id
                && member.membership_kind == "user"
        })
        .ok_or(ServiceError::Forbidden("project_membership_required"))?;
    if !member.accepts_access() {
        return Err(ServiceError::Forbidden("project_membership_required"));
    }
    active_organization_member_for_actor(state, actor, &member.organization_id).await?;
    Ok(member)
}

fn auth_session_response_json(session: &PlatformAuthSessionRecord) -> Value {
    json!({
        "schema": "platform.auth.session.v1",
        "session": auth_session_safe_json(session),
        "csrf": csrf_response_json(session),
        "actor": actor_json(&session.actor),
        "session_token_hash_included": false,
        "raw_session_token_included": false,
    })
}

fn auth_session_safe_json(session: &PlatformAuthSessionRecord) -> Value {
    json!({
        "kind": "auth_session",
        "id": session.session_id,
        "session_id": session.session_id,
        "status": session.status.as_str(),
        "actor": actor_json(&session.actor),
        "session_token_hash_included": false,
        "raw_session_token_included": false,
    })
}

fn csrf_response_json(session: &PlatformAuthSessionRecord) -> Value {
    json!({
        "header": PLATFORM_CSRF_TOKEN_HEADER,
        "token": platform_csrf_token(session),
    })
}

fn actor_json(actor: &AuthenticatedActor) -> Value {
    json!({
        "tenant_id": actor.tenant_id,
        "organization_id": actor.organization_id,
        "project_id": actor.project_id,
        "principal_id": actor.principal_id,
        "actor_kind": actor_kind_name(actor.actor_kind),
    })
}

fn platform_csrf_token(session: &PlatformAuthSessionRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"starweaver-platform-csrf-v1\0");
    hasher.update(session.session_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(session.token_hash.as_bytes());
    let digest = hasher.finalize();
    let mut token = String::with_capacity("sha256:".len() + 64);
    token.push_str("sha256:");
    push_lower_hex(&mut token, &digest);
    token
}

fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn validate_oidc_callback_request(request: &OidcLoginCallbackRequest) -> Result<(), ServiceError> {
    if request.state.trim().is_empty() {
        return Err(ServiceError::AuthenticationFailed("oidc_state_empty"));
    }
    if request.code.trim().is_empty() {
        return Err(ServiceError::AuthenticationFailed(
            "oidc_authorization_code_empty",
        ));
    }
    if request.nonce.trim().is_empty() {
        return Err(ServiceError::AuthenticationFailed("oidc_nonce_empty"));
    }
    if request.code_verifier.trim().is_empty() {
        return Err(ServiceError::AuthenticationFailed(
            "oidc_pkce_verifier_empty",
        ));
    }
    Ok(())
}

async fn oidc_login_provider(
    state: &PlatformServiceState,
    identity_provider_id: &str,
) -> Result<OidcLoginProviderRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .oidc_logins
            .provider(identity_provider_id)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .oidc_login_provider(identity_provider_id)
            .await
            .map_err(data_repository_error)?
            .ok_or(ServiceError::ResourceNotFound),
    }
}

async fn oidc_login_attempt_for_state(
    state: &PlatformServiceState,
    raw_state: &str,
) -> Result<OidcLoginAttemptRecord, ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            state.oidc_logins.attempt_for_state(raw_state).ok_or(
                ServiceError::AuthenticationFailed("oidc_login_attempt_unavailable"),
            )
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .oidc_login_attempt_for_state(raw_state)
            .await
            .map_err(auth_repository_error)?
            .ok_or(ServiceError::AuthenticationFailed(
                "oidc_login_attempt_unavailable",
            )),
    }
}

fn validate_oidc_callback_attempt(
    provider: &OidcLoginProviderRecord,
    attempt: &OidcLoginAttemptRecord,
    request: &OidcLoginCallbackRequest,
    now_unix: i64,
) -> Result<(), ServiceError> {
    if provider.status != OidcLoginProviderStatus::Active {
        return Err(ServiceError::AuthenticationFailed("oidc_provider_inactive"));
    }
    if attempt.tenant_id != provider.tenant_id
        || attempt.identity_provider_id != provider.identity_provider_id
        || attempt.status != OidcLoginAttemptStatus::Active
        || attempt.expires_at_unix <= now_unix
    {
        return Err(ServiceError::AuthenticationFailed(
            "oidc_login_attempt_unavailable",
        ));
    }
    if attempt.state_hash != hash_oidc_login_state(request.state.trim()) {
        return Err(ServiceError::AuthenticationFailed(
            "oidc_login_attempt_unavailable",
        ));
    }
    if attempt.nonce_hash != hash_oidc_login_nonce(request.nonce.trim()) {
        return Err(ServiceError::AuthenticationFailed("oidc_nonce_mismatch"));
    }
    if attempt.pkce_verifier_hash != hash_oidc_pkce_verifier(request.code_verifier.trim()) {
        return Err(ServiceError::AuthenticationFailed(
            "oidc_pkce_verifier_mismatch",
        ));
    }
    Ok(())
}

async fn oidc_resolved_provider_metadata(
    state: &PlatformServiceState,
    provider: &OidcLoginProviderRecord,
) -> Result<OidcResolvedProviderMetadata, ServiceError> {
    let discovery = if oidc_metadata_needs_discovery(provider) {
        Some(
            state
                .oidc_http
                .get_json::<OidcDiscoveryDocument>(&oidc_discovery_url(&provider.issuer_url))
                .await?,
        )
    } else {
        None
    };
    resolve_oidc_provider_metadata(provider, discovery.as_ref())
        .map_err(|error| ServiceError::AuthenticationFailed(error.as_str()))
}

fn oidc_metadata_needs_discovery(provider: &OidcLoginProviderRecord) -> bool {
    provider.authorization_endpoint.trim().is_empty()
        || provider.token_endpoint.trim().is_empty()
        || provider.jwks_uri.trim().is_empty()
}

async fn oidc_client_secret_for_metadata(
    state: &PlatformServiceState,
    metadata: &OidcResolvedProviderMetadata,
) -> Result<Option<PlatformSecretValue>, ServiceError> {
    let Some(secret_ref_id) = metadata.client_secret_ref.as_deref() else {
        return Ok(None);
    };
    let secret_ref = secret_ref_by_id(state, secret_ref_id).await?;
    if secret_ref.tenant_id != metadata.tenant_id {
        return Err(ServiceError::Forbidden("tenant_mismatch"));
    }
    let secret = resolve_platform_secret(state, secret_ref_id).await?;
    Ok(Some(secret))
}

async fn exchange_oidc_authorization_code(
    state: &PlatformServiceState,
    metadata: &OidcResolvedProviderMetadata,
    attempt: &OidcLoginAttemptRecord,
    request: &OidcLoginCallbackRequest,
    client_secret: Option<&PlatformSecretValue>,
) -> Result<String, ServiceError> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", request.code.trim()),
        ("redirect_uri", attempt.redirect_uri.as_str()),
        ("code_verifier", request.code_verifier.trim()),
    ];
    let basic_auth = match metadata.token_endpoint_auth_method {
        OidcTokenEndpointAuthMethod::None => {
            form.push(("client_id", metadata.client_id.as_str()));
            None
        }
        OidcTokenEndpointAuthMethod::ClientSecretBasic => {
            let secret = client_secret.ok_or(ServiceError::AuthenticationFailed(
                "oidc_client_secret_missing",
            ))?;
            Some((metadata.client_id.as_str(), secret.expose()))
        }
        OidcTokenEndpointAuthMethod::ClientSecretPost => {
            let secret = client_secret.ok_or(ServiceError::AuthenticationFailed(
                "oidc_client_secret_missing",
            ))?;
            form.push(("client_id", metadata.client_id.as_str()));
            form.push(("client_secret", secret.expose()));
            None
        }
    };
    let token_response = state
        .oidc_http
        .post_form_json::<OidcTokenResponse>(&metadata.token_endpoint, &form, basic_auth)
        .await?;
    if token_response.id_token.trim().is_empty() {
        return Err(ServiceError::AuthenticationFailed("oidc_id_token_missing"));
    }
    Ok(token_response.id_token)
}

fn oidc_login_completion_record(
    provider: &OidcLoginProviderRecord,
    attempt: &OidcLoginAttemptRecord,
    claims: &OidcVerifiedClaims,
    session_token: &str,
    now_unix: i64,
) -> OidcLoginCompletionRecord {
    let suffix = stable_oidc_subject_suffix(
        &provider.tenant_id,
        &provider.identity_provider_id,
        &claims.subject,
    );
    let organization_id = format!("org_oidc_{suffix}");
    let project_id = format!("prj_oidc_{suffix}");
    let user_id = format!("usr_oidc_{suffix}");
    let session_id = format!(
        "sess_oidc_{}",
        &session_token[OIDC_CALLBACK_SESSION_TOKEN_PREFIX.len()
            ..OIDC_CALLBACK_SESSION_TOKEN_PREFIX.len() + 16]
    );
    let actor = AuthenticatedActor::project_user(
        &provider.tenant_id,
        &organization_id,
        &project_id,
        &user_id,
    );
    let display_name = claims
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or(claims.email.as_deref())
        .unwrap_or(claims.subject.as_str())
        .to_owned();
    OidcLoginCompletionRecord {
        login_attempt_id: attempt.login_attempt_id.clone(),
        tenant_id: provider.tenant_id.clone(),
        organization_id,
        project_id,
        user_id,
        identity_provider_id: provider.identity_provider_id.clone(),
        external_identity_id: format!("xid_oidc_{suffix}"),
        organization_member_id: format!("om_oidc_{suffix}"),
        project_member_id: format!("pm_oidc_{suffix}"),
        organization_role_binding_id: format!("rb_oidc_org_admin_{suffix}"),
        provider_subject: claims.subject.clone(),
        email: claims.email.clone(),
        email_verified: claims.email_verified,
        user_display_name: display_name.clone(),
        organization_display_name: format!("{display_name} Organization"),
        project_display_name: format!("{display_name} Default Project"),
        session: PlatformAuthSessionRecord::active(session_id, session_token, actor),
        consumed_at_unix: now_unix,
    }
}

async fn complete_oidc_login(
    state: &PlatformServiceState,
    completion: &OidcLoginCompletionRecord,
) -> Result<(), ServiceError> {
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => {
            let existing_user = state.users.user_including_deleted(&completion.user_id);
            state
                .users
                .record_user(PlatformUserRecord {
                    user_id: completion.user_id.clone(),
                    tenant_id: completion.tenant_id.clone(),
                    default_organization_id: Some(completion.organization_id.clone()),
                    default_project_id: Some(completion.project_id.clone()),
                    primary_email: completion.email.clone(),
                    display_name: completion.user_display_name.clone(),
                    status: existing_user
                        .as_ref()
                        .map_or(PlatformUserStatus::Active, |user| user.status),
                    resource_version: existing_user
                        .as_ref()
                        .map_or(1, |user| user.resource_version + 1),
                })
                .map_err(user_error_to_service)?;
            state
                .external_identities
                .upsert_external_identity(PlatformExternalIdentityRecord {
                    external_identity_id: completion.external_identity_id.clone(),
                    tenant_id: completion.tenant_id.clone(),
                    principal_id: completion.user_id.clone(),
                    identity_provider_id: completion.identity_provider_id.clone(),
                    provider_kind: "oidc".to_owned(),
                    provider_subject: completion.provider_subject.clone(),
                    email: completion.email.clone(),
                    email_verified: completion.email_verified,
                    status: PlatformExternalIdentityStatus::Active,
                })
                .map_err(external_identity_error_to_service)?;
            state.oidc_logins.consume_attempt(completion)?;
            state
                .auth_sessions
                .record_auth_session(completion.session.clone())
                .map_err(|error| ServiceError::AuthenticationFailed(error.as_str()))?;
            state
                .memberships
                .record_organization_member(PlatformOrganizationMembershipRecord {
                    organization_member_id: completion.organization_member_id.clone(),
                    tenant_id: completion.tenant_id.clone(),
                    organization_id: completion.organization_id.clone(),
                    principal_id: completion.user_id.clone(),
                    membership_kind: "user".to_owned(),
                    status: PlatformMembershipStatus::Active,
                    resource_version: 1,
                })
                .map_err(membership_error_to_service)?;
            state
                .memberships
                .record_project_member(PlatformProjectMembershipRecord {
                    project_member_id: completion.project_member_id.clone(),
                    tenant_id: completion.tenant_id.clone(),
                    organization_id: completion.organization_id.clone(),
                    project_id: completion.project_id.clone(),
                    principal_id: completion.user_id.clone(),
                    organization_member_id: Some(completion.organization_member_id.clone()),
                    membership_kind: "user".to_owned(),
                    status: PlatformMembershipStatus::Active,
                    resource_version: 1,
                })
                .map_err(membership_error_to_service)?;
            state
                .role_bindings
                .record_role_binding(PlatformRoleBindingRecord {
                    role_binding_id: completion.organization_role_binding_id.clone(),
                    tenant_id: completion.tenant_id.clone(),
                    organization_id: Some(completion.organization_id.clone()),
                    project_id: None,
                    principal_id: completion.user_id.clone(),
                    role_id: BuiltInRole::OrganizationAdmin.as_str().to_owned(),
                    status: PlatformRoleBindingStatus::Active,
                    resource_version: 1,
                })
                .map_err(role_binding_error_to_service)
        }
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .complete_oidc_login(completion)
            .await
            .map_err(auth_repository_error),
    }
}

fn oidc_login_callback_response(
    provider: &OidcLoginProviderRecord,
    claims: &OidcVerifiedClaims,
    completion: &OidcLoginCompletionRecord,
    session_token: &str,
) -> Value {
    json!({
        "schema": "platform.auth.oidc_callback.v1",
        "provider": {
            "identity_provider_id": provider.identity_provider_id,
            "tenant_id": provider.tenant_id,
            "display_name": provider.display_name,
        },
        "session": {
            "session_id": completion.session.session_id,
            "token_type": "bearer",
            "access_token": session_token,
        },
        "csrf": csrf_response_json(&completion.session),
        "actor": {
            "tenant_id": completion.session.actor.tenant_id,
            "organization_id": completion.session.actor.organization_id,
            "project_id": completion.session.actor.project_id,
            "principal_id": completion.session.actor.principal_id,
            "actor_kind": actor_kind_name(completion.session.actor.actor_kind),
        },
        "user": {
            "user_id": completion.user_id,
            "display_name": completion.user_display_name,
            "primary_email": completion.email,
            "email_verified": completion.email_verified,
            "default_organization_id": completion.organization_id,
            "default_project_id": completion.project_id,
        },
        "organization": {
            "organization_id": completion.organization_id,
            "display_name": completion.organization_display_name,
        },
        "project": {
            "project_id": completion.project_id,
            "display_name": completion.project_display_name,
        },
        "external_identity": {
            "external_identity_id": completion.external_identity_id,
            "provider_subject": claims.subject,
            "issuer": claims.issuer,
            "audiences": claims.audiences,
        },
        "raw_tokens_included": false,
        "authorization_code_included": false,
    })
}

fn stable_oidc_subject_suffix(tenant_id: &str, provider_id: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"starweaver-platform-oidc-subject-id-v1\0");
    hasher.update(tenant_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(provider_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(subject.trim().as_bytes());
    let digest = hasher.finalize();
    let mut suffix = String::with_capacity(40);
    push_lower_hex(&mut suffix, &digest[..20]);
    suffix
}

fn json_string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, ServiceError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or(ServiceError::BadRequest(
            "invalid_single_user_login_request",
        ))
}

fn single_user_actor() -> AuthenticatedActor {
    AuthenticatedActor::project_user(
        SINGLE_USER_TENANT_ID,
        SINGLE_USER_ORGANIZATION_ID,
        SINGLE_USER_PROJECT_ID,
        SINGLE_USER_ID,
    )
}

fn generate_session_token() -> String {
    generate_session_token_with_prefix(SINGLE_USER_SESSION_TOKEN_PREFIX)
}

fn generate_session_token_with_prefix(prefix: &str) -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(prefix.len() + 64);
    token.push_str(prefix);
    push_lower_hex(&mut token, &bytes);
    token
}

fn new_prefixed_id(prefix: &str) -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut id = String::with_capacity(prefix.len() + 1 + 32);
    id.push_str(prefix);
    id.push('_');
    push_lower_hex(&mut id, &bytes);
    id
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

fn current_unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
        })
}

async fn dispatch_foundation_request(
    State(state): State<PlatformServiceState>,
    headers: HeaderMap,
    request: Request<Body>,
) -> Response {
    let (parts, _body) = request.into_parts();
    match handle_foundation_request(&state, &headers, &parts.method, parts.uri.path()).await {
        Ok(body) => (StatusCode::OK, Json(body)).into_response(),
        Err(error) => error.into_response(),
    }
}

async fn handle_foundation_request(
    state: &PlatformServiceState,
    headers: &HeaderMap,
    method: &Method,
    path: &str,
) -> Result<Value, ServiceError> {
    let matched = match_route(method, path).ok_or(ServiceError::RouteNotFound)?;
    let actor = authenticated_actor_from_headers(state, headers).await?;
    let resource = authorization_resource(state, &actor, &matched).await?;
    authorize_service_action(state, &actor, matched.route.action, &resource).await?;
    let business = business_resource(state, &matched).await?;
    Ok(authorized_response(
        &actor,
        &resource,
        &matched,
        business.as_ref(),
    ))
}

async fn authorization_resource(
    state: &PlatformServiceState,
    actor: &AuthenticatedActor,
    matched: &MatchedRoute,
) -> Result<ResourceRef, ServiceError> {
    if let Some(param) = matched.route.resource_id_path_param {
        let resource_id = matched
            .params
            .get(param)
            .ok_or(ServiceError::BadRequest("resource_id_param_missing"))?;
        return match state.repository_backend {
            PlatformRepositoryBackendKind::InMemory => state
                .owners
                .resource_owner(matched.route.resource_kind, resource_id)
                .map(|owner| owner.to_resource_ref())
                .ok_or(ServiceError::ResourceNotFound),
            PlatformRepositoryBackendKind::Postgres => state
                .postgres_repository()
                .ok_or(ServiceError::Internal("postgres_repository_missing"))?
                .resource_owner(matched.route.resource_kind, resource_id)
                .await
                .map_err(data_repository_error)?
                .map(|owner| owner.to_resource_ref())
                .ok_or(ServiceError::ResourceNotFound),
        };
    }

    Ok(scope_resource(actor, matched.route.resource_kind))
}

async fn business_resource(
    state: &PlatformServiceState,
    matched: &MatchedRoute,
) -> Result<Option<PlatformResourceRecord>, ServiceError> {
    let Some(param) = matched.route.resource_id_path_param else {
        return Ok(None);
    };
    let resource_id = matched
        .params
        .get(param)
        .ok_or(ServiceError::BadRequest("resource_id_param_missing"))?;
    match state.repository_backend {
        PlatformRepositoryBackendKind::InMemory => state
            .resources
            .platform_resource(matched.route.resource_kind, resource_id)
            .map(Some)
            .ok_or(ServiceError::ResourceNotFound),
        PlatformRepositoryBackendKind::Postgres => state
            .postgres_repository()
            .ok_or(ServiceError::Internal("postgres_repository_missing"))?
            .platform_resource(matched.route.resource_kind, resource_id)
            .await
            .map_err(data_repository_error)?
            .map(Some)
            .ok_or(ServiceError::ResourceNotFound),
    }
}

fn scope_resource(actor: &AuthenticatedActor, resource_kind: &str) -> ResourceRef {
    match (&actor.organization_id, &actor.project_id) {
        (Some(organization_id), Some(project_id)) => ResourceRef::project(
            resource_kind,
            &actor.tenant_id,
            organization_id,
            project_id,
            "scope",
        ),
        _ => ResourceRef::tenant(resource_kind, &actor.tenant_id, &actor.tenant_id),
    }
}

async fn authenticated_actor_from_headers(
    state: &PlatformServiceState,
    headers: &HeaderMap,
) -> Result<AuthenticatedActor, ServiceError> {
    if let Some(authorization) = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        let Some(raw_token) = bearer_token(authorization) else {
            return Err(ServiceError::AuthenticationFailed(
                "invalid_bearer_authorization",
            ));
        };
        return match state.repository_backend {
            PlatformRepositoryBackendKind::InMemory => match state
                .auth_sessions
                .authenticated_actor_for_bearer(raw_token)
            {
                Ok(actor) => Ok(actor),
                Err(AuthError::SessionNotFound) => state
                    .bearer_credentials
                    .authenticated_actor_for_bearer_credential(raw_token)
                    .map_err(|error| ServiceError::AuthenticationFailed(error.as_str())),
                Err(error) => Err(ServiceError::AuthenticationFailed(error.as_str())),
            },
            PlatformRepositoryBackendKind::Postgres => {
                let repository = state
                    .postgres_repository()
                    .ok_or(ServiceError::Internal("postgres_repository_missing"))?;
                match repository
                    .authenticated_actor_for_session_bearer(raw_token)
                    .await
                {
                    Ok(actor) => Ok(actor),
                    Err(PlatformRepositoryError::Auth(AuthError::SessionNotFound)) => repository
                        .authenticated_actor_for_bearer_credential(raw_token)
                        .await
                        .map_err(auth_repository_error),
                    Err(error) => Err(auth_repository_error(error)),
                }
            }
        };
    }

    if let Some(subject) = headers
        .get(VERIFIED_MTLS_SUBJECT_HEADER)
        .and_then(|value| value.to_str().ok())
    {
        return match state.repository_backend {
            PlatformRepositoryBackendKind::InMemory => state
                .mtls_identities
                .authenticated_actor_for_mtls_subject(subject)
                .map_err(|error| ServiceError::AuthenticationFailed(error.as_str())),
            PlatformRepositoryBackendKind::Postgres => state
                .postgres_repository()
                .ok_or(ServiceError::Internal("postgres_repository_missing"))?
                .authenticated_actor_for_mtls_subject(subject)
                .await
                .map_err(auth_repository_error),
        };
    }

    Err(ServiceError::AuthenticationRequired)
}

fn bearer_token(authorization: &str) -> Option<&str> {
    let value = authorization.trim();
    let token = value.strip_prefix("Bearer ")?;
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Header set by a trusted mTLS terminator after it verifies the client certificate.
pub const VERIFIED_MTLS_SUBJECT_HEADER: &str = "x-starweaver-verified-client-cert-subject";

/// Header carrying the platform session CSRF token for browser mutations.
pub const PLATFORM_CSRF_TOKEN_HEADER: &str = "x-starweaver-platform-csrf-token";

#[derive(Clone, Debug, Eq, PartialEq)]
struct MatchedRoute {
    route: &'static RouteMetadata,
    params: BTreeMap<&'static str, String>,
}

fn match_route(method: &Method, path: &str) -> Option<MatchedRoute> {
    let platform_method = platform_method(method)?;
    foundation_routes()
        .iter()
        .filter(|route| route.method == platform_method)
        .find_map(|route| {
            match_path_pattern(route.path_pattern, path)
                .map(|params| MatchedRoute { route, params })
        })
}

const fn platform_method(method: &Method) -> Option<HttpMethod> {
    match *method {
        Method::DELETE => Some(HttpMethod::Delete),
        Method::GET => Some(HttpMethod::Get),
        Method::POST => Some(HttpMethod::Post),
        _ => None,
    }
}

fn match_path_pattern(pattern: &'static str, path: &str) -> Option<BTreeMap<&'static str, String>> {
    let pattern_segments = path_segments(pattern);
    let path_segments = path_segments(path);
    if pattern_segments.len() != path_segments.len() {
        return None;
    }
    let mut params = BTreeMap::new();
    for (pattern_segment, path_segment) in pattern_segments.into_iter().zip(path_segments) {
        match_segment(pattern_segment, path_segment, &mut params)?;
    }
    Some(params)
}

fn path_segments(path: &str) -> Vec<&str> {
    path.trim_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect()
}

fn match_segment(
    pattern_segment: &'static str,
    path_segment: &str,
    params: &mut BTreeMap<&'static str, String>,
) -> Option<()> {
    let Some(open) = pattern_segment.find('{') else {
        return (pattern_segment == path_segment).then_some(());
    };
    let close = pattern_segment[open + 1..].find('}')? + open + 1;
    let prefix = &pattern_segment[..open];
    let name = &pattern_segment[open + 1..close];
    let suffix = &pattern_segment[close + 1..];
    if name.is_empty()
        || !path_segment.starts_with(prefix)
        || !path_segment.ends_with(suffix)
        || path_segment.len() < prefix.len() + suffix.len()
    {
        return None;
    }
    let value_end = path_segment.len() - suffix.len();
    let value = &path_segment[prefix.len()..value_end];
    if value.is_empty() {
        return None;
    }
    params.insert(name, value.to_owned());
    Some(())
}

fn authorized_response(
    actor: &AuthenticatedActor,
    resource: &ResourceRef,
    matched: &MatchedRoute,
    business: Option<&PlatformResourceRecord>,
) -> Value {
    json!({
        "schema": "platform.http.authorization.v1",
        "authorized": true,
        "route": {
            "method": matched.route.method.as_str(),
            "path_pattern": matched.route.path_pattern,
            "action": matched.route.action.as_str(),
            "resource_kind": matched.route.resource_kind,
            "resource_id_path_param": matched.route.resource_id_path_param,
            "access": matched.route.access.as_str(),
            "user_actor_required": matched.route.user_actor_required,
        },
        "actor": {
            "tenant_id": actor.tenant_id,
            "organization_id": actor.organization_id,
            "project_id": actor.project_id,
            "principal_id": actor.principal_id,
            "actor_kind": actor_kind_name(actor.actor_kind),
        },
        "resource": {
            "kind": resource.kind,
            "tenant_id": resource.tenant_id,
            "organization_id": resource.organization_id,
            "project_id": resource.project_id,
            "resource_id": resource.resource_id,
        },
        "business_resource": business.map(PlatformResourceRecord::to_safe_json),
    })
}

const fn actor_kind_name(kind: ActorKind) -> &'static str {
    match kind {
        ActorKind::User => "user",
        ActorKind::ServiceAccount => "service_account",
        ActorKind::System => "system",
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceError {
    AuthenticationRequired,
    AuthenticationFailed(&'static str),
    BadRequest(&'static str),
    Forbidden(&'static str),
    Internal(&'static str),
    ResourceNotFound,
    RouteNotFound,
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::AuthenticationRequired => (StatusCode::UNAUTHORIZED, "authentication_required"),
            Self::AuthenticationFailed(code) => (StatusCode::UNAUTHORIZED, code),
            Self::BadRequest(code) => (StatusCode::BAD_REQUEST, code),
            Self::Forbidden(code) => (StatusCode::FORBIDDEN, code),
            Self::Internal(code) => (StatusCode::INTERNAL_SERVER_ERROR, code),
            Self::ResourceNotFound => (StatusCode::NOT_FOUND, "resource_not_found"),
            Self::RouteNotFound => (StatusCode::NOT_FOUND, "route_not_found"),
        };
        (
            status,
            Json(json!({
                "schema": "platform.error.v1",
                "error": {
                    "code": code,
                    "status": status.as_u16(),
                }
            })),
        )
            .into_response()
    }
}

fn auth_repository_error(error: PlatformRepositoryError) -> ServiceError {
    match error {
        PlatformRepositoryError::Auth(error) => ServiceError::AuthenticationFailed(error.as_str()),
        PlatformRepositoryError::Identity(error) => ServiceError::BadRequest(error.as_str()),
        PlatformRepositoryError::ExternalIdentity(error) => {
            external_identity_error_to_service(error)
        }
        PlatformRepositoryError::RoleBinding(error) => role_binding_error_to_service(error),
        PlatformRepositoryError::User(error) => user_error_to_service(error),
        PlatformRepositoryError::Audit(error) => audit_error_to_service(error),
        PlatformRepositoryError::Membership(error) => membership_error_to_service(error),
        PlatformRepositoryError::Invitation(error) => invitation_error_to_service(error),
        PlatformRepositoryError::Secret(error) => secret_error_to_service(error),
        PlatformRepositoryError::Database(_) => ServiceError::Internal("database_error"),
        PlatformRepositoryError::UnknownActorKind(_) => {
            ServiceError::Internal("unknown_actor_kind")
        }
        PlatformRepositoryError::UnknownSessionStatus(_) => {
            ServiceError::Internal("unknown_session_status")
        }
        PlatformRepositoryError::UnknownCredentialStatus(_) => {
            ServiceError::Internal("unknown_credential_status")
        }
        PlatformRepositoryError::UnknownMtlsIdentityStatus(_) => {
            ServiceError::Internal("unknown_mtls_identity_status")
        }
        PlatformRepositoryError::UnknownOidcLoginProviderStatus(_) => {
            ServiceError::Internal("unknown_oidc_login_provider_status")
        }
        PlatformRepositoryError::UnknownOidcLoginAttemptStatus(_) => {
            ServiceError::Internal("unknown_oidc_login_attempt_status")
        }
        PlatformRepositoryError::UnknownSecretRefStatus(_) => {
            ServiceError::Internal("unknown_secret_ref_status")
        }
        PlatformRepositoryError::UnknownMembershipStatus(_) => {
            ServiceError::Internal("unknown_membership_status")
        }
        PlatformRepositoryError::UnknownInvitationStatus(_) => {
            ServiceError::Internal("unknown_invitation_status")
        }
        PlatformRepositoryError::UnknownExternalIdentityStatus(_) => {
            ServiceError::Internal("unknown_external_identity_status")
        }
        PlatformRepositoryError::UnknownRoleBindingStatus(_) => {
            ServiceError::Internal("unknown_role_binding_status")
        }
        PlatformRepositoryError::UnknownUserStatus(_) => {
            ServiceError::Internal("unknown_user_status")
        }
        PlatformRepositoryError::OidcLoginAttemptUnavailable(_) => {
            ServiceError::AuthenticationFailed("oidc_login_attempt_unavailable")
        }
        PlatformRepositoryError::OidcExternalIdentityPrincipalMismatch(_) => {
            ServiceError::Forbidden("oidc_external_identity_principal_mismatch")
        }
        PlatformRepositoryError::OidcSessionActorMismatch(_) => {
            ServiceError::Internal("oidc_session_actor_mismatch")
        }
        PlatformRepositoryError::Store(error) => ServiceError::Internal(error.as_str()),
        PlatformRepositoryError::Resource(error) => ServiceError::Internal(error.as_str()),
        PlatformRepositoryError::ProjectScopeRequired(_) => {
            ServiceError::Internal("project_scope_required")
        }
    }
}

fn data_repository_error(error: PlatformRepositoryError) -> ServiceError {
    match error {
        PlatformRepositoryError::Database(_) => ServiceError::Internal("database_error"),
        PlatformRepositoryError::Auth(error) => ServiceError::Internal(error.as_str()),
        PlatformRepositoryError::Identity(error) => ServiceError::BadRequest(error.as_str()),
        PlatformRepositoryError::ExternalIdentity(error) => {
            external_identity_error_to_service(error)
        }
        PlatformRepositoryError::RoleBinding(error) => role_binding_error_to_service(error),
        PlatformRepositoryError::User(error) => user_error_to_service(error),
        PlatformRepositoryError::Audit(error) => audit_error_to_service(error),
        PlatformRepositoryError::Membership(error) => membership_error_to_service(error),
        PlatformRepositoryError::Invitation(error) => invitation_error_to_service(error),
        PlatformRepositoryError::Secret(error) => secret_error_to_service(error),
        PlatformRepositoryError::Store(error) => ServiceError::Internal(error.as_str()),
        PlatformRepositoryError::Resource(error) => ServiceError::Internal(error.as_str()),
        PlatformRepositoryError::UnknownActorKind(_) => {
            ServiceError::Internal("unknown_actor_kind")
        }
        PlatformRepositoryError::UnknownSessionStatus(_) => {
            ServiceError::Internal("unknown_session_status")
        }
        PlatformRepositoryError::UnknownCredentialStatus(_) => {
            ServiceError::Internal("unknown_credential_status")
        }
        PlatformRepositoryError::UnknownMtlsIdentityStatus(_) => {
            ServiceError::Internal("unknown_mtls_identity_status")
        }
        PlatformRepositoryError::UnknownOidcLoginProviderStatus(_) => {
            ServiceError::Internal("unknown_oidc_login_provider_status")
        }
        PlatformRepositoryError::UnknownOidcLoginAttemptStatus(_) => {
            ServiceError::Internal("unknown_oidc_login_attempt_status")
        }
        PlatformRepositoryError::UnknownSecretRefStatus(_) => {
            ServiceError::Internal("unknown_secret_ref_status")
        }
        PlatformRepositoryError::UnknownMembershipStatus(_) => {
            ServiceError::Internal("unknown_membership_status")
        }
        PlatformRepositoryError::UnknownInvitationStatus(_) => {
            ServiceError::Internal("unknown_invitation_status")
        }
        PlatformRepositoryError::UnknownExternalIdentityStatus(_) => {
            ServiceError::Internal("unknown_external_identity_status")
        }
        PlatformRepositoryError::UnknownRoleBindingStatus(_) => {
            ServiceError::Internal("unknown_role_binding_status")
        }
        PlatformRepositoryError::UnknownUserStatus(_) => {
            ServiceError::Internal("unknown_user_status")
        }
        PlatformRepositoryError::OidcLoginAttemptUnavailable(_) => {
            ServiceError::AuthenticationFailed("oidc_login_attempt_unavailable")
        }
        PlatformRepositoryError::OidcExternalIdentityPrincipalMismatch(_) => {
            ServiceError::Forbidden("oidc_external_identity_principal_mismatch")
        }
        PlatformRepositoryError::OidcSessionActorMismatch(_) => {
            ServiceError::Internal("oidc_session_actor_mismatch")
        }
        PlatformRepositoryError::ProjectScopeRequired(_) => {
            ServiceError::Internal("project_scope_required")
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{to_bytes, Body};
    use axum::http::header::AUTHORIZATION;
    use axum::http::{Method, Request, StatusCode};
    use jsonwebtoken::jwk::{Jwk, JwkSet, PublicKeyUse};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use serde_json::{json, Value};
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use crate::action::{
        ActionGrant, ActorKind, AuthenticatedActor, AuthorizationEngine, AuthorizationRequest,
        BuiltInRole, FoundationAuthorizationEngine, PlatformAction, ResourceRef, RoleScopeKind,
    };
    use crate::audit::{PlatformAuditEventRecord, PLATFORM_AUDIT_REDACTION_PROFILE};
    use crate::auth::{
        InMemoryPlatformAuthSessionStore, InMemoryPlatformBearerCredentialStore,
        InMemoryPlatformMtlsIdentityStore, PlatformAuthSessionRecord,
        PlatformAuthSessionRepository, PlatformAuthSessionStatus, PlatformBearerCredentialKind,
        PlatformBearerCredentialRecord, PlatformBearerCredentialRepository,
        PlatformBearerCredentialStatus, PlatformMtlsIdentityRecord, PlatformMtlsIdentityRepository,
    };
    use crate::config::{PlatformConfig, PlatformSingleUserConfig};
    use crate::identity::{
        oidc_discovery_url, InMemoryPlatformExternalIdentityStore, OidcLoginAttemptRecord,
        OidcLoginAttemptStart, OidcLoginProviderRecord, OidcLoginProviderStatus,
        OidcTokenEndpointAuthMethod, PlatformExternalIdentityRecord,
        PlatformExternalIdentityStatus,
    };
    use crate::invitation::{
        hash_platform_invitation_token, InMemoryPlatformInvitationStore, PlatformInvitationStatus,
        PlatformOrganizationInvitationRecord,
    };
    use crate::membership::{
        InMemoryPlatformMembershipStore, PlatformMembershipStatus,
        PlatformOrganizationMembershipRecord, PlatformProjectMembershipRecord,
    };
    use crate::postgres::PostgresPlatformRepository;
    use crate::resource::{
        ApprovalRecord, ConversationRecord, EnvironmentAttachmentRecord, EvidenceArchiveRecord,
        InMemoryPlatformResourceStore, PlatformResourceData, PlatformResourceRecord,
        PlatformResourceRepository, RunRecord,
    };
    use crate::role::{
        InMemoryPlatformRoleBindingStore, PlatformRoleBindingRecord, PlatformRoleBindingStatus,
    };
    use crate::secret::{
        CreatePlatformSecretRefRequest, InMemoryPlatformSecretStore, IN_MEMORY_SECRET_BACKEND,
    };
    use crate::service::{
        build_platform_service_state, current_unix_timestamp, match_route, router,
        InMemoryOidcLoginStore, PlatformOidcHttpClient, PlatformRepositoryBackendKind,
        PlatformRunError, PlatformServiceState, StaticOidcHttpClient, PLATFORM_CSRF_TOKEN_HEADER,
        SINGLE_USER_ID, SINGLE_USER_ORGANIZATION_ID, SINGLE_USER_PROJECT_ID,
        SINGLE_USER_SESSION_TOKEN_PREFIX, SINGLE_USER_TENANT_ID, VERIFIED_MTLS_SUBJECT_HEADER,
    };
    use crate::storage::{
        InMemoryResourceOwnerStore, ResourceOwnerRecord, ResourceOwnerRepository,
    };
    use crate::user::{InMemoryPlatformUserStore, PlatformUserRecord, PlatformUserStatus};

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const OTHER_PROJECT_ID: &str = "prj_other";
    const USER_ID: &str = "usr_test";
    const TARGET_USER_ID: &str = "usr_target";
    const SERVICE_ACCOUNT_ID: &str = "svc_test";
    const USER_TOKEN: &str = "platform-user-session-token";
    const TARGET_TOKEN: &str = "platform-target-session-token";
    const SERVICE_ACCOUNT_TOKEN: &str = "platform-service-account-session-token";
    const API_KEY_TOKEN: &str = "platform-api-key-token";
    const MTLS_SUBJECT: &str = "spiffe://platform.test/ns/default/sa/platform-worker";

    #[test]
    fn default_service_state_uses_in_memory_backend() {
        let state = PlatformServiceState::new(
            InMemoryResourceOwnerStore::new(),
            FoundationAuthorizationEngine::new(Vec::<ActionGrant>::new()),
        );

        assert_eq!(
            state.repository_backend(),
            PlatformRepositoryBackendKind::InMemory
        );
        assert!(state.postgres_repository().is_none());
    }

    #[tokio::test]
    async fn postgres_repository_state_selects_durable_backend() {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://platform:platform@127.0.0.1:1/platform")
            .unwrap_or_else(|error| panic!("lazy postgres pool should build: {error}"));
        let state = PlatformServiceState::with_postgres_repository(
            PostgresPlatformRepository::new(pool),
            FoundationAuthorizationEngine::new(Vec::<ActionGrant>::new()),
        );

        assert_eq!(
            state.repository_backend(),
            PlatformRepositoryBackendKind::Postgres
        );
        assert!(state.postgres_repository().is_some());
        assert!(state.owners().resource_owners().is_empty());
    }

    #[tokio::test]
    async fn startup_config_builds_in_memory_service_state() {
        let state = build_platform_service_state(&PlatformConfig::default())
            .await
            .unwrap_or_else(|error| panic!("default platform config should build: {error}"));

        assert_eq!(
            state.repository_backend(),
            PlatformRepositoryBackendKind::InMemory
        );
        assert!(state.postgres_repository().is_none());
    }

    #[tokio::test]
    async fn startup_config_rejects_unsafe_production_before_binding() {
        let config = PlatformConfig {
            environment: "production".to_owned(),
            ..PlatformConfig::default()
        };
        let Err(error) = build_platform_service_state(&config).await else {
            panic!("unsafe production config should fail");
        };

        match error {
            PlatformRunError::Config(config_error) => assert_eq!(
                config_error.codes(),
                vec![
                    "durable_repository_backend_required",
                    "database_url_required"
                ]
            ),
            unexpected => panic!("unexpected startup error: {unexpected}"),
        }
    }

    #[tokio::test]
    async fn single_user_login_is_hidden_until_credentials_are_configured() {
        let response = request_json_body(
            PlatformServiceState::default(),
            Method::POST,
            "/auth/v1/single-user/login",
            [],
            json!({
                "username": "admin",
                "password": "secret",
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.body["error"]["code"], "route_not_found");
    }

    #[tokio::test]
    async fn single_user_login_creates_session_with_default_scope() {
        let state = build_platform_service_state(&PlatformConfig {
            single_user_auth: Some(single_user_config()),
            ..PlatformConfig::default()
        })
        .await
        .unwrap_or_else(|error| panic!("single-user state should build: {error}"));

        let wrong_password = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/single-user/login",
            [],
            json!({
                "username": "admin",
                "password": "wrong",
            }),
        )
        .await;
        assert_eq!(wrong_password.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            wrong_password.body["error"]["code"],
            "single_user_credentials_invalid"
        );

        let response = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/single-user/login",
            [],
            json!({
                "username": "admin",
                "password": "correct horse battery staple",
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.body["schema"],
            "platform.auth.single_user_login.v1"
        );
        assert_eq!(
            response.body["user"]["default_organization_id"],
            SINGLE_USER_ORGANIZATION_ID
        );
        assert_eq!(
            response.body["user"]["default_project_id"],
            SINGLE_USER_PROJECT_ID
        );
        let token = response.body["session"]["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("login response should include access token"));
        assert!(token.starts_with(SINGLE_USER_SESSION_TOKEN_PREFIX));
        assert_eq!(response.body["csrf"]["header"], PLATFORM_CSRF_TOKEN_HEADER);
        assert!(response.body["csrf"]["token"]
            .as_str()
            .is_some_and(|token| token.starts_with("sha256:")));

        let actor = state
            .auth_sessions()
            .authenticated_actor_for_bearer(token)
            .unwrap_or_else(|error| panic!("login token should resolve: {error:?}"));
        assert_eq!(actor.principal_id, SINGLE_USER_ID);
        assert_eq!(
            actor.organization_id.as_deref(),
            Some(SINGLE_USER_ORGANIZATION_ID)
        );
        assert_eq!(actor.project_id.as_deref(), Some(SINGLE_USER_PROJECT_ID));

        let decision = state.authorization().authorize(&AuthorizationRequest {
            actor,
            action: PlatformAction::RunRead,
            resource: ResourceRef::project(
                "Run",
                SINGLE_USER_TENANT_ID,
                SINGLE_USER_ORGANIZATION_ID,
                SINGLE_USER_PROJECT_ID,
                "run_single_user",
            ),
        });
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn auth_session_read_and_logout_use_session_csrf() {
        let state = project_state(USER_ID, BuiltInRole::ProjectDeveloper, []);

        let session = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/session",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(session.status, StatusCode::OK, "{:?}", session.body);
        assert_eq!(session.body["schema"], "platform.auth.session.v1");
        assert_eq!(session.body["session"]["session_id"], "sess_test");
        assert_eq!(session.body["session"]["status"], "active");
        assert_eq!(session.body["actor"]["principal_id"], USER_ID);
        assert_eq!(session.body["session_token_hash_included"], false);
        assert_eq!(session.body["raw_session_token_included"], false);
        assert!(!session.body.to_string().contains(USER_TOKEN));
        let csrf = csrf_token_from_body(&session.body);

        let missing_csrf = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/logout",
            auth_headers(USER_TOKEN),
            json!({}),
        )
        .await;
        assert_eq!(missing_csrf.status, StatusCode::UNAUTHORIZED);
        assert_eq!(missing_csrf.body["error"]["code"], "csrf_token_required");

        let wrong_csrf = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/logout",
            auth_headers_with_csrf(USER_TOKEN, "sha256:wrong"),
            json!({}),
        )
        .await;
        assert_eq!(wrong_csrf.status, StatusCode::UNAUTHORIZED);
        assert_eq!(wrong_csrf.body["error"]["code"], "csrf_token_invalid");

        let logout = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/logout",
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({}),
        )
        .await;
        assert_eq!(logout.status, StatusCode::OK, "{:?}", logout.body);
        assert_eq!(logout.body["schema"], "platform.auth.logout.v1");
        assert_eq!(logout.body["session"]["status"], "revoked");
        assert_eq!(logout.body["revoked"], true);

        let after_logout = request_json(
            state,
            Method::GET,
            "/auth/v1/session",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(after_logout.status, StatusCode::UNAUTHORIZED);
        assert_eq!(after_logout.body["error"]["code"], "auth_session_revoked");
    }

    #[tokio::test]
    async fn auth_session_context_updates_require_active_membership() {
        let state = project_state(USER_ID, BuiltInRole::ProjectDeveloper, [])
            .with_membership_store(membership_store());
        let session = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/session",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(session.status, StatusCode::OK, "{:?}", session.body);
        let csrf = csrf_token_from_body(&session.body);

        let project = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/session/active-project",
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({
                "project_id": PROJECT_ID,
            }),
        )
        .await;
        assert_eq!(project.status, StatusCode::OK, "{:?}", project.body);
        assert_eq!(project.body["actor"]["organization_id"], ORGANIZATION_ID);
        assert_eq!(project.body["actor"]["project_id"], PROJECT_ID);

        let organization = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/session/active-organization",
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({
                "organization_id": ORGANIZATION_ID,
            }),
        )
        .await;
        assert_eq!(
            organization.status,
            StatusCode::OK,
            "{:?}",
            organization.body
        );
        assert_eq!(
            organization.body["actor"]["organization_id"],
            ORGANIZATION_ID
        );
        assert_eq!(organization.body["actor"]["project_id"], Value::Null);

        let denied = request_json_body(
            state,
            Method::POST,
            "/auth/v1/session/active-project",
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({
                "project_id": OTHER_PROJECT_ID,
            }),
        )
        .await;
        assert_eq!(denied.status, StatusCode::FORBIDDEN);
        assert_eq!(denied.body["error"]["code"], "project_membership_required");
    }

    #[tokio::test]
    async fn service_account_session_cannot_use_user_session_api() {
        let state = project_state_with_actor(
            ActorKind::ServiceAccount,
            SERVICE_ACCOUNT_ID,
            SERVICE_ACCOUNT_TOKEN,
            BuiltInRole::TenantOwner,
            [],
        );

        let response = request_json(
            state,
            Method::GET,
            "/auth/v1/session",
            auth_headers(SERVICE_ACCOUNT_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.body["error"]["code"], "user_actor_required");
    }

    #[tokio::test]
    async fn public_auth_provider_discovery_redacts_secrets_and_filters_status() {
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(oidc_provider_with_discovery());
        oidc_logins.record_provider(OidcLoginProviderRecord {
            identity_provider_id: "idp_disabled".to_owned(),
            status: OidcLoginProviderStatus::Disabled,
            ..oidc_provider_with_discovery()
        });
        let state = PlatformServiceState::default()
            .with_single_user_auth(Some(single_user_config()))
            .with_oidc_login_store(oidc_logins);

        let local = request_json(state.clone(), Method::GET, "/auth/v1/providers", []).await;
        assert_eq!(local.status, StatusCode::OK, "{:?}", local.body);
        assert_eq!(local.body["schema"], "platform.auth.providers.v1");
        assert_eq!(
            local.body["providers"][0]["provider_kind"],
            "single_user_password"
        );
        assert_eq!(
            local.body["providers"][0]["login_path"],
            "/auth/v1/single-user/login"
        );

        let oidc = request_json(
            state,
            Method::GET,
            "/auth/v1/providers?tenant_id=ten_test",
            [],
        )
        .await;
        assert_eq!(oidc.status, StatusCode::OK, "{:?}", oidc.body);
        assert_eq!(oidc.body["providers"].as_array().map(Vec::len), Some(1));
        assert_eq!(oidc.body["providers"][0]["provider_kind"], "oidc");
        assert_eq!(
            oidc.body["providers"][0]["login_path"],
            "/auth/v1/providers/idp_oidc/login"
        );
        assert_eq!(
            oidc.body["providers"][0]["start_path"],
            "/auth/v1/providers/idp_oidc/start"
        );
        assert_eq!(
            oidc.body["providers"][0]["provider_secret_material_included"],
            false
        );
        let response_text = oidc.body.to_string();
        assert!(!response_text.contains("token_endpoint"));
        assert!(!response_text.contains("client_secret"));
        assert!(!response_text.contains("idp_disabled"));
    }

    #[tokio::test]
    async fn oidc_login_start_persists_attempt_for_callback() {
        let provider = oidc_provider_with_discovery();
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(provider.clone());
        let oidc_http = StaticOidcHttpClient::new();
        seed_oidc_discovery(&oidc_http, &provider);
        let state = PlatformServiceState::default()
            .with_oidc_login_store(oidc_logins)
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let start = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/providers/idp_oidc/start",
            [],
            json!({
                "tenant_id": TENANT_ID,
            }),
        )
        .await;

        assert_eq!(start.status, StatusCode::OK, "{:?}", start.body);
        assert_eq!(start.body["schema"], "platform.auth.oidc_login_start.v1");
        assert_eq!(start.body["provider_secret_material_included"], false);
        assert_eq!(start.body["authorization_code_included"], false);
        assert_eq!(start.body["raw_tokens_included"], false);
        let raw_state = start.body["client_state"]["state"]
            .as_str()
            .unwrap_or_else(|| panic!("start response should include state"));
        let nonce = start.body["client_state"]["nonce"]
            .as_str()
            .unwrap_or_else(|| panic!("start response should include nonce"));
        let code_verifier = start.body["client_state"]["code_verifier"]
            .as_str()
            .unwrap_or_else(|| panic!("start response should include verifier"));
        let authorization_url = start.body["authorization_url"]
            .as_str()
            .unwrap_or_else(|| panic!("start response should include authorization URL"));
        assert!(!authorization_url.contains(code_verifier));
        let parsed_url = url::Url::parse(authorization_url)
            .unwrap_or_else(|error| panic!("authorization URL should parse: {error}"));
        let query = parsed_url.query_pairs().collect::<Vec<_>>();
        assert!(query
            .iter()
            .any(|(name, value)| name == "response_type" && value == "code"));
        assert!(query
            .iter()
            .any(|(name, value)| name == "client_id" && value == "oidc_client"));
        assert!(query
            .iter()
            .any(|(name, value)| name == "state" && value == raw_state));
        assert!(query
            .iter()
            .any(|(name, value)| name == "nonce" && value == nonce));
        assert!(query
            .iter()
            .any(|(name, value)| name == "code_challenge_method" && value == "S256"));
        assert!(query.iter().any(|(name, value)| {
            name == "scope" && value.split(' ').any(|scope| scope == "openid")
        }));

        seed_oidc_http(&oidc_http, &provider, nonce, "oidc_authorization_code");
        let callback = request_json_body(
            state,
            Method::POST,
            "/auth/v1/providers/idp_oidc/callback",
            [],
            json!({
                "state": raw_state,
                "code": "oidc_authorization_code",
                "nonce": nonce,
                "code_verifier": code_verifier
            }),
        )
        .await;

        assert_eq!(callback.status, StatusCode::OK, "{:?}", callback.body);
        assert_eq!(callback.body["schema"], "platform.auth.oidc_callback.v1");
        assert_eq!(callback.body["csrf"]["header"], PLATFORM_CSRF_TOKEN_HEADER);
        let requests = oidc_http.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.method == "GET"
                    && request.url == oidc_discovery_url("https://issuer.example"))
                .count(),
            2
        );
        let token_request = requests
            .iter()
            .find(|request| request.method == "POST")
            .unwrap_or_else(|| panic!("callback should exchange authorization code"));
        let token_body = token_request
            .body
            .as_deref()
            .unwrap_or_else(|| panic!("token exchange should include form body"));
        assert!(token_body.contains("code_verifier="));
        assert!(token_body.contains("client_id=oidc_client"));
        assert!(!token_body.contains(nonce));
    }

    #[tokio::test]
    async fn oidc_login_start_rejects_inactive_provider_before_discovery() {
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(OidcLoginProviderRecord {
            status: OidcLoginProviderStatus::Disabled,
            ..oidc_provider_with_discovery()
        });
        let oidc_http = StaticOidcHttpClient::new();
        let state = PlatformServiceState::default()
            .with_oidc_login_store(oidc_logins)
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let response = request_json_body(
            state,
            Method::POST,
            "/auth/v1/providers/idp_oidc/start",
            [],
            json!({}),
        )
        .await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.body["error"]["code"], "oidc_provider_inactive");
        assert!(oidc_http.requests().is_empty());
    }

    #[tokio::test]
    async fn oidc_login_start_rejects_wrong_tenant_before_discovery() {
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(oidc_provider_with_discovery());
        let oidc_http = StaticOidcHttpClient::new();
        let state = PlatformServiceState::default()
            .with_oidc_login_store(oidc_logins)
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let response = request_json(
            state,
            Method::GET,
            "/auth/v1/providers/idp_oidc/login?tenant_id=ten_other",
            [],
        )
        .await;

        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.body["error"]["code"], "resource_not_found");
        assert!(oidc_http.requests().is_empty());
    }

    #[tokio::test]
    async fn admin_created_oidc_provider_supports_discovery_login_callback_and_replay_reject() {
        let provider = OidcLoginProviderRecord {
            identity_provider_id: "idp_admin_e2e".to_owned(),
            display_name: "Admin E2E OIDC".to_owned(),
            ..oidc_provider_with_discovery()
        };
        let oidc_http = StaticOidcHttpClient::new();
        seed_oidc_discovery(&oidc_http, &provider);
        let state = project_state(USER_ID, BuiltInRole::TenantOwner, [])
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let create_provider = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/identity-providers",
            auth_headers(USER_TOKEN),
            json!({
                "identity_provider_id": provider.identity_provider_id,
                "display_name": provider.display_name,
                "issuer_url": provider.issuer_url,
                "client_id": provider.client_id,
                "redirect_uri": provider.redirect_uri,
                "requested_scopes": provider.requested_scopes,
                "accepted_audiences": provider.accepted_audiences
            }),
        )
        .await;
        assert_eq!(
            create_provider.status,
            StatusCode::OK,
            "{:?}",
            create_provider.body
        );

        let discovery = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/providers?tenant_id=ten_test",
            [],
        )
        .await;
        assert_eq!(discovery.status, StatusCode::OK, "{:?}", discovery.body);
        assert_eq!(
            discovery.body["providers"].as_array().map(Vec::len),
            Some(1)
        );
        assert_eq!(
            discovery.body["providers"][0]["login_path"],
            "/auth/v1/providers/idp_admin_e2e/login"
        );

        let start = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/providers/idp_admin_e2e/login?tenant_id=ten_test",
            [],
        )
        .await;
        assert_eq!(start.status, StatusCode::OK, "{:?}", start.body);
        let raw_state = start.body["client_state"]["state"]
            .as_str()
            .unwrap_or_else(|| panic!("login response should include state"));
        let nonce = start.body["client_state"]["nonce"]
            .as_str()
            .unwrap_or_else(|| panic!("login response should include nonce"));
        let code_verifier = start.body["client_state"]["code_verifier"]
            .as_str()
            .unwrap_or_else(|| panic!("login response should include verifier"));
        assert!(!start.body.to_string().contains("client_secret"));

        seed_oidc_http(&oidc_http, &provider, nonce, "oidc_authorization_code");
        let callback_body = json!({
            "state": raw_state,
            "code": "oidc_authorization_code",
            "nonce": nonce,
            "code_verifier": code_verifier
        });
        let callback = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/providers/idp_admin_e2e/callback",
            [],
            callback_body.clone(),
        )
        .await;
        assert_eq!(callback.status, StatusCode::OK, "{:?}", callback.body);
        assert_eq!(callback.body["schema"], "platform.auth.oidc_callback.v1");
        assert_eq!(callback.body["raw_tokens_included"], false);
        assert!(!callback.body.to_string().contains("id_token"));

        let replay = request_json_body(
            state,
            Method::POST,
            "/auth/v1/providers/idp_admin_e2e/callback",
            [],
            callback_body,
        )
        .await;
        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay.body["error"]["code"],
            "oidc_login_attempt_unavailable"
        );
    }

    #[tokio::test]
    async fn oidc_login_callback_exchanges_code_validates_jwks_and_creates_session() {
        let provider = oidc_provider_with_discovery();
        let attempt = oidc_attempt("state_secret", "nonce_secret", "pkce_secret");
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(provider.clone());
        oidc_logins.record_attempt(attempt);
        let oidc_http = StaticOidcHttpClient::new();
        seed_oidc_http(
            &oidc_http,
            &provider,
            "nonce_secret",
            "oidc_authorization_code",
        );
        let state = PlatformServiceState::default()
            .with_oidc_login_store(oidc_logins)
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let response = request_json_body(
            state.clone(),
            Method::POST,
            "/auth/v1/providers/idp_oidc/callback",
            [],
            json!({
                "state": "state_secret",
                "code": "oidc_authorization_code",
                "nonce": "nonce_secret",
                "code_verifier": "pkce_secret"
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
        assert_eq!(response.body["schema"], "platform.auth.oidc_callback.v1");
        assert_eq!(response.body["csrf"]["header"], PLATFORM_CSRF_TOKEN_HEADER);
        assert_eq!(
            response.body["external_identity"]["provider_subject"],
            "oidc-user-456"
        );
        assert_eq!(response.body["raw_tokens_included"], false);
        assert_eq!(response.body["authorization_code_included"], false);
        let access_token = response.body["session"]["access_token"]
            .as_str()
            .unwrap_or_else(|| panic!("OIDC callback should return bearer token"));
        let actor = state
            .auth_sessions()
            .authenticated_actor_for_bearer(access_token)
            .unwrap_or_else(|error| panic!("OIDC session should resolve: {error:?}"));
        assert!(actor.principal_id.starts_with("usr_oidc_"));
        assert!(actor
            .organization_id
            .as_deref()
            .is_some_and(|id| id.starts_with("org_oidc_")));
        assert!(actor
            .project_id
            .as_deref()
            .is_some_and(|id| id.starts_with("prj_oidc_")));
        assert_oidc_external_identity_recorded(&state, &actor.principal_id);

        let requests = oidc_http.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(
            (requests[0].method.as_str(), requests[0].url.as_str()),
            ("GET", oidc_discovery_url("https://issuer.example").as_str())
        );
        assert_eq!(
            (requests[1].method.as_str(), requests[1].url.as_str()),
            ("POST", "https://issuer.example/token")
        );
        let token_body = requests[1]
            .body
            .as_deref()
            .unwrap_or_else(|| panic!("token exchange should include form body"));
        assert!(token_body.contains("grant_type=authorization_code"));
        assert!(token_body.contains("code=oidc_authorization_code"));
        assert!(token_body.contains("code_verifier=pkce_secret"));
        assert!(token_body.contains("client_id=oidc_client"));
        assert!(!token_body.contains("nonce_secret"));
        assert_eq!(
            (requests[2].method.as_str(), requests[2].url.as_str()),
            ("GET", "https://issuer.example/jwks.json")
        );

        let replay = request_json_body(
            state,
            Method::POST,
            "/auth/v1/providers/idp_oidc/callback",
            [],
            json!({
                "state": "state_secret",
                "code": "oidc_authorization_code",
                "nonce": "nonce_secret",
                "code_verifier": "pkce_secret"
            }),
        )
        .await;
        assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            replay.body["error"]["code"],
            "oidc_login_attempt_unavailable"
        );
    }

    #[tokio::test]
    async fn oidc_login_callback_rejects_nonce_before_token_exchange() {
        let provider = oidc_provider_with_discovery();
        let attempt = oidc_attempt("state_secret", "nonce_secret", "pkce_secret");
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(provider.clone());
        oidc_logins.record_attempt(attempt);
        let oidc_http = StaticOidcHttpClient::new();
        seed_oidc_http(
            &oidc_http,
            &provider,
            "wrong_nonce",
            "oidc_authorization_code",
        );
        let state = PlatformServiceState::default()
            .with_oidc_login_store(oidc_logins)
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let response = request_json_body(
            state,
            Method::POST,
            "/auth/v1/providers/idp_oidc/callback",
            [],
            json!({
                "state": "state_secret",
                "code": "oidc_authorization_code",
                "nonce": "wrong_nonce",
                "code_verifier": "pkce_secret"
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.body["error"]["code"], "oidc_nonce_mismatch");
        assert!(oidc_http.requests().is_empty());
    }

    #[tokio::test]
    async fn admin_oidc_provider_and_secret_ref_api_redacts_secret_material() {
        let state = project_state(USER_ID, BuiltInRole::TenantOwner, []);
        let secret = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/secret-refs",
            auth_headers(USER_TOKEN),
            json!({
                "secret_ref_id": "sec_oidc_client_secret",
                "purpose": "OIDC client secret",
                "backend_kind": "in_memory",
                "backend_locator": "memory://oidc/client",
                "secret_value": "oidc-client-secret-value"
            }),
        )
        .await;
        assert_eq!(secret.status, StatusCode::OK, "{:?}", secret.body);
        assert_eq!(
            secret.body["resource"]["secret_ref_id"],
            "sec_oidc_client_secret"
        );
        assert_eq!(secret.body["resource"]["raw_secret_included"], false);
        let secret_text = secret.body.to_string();
        assert!(!secret_text.contains("oidc-client-secret-value"));

        let provider = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/identity-providers",
            auth_headers(USER_TOKEN),
            json!({
                "identity_provider_id": "idp_admin_oidc",
                "display_name": "Admin OIDC",
                "issuer_url": "https://issuer.example",
                "client_id": "oidc_client",
                "client_secret_ref": "sec_oidc_client_secret",
                "token_endpoint_auth_method": "client_secret_basic",
                "redirect_uri": "https://app.example/auth/oidc/callback",
                "requested_scopes": ["openid", "email", "profile"],
                "accepted_audiences": ["oidc_client"]
            }),
        )
        .await;
        assert_eq!(provider.status, StatusCode::OK, "{:?}", provider.body);
        assert_eq!(provider.body["resource"]["client_secret_ref"], "sec_***");
        assert_eq!(
            provider.body["resource"]["token_endpoint_auth_method"],
            "client_secret_basic"
        );
        let provider_text = provider.body.to_string();
        assert!(!provider_text.contains("sec_oidc_client_secret"));
        assert!(!provider_text.contains("oidc-client-secret-value"));

        let get_provider = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/identity-providers/idp_admin_oidc",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(
            get_provider.status,
            StatusCode::OK,
            "{:?}",
            get_provider.body
        );
        assert_eq!(
            get_provider.body["resource"]["client_secret_ref"],
            "sec_***"
        );
        assert!(!get_provider
            .body
            .to_string()
            .contains("sec_oidc_client_secret"));

        let list_provider = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/identity-providers",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(
            list_provider.status,
            StatusCode::OK,
            "{:?}",
            list_provider.body
        );
        assert_eq!(
            list_provider.body["resources"].as_array().map(Vec::len),
            Some(1)
        );
    }

    #[tokio::test]
    async fn admin_oidc_provider_rejects_raw_client_secret() {
        let state = project_state(USER_ID, BuiltInRole::TenantOwner, []);
        let response = request_json_body(
            state,
            Method::POST,
            "/admin/v1/identity-providers",
            auth_headers(USER_TOKEN),
            json!({
                "identity_provider_id": "idp_raw_secret",
                "display_name": "Raw Secret OIDC",
                "issuer_url": "https://issuer.example",
                "client_id": "oidc_client",
                "client_secret": "do-not-accept-this",
                "redirect_uri": "https://app.example/auth/oidc/callback",
                "requested_scopes": ["openid"],
                "accepted_audiences": ["oidc_client"]
            }),
        )
        .await;
        assert_eq!(response.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            response.body["error"]["code"],
            "oidc_client_secret_raw_unsupported"
        );
    }

    #[tokio::test]
    async fn admin_oidc_secret_write_requires_tenant_admin_grant() {
        let state = project_state(USER_ID, BuiltInRole::ProjectViewer, []);
        let response = request_json_body(
            state,
            Method::POST,
            "/admin/v1/secret-refs",
            auth_headers(USER_TOKEN),
            json!({
                "secret_ref_id": "sec_denied",
                "purpose": "OIDC client secret",
                "backend_kind": "in_memory",
                "backend_locator": "memory://oidc/client",
                "secret_value": "oidc-client-secret-value"
            }),
        )
        .await;
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.body["error"]["code"], "missing_action_grant");
    }

    #[tokio::test]
    async fn admin_external_identity_list_get_are_tenant_scoped() {
        let state = project_state(USER_ID, BuiltInRole::TenantOwner, [])
            .with_external_identity_store(external_identity_store());

        let list = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_test/external-identities",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
        assert_eq!(
            list.body["schema"],
            "platform.admin.external_identity.list.v1"
        );
        assert_eq!(list.body["resources"].as_array().map(Vec::len), Some(2));
        for resource in list.body["resources"]
            .as_array()
            .unwrap_or_else(|| panic!("list should return resources"))
        {
            assert_eq!(resource["access_token_included"], false);
            assert_eq!(resource["refresh_token_included"], false);
            assert_eq!(resource["client_secret_included"], false);
        }

        let get = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_test/external-identities/xid_test",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(get.status, StatusCode::OK, "{:?}", get.body);
        assert_eq!(get.body["resource"]["external_identity_id"], "xid_test");
        assert_eq!(get.body["resource"]["provider_kind"], "oidc");
        assert_eq!(get.body["resource"]["email_verified"], true);
        assert_eq!(get.body["resource"]["access_token_included"], false);
        assert_eq!(get.body["resource"]["refresh_token_included"], false);
        assert_eq!(get.body["resource"]["client_secret_included"], false);

        let wrong_user = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_other/external-identities/xid_test",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(wrong_user.status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn admin_external_identity_unlink_requires_confirmation_and_audits() {
        let state = project_state(USER_ID, BuiltInRole::TenantOwner, [])
            .with_external_identity_store(external_identity_store());

        let unlink = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/users/usr_test/external-identities/xid_test/unlink",
            auth_headers(USER_TOKEN),
            json!({}),
        )
        .await;
        assert_eq!(unlink.status, StatusCode::FORBIDDEN);
        assert_eq!(
            unlink.body["error"]["code"],
            "strong_auth_confirmation_required"
        );

        let unlink = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/users/usr_test/external-identities/xid_test/unlink",
            auth_headers(USER_TOKEN),
            json!({
                "reason": "Operator unlink.",
                "strong_auth_confirmation": "confirm"
            }),
        )
        .await;
        assert_eq!(unlink.status, StatusCode::OK, "{:?}", unlink.body);
        assert_eq!(
            unlink.body["schema"],
            "platform.admin.external_identity_mutation.v1"
        );
        assert_eq!(unlink.body["resource"]["status"], "deleted");
        assert_eq!(unlink.body["unlinked"], true);
        assert_eq!(unlink.body["reason_recorded"], true);
        assert_eq!(unlink.body["strong_auth_confirmed"], true);
        assert_eq!(unlink.body["raw_tokens_included"], false);
        let audit_event_id = unlink.body["audit_event_id"]
            .as_str()
            .unwrap_or_else(|| panic!("audit_event_id should be a string"));
        assert!(audit_event_id.starts_with("audit_"));
        let audit_events = state.audits().audit_events_for_tenant(TENANT_ID);
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].audit_event_id, audit_event_id);
        assert_eq!(
            audit_events[0].event_type,
            "platform.external_identity.unlink"
        );
        assert_eq!(
            audit_events[0].action_id,
            "platform.external_identity.unlink"
        );
        assert_eq!(audit_events[0].resource_kind, "ExternalIdentity");
        assert_eq!(audit_events[0].resource_id, "xid_test");
        assert_eq!(audit_events[0].reason.as_deref(), Some("Operator unlink."));

        let after_unlink = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_test/external-identities",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(
            after_unlink.status,
            StatusCode::OK,
            "{:?}",
            after_unlink.body
        );
        assert_eq!(
            after_unlink.body["resources"].as_array().map(Vec::len),
            Some(1)
        );

        let single_user_unlink = request_json_body(
            state,
            Method::POST,
            "/admin/v1/users/usr_test/external-identities/xid_single_user/unlink",
            auth_headers(USER_TOKEN),
            json!({
                "strong_auth_confirmation": "confirm"
            }),
        )
        .await;
        assert_eq!(single_user_unlink.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            single_user_unlink.body["error"]["code"],
            "single_user_identity_unlink_forbidden"
        );
    }

    #[tokio::test]
    async fn admin_external_identity_requires_matching_grant() {
        let state = project_state(USER_ID, BuiltInRole::ProjectViewer, [])
            .with_external_identity_store(external_identity_store());

        let list = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_test/external-identities",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(list.status, StatusCode::FORBIDDEN);
        assert_eq!(list.body["error"]["code"], "missing_action_grant");

        let unlink = request_json_body(
            state,
            Method::POST,
            "/admin/v1/users/usr_test/external-identities/xid_test/unlink",
            auth_headers(USER_TOKEN),
            json!({}),
        )
        .await;
        assert_eq!(unlink.status, StatusCode::FORBIDDEN);
        assert_eq!(unlink.body["error"]["code"], "missing_action_grant");
    }

    #[tokio::test]
    async fn admin_organization_member_update_cascades_project_memberships() {
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_membership_store(membership_store());

        let list = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/organizations/org_test/members",
            auth_headers(USER_TOKEN),
        )
        .await;
        let get = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/organizations/org_test/members/om_test",
            auth_headers(USER_TOKEN),
        )
        .await;
        let update = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/members/om_test/status",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "status": "suspended",
                "reason": "Suspend organization member."
            }),
        )
        .await;
        let project_get = request_json(
            state,
            Method::GET,
            "/admin/v1/projects/prj_test/members/pm_test",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
        assert_eq!(get.status, StatusCode::OK, "{:?}", get.body);
        assert_eq!(update.status, StatusCode::OK, "{:?}", update.body);
        assert_eq!(list.body["resources"].as_array().map(Vec::len), Some(1));
        assert_eq!(get.body["resource"]["organization_member_id"], "om_test");
        assert_eq!(update.body["resource"]["status"], "suspended");
        assert_eq!(update.body["resource"]["resource_version"], 2);
        assert_eq!(update.body["cascaded_project_member_count"], 1);
        assert_eq!(update.body["reason_recorded"], true);
        assert_eq!(project_get.status, StatusCode::OK, "{:?}", project_get.body);
        assert_eq!(project_get.body["resource"]["status"], "suspended");
        assert_eq!(project_get.body["resource"]["resource_version"], 2);
    }

    #[tokio::test]
    async fn admin_organization_member_create_is_idempotent() {
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_membership_store(membership_store());

        let created = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "organization_member_id": "om_created",
                "principal_id": "usr_created",
                "membership_kind": "user"
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
        assert_eq!(
            created.body["schema"],
            "platform.admin.organization_member_mutation.v1"
        );
        assert_eq!(created.body["created"], true);
        assert_eq!(
            created.body["resource"]["organization_member_id"],
            "om_created"
        );
        assert_eq!(created.body["resource"]["principal_id"], "usr_created");
        assert_eq!(created.body["resource"]["status"], "active");

        let replay = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "organization_member_id": "om_created",
                "principal_id": "usr_created",
                "membership_kind": "user"
            }),
        )
        .await;
        assert_eq!(replay.status, StatusCode::OK, "{:?}", replay.body);
        assert_eq!(replay.body["created"], false);
        assert_eq!(
            replay.body["resource"]["organization_member_id"],
            "om_created"
        );

        let list = request_json(
            state,
            Method::GET,
            "/admin/v1/organizations/org_test/members",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
        assert_eq!(list.body["resources"].as_array().map(Vec::len), Some(2));
    }

    #[tokio::test]
    async fn admin_organization_member_create_reactivates_removed_member() {
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_membership_store(membership_store_with_removed_organization_member());

        let response = request_json_body(
            state,
            Method::POST,
            "/admin/v1/organizations/org_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "principal_id": "usr_removed",
                "membership_kind": "user"
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
        assert_eq!(response.body["created"], false);
        assert_eq!(
            response.body["resource"]["organization_member_id"],
            "om_removed"
        );
        assert_eq!(response.body["resource"]["status"], "active");
        assert_eq!(response.body["resource"]["resource_version"], 2);
    }

    #[tokio::test]
    async fn admin_project_member_update_rejects_stale_version() {
        let state = project_state(USER_ID, BuiltInRole::ProjectAdmin, [])
            .with_membership_store(membership_store());

        let update = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/projects/prj_test/members/pm_test/status",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 2,
                "status": "removed"
            }),
        )
        .await;

        assert_eq!(update.status, StatusCode::BAD_REQUEST);
        assert_eq!(update.body["error"]["code"], "stale_resource_version");
    }

    #[tokio::test]
    async fn admin_project_member_create_requires_active_parent_organization_member() {
        let state = project_state(USER_ID, BuiltInRole::ProjectAdmin, [])
            .with_membership_store(membership_store_with_project_candidate());

        let created = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/projects/prj_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "project_member_id": "pm_created",
                "organization_member_id": "om_candidate"
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
        assert_eq!(
            created.body["schema"],
            "platform.admin.project_member_mutation.v1"
        );
        assert_eq!(created.body["created"], true);
        assert_eq!(created.body["resource"]["project_member_id"], "pm_created");
        assert_eq!(
            created.body["resource"]["organization_member_id"],
            "om_candidate"
        );
        assert_eq!(created.body["resource"]["principal_id"], "usr_candidate");
        assert_eq!(created.body["resource"]["status"], "active");

        let replay = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/projects/prj_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "project_member_id": "pm_created",
                "organization_member_id": "om_candidate"
            }),
        )
        .await;
        assert_eq!(replay.status, StatusCode::OK, "{:?}", replay.body);
        assert_eq!(replay.body["created"], false);
        assert_eq!(replay.body["resource"]["project_member_id"], "pm_created");

        let list = request_json(
            state,
            Method::GET,
            "/admin/v1/projects/prj_test/members",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(list.status, StatusCode::OK, "{:?}", list.body);
        assert_eq!(list.body["resources"].as_array().map(Vec::len), Some(2));
    }

    #[tokio::test]
    async fn admin_project_member_create_rejects_inactive_parent_member() {
        let state = project_state(USER_ID, BuiltInRole::ProjectAdmin, [])
            .with_membership_store(membership_store_with_suspended_candidate());

        let response = request_json_body(
            state,
            Method::POST,
            "/admin/v1/projects/prj_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "project_member_id": "pm_created",
                "organization_member_id": "om_candidate"
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(
            response.body["error"]["code"],
            "organization_membership_required"
        );
    }

    #[tokio::test]
    async fn admin_membership_write_requires_matching_grant() {
        let state = project_state(USER_ID, BuiltInRole::ProjectViewer, [])
            .with_membership_store(membership_store());

        let update = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/projects/prj_test/members/pm_test/status",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "status": "removed"
            }),
        )
        .await;

        assert_eq!(update.status, StatusCode::FORBIDDEN);
        assert_eq!(update.body["error"]["code"], "missing_action_grant");

        let organization_create = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "organization_member_id": "om_denied",
                "principal_id": "usr_denied"
            }),
        )
        .await;
        assert_eq!(organization_create.status, StatusCode::FORBIDDEN);
        assert_eq!(
            organization_create.body["error"]["code"],
            "missing_action_grant"
        );

        let create = request_json_body(
            state,
            Method::POST,
            "/admin/v1/projects/prj_test/members",
            auth_headers(USER_TOKEN),
            json!({
                "project_member_id": "pm_denied",
                "organization_member_id": "om_test"
            }),
        )
        .await;
        assert_eq!(create.status, StatusCode::FORBIDDEN);
        assert_eq!(create.body["error"]["code"], "missing_action_grant");
    }

    #[tokio::test]
    async fn admin_role_binding_create_updates_dynamic_authorization() {
        let state = role_binding_admin_and_target_state(
            InMemoryPlatformRoleBindingStore::new(),
            [run_resource("run_dynamic", PROJECT_ID, "running")],
        );

        let before = request_json(
            state.clone(),
            Method::GET,
            "/v1/runs/run_dynamic",
            auth_headers(TARGET_TOKEN),
        )
        .await;
        assert_eq!(before.status, StatusCode::FORBIDDEN);
        assert_eq!(before.body["error"]["code"], "missing_action_grant");

        let created = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/role-bindings",
            auth_headers(USER_TOKEN),
            json!({
                "role_binding_id": "rb_target_project_viewer",
                "organization_id": ORGANIZATION_ID,
                "project_id": PROJECT_ID,
                "principal_id": TARGET_USER_ID,
                "role_id": "project_viewer"
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
        assert_eq!(
            created.body["schema"],
            "platform.admin.role_binding_mutation.v1"
        );
        assert_eq!(created.body["created"], true);
        assert_eq!(created.body["resource"]["scope_kind"], "project");
        assert_eq!(created.body["resource"]["status"], "active");

        let after = request_json(
            state.clone(),
            Method::GET,
            "/v1/runs/run_dynamic",
            auth_headers(TARGET_TOKEN),
        )
        .await;
        assert_eq!(after.status, StatusCode::OK, "{:?}", after.body);
        assert_eq!(
            after.body["business_resource"]["resource_id"],
            "run_dynamic"
        );

        let replay = request_json_body(
            state,
            Method::POST,
            "/admin/v1/role-bindings",
            auth_headers(USER_TOKEN),
            json!({
                "role_binding_id": "rb_replay",
                "organization_id": ORGANIZATION_ID,
                "project_id": PROJECT_ID,
                "principal_id": TARGET_USER_ID,
                "role_id": "project_viewer"
            }),
        )
        .await;
        assert_eq!(replay.status, StatusCode::OK, "{:?}", replay.body);
        assert_eq!(replay.body["created"], false);
        assert_eq!(
            replay.body["resource"]["role_binding_id"],
            "rb_target_project_viewer"
        );
    }

    #[tokio::test]
    async fn admin_role_binding_status_disable_revokes_dynamic_authorization() {
        let role_bindings = role_binding_store([role_binding_record(
            "rb_target_project_viewer",
            Some(ORGANIZATION_ID),
            Some(PROJECT_ID),
            TARGET_USER_ID,
            BuiltInRole::ProjectViewer,
        )]);
        let state = role_binding_admin_and_target_state(
            role_bindings,
            [run_resource("run_dynamic_disable", PROJECT_ID, "running")],
        );

        let before = request_json(
            state.clone(),
            Method::GET,
            "/v1/runs/run_dynamic_disable",
            auth_headers(TARGET_TOKEN),
        )
        .await;
        assert_eq!(before.status, StatusCode::OK, "{:?}", before.body);

        let disabled = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/role-bindings/rb_target_project_viewer/status",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable temporary access."
            }),
        )
        .await;
        assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
        assert_eq!(disabled.body["resource"]["status"], "disabled");
        assert_eq!(disabled.body["resource"]["resource_version"], 2);
        assert_eq!(disabled.body["reason_recorded"], true);

        let after = request_json(
            state,
            Method::GET,
            "/v1/runs/run_dynamic_disable",
            auth_headers(TARGET_TOKEN),
        )
        .await;
        assert_eq!(after.status, StatusCode::FORBIDDEN);
        assert_eq!(after.body["error"]["code"], "missing_action_grant");
    }

    #[tokio::test]
    async fn admin_user_status_disable_marks_sessions_principal_disabled() {
        let state =
            role_binding_admin_and_target_state(InMemoryPlatformRoleBindingStore::new(), []);

        let users = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(users.status, StatusCode::OK, "{:?}", users.body);
        assert_eq!(users.body["schema"], "platform.admin.user.list.v1");
        assert_eq!(
            users.body["resources"]
                .as_array()
                .unwrap_or_else(|| panic!("user list resources should be an array"))
                .len(),
            2
        );

        let target = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_target",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(target.status, StatusCode::OK, "{:?}", target.body);
        assert_eq!(target.body["resource"]["status"], "active");
        assert_eq!(target.body["resource"]["resource_version"], 1);

        let disabled = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/users/usr_target/status",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable compromised user."
            }),
        )
        .await;
        assert_eq!(
            disabled.status,
            StatusCode::FORBIDDEN,
            "{:?}",
            disabled.body
        );
        assert_eq!(
            disabled.body["error"]["code"],
            "strong_auth_confirmation_required"
        );

        let disabled = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/users/usr_target/status",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "status": "disabled",
                "reason": "Disable compromised user.",
                "strong_auth_confirmation": "confirm"
            }),
        )
        .await;
        assert_eq!(disabled.status, StatusCode::OK, "{:?}", disabled.body);
        assert_eq!(disabled.body["resource"]["status"], "disabled");
        assert_eq!(disabled.body["resource"]["resource_version"], 2);
        assert_eq!(disabled.body["previous_status"], "active");
        assert_eq!(disabled.body["disabled_session_count"], 1);
        assert_eq!(disabled.body["reason_recorded"], true);
        assert_eq!(disabled.body["strong_auth_confirmed"], true);
        let audit_event_id = disabled.body["audit_event_id"]
            .as_str()
            .unwrap_or_else(|| panic!("audit_event_id should be a string"));
        assert!(audit_event_id.starts_with("audit_"));
        let audit_events = state.audits().audit_events_for_tenant(TENANT_ID);
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].audit_event_id, audit_event_id);
        assert_eq!(audit_events[0].event_type, "platform.user.status.update");
        assert_eq!(audit_events[0].action_id, "platform.user.write");
        assert_eq!(audit_events[0].resource_kind, "User");
        assert_eq!(audit_events[0].resource_id, TARGET_USER_ID);
        assert_eq!(
            audit_events[0].reason.as_deref(),
            Some("Disable compromised user.")
        );
        assert!(!format!("{audit_events:?}").contains(TARGET_TOKEN));

        let target_session = request_json(
            state,
            Method::GET,
            "/auth/v1/session",
            auth_headers(TARGET_TOKEN),
        )
        .await;
        assert_eq!(target_session.status, StatusCode::UNAUTHORIZED);
        assert_eq!(target_session.body["error"]["code"], "principal_disabled");
    }

    #[tokio::test]
    async fn admin_user_session_list_and_revoke_are_redacted() {
        let state =
            role_binding_admin_and_target_state(InMemoryPlatformRoleBindingStore::new(), []);

        let sessions = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/users/usr_target/sessions",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(sessions.status, StatusCode::OK, "{:?}", sessions.body);
        assert_eq!(
            sessions.body["schema"],
            "platform.admin.user_auth_session.list.v1"
        );
        assert_eq!(
            sessions.body["resources"]
                .as_array()
                .unwrap_or_else(|| panic!("session list resources should be an array"))
                .len(),
            1
        );
        assert_eq!(sessions.body["resources"][0]["session_id"], "sess_target");
        assert_eq!(sessions.body["resources"][0]["status"], "active");
        assert_eq!(
            sessions.body["resources"][0]["session_token_hash_included"],
            false
        );
        assert_eq!(
            sessions.body["resources"][0]["raw_session_token_included"],
            false
        );
        assert!(sessions.body["resources"][0].get("access_token").is_none());

        let revoked = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/users/usr_target/sessions/sess_target/revoke",
            auth_headers(USER_TOKEN),
            json!({
                "reason": "Operator revoke."
            }),
        )
        .await;
        assert_eq!(revoked.status, StatusCode::FORBIDDEN, "{:?}", revoked.body);
        assert_eq!(
            revoked.body["error"]["code"],
            "strong_auth_confirmation_required"
        );

        let revoked = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/users/usr_target/sessions/sess_target/revoke",
            auth_headers(USER_TOKEN),
            json!({
                "reason": "Operator revoke.",
                "strong_auth_confirmation": "confirm"
            }),
        )
        .await;
        assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
        assert_eq!(
            revoked.body["schema"],
            "platform.admin.user_auth_session_mutation.v1"
        );
        assert_eq!(revoked.body["resource"]["status"], "revoked");
        assert_eq!(revoked.body["previous_status"], "active");
        assert_eq!(revoked.body["reason_recorded"], true);
        assert_eq!(revoked.body["strong_auth_confirmed"], true);
        let audit_event_id = revoked.body["audit_event_id"]
            .as_str()
            .unwrap_or_else(|| panic!("audit_event_id should be a string"));
        assert!(audit_event_id.starts_with("audit_"));
        let audit_events = state.audits().audit_events_for_tenant(TENANT_ID);
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].audit_event_id, audit_event_id);
        assert_eq!(audit_events[0].event_type, "platform.auth_session.revoke");
        assert_eq!(audit_events[0].action_id, "platform.auth_session.revoke");
        assert_eq!(audit_events[0].resource_kind, "AuthSession");
        assert_eq!(audit_events[0].resource_id, "sess_target");
        assert_eq!(audit_events[0].reason.as_deref(), Some("Operator revoke."));
        assert!(!format!("{audit_events:?}").contains(TARGET_TOKEN));

        let target_session = request_json(
            state,
            Method::GET,
            "/auth/v1/session",
            auth_headers(TARGET_TOKEN),
        )
        .await;
        assert_eq!(target_session.status, StatusCode::UNAUTHORIZED);
        assert_eq!(target_session.body["error"]["code"], "auth_session_revoked");
    }

    #[tokio::test]
    async fn admin_audit_event_list_requires_confirmation_and_filters() {
        let state = audit_event_list_state();

        let missing_confirmation = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/audit-events",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(missing_confirmation.status, StatusCode::FORBIDDEN);
        assert_eq!(
            missing_confirmation.body["error"]["code"],
            "strong_auth_confirmation_required"
        );

        let first_page = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/audit-events?strong_auth_confirmation=confirm&limit=1",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(first_page.status, StatusCode::OK, "{:?}", first_page.body);
        assert_eq!(
            first_page.body["schema"],
            "platform.admin.audit_event.list.v1"
        );
        assert_eq!(first_page.body["strong_auth_confirmed"], true);
        assert_eq!(first_page.body["total_filtered_count"], 3);
        assert_eq!(first_page.body["next_cursor"], "1");
        assert_eq!(
            first_page.body["resources"][0]["audit_event_id"],
            "audit_new_session"
        );
        assert_eq!(
            first_page.body["resources"][0]["event_type"],
            "platform.auth_session.revoke"
        );
        assert_eq!(first_page.body["resources"][0]["actor_kind"], "user");
        assert!(first_page.body["resources"][0].get("token_hash").is_none());
        assert!(first_page.body["resources"][0]
            .get("raw_session_token")
            .is_none());

        let second_page = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/audit-events?strong_auth_confirmation=confirm&limit=1&cursor=1",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(second_page.status, StatusCode::OK, "{:?}", second_page.body);
        assert_eq!(
            second_page.body["resources"][0]["audit_event_id"],
            "audit_middle_external_identity"
        );
        assert_eq!(second_page.body["next_cursor"], "2");

        let body_text = serde_json::to_string(&first_page.body)
            .unwrap_or_else(|error| panic!("audit list body should serialize: {error}"));
        assert!(!body_text.contains(TARGET_TOKEN));
    }

    #[tokio::test]
    async fn admin_audit_event_list_filters_and_validates_cursor() {
        let state = audit_event_list_state();

        let filtered = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/audit-events?strong_auth_confirmation=confirm&event_type=platform.user.status.update&resource_kind=User",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(filtered.status, StatusCode::OK, "{:?}", filtered.body);
        assert_eq!(filtered.body["total_filtered_count"], 1);
        assert_eq!(filtered.body["resources"][0]["resource_id"], TARGET_USER_ID);

        let invalid_cursor = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/audit-events?strong_auth_confirmation=confirm&cursor=abc",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(invalid_cursor.status, StatusCode::BAD_REQUEST);
        assert_eq!(
            invalid_cursor.body["error"]["code"],
            "audit_event_cursor_invalid"
        );
    }

    #[tokio::test]
    async fn admin_organization_member_remove_cascades_role_bindings() {
        let role_bindings = role_binding_store([
            role_binding_record(
                "rb_target_org_admin",
                Some(ORGANIZATION_ID),
                None,
                TARGET_USER_ID,
                BuiltInRole::OrganizationAdmin,
            ),
            role_binding_record(
                "rb_target_project_viewer",
                Some(ORGANIZATION_ID),
                Some(PROJECT_ID),
                TARGET_USER_ID,
                BuiltInRole::ProjectViewer,
            ),
        ]);
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_membership_store(membership_store_for_principal(
                "om_target",
                "pm_target",
                TARGET_USER_ID,
            ))
            .with_role_binding_store(role_bindings);

        let removed = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/members/om_target/remove",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "reason": "Remove departed user."
            }),
        )
        .await;
        assert_eq!(removed.status, StatusCode::OK, "{:?}", removed.body);
        assert_eq!(removed.body["resource"]["status"], "removed");
        assert_eq!(removed.body["removed"], true);
        assert_eq!(removed.body["cascaded_project_member_count"], 1);
        assert_eq!(removed.body["cascaded_role_binding_count"], 2);
        assert_eq!(removed.body["reason_recorded"], true);

        let project_member = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/projects/prj_test/members/pm_target",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(
            project_member.status,
            StatusCode::OK,
            "{:?}",
            project_member.body
        );
        assert_eq!(project_member.body["resource"]["status"], "removed");
        assert!(state
            .role_bindings()
            .active_role_bindings_for_principal(TENANT_ID, TARGET_USER_ID)
            .is_empty());
    }

    #[tokio::test]
    async fn organization_invitation_create_preview_accept_are_redacted() {
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, []);

        let created = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/invitations",
            auth_headers(USER_TOKEN),
            json!({
                "invitation_id": "inv_test",
                "project_id": PROJECT_ID,
                "invited_principal_id": USER_ID,
                "role_id": "project_developer",
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::OK, "{:?}", created.body);
        assert_eq!(
            created.body["schema"],
            "platform.admin.organization_invitation_mutation.v1"
        );
        let raw_token = created.body["invitation_token"]
            .as_str()
            .unwrap_or_else(|| panic!("create should return raw token once"))
            .to_owned();
        assert!(raw_token.starts_with("swp_inv_"));
        assert_eq!(
            created.body["resource"]["invitation_token_hash_included"],
            false
        );
        assert!(!created.body["resource"].to_string().contains(&raw_token));

        let replay_list = request_json(
            state.clone(),
            Method::GET,
            "/admin/v1/organizations/org_test/invitations",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(replay_list.status, StatusCode::OK, "{:?}", replay_list.body);
        assert_eq!(
            replay_list.body["resources"].as_array().map(Vec::len),
            Some(1)
        );
        assert!(!replay_list.body.to_string().contains(&raw_token));
        assert!(!replay_list
            .body
            .to_string()
            .contains(&hash_platform_invitation_token(&raw_token)));

        let preview = request_json(
            state.clone(),
            Method::GET,
            &format!("/auth/v1/invitations/{raw_token}/preview"),
            [],
        )
        .await;
        assert_eq!(preview.status, StatusCode::OK, "{:?}", preview.body);
        assert_eq!(
            preview.body["schema"],
            "platform.auth.invitation_preview.v1"
        );
        assert_eq!(preview.body["resource"]["status"], "pending");
        assert!(!preview.body.to_string().contains(&raw_token));

        let session = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/session",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(session.status, StatusCode::OK, "{:?}", session.body);
        let csrf = csrf_token_from_body(&session.body);

        let accepted = request_json_body(
            state.clone(),
            Method::POST,
            &format!("/auth/v1/invitations/{raw_token}/accept"),
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({}),
        )
        .await;
        assert_eq!(accepted.status, StatusCode::OK, "{:?}", accepted.body);
        assert_eq!(
            accepted.body["schema"],
            "platform.auth.invitation_accept.v1"
        );
        assert_eq!(accepted.body["resource"]["status"], "accepted");
        assert_eq!(
            accepted.body["organization_member"]["principal_id"],
            USER_ID
        );
        assert_eq!(accepted.body["project_member"]["project_id"], PROJECT_ID);
        assert_eq!(accepted.body["invitation_token_included"], false);
        assert!(!accepted.body.to_string().contains(&raw_token));

        let replay = request_json_body(
            state,
            Method::POST,
            &format!("/auth/v1/invitations/{raw_token}/accept"),
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({}),
        )
        .await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);
        assert_eq!(replay.body["error"]["code"], "invitation_not_accepting");
    }

    #[tokio::test]
    async fn organization_invitation_accept_requires_session_csrf() {
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_invitation_store(invitation_store());

        let response = request_json_body(
            state,
            Method::POST,
            "/auth/v1/invitations/swp_inv_seed/accept",
            auth_headers(USER_TOKEN),
            json!({}),
        )
        .await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.body["error"]["code"], "csrf_token_required");
    }

    #[tokio::test]
    async fn organization_invitation_revoke_blocks_accept() {
        let invitations = invitation_store();
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_invitation_store(invitations);

        let revoked = request_json_body(
            state.clone(),
            Method::POST,
            "/admin/v1/organizations/org_test/invitations/inv_seed/revoke",
            auth_headers(USER_TOKEN),
            json!({
                "expected_version": 1,
                "reason": "No longer needed."
            }),
        )
        .await;
        assert_eq!(revoked.status, StatusCode::OK, "{:?}", revoked.body);
        assert_eq!(revoked.body["resource"]["status"], "revoked");
        assert_eq!(revoked.body["reason_recorded"], true);

        let session = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/session",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(session.status, StatusCode::OK, "{:?}", session.body);
        let csrf = csrf_token_from_body(&session.body);

        let accepted = request_json_body(
            state,
            Method::POST,
            "/auth/v1/invitations/swp_inv_seed/accept",
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({}),
        )
        .await;
        assert_eq!(accepted.status, StatusCode::BAD_REQUEST);
        assert_eq!(accepted.body["error"]["code"], "invitation_not_accepting");
    }

    #[tokio::test]
    async fn invitation_accept_requires_invited_principal() {
        let invitations = InMemoryPlatformInvitationStore::new();
        invitations
            .create_organization_invitation(PlatformOrganizationInvitationRecord {
                invited_principal_id: Some("usr_invited".to_owned()),
                ..seed_invitation()
            })
            .unwrap_or_else(|error| panic!("seed invitation should be valid: {error:?}"));
        let state = project_state(USER_ID, BuiltInRole::OrganizationAdmin, [])
            .with_invitation_store(invitations);

        let session = request_json(
            state.clone(),
            Method::GET,
            "/auth/v1/session",
            auth_headers(USER_TOKEN),
        )
        .await;
        assert_eq!(session.status, StatusCode::OK, "{:?}", session.body);
        let csrf = csrf_token_from_body(&session.body);

        let accepted = request_json_body(
            state,
            Method::POST,
            "/auth/v1/invitations/swp_inv_seed/accept",
            auth_headers_with_csrf(USER_TOKEN, &csrf),
            json!({}),
        )
        .await;
        assert_eq!(accepted.status, StatusCode::FORBIDDEN);
        assert_eq!(
            accepted.body["error"]["code"],
            "invitation_principal_mismatch"
        );
    }

    #[tokio::test]
    async fn organization_invitation_create_requires_admin_grant() {
        let state = project_state(USER_ID, BuiltInRole::ProjectViewer, []);
        let created = request_json_body(
            state,
            Method::POST,
            "/admin/v1/organizations/org_test/invitations",
            auth_headers(USER_TOKEN),
            json!({
                "invited_principal_id": USER_ID,
            }),
        )
        .await;
        assert_eq!(created.status, StatusCode::FORBIDDEN);
        assert_eq!(created.body["error"]["code"], "missing_action_grant");
    }

    #[tokio::test]
    async fn oidc_login_callback_uses_confidential_client_secret_basic() {
        let provider = OidcLoginProviderRecord {
            client_secret_ref: Some("sec_oidc_client_secret".to_owned()),
            token_endpoint_auth_method: OidcTokenEndpointAuthMethod::ClientSecretBasic,
            ..oidc_provider_with_discovery()
        };
        let attempt = oidc_attempt("state_secret", "nonce_secret", "pkce_secret");
        let oidc_logins = InMemoryOidcLoginStore::new();
        oidc_logins.record_provider(provider.clone());
        oidc_logins.record_attempt(attempt);

        let secrets = InMemoryPlatformSecretStore::new();
        secrets
            .create_secret_ref(&CreatePlatformSecretRefRequest {
                secret_ref_id: "sec_oidc_client_secret".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: None,
                project_id: None,
                purpose: "OIDC client secret".to_owned(),
                backend_kind: IN_MEMORY_SECRET_BACKEND.to_owned(),
                backend_locator: "memory://oidc/client".to_owned(),
                in_memory_secret_value: Some("oidc-client-secret-value".to_owned()),
                created_by: USER_ID.to_owned(),
            })
            .unwrap_or_else(|error| panic!("OIDC client secret should be valid: {error}"));

        let oidc_http = StaticOidcHttpClient::new();
        seed_oidc_http(
            &oidc_http,
            &provider,
            "nonce_secret",
            "oidc_authorization_code",
        );
        let state = PlatformServiceState::default()
            .with_oidc_login_store(oidc_logins)
            .with_secret_store(secrets)
            .with_oidc_http_client(PlatformOidcHttpClient::Static(oidc_http.clone()));

        let response = request_json_body(
            state,
            Method::POST,
            "/auth/v1/providers/idp_oidc/callback",
            [],
            json!({
                "state": "state_secret",
                "code": "oidc_authorization_code",
                "nonce": "nonce_secret",
                "code_verifier": "pkce_secret"
            }),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK, "{:?}", response.body);
        let response_text = response.body.to_string();
        assert!(!response_text.contains("oidc-client-secret-value"));
        assert!(!response_text.contains("sec_oidc_client_secret"));

        let requests = oidc_http.requests();
        let token_request = requests
            .iter()
            .find(|request| {
                request.method == "POST" && request.url == "https://issuer.example/token"
            })
            .unwrap_or_else(|| panic!("token request should be captured"));
        assert_eq!(
            token_request.authorization.as_deref(),
            Some("Basic <redacted>")
        );
        let token_body = token_request
            .body
            .as_deref()
            .unwrap_or_else(|| panic!("token exchange should include form body"));
        assert!(token_body.contains("grant_type=authorization_code"));
        assert!(token_body.contains("code_verifier=pkce_secret"));
        assert!(!token_body.contains("client_id=oidc_client"));
        assert!(!token_body.contains("client_secret"));
        assert!(!token_body.contains("oidc-client-secret-value"));
    }

    #[tokio::test]
    async fn run_read_authorizes_from_route_metadata_and_owner_store() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectViewer,
            [run_resource("run_allowed", PROJECT_ID, "running")],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_allowed",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body["authorized"], true);
        assert_eq!(response.body["route"]["action"], "platform.run.read");
        assert_eq!(response.body["route"]["resource_kind"], "Run");
        assert_eq!(response.body["resource"]["project_id"], PROJECT_ID);
        assert_eq!(
            response.body["business_resource"]["data"]["status"],
            "running"
        );
        assert_eq!(
            response.body["business_resource"]["data"]["model_alias"],
            "default-agent"
        );
    }

    #[tokio::test]
    async fn conversation_read_returns_business_resource_after_authorization() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectViewer,
            [conversation_resource("conv_test", PROJECT_ID)],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/conversations/conv_test",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.body["route"]["action"],
            "platform.conversation.read"
        );
        assert_eq!(
            response.body["business_resource"]["data"]["title"],
            "Agent conversation"
        );
    }

    #[tokio::test]
    async fn run_cancel_uses_colon_route_and_returns_business_resource() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectDeveloper,
            [run_resource("run_cancel", PROJECT_ID, "running")],
        );
        let response = request_json(
            state,
            Method::POST,
            "/v1/runs/run_cancel:cancel",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body["route"]["action"], "platform.run.cancel");
        assert_eq!(
            response.body["business_resource"]["resource_id"],
            "run_cancel"
        );
    }

    #[tokio::test]
    async fn api_key_credential_authorizes_business_resource() {
        let state = project_state_with_api_key(
            USER_ID,
            BuiltInRole::ProjectViewer,
            [run_resource("run_apikey", PROJECT_ID, "running")],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_apikey",
            auth_headers(API_KEY_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body["actor"]["actor_kind"], "user");
        assert_eq!(
            response.body["business_resource"]["resource_id"],
            "run_apikey"
        );
    }

    #[tokio::test]
    async fn cross_project_run_read_is_denied_from_resolved_owner() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectViewer,
            [run_resource("run_other", OTHER_PROJECT_ID, "running")],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_other",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.body["error"]["code"], "missing_action_grant");
    }

    #[tokio::test]
    async fn approval_decide_requires_human_user_actor() {
        let state = project_state_with_actor(
            ActorKind::ServiceAccount,
            SERVICE_ACCOUNT_ID,
            SERVICE_ACCOUNT_TOKEN,
            BuiltInRole::TenantOwner,
            [approval_resource("appr_test", PROJECT_ID, "pending")],
        );
        let response = request_json(
            state,
            Method::POST,
            "/v1/approvals/appr_test:decide",
            auth_headers(SERVICE_ACCOUNT_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.body["error"]["code"], "user_actor_required");
    }

    #[tokio::test]
    async fn service_token_credential_cannot_use_user_only_action() {
        let state = project_state_with_service_token(
            SERVICE_ACCOUNT_ID,
            BuiltInRole::TenantOwner,
            [approval_resource(
                "appr_service_token",
                PROJECT_ID,
                "pending",
            )],
        );
        let response = request_json(
            state,
            Method::POST,
            "/v1/approvals/appr_service_token:decide",
            auth_headers(SERVICE_ACCOUNT_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert_eq!(response.body["error"]["code"], "user_actor_required");
    }

    #[tokio::test]
    async fn mtls_identity_header_authorizes_business_resource() {
        let state = project_state_with_mtls_identity(
            SERVICE_ACCOUNT_ID,
            BuiltInRole::ProjectViewer,
            [run_resource("run_mtls", PROJECT_ID, "running")],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_mtls",
            mtls_headers(MTLS_SUBJECT),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body["actor"]["actor_kind"], "service_account");
        assert_eq!(
            response.body["business_resource"]["resource_id"],
            "run_mtls"
        );
    }

    #[tokio::test]
    async fn unknown_mtls_identity_header_is_rejected() {
        let state = project_state_with_mtls_identity(
            SERVICE_ACCOUNT_ID,
            BuiltInRole::ProjectViewer,
            [run_resource("run_mtls_missing", PROJECT_ID, "running")],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_mtls_missing",
            mtls_headers("spiffe://platform.test/unknown"),
        )
        .await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.body["error"]["code"], "mtls_identity_not_found");
    }

    #[tokio::test]
    async fn approval_decide_returns_business_resource_for_user_actor() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectDeveloper,
            [approval_resource("appr_test", PROJECT_ID, "pending")],
        );
        let response = request_json(
            state,
            Method::POST,
            "/v1/approvals/appr_test:decide",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body["route"]["action"], "platform.approval.decide");
        assert_eq!(
            response.body["business_resource"]["data"]["requested_action"],
            "tool.execute"
        );
    }

    #[tokio::test]
    async fn environment_attachment_health_uses_attachment_owner() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectViewer,
            [environment_attachment_resource("lease_test", PROJECT_ID)],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/environment-attachments/lease_test/health",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.body["route"]["action"],
            "platform.environment_attachment.health.read"
        );
        assert_eq!(response.body["resource"]["resource_id"], "lease_test");
        assert_eq!(
            response.body["business_resource"]["data"]["readiness"],
            "ready"
        );
    }

    #[tokio::test]
    async fn evidence_archive_read_allows_project_auditor() {
        let state = project_state(
            USER_ID,
            BuiltInRole::Auditor,
            [evidence_archive_resource("evid_test", PROJECT_ID)],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/evidence-archives/evid_test",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response.body["route"]["action"],
            PlatformAction::EvidenceArchiveRead.as_str()
        );
        assert_eq!(
            response.body["business_resource"]["data"]["retention_class"],
            "standard"
        );
    }

    #[tokio::test]
    async fn missing_owner_returns_not_found_before_authorization() {
        let state = project_state(USER_ID, BuiltInRole::ProjectViewer, []);
        let response = request_json(
            state,
            Method::GET,
            "/v1/conversations/conv_missing",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.body["error"]["code"], "resource_not_found");
    }

    #[tokio::test]
    async fn missing_business_resource_returns_not_found_after_authorization() {
        let state = project_state_with_owners_and_resources(
            ActorKind::User,
            USER_ID,
            USER_TOKEN,
            BuiltInRole::ProjectViewer,
            [owner("Run", "run_owner_only", PROJECT_ID)],
            [],
        );
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_owner_only",
            auth_headers(USER_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::NOT_FOUND);
        assert_eq!(response.body["error"]["code"], "resource_not_found");
    }

    #[tokio::test]
    async fn missing_bearer_session_returns_unauthorized() {
        let state = project_state(
            USER_ID,
            BuiltInRole::ProjectViewer,
            [run_resource("run_allowed", PROJECT_ID, "running")],
        );
        let response = request_json(state, Method::GET, "/v1/runs/run_allowed", []).await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.body["error"]["code"], "authentication_required");
    }

    #[tokio::test]
    async fn revoked_session_does_not_fallback_to_active_credential_with_same_token() {
        let state = project_state_with_revoked_session_and_matching_api_key([run_resource(
            "run_shadowed",
            PROJECT_ID,
            "running",
        )]);
        let response = request_json(
            state,
            Method::GET,
            "/v1/runs/run_shadowed",
            auth_headers(API_KEY_TOKEN),
        )
        .await;

        assert_eq!(response.status, StatusCode::UNAUTHORIZED);
        assert_eq!(response.body["error"]["code"], "auth_session_revoked");
    }

    #[test]
    fn route_matcher_extracts_colon_action_resource_ids() {
        let matched = match_route(&Method::POST, "/v1/runs/run_test:cancel")
            .unwrap_or_else(|| panic!("run cancel route should match"));
        assert_eq!(matched.route.action, PlatformAction::RunCancel);
        assert_eq!(
            matched.params.get("run_id").map(String::as_str),
            Some("run_test")
        );
    }

    fn project_state<const N: usize>(
        principal_id: &str,
        role: BuiltInRole,
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        project_state_with_owners_and_resources(
            ActorKind::User,
            principal_id,
            USER_TOKEN,
            role,
            [],
            resources,
        )
    }

    fn project_state_with_actor<const N: usize>(
        actor_kind: ActorKind,
        principal_id: &str,
        raw_token: &str,
        role: BuiltInRole,
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        project_state_with_owners_and_resources(
            actor_kind,
            principal_id,
            raw_token,
            role,
            [],
            resources,
        )
    }

    fn project_state_with_api_key<const N: usize>(
        principal_id: &str,
        role: BuiltInRole,
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        project_state_with_credential(
            ActorKind::User,
            principal_id,
            API_KEY_TOKEN,
            role,
            resources,
            PlatformBearerCredentialKind::ApiKey,
        )
    }

    fn project_state_with_service_token<const N: usize>(
        principal_id: &str,
        role: BuiltInRole,
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        project_state_with_credential(
            ActorKind::ServiceAccount,
            principal_id,
            SERVICE_ACCOUNT_TOKEN,
            role,
            resources,
            PlatformBearerCredentialKind::ServiceToken,
        )
    }

    fn project_state_with_mtls_identity<const N: usize>(
        principal_id: &str,
        role: BuiltInRole,
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        let owner_store = InMemoryResourceOwnerStore::new();
        let resource_store = InMemoryPlatformResourceStore::new();
        for resource in resources {
            assert_eq!(
                owner_store.record_resource_owner(resource.owner.clone()),
                Ok(())
            );
            assert_eq!(resource_store.record_platform_resource(resource), Ok(()));
        }
        let mtls_identities = InMemoryPlatformMtlsIdentityStore::new();
        assert_eq!(
            mtls_identities.record_mtls_identity(PlatformMtlsIdentityRecord::active(
                "mtls_test",
                MTLS_SUBJECT,
                authenticated_actor(ActorKind::ServiceAccount, principal_id),
            )),
            Ok(())
        );
        let grants =
            ActionGrant::for_builtin_role(TENANT_ID, role_scope_id(role), principal_id, role);
        PlatformServiceState::with_resources_and_mtls(
            owner_store,
            InMemoryPlatformAuthSessionStore::new(),
            InMemoryPlatformBearerCredentialStore::new(),
            mtls_identities,
            resource_store,
            FoundationAuthorizationEngine::new(grants),
        )
    }

    fn project_state_with_credential<const N: usize>(
        actor_kind: ActorKind,
        principal_id: &str,
        raw_token: &str,
        role: BuiltInRole,
        resources: [PlatformResourceRecord; N],
        credential_kind: PlatformBearerCredentialKind,
    ) -> PlatformServiceState {
        let owner_store = InMemoryResourceOwnerStore::new();
        let resource_store = InMemoryPlatformResourceStore::new();
        for resource in resources {
            assert_eq!(
                owner_store.record_resource_owner(resource.owner.clone()),
                Ok(())
            );
            assert_eq!(resource_store.record_platform_resource(resource), Ok(()));
        }
        let credentials = InMemoryPlatformBearerCredentialStore::new();
        assert_eq!(
            credentials.record_bearer_credential(PlatformBearerCredentialRecord::active(
                "cred_test",
                credential_kind,
                raw_token,
                authenticated_actor(actor_kind, principal_id),
            )),
            Ok(())
        );
        let grants =
            ActionGrant::for_builtin_role(TENANT_ID, role_scope_id(role), principal_id, role);
        PlatformServiceState::with_resources(
            owner_store,
            InMemoryPlatformAuthSessionStore::new(),
            credentials,
            resource_store,
            FoundationAuthorizationEngine::new(grants),
        )
    }

    fn project_state_with_revoked_session_and_matching_api_key<const N: usize>(
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        let owner_store = InMemoryResourceOwnerStore::new();
        let resource_store = InMemoryPlatformResourceStore::new();
        for resource in resources {
            assert_eq!(
                owner_store.record_resource_owner(resource.owner.clone()),
                Ok(())
            );
            assert_eq!(resource_store.record_platform_resource(resource), Ok(()));
        }
        let auth_sessions = InMemoryPlatformAuthSessionStore::new();
        assert_eq!(
            auth_sessions.record_auth_session(
                PlatformAuthSessionRecord::active(
                    "sess_revoked",
                    API_KEY_TOKEN,
                    authenticated_actor(ActorKind::User, USER_ID),
                )
                .with_status(PlatformAuthSessionStatus::Revoked),
            ),
            Ok(())
        );
        let credentials = InMemoryPlatformBearerCredentialStore::new();
        assert_eq!(
            credentials.record_bearer_credential(
                PlatformBearerCredentialRecord::active_api_key(
                    "apikey_shadowed",
                    API_KEY_TOKEN,
                    authenticated_actor(ActorKind::User, USER_ID),
                )
                .with_status(PlatformBearerCredentialStatus::Active),
            ),
            Ok(())
        );
        let grants = ActionGrant::for_builtin_role(
            TENANT_ID,
            PROJECT_ID,
            USER_ID,
            BuiltInRole::ProjectViewer,
        );
        PlatformServiceState::with_resources(
            owner_store,
            auth_sessions,
            credentials,
            resource_store,
            FoundationAuthorizationEngine::new(grants),
        )
    }

    fn project_state_with_owners_and_resources<const O: usize, const R: usize>(
        actor_kind: ActorKind,
        principal_id: &str,
        raw_token: &str,
        role: BuiltInRole,
        owners: [ResourceOwnerRecord; O],
        resources: [PlatformResourceRecord; R],
    ) -> PlatformServiceState {
        let owner_store = InMemoryResourceOwnerStore::new();
        let resource_store = InMemoryPlatformResourceStore::new();
        for owner in owners {
            assert_eq!(owner_store.record_resource_owner(owner), Ok(()));
        }
        for resource in resources {
            assert_eq!(
                owner_store.record_resource_owner(resource.owner.clone()),
                Ok(())
            );
            assert_eq!(resource_store.record_platform_resource(resource), Ok(()));
        }
        let auth_sessions = InMemoryPlatformAuthSessionStore::new();
        assert_eq!(
            auth_sessions.record_auth_session(PlatformAuthSessionRecord::active(
                "sess_test",
                raw_token,
                AuthenticatedActor {
                    tenant_id: TENANT_ID.to_owned(),
                    organization_id: Some(ORGANIZATION_ID.to_owned()),
                    project_id: Some(PROJECT_ID.to_owned()),
                    principal_id: principal_id.to_owned(),
                    actor_kind,
                },
            )),
            Ok(())
        );
        let grants =
            ActionGrant::for_builtin_role(TENANT_ID, role_scope_id(role), principal_id, role);
        PlatformServiceState::with_resources(
            owner_store,
            auth_sessions,
            InMemoryPlatformBearerCredentialStore::new(),
            resource_store,
            FoundationAuthorizationEngine::new(grants),
        )
    }

    fn owner(kind: &str, id: &str, project_id: &str) -> ResourceOwnerRecord {
        ResourceOwnerRecord::project(kind, id, TENANT_ID, ORGANIZATION_ID, project_id)
    }

    fn conversation_resource(resource_id: &str, project_id: &str) -> PlatformResourceRecord {
        platform_resource(
            owner("Conversation", resource_id, project_id),
            PlatformResourceData::Conversation(ConversationRecord {
                title: "Agent conversation".to_owned(),
                status: "active".to_owned(),
            }),
        )
    }

    fn run_resource(resource_id: &str, project_id: &str, status: &str) -> PlatformResourceRecord {
        platform_resource(
            owner("Run", resource_id, project_id),
            PlatformResourceData::Run(RunRecord {
                conversation_id: "conv_test".to_owned(),
                status: status.to_owned(),
                model_alias: "default-agent".to_owned(),
            }),
        )
    }

    fn approval_resource(
        resource_id: &str,
        project_id: &str,
        status: &str,
    ) -> PlatformResourceRecord {
        platform_resource(
            owner("Approval", resource_id, project_id),
            PlatformResourceData::Approval(ApprovalRecord {
                run_id: "run_allowed".to_owned(),
                status: status.to_owned(),
                requested_action: "tool.execute".to_owned(),
            }),
        )
    }

    fn environment_attachment_resource(
        resource_id: &str,
        project_id: &str,
    ) -> PlatformResourceRecord {
        platform_resource(
            owner("EnvironmentAttachment", resource_id, project_id),
            PlatformResourceData::EnvironmentAttachment(EnvironmentAttachmentRecord {
                lease_id: resource_id.to_owned(),
                status: "active".to_owned(),
                readiness: "ready".to_owned(),
            }),
        )
    }

    fn evidence_archive_resource(resource_id: &str, project_id: &str) -> PlatformResourceRecord {
        platform_resource(
            owner("EvidenceArchive", resource_id, project_id),
            PlatformResourceData::EvidenceArchive(EvidenceArchiveRecord {
                manifest_uri: format!("object://evidence/{resource_id}.json"),
                retention_class: "standard".to_owned(),
                debug_available: true,
            }),
        )
    }

    fn platform_resource(
        owner: ResourceOwnerRecord,
        data: PlatformResourceData,
    ) -> PlatformResourceRecord {
        PlatformResourceRecord::new(owner, data)
            .unwrap_or_else(|error| panic!("platform resource should be valid: {error:?}"))
    }

    fn auth_headers(raw_token: &str) -> [(&'static str, String); 1] {
        [(AUTHORIZATION.as_str(), format!("Bearer {raw_token}"))]
    }

    fn auth_headers_with_csrf(raw_token: &str, csrf_token: &str) -> [(&'static str, String); 2] {
        [
            (AUTHORIZATION.as_str(), format!("Bearer {raw_token}")),
            (PLATFORM_CSRF_TOKEN_HEADER, csrf_token.to_owned()),
        ]
    }

    fn mtls_headers(subject: &str) -> [(&'static str, String); 1] {
        [(VERIFIED_MTLS_SUBJECT_HEADER, subject.to_owned())]
    }

    fn csrf_token_from_body(body: &Value) -> String {
        body["csrf"]["token"]
            .as_str()
            .unwrap_or_else(|| panic!("response should include csrf token"))
            .to_owned()
    }

    const fn role_scope_id(role: BuiltInRole) -> &'static str {
        match role.scope_kind() {
            RoleScopeKind::Tenant => TENANT_ID,
            RoleScopeKind::Organization => ORGANIZATION_ID,
            RoleScopeKind::Project | RoleScopeKind::Any => PROJECT_ID,
        }
    }

    fn authenticated_actor(actor_kind: ActorKind, principal_id: &str) -> AuthenticatedActor {
        AuthenticatedActor {
            tenant_id: TENANT_ID.to_owned(),
            organization_id: Some(ORGANIZATION_ID.to_owned()),
            project_id: Some(PROJECT_ID.to_owned()),
            principal_id: principal_id.to_owned(),
            actor_kind,
        }
    }

    fn membership_store() -> InMemoryPlatformMembershipStore {
        let store = InMemoryPlatformMembershipStore::new();
        store
            .record_organization_member(PlatformOrganizationMembershipRecord {
                organization_member_id: "om_test".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                principal_id: USER_ID.to_owned(),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            })
            .unwrap_or_else(|error| panic!("organization membership should be valid: {error:?}"));
        store
            .record_project_member(PlatformProjectMembershipRecord {
                project_member_id: "pm_test".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                project_id: PROJECT_ID.to_owned(),
                principal_id: USER_ID.to_owned(),
                organization_member_id: Some("om_test".to_owned()),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            })
            .unwrap_or_else(|error| panic!("project membership should be valid: {error:?}"));
        store
    }

    fn membership_store_for_principal(
        organization_member_id: &str,
        project_member_id: &str,
        principal_id: &str,
    ) -> InMemoryPlatformMembershipStore {
        let store = InMemoryPlatformMembershipStore::new();
        store
            .record_organization_member(PlatformOrganizationMembershipRecord {
                organization_member_id: organization_member_id.to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                principal_id: principal_id.to_owned(),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            })
            .unwrap_or_else(|error| panic!("organization membership should be valid: {error:?}"));
        store
            .record_project_member(PlatformProjectMembershipRecord {
                project_member_id: project_member_id.to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                project_id: PROJECT_ID.to_owned(),
                principal_id: principal_id.to_owned(),
                organization_member_id: Some(organization_member_id.to_owned()),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            })
            .unwrap_or_else(|error| panic!("project membership should be valid: {error:?}"));
        store
    }

    fn role_binding_admin_and_target_state<const N: usize>(
        role_bindings: InMemoryPlatformRoleBindingStore,
        resources: [PlatformResourceRecord; N],
    ) -> PlatformServiceState {
        let owner_store = InMemoryResourceOwnerStore::new();
        let resource_store = InMemoryPlatformResourceStore::new();
        for resource in resources {
            assert_eq!(
                owner_store.record_resource_owner(resource.owner.clone()),
                Ok(())
            );
            assert_eq!(resource_store.record_platform_resource(resource), Ok(()));
        }
        let auth_sessions = InMemoryPlatformAuthSessionStore::new();
        assert_eq!(
            auth_sessions.record_auth_session(PlatformAuthSessionRecord::active(
                "sess_admin",
                USER_TOKEN,
                authenticated_actor(ActorKind::User, USER_ID),
            )),
            Ok(())
        );
        assert_eq!(
            auth_sessions.record_auth_session(PlatformAuthSessionRecord::active(
                "sess_target",
                TARGET_TOKEN,
                authenticated_actor(ActorKind::User, TARGET_USER_ID),
            )),
            Ok(())
        );
        let grants =
            ActionGrant::for_builtin_role(TENANT_ID, TENANT_ID, USER_ID, BuiltInRole::TenantOwner);
        PlatformServiceState::with_resources(
            owner_store,
            auth_sessions,
            InMemoryPlatformBearerCredentialStore::new(),
            resource_store,
            FoundationAuthorizationEngine::new(grants),
        )
        .with_membership_store(membership_store_for_principal(
            "om_target",
            "pm_target",
            TARGET_USER_ID,
        ))
        .with_role_binding_store(role_bindings)
        .with_user_store(user_store([USER_ID, TARGET_USER_ID]))
    }

    fn user_store<const N: usize>(user_ids: [&str; N]) -> InMemoryPlatformUserStore {
        let store = InMemoryPlatformUserStore::new();
        for user_id in user_ids {
            store
                .record_user(PlatformUserRecord {
                    user_id: user_id.to_owned(),
                    tenant_id: TENANT_ID.to_owned(),
                    default_organization_id: Some(ORGANIZATION_ID.to_owned()),
                    default_project_id: Some(PROJECT_ID.to_owned()),
                    primary_email: Some(format!("{user_id}@example.com")),
                    display_name: user_id.to_owned(),
                    status: PlatformUserStatus::Active,
                    resource_version: 1,
                })
                .unwrap_or_else(|error| panic!("user should be valid: {error:?}"));
        }
        store
    }

    fn platform_audit_event(
        audit_event_id: &str,
        event_type: &str,
        action_id: &str,
        resource_kind: &str,
        resource_id: &str,
        created_at_unix: i64,
    ) -> PlatformAuditEventRecord {
        PlatformAuditEventRecord {
            audit_event_id: audit_event_id.to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: Some(ORGANIZATION_ID.to_owned()),
            project_id: Some(PROJECT_ID.to_owned()),
            actor_principal_id: USER_ID.to_owned(),
            actor_kind: ActorKind::User,
            action_id: action_id.to_owned(),
            resource_kind: resource_kind.to_owned(),
            resource_id: resource_id.to_owned(),
            event_type: event_type.to_owned(),
            reason: Some("Operator confirmed request.".to_owned()),
            redaction: PLATFORM_AUDIT_REDACTION_PROFILE.to_owned(),
            created_at_unix,
        }
    }

    fn audit_event_list_state() -> PlatformServiceState {
        let state =
            role_binding_admin_and_target_state(InMemoryPlatformRoleBindingStore::new(), []);
        for event in [
            platform_audit_event(
                "audit_old_user",
                "platform.user.status.update",
                "platform.user.write",
                "User",
                TARGET_USER_ID,
                100,
            ),
            platform_audit_event(
                "audit_new_session",
                "platform.auth_session.revoke",
                "platform.auth_session.revoke",
                "AuthSession",
                "sess_target",
                300,
            ),
            platform_audit_event(
                "audit_middle_external_identity",
                "platform.external_identity.unlink",
                "platform.external_identity.unlink",
                "ExternalIdentity",
                "xid_target",
                200,
            ),
        ] {
            state
                .audits()
                .record_audit_event(event)
                .unwrap_or_else(|error| panic!("audit event should record: {error:?}"));
        }
        state
    }

    fn role_binding_store<const N: usize>(
        records: [PlatformRoleBindingRecord; N],
    ) -> InMemoryPlatformRoleBindingStore {
        let store = InMemoryPlatformRoleBindingStore::new();
        for record in records {
            store
                .record_role_binding(record)
                .unwrap_or_else(|error| panic!("role binding should be valid: {error:?}"));
        }
        store
    }

    fn role_binding_record(
        role_binding_id: &str,
        organization_id: Option<&str>,
        project_id: Option<&str>,
        principal_id: &str,
        role: BuiltInRole,
    ) -> PlatformRoleBindingRecord {
        PlatformRoleBindingRecord {
            role_binding_id: role_binding_id.to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: organization_id.map(ToOwned::to_owned),
            project_id: project_id.map(ToOwned::to_owned),
            principal_id: principal_id.to_owned(),
            role_id: role.as_str().to_owned(),
            status: PlatformRoleBindingStatus::Active,
            resource_version: 1,
        }
    }

    fn membership_store_with_removed_organization_member() -> InMemoryPlatformMembershipStore {
        let store = membership_store();
        store
            .record_organization_member(PlatformOrganizationMembershipRecord {
                organization_member_id: "om_removed".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                principal_id: "usr_removed".to_owned(),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Removed,
                resource_version: 1,
            })
            .unwrap_or_else(|error| {
                panic!("removed organization member should be valid: {error:?}")
            });
        store
    }

    fn membership_store_with_project_candidate() -> InMemoryPlatformMembershipStore {
        let store = membership_store();
        store
            .record_organization_member(PlatformOrganizationMembershipRecord {
                organization_member_id: "om_candidate".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                principal_id: "usr_candidate".to_owned(),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Active,
                resource_version: 1,
            })
            .unwrap_or_else(|error| {
                panic!("candidate organization member should be valid: {error:?}")
            });
        store
    }

    fn membership_store_with_suspended_candidate() -> InMemoryPlatformMembershipStore {
        let store = membership_store();
        store
            .record_organization_member(PlatformOrganizationMembershipRecord {
                organization_member_id: "om_candidate".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                organization_id: ORGANIZATION_ID.to_owned(),
                principal_id: "usr_candidate".to_owned(),
                membership_kind: "user".to_owned(),
                status: PlatformMembershipStatus::Suspended,
                resource_version: 1,
            })
            .unwrap_or_else(|error| {
                panic!("suspended organization member should be valid: {error:?}")
            });
        store
    }

    fn external_identity_store() -> InMemoryPlatformExternalIdentityStore {
        let store = InMemoryPlatformExternalIdentityStore::new();
        store
            .record_external_identity(PlatformExternalIdentityRecord {
                external_identity_id: "xid_test".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                principal_id: USER_ID.to_owned(),
                identity_provider_id: "idp_oidc".to_owned(),
                provider_kind: "oidc".to_owned(),
                provider_subject: "oidc-subject-123".to_owned(),
                email: Some("user@example.com".to_owned()),
                email_verified: true,
                status: PlatformExternalIdentityStatus::Active,
            })
            .unwrap_or_else(|error| panic!("external identity should be valid: {error:?}"));
        store
            .record_external_identity(PlatformExternalIdentityRecord {
                external_identity_id: "xid_single_user".to_owned(),
                tenant_id: TENANT_ID.to_owned(),
                principal_id: USER_ID.to_owned(),
                identity_provider_id: "idp_single_user".to_owned(),
                provider_kind: "single_user".to_owned(),
                provider_subject: "admin".to_owned(),
                email: None,
                email_verified: false,
                status: PlatformExternalIdentityStatus::Active,
            })
            .unwrap_or_else(|error| panic!("single-user identity should be valid: {error:?}"));
        store
    }

    fn assert_oidc_external_identity_recorded(state: &PlatformServiceState, principal_id: &str) {
        let identities = state
            .external_identities()
            .external_identities_for_principal(TENANT_ID, principal_id);
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].provider_kind, "oidc");
        assert_eq!(identities[0].provider_subject, "oidc-user-456");
        assert_eq!(identities[0].email.as_deref(), Some("owner@example.com"));
        assert!(identities[0].email_verified);
    }

    fn invitation_store() -> InMemoryPlatformInvitationStore {
        let store = InMemoryPlatformInvitationStore::new();
        store
            .create_organization_invitation(seed_invitation())
            .unwrap_or_else(|error| panic!("invitation should be valid: {error:?}"));
        store
    }

    fn seed_invitation() -> PlatformOrganizationInvitationRecord {
        PlatformOrganizationInvitationRecord {
            invitation_id: "inv_seed".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            organization_id: ORGANIZATION_ID.to_owned(),
            project_id: Some(PROJECT_ID.to_owned()),
            invited_email: None,
            invited_principal_id: Some(USER_ID.to_owned()),
            invitation_token_hash: hash_platform_invitation_token("swp_inv_seed"),
            role_id: "project_developer".to_owned(),
            status: PlatformInvitationStatus::Pending,
            expires_at_unix: current_unix_timestamp() + 300,
            accepted_at_unix: None,
            created_by: USER_ID.to_owned(),
            resource_version: 1,
            created_at_unix: current_unix_timestamp(),
            updated_at_unix: current_unix_timestamp(),
        }
    }

    fn single_user_config() -> PlatformSingleUserConfig {
        PlatformSingleUserConfig::new("admin", "correct horse battery staple")
    }

    fn oidc_provider_with_discovery() -> OidcLoginProviderRecord {
        OidcLoginProviderRecord {
            identity_provider_id: "idp_oidc".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            display_name: "Example OIDC".to_owned(),
            issuer_url: "https://issuer.example".to_owned(),
            authorization_endpoint: String::new(),
            token_endpoint: String::new(),
            jwks_uri: String::new(),
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

    fn oidc_attempt(
        raw_state: &str,
        raw_nonce: &str,
        raw_pkce_verifier: &str,
    ) -> OidcLoginAttemptRecord {
        OidcLoginAttemptRecord::active(OidcLoginAttemptStart {
            login_attempt_id: "ola_oidc_test".to_owned(),
            tenant_id: TENANT_ID.to_owned(),
            identity_provider_id: "idp_oidc".to_owned(),
            raw_state: raw_state.to_owned(),
            raw_nonce: raw_nonce.to_owned(),
            raw_pkce_verifier: raw_pkce_verifier.to_owned(),
            redirect_uri: "https://app.example/auth/oidc/callback".to_owned(),
            expires_at_unix: current_unix_timestamp() + 300,
        })
        .unwrap_or_else(|error| panic!("OIDC attempt should be valid: {error}"))
    }

    fn seed_oidc_http(
        oidc_http: &StaticOidcHttpClient,
        provider: &OidcLoginProviderRecord,
        nonce: &str,
        expected_code: &str,
    ) {
        seed_oidc_discovery(oidc_http, provider);
        oidc_http.respond_json(
            "POST",
            "https://issuer.example/token",
            200,
            &json!({
                "token_type": "Bearer",
                "id_token": signed_oidc_id_token("https://issuer.example", nonce, expected_code)
            }),
        );
        oidc_http.respond_json(
            "GET",
            "https://issuer.example/jwks.json",
            200,
            &serde_json::to_value(test_jwks())
                .unwrap_or_else(|error| panic!("JWKS should serialize: {error}")),
        );
    }

    fn seed_oidc_discovery(oidc_http: &StaticOidcHttpClient, provider: &OidcLoginProviderRecord) {
        oidc_http.respond_json(
            "GET",
            &oidc_discovery_url(&provider.issuer_url),
            200,
            &json!({
                "issuer": provider.issuer_url,
                "authorization_endpoint": "https://issuer.example/authorize",
                "token_endpoint": "https://issuer.example/token",
                "jwks_uri": "https://issuer.example/jwks.json",
                "id_token_signing_alg_values_supported": ["RS256"]
            }),
        );
    }

    fn test_jwks() -> JwkSet {
        let signing_key = test_encoding_key();
        let mut jwk = Jwk::from_encoding_key(&signing_key, Algorithm::RS256)
            .unwrap_or_else(|error| panic!("test JWK should derive from RSA key: {error}"));
        jwk.common.key_id = Some("test-oidc-key".to_owned());
        jwk.common.public_key_use = Some(PublicKeyUse::Signature);
        JwkSet { keys: vec![jwk] }
    }

    fn signed_oidc_id_token(issuer: &str, nonce: &str, code: &str) -> String {
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-oidc-key".to_owned());
        encode(
            &header,
            &json!({
                "iss": issuer,
                "sub": "oidc-user-456",
                "aud": "oidc_client",
                "exp": current_unix_timestamp() + 300,
                "iat": current_unix_timestamp(),
                "nonce": nonce,
                "email": "owner@example.com",
                "email_verified": true,
                "name": format!("OIDC Owner {code}")
            }),
            &test_encoding_key(),
        )
        .unwrap_or_else(|error| panic!("test ID token should sign: {error}"))
    }

    fn test_encoding_key() -> EncodingKey {
        EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_KEY_PEM.as_bytes())
            .unwrap_or_else(|error| panic!("test RSA key should parse: {error}"))
    }

    async fn request_json<const N: usize>(
        state: PlatformServiceState,
        method: Method,
        path: &str,
        headers: [(&'static str, String); N],
    ) -> JsonResponse {
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .body(Body::empty())
            .unwrap_or_else(|error| panic!("request should build: {error}"));
        let response = router(state)
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("request should be handled: {error}"));
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|error| panic!("response body should read: {error}"));
        let body = serde_json::from_slice::<Value>(&body)
            .unwrap_or_else(|error| panic!("response body should be json: {error}"));
        JsonResponse { status, body }
    }

    async fn request_json_body<const N: usize>(
        state: PlatformServiceState,
        method: Method,
        path: &str,
        headers: [(&'static str, String); N],
        body: Value,
    ) -> JsonResponse {
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap_or_else(|error| panic!("request should build: {error}"));
        let response = router(state)
            .oneshot(request)
            .await
            .unwrap_or_else(|error| panic!("request should be handled: {error}"));
        let status = response.status();
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap_or_else(|error| panic!("response body should read: {error}"));
        let body = serde_json::from_slice::<Value>(&body)
            .unwrap_or_else(|error| panic!("response body should be json: {error}"));
        JsonResponse { status, body }
    }

    struct JsonResponse {
        status: StatusCode,
        body: Value,
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
