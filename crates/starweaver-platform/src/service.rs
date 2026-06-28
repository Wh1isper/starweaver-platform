//! Platform HTTP service foundation.

use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use axum::body::Body;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde_json::{json, Value};
use sqlx::postgres::PgPoolOptions;

use crate::action::{
    ActionGrant, ActorKind, AuthenticatedActor, AuthorizationEngine, AuthorizationRequest,
    FoundationAuthorizationEngine, ResourceRef,
};
use crate::auth::{
    AuthError, InMemoryPlatformAuthSessionStore, InMemoryPlatformBearerCredentialStore,
    InMemoryPlatformMtlsIdentityStore, PlatformAuthSessionRepository,
    PlatformBearerCredentialRepository, PlatformMtlsIdentityRepository,
};
use crate::config::{validate_platform_config, PlatformConfig, PlatformConfigError};
use crate::migrations::{self, PlatformMigrationError};
use crate::postgres::{PlatformRepositoryError, PostgresPlatformRepository};
use crate::resource::{
    InMemoryPlatformResourceStore, PlatformResourceRecord, PlatformResourceRepository,
};
use crate::route::{foundation_routes, HttpMethod, RouteMetadata};
use crate::storage::{InMemoryResourceOwnerStore, ResourceOwnerRepository};

/// HTTP foundation service state.
#[derive(Clone, Debug, Default)]
pub struct PlatformServiceState {
    owners: InMemoryResourceOwnerStore,
    auth_sessions: InMemoryPlatformAuthSessionStore,
    bearer_credentials: InMemoryPlatformBearerCredentialStore,
    mtls_identities: InMemoryPlatformMtlsIdentityStore,
    resources: InMemoryPlatformResourceStore,
    repository_backend: PlatformRepositoryBackendKind,
    postgres_repository: Option<PostgresPlatformRepository>,
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
    pub const fn with_resources_and_mtls(
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
            repository_backend: PlatformRepositoryBackendKind::InMemory,
            postgres_repository: None,
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
            repository_backend: PlatformRepositoryBackendKind::Postgres,
            postgres_repository: Some(postgres_repository),
            authorization,
        }
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
    match config.repository_backend {
        PlatformRepositoryBackendKind::InMemory => Ok(PlatformServiceState::new(
            InMemoryResourceOwnerStore::new(),
            FoundationAuthorizationEngine::new(Vec::<ActionGrant>::new()),
        )),
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
            Ok(PlatformServiceState::with_postgres_repository(
                PostgresPlatformRepository::new(pool),
                FoundationAuthorizationEngine::new(Vec::<ActionGrant>::new()),
            ))
        }
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
    Router::new()
        .fallback(dispatch_foundation_request)
        .with_state(state)
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
    let decision = state.authorization.authorize(&AuthorizationRequest {
        actor: actor.clone(),
        action: matched.route.action,
        resource: resource.clone(),
    });
    if !decision.allowed {
        return Err(ServiceError::Forbidden(decision.reason));
    }
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
    use serde_json::Value;
    use sqlx::postgres::PgPoolOptions;
    use tower::ServiceExt;

    use crate::action::{
        ActionGrant, ActorKind, AuthenticatedActor, BuiltInRole, FoundationAuthorizationEngine,
        PlatformAction, RoleScopeKind,
    };
    use crate::auth::{
        InMemoryPlatformAuthSessionStore, InMemoryPlatformBearerCredentialStore,
        InMemoryPlatformMtlsIdentityStore, PlatformAuthSessionRecord,
        PlatformAuthSessionRepository, PlatformAuthSessionStatus, PlatformBearerCredentialKind,
        PlatformBearerCredentialRecord, PlatformBearerCredentialRepository,
        PlatformBearerCredentialStatus, PlatformMtlsIdentityRecord, PlatformMtlsIdentityRepository,
    };
    use crate::config::PlatformConfig;
    use crate::postgres::PostgresPlatformRepository;
    use crate::resource::{
        ApprovalRecord, ConversationRecord, EnvironmentAttachmentRecord, EvidenceArchiveRecord,
        InMemoryPlatformResourceStore, PlatformResourceData, PlatformResourceRecord,
        PlatformResourceRepository, RunRecord,
    };
    use crate::service::{
        build_platform_service_state, match_route, router, PlatformRepositoryBackendKind,
        PlatformRunError, PlatformServiceState, VERIFIED_MTLS_SUBJECT_HEADER,
    };
    use crate::storage::{
        InMemoryResourceOwnerStore, ResourceOwnerRecord, ResourceOwnerRepository,
    };

    const TENANT_ID: &str = "ten_test";
    const ORGANIZATION_ID: &str = "org_test";
    const PROJECT_ID: &str = "prj_test";
    const OTHER_PROJECT_ID: &str = "prj_other";
    const USER_ID: &str = "usr_test";
    const SERVICE_ACCOUNT_ID: &str = "svc_test";
    const USER_TOKEN: &str = "platform-user-session-token";
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

    fn mtls_headers(subject: &str) -> [(&'static str, String); 1] {
        [(VERIFIED_MTLS_SUBJECT_HEADER, subject.to_owned())]
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

    struct JsonResponse {
        status: StatusCode,
        body: Value,
    }
}
