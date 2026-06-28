//! Authentication helpers for API keys and actor context.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::{DateTime, Utc};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::domain::{
    new_prefixed_id, ActorScope, ApiKeyRecord, ApiKeyStatus, AuthSessionRecord, AuthSessionStatus,
    AuthenticatedActor, PrincipalId, ProjectId, RequestId, TraceId,
};
use crate::error::{GatewayError, Result};
use crate::storage::{
    ApiKeyLastUsedUpdate, ApiKeyRepository, AuthSessionRepository, TenancyRepository,
};

/// API key prefix byte length.
pub const API_KEY_PREFIX_LEN: usize = 12;

const RAW_SECRET_BYTES: usize = 32;
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Newly created API key material. Raw key is returned only once.
#[derive(Debug)]
pub struct CreatedApiKey {
    /// Durable API key metadata.
    pub record: ApiKeyRecord,
    /// Raw key value returned once to the creator.
    pub raw_key: SecretString,
}

/// Newly created server-side auth session. Raw token is returned only once.
#[derive(Debug)]
pub struct CreatedAuthSession {
    /// Durable session metadata.
    pub record: AuthSessionRecord,
    /// Raw opaque session token returned once to the caller.
    pub raw_token: SecretString,
}

/// Request to create an API key.
#[derive(Clone, Debug)]
pub struct CreateApiKeyRequest {
    /// Owning tenant.
    pub tenant_id: String,
    /// Optional organization binding.
    pub organization_id: Option<String>,
    /// Optional project binding.
    pub project_id: Option<String>,
    /// Owning principal.
    pub owner_principal_id: String,
    /// Human label.
    pub name: String,
    /// Creating actor.
    pub created_by: String,
    /// Optional expiry.
    pub expires_at: Option<DateTime<Utc>>,
    /// Allowed action prefilter.
    pub allowed_actions: Vec<String>,
    /// Allowed resource prefilter.
    pub allowed_resources: Vec<String>,
}

/// Request to create an opaque server-side auth session.
#[derive(Clone, Debug)]
pub struct CreateAuthSessionRequest {
    /// Owning tenant.
    pub tenant_id: String,
    /// Authenticated principal.
    pub principal_id: String,
    /// Active organization context for browser session requests.
    pub active_organization_id: Option<String>,
    /// Active project context for browser session requests.
    pub active_project_id: Option<String>,
    /// Session expiry.
    pub expires_at: DateTime<Utc>,
}

/// Request to resolve a human session actor against a project context.
#[derive(Clone, Debug)]
pub struct ResolveUserSessionRequest {
    /// Authenticated user principal.
    pub principal_id: PrincipalId,
    /// Server-side session id.
    pub session_id: String,
    /// Active project context.
    pub project_id: ProjectId,
    /// Gateway request id.
    pub request_id: RequestId,
    /// Gateway trace id.
    pub trace_id: TraceId,
    /// Session expiry.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Request to resolve a service-account actor against a project context.
#[derive(Clone, Debug)]
pub struct ResolveServiceAccountRequest {
    /// Authenticated service account principal.
    pub service_account_id: PrincipalId,
    /// Active project context.
    pub project_id: ProjectId,
    /// Gateway request id.
    pub request_id: RequestId,
    /// Gateway trace id.
    pub trace_id: TraceId,
}

/// Creates an API key record and one-time raw value.
pub fn create_api_key(request: CreateApiKeyRequest, now: DateTime<Utc>) -> Result<CreatedApiKey> {
    let raw_key = generate_raw_key();
    let key_prefix = key_prefix(raw_key.expose_secret())?;
    let salt = SaltString::generate(&mut OsRng);
    let secret_hash = Argon2::default()
        .hash_password(raw_key.expose_secret().as_bytes(), &salt)
        .map_err(|error| GatewayError::Internal {
            message: format!("api key hash failed: {error}"),
        })?
        .to_string();

    Ok(CreatedApiKey {
        record: ApiKeyRecord {
            api_key_id: new_prefixed_id("ak"),
            tenant_id: request.tenant_id,
            organization_id: request.organization_id,
            project_id: request.project_id,
            owner_principal_id: request.owner_principal_id,
            name: request.name,
            key_prefix,
            secret_hash,
            hash_version: 1,
            status: ApiKeyStatus::Active,
            allowed_actions: request.allowed_actions,
            allowed_resources: request.allowed_resources,
            expires_at: request.expires_at,
            last_used_at: None,
            last_used_request_id: None,
            created_by: request.created_by,
            created_at: now,
            updated_at: now,
        },
        raw_key,
    })
}

/// Creates a server-side auth session record and one-time raw token.
#[must_use]
pub fn create_auth_session(
    request: CreateAuthSessionRequest,
    now: DateTime<Utc>,
) -> CreatedAuthSession {
    let raw_token = generate_raw_session_token();
    CreatedAuthSession {
        record: AuthSessionRecord {
            auth_session_id: new_prefixed_id("sess"),
            tenant_id: request.tenant_id,
            principal_id: request.principal_id,
            active_organization_id: request.active_organization_id,
            active_project_id: request.active_project_id,
            session_hash: session_token_hash(raw_token.expose_secret()),
            status: AuthSessionStatus::Active,
            expires_at: request.expires_at,
            created_at: now,
            updated_at: now,
        },
        raw_token,
    }
}

/// Verifies a raw API key and returns an authenticated actor.
pub fn verify_api_key(
    repository: &dyn ApiKeyRepository,
    presented_key: &str,
    request_id: RequestId,
    trace_id: TraceId,
    now: DateTime<Utc>,
) -> Result<AuthenticatedActor> {
    let prefix = key_prefix(presented_key)?;
    if !repository.api_key_failed_auth_allowed(&prefix, now) {
        return Err(GatewayError::Authentication);
    }
    let candidates = repository.candidates_by_prefix(&prefix);
    if candidates.is_empty() {
        repository.record_api_key_failed_auth(&prefix, now);
        return Err(GatewayError::Authentication);
    }

    for candidate in candidates {
        if !constant_time_eq(candidate.key_prefix.as_bytes(), prefix.as_bytes()) {
            continue;
        }
        if !candidate.can_authenticate_at(now) {
            continue;
        }
        if verify_secret(presented_key, &candidate.secret_hash)? {
            repository.record_api_key_last_used(ApiKeyLastUsedUpdate {
                tenant_id: candidate.tenant_id.clone(),
                api_key_id: candidate.api_key_id.clone(),
                key_prefix: prefix,
                request_id: request_id.clone(),
                used_at: now,
            });
            return Ok(AuthenticatedActor::for_api_key(
                &candidate, request_id, trace_id,
            ));
        }
    }
    repository.record_api_key_failed_auth(&prefix, now);
    Err(GatewayError::Authentication)
}

/// Verifies an opaque session token and returns durable session metadata.
pub fn verify_session_token(
    repository: &dyn AuthSessionRepository,
    presented_token: &str,
    now: DateTime<Utc>,
) -> Result<AuthSessionRecord> {
    if !presented_token.is_ascii() || !presented_token.starts_with("sws_") {
        return Err(GatewayError::Authentication);
    }
    let presented_hash = session_token_hash(presented_token);
    let Some(session) = repository.session_by_hash(&presented_hash) else {
        return Err(GatewayError::Authentication);
    };
    if !constant_time_eq(session.session_hash.as_bytes(), presented_hash.as_bytes())
        || !session.can_authenticate_at(now)
    {
        return Err(GatewayError::Authentication);
    }
    Ok(session)
}

/// Resolves a user session into an actor using active project membership.
pub fn resolve_user_session_actor(
    repository: &dyn TenancyRepository,
    request: ResolveUserSessionRequest,
) -> Result<AuthenticatedActor> {
    let membership = active_project_membership(
        repository,
        &request.principal_id,
        &request.project_id,
        "user_project_membership_required",
    )?;
    Ok(AuthenticatedActor::for_user_session(
        ActorScope::from_project_membership(&membership),
        request.principal_id,
        request.session_id,
        request.request_id,
        request.trace_id,
        request.expires_at,
    ))
}

/// Resolves a service-account token into an actor using active project membership.
pub fn resolve_service_account_actor(
    repository: &dyn TenancyRepository,
    request: ResolveServiceAccountRequest,
) -> Result<AuthenticatedActor> {
    let membership = active_project_membership(
        repository,
        &request.service_account_id,
        &request.project_id,
        "service_account_project_membership_required",
    )?;
    Ok(AuthenticatedActor::for_service_account(
        ActorScope::from_project_membership(&membership),
        request.service_account_id,
        request.request_id,
        request.trace_id,
    ))
}

fn active_project_membership(
    repository: &dyn TenancyRepository,
    principal_id: &str,
    project_id: &str,
    missing_reason: &'static str,
) -> Result<crate::domain::ProjectMembershipRecord> {
    let Some(membership) = repository.project_membership(principal_id, project_id) else {
        return Err(GatewayError::Authorization {
            reason: missing_reason,
        });
    };
    if !membership.accepts_access() {
        return Err(GatewayError::Authorization {
            reason: "project_membership_inactive",
        });
    }
    Ok(membership)
}

pub(crate) fn verify_secret(presented_key: &str, secret_hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(secret_hash).map_err(|error| GatewayError::Internal {
        message: format!("stored api key hash is invalid: {error}"),
    })?;
    Ok(Argon2::default()
        .verify_password(presented_key.as_bytes(), &parsed_hash)
        .is_ok())
}

fn generate_raw_key() -> SecretString {
    generate_raw_prefixed_token("swg_")
}

fn generate_raw_session_token() -> SecretString {
    generate_raw_prefixed_token("sws_")
}

fn generate_raw_prefixed_token(prefix: &str) -> SecretString {
    let mut bytes = [0_u8; RAW_SECRET_BYTES];
    OsRng.fill_bytes(&mut bytes);
    let mut encoded = String::with_capacity(prefix.len() + RAW_SECRET_BYTES * 2);
    encoded.push_str(prefix);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    SecretString::from(encoded)
}

pub(crate) fn session_token_hash(raw_token: &str) -> String {
    let digest = Sha256::digest(raw_token.as_bytes());
    format!("sha256:{digest:x}")
}

pub(crate) fn key_prefix(raw_key: &str) -> Result<String> {
    let prefix_len = "swg_".len() + API_KEY_PREFIX_LEN;
    if !raw_key.is_ascii() || !raw_key.starts_with("swg_") || raw_key.len() < prefix_len {
        return Err(GatewayError::Authentication);
    }
    Ok(raw_key[..prefix_len].to_owned())
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len() && left.ct_eq(right).into()
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use secrecy::ExposeSecret;

    use super::{
        create_api_key, create_auth_session, resolve_service_account_actor,
        resolve_user_session_actor, verify_api_key, verify_session_token, CreateApiKeyRequest,
        CreateAuthSessionRequest, ResolveServiceAccountRequest, ResolveUserSessionRequest,
    };
    use crate::domain::{
        ActorKind, ApiKeyStatus, AuthSessionStatus, CredentialKind, MembershipStatus,
        ProjectMembershipRecord,
    };
    use crate::storage::InMemoryGatewayStore;

    fn active_project_membership(principal_id: &str) -> ProjectMembershipRecord {
        ProjectMembershipRecord {
            project_member_id: "pm_test".to_owned(),
            tenant_id: "ten_test".to_owned(),
            organization_id: "org_test".to_owned(),
            project_id: "prj_test".to_owned(),
            principal_id: principal_id.to_owned(),
            organization_member_id: Some("om_test".to_owned()),
            status: MembershipStatus::Active,
            resource_version: 1,
        }
    }

    #[test]
    fn api_key_verification_builds_actor() {
        let now = chrono::Utc::now();
        let created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: "ten_test".to_owned(),
                organization_id: Some("org_test".to_owned()),
                project_id: Some("prj_test".to_owned()),
                owner_principal_id: "usr_test".to_owned(),
                name: "test key".to_owned(),
                created_by: "usr_test".to_owned(),
                expires_at: None,
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should be created: {error}"),
        };
        let store = InMemoryGatewayStore::default();
        store.insert_api_key(created.record);

        let actor = match verify_api_key(
            &store,
            created.raw_key.expose_secret(),
            "req_1".to_owned(),
            "tr_1".to_owned(),
            now,
        ) {
            Ok(actor) => actor,
            Err(error) => panic!("api key should verify: {error}"),
        };

        assert_eq!(actor.tenant_id, "ten_test");
        assert_eq!(actor.project_id.as_deref(), Some("prj_test"));
        assert_eq!(actor.principal_id.as_deref(), Some("usr_test"));
        assert_eq!(actor.trace_id, "tr_1");
        let updates = store.api_key_last_used_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].tenant_id, "ten_test");
        assert_eq!(updates[0].request_id, "req_1");
    }

    #[test]
    fn auth_session_creation_stores_hash_not_raw_token() {
        let now = chrono::Utc::now();
        let created = create_auth_session(
            CreateAuthSessionRequest {
                tenant_id: "ten_test".to_owned(),
                principal_id: "usr_test".to_owned(),
                active_organization_id: Some("org_test".to_owned()),
                active_project_id: Some("prj_test".to_owned()),
                expires_at: now + Duration::hours(1),
            },
            now,
        );

        assert!(created.raw_token.expose_secret().starts_with("sws_"));
        assert!(created.record.session_hash.starts_with("sha256:"));
        assert_ne!(
            created.record.session_hash,
            *created.raw_token.expose_secret()
        );
        assert_eq!(created.record.status, AuthSessionStatus::Active);
    }

    #[test]
    fn active_auth_session_token_verifies_by_hash() {
        let now = chrono::Utc::now();
        let created = create_auth_session(
            CreateAuthSessionRequest {
                tenant_id: "ten_test".to_owned(),
                principal_id: "usr_test".to_owned(),
                active_organization_id: Some("org_test".to_owned()),
                active_project_id: Some("prj_test".to_owned()),
                expires_at: now + Duration::hours(1),
            },
            now,
        );
        let raw_token = created.raw_token.expose_secret().to_owned();
        let store = InMemoryGatewayStore::default();
        store.insert_auth_session(created.record);

        let session = match verify_session_token(&store, &raw_token, now) {
            Ok(session) => session,
            Err(error) => panic!("session token should verify: {error}"),
        };

        assert_eq!(session.principal_id, "usr_test");
        assert_eq!(session.tenant_id, "ten_test");
    }

    #[test]
    fn revoked_or_expired_auth_session_token_is_rejected() {
        let now = chrono::Utc::now();
        let revoked = create_auth_session(
            CreateAuthSessionRequest {
                tenant_id: "ten_test".to_owned(),
                principal_id: "usr_test".to_owned(),
                active_organization_id: Some("org_test".to_owned()),
                active_project_id: Some("prj_test".to_owned()),
                expires_at: now + Duration::hours(1),
            },
            now,
        );
        let revoked_token = revoked.raw_token.expose_secret().to_owned();
        let mut revoked_record = revoked.record;
        revoked_record.status = AuthSessionStatus::Revoked;

        let expired = create_auth_session(
            CreateAuthSessionRequest {
                tenant_id: "ten_test".to_owned(),
                principal_id: "usr_test".to_owned(),
                active_organization_id: Some("org_test".to_owned()),
                active_project_id: Some("prj_test".to_owned()),
                expires_at: now - Duration::seconds(1),
            },
            now,
        );
        let expired_token = expired.raw_token.expose_secret().to_owned();
        let store = InMemoryGatewayStore::default();
        store.insert_auth_session(revoked_record);
        store.insert_auth_session(expired.record);

        assert!(verify_session_token(&store, &revoked_token, now).is_err());
        assert!(verify_session_token(&store, &expired_token, now).is_err());
    }

    #[test]
    fn disabled_api_key_is_rejected_before_success() {
        let now = chrono::Utc::now();
        let mut created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                owner_principal_id: "usr_test".to_owned(),
                name: "disabled key".to_owned(),
                created_by: "usr_test".to_owned(),
                expires_at: None,
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should be created: {error}"),
        };
        created.record.status = ApiKeyStatus::Disabled;
        let store = InMemoryGatewayStore::default();
        store.insert_api_key(created.record);

        assert!(verify_api_key(
            &store,
            created.raw_key.expose_secret(),
            "req_1".to_owned(),
            "tr_1".to_owned(),
            now
        )
        .is_err());
    }

    #[test]
    fn expired_api_key_is_rejected() {
        let now = chrono::Utc::now();
        let created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                owner_principal_id: "usr_test".to_owned(),
                name: "expired key".to_owned(),
                created_by: "usr_test".to_owned(),
                expires_at: Some(now - Duration::seconds(1)),
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should be created: {error}"),
        };
        let store = InMemoryGatewayStore::default();
        store.insert_api_key(created.record);

        assert!(verify_api_key(
            &store,
            created.raw_key.expose_secret(),
            "req_1".to_owned(),
            "tr_1".to_owned(),
            now
        )
        .is_err());
    }

    #[test]
    fn malformed_api_key_is_rejected_before_lookup() {
        let store = InMemoryGatewayStore::default();
        assert!(verify_api_key(
            &store,
            "not-a-gateway-key",
            "req_1".to_owned(),
            "tr_1".to_owned(),
            chrono::Utc::now()
        )
        .is_err());
    }

    #[test]
    fn wrong_secret_with_valid_prefix_is_rejected() {
        let now = chrono::Utc::now();
        let created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                owner_principal_id: "usr_test".to_owned(),
                name: "test key".to_owned(),
                created_by: "usr_test".to_owned(),
                expires_at: None,
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should be created: {error}"),
        };
        let wrong_key = format!("{}0", created.raw_key.expose_secret());
        let prefix = created.raw_key.expose_secret()[..16].to_owned();
        let store = InMemoryGatewayStore::default();
        store.insert_api_key(created.record);

        assert!(verify_api_key(
            &store,
            &wrong_key,
            "req_1".to_owned(),
            "tr_1".to_owned(),
            now
        )
        .is_err());
        assert_eq!(store.failed_api_key_auth_count(&prefix, now), 1);
    }

    #[test]
    fn repeated_wrong_secret_is_rate_limited_by_prefix() {
        let now = chrono::Utc::now();
        let created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                owner_principal_id: "usr_test".to_owned(),
                name: "limited key".to_owned(),
                created_by: "usr_test".to_owned(),
                expires_at: None,
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should be created: {error}"),
        };
        let prefix = created.raw_key.expose_secret()[..16].to_owned();
        let wrong_key = format!("{}0", created.raw_key.expose_secret());
        let store = InMemoryGatewayStore::default();
        store.insert_api_key(created.record);

        for index in 0..8 {
            assert!(verify_api_key(
                &store,
                &wrong_key,
                format!("req_{index}"),
                format!("tr_{index}"),
                now
            )
            .is_err());
        }
        assert_eq!(store.failed_api_key_auth_count(&prefix, now), 8);
        assert!(verify_api_key(
            &store,
            &wrong_key,
            "req_blocked".to_owned(),
            "tr_blocked".to_owned(),
            now
        )
        .is_err());
        assert_eq!(store.failed_api_key_auth_count(&prefix, now), 8);

        let later = now + Duration::seconds(61);
        assert!(verify_api_key(
            &store,
            &wrong_key,
            "req_later".to_owned(),
            "tr_later".to_owned(),
            later
        )
        .is_err());
        assert_eq!(store.failed_api_key_auth_count(&prefix, later), 1);
    }

    #[test]
    fn rotating_api_key_can_authenticate() {
        let now = chrono::Utc::now();
        let mut created = match create_api_key(
            CreateApiKeyRequest {
                tenant_id: "ten_test".to_owned(),
                organization_id: None,
                project_id: None,
                owner_principal_id: "usr_test".to_owned(),
                name: "rotating key".to_owned(),
                created_by: "usr_test".to_owned(),
                expires_at: None,
                allowed_actions: Vec::new(),
                allowed_resources: Vec::new(),
            },
            now,
        ) {
            Ok(created) => created,
            Err(error) => panic!("api key should be created: {error}"),
        };
        created.record.status = ApiKeyStatus::Rotating;
        let store = InMemoryGatewayStore::default();
        store.insert_api_key(created.record);

        assert!(verify_api_key(
            &store,
            created.raw_key.expose_secret(),
            "req_1".to_owned(),
            "tr_1".to_owned(),
            now
        )
        .is_ok());
    }

    #[test]
    fn user_session_actor_requires_active_project_membership() {
        let store = InMemoryGatewayStore::default();
        store.insert_project_membership(active_project_membership("usr_test"));

        let actor = match resolve_user_session_actor(
            &store,
            ResolveUserSessionRequest {
                principal_id: "usr_test".to_owned(),
                session_id: "sess_test".to_owned(),
                project_id: "prj_test".to_owned(),
                request_id: "req_test".to_owned(),
                trace_id: "tr_test".to_owned(),
                expires_at: None,
            },
        ) {
            Ok(actor) => actor,
            Err(error) => panic!("session actor should resolve: {error}"),
        };

        assert_eq!(actor.actor_kind, ActorKind::User);
        assert_eq!(actor.credential_kind, CredentialKind::Session);
        assert_eq!(actor.tenant_id, "ten_test");
        assert_eq!(actor.organization_id.as_deref(), Some("org_test"));
        assert_eq!(actor.project_id.as_deref(), Some("prj_test"));
        assert_eq!(actor.trace_id, "tr_test");
    }

    #[test]
    fn suspended_membership_cannot_resolve_session_actor() {
        let store = InMemoryGatewayStore::default();
        let mut membership = active_project_membership("usr_test");
        membership.status = MembershipStatus::Suspended;
        store.insert_project_membership(membership);

        assert!(resolve_user_session_actor(
            &store,
            ResolveUserSessionRequest {
                principal_id: "usr_test".to_owned(),
                session_id: "sess_test".to_owned(),
                project_id: "prj_test".to_owned(),
                request_id: "req_test".to_owned(),
                trace_id: "tr_test".to_owned(),
                expires_at: None,
            },
        )
        .is_err());
    }

    #[test]
    fn service_account_actor_requires_project_membership() {
        let store = InMemoryGatewayStore::default();
        store.insert_project_membership(active_project_membership("svc_test"));

        let actor = match resolve_service_account_actor(
            &store,
            ResolveServiceAccountRequest {
                service_account_id: "svc_test".to_owned(),
                project_id: "prj_test".to_owned(),
                request_id: "req_test".to_owned(),
                trace_id: "tr_test".to_owned(),
            },
        ) {
            Ok(actor) => actor,
            Err(error) => panic!("service account actor should resolve: {error}"),
        };

        assert_eq!(actor.actor_kind, ActorKind::ServiceAccount);
        assert_eq!(actor.credential_kind, CredentialKind::ServiceToken);
        assert_eq!(actor.tenant_id, "ten_test");
        assert_eq!(actor.project_id.as_deref(), Some("prj_test"));
        assert_eq!(actor.trace_id, "tr_test");
    }
}
