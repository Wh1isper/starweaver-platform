//! Database migration entry points for the agent platform schema.

use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use sqlx::postgres::PgPool;

/// First platform core schema migration version.
pub const CORE_SCHEMA_MIGRATION_VERSION: i64 = 20_260_627_000_001;

/// SQL source for the first platform core schema migration.
pub const CORE_SCHEMA_SQL: &str = include_str!("../migrations/20260627000001_core_schema.sql");

/// `OIDC` login attempts migration version.
pub const OIDC_LOGIN_ATTEMPTS_MIGRATION_VERSION: i64 = 20_260_627_000_002;

/// SQL source for the `OIDC` login attempts migration.
pub const OIDC_LOGIN_ATTEMPTS_SQL: &str =
    include_str!("../migrations/20260627000002_oidc_login_attempts.sql");

/// Platform secret refs and `OIDC` auth-method migration version.
pub const SECRET_REFS_OIDC_AUTH_METHOD_MIGRATION_VERSION: i64 = 20_260_627_000_003;

/// SQL source for the platform secret refs and `OIDC` auth-method migration.
pub const SECRET_REFS_OIDC_AUTH_METHOD_SQL: &str =
    include_str!("../migrations/20260627000003_platform_secret_refs_and_oidc_auth_method.sql");

/// Platform organization invitations migration version.
pub const ORGANIZATION_INVITATIONS_MIGRATION_VERSION: i64 = 20_260_627_000_004;

/// SQL source for the platform organization invitations migration.
pub const ORGANIZATION_INVITATIONS_SQL: &str =
    include_str!("../migrations/20260627000004_platform_organization_invitations.sql");

/// Platform audit events migration version.
pub const PLATFORM_AUDIT_EVENTS_MIGRATION_VERSION: i64 = 20_260_627_000_005;

/// SQL source for the platform audit events migration.
pub const PLATFORM_AUDIT_EVENTS_SQL: &str =
    include_str!("../migrations/20260627000005_platform_audit_events.sql");

/// Embedded platform schema migrator.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Result type used by platform migration helpers.
pub type Result<T> = std::result::Result<T, PlatformMigrationError>;

/// Platform migration error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformMigrationError {
    message: String,
}

impl PlatformMigrationError {
    /// Builds a migration error from a message.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Returns the operator-facing migration error message.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl Display for PlatformMigrationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PlatformMigrationError {}

/// Applies all embedded platform migrations to a `PostgreSQL` database.
///
/// # Errors
///
/// Returns [`PlatformMigrationError`] when `sqlx` fails to apply one or more
/// embedded migrations.
pub async fn run(pool: &PgPool) -> Result<()> {
    MIGRATOR.run(pool).await.map_err(|error| {
        PlatformMigrationError::new(format!("platform migrations failed: {error}"))
    })
}

/// Returns the embedded migration versions for readiness and tests.
#[must_use]
pub fn migration_versions() -> Vec<i64> {
    MIGRATOR.iter().map(|migration| migration.version).collect()
}

/// Returns successful migration versions recorded by `sqlx`.
///
/// # Errors
///
/// Returns [`PlatformMigrationError`] when the migration history table cannot be
/// queried.
pub async fn applied_versions(pool: &PgPool) -> Result<HashSet<i64>> {
    sqlx::query_scalar::<_, i64>(
        "SELECT version FROM _sqlx_migrations WHERE success = true ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map(|versions| versions.into_iter().collect())
    .map_err(|error| {
        PlatformMigrationError::new(format!(
            "failed to read platform migration history: {error}"
        ))
    })
}

/// Returns embedded migration versions that have not been applied.
#[must_use]
pub fn missing_versions<S: std::hash::BuildHasher>(applied: &HashSet<i64, S>) -> Vec<i64> {
    migration_versions()
        .into_iter()
        .filter(|version| !applied.contains(version))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        migration_versions, missing_versions, CORE_SCHEMA_MIGRATION_VERSION, CORE_SCHEMA_SQL,
        OIDC_LOGIN_ATTEMPTS_MIGRATION_VERSION, OIDC_LOGIN_ATTEMPTS_SQL,
        ORGANIZATION_INVITATIONS_MIGRATION_VERSION, ORGANIZATION_INVITATIONS_SQL,
        PLATFORM_AUDIT_EVENTS_MIGRATION_VERSION, PLATFORM_AUDIT_EVENTS_SQL,
        SECRET_REFS_OIDC_AUTH_METHOD_MIGRATION_VERSION, SECRET_REFS_OIDC_AUTH_METHOD_SQL,
    };

    #[test]
    fn platform_migrations_are_embedded() {
        assert!(migration_versions().contains(&CORE_SCHEMA_MIGRATION_VERSION));
        assert!(migration_versions().contains(&OIDC_LOGIN_ATTEMPTS_MIGRATION_VERSION));
        assert!(migration_versions().contains(&SECRET_REFS_OIDC_AUTH_METHOD_MIGRATION_VERSION));
        assert!(migration_versions().contains(&ORGANIZATION_INVITATIONS_MIGRATION_VERSION));
        assert!(migration_versions().contains(&PLATFORM_AUDIT_EVENTS_MIGRATION_VERSION));
    }

    #[test]
    fn missing_versions_returns_unapplied_embedded_migrations() {
        let applied = HashSet::new();

        assert_eq!(
            missing_versions(&applied),
            vec![
                CORE_SCHEMA_MIGRATION_VERSION,
                OIDC_LOGIN_ATTEMPTS_MIGRATION_VERSION,
                SECRET_REFS_OIDC_AUTH_METHOD_MIGRATION_VERSION,
                ORGANIZATION_INVITATIONS_MIGRATION_VERSION,
                PLATFORM_AUDIT_EVENTS_MIGRATION_VERSION,
            ]
        );

        let applied = HashSet::from([
            CORE_SCHEMA_MIGRATION_VERSION,
            OIDC_LOGIN_ATTEMPTS_MIGRATION_VERSION,
            SECRET_REFS_OIDC_AUTH_METHOD_MIGRATION_VERSION,
            ORGANIZATION_INVITATIONS_MIGRATION_VERSION,
            PLATFORM_AUDIT_EVENTS_MIGRATION_VERSION,
        ]);
        assert!(missing_versions(&applied).is_empty());
    }

    #[test]
    fn core_schema_declares_identity_and_actor_resolution_tables() {
        for table in [
            "platform_tenants",
            "platform_organizations",
            "platform_projects",
            "platform_principals",
            "platform_users",
            "platform_service_accounts",
            "platform_identity_providers",
            "platform_external_identities",
            "platform_auth_sessions",
            "platform_bearer_credentials",
            "platform_mtls_identities",
        ] {
            assert_schema_contains_table(table);
        }
    }

    #[test]
    fn core_schema_supports_generic_oidc_login_provider() {
        assert!(CORE_SCHEMA_SQL.contains("provider_kind IN ('oidc', 'single_user')"));
        assert!(CORE_SCHEMA_SQL.contains("provider_kind <> 'oidc' OR issuer_url IS NOT NULL"));
        assert!(CORE_SCHEMA_SQL.contains("provider_kind <> 'oidc' OR client_id IS NOT NULL"));
        assert!(CORE_SCHEMA_SQL.contains("provider_kind <> 'oidc' OR redirect_uri IS NOT NULL"));
        assert!(CORE_SCHEMA_SQL.contains("provider_kind <> 'oidc' OR requested_scopes ? 'openid'"));
        assert!(CORE_SCHEMA_SQL
            .contains("provider_kind <> 'oidc' OR jsonb_array_length(oidc_audiences) > 0"));
        assert!(CORE_SCHEMA_SQL.contains("platform_identity_providers_tenant_kind_idx"));
    }

    #[test]
    fn core_schema_never_stores_raw_credentials() {
        let lower = CORE_SCHEMA_SQL.to_ascii_lowercase();

        for forbidden in [
            "raw_token",
            "raw_bearer",
            "raw_api_key",
            "raw_password",
            "password_hash",
            "client_secret text",
        ] {
            assert!(
                !lower.contains(forbidden),
                "schema must not contain raw credential column: {forbidden}"
            );
        }

        assert!(lower.contains("token_hash text not null unique"));
        assert!(lower.contains("client_secret_ref text"));
    }

    #[test]
    fn oidc_login_attempts_store_only_hashed_transient_secrets() {
        let lower = OIDC_LOGIN_ATTEMPTS_SQL.to_ascii_lowercase();

        assert!(lower.contains("create table if not exists platform_oidc_login_attempts"));
        assert!(lower.contains("state_hash text not null unique"));
        assert!(lower.contains("nonce_hash text not null"));
        assert!(lower.contains("pkce_verifier_hash text not null"));
        assert!(lower.contains("platform_oidc_login_attempts_provider_status_idx"));
        for forbidden in [
            " raw_state",
            " raw_nonce",
            " raw_pkce",
            " state text",
            " nonce text",
            " pkce_verifier text",
            " code_verifier text",
        ] {
            assert!(
                !lower.contains(forbidden),
                "OIDC attempt migration must not store raw login secret: {forbidden}"
            );
        }
    }

    #[test]
    fn secret_ref_migration_stores_safe_metadata_and_oidc_auth_method() {
        let lower = SECRET_REFS_OIDC_AUTH_METHOD_SQL.to_ascii_lowercase();

        assert!(lower.contains("create table if not exists platform_secret_refs"));
        assert!(lower.contains("secret_ref_id text primary key"));
        assert!(lower.contains("backend_kind text not null"));
        assert!(lower.contains("backend_locator text not null"));
        assert!(lower.contains("display_mask text not null"));
        assert!(lower.contains("fingerprint text not null"));
        assert!(lower.contains("add column if not exists token_endpoint_auth_method"));
        assert!(lower.contains("client_secret_basic"));
        assert!(lower.contains("client_secret_post"));
        assert!(lower.contains("foreign key (client_secret_ref)"));

        for forbidden in ["secret_value", "raw_secret", "client_secret text"] {
            assert!(
                !lower.contains(forbidden),
                "secret migration must not store raw secret material: {forbidden}"
            );
        }
    }

    #[test]
    fn organization_invitation_migration_stores_token_hash_only() {
        let lower = ORGANIZATION_INVITATIONS_SQL.to_ascii_lowercase();

        assert!(lower.contains("create table if not exists platform_organization_invitations"));
        assert!(lower.contains("invitation_token_hash text not null unique"));
        assert!(lower.contains("status in ('pending', 'accepted', 'revoked', 'expired')"));
        assert!(lower.contains("platform_org_invitations_org_status_idx"));
        assert!(lower.contains("invited_email is not null and invited_principal_id is null"));
        assert!(lower.contains("invited_email is null and invited_principal_id is not null"));

        for forbidden in ["raw_token", "invitation_token text", "token text not null"] {
            assert!(
                !lower.contains(forbidden),
                "invitation migration must not store raw token material: {forbidden}"
            );
        }
    }

    #[test]
    fn platform_audit_events_migration_stores_redacted_event_envelopes() {
        let lower = PLATFORM_AUDIT_EVENTS_SQL.to_ascii_lowercase();

        assert!(lower.contains("create table if not exists platform_audit_events"));
        assert!(lower.contains("audit_event_id text primary key"));
        assert!(lower.contains("actor_principal_id text not null"));
        assert!(lower.contains("action_id text not null"));
        assert!(lower.contains("resource_kind text not null"));
        assert!(lower.contains("resource_id text not null"));
        assert!(lower.contains("event_type text not null"));
        assert!(lower.contains("redaction text not null"));
        assert!(lower.contains("platform_audit_events_tenant_created_idx"));
        assert!(lower.contains("platform_audit_events_resource_idx"));

        for forbidden in [
            "raw_token",
            "raw_bearer",
            "raw_api_key",
            "raw_password",
            "token_hash",
            "client_secret",
        ] {
            assert!(
                !lower.contains(forbidden),
                "audit migration must not store credential material: {forbidden}"
            );
        }
    }

    #[test]
    fn core_schema_declares_resource_owner_key_and_scope_shape() {
        assert_schema_contains_table("platform_resource_owners");
        assert!(CORE_SCHEMA_SQL.contains("PRIMARY KEY (resource_kind, resource_id)"));
        assert!(
            CORE_SCHEMA_SQL.contains("CHECK (project_id IS NULL OR organization_id IS NOT NULL)")
        );
        assert!(CORE_SCHEMA_SQL.contains("platform_resource_owners_scope_idx"));
    }

    #[test]
    fn core_schema_declares_safe_business_resource_tables() {
        for table in [
            "platform_conversations",
            "platform_agent_sessions",
            "platform_runs",
            "platform_run_events",
            "platform_approvals",
            "platform_deferred_tools",
            "platform_environment_attachments",
            "platform_evidence_archives",
            "platform_idempotency_keys",
        ] {
            assert_schema_contains_table(table);
        }
    }

    #[test]
    fn core_schema_indexes_status_and_scope_read_paths() {
        for index in [
            "platform_auth_sessions_actor_scope_idx",
            "platform_bearer_credentials_actor_scope_idx",
            "platform_mtls_identities_subject_idx",
            "platform_mtls_identities_actor_scope_idx",
            "platform_conversations_project_status_idx",
            "platform_runs_project_status_idx",
            "platform_approvals_project_status_idx",
            "platform_deferred_tools_project_status_idx",
            "platform_environment_attachments_project_status_idx",
            "platform_evidence_archives_project_idx",
        ] {
            assert!(CORE_SCHEMA_SQL.contains(index), "missing index: {index}");
        }
    }

    fn assert_schema_contains_table(table: &str) {
        let create_table = format!("CREATE TABLE IF NOT EXISTS {table} (");
        assert!(
            CORE_SCHEMA_SQL.contains(&create_table),
            "missing table: {table}"
        );
    }
}
