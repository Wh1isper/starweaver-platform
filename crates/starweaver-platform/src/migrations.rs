//! Database migration entry points for the agent platform schema.

use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use sqlx::postgres::PgPool;

/// First platform core schema migration version.
pub const CORE_SCHEMA_MIGRATION_VERSION: i64 = 20_260_627_000_001;

/// SQL source for the first platform core schema migration.
pub const CORE_SCHEMA_SQL: &str = include_str!("../migrations/20260627000001_core_schema.sql");

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
    };

    #[test]
    fn core_schema_migration_is_embedded() {
        assert!(migration_versions().contains(&CORE_SCHEMA_MIGRATION_VERSION));
    }

    #[test]
    fn missing_versions_returns_unapplied_embedded_migrations() {
        let applied = HashSet::new();

        assert_eq!(
            missing_versions(&applied),
            vec![CORE_SCHEMA_MIGRATION_VERSION]
        );

        let applied = HashSet::from([CORE_SCHEMA_MIGRATION_VERSION]);
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
        assert!(CORE_SCHEMA_SQL
            .contains("provider_kind IN ('oidc', 'github_oauth_app', 'single_user')"));
        assert!(CORE_SCHEMA_SQL.contains("provider_kind <> 'oidc' OR issuer_url IS NOT NULL"));
        assert!(CORE_SCHEMA_SQL.contains("provider_kind <> 'oidc' OR jwks_uri IS NOT NULL"));
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
