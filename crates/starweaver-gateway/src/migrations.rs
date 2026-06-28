//! Database migration entry points for the gateway schema.

use std::collections::HashSet;

use sqlx::postgres::PgPool;

/// Embedded gateway schema migrator.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Applies all embedded gateway migrations to a `PostgreSQL` database.
pub async fn run(pool: &PgPool) -> crate::error::Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|error| crate::error::GatewayError::Internal {
            message: format!("gateway migrations failed: {error}"),
        })
}

/// Returns the embedded migration versions for readiness and tests.
#[must_use]
pub fn migration_versions() -> Vec<i64> {
    MIGRATOR.iter().map(|migration| migration.version).collect()
}

/// Returns successful migration versions recorded by `sqlx`.
pub async fn applied_versions(pool: &PgPool) -> crate::error::Result<HashSet<i64>> {
    sqlx::query_scalar::<_, i64>(
        "SELECT version FROM _sqlx_migrations WHERE success = true ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map(|versions| versions.into_iter().collect())
    .map_err(|error| crate::error::GatewayError::Internal {
        message: format!("failed to read gateway migration history: {error}"),
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
    use super::migration_versions;

    #[test]
    fn core_schema_migration_is_embedded() {
        assert!(migration_versions().contains(&20_260_625_000_001));
        assert!(migration_versions().contains(&20_260_628_000_001));
        assert!(migration_versions().contains(&20_260_628_000_002));
        assert!(migration_versions().contains(&20_260_628_000_003));
        assert!(migration_versions().contains(&20_260_628_000_004));
    }
}
