//! Startup configuration for the platform service.

use std::fmt::{Debug, Display, Formatter};

use crate::service::PlatformRepositoryBackendKind;

/// Default platform HTTP listen address for local development.
pub const DEFAULT_PLATFORM_LISTEN_ADDR: &str = "127.0.0.1:8090";

/// Default platform environment profile.
pub const DEFAULT_PLATFORM_ENVIRONMENT: &str = "local";

/// Platform service startup configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformConfig {
    /// Address used by the future platform HTTP entrypoint.
    pub listen_addr: String,
    /// Environment profile, such as `local`, `test`, `prod`, or `production`.
    pub environment: String,
    /// Durable `PostgreSQL` connection string.
    pub database_url: Option<String>,
    /// Repository backend selected for request handling.
    pub repository_backend: PlatformRepositoryBackendKind,
    /// Optional local single-user password login configuration.
    pub single_user_auth: Option<PlatformSingleUserConfig>,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            listen_addr: DEFAULT_PLATFORM_LISTEN_ADDR.to_owned(),
            environment: DEFAULT_PLATFORM_ENVIRONMENT.to_owned(),
            database_url: None,
            repository_backend: PlatformRepositoryBackendKind::InMemory,
            single_user_auth: None,
        }
    }
}

impl PlatformConfig {
    /// Loads platform startup configuration from `STARWEAVER_PLATFORM_*` environment variables.
    #[must_use]
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Ok(value) = std::env::var("STARWEAVER_PLATFORM_LISTEN_ADDR") {
            if let Some(value) = non_empty_env(&value) {
                config.listen_addr = value;
            }
        }
        if let Ok(value) = std::env::var("STARWEAVER_PLATFORM_ENV") {
            if let Some(value) = non_empty_env(&value) {
                config.environment = value.to_ascii_lowercase();
            }
        }
        if let Ok(value) = std::env::var("STARWEAVER_PLATFORM_DATABASE_URL") {
            config.database_url = non_empty_env(&value);
        }
        if let Ok(value) = std::env::var("STARWEAVER_PLATFORM_REPOSITORY_BACKEND") {
            if let Some(backend) = parse_platform_repository_backend(&value) {
                config.repository_backend = backend;
            }
        }
        config.single_user_auth = single_user_auth_from_env();
        config
    }
}

/// Local single-user password login configuration.
#[derive(Clone, Eq, PartialEq)]
pub struct PlatformSingleUserConfig {
    username: String,
    password: String,
    user_primary_email: Option<String>,
    user_display_name: String,
}

impl Debug for PlatformSingleUserConfig {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlatformSingleUserConfig")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("user_primary_email", &self.user_primary_email)
            .field("user_display_name", &self.user_display_name)
            .finish()
    }
}

impl PlatformSingleUserConfig {
    /// Builds a single-user config from required credentials.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        let username = username.into();
        Self {
            user_display_name: username.clone(),
            username,
            password: password.into(),
            user_primary_email: None,
        }
    }

    /// Returns the configured login username.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the optional primary email for the local user.
    #[must_use]
    pub fn user_primary_email(&self) -> Option<&str> {
        self.user_primary_email.as_deref()
    }

    /// Returns the local user's display name.
    #[must_use]
    pub fn user_display_name(&self) -> &str {
        &self.user_display_name
    }

    /// Returns whether the supplied credentials match the configured user.
    #[must_use]
    pub fn credentials_match(&self, username: &str, password: &str) -> bool {
        constant_time_eq(self.username.as_bytes(), username.as_bytes())
            & constant_time_eq(self.password.as_bytes(), password.as_bytes())
    }

    fn with_user_primary_email(mut self, user_primary_email: Option<String>) -> Self {
        self.user_primary_email = user_primary_email;
        self
    }

    fn with_user_display_name(mut self, user_display_name: String) -> Self {
        self.user_display_name = user_display_name;
        self
    }
}

/// Platform startup validation error.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformConfigError {
    diagnostics: Vec<PlatformStartupDiagnostic>,
}

impl PlatformConfigError {
    /// Builds a validation error from startup diagnostics.
    ///
    /// # Panics
    ///
    /// Panics when called with an empty diagnostic list.
    #[must_use]
    pub fn new(diagnostics: Vec<PlatformStartupDiagnostic>) -> Self {
        assert!(
            !diagnostics.is_empty(),
            "platform config error requires diagnostics"
        );
        Self { diagnostics }
    }

    /// Returns startup diagnostics that caused validation failure.
    #[must_use]
    pub fn diagnostics(&self) -> &[PlatformStartupDiagnostic] {
        &self.diagnostics
    }

    /// Returns stable diagnostic codes.
    #[must_use]
    pub fn codes(&self) -> Vec<&'static str> {
        self.diagnostics
            .iter()
            .map(PlatformStartupDiagnostic::code)
            .collect()
    }
}

impl Display for PlatformConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "platform startup configuration is unsafe: {}",
            self.codes().join(",")
        )
    }
}

impl std::error::Error for PlatformConfigError {}

/// Startup validation diagnostic for platform configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlatformStartupDiagnostic {
    code: &'static str,
    message: &'static str,
}

impl PlatformStartupDiagnostic {
    /// Creates a startup diagnostic.
    #[must_use]
    pub const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Returns the stable diagnostic code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the operator-facing diagnostic message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

/// Validates platform startup configuration.
///
/// # Errors
///
/// Returns a `PlatformConfigError` when production or backend-specific
/// requirements are not satisfied.
pub fn validate_platform_config(config: &PlatformConfig) -> Result<(), PlatformConfigError> {
    let diagnostics = platform_startup_diagnostics(config);
    if diagnostics.is_empty() {
        Ok(())
    } else {
        Err(PlatformConfigError::new(diagnostics))
    }
}

/// Returns platform startup diagnostics without failing fast.
#[must_use]
pub fn platform_startup_diagnostics(config: &PlatformConfig) -> Vec<PlatformStartupDiagnostic> {
    let mut diagnostics = Vec::new();
    push_repository_backend_diagnostics(config, &mut diagnostics);
    if is_platform_production_environment(&config.environment) {
        push_production_diagnostics(config, &mut diagnostics);
    }
    diagnostics
}

/// Returns whether a platform environment profile is production.
#[must_use]
pub fn is_platform_production_environment(environment: &str) -> bool {
    matches!(
        environment.trim().to_ascii_lowercase().as_str(),
        "prod" | "production"
    )
}

/// Parses a platform repository backend profile.
#[must_use]
pub fn parse_platform_repository_backend(value: &str) -> Option<PlatformRepositoryBackendKind> {
    match value.trim().to_ascii_lowercase().as_str() {
        "in_memory" | "in-memory" | "memory" | "mem" => {
            Some(PlatformRepositoryBackendKind::InMemory)
        }
        "postgres" | "postgresql" | "pg" => Some(PlatformRepositoryBackendKind::Postgres),
        _ => None,
    }
}

fn single_user_auth_from_env() -> Option<PlatformSingleUserConfig> {
    let username = std::env::var("STARWEAVER_PLATFORM_SINGLE_USER_USERNAME")
        .ok()
        .and_then(|value| non_empty_env(&value));
    let password = std::env::var("STARWEAVER_PLATFORM_SINGLE_USER_PASSWORD")
        .ok()
        .and_then(|value| non_empty_env(&value));
    let (Some(username), Some(password)) = (username, password) else {
        return None;
    };
    let mut config = PlatformSingleUserConfig::new(username, password);
    if let Ok(value) = std::env::var("STARWEAVER_PLATFORM_SINGLE_USER_EMAIL") {
        config = config.with_user_primary_email(non_empty_env(&value));
    }
    if let Ok(value) = std::env::var("STARWEAVER_PLATFORM_SINGLE_USER_DISPLAY_NAME") {
        if let Some(value) = non_empty_env(&value) {
            config = config.with_user_display_name(value);
        }
    }
    Some(config)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = left.len() ^ right.len();
    let max_len = left.len().max(right.len());
    for index in 0..max_len {
        let left_byte = left.get(index).copied().unwrap_or(0);
        let right_byte = right.get(index).copied().unwrap_or(0);
        diff |= usize::from(left_byte ^ right_byte);
    }
    diff == 0
}

fn push_repository_backend_diagnostics(
    config: &PlatformConfig,
    diagnostics: &mut Vec<PlatformStartupDiagnostic>,
) {
    if matches!(
        config.repository_backend,
        PlatformRepositoryBackendKind::Postgres
    ) && config.database_url.is_none()
        && !is_platform_production_environment(&config.environment)
    {
        diagnostics.push(PlatformStartupDiagnostic::new(
            "postgres_database_url_required",
            "postgres repository backend requires STARWEAVER_PLATFORM_DATABASE_URL",
        ));
    }
}

fn push_production_diagnostics(
    config: &PlatformConfig,
    diagnostics: &mut Vec<PlatformStartupDiagnostic>,
) {
    if matches!(
        config.repository_backend,
        PlatformRepositoryBackendKind::InMemory
    ) {
        diagnostics.push(PlatformStartupDiagnostic::new(
            "durable_repository_backend_required",
            "production must not use the in-memory platform repository backend",
        ));
    }
    if config.database_url.is_none() {
        diagnostics.push(PlatformStartupDiagnostic::new(
            "database_url_required",
            "production requires STARWEAVER_PLATFORM_DATABASE_URL",
        ));
    }
}

fn non_empty_env(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use super::{
        is_platform_production_environment, parse_platform_repository_backend,
        platform_startup_diagnostics, validate_platform_config, PlatformConfig,
    };
    use crate::service::PlatformRepositoryBackendKind;

    const ENV_KEYS: [&str; 8] = [
        "STARWEAVER_PLATFORM_LISTEN_ADDR",
        "STARWEAVER_PLATFORM_ENV",
        "STARWEAVER_PLATFORM_DATABASE_URL",
        "STARWEAVER_PLATFORM_REPOSITORY_BACKEND",
        "STARWEAVER_PLATFORM_SINGLE_USER_USERNAME",
        "STARWEAVER_PLATFORM_SINGLE_USER_PASSWORD",
        "STARWEAVER_PLATFORM_SINGLE_USER_EMAIL",
        "STARWEAVER_PLATFORM_SINGLE_USER_DISPLAY_NAME",
    ];

    fn env_lock() -> &'static Mutex<()> {
        static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        ENV_LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_platform_env() {
        for key in ENV_KEYS {
            std::env::remove_var(key);
        }
    }

    fn diagnostic_codes(config: &PlatformConfig) -> Vec<&'static str> {
        platform_startup_diagnostics(config)
            .into_iter()
            .map(|diagnostic| diagnostic.code())
            .collect()
    }

    #[test]
    fn default_config_uses_local_in_memory_backend() {
        let config = PlatformConfig::default();

        assert_eq!(config.listen_addr, "127.0.0.1:8090");
        assert_eq!(config.environment, "local");
        assert_eq!(config.database_url, None);
        assert_eq!(
            config.repository_backend,
            PlatformRepositoryBackendKind::InMemory
        );
        assert!(config.single_user_auth.is_none());
        assert!(validate_platform_config(&config).is_ok());
    }

    #[test]
    fn from_env_parses_platform_values() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(|error| panic!("environment lock poisoned: {error}"));
        clear_platform_env();
        std::env::set_var("STARWEAVER_PLATFORM_LISTEN_ADDR", " 127.0.0.1:9001 ");
        std::env::set_var("STARWEAVER_PLATFORM_ENV", " Production ");
        std::env::set_var(
            "STARWEAVER_PLATFORM_DATABASE_URL",
            " postgres://platform@example/platform ",
        );
        std::env::set_var("STARWEAVER_PLATFORM_REPOSITORY_BACKEND", "PostgreSQL");

        let config = PlatformConfig::from_env();
        clear_platform_env();

        assert_eq!(config.listen_addr, "127.0.0.1:9001");
        assert_eq!(config.environment, "production");
        assert_eq!(
            config.database_url.as_deref(),
            Some("postgres://platform@example/platform")
        );
        assert_eq!(
            config.repository_backend,
            PlatformRepositoryBackendKind::Postgres
        );
        assert!(validate_platform_config(&config).is_ok());
    }

    #[test]
    fn from_env_ignores_blank_values_and_unknown_backend() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(|error| panic!("environment lock poisoned: {error}"));
        clear_platform_env();
        std::env::set_var("STARWEAVER_PLATFORM_LISTEN_ADDR", " ");
        std::env::set_var("STARWEAVER_PLATFORM_ENV", " ");
        std::env::set_var("STARWEAVER_PLATFORM_DATABASE_URL", " ");
        std::env::set_var("STARWEAVER_PLATFORM_REPOSITORY_BACKEND", "unknown");

        let config = PlatformConfig::from_env();
        clear_platform_env();

        assert_eq!(config, PlatformConfig::default());
    }

    #[test]
    fn from_env_enables_single_user_only_with_required_credentials() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(|error| panic!("environment lock poisoned: {error}"));
        clear_platform_env();

        assert!(PlatformConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_PLATFORM_SINGLE_USER_USERNAME", "admin");
        assert!(PlatformConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_PLATFORM_SINGLE_USER_PASSWORD", " ");
        assert!(PlatformConfig::from_env().single_user_auth.is_none());

        std::env::set_var("STARWEAVER_PLATFORM_SINGLE_USER_USERNAME", " admin ");
        std::env::set_var("STARWEAVER_PLATFORM_SINGLE_USER_PASSWORD", " secret ");
        std::env::set_var(
            "STARWEAVER_PLATFORM_SINGLE_USER_EMAIL",
            " admin@example.com ",
        );
        std::env::set_var("STARWEAVER_PLATFORM_SINGLE_USER_DISPLAY_NAME", " Admin ");

        let single_user = PlatformConfig::from_env()
            .single_user_auth
            .unwrap_or_else(|| panic!("single-user config should be enabled"));
        clear_platform_env();

        assert_eq!(single_user.username(), "admin");
        assert_eq!(single_user.user_primary_email(), Some("admin@example.com"));
        assert_eq!(single_user.user_display_name(), "Admin");
        assert!(single_user.credentials_match("admin", "secret"));
        assert!(!single_user.credentials_match("admin", "wrong"));
        assert!(!single_user.credentials_match("other", "secret"));
        assert!(!format!("{single_user:?}").contains("secret"));
    }

    #[test]
    fn backend_parser_accepts_documented_aliases() {
        assert_eq!(
            parse_platform_repository_backend("memory"),
            Some(PlatformRepositoryBackendKind::InMemory)
        );
        assert_eq!(
            parse_platform_repository_backend("in-memory"),
            Some(PlatformRepositoryBackendKind::InMemory)
        );
        assert_eq!(
            parse_platform_repository_backend("postgresql"),
            Some(PlatformRepositoryBackendKind::Postgres)
        );
        assert_eq!(parse_platform_repository_backend("sqlite"), None);
    }

    #[test]
    fn production_environment_parser_is_case_and_space_tolerant() {
        assert!(is_platform_production_environment("prod"));
        assert!(is_platform_production_environment(" Production "));
        assert!(!is_platform_production_environment("local"));
    }

    #[test]
    fn production_rejects_in_memory_without_database_url() {
        let config = PlatformConfig {
            environment: "production".to_owned(),
            ..PlatformConfig::default()
        };

        let codes = diagnostic_codes(&config);
        assert_eq!(
            codes,
            vec![
                "durable_repository_backend_required",
                "database_url_required"
            ]
        );

        let Err(error) = validate_platform_config(&config) else {
            panic!("production config should fail validation");
        };
        assert_eq!(
            error.to_string(),
            "platform startup configuration is unsafe: durable_repository_backend_required,database_url_required"
        );
    }

    #[test]
    fn postgres_backend_requires_database_url_in_every_environment() {
        let config = PlatformConfig {
            repository_backend: PlatformRepositoryBackendKind::Postgres,
            ..PlatformConfig::default()
        };

        assert_eq!(
            diagnostic_codes(&config),
            vec!["postgres_database_url_required"]
        );
        assert!(validate_platform_config(&config).is_err());
    }

    #[test]
    fn production_postgres_without_database_url_reports_production_code_once() {
        let config = PlatformConfig {
            environment: "prod".to_owned(),
            repository_backend: PlatformRepositoryBackendKind::Postgres,
            ..PlatformConfig::default()
        };

        assert_eq!(diagnostic_codes(&config), vec!["database_url_required"]);
        assert!(validate_platform_config(&config).is_err());
    }

    #[test]
    fn production_accepts_postgres_with_database_url() {
        let config = PlatformConfig {
            environment: "prod".to_owned(),
            database_url: Some("postgres://platform@example/platform".to_owned()),
            repository_backend: PlatformRepositoryBackendKind::Postgres,
            ..PlatformConfig::default()
        };

        assert!(diagnostic_codes(&config).is_empty());
        assert!(validate_platform_config(&config).is_ok());
    }
}
