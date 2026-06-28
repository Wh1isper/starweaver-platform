#![doc = "Binary entry point for the Starweaver agent platform service."]
#![forbid(unsafe_code)]

use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;
use starweaver_platform::config::PlatformConfig;
use starweaver_platform::migrations;
use starweaver_platform::service::run;

#[tokio::main]
async fn main() -> ExitCode {
    match run_command().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

async fn run_command() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        None => run(PlatformConfig::from_env())
            .await
            .map_err(|error| error.to_string()),
        Some("migrate") => run_migration_command(args.get(1).map(String::as_str)).await,
        Some("--help" | "-h" | "help") => {
            print_usage();
            Ok(())
        }
        Some(command) => Err(format!("unknown command: {command}\n\n{}", usage())),
    }
}

async fn run_migration_command(command: Option<&str>) -> Result<(), String> {
    match command {
        Some("run") => {
            let pool = migration_pool().await?;
            migrations::run(&pool)
                .await
                .map_err(|error| error.to_string())?;
            println!(
                "platform migrations applied: {:?}",
                migrations::migration_versions()
            );
            Ok(())
        }
        Some("check") => {
            let pool = migration_pool().await?;
            let applied = migrations::applied_versions(&pool)
                .await
                .map_err(|error| error.to_string())?;
            let missing = migrations::missing_versions(&applied);
            if missing.is_empty() {
                println!("platform migrations ready: {applied:?}");
                Ok(())
            } else {
                Err(format!("platform migrations missing: {missing:?}"))
            }
        }
        _ => Err(format!("unknown migrate command\n\n{}", usage())),
    }
}

async fn migration_pool() -> Result<sqlx::PgPool, String> {
    let database_url = PlatformConfig::from_env()
        .database_url
        .ok_or_else(|| "STARWEAVER_PLATFORM_DATABASE_URL is required".to_owned())?;
    PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .map_err(|error| format!("failed to connect to PostgreSQL: {error}"))
}

fn print_usage() {
    println!("{}", usage());
}

const fn usage() -> &'static str {
    "usage:\n  starweaver-platform\n  starweaver-platform migrate run\n  starweaver-platform migrate check"
}
