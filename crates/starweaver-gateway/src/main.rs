#![doc = "Binary entry point for the Starweaver LLM gateway service."]
#![forbid(unsafe_code)]

use std::process::ExitCode;

use sqlx::postgres::PgPoolOptions;
use starweaver_gateway::migrations;
use starweaver_gateway::service::{GatewayConfig, run};

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
        None => run(GatewayConfig::from_env())
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
                "gateway migrations applied: {:?}",
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
                println!("gateway migrations ready: {applied:?}");
                Ok(())
            } else {
                Err(format!("gateway migrations missing: {missing:?}"))
            }
        }
        _ => Err(format!("unknown migrate command\n\n{}", usage())),
    }
}

async fn migration_pool() -> Result<sqlx::PgPool, String> {
    let database_url = GatewayConfig::from_env()
        .database_url
        .ok_or_else(|| "STARWEAVER_GATEWAY_DATABASE_URL is required".to_owned())?;
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
    "usage:\n  starweaver-gateway\n  starweaver-gateway migrate run\n  starweaver-gateway migrate check"
}
