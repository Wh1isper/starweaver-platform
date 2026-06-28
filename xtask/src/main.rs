#![allow(
    missing_docs,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use starweaver_gateway::{
    ProtocolFamily,
    action::{ActionGrant, FoundationAuthorizationEngine},
    config::{
        PublishConfigSnapshotRequest, PublishedConfigSnapshot, ResourceVersion,
        publish_config_snapshot,
    },
    domain::{
        ActorKind, AuditEventRecord, AuthenticatedActor, CredentialKind, SecretRefRecord,
        UsageEventRecord,
    },
    replay::{GatewayReplayCase, foundation_route_replay_cases},
    route::foundation_routes,
    runtime::run_fake_provider_replay,
    storage::{
        BootstrapDefaultProjectRequest, ConfigSnapshotStore, CreateSecretRefRequest,
        InMemoryGatewayStore, SecretRefAdminRepository, TenancyBootstrapRepository,
        UsageAccountingRepository,
    },
};
use starweaver_platform::route::{
    RouteAccess as PlatformRouteAccess, foundation_routes as platform_foundation_routes,
};

const PAGES_PROJECT_NAME: &str = "starweaver-platform-docs";
const GATEWAY_EXTERNAL_API_PREFIX: &str = "/api";
const SITE_URL: &str = "https://starweaver-platform-docs.pages.dev";
const HARNESS_TENANT_ID: &str = "ten_harness";
const HARNESS_ORGANIZATION_ID: &str = "org_harness";
const HARNESS_PROJECT_ID: &str = "prj_harness";
const HARNESS_PRINCIPAL_ID: &str = "usr_harness";
const HARNESS_API_KEY_ID: &str = "ak_harness";
const HARNESS_MODEL_ALIAS_ID: &str = "ma_harness";
const MIGRATION_CHECKSUM_MANIFEST: &str = "release/migration-checksums.txt";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    let rest = args.collect::<Vec<_>>();
    match command.as_str() {
        "check-docs-examples" => check_docs_examples(&rest),
        "check-gateway-contracts" => check_gateway_contracts(&rest),
        "check-migration-checksums" => check_migration_checksums(&rest),
        "check-openapi" => check_openapi(&rest),
        "check-repository-scripts" => check_repository_scripts(&rest),
        "finalize-docs-site" => finalize_docs_site(&rest),
        "gateway-load-harness" => gateway_load_harness(&rest),
        "gateway-soak-harness" => gateway_soak_harness(&rest),
        "gateway-restore-rehearsal" => gateway_restore_rehearsal(&rest),
        "generate-migration-checksums" => generate_migration_checksums(&rest),
        "generate-openapi" => generate_openapi(&rest),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: cargo run -p xtask -- <check-docs-examples|check-gateway-contracts|check-migration-checksums|check-openapi|check-repository-scripts|finalize-docs-site|gateway-load-harness|gateway-soak-harness|gateway-restore-rehearsal|generate-migration-checksums|generate-openapi>"
        .to_string()
}

fn root() -> Result<PathBuf, String> {
    let current = env::current_dir().map_err(|error| error.to_string())?;
    if current.join("Cargo.toml").exists() {
        Ok(current)
    } else {
        Err("run xtask from the repository root".to_string())
    }
}

fn check_docs_examples(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("check-docs-examples takes no arguments".to_string());
    }

    let root = root()?;
    let docs = root.join("docs");
    let mut files = Vec::new();
    collect_files(&docs, "md", &mut files)?;
    if files.is_empty() {
        return Err("docs directory has no markdown files".to_string());
    }

    for file in &files {
        let text = fs::read_to_string(file).map_err(|error| error.to_string())?;
        validate_fenced_blocks(file, &text)?;
    }
    validate_summary_links(&docs)?;
    println!("Checked {} markdown files", files.len());
    Ok(())
}

fn validate_fenced_blocks(path: &Path, text: &str) -> Result<(), String> {
    let fence_count = text.match_indices("```").count();
    if fence_count.is_multiple_of(2) {
        Ok(())
    } else {
        Err(format!("unclosed fenced code block in {}", path.display()))
    }
}

fn validate_summary_links(docs: &Path) -> Result<(), String> {
    let summary_path = docs.join("SUMMARY.md");
    let summary = fs::read_to_string(&summary_path).map_err(|error| error.to_string())?;
    let mut rest = summary.as_str();
    while let Some(open) = rest.find("](") {
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find(')') else {
            return Err("malformed markdown link in docs/SUMMARY.md".to_string());
        };
        let link = &after_open[..close];
        if !link.starts_with("http") && !link.starts_with('#') {
            let target = docs.join(link);
            if !target.exists() {
                return Err(format!("docs/SUMMARY.md links to missing file: {link}"));
            }
        }
        rest = &after_open[close + 1..];
    }
    Ok(())
}

fn generate_openapi(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("generate-openapi takes no arguments".to_string());
    }

    let root = root()?;
    write_openapi_contracts(&root)?;
    println!("Generated OpenAPI contract files");
    Ok(())
}

fn generate_migration_checksums(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("generate-migration-checksums takes no arguments".to_string());
    }

    let root = root()?;
    let manifest = migration_checksum_manifest(&root)?;
    let path = root.join(MIGRATION_CHECKSUM_MANIFEST);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(path, manifest).map_err(|error| error.to_string())?;
    println!("Generated migration checksum manifest");
    Ok(())
}

fn check_migration_checksums(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("check-migration-checksums takes no arguments".to_string());
    }

    let root = root()?;
    let path = root.join(MIGRATION_CHECKSUM_MANIFEST);
    let existing = fs::read_to_string(&path).map_err(|error| {
        format!("{MIGRATION_CHECKSUM_MANIFEST} is missing or unreadable: {error}")
    })?;
    let expected = migration_checksum_manifest(&root)?;
    if existing != expected {
        return Err(format!(
            "{MIGRATION_CHECKSUM_MANIFEST} is stale; run `cargo run -p xtask -- generate-migration-checksums`"
        ));
    }
    println!("Checked migration checksum manifest");
    Ok(())
}

fn migration_checksum_manifest(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(
        &root.join("crates/starweaver-gateway/migrations"),
        "sql",
        &mut files,
    )?;
    collect_files(
        &root.join("crates/starweaver-platform/migrations"),
        "sql",
        &mut files,
    )?;
    if files.is_empty() {
        return Err("no migration SQL files found".to_string());
    }
    files.sort();

    let mut output = String::new();
    output.push_str("# Starweaver Platform Migration Checksums\n");
    output.push_str("# Generated by `cargo run -p xtask -- generate-migration-checksums`.\n");
    output.push_str("# Format: sha256  relative-path\n\n");
    for file in files {
        let bytes = fs::read(&file).map_err(|error| error.to_string())?;
        let digest = Sha256::digest(&bytes);
        let relative = file
            .strip_prefix(root)
            .map_err(|error| error.to_string())?
            .to_string_lossy()
            .replace('\\', "/");
        writeln!(&mut output, "{digest:x}  {relative}").map_err(|error| error.to_string())?;
    }
    Ok(output)
}

fn check_openapi(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("check-openapi takes no arguments".to_string());
    }

    let root = root()?;
    for (path, expected) in openapi_contracts() {
        let absolute_path = root.join(&path);
        let existing = fs::read_to_string(&absolute_path)
            .map_err(|error| format!("failed to read {}: {error}", absolute_path.display()))?;
        let existing_json = serde_json::from_str::<Value>(&existing)
            .map_err(|error| format!("invalid JSON in {}: {error}", absolute_path.display()))?;
        if existing_json != expected {
            return Err(format!(
                "{} is stale; run `cargo run -p xtask -- generate-openapi`",
                path.display()
            ));
        }
        validate_openapi_document(&existing_json, &path)?;
    }
    println!("Checked OpenAPI contract files");
    Ok(())
}

fn validate_openapi_document(document: &Value, path: &Path) -> Result<(), String> {
    if document.get("openapi").and_then(Value::as_str) != Some("3.1.0") {
        return Err(format!(
            "{} must be an OpenAPI 3.1 document",
            path.display()
        ));
    }
    let paths = document
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{} must contain an OpenAPI paths object", path.display()))?;
    if paths.is_empty() {
        return Err(format!("{} must declare at least one path", path.display()));
    }

    let mut operation_ids = BTreeSet::new();
    for (path_pattern, path_item) in paths {
        let methods = path_item
            .as_object()
            .ok_or_else(|| format!("{path_pattern} path item is not an object"))?;
        for (method, operation) in methods {
            validate_openapi_operation(path, path_pattern, method, operation, &mut operation_ids)?;
        }
    }
    Ok(())
}

fn validate_openapi_operation(
    document_path: &Path,
    path_pattern: &str,
    method: &str,
    operation: &Value,
    operation_ids: &mut BTreeSet<String>,
) -> Result<(), String> {
    let context = format!("{} {method} {path_pattern}", document_path.display());
    let object = operation
        .as_object()
        .ok_or_else(|| format!("{context} operation must be an object"))?;
    let operation_id = object
        .get("operationId")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} missing operationId"))?;
    if !operation_ids.insert(operation_id.to_owned()) {
        return Err(format!("{context} duplicates operationId {operation_id}"));
    }
    for extension in ["x-starweaver-action-id", "x-starweaver-resource-kind"] {
        if !object.contains_key(extension) {
            return Err(format!("{context} missing required extension {extension}"));
        }
    }
    let has_gateway_boundary = object.contains_key("x-starweaver-strong-auth-required")
        && object.contains_key("x-starweaver-allow-api-key");
    let has_platform_boundary = object.contains_key("x-starweaver-access")
        && object.contains_key("x-starweaver-user-actor-required");
    if !has_gateway_boundary && !has_platform_boundary {
        return Err(format!(
            "{context} missing gateway or platform access boundary extensions"
        ));
    }
    if !object
        .get("x-starweaver-action-id")
        .and_then(Value::as_str)
        .is_some_and(|action| action.contains('.'))
    {
        return Err(format!("{context} has invalid x-starweaver-action-id"));
    }
    if object
        .get("x-starweaver-resource-kind")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(format!("{context} has invalid x-starweaver-resource-kind"));
    }
    Ok(())
}

fn check_gateway_contracts(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("check-gateway-contracts takes no arguments".to_string());
    }

    let gateway_openapi = gateway_openapi_document();
    validate_gateway_route_contracts(&gateway_openapi)?;
    validate_gateway_replay_contracts(&gateway_openapi)?;
    println!(
        "Checked gateway contracts for {} routes and {} replay cases",
        foundation_routes().len(),
        foundation_route_replay_cases().len()
    );
    Ok(())
}

fn validate_gateway_route_contracts(gateway_openapi: &Value) -> Result<(), String> {
    let mut seen_routes = BTreeSet::new();
    let mut route_protocols = BTreeSet::new();
    for route in foundation_routes() {
        let route_key = format!("{} {}", route.method.as_str(), route.path_pattern);
        if !seen_routes.insert(route_key.clone()) {
            return Err(format!("duplicate gateway route contract: {route_key}"));
        }
        if route.action.resource_kind() != route.resource_kind {
            return Err(format!(
                "{route_key} action {} expects resource kind {}, route declares {}",
                route.action.as_str(),
                route.action.resource_kind(),
                route.resource_kind
            ));
        }
        if let Some(protocol_family) = route.protocol_family {
            route_protocols.insert(protocol_family.as_str());
        }
        let operation = openapi_operation(
            gateway_openapi,
            &gateway_external_path(route.path_pattern),
            &route.method.as_str().to_ascii_lowercase(),
        )?;
        validate_operation_extension(
            operation,
            "x-starweaver-canonical-path",
            route.path_pattern,
            &route_key,
        )?;
        validate_operation_extension(
            operation,
            "x-starweaver-action-id",
            route.action.as_str(),
            &route_key,
        )?;
        validate_operation_extension(
            operation,
            "x-starweaver-resource-kind",
            route.resource_kind,
            &route_key,
        )?;
        validate_operation_bool_extension(
            operation,
            "x-starweaver-allow-api-key",
            route.allow_api_key,
            &route_key,
        )?;
        validate_operation_bool_extension(
            operation,
            "x-starweaver-strong-auth-required",
            route.strong_auth_required,
            &route_key,
        )?;
        if let Some(protocol_family) = route.protocol_family {
            validate_operation_extension(
                operation,
                "x-starweaver-protocol-family",
                protocol_family.as_str(),
                &route_key,
            )?;
        }
    }

    let expected_protocols = ProtocolFamily::all()
        .iter()
        .map(|family| family.as_str())
        .collect::<BTreeSet<_>>();
    if route_protocols != expected_protocols {
        return Err(format!(
            "gateway route protocols {route_protocols:?} do not match expected {expected_protocols:?}"
        ));
    }
    Ok(())
}

fn validate_gateway_replay_contracts(gateway_openapi: &Value) -> Result<(), String> {
    let mut replay_names = BTreeSet::new();
    let mut replay_protocols = BTreeSet::new();
    let mut replay_case_count_by_route = BTreeMap::<String, usize>::new();
    for replay_case in foundation_route_replay_cases() {
        if !replay_names.insert(replay_case.name) {
            return Err(format!(
                "duplicate gateway replay case: {}",
                replay_case.name
            ));
        }
        replay_protocols.insert(replay_case.protocol_family.as_str());
        validate_gateway_replay_case(
            gateway_openapi,
            replay_case,
            &mut replay_case_count_by_route,
        )?;
    }

    let expected_protocols = ProtocolFamily::all()
        .iter()
        .map(|family| family.as_str())
        .collect::<BTreeSet<_>>();
    if replay_protocols != expected_protocols {
        return Err(format!(
            "gateway replay protocols {replay_protocols:?} do not match expected {expected_protocols:?}"
        ));
    }

    for route in foundation_routes()
        .iter()
        .filter(|route| route.protocol_family.is_some())
    {
        let route_key = gateway_route_key(route.protocol_family, route.action.as_str());
        if !replay_case_count_by_route.contains_key(&route_key) {
            return Err(format!(
                "gateway route {} {} has no replay contract",
                route.method.as_str(),
                route.path_pattern
            ));
        }
    }
    Ok(())
}

fn validate_gateway_replay_case(
    gateway_openapi: &Value,
    replay_case: &GatewayReplayCase,
    replay_case_count_by_route: &mut BTreeMap<String, usize>,
) -> Result<(), String> {
    let classified =
        starweaver_gateway::replay::classify_ingress(&replay_case.method, replay_case.ingress_path)
            .ok_or_else(|| format!("gateway replay case {} did not classify", replay_case.name))?;
    if classified != replay_case.protocol_family {
        return Err(format!(
            "gateway replay case {} classified as {}, expected {}",
            replay_case.name,
            classified.as_str(),
            replay_case.protocol_family.as_str()
        ));
    }

    let route = foundation_routes()
        .iter()
        .find(|route| {
            route.protocol_family == Some(replay_case.protocol_family)
                && route.action == replay_case.action
        })
        .ok_or_else(|| {
            format!(
                "gateway replay case {} has no route metadata",
                replay_case.name
            )
        })?;
    let route_key = gateway_route_key(route.protocol_family, route.action.as_str());
    *replay_case_count_by_route.entry(route_key).or_default() += 1;

    let operation = openapi_operation(
        gateway_openapi,
        &gateway_external_path(route.path_pattern),
        &route.method.as_str().to_ascii_lowercase(),
    )?;
    validate_operation_extension(
        operation,
        "x-starweaver-action-id",
        replay_case.action.as_str(),
        replay_case.name,
    )?;
    validate_operation_extension(
        operation,
        "x-starweaver-protocol-family",
        replay_case.protocol_family.as_str(),
        replay_case.name,
    )?;

    if replay_case.requires_native_grant
        && replay_case.protocol_family != ProtocolFamily::ProviderNative
    {
        return Err(format!(
            "gateway replay case {} requires native grant but is not provider-native",
            replay_case.name
        ));
    }
    Ok(())
}

fn gateway_route_key(protocol_family: Option<ProtocolFamily>, action: &str) -> String {
    format!(
        "{}:{action}",
        protocol_family.map_or("none", ProtocolFamily::as_str)
    )
}

fn openapi_operation<'a>(
    document: &'a Value,
    path_pattern: &str,
    method: &str,
) -> Result<&'a Value, String> {
    document
        .get("paths")
        .and_then(Value::as_object)
        .and_then(|paths| paths.get(path_pattern))
        .and_then(Value::as_object)
        .and_then(|path_item| path_item.get(method))
        .ok_or_else(|| format!("OpenAPI operation missing for {method} {path_pattern}"))
}

fn validate_operation_extension(
    operation: &Value,
    extension: &str,
    expected: &str,
    context: &str,
) -> Result<(), String> {
    let actual = operation
        .get(extension)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} missing string extension {extension}"))?;
    if actual != expected {
        return Err(format!(
            "{context} extension {extension} was {actual}, expected {expected}"
        ));
    }
    Ok(())
}

fn validate_operation_bool_extension(
    operation: &Value,
    extension: &str,
    expected: bool,
    context: &str,
) -> Result<(), String> {
    let actual = operation
        .get(extension)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{context} missing boolean extension {extension}"))?;
    if actual != expected {
        return Err(format!(
            "{context} extension {extension} was {actual}, expected {expected}"
        ));
    }
    Ok(())
}

fn write_openapi_contracts(root: &Path) -> Result<(), String> {
    for (path, document) in openapi_contracts() {
        let absolute_path = root.join(&path);
        if let Some(parent) = absolute_path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let rendered =
            serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
        fs::write(absolute_path, format!("{rendered}\n")).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn openapi_contracts() -> Vec<(PathBuf, Value)> {
    vec![
        (
            PathBuf::from("docs/openapi/gateway.openapi.json"),
            gateway_openapi_document(),
        ),
        (
            PathBuf::from("docs/openapi/platform.openapi.json"),
            platform_openapi_document(),
        ),
    ]
}

fn gateway_openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
    for route in foundation_routes() {
        let external_path = gateway_external_path(route.path_pattern);
        let method = route.method.as_str().to_ascii_lowercase();
        let operation = json!({
            "operationId": operation_id("gateway", route.method.as_str(), &external_path, route.action.as_str()),
            "tags": [gateway_route_tag(route.path_pattern)],
            "summary": format!("{} {}", route.method.as_str(), external_path),
            "parameters": path_parameters(&external_path),
            "requestBody": request_body(route.method.as_str()),
            "responses": standard_responses(),
            "security": [{"bearerAuth": []}],
            "x-starweaver-canonical-path": route.path_pattern,
            "x-starweaver-action-id": route.action.as_str(),
            "x-starweaver-resource-kind": route.resource_kind,
            "x-starweaver-scope-params": route.scope_params,
            "x-starweaver-allow-api-key": route.allow_api_key,
            "x-starweaver-strong-auth-required": route.strong_auth_required,
            "x-starweaver-audit-event-type": route.audit_event_type,
            "x-starweaver-protocol-family": route.protocol_family.map(ProtocolFamily::as_str),
        });
        insert_openapi_operation(&mut paths, &external_path, method, operation);
    }
    service_openapi_document(
        "Starweaver Gateway API",
        "External /api route metadata generated from starweaver-gateway foundation routes.",
        &paths,
    )
}

fn gateway_external_path(path_pattern: &str) -> String {
    format!("{GATEWAY_EXTERNAL_API_PREFIX}{path_pattern}")
}

fn platform_openapi_document() -> Value {
    let mut paths = serde_json::Map::new();
    for route in platform_foundation_routes() {
        let method = route.method.as_str().to_ascii_lowercase();
        let operation = json!({
            "operationId": operation_id("platform", route.method.as_str(), route.path_pattern, route.action.as_str()),
            "tags": [platform_route_tag(route.path_pattern)],
            "summary": format!("{} {}", route.method.as_str(), route.path_pattern),
            "parameters": path_parameters(route.path_pattern),
            "requestBody": request_body(route.method.as_str()),
            "responses": standard_responses(),
            "security": platform_security(route.access),
            "x-starweaver-action-id": route.action.as_str(),
            "x-starweaver-resource-kind": route.resource_kind,
            "x-starweaver-resource-id-path-param": route.resource_id_path_param,
            "x-starweaver-scope-path-params": route.scope_path_params,
            "x-starweaver-access": route.access.as_str(),
            "x-starweaver-user-actor-required": route.user_actor_required,
        });
        insert_openapi_operation(&mut paths, route.path_pattern, method, operation);
    }
    service_openapi_document(
        "Starweaver Platform API",
        "Route metadata generated from starweaver-platform foundation routes.",
        &paths,
    )
}

fn insert_openapi_operation(
    paths: &mut serde_json::Map<String, Value>,
    path_pattern: &str,
    method: String,
    operation: Value,
) {
    let path_item = paths
        .entry(path_pattern.to_owned())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    if let Value::Object(object) = path_item {
        object.insert(method, operation);
    }
}

fn service_openapi_document(
    title: &str,
    description: &str,
    paths: &serde_json::Map<String, Value>,
) -> Value {
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": env!("CARGO_PKG_VERSION"),
            "description": description,
        },
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                },
            },
            "schemas": {
                "ErrorEnvelope": {
                    "type": "object",
                    "additionalProperties": true,
                },
                "ResourceEnvelope": {
                    "type": "object",
                    "additionalProperties": true,
                },
            },
        },
    })
}

fn path_parameters(path_pattern: &str) -> Value {
    let mut parameters = Vec::new();
    let mut rest = path_pattern;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            break;
        };
        let name = &after_open[..close];
        parameters.push(json!({
            "name": name,
            "in": "path",
            "required": true,
            "schema": {"type": "string"},
        }));
        rest = &after_open[close + 1..];
    }
    json!(parameters)
}

fn request_body(method: &str) -> Value {
    if matches!(method, "POST" | "PATCH" | "PUT") {
        json!({
            "required": false,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "additionalProperties": true,
                    },
                },
            },
        })
    } else {
        Value::Null
    }
}

fn standard_responses() -> Value {
    json!({
        "200": {
            "description": "Request accepted by the service contract.",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/ResourceEnvelope",
                    },
                },
            },
        },
        "default": {
            "description": "Structured service error envelope.",
            "content": {
                "application/json": {
                    "schema": {
                        "$ref": "#/components/schemas/ErrorEnvelope",
                    },
                },
            },
        },
    })
}

fn platform_security(access: PlatformRouteAccess) -> Value {
    match access {
        PlatformRouteAccess::Public => json!([]),
        PlatformRouteAccess::Session | PlatformRouteAccess::Authorized => {
            json!([{"bearerAuth": []}])
        }
    }
}

fn gateway_route_tag(path_pattern: &str) -> &'static str {
    if path_pattern.starts_with("/admin/v1/") {
        "gateway-admin"
    } else {
        "gateway-runtime"
    }
}

fn platform_route_tag(path_pattern: &str) -> &'static str {
    if path_pattern.starts_with("/auth/v1/") {
        "platform-auth"
    } else if path_pattern.starts_with("/admin/v1/") {
        "platform-admin"
    } else {
        "platform-runtime"
    }
}

fn operation_id(service: &str, method: &str, path_pattern: &str, action: &str) -> String {
    let raw = format!("{service}_{method}_{path_pattern}_{action}");
    let mut output = String::with_capacity(raw.len());
    let mut last_was_separator = false;
    for character in raw.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            output.push('_');
            last_was_separator = true;
        }
    }
    output.trim_matches('_').to_owned()
}

fn check_repository_scripts(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("check-repository-scripts takes no arguments".to_string());
    }

    let root = root()?;
    for required in [
        "Makefile",
        ".pre-commit-config.yaml",
        ".github/workflows/ci.yml",
        ".github/workflows/docs.yml",
        ".github/workflows/images.yml",
        ".github/workflows/live-provider-smoke.yml",
        ".github/workflows/pre-commit.yml",
        ".dockerignore",
        "docker-compose.yml",
        "book.toml",
        "crates/starweaver-gateway/Dockerfile",
        "crates/starweaver-platform/Dockerfile",
        "docs/mermaid-init.js",
        "docs/openapi/gateway.openapi.json",
        "docs/openapi/platform.openapi.json",
        "docs/SUMMARY.md",
        "docs/nav.json",
        MIGRATION_CHECKSUM_MANIFEST,
    ] {
        if !root.join(required).exists() {
            return Err(format!(
                "missing repository infrastructure file: {required}"
            ));
        }
    }

    let docs_workflow = fs::read_to_string(root.join(".github/workflows/docs.yml"))
        .map_err(|error| error.to_string())?;
    if !docs_workflow.contains(PAGES_PROJECT_NAME) {
        return Err(format!(
            ".github/workflows/docs.yml does not deploy to {PAGES_PROJECT_NAME}"
        ));
    }
    validate_mermaid_docs_support(&root)?;
    validate_docs_static_headers(&root)?;
    validate_gateway_compose_support(&root)?;
    validate_live_provider_smoke_workflow(&root)?;
    check_migration_checksums(&[])?;
    check_openapi(&[])?;
    check_gateway_contracts(&[])?;

    let ci_workflow = fs::read_to_string(root.join(".github/workflows/ci.yml"))
        .map_err(|error| error.to_string())?;
    for required in [
        "runs-on: ubuntu-latest",
        "make scripts-check",
        "make migration-checksum-check",
        "make openapi-check",
        "make gateway-contract-check",
        "make gateway-harness-check",
    ] {
        if !ci_workflow.contains(required) {
            return Err(format!(
                ".github/workflows/ci.yml is missing required CI contract wiring: {required}"
            ));
        }
    }

    let images_workflow = fs::read_to_string(root.join(".github/workflows/images.yml"))
        .map_err(|error| error.to_string())?;
    for required in [
        "schedule:",
        "workflow_dispatch:",
        "release:",
        "types: [published]",
        "push:",
        "branches:",
        "- main",
        "tags:",
        "v*.*.*",
        "inputs.channel == 'nightly'",
        "inputs.channel == 'release'",
        "github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "github.ref == 'refs/heads/main'",
        "startsWith(github.ref, 'refs/tags/v')",
        "starweaver-gateway",
        "starweaver-platform",
        "crates/starweaver-platform/Dockerfile",
        "gcr.io",
        "GCP_PROJECT_ID",
        "GCP_WORKLOAD_IDENTITY_PROVIDER",
        "GCP_SERVICE_ACCOUNT",
        "token_format: access_token",
        "Validate release contract artifacts",
        "make migration-checksum-check openapi-check",
        "Run service image smoke",
        "load: true",
        "provenance: mode=max",
        "sbom: true",
        "actions/upload-artifact@v4",
        "docs/openapi/*.openapi.json",
        "release/migration-checksums.txt",
        "openapi-contracts.txt",
        "migration-checksums.txt",
        "SHA256SUMS",
        "find . -type f ! -name SHA256SUMS",
        "artifact_prefix: gateway",
        "artifact_prefix: platform",
        "-nightly-image-",
        "-release-image-",
    ] {
        if !images_workflow.contains(required) {
            return Err(format!(
                ".github/workflows/images.yml is missing required image publish wiring: {required}"
            ));
        }
    }

    println!("Checked repository infrastructure files");
    Ok(())
}

fn validate_live_provider_smoke_workflow(root: &Path) -> Result<(), String> {
    let workflow = fs::read_to_string(root.join(".github/workflows/live-provider-smoke.yml"))
        .map_err(|error| error.to_string())?;
    for required in [
        "workflow_dispatch:",
        "run-live-provider-smoke",
        "LIVE_GATEWAY_API_KEY",
        "gateway_url",
        "request_path",
        "request_body",
        "expected_status",
        "upload_redacted_response",
        "https://",
        "actions/upload-artifact@v4",
        "response-summary.json",
    ] {
        if !workflow.contains(required) {
            return Err(format!(
                ".github/workflows/live-provider-smoke.yml is missing required manual smoke wiring: {required}"
            ));
        }
    }
    if workflow.contains("pull_request:") || workflow.contains("push:") {
        return Err(
            ".github/workflows/live-provider-smoke.yml must remain manual-only".to_string(),
        );
    }
    Ok(())
}

fn validate_docs_static_headers(root: &Path) -> Result<(), String> {
    let headers =
        fs::read_to_string(root.join("docs/_headers")).map_err(|error| error.to_string())?;
    for required in [
        "/openapi/*.json",
        "Content-Type: application/json; charset=utf-8",
        "Cache-Control: public, max-age=300, must-revalidate",
    ] {
        if !headers.contains(required) {
            return Err(format!(
                "docs/_headers is missing required OpenAPI static header wiring: {required}"
            ));
        }
    }
    Ok(())
}

fn validate_gateway_compose_support(root: &Path) -> Result<(), String> {
    let compose =
        fs::read_to_string(root.join("docker-compose.yml")).map_err(|error| error.to_string())?;
    for required in [
        "postgres:",
        "redis:",
        "gateway-migrate:",
        "migrate\", \"run",
        "gateway:",
    ] {
        if !compose.contains(required) {
            return Err(format!(
                "docker-compose.yml is missing required gateway stack wiring: {required}"
            ));
        }
    }

    let makefile = fs::read_to_string(root.join("Makefile")).map_err(|error| error.to_string())?;
    for required in [
        "compose-up",
        "compose-down",
        "compose-migrate",
        "compose-smoke",
        "gateway-load-harness",
        "gateway-soak-harness",
        "gateway-restore-rehearsal",
        "migration-checksum-check",
        "gateway-contract-check",
        "docker-build-platform",
    ] {
        if !makefile.contains(required) {
            return Err(format!(
                "Makefile is missing required compose target: {required}"
            ));
        }
    }

    Ok(())
}

fn validate_mermaid_docs_support(root: &Path) -> Result<(), String> {
    let book_toml =
        fs::read_to_string(root.join("book.toml")).map_err(|error| error.to_string())?;
    if !book_toml.contains("additional-js = [\"docs/mermaid-init.js\"]") {
        return Err(
            "book.toml must include docs/mermaid-init.js as additional HTML JavaScript".into(),
        );
    }

    let mermaid_init =
        fs::read_to_string(root.join("docs/mermaid-init.js")).map_err(|error| error.to_string())?;
    for required in ["mermaid@11", "language-mermaid", "mermaid.run"] {
        if !mermaid_init.contains(required) {
            return Err(format!(
                "docs/mermaid-init.js is missing required Mermaid renderer wiring: {required}"
            ));
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct LoadHarnessOptions {
    iterations: usize,
    concurrency: usize,
}

#[derive(Clone, Copy, Debug)]
struct SoakHarnessOptions {
    duration_seconds: u64,
    concurrency: usize,
    interval_ms: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct GatewayHarnessSummary {
    iterations: usize,
    requests: usize,
    allowed: usize,
    denied: usize,
    streaming: usize,
    authorization_decisions: usize,
}

#[derive(Clone, Debug)]
struct GatewayRestoreBackup {
    config_snapshots: Vec<PublishedConfigSnapshot>,
    secret_refs: Vec<GatewaySecretRefBackup>,
    audit_events: Vec<AuditEventRecord>,
    usage_events: Vec<UsageEventRecord>,
}

#[derive(Clone, Debug)]
struct GatewaySecretRefBackup {
    record: SecretRefRecord,
    secret_value: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GatewayLedgerTotals {
    bucket_count: usize,
    request_count: i64,
    success_count: i64,
    input_tokens: i64,
    output_tokens: i64,
    estimated_cost_micros: i64,
}

impl GatewayHarnessSummary {
    const fn merge(&mut self, other: Self) {
        self.iterations += other.iterations;
        self.requests += other.requests;
        self.allowed += other.allowed;
        self.denied += other.denied;
        self.streaming += other.streaming;
        self.authorization_decisions += other.authorization_decisions;
    }
}

fn gateway_load_harness(args: &[String]) -> Result<(), String> {
    let options = parse_load_harness_options(args)?;
    let started = Instant::now();
    let summary = run_gateway_harness_load(options)?;
    print_gateway_harness_summary("load", summary, started.elapsed());
    Ok(())
}

fn gateway_soak_harness(args: &[String]) -> Result<(), String> {
    let options = parse_soak_harness_options(args)?;
    let started = Instant::now();
    let summary = run_gateway_harness_soak(options)?;
    print_gateway_harness_summary("soak", summary, started.elapsed());
    Ok(())
}

fn gateway_restore_rehearsal(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("gateway-restore-rehearsal takes no arguments".to_string());
    }

    let source = InMemoryGatewayStore::default();
    let now = chrono::Utc::now();
    seed_gateway_restore_source(&source, now)?;
    let backup = capture_gateway_restore_backup(&source)?;
    let restored = InMemoryGatewayStore::default();
    restore_gateway_backup(&restored, &backup);
    verify_gateway_restore(&source, &restored, &backup)?;
    println!(
        "gateway restore rehearsal completed: config_snapshots={} secret_refs={} audit_events={} usage_events={} ledger_buckets={}",
        backup.config_snapshots.len(),
        backup.secret_refs.len(),
        backup.audit_events.len(),
        backup.usage_events.len(),
        restored.ledger_buckets_for_tenant(HARNESS_TENANT_ID).len()
    );
    Ok(())
}

fn parse_load_harness_options(args: &[String]) -> Result<LoadHarnessOptions, String> {
    let mut options = LoadHarnessOptions {
        iterations: 36,
        concurrency: 4,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--iterations" => {
                options.iterations = parse_next_usize(args, &mut index, "--iterations")?;
            }
            "--concurrency" => {
                options.concurrency = parse_next_usize(args, &mut index, "--concurrency")?;
            }
            "--help" | "-h" => return Err(load_harness_usage()),
            other => return Err(format!("unknown gateway-load-harness argument: {other}")),
        }
        index += 1;
    }
    if options.iterations == 0 {
        return Err("gateway-load-harness requires --iterations greater than zero".to_string());
    }
    if options.concurrency == 0 {
        return Err("gateway-load-harness requires --concurrency greater than zero".to_string());
    }
    Ok(options)
}

fn parse_soak_harness_options(args: &[String]) -> Result<SoakHarnessOptions, String> {
    let mut options = SoakHarnessOptions {
        duration_seconds: 1,
        concurrency: 2,
        interval_ms: 25,
    };
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--duration-seconds" => {
                options.duration_seconds = parse_next_u64(args, &mut index, "--duration-seconds")?;
            }
            "--concurrency" => {
                options.concurrency = parse_next_usize(args, &mut index, "--concurrency")?;
            }
            "--interval-ms" => {
                options.interval_ms = parse_next_u64(args, &mut index, "--interval-ms")?;
            }
            "--help" | "-h" => return Err(soak_harness_usage()),
            other => return Err(format!("unknown gateway-soak-harness argument: {other}")),
        }
        index += 1;
    }
    if options.duration_seconds == 0 {
        return Err(
            "gateway-soak-harness requires --duration-seconds greater than zero".to_string(),
        );
    }
    if options.concurrency == 0 {
        return Err("gateway-soak-harness requires --concurrency greater than zero".to_string());
    }
    Ok(options)
}

fn parse_next_usize(args: &[String], index: &mut usize, flag: &str) -> Result<usize, String> {
    *index += 1;
    let Some(value) = args.get(*index) else {
        return Err(format!("{flag} requires a value"));
    };
    value
        .parse::<usize>()
        .map_err(|error| format!("{flag} must be a positive integer: {error}"))
}

fn parse_next_u64(args: &[String], index: &mut usize, flag: &str) -> Result<u64, String> {
    *index += 1;
    let Some(value) = args.get(*index) else {
        return Err(format!("{flag} requires a value"));
    };
    value
        .parse::<u64>()
        .map_err(|error| format!("{flag} must be a positive integer: {error}"))
}

fn load_harness_usage() -> String {
    "usage: cargo run -p xtask -- gateway-load-harness [--iterations N] [--concurrency N]"
        .to_string()
}

fn soak_harness_usage() -> String {
    "usage: cargo run -p xtask -- gateway-soak-harness [--duration-seconds N] [--concurrency N] [--interval-ms N]"
        .to_string()
}

fn seed_gateway_restore_source(
    store: &InMemoryGatewayStore,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    seed_gateway_restore_tenancy(store, now)?;
    let secret_ref = seed_gateway_restore_secret(store, now)?;
    seed_gateway_restore_config_snapshot(store, &secret_ref, now)?;
    record_gateway_restore_audit(store, now);
    record_gateway_restore_usage(store, now);
    Ok(())
}

fn seed_gateway_restore_tenancy(
    store: &InMemoryGatewayStore,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    store
        .bootstrap_default_project(
            BootstrapDefaultProjectRequest {
                tenant_id: HARNESS_TENANT_ID.to_owned(),
                tenant_display_name: "Harness Tenant".to_owned(),
                organization_id: HARNESS_ORGANIZATION_ID.to_owned(),
                organization_display_name: "Harness Organization".to_owned(),
                project_id: HARNESS_PROJECT_ID.to_owned(),
                project_display_name: "Harness Project".to_owned(),
                user_id: HARNESS_PRINCIPAL_ID.to_owned(),
                user_display_name: "Harness User".to_owned(),
                user_primary_email: Some("harness@example.com".to_owned()),
                organization_member_id: "om_harness".to_owned(),
                project_member_id: "pm_harness".to_owned(),
                created_by: HARNESS_PRINCIPAL_ID.to_owned(),
            },
            now,
        )
        .map_err(|error| format!("restore rehearsal tenancy seed failed: {error}"))
        .map(|_| ())
}

fn seed_gateway_restore_secret(
    store: &InMemoryGatewayStore,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<SecretRefRecord, String> {
    store
        .create_secret_ref(
            CreateSecretRefRequest {
                tenant_id: HARNESS_TENANT_ID.to_owned(),
                organization_id: Some(HARNESS_ORGANIZATION_ID.to_owned()),
                project_id: Some(HARNESS_PROJECT_ID.to_owned()),
                purpose: "restore rehearsal webhook signing".to_owned(),
                backend_kind: "memory".to_owned(),
                secret_value: SecretString::from("restore-rehearsal-secret-value".to_owned()),
                created_by: HARNESS_PRINCIPAL_ID.to_owned(),
            },
            now,
        )
        .map_err(|error| format!("restore rehearsal secret seed failed: {error}"))
}

fn seed_gateway_restore_config_snapshot(
    store: &InMemoryGatewayStore,
    secret_ref: &SecretRefRecord,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    publish_config_snapshot(
        store,
        PublishConfigSnapshotRequest {
            tenant_id: HARNESS_TENANT_ID.to_owned(),
            resource_versions: vec![ResourceVersion {
                resource_kind: "SecretRef".to_owned(),
                resource_id: secret_ref.secret_ref_id.clone(),
                version: secret_ref.resource_version,
            }],
            payload: json!({
                "secret_refs": [{
                    "id": secret_ref.secret_ref_id,
                    "purpose": "restore rehearsal webhook signing"
                }],
                "model_aliases": [{
                    "id": HARNESS_MODEL_ALIAS_ID,
                    "name": "restore-harness"
                }]
            }),
            created_by: HARNESS_PRINCIPAL_ID.to_owned(),
        },
        now,
    )
    .map_err(|error| format!("restore rehearsal config snapshot seed failed: {error}"))
    .map(|_| ())
}

fn record_gateway_restore_audit(store: &InMemoryGatewayStore, now: chrono::DateTime<chrono::Utc>) {
    store.record_audit_event(AuditEventRecord {
        audit_event_id: "aud_restore_rehearsal".to_owned(),
        event_type: "gateway.restore_rehearsal.seed".to_owned(),
        tenant_id: HARNESS_TENANT_ID.to_owned(),
        organization_id: Some(HARNESS_ORGANIZATION_ID.to_owned()),
        project_id: Some(HARNESS_PROJECT_ID.to_owned()),
        scope_kind: "project".to_owned(),
        scope_id: HARNESS_PROJECT_ID.to_owned(),
        resource_kind: "ConfigSnapshot".to_owned(),
        resource_id: HARNESS_MODEL_ALIAS_ID.to_owned(),
        before_version: None,
        after_version: Some(1),
        actor_id: HARNESS_PRINCIPAL_ID.to_owned(),
        actor_kind: ActorKind::User,
        principal_id: Some(HARNESS_PRINCIPAL_ID.to_owned()),
        request_id: "req_restore_rehearsal_audit".to_owned(),
        trace_id: "tr_restore_rehearsal_audit".to_owned(),
        redacted_diff: json!({
            "schema": "gateway.restore_rehearsal.audit.v1",
            "secret_ref_id": "sec_***",
            "raw_secret_included": false
        }),
        occurred_at: now,
    });
}

fn record_gateway_restore_usage(store: &InMemoryGatewayStore, now: chrono::DateTime<chrono::Utc>) {
    store.record_usage_event(UsageEventRecord {
        usage_event_id: "use_restore_rehearsal".to_owned(),
        tenant_id: HARNESS_TENANT_ID.to_owned(),
        organization_id: Some(HARNESS_ORGANIZATION_ID.to_owned()),
        project_id: Some(HARNESS_PROJECT_ID.to_owned()),
        principal_id: Some(HARNESS_PRINCIPAL_ID.to_owned()),
        project_member_id: Some("pm_harness".to_owned()),
        service_account_id: None,
        api_key_id: Some(HARNESS_API_KEY_ID.to_owned()),
        request_id: "req_restore_rehearsal_usage".to_owned(),
        trace_id: "tr_restore_rehearsal_usage".to_owned(),
        protocol_family: ProtocolFamily::OpenAiResponses,
        route_decision_id: Some("rd_restore_rehearsal".to_owned()),
        model_alias_id: Some(HARNESS_MODEL_ALIAS_ID.to_owned()),
        model_target_id: Some("mt_restore_rehearsal".to_owned()),
        route_policy_id: Some("rp_restore_rehearsal".to_owned()),
        routing_group_id: Some("rg_restore_rehearsal".to_owned()),
        provider_endpoint_id: Some("pep_restore_rehearsal".to_owned()),
        upstream_credential_id: Some("upc_restore_rehearsal".to_owned()),
        usage_confidence: "exact".to_owned(),
        latency_ms: Some(42),
        time_to_first_token_ms: Some(10),
        status: "success".to_owned(),
        usage_payload: json!({
            "input_tokens": 12,
            "output_tokens": 24,
            "total_tokens": 36,
            "reasoning_tokens": 0,
            "image_input_units": 0,
            "image_output_units": 0,
            "audio_input_units": 0,
            "audio_output_units": 0,
            "request_units": 0
        }),
        cost_payload: json!({
            "currency": "USD",
            "unit": "micro_usd",
            "total_cost": 1234,
            "pricing_version": "restore-rehearsal"
        }),
        occurred_at: now,
    });
}

fn capture_gateway_restore_backup(
    store: &InMemoryGatewayStore,
) -> Result<GatewayRestoreBackup, String> {
    let mut secret_refs = Vec::new();
    for record in store.secret_refs_for_tenant(HARNESS_TENANT_ID) {
        let secret_value = store
            .secret_value(&record.secret_ref_id)
            .ok_or_else(|| {
                format!(
                    "restore rehearsal secret {} has no backend value",
                    record.secret_ref_id
                )
            })?
            .expose_secret()
            .to_owned();
        secret_refs.push(GatewaySecretRefBackup {
            record,
            secret_value,
        });
    }
    Ok(GatewayRestoreBackup {
        config_snapshots: store.config_snapshots(),
        secret_refs,
        audit_events: store.audit_events_for_tenant(HARNESS_TENANT_ID),
        usage_events: store.usage_events_for_tenant(HARNESS_TENANT_ID),
    })
}

fn restore_gateway_backup(store: &InMemoryGatewayStore, backup: &GatewayRestoreBackup) {
    for snapshot in &backup.config_snapshots {
        store.insert_config_snapshot(snapshot.clone());
    }
    for secret_ref in &backup.secret_refs {
        store.restore_secret_ref(
            secret_ref.record.clone(),
            SecretString::from(secret_ref.secret_value.clone()),
        );
    }
    for audit_event in &backup.audit_events {
        store.record_audit_event(audit_event.clone());
    }
    for usage_event in &backup.usage_events {
        store.record_usage_event(usage_event.clone());
        store.record_usage_event(usage_event.clone());
    }
}

fn verify_gateway_restore(
    source: &InMemoryGatewayStore,
    restored: &InMemoryGatewayStore,
    backup: &GatewayRestoreBackup,
) -> Result<(), String> {
    if source.latest_published_snapshot_for_tenant(HARNESS_TENANT_ID)
        != restored.latest_published_snapshot_for_tenant(HARNESS_TENANT_ID)
    {
        return Err("restore rehearsal latest config snapshot mismatch".to_owned());
    }
    if source.config_snapshots() != restored.config_snapshots() {
        return Err("restore rehearsal config snapshot history mismatch".to_owned());
    }
    for secret_ref in &backup.secret_refs {
        let restored_record = restored
            .secret_ref(&secret_ref.record.secret_ref_id)
            .ok_or_else(|| {
                format!(
                    "restore rehearsal missing secret ref {}",
                    secret_ref.record.secret_ref_id
                )
            })?;
        if restored_record != secret_ref.record {
            return Err(format!(
                "restore rehearsal secret ref {} metadata mismatch",
                secret_ref.record.secret_ref_id
            ));
        }
        let restored_value = restored
            .secret_value(&secret_ref.record.secret_ref_id)
            .ok_or_else(|| {
                format!(
                    "restore rehearsal missing secret value {}",
                    secret_ref.record.secret_ref_id
                )
            })?;
        if restored_value.expose_secret() != secret_ref.secret_value {
            return Err(format!(
                "restore rehearsal secret value {} mismatch",
                secret_ref.record.secret_ref_id
            ));
        }
    }
    if source.audit_events_for_tenant(HARNESS_TENANT_ID)
        != restored.audit_events_for_tenant(HARNESS_TENANT_ID)
    {
        return Err("restore rehearsal audit evidence mismatch".to_owned());
    }
    if source.usage_events_for_tenant(HARNESS_TENANT_ID)
        != restored.usage_events_for_tenant(HARNESS_TENANT_ID)
    {
        return Err("restore rehearsal usage evidence mismatch".to_owned());
    }
    if ledger_totals(source) != ledger_totals(restored) {
        return Err("restore rehearsal ledger aggregate mismatch".to_owned());
    }
    let audit_text = serde_json::to_string(&restored.audit_events_for_tenant(HARNESS_TENANT_ID))
        .map_err(|error| format!("restore rehearsal audit serialization failed: {error}"))?;
    if audit_text.contains("restore-rehearsal-secret-value") {
        return Err("restore rehearsal leaked raw secret into audit evidence".to_owned());
    }
    Ok(())
}

fn ledger_totals(store: &InMemoryGatewayStore) -> GatewayLedgerTotals {
    let buckets = store.ledger_buckets_for_tenant(HARNESS_TENANT_ID);
    GatewayLedgerTotals {
        bucket_count: buckets.len(),
        request_count: buckets.iter().map(|bucket| bucket.request_count).sum(),
        success_count: buckets.iter().map(|bucket| bucket.success_count).sum(),
        input_tokens: buckets.iter().map(|bucket| bucket.input_tokens).sum(),
        output_tokens: buckets.iter().map(|bucket| bucket.output_tokens).sum(),
        estimated_cost_micros: buckets
            .iter()
            .map(|bucket| bucket.estimated_cost_micros)
            .sum(),
    }
}

fn run_gateway_harness_load(options: LoadHarnessOptions) -> Result<GatewayHarnessSummary, String> {
    let workers = options.concurrency.min(options.iterations);
    let chunk = options.iterations.div_ceil(workers);
    let worker_results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for worker_index in 0..workers {
            let start = worker_index * chunk;
            let end = options.iterations.min(start + chunk);
            if start >= end {
                continue;
            }
            handles.push(scope.spawn(move || run_gateway_harness_iterations(end - start)));
        }
        handles
            .into_iter()
            .map(std::thread::ScopedJoinHandle::join)
            .collect::<Vec<_>>()
    });
    merge_worker_results(worker_results)
}

fn run_gateway_harness_soak(options: SoakHarnessOptions) -> Result<GatewayHarnessSummary, String> {
    let deadline = Instant::now() + Duration::from_secs(options.duration_seconds);
    let interval = Duration::from_millis(options.interval_ms);
    let worker_results = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(options.concurrency);
        for _ in 0..options.concurrency {
            handles.push(scope.spawn(move || {
                let mut summary = GatewayHarnessSummary::default();
                while Instant::now() < deadline {
                    summary.merge(run_gateway_harness_iterations(1)?);
                    if !interval.is_zero() {
                        thread::sleep(interval);
                    }
                }
                Ok(summary)
            }));
        }
        handles
            .into_iter()
            .map(std::thread::ScopedJoinHandle::join)
            .collect::<Vec<_>>()
    });
    merge_worker_results(worker_results)
}

fn merge_worker_results(
    worker_results: Vec<std::thread::Result<Result<GatewayHarnessSummary, String>>>,
) -> Result<GatewayHarnessSummary, String> {
    let mut summary = GatewayHarnessSummary::default();
    for result in worker_results {
        let worker_summary =
            result.map_err(|_| "gateway harness worker panicked".to_string())??;
        summary.merge(worker_summary);
    }
    Ok(summary)
}

fn run_gateway_harness_iterations(iterations: usize) -> Result<GatewayHarnessSummary, String> {
    let mut summary = GatewayHarnessSummary::default();
    for iteration in 0..iterations {
        for replay_case in foundation_route_replay_cases() {
            run_gateway_harness_case(iteration, replay_case, &mut summary)?;
        }
        summary.iterations += 1;
    }
    Ok(summary)
}

fn run_gateway_harness_case(
    iteration: usize,
    replay_case: &GatewayReplayCase,
    summary: &mut GatewayHarnessSummary,
) -> Result<(), String> {
    let store = InMemoryGatewayStore::default();
    let response = run_fake_provider_replay(
        replay_case,
        &gateway_harness_engine(replay_case)?,
        &store,
        gateway_harness_actor(iteration),
        HARNESS_MODEL_ALIAS_ID,
        &json!({
            "model": HARNESS_MODEL_ALIAS_ID,
            "input": "fake provider harness request"
        }),
        chrono::Utc::now(),
    )
    .map_err(|error| format!("fake-provider replay {} failed: {error}", replay_case.name))?;

    let authorization_decisions = store.authorization_decisions();
    if authorization_decisions.len() != 1 {
        return Err(format!(
            "fake-provider replay {} recorded {} authorization decisions, expected 1",
            replay_case.name,
            authorization_decisions.len()
        ));
    }
    if response.protocol_family != replay_case.protocol_family {
        return Err(format!(
            "fake-provider replay {} returned protocol {}, expected {}",
            replay_case.name,
            response.protocol_family.as_str(),
            replay_case.protocol_family.as_str()
        ));
    }
    if response.streaming != replay_case.streaming {
        return Err(format!(
            "fake-provider replay {} streaming mismatch",
            replay_case.name
        ));
    }
    if replay_case.requires_native_grant && response.authorization.allowed {
        return Err(format!(
            "fake-provider replay {} unexpectedly allowed provider-native access",
            replay_case.name
        ));
    }
    if !replay_case.requires_native_grant && !response.authorization.allowed {
        return Err(format!(
            "fake-provider replay {} unexpectedly denied access: {}",
            replay_case.name, response.authorization.reason
        ));
    }

    summary.requests += 1;
    summary.authorization_decisions += authorization_decisions.len();
    if response.authorization.allowed {
        summary.allowed += 1;
    } else {
        summary.denied += 1;
    }
    if response.streaming {
        summary.streaming += 1;
    }
    Ok(())
}

fn gateway_harness_engine(
    replay_case: &GatewayReplayCase,
) -> Result<FoundationAuthorizationEngine, String> {
    let route = foundation_routes()
        .iter()
        .find(|route| {
            route.protocol_family == Some(replay_case.protocol_family)
                && route.action == replay_case.action
        })
        .ok_or_else(|| format!("replay case {} has no route metadata", replay_case.name))?;
    Ok(FoundationAuthorizationEngine::new(vec![
        ActionGrant::project(
            HARNESS_TENANT_ID,
            HARNESS_ORGANIZATION_ID,
            HARNESS_PROJECT_ID,
            HARNESS_PRINCIPAL_ID,
            replay_case.action,
            route.resource(HARNESS_MODEL_ALIAS_ID),
        ),
    ]))
}

fn gateway_harness_actor(iteration: usize) -> AuthenticatedActor {
    AuthenticatedActor {
        actor_id: HARNESS_API_KEY_ID.to_owned(),
        actor_kind: ActorKind::ApiKey,
        tenant_id: HARNESS_TENANT_ID.to_owned(),
        organization_id: Some(HARNESS_ORGANIZATION_ID.to_owned()),
        project_id: Some(HARNESS_PROJECT_ID.to_owned()),
        principal_id: Some(HARNESS_PRINCIPAL_ID.to_owned()),
        api_key_id: Some(HARNESS_API_KEY_ID.to_owned()),
        credential_kind: CredentialKind::ApiKey,
        auth_strength: 50,
        expires_at: None,
        api_key_allowed_actions: Vec::new(),
        api_key_allowed_resources: Vec::new(),
        request_id: format!("req_harness_{iteration}"),
        trace_id: format!("tr_harness_{iteration}"),
    }
}

fn print_gateway_harness_summary(
    harness_kind: &str,
    summary: GatewayHarnessSummary,
    elapsed: Duration,
) {
    println!(
        "gateway fake-provider {harness_kind} harness completed: iterations={} requests={} allowed={} denied={} streaming={} authorization_decisions={} elapsed_ms={}",
        summary.iterations,
        summary.requests,
        summary.allowed,
        summary.denied,
        summary.streaming,
        summary.authorization_decisions,
        elapsed.as_millis()
    );
}

fn finalize_docs_site(args: &[String]) -> Result<(), String> {
    if !args.is_empty() {
        return Err("finalize-docs-site takes no arguments".to_string());
    }

    let root = root()?;
    let book = root.join("book");
    if !book.exists() {
        return Err("book directory does not exist; run mdbook build first".to_string());
    }

    copy_if_exists(&root.join("docs/_headers"), &book.join("_headers"))?;
    copy_if_exists(&root.join("docs/nav.json"), &book.join("nav.json"))?;

    let mut urls = Vec::new();
    collect_html(&book, &book, &mut urls)?;
    urls.sort();
    let mut sitemap = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for url in &urls {
        writeln!(sitemap, "  <url><loc>{}</loc></url>", escape_xml(url))
            .map_err(|error| error.to_string())?;
    }
    sitemap.push_str("</urlset>\n");
    fs::write(book.join("sitemap.xml"), sitemap).map_err(|error| error.to_string())?;
    fs::write(
        book.join("robots.txt"),
        format!("User-agent: *\nAllow: /\nSitemap: {SITE_URL}/sitemap.xml\n"),
    )
    .map_err(|error| error.to_string())?;
    println!("Wrote sitemap.xml with {} URLs and robots.txt", urls.len());
    Ok(())
}

fn copy_if_exists(source: &Path, target: &Path) -> Result<(), String> {
    if source.exists() {
        fs::copy(source, target).map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn collect_html(root: &Path, dir: &Path, urls: &mut Vec<String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            collect_html(root, &path, urls)?;
        } else if path.extension() == Some(OsStr::new("html"))
            && path.file_name() != Some(OsStr::new("404.html"))
            && path.file_name() != Some(OsStr::new("toc.html"))
        {
            let relative = path
                .strip_prefix(root)
                .map_err(|error| error.to_string())?
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "index.html" {
                urls.push(format!("{SITE_URL}/"));
            } else {
                urls.push(format!("{SITE_URL}/{relative}"));
            }
        }
    }
    Ok(())
}

fn collect_files(dir: &Path, extension: &str, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            collect_files(&path, extension, files)?;
        } else if path.extension() == Some(OsStr::new(extension)) {
            files.push(path);
        }
    }
    files.sort();
    Ok(())
}

fn escape_xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
