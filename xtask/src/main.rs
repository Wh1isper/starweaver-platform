#![allow(
    missing_docs,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc
)]

use std::{
    env,
    ffi::OsStr,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

const PAGES_PROJECT_NAME: &str = "starweaver-platform-docs";
const SITE_URL: &str = "https://starweaver-platform-docs.pages.dev";

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
        "check-repository-scripts" => check_repository_scripts(&rest),
        "finalize-docs-site" => finalize_docs_site(&rest),
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: cargo run -p xtask -- <check-docs-examples|check-repository-scripts|finalize-docs-site>"
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
        ".github/workflows/pre-commit.yml",
        ".dockerignore",
        "docker-compose.yml",
        "book.toml",
        "crates/starweaver-gateway/Dockerfile",
        "docs/mermaid-init.js",
        "docs/SUMMARY.md",
        "docs/nav.json",
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
    validate_gateway_compose_support(&root)?;

    let images_workflow = fs::read_to_string(root.join(".github/workflows/images.yml"))
        .map_err(|error| error.to_string())?;
    for required in [
        "starweaver-gateway",
        "gcr.io",
        "GCP_PROJECT_ID",
        "GCP_WORKLOAD_IDENTITY_PROVIDER",
        "GCP_SERVICE_ACCOUNT",
        "Run gateway image smoke",
        "load: true",
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
