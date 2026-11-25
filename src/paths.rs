use futures::stream::{self, StreamExt};
use regex::Regex;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use crate::findings::{Findings, Severity, Stage};
use crate::http::{Fetched, Http};
use crate::log;
use crate::scope::Scope;
use crate::util;

static ENV_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=").unwrap());
static LOC_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<loc>\s*([^<\s]+)\s*</loc>").unwrap());
static DISALLOW_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?im)^\s*(?:allow|disallow|sitemap)\s*:\s*(\S+)").unwrap());

/// Every probe is a single GET for a well-known path. No payloads, no
/// mutation, no brute force beyond this fixed list.
const CHECKS: &[&str] = &[
    "/.git/HEAD",
    "/.git/config",
    "/.env",
    "/.env.local",
    "/.env.dev",
    "/.env.production",
    "/.DS_Store",
    "/.svn/entries",
    "/.aws/credentials",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.well-known/openid-configuration",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/metrics",
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/swagger-ui.html",
    "/swagger.json",
    "/v2/api-docs",
    "/openapi.json",
    "/api-docs",
    "/graphql",
    "/.well-known/change-password",
];

#[derive(Default)]
pub struct PathScan {
    pub findings: Findings,
    pub extra_urls: BTreeSet<String>,
    pub checked: usize,
    pub hits: usize,
}

fn looks_like_html(body: &str) -> bool {
    let head = body.trim_start().to_ascii_lowercase();
    head.starts_with("<!doctype html") || head.starts_with("<html") || head.contains("<body")
}

fn classify(path: &str, f: &Fetched) -> Option<(Severity, &'static str, &'static str)> {
    if f.status == 404 || f.status == 410 {
        return None;
    }
    // 401/403 means "exists but protected" for sensitive paths: worth an info line.
    let protected = f.status == 401 || f.status == 403;
    let ok = (200..300).contains(&f.status);
    let body = &f.body;
    let lower = body.to_ascii_lowercase();

    match path {
        "/.git/HEAD" => {
            if ok
                && body.trim_start().starts_with("ref:")
                && (body.contains("/heads/") || body.contains("refs/"))
            {
                Some((
                    Severity::High,
                    "exposed-git",
                    "Wystawiony .git/HEAD (ujawnienie źródeł)",
                ))
            } else {
                None
            }
        }
        "/.git/config" => {
            if ok && lower.contains("[core]") && lower.contains("repositoryformatversion") {
                Some((
                    Severity::High,
                    "exposed-git",
                    "Wystawiony .git/config (ujawnienie źródeł)",
                ))
            } else {
                None
            }
        }
        "/.env" | "/.env.local" | "/.env.dev" | "/.env.production" => {
            let env_like = ok && !looks_like_html(body) && ENV_RE.find_iter(body).count() >= 2;
            if !env_like {
                return None;
            }
            if [
                "aws_secret",
                "db_password",
                "database_url",
                "stripe",
                "jwt_secret",
                "smtp_pass",
            ]
            .iter()
            .any(|k| lower.contains(k))
            {
                Some((
                    Severity::High,
                    "exposed-config",
                    "Wystawiony .env z poświadczeniami",
                ))
            } else {
                Some((Severity::Medium, "exposed-config", "Wystawiony plik .env"))
            }
        }
        "/.DS_Store" => {
            if ok && (body.contains("Bud1") || body.starts_with("\u{0}\u{0}\u{0}\u{1}")) {
                Some((
                    Severity::Low,
                    "exposed-meta",
                    "Wystawiony .DS_Store (lista plików)",
                ))
            } else {
                None
            }
        }
        "/.svn/entries" => {
            if ok && !looks_like_html(body) && body.len() > 20 {
                Some((Severity::Medium, "exposed-vcs", "Wystawiony .svn/entries"))
            } else {
                None
            }
        }
        "/.aws/credentials" => {
            if ok && lower.contains("aws_access_key_id") {
                Some((
                    Severity::High,
                    "exposed-credentials",
                    "Wystawiony plik poświadczeń AWS",
                ))
            } else {
                None
            }
        }
        "/server-status" => {
            if ok && lower.contains("apache server status") {
                Some((
                    Severity::Medium,
                    "exposed-debug",
                    "Wystawiony Apache server-status",
                ))
            } else {
                None
            }
        }
        "/server-info" => {
            if ok && lower.contains("apache server information") {
                Some((
                    Severity::Medium,
                    "exposed-debug",
                    "Wystawiony Apache server-info",
                ))
            } else {
                None
            }
        }
        "/phpinfo.php" => {
            if ok && lower.contains("php version") && lower.contains("phpinfo()") {
                Some((Severity::Medium, "exposed-debug", "Wystawiony phpinfo()"))
            } else {
                None
            }
        }
        "/metrics" => {
            if ok && body.starts_with("# HELP") && body.contains("# TYPE") {
                Some((
                    Severity::Low,
                    "exposed-metrics",
                    "Wystawione metryki Prometheusa",
                ))
            } else {
                None
            }
        }
        "/actuator" => {
            if ok && lower.contains(r#""_links""#) && lower.contains("actuator") {
                Some((
                    Severity::Low,
                    "exposed-debug",
                    "Wystawiony indeks Spring Boot Actuator",
                ))
            } else {
                None
            }
        }
        "/actuator/env" => {
            if ok && lower.contains("propertysources") {
                Some((
                    Severity::High,
                    "exposed-config",
                    "Wystawiony Spring Actuator /env (sekrety, zmienne środowiskowe)",
                ))
            } else {
                None
            }
        }
        "/actuator/health" => {
            if ok && lower.contains("\"status\"") {
                Some((
                    Severity::Info,
                    "exposed-debug",
                    "Wystawiony Spring Actuator /health",
                ))
            } else {
                None
            }
        }
        "/swagger-ui.html" | "/swagger.json" | "/v2/api-docs" | "/openapi.json" | "/api-docs" => {
            if ok
                && (lower.contains("swagger")
                    || lower.contains("openapi")
                    || lower.contains("\"paths\""))
            {
                Some((
                    Severity::Info,
                    "api-docs",
                    "Wystawiona dokumentacja API (mapa powierzchni ataku)",
                ))
            } else {
                None
            }
        }
        "/graphql" => {
            if (ok || f.status == 400)
                && (lower.contains("graphql")
                    || lower.contains("must provide query string")
                    || lower.contains("\"errors\""))
            {
                Some((Severity::Info, "api-docs", "Wykryty endpoint GraphQL"))
            } else {
                None
            }
        }
        "/.well-known/openid-configuration" => {
            if ok && lower.contains("\"issuer\"") && lower.contains("authorization_endpoint") {
                Some((
                    Severity::Info,
                    "auth-surface",
                    "Wystawiona konfiguracja OpenID Connect",
                ))
            } else {
                None
            }
        }
        "/.well-known/security.txt" | "/security.txt" => {
            if ok && lower.contains("contact:") {
                Some((Severity::Info, "meta", "Plik security.txt obecny (dobrze)"))
            } else {
                None
            }
        }
        _ => {
            if protected {
                Some((
                    Severity::Info,
                    "auth-surface",
                    "Ścieżka istnieje, ale jest chroniona (401/403)",
                ))
            } else {
                None
            }
        }
    }
}

impl PathScan {
    pub fn merge(&mut self, other: PathScan) {
        self.extra_urls.extend(other.extra_urls);
        self.checked += other.checked;
        self.hits += other.hits;
        self.findings.merge(other.findings);
    }
}

pub async fn run(http: &Http, base: &str, scope: &Scope, extra: &[String]) -> PathScan {
    let mut scan = PathScan {
        findings: Findings::with_stage(Stage::Paths),
        ..PathScan::default()
    };
    let Some(host) = util::host_of(base) else {
        return scan;
    };
    if !scope.allows(&host) {
        return scan;
    }

    let mut paths: Vec<String> = CHECKS.iter().map(|p| (*p).to_string()).collect();
    for path in extra.iter().filter(|p| p.starts_with('/')).take(40) {
        if !paths.iter().any(|p| p == path) {
            paths.push(path.clone());
        }
    }

    let results: Vec<(String, anyhow::Result<crate::http::Fetched>)> =
        stream::iter(paths.into_iter())
            .map(|path| async move {
                let url = format!("{}{}", base.trim_end_matches('/'), path);
                let result = http.fetch(&url, &[], 300_000).await;
                (path, result)
            })
            .buffer_unordered(4)
            .collect()
            .await;

    for (path, result) in results {
        let Ok(f) = result else {
            continue;
        };
        scan.checked += 1;

        if path == "/robots.txt" && (200..300).contains(&f.status) && !f.body.contains("<html") {
            for cap in DISALLOW_RE.captures_iter(&f.body).take(200) {
                let entry = cap[1].trim();
                if entry.starts_with('/') && entry.len() > 1 {
                    scan.extra_urls
                        .insert(format!("{}{}", util::origin(&f.final_url), entry));
                } else if entry.starts_with("http") {
                    scan.extra_urls.insert(entry.to_string());
                }
            }
        }
        if path == "/sitemap.xml" && (200..300).contains(&f.status) {
            for cap in LOC_RE.captures_iter(&f.body).take(500) {
                if let Some(m) = cap.get(1) {
                    scan.extra_urls.insert(m.as_str().to_string());
                }
            }
        }

        // Generic directory listing, independent of the requested path.
        if (200..300).contains(&f.status) && f.is_html() {
            let lower = f.body.to_ascii_lowercase();
            if lower.contains("<title>index of /") || lower.contains("<title>directory listing for")
            {
                scan.hits += 1;
                scan.findings.add(
                    Severity::Low,
                    "directory-listing",
                    &host,
                    &f.final_url,
                    format!("Directory listing enabled at {path}"),
                    "Index page lists files; may expose backups or unrelated assets.",
                );
                continue;
            }
        }

        if let Some((severity, category, title)) = classify(&path, &f) {
            scan.hits += 1;
            scan.findings.add(
                severity,
                category,
                &host,
                &f.final_url,
                title.to_string(),
                format!("HTTP {} · {} B", f.status, f.body_len),
            );
            continue;
        }

        // Custom paths: existence only, no content classification.
        if !CHECKS.contains(&path.as_str()) {
            let ok = (200..300).contains(&f.status);
            let protected = f.status == 401 || f.status == 403;
            if !ok && !protected {
                continue;
            }
            let lower = f.body.to_ascii_lowercase();
            if ok && (lower.contains("not found") || lower.contains("nie znaleziono")) {
                continue;
            }
            scan.hits += 1;
            scan.findings.add(
                Severity::Info,
                "custom-rule",
                &host,
                &f.final_url,
                format!("Własna ścieżka odpowiada: {path}"),
                format!(
                    "HTTP {} · reguła użytkownika, bez walidacji treści",
                    f.status
                ),
            );
        }
    }

    scan
}

pub async fn run_many(
    http: &Http,
    bases: &[String],
    concurrency: usize,
    scope: &Scope,
    extra: &[String],
) -> PathScan {
    log::stage(&format!("low-hanging checks on {} hosts", bases.len()));
    let results: Vec<PathScan> = stream::iter(bases.iter().cloned())
        .map(|base| async move { run(http, &base, scope, extra).await })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut merged = PathScan {
        findings: Findings::with_stage(Stage::Paths),
        ..PathScan::default()
    };
    for mut r in results {
        merged.extra_urls.extend(std::mem::take(&mut r.extra_urls));
        merged.checked += r.checked;
        merged.hits += r.hits;
        merged.findings.merge(r.findings);
    }
    log::ok(&format!(
        "{} probes, {} interesting hits",
        merged.checked, merged.hits
    ));
    merged
}
