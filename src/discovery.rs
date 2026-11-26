use std::sync::atomic::{AtomicBool, Ordering};

use futures::stream::{self, StreamExt};
use serde::Serialize;

use crate::findings::{Findings, Severity, Stage};
use crate::http::{Fetched, Http};
use crate::log;
use crate::probe::{title_of, HostResult};
use crate::scope::Scope;
use crate::util;

const LABELS: &[&str] = &[
    "admin",
    "administrator",
    "api",
    "app",
    "assets",
    "backup",
    "backups",
    "config",
    "dashboard",
    "debug",
    "dev",
    "docs",
    "download",
    "files",
    "internal",
    "login",
    "logs",
    "old",
    "panel",
    "private",
    "prod",
    "public",
    "staging",
    "static",
    "status",
    "test",
    "tmp",
    "uploads",
    "vendor",
];

const FILES: &[&str] = &[
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "db.sql",
    "dump.sql",
    "database.sql",
    "config.json",
    "package.json",
    "composer.json",
    "swagger.json",
    "openapi.json",
    "api/docs",
    "graphql",
    "robots.txt",
    "sitemap.xml",
    "security.txt",
    ".DS_Store",
];

pub fn default_paths() -> Vec<String> {
    let mut out: Vec<String> = LABELS.iter().map(|l| format!("/{l}/")).collect();
    out.extend(FILES.iter().map(|f| format!("/{f}")));
    out
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryHit {
    pub host: String,
    pub url: String,
    pub status: u16,
    pub size: usize,
    pub title: String,
    pub kind: String,
}

#[derive(Default)]
pub struct DiscoveryScan {
    pub hits: Vec<DiscoveryHit>,
    pub findings: Findings,
    pub checked: usize,
}

fn title(f: &Fetched) -> String {
    if f.is_html() {
        title_of(f)
    } else {
        String::new()
    }
}

fn looks_like_listing(f: &Fetched) -> bool {
    let title = title(f).to_ascii_lowercase();
    let body = f.body.to_ascii_lowercase();
    title.starts_with("index of") || body.contains("directory listing for")
}

fn kind_of(path: &str, f: &Fetched) -> (&'static str, Option<(Severity, &'static str)>) {
    let p = path.to_ascii_lowercase();
    if looks_like_listing(f) {
        return (
            "listing",
            Some((Severity::Low, "Włączone listowanie katalogu")),
        );
    }
    if [
        ".sql", ".bak", ".zip", ".tar.gz", ".tgz", ".old", ".swp", "~",
    ]
    .iter()
    .any(|ext| p.ends_with(ext))
    {
        return (
            "backup",
            Some((Severity::High, "Wystawiony plik kopii zapasowej")),
        );
    }
    if ["/config.json", "/package.json", "/composer.json"]
        .iter()
        .any(|x| p == *x)
    {
        return (
            "config",
            Some((Severity::Low, "Wystawiony plik konfiguracji projektu")),
        );
    }
    if [
        "/admin/",
        "/administrator/",
        "/dashboard/",
        "/panel/",
        "/login/",
        "/internal/",
        "/debug/",
    ]
    .iter()
    .any(|x| p == *x)
    {
        return (
            "panel",
            Some((Severity::Info, "Odnaleziony panel administracyjny")),
        );
    }
    if let Some(ext) = p.rsplit('.').next() {
        if ["js", "css", "map", "json", "xml", "txt"].contains(&ext) {
            return ("asset", None);
        }
    }
    ("other", None)
}

fn soft_404(base: (u16, String, usize), candidate: (u16, String, usize)) -> bool {
    if candidate.0 == 404 || candidate.0 == 410 || candidate.0 == 0 {
        return true;
    }
    candidate.0 == base.0
        && candidate.1 == base.1
        && candidate.2.abs_diff(base.2) <= (base.2 / 10).max(32)
}

async fn check_path(
    http: &Http,
    host: &str,
    url: String,
    path: String,
    baseline: (u16, String, usize),
) -> Option<(DiscoveryHit, Option<(Severity, &'static str)>)> {
    let fetched = http.fetch(&url, &[], 48_000).await.ok()?;
    let title = title(&fetched);
    let candidate = (fetched.status, title.clone(), fetched.body_len);
    if soft_404(baseline, candidate) {
        return None;
    }
    if !(fetched.status == 200
        || fetched.status == 201
        || fetched.status == 204
        || fetched.status == 301
        || fetched.status == 302
        || fetched.status == 401
        || fetched.status == 403)
    {
        return None;
    }
    let (kind, finding) = kind_of(&path, &fetched);
    Some((
        DiscoveryHit {
            host: host.to_string(),
            url: fetched.final_url.clone(),
            status: fetched.status,
            size: fetched.body_len,
            title,
            kind: kind.to_string(),
        },
        finding,
    ))
}

pub async fn scan(
    http: &Http,
    hosts: &[HostResult],
    limit: usize,
    paths: &[String],
    concurrency: usize,
    scope: &Scope,
    cancel: &AtomicBool,
) -> DiscoveryScan {
    let mut out = DiscoveryScan {
        findings: Findings::with_stage(Stage::Discovery),
        ..Default::default()
    };
    let paths: Vec<String> = if paths.is_empty() {
        default_paths()
    } else {
        paths
            .iter()
            .map(|p| {
                if p.starts_with('/') {
                    p.clone()
                } else {
                    format!("/{p}")
                }
            })
            .collect()
    };
    let mut picked = 0usize;
    for h in hosts
        .iter()
        .filter(|h| h.alias_of.is_none() && h.status > 0)
    {
        if picked >= limit.max(1) || cancel.load(Ordering::Relaxed) {
            break;
        }
        if !scope.allows(&util::host_of(&h.host).unwrap_or_else(|| h.host.clone())) {
            continue;
        }
        let Ok(mut base) = url::Url::parse(&h.final_url) else {
            continue;
        };
        base.set_path("/");
        base.set_query(None);
        base.set_fragment(None);
        let base = base.to_string();
        let base = base.trim_end_matches('/').to_string();
        let probe_path = format!("/bbhunter-{}.html", fastrand::u64(..));
        let baseline = match http
            .fetch(&format!("{base}{probe_path}"), &[], 32_000)
            .await
        {
            Ok(f) => (f.status, title(&f), f.body_len),
            Err(_) => continue,
        };
        picked += 1;
        out.checked += paths.len();
        let results = stream::iter(paths.iter().cloned().map(|path| {
            let url = format!("{base}{path}");
            check_path(http, &h.host, url, path, baseline.clone())
        }))
        .buffer_unordered(concurrency.clamp(1, 24))
        .filter_map(|x| async move { x })
        .collect::<Vec<_>>()
        .await;
        for (hit, finding) in results {
            log::plus(&format!("discovery {} (HTTP {})", hit.url, hit.status));
            if let Some((severity, title)) = finding {
                out.findings.add(
                    severity,
                    "discovery",
                    &hit.host,
                    &hit.url,
                    title,
                    format!("HTTP {} · {} B · {}", hit.status, hit.size, hit.kind),
                );
            }
            out.hits.push(hit);
        }
    }
    out.hits.sort_by(|a, b| a.url.cmp(&b.url));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_absolute() {
        let p = default_paths();
        assert!(p.iter().all(|x| x.starts_with('/')));
        assert!(p.contains(&"/admin/".to_string()));
        assert!(p.contains(&"/backup.zip".to_string()));
    }
}
