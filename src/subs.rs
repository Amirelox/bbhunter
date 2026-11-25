use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::dnsx::{looks_wildcard, Resolver};
use crate::http::Http;
use crate::log;
use crate::scope::Scope;
use crate::util::{normalize_host, registrable};

pub const COMMON_SUBS: &[&str] = &[
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "dev",
    "staging",
    "stage",
    "stg",
    "test",
    "testing",
    "qa",
    "uat",
    "preprod",
    "prod",
    "demo",
    "sandbox",
    "beta",
    "alpha",
    "internal",
    "intranet",
    "vpn",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "ns1",
    "ns2",
    "ns3",
    "dns",
    "mx",
    "cdn",
    "static",
    "assets",
    "media",
    "img",
    "images",
    "files",
    "upload",
    "uploads",
    "download",
    "downloads",
    "docs",
    "doc",
    "wiki",
    "help",
    "support",
    "status",
    "monitor",
    "grafana",
    "kibana",
    "jenkins",
    "ci",
    "cd",
    "git",
    "gitlab",
    "github",
    "bitbucket",
    "jira",
    "confluence",
    "sonar",
    "nexus",
    "artifactory",
    "registry",
    "docker",
    "k8s",
    "kubernetes",
    "rancher",
    "console",
    "dashboard",
    "manage",
    "management",
    "backoffice",
    "partner",
    "partners",
    "customer",
    "customers",
    "client",
    "clients",
    "account",
    "accounts",
    "auth",
    "sso",
    "login",
    "id",
    "identity",
    "oauth",
    "pay",
    "payments",
    "billing",
    "invoice",
    "checkout",
    "shop",
    "store",
    "cart",
    "orders",
    "crm",
    "erp",
    "hr",
    "jobs",
    "careers",
    "blog",
    "news",
    "forum",
    "community",
    "app1",
    "app2",
    "web",
    "web1",
    "web2",
    "proxy",
    "gateway",
    "gw",
    "edge",
    "origin",
    "lb",
    "vpn1",
    "remote",
    "rdp",
    "ssh",
    "ftp",
    "sftp",
    "db",
    "database",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elastic",
    "elasticsearch",
    "kafka",
    "rabbitmq",
    "cache",
    "redis1",
    "s3",
    "storage",
    "backup",
    "bak",
    "old",
    "legacy",
    "v1",
    "v2",
    "api-v1",
    "api-v2",
    "graphql",
    "rest",
    "ws",
    "socket",
    "realtime",
    "search",
    "analytics",
    "metrics",
    "trace",
    "sentry",
    "logs",
    "logging",
    "vault",
    "secrets",
    "config",
    "private",
    "secure",
    "ssl",
    "dev1",
    "dev2",
    "test1",
    "test2",
    "staging1",
    "sandbox1",
    "preview",
    "review",
    "uat1",
];

#[derive(Debug, Default)]
pub struct SubReport {
    pub hosts: Vec<String>,
    pub by_source: BTreeMap<String, usize>,
    pub wildcard: Vec<String>,
}

fn valid_child(candidate: &str, root: &str) -> Option<String> {
    let host = normalize_host(candidate)?;
    let host = host.trim_start_matches("*.").to_string();
    if host == root || host.ends_with(&format!(".{root}")) {
        Some(host)
    } else {
        None
    }
}

async fn crtsh(http: &Http, root: &str) -> Vec<String> {
    let url = format!("https://crt.sh/?q=%25.{root}&output=json");
    let Ok(f) = http.get(&url).await else {
        log::warn("crt.sh unreachable, skipping");
        return Vec::new();
    };
    if f.status != 200 {
        log::warn(&format!("crt.sh returned HTTP {}", f.status));
        return Vec::new();
    }
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&f.body) else {
        log::warn("crt.sh returned non-JSON (probably rate limited)");
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    if let Some(rows) = json.as_array() {
        for row in rows {
            if let Some(names) = row.get("name_value").and_then(|v| v.as_str()) {
                for name in names.lines() {
                    if let Some(h) = valid_child(name, root) {
                        out.insert(h);
                    }
                }
            }
            if let Some(name) = row.get("common_name").and_then(|v| v.as_str()) {
                if let Some(h) = valid_child(name, root) {
                    out.insert(h);
                }
            }
        }
    }
    out.into_iter().collect()
}

async fn hackertarget(http: &Http, root: &str) -> Vec<String> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={root}");
    let Ok(f) = http.get(&url).await else {
        log::warn("hackertarget unreachable, skipping");
        return Vec::new();
    };
    if f.status != 200 || f.body.contains("API count exceeded") {
        log::warn("hackertarget quota/error, skipping");
        return Vec::new();
    }
    f.body
        .lines()
        .filter_map(|line| line.split(',').next())
        .filter_map(|h| valid_child(h, root))
        .collect()
}

async fn otx(http: &Http, root: &str) -> Vec<String> {
    let url = format!("https://otx.alienvault.com/api/v1/indicators/domain/{root}/passive_dns");
    let Ok(f) = http.get(&url).await else {
        log::warn("alienvault otx unreachable, skipping");
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&f.body) else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    if let Some(rows) = json.get("passive_dns").and_then(|v| v.as_array()) {
        for row in rows {
            if let Some(h) = row.get("hostname").and_then(|v| v.as_str()) {
                if let Some(h) = valid_child(h, root) {
                    out.insert(h);
                }
            }
        }
    }
    out.into_iter().collect()
}

async fn urlscan(http: &Http, root: &str) -> Vec<String> {
    let url = format!("https://urlscan.io/api/v1/search/?q=domain:{root}&size=1000");
    let Ok(f) = http.get(&url).await else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&f.body) else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    if let Some(rows) = json.get("results").and_then(|v| v.as_array()) {
        for row in rows {
            if let Some(h) = row
                .get("page")
                .and_then(|p| p.get("domain"))
                .and_then(|v| v.as_str())
            {
                if let Some(h) = valid_child(h, root) {
                    out.insert(h);
                }
            }
            if let Some(h) = row
                .get("task")
                .and_then(|t| t.get("domain"))
                .and_then(|v| v.as_str())
            {
                if let Some(h) = valid_child(h, root) {
                    out.insert(h);
                }
            }
        }
    }
    out.into_iter().collect()
}

async fn brute(
    resolver: &Resolver,
    root: &str,
    wordlist: Option<&Path>,
    wildcard: &[String],
    scope: &Scope,
) -> Vec<String> {
    let mut words: Vec<String> = COMMON_SUBS.iter().map(|s| s.to_string()).collect();
    if let Some(path) = wordlist {
        if let Ok(text) = std::fs::read_to_string(path) {
            words.extend(
                text.lines()
                    .map(|l| l.trim().to_ascii_lowercase())
                    .filter(|l| !l.is_empty() && !l.starts_with('#')),
            );
        } else {
            log::warn(&format!("cannot read wordlist {}", path.display()));
        }
    }
    words.sort();
    words.dedup();

    log::info(&format!("resolving {} brute-force candidates", words.len()));
    let mut out = Vec::new();
    for chunk in words.chunks(128) {
        let mut futs = Vec::new();
        for w in chunk {
            let host = if w.ends_with(root) {
                w.clone()
            } else {
                format!("{w}.{root}")
            };
            if !scope.allows(&host) {
                continue;
            }
            futs.push(async move {
                let info = resolver.resolve(&host).await;
                (host, info.ips)
            });
        }
        for (host, ips) in futures::future::join_all(futs).await {
            if !ips.is_empty() && !looks_wildcard(&ips, wildcard) {
                out.push(host);
            }
        }
    }
    out
}

pub async fn enumerate(
    http: &Http,
    resolver: &Resolver,
    target: &str,
    do_brute: bool,
    wordlist: Option<&Path>,
    scope: &Scope,
) -> Result<SubReport> {
    let root =
        registrable(&crate::util::normalize_host(target).unwrap_or_else(|| target.to_string()));
    let mut report = SubReport::default();
    let mut found: BTreeSet<String> = BTreeSet::new();

    log::stage(&format!("passive subdomain enumeration: {root}"));
    report.wildcard = resolver.wildcard_ips(&root).await;
    if !report.wildcard.is_empty() {
        log::warn(&format!(
            "wildcard DNS detected for *.{root} -> {}",
            report.wildcard.join(", ")
        ));
    }

    let sources: [(&str, futures::future::BoxFuture<'_, Vec<String>>); 4] = [
        ("crt.sh", Box::pin(crtsh(http, &root))),
        ("hackertarget", Box::pin(hackertarget(http, &root))),
        ("otx", Box::pin(otx(http, &root))),
        ("urlscan", Box::pin(urlscan(http, &root))),
    ];
    for (name, fut) in sources {
        let hits = fut.await;
        let before = found.len();
        found.extend(hits);
        let added = found.len() - before;
        report.by_source.insert(name.to_string(), added);
        log::info(&format!("{name}: {added} new"));
    }

    found.insert(root.clone());
    if do_brute {
        let extra = brute(resolver, &root, wordlist, &report.wildcard, scope).await;
        let before = found.len();
        found.extend(extra);
        report
            .by_source
            .insert("bruteforce".to_string(), found.len() - before);
        log::info(&format!("bruteforce: {} new", found.len() - before));
    }

    // Final safety net: never emit a host outside the allowlist.
    let (hosts, dropped) = scope.filter(found);
    if dropped > 0 {
        log::warn(&format!("scope filter dropped {dropped} discovered hosts"));
    }
    report.hosts = hosts;
    log::ok(&format!("{} unique subdomains", report.hosts.len()));
    Ok(report)
}
