use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::header::{HeaderName, HeaderValue};
use serde::Serialize;

use crate::findings::{Findings, Severity, Stage};
use crate::http::{Fetched, Http};
use crate::log;
use crate::probe::{title_of, HostResult};
use crate::scope::Scope;
use crate::util;

const LABELS: &[&str] = &[
    "www",
    "api",
    "app",
    "admin",
    "portal",
    "dev",
    "staging",
    "test",
    "beta",
    "mail",
    "vpn",
    "intranet",
    "internal",
    "cdn",
    "static",
    "docs",
    "blog",
    "shop",
    "dashboard",
    "secure",
];

#[derive(Debug, Clone, Serialize)]
pub struct VhostHit {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub candidate: String,
    pub status: u16,
    pub title: String,
    pub evidence: String,
}

#[derive(Default)]
pub struct VhostScan {
    pub hits: Vec<VhostHit>,
    pub findings: Findings,
    pub discovered: BTreeSet<String>,
    pub checked: usize,
}

pub fn candidates(host: &str) -> Vec<String> {
    let hostname = util::host_of(host).unwrap_or_else(|| host.to_string());
    if util::is_ip(&hostname) || hostname == "localhost" {
        return Vec::new();
    }
    let root = util::registrable(&hostname);
    let mut out = BTreeSet::new();
    if root != hostname {
        out.insert(root.clone());
    }
    for label in LABELS {
        let name = format!("{label}.{root}");
        if name != hostname {
            out.insert(name);
        }
    }
    out.into_iter().collect()
}

fn title(f: &Fetched) -> String {
    if f.is_html() {
        title_of(f)
    } else {
        String::new()
    }
}

fn interesting(base: (u16, String, usize), candidate: (u16, String, usize)) -> bool {
    let (bs, bt, bl) = base;
    let (cs, ct, cl) = candidate;
    if cs == 404 || cs == 410 || cs == 0 {
        return false;
    }
    if cs == bs && ct == bt {
        let delta = bl.abs_diff(cl);
        if delta <= (bl / 5).max(32) {
            return false;
        }
    }
    true
}

async fn test_candidate(
    http: &Http,
    host: &str,
    ip: IpAddr,
    scheme: &str,
    port: u16,
    candidate: String,
    baseline: (u16, String, usize),
) -> Option<VhostHit> {
    let host_name = if ip.is_ipv6() {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    let url = format!("{scheme}://{host_name}:{port}/");
    let host_header = HeaderValue::from_str(&candidate).ok()?;
    let fetched = http
        .fetch(
            &url,
            &[(HeaderName::from_static("host"), host_header)],
            48_000,
        )
        .await
        .ok()?;
    let title = title(&fetched);
    let current = (fetched.status, title.clone(), fetched.body_len);
    if !interesting(baseline, current) {
        return None;
    }
    let evidence = format!(
        "IP {ip}:{port} · HTTP {} · {} · {} B",
        fetched.status,
        if title.is_empty() {
            "bez tytułu"
        } else {
            &title
        },
        fetched.body_len
    );
    Some(VhostHit {
        host: host.to_string(),
        ip: ip.to_string(),
        port,
        candidate,
        status: fetched.status,
        title,
        evidence,
    })
}

pub async fn scan(
    http: &Http,
    hosts: &[HostResult],
    limit: usize,
    concurrency: usize,
    timeout_secs: u64,
    scope: &Scope,
    cancel: &AtomicBool,
) -> VhostScan {
    let _ = Duration::from_secs(timeout_secs);
    let mut out = VhostScan {
        findings: Findings::with_stage(Stage::Vhosts),
        ..Default::default()
    };
    let mut picked = 0usize;
    for h in hosts
        .iter()
        .filter(|h| h.alias_of.is_none() && h.status > 0)
    {
        if picked >= limit.max(1) || cancel.load(Ordering::Relaxed) {
            break;
        }
        let Some(ip) = h.ips.iter().find_map(|v| v.parse::<IpAddr>().ok()) else {
            continue;
        };
        let Ok(base_url) = url::Url::parse(&h.final_url) else {
            continue;
        };
        let scheme = base_url.scheme().to_string();
        let port = base_url.port_or_known_default().unwrap_or(443);
        let candidates: Vec<String> = candidates(&h.host)
            .into_iter()
            .filter(|c| scope.allows(c))
            .take(24)
            .collect();
        if candidates.is_empty() {
            continue;
        }
        picked += 1;
        let baseline = match http.fetch(&h.final_url, &[], 48_000).await {
            Ok(f) => (f.status, title(&f), f.body_len),
            Err(_) => continue,
        };
        out.checked += 1 + candidates.len();
        let results = stream::iter(candidates.into_iter().map(|candidate| {
            test_candidate(
                http,
                &h.host,
                ip,
                &scheme,
                port,
                candidate,
                baseline.clone(),
            )
        }))
        .buffer_unordered(concurrency.clamp(1, 16))
        .filter_map(|x| async move { x })
        .collect::<Vec<_>>()
        .await;
        for hit in results {
            log::plus(&format!(
                "vhost {} → {} (HTTP {})",
                hit.host, hit.candidate, hit.status
            ));
            out.findings.add(
                Severity::Info,
                "vhost",
                &hit.host,
                &format!("{}://{}:{}/", scheme, hit.candidate, hit.port),
                format!("Wirtualny host odpowiada: {}", hit.candidate),
                hit.evidence.clone(),
            );
            out.discovered.insert(hit.candidate.clone());
            out.hits.push(hit);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidates_use_registrable_root() {
        let c = candidates("app.example.com");
        assert!(c.contains(&"www.example.com".to_string()));
        assert!(c.contains(&"example.com".to_string()));
        assert!(!c.contains(&"app.example.com".to_string()));
    }

    #[test]
    fn ip_targets_have_no_candidates() {
        assert!(candidates("127.0.0.1:8080").is_empty());
    }
}

#[cfg(test)]
mod runtime_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn sends_host_header_and_detects_other_vhost() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_ascii_lowercase();
            let body = if req.contains("host: www.app.localhost") {
                "<!doctype html><title>WWW admin</title>"
            } else {
                "<!doctype html><title>WRONG</title>"
            };
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes()).await;
        });
        let http = Http::new(2, 0, 3, None, &[]).unwrap();
        let hit = test_candidate(
            &http,
            "app.localhost",
            addr.ip(),
            "http",
            addr.port(),
            "www.app.localhost".to_string(),
            (404, String::new(), 0),
        )
        .await;
        let hit = hit.expect("vhost should be detected");
        assert_eq!(hit.title, "WWW admin");
    }
}
