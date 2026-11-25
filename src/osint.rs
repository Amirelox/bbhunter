use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::dnsx::Resolver;
use crate::http::Http;
use crate::log;
use crate::scope::Scope;
use crate::subs;
use crate::util;

const MAX_FAVICON: usize = 120_000;
const MAX_CLOUD_NAMES: usize = 15;

#[derive(Default, Serialize)]
pub struct OsintReport {
    pub domain: String,
    pub subdomains: Vec<String>,
    pub new_subdomains: Vec<String>,
    pub rdap: Option<Rdap>,
    pub asn: Vec<AsnInfo>,
    pub shodan: Vec<ShodanHost>,
    pub prefixes: Vec<String>,
    pub cloud: Vec<CloudHit>,
    pub code_hits: Vec<CodeHit>,
    pub favicons: Vec<FaviconGroup>,
    pub dorks: Vec<Dork>,
    pub notes: Vec<String>,
}

#[derive(Serialize)]
pub struct Rdap {
    pub registrar: Option<String>,
    pub registered: Option<String>,
    pub expires: Option<String>,
    pub nameservers: Vec<String>,
}

#[derive(Serialize)]
pub struct AsnInfo {
    pub ip: String,
    pub asn: u32,
    pub name: String,
    pub description: String,
    pub prefixes: Vec<String>,
}

#[derive(Default, Serialize)]
pub struct ShodanHost {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub vulns: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Serialize)]
pub struct CloudHit {
    pub provider: &'static str,
    pub name: String,
    pub url: String,
    pub status: u16,
    pub kind: &'static str,
}

#[derive(Serialize)]
pub struct CodeHit {
    pub source: &'static str,
    pub repo: String,
    pub path: String,
    pub url: String,
}

#[derive(Serialize)]
pub struct FaviconGroup {
    pub hash: i64,
    pub hosts: Vec<String>,
    pub related: Vec<String>,
}

#[derive(Serialize)]
pub struct Dork {
    pub engine: &'static str,
    pub label: &'static str,
    pub url: String,
}

pub struct Options {
    pub cloud: bool,
    pub dorks: bool,
    pub favicon: bool,
    pub favicon_hosts: usize,
    /// Skipped when recon already ran its own passive enumeration.
    pub skip_passive: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub subdomains: usize,
    pub new_subdomains: usize,
    pub cloud: usize,
    pub dorks: usize,
    pub code_hits: usize,
    pub favicons: usize,
}

impl OsintReport {
    pub fn summary(&self) -> Summary {
        Summary {
            subdomains: self.subdomains.len(),
            new_subdomains: self.new_subdomains.len(),
            cloud: self.cloud.len(),
            dorks: self.dorks.len(),
            code_hits: self.code_hits.len(),
            favicons: self.favicons.len(),
        }
    }
}

// --------------------------------------------------------------- źródła

async fn common_crawl(http: &Http, domain: &str) -> (Vec<String>, Option<String>) {
    let Ok(f) = http
        .fetch("https://index.commoncrawl.org/collinfo.json", &[], 200_000)
        .await
    else {
        return (
            Vec::new(),
            Some("Common Crawl: indeks niedostępny".to_string()),
        );
    };
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return (
            Vec::new(),
            Some("Common Crawl: niepoprawny collinfo".to_string()),
        );
    };
    // collinfo is ordered newest first.
    let Some(id) = v
        .as_array()
        .and_then(|a| a.first())
        .and_then(|x| x.get("id"))
        .and_then(|x| x.as_str())
    else {
        return (
            Vec::new(),
            Some("Common Crawl: brak identyfikatora indeksu".to_string()),
        );
    };
    let url = format!(
        "https://index.commoncrawl.org/{id}-index?url=*.{domain}&output=json&fl=url&collapse=urlkey&limit=3000"
    );
    let Ok(f) = http.fetch(&url, &[], 6_000_000).await else {
        return (
            Vec::new(),
            Some("Common Crawl: zapytanie nie powiodło się".to_string()),
        );
    };
    if f.status != 200 {
        return (Vec::new(), Some(format!("Common Crawl: HTTP {}", f.status)));
    }
    let mut out = BTreeSet::new();
    for line in f.body.lines() {
        let Ok(row) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if let Some(u) = row.get("url").and_then(|v| v.as_str()) {
            out.insert(u.to_string());
        }
    }
    (out.into_iter().collect(), None)
}

async fn security_trails(http: &Http, domain: &str) -> (Vec<String>, Option<String>) {
    let Some(key) = std::env::var("SECURITYTRAILS_API_KEY").ok() else {
        return (
            Vec::new(),
            Some("SecurityTrails: brak SECURITYTRAILS_API_KEY".to_string()),
        );
    };
    let url =
        format!("https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=false");
    let header = (
        reqwest::header::HeaderName::from_static("apikey"),
        reqwest::header::HeaderValue::from_str(&key)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
    );
    let Ok(f) = http.fetch(&url, &[header], 2_000_000).await else {
        return (
            Vec::new(),
            Some("SecurityTrails: request failed".to_string()),
        );
    };
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return (
            Vec::new(),
            Some(format!("SecurityTrails: HTTP {}", f.status)),
        );
    };
    let mut out = Vec::new();
    if let Some(rows) = v.get("subdomains").and_then(|x| x.as_array()) {
        for row in rows {
            if let Some(label) = row.as_str() {
                out.push(format!("{label}.{domain}"));
            }
        }
    }
    (out, None)
}

async fn virustotal(http: &Http, domain: &str) -> (Vec<String>, Option<String>) {
    let Some(key) = std::env::var("VT_API_KEY").ok() else {
        return (Vec::new(), Some("VirusTotal: brak VT_API_KEY".to_string()));
    };
    let url = format!("https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=100");
    let header = (
        reqwest::header::HeaderName::from_static("x-apikey"),
        reqwest::header::HeaderValue::from_str(&key)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
    );
    let Ok(f) = http.fetch(&url, &[header], 4_000_000).await else {
        return (Vec::new(), Some("VirusTotal: request failed".to_string()));
    };
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return (Vec::new(), Some(format!("VirusTotal: HTTP {}", f.status)));
    };
    let mut out = Vec::new();
    if let Some(rows) = v.get("data").and_then(|x| x.as_array()) {
        for row in rows {
            if let Some(id) = row.get("id").and_then(|x| x.as_str()) {
                out.push(id.to_string());
            }
        }
    }
    (out, None)
}

async fn shodan_dns(http: &Http, domain: &str) -> (Vec<String>, Option<String>) {
    let Some(key) = std::env::var("SHODAN_API_KEY").ok() else {
        return (
            Vec::new(),
            Some("Shodan DNS: brak SHODAN_API_KEY".to_string()),
        );
    };
    let url = format!(
        "https://api.shodan.io/dns/domain/{domain}?key={}",
        encoded(&key)
    );
    let Ok(f) = http.fetch(&url, &[], 4_000_000).await else {
        return (Vec::new(), Some("Shodan DNS: request failed".to_string()));
    };
    if f.status != 200 {
        return (Vec::new(), Some(format!("Shodan DNS: HTTP {}", f.status)));
    }
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return (Vec::new(), Some("Shodan DNS: bad JSON".to_string()));
    };
    let mut out = Vec::new();
    if let Some(rows) = v.get("data").and_then(|x| x.as_array()) {
        for row in rows {
            if let Some(sub) = row.get("subdomain").and_then(|x| x.as_str()) {
                out.push(format!("{sub}.{domain}"));
            }
        }
    }
    (out, None)
}

// --------------------------------------------------------------- RDAP

fn vcard_fn(entity: &Value) -> Option<String> {
    let props = entity.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    for prop in props {
        let prop = prop.as_array()?;
        if prop.first()?.as_str()? == "fn" {
            return prop.get(3)?.as_str().map(str::to_string);
        }
    }
    None
}

fn event_date(rdap: &Value, action: &str) -> Option<String> {
    rdap.get("events")?
        .as_array()?
        .iter()
        .find(|e| e.get("eventAction").and_then(|v| v.as_str()) == Some(action))
        .and_then(|e| e.get("eventDate").and_then(|v| v.as_str()))
        .map(str::to_string)
}

async fn rdap(http: &Http, domain: &str) -> Option<Rdap> {
    let f = http
        .fetch(&format!("https://rdap.org/domain/{domain}"), &[], 1_000_000)
        .await
        .ok()?;
    if f.status != 200 {
        return None;
    }
    let v: Value = serde_json::from_str(&f.body).ok()?;
    let registrar = v
        .get("entities")
        .and_then(|e| e.as_array())
        .and_then(|entities| {
            entities.iter().find_map(|entity| {
                let roles = entity.get("roles")?.as_array()?;
                let is_registrar = roles.iter().any(|r| r.as_str() == Some("registrar"));
                if is_registrar {
                    vcard_fn(entity)
                } else {
                    None
                }
            })
        });
    let mut nameservers = Vec::new();
    if let Some(list) = v.get("nameservers").and_then(|x| x.as_array()) {
        for ns in list {
            if let Some(name) = ns.get("ldhName").and_then(|x| x.as_str()) {
                nameservers.push(name.to_string());
            }
        }
    }
    Some(Rdap {
        registrar,
        registered: event_date(&v, "registration"),
        expires: event_date(&v, "expiration"),
        nameservers,
    })
}

// --------------------------------------------------------------- ASN

async fn asn_lookup(http: &Http, ip: &str) -> Option<AsnInfo> {
    // RIPE Stat is free and reliable for most announced addresses.
    if let Ok(f) = http
        .fetch(
            &format!("https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"),
            &[],
            1_000_000,
        )
        .await
    {
        if f.status == 200 {
            if let Ok(v) = serde_json::from_str::<Value>(&f.body) {
                let data = v.get("data")?;
                if let Some(first) = data
                    .get("asns")
                    .and_then(|a| a.as_array())
                    .and_then(|a| a.first())
                {
                    return Some(AsnInfo {
                        ip: ip.to_string(),
                        asn: first.get("asn").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                        name: first
                            .get("holder")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string(),
                        description: String::new(),
                        prefixes: data
                            .get("resource")
                            .and_then(|x| x.as_str())
                            .map(|p| vec![p.to_string()])
                            .unwrap_or_default(),
                    });
                }
            }
        }
    }

    // Fallback: hackertarget AS lookup, plain CSV.
    let f = http
        .fetch(
            &format!("https://api.hackertarget.com/aslookup/?q={ip}"),
            &[],
            200_000,
        )
        .await
        .ok()?;
    if f.status != 200 || f.body.contains("error") || f.body.contains("API count") {
        return None;
    }
    let fields: Vec<&str> = f
        .body
        .trim()
        .trim_matches('"')
        .split("\",\"")
        .map(|x| x.trim_matches('"'))
        .collect();
    if fields.len() < 3 {
        return None;
    }
    Some(AsnInfo {
        ip: ip.to_string(),
        asn: fields[1].parse().unwrap_or(0),
        name: fields[3.min(fields.len() - 1)].to_string(),
        description: String::new(),
        prefixes: vec![fields[2].to_string()],
    })
}

async fn internetdb(http: &Http, ip: &str) -> Option<ShodanHost> {
    let f = http
        .fetch(
            &format!("https://internetdb.shodan.io/{ip}"),
            &[],
            1_000_000,
        )
        .await
        .ok()?;
    if f.status != 200 {
        return None;
    }
    let v: Value = serde_json::from_str(&f.body).ok()?;
    let list = |key: &str| -> Vec<String> {
        v.get(key)
            .and_then(|x| x.as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(ShodanHost {
        ip: ip.to_string(),
        ports: v
            .get("ports")
            .and_then(|x| x.as_array())
            .map(|rows| {
                rows.iter()
                    .filter_map(|p| p.as_u64())
                    .map(|p| p as u16)
                    .collect()
            })
            .unwrap_or_default(),
        hostnames: list("hostnames"),
        vulns: list("vulns"),
        tags: list("tags"),
    })
}

// --------------------------------------------------------------- chmura

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn cloud_candidates(domain: &str) -> Vec<String> {
    let apex = util::registrable(domain);
    let label = apex.split('.').next().unwrap_or(&apex);
    let brand = sanitize_label(label);
    if brand.is_empty() {
        return Vec::new();
    }
    let suffixes = [
        "",
        "-dev",
        "-staging",
        "-test",
        "-prod",
        "-backup",
        "-assets",
        "-static",
        "-media",
        "-files",
        "-data",
        "-logs",
        "-internal",
        "-admin",
    ];
    let mut names: Vec<String> = suffixes.iter().map(|s| format!("{brand}{s}")).collect();
    names.push(format!("dev-{brand}"));
    names.sort();
    names.dedup();
    names.truncate(MAX_CLOUD_NAMES);
    names
}

async fn cloud_check(http: &Http, name: &str) -> Vec<CloudHit> {
    let mut hits = Vec::new();

    let s3 = format!("https://{name}.s3.amazonaws.com/");
    if let Ok(f) = http.head(&s3).await {
        match f.status {
            200 => hits.push(CloudHit {
                provider: "S3",
                name: name.to_string(),
                url: s3.clone(),
                status: 200,
                kind: "publiczna lista",
            }),
            403 => hits.push(CloudHit {
                provider: "S3",
                name: name.to_string(),
                url: s3.clone(),
                status: 403,
                kind: "istnieje, prywatny",
            }),
            _ => {}
        }
    }

    let gcs = format!("https://storage.googleapis.com/{name}");
    if let Ok(f) = http.head(&gcs).await {
        match f.status {
            200 => hits.push(CloudHit {
                provider: "GCS",
                name: name.to_string(),
                url: gcs.clone(),
                status: 200,
                kind: "publiczna lista",
            }),
            403 => hits.push(CloudHit {
                provider: "GCS",
                name: name.to_string(),
                url: gcs.clone(),
                status: 403,
                kind: "istnieje, prywatny",
            }),
            _ => {}
        }
    }

    let azure = format!("https://{name}.blob.core.windows.net/");
    if let Ok(f) = http.head(&azure).await {
        if (f.status == 400 || f.status == 403) && f.headers.contains_key("x-ms-request-id") {
            hits.push(CloudHit {
                provider: "Azure Blob",
                name: name.to_string(),
                url: azure.clone(),
                status: f.status,
                kind: "istnieje, prywatny",
            });
        }
    }

    hits
}

// --------------------------------------------------------------- kod

fn encoded(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn grep_app(http: &Http, domain: &str) -> (Vec<CodeHit>, Option<String>) {
    let query = format!("\"{domain}\"");
    let url = format!("https://grep.app/api/search?q={}", encoded(&query));
    let Ok(f) = http.fetch(&url, &[], 4_000_000).await else {
        return (Vec::new(), Some("grep.app: request failed".to_string()));
    };
    if f.status != 200 {
        return (Vec::new(), Some(format!("grep.app: HTTP {}", f.status)));
    }
    if f.body.trim_start().starts_with("<!DOCTYPE") || f.body.contains("Security Checkpoint") {
        return (
            Vec::new(),
            Some("grep.app: blokada bota (checkpoint), pominięto".to_string()),
        );
    }
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return (Vec::new(), Some("grep.app: bad JSON".to_string()));
    };
    let mut out = Vec::new();
    if let Some(rows) = v
        .get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(|h| h.as_array())
    {
        for row in rows.iter().take(15) {
            let repo = row
                .get("repo")
                .and_then(|r| r.get("raw"))
                .and_then(|r| r.as_str())
                .unwrap_or("");
            let path = row
                .get("path")
                .and_then(|p| p.get("raw"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            if repo.is_empty() && path.is_empty() {
                continue;
            }
            out.push(CodeHit {
                source: "grep.app",
                repo: repo.to_string(),
                path: path.to_string(),
                url: format!("https://grep.app/search?q={}", encoded(&query)),
            });
        }
    }
    (out, None)
}

async fn github_search(http: &Http, domain: &str) -> (Vec<CodeHit>, Option<String>) {
    let Some(token) = std::env::var("GITHUB_TOKEN").ok() else {
        return (
            Vec::new(),
            Some("GitHub code search: brak GITHUB_TOKEN (dork jest w liście)".to_string()),
        );
    };
    let q = format!("\"{domain}\" (password OR api_key OR secret OR token)");
    let url = format!(
        "https://api.github.com/search/code?q={}&per_page=10",
        encoded(&q)
    );
    let header = (
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static("")),
    );
    let Ok(f) = http
        .fetch(
            &url,
            &[
                header,
                (
                    reqwest::header::ACCEPT,
                    reqwest::header::HeaderValue::from_static("application/vnd.github+json"),
                ),
            ],
            2_000_000,
        )
        .await
    else {
        return (
            Vec::new(),
            Some("GitHub code search: request failed".to_string()),
        );
    };
    if f.status != 200 {
        return (
            Vec::new(),
            Some(format!("GitHub code search: HTTP {}", f.status)),
        );
    }
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return (Vec::new(), Some("GitHub code search: bad JSON".to_string()));
    };
    let mut out = Vec::new();
    if let Some(rows) = v.get("items").and_then(|x| x.as_array()) {
        for row in rows.iter().take(10) {
            out.push(CodeHit {
                source: "GitHub",
                repo: row
                    .get("repository")
                    .and_then(|r| r.get("full_name"))
                    .and_then(|r| r.as_str())
                    .unwrap_or("")
                    .to_string(),
                path: row
                    .get("path")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string(),
                url: row
                    .get("html_url")
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    (out, None)
}

// --------------------------------------------------------------- favicon

fn wrap76(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + input.len() / 76 + 1);
    for (i, ch) in input.chars().enumerate() {
        if i > 0 && i % 76 == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out.push('\n');
    out
}

/// MurmurHash3 x86 32-bit, the hash Shodan uses for `http.favicon.hash`.
fn mmh3_32(data: &[u8], seed: u32) -> u32 {
    let mut h = seed;
    let c1: u32 = 0xcc9e2d51;
    let c2: u32 = 0x1b873593;
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        k = k.wrapping_mul(c1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(c2);
        h ^= k;
        h = h.rotate_left(13);
        h = h.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }
    let tail = chunks.remainder();
    let mut k = 0u32;
    match tail.len() {
        3 => {
            k ^= (tail[2] as u32) << 16;
            k ^= (tail[1] as u32) << 8;
            k ^= tail[0] as u32;
        }
        2 => {
            k ^= (tail[1] as u32) << 8;
            k ^= tail[0] as u32;
        }
        1 => k ^= tail[0] as u32,
        _ => {}
    }
    if !tail.is_empty() {
        k = k.wrapping_mul(c1);
        k = k.rotate_left(15);
        k = k.wrapping_mul(c2);
        h ^= k;
    }
    h ^= data.len() as u32;
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

fn favicon_hash(bytes: &[u8]) -> i64 {
    let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
    let wrapped = wrap76(&b64);
    mmh3_32(wrapped.as_bytes(), 0) as i32 as i64
}

async fn fetch_favicon(http: &Http, target: &str) -> Option<i64> {
    let bases: Vec<String> = if target.starts_with("http://") || target.starts_with("https://") {
        vec![target.trim_end_matches('/').to_string()]
    } else {
        vec![
            format!("https://{}", target.trim_end_matches('/')),
            format!("http://{}", target.trim_end_matches('/')),
        ]
    };
    for base in bases {
        let Ok(f) = http
            .fetch(&format!("{base}/favicon.ico"), &[], MAX_FAVICON)
            .await
        else {
            continue;
        };
        if f.status < 400 && !f.bytes.is_empty() {
            return Some(favicon_hash(&f.bytes));
        }
    }
    None
}

async fn shodan_favicon(http: &Http, hash: i64, key: &str) -> Vec<String> {
    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query=http.favicon.hash%3A{}&fields=ip_str,hostnames",
        encoded(key),
        hash
    );
    let Ok(f) = http.fetch(&url, &[], 2_000_000).await else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&f.body) else {
        return Vec::new();
    };
    let mut out = BTreeSet::new();
    if let Some(rows) = v.get("matches").and_then(|x| x.as_array()) {
        for row in rows {
            if let Some(hosts) = row.get("hostnames").and_then(|x| x.as_array()) {
                for h in hosts {
                    if let Some(h) = h.as_str() {
                        out.insert(h.to_string());
                    }
                }
            }
        }
    }
    out.into_iter().take(50).collect()
}

// --------------------------------------------------------------- dorki

fn dorks(domain: &str) -> Vec<Dork> {
    let google = |q: String| format!("https://www.google.com/search?q={}", encoded(&q));
    let github = |q: String| format!("https://github.com/search?q={}&type=code", encoded(&q));
    let gitlab = |q: String| {
        format!(
            "https://gitlab.com/search?search={}&scope=blobs",
            encoded(&q)
        )
    };
    vec![
        Dork {
            engine: "Google",
            label: "pliki .env",
            url: google(format!("site:{domain} ext:env")),
        },
        Dork {
            engine: "Google",
            label: "kopie i backupy",
            url: google(format!(
                "site:{domain} (ext:bak OR ext:old OR ext:zip OR ext:sql)"
            )),
        },
        Dork {
            engine: "Google",
            label: "listing katalogów",
            url: google(format!("site:{domain} intitle:\"index of\"")),
        },
        Dork {
            engine: "Google",
            label: "panele i logowanie",
            url: google(format!("site:{domain} inurl:(admin OR login OR dashboard)")),
        },
        Dork {
            engine: "Google",
            label: "dokumenty i PDF",
            url: google(format!("site:{domain} (ext:pdf OR ext:docx OR ext:xlsx)")),
        },
        Dork {
            engine: "GitHub",
            label: "kod: hasła i klucze",
            url: github(format!(
                "\"{domain}\" (password OR api_key OR secret OR token)"
            )),
        },
        Dork {
            engine: "GitHub",
            label: "kod: konfiguracja",
            url: github(format!("\"{domain}\" (env OR config OR credentials)")),
        },
        Dork {
            engine: "GitLab",
            label: "kod w GitLabie",
            url: gitlab(domain.to_string()),
        },
        Dork {
            engine: "grep.app",
            label: "kod publiczny",
            url: format!("https://grep.app/search?q={}", encoded(domain)),
        },
        Dork {
            engine: "Shodan",
            label: "certyfikat SSL",
            url: format!(
                "https://www.shodan.io/search?query=ssl%3A%22{}%22",
                encoded(domain)
            ),
        },
        Dork {
            engine: "Censys",
            label: "hosty i certyfikaty",
            url: format!(
                "https://search.censys.io/search?resource=hosts&q={}",
                encoded(&format!("names: {domain}"))
            ),
        },
    ]
}

// --------------------------------------------------------------- orkiestracja

pub async fn run(
    http: &Http,
    resolver: &Resolver,
    scope: &Scope,
    domain: &str,
    hosts: &[String],
    opts: &Options,
) -> Result<OsintReport> {
    let mut report = OsintReport {
        domain: domain.to_string(),
        ..OsintReport::default()
    };
    let mut subs_all: BTreeSet<String> = BTreeSet::new();

    let domain_like = !util::is_ip(domain) && domain != "localhost";

    if !opts.skip_passive {
        log::stage(&format!("passive sources: {domain}"));
        match subs::enumerate(http, resolver, domain, false, None, scope).await {
            Ok(r) => subs_all.extend(r.hosts),
            Err(e) => report.notes.push(format!("passive enumeration: {e:#}")),
        }
    }

    if domain_like {
        log::info("Common Crawl index");
    }
    let (cc, cc_note) = if domain_like {
        common_crawl(http, domain).await
    } else {
        (Vec::new(), None)
    };
    if let Some(note) = cc_note {
        report.notes.push(note);
    }
    for url in &cc {
        if let Some(host) = util::host_of(url) {
            if host == domain || host.ends_with(&format!(".{domain}")) {
                subs_all.insert(host);
            }
        }
    }
    log::info(&format!("Common Crawl: {} URL-i", cc.len()));

    log::info("SecurityTrails / VirusTotal (jeśli klucze są w env)");
    let (st, st_note) = if domain_like {
        security_trails(http, domain).await
    } else {
        (Vec::new(), None)
    };
    if let Some(note) = st_note {
        report.notes.push(note);
    }
    for host in st {
        if let Some(h) = util::normalize_host(&host) {
            if scope.allows(&h) {
                subs_all.insert(h);
            }
        }
    }
    let (sh, sh_note) = if domain_like {
        shodan_dns(http, domain).await
    } else {
        (Vec::new(), None)
    };
    if let Some(note) = sh_note {
        report.notes.push(note);
    }
    for host in sh {
        if let Some(h) = util::normalize_host(&host) {
            if scope.allows(&h) {
                subs_all.insert(h);
            }
        }
    }
    let (vt, vt_note) = if domain_like {
        virustotal(http, domain).await
    } else {
        (Vec::new(), None)
    };
    if let Some(note) = vt_note {
        report.notes.push(note);
    }
    for host in vt {
        if let Some(h) = util::normalize_host(&host) {
            if scope.allows(&h) {
                subs_all.insert(h);
            }
        }
    }

    subs_all.insert(domain.to_string());
    report.subdomains = subs_all.iter().cloned().collect();
    let input: BTreeSet<String> = hosts.iter().cloned().collect();
    report.new_subdomains = report
        .subdomains
        .iter()
        .filter(|h| !input.contains(*h))
        .cloned()
        .collect();
    log::ok(&format!(
        "{} subdomen, {} nowych względem wejścia",
        report.subdomains.len(),
        report.new_subdomains.len()
    ));

    log::stage("RDAP / WHOIS");
    match if domain_like {
        rdap(http, domain).await
    } else {
        None
    } {
        Some(r) => {
            log::ok(&format!(
                "rejestrator: {}",
                r.registrar.as_deref().unwrap_or("nieznany")
            ));
            report.rdap = Some(r);
        }
        None => report.notes.push("RDAP: brak odpowiedzi".to_string()),
    }

    log::stage("ASN, prefiksy, Shodan InternetDB");
    let mut ips: BTreeSet<String> = BTreeSet::new();
    for host in std::iter::once(domain.to_string()).chain(hosts.iter().take(5).cloned()) {
        let bare = util::normalize_host(&host).unwrap_or(host);
        for ip in resolver.resolve(&bare).await.ips {
            ips.insert(ip);
        }
    }
    for ip in ips.iter().take(4) {
        if let Some(info) = asn_lookup(http, ip).await {
            for prefix in &info.prefixes {
                if !report.prefixes.contains(prefix) {
                    report.prefixes.push(prefix.clone());
                }
            }
            report.asn.push(info);
        }
        if let Some(host) = internetdb(http, ip).await {
            report.shodan.push(host);
        }
    }
    log::ok(&format!(
        "{} IP, {} ASN, {} prefiksów",
        ips.len(),
        report.asn.len(),
        report.prefixes.len()
    ));

    if opts.cloud && domain_like {
        log::stage("Kandydaci nazw w chmurze (S3 / GCS / Azure)");
        let names = cloud_candidates(domain);
        for name in &names {
            let hits = cloud_check(http, name).await;
            for hit in hits {
                log::ok(&format!("{}: {} ({})", hit.provider, hit.name, hit.kind));
                report.cloud.push(hit);
            }
        }
        log::ok(&format!(
            "{} kandydatów, {} istniejących nazw",
            names.len(),
            report.cloud.len()
        ));
        report.notes.push(
            "Nazwy w chmurze to kandydaci z permutacji domeny; istnienie nie potwierdza własności."
                .to_string(),
        );
    }

    if opts.dorks && domain_like {
        report.dorks = dorks(domain);
        let (grep_hits, grep_note) = grep_app(http, domain).await;
        if let Some(note) = grep_note {
            report.notes.push(note);
        }
        report.code_hits.extend(grep_hits);
        let (gh_hits, gh_note) = github_search(http, domain).await;
        if let Some(note) = gh_note {
            report.notes.push(note);
        }
        report.code_hits.extend(gh_hits);
        log::ok(&format!(
            "{} dorków, {} trafień w kodzie",
            report.dorks.len(),
            report.code_hits.len()
        ));
    }

    if opts.favicon && !hosts.is_empty() {
        log::stage("Favicon hash (Shodan)");
        let key = std::env::var("SHODAN_API_KEY").ok();
        let mut groups: BTreeMap<i64, Vec<String>> = BTreeMap::new();
        for host in hosts.iter().take(opts.favicon_hosts.max(1)) {
            if let Some(hash) = fetch_favicon(http, host).await {
                groups.entry(hash).or_default().push(host.clone());
            }
        }
        for (hash, group_hosts) in groups {
            let related = match &key {
                Some(key) => shodan_favicon(http, hash, key).await,
                None => Vec::new(),
            };
            report.favicons.push(FaviconGroup {
                hash,
                hosts: group_hosts,
                related,
            });
        }
        if report.favicons.is_empty() {
            report
                .notes
                .push("Favicon: nie pobrano żadnej ikony".to_string());
        } else if key.is_none() {
            report
                .notes
                .push("Favicon: brak SHODAN_API_KEY, więc bez wyszukiwania po hashach".to_string());
        }
        log::ok(&format!("{} grup favicon", report.favicons.len()));
    }

    Ok(report)
}

// --------------------------------------------------------------- artefakty

fn write_list(path: impl AsRef<Path>, items: impl IntoIterator<Item = String>) -> Result<()> {
    let path = path.as_ref();
    let mut buf = String::new();
    for item in items {
        buf.push_str(&item);
        buf.push('\n');
    }
    std::fs::write(path, buf).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

pub fn write_artifacts(dir: &Path, report: &OsintReport) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join("osint.md"), markdown(report))?;
    std::fs::write(
        dir.join("osint.json"),
        serde_json::to_string_pretty(report)?,
    )?;
    write_list(
        dir.join("subdomains.txt"),
        report.subdomains.iter().cloned(),
    )?;
    write_list(
        dir.join("cloud.txt"),
        report
            .cloud
            .iter()
            .map(|c| format!("{}\t{}\t{}\t{}", c.provider, c.name, c.status, c.kind)),
    )?;
    write_list(
        dir.join("dorks.txt"),
        report
            .dorks
            .iter()
            .map(|d| format!("{}\t{}\t{}", d.engine, d.label, d.url)),
    )?;
    write_list(
        dir.join("favicons.txt"),
        report
            .favicons
            .iter()
            .map(|f| format!("{}\t{}", f.hash, f.hosts.join(","))),
    )?;
    Ok(())
}

// --------------------------------------------------------------- markdown

pub fn markdown(report: &OsintReport) -> String {
    let mut md = String::new();
    md.push_str(&format!("# OSINT — {}\n\n", report.domain));
    md.push_str(&format!(
        "- Subdomeny: {} ({} nowych względem wejścia)\n",
        report.subdomains.len(),
        report.new_subdomains.len()
    ));

    if let Some(rdap) = &report.rdap {
        md.push_str("\n## RDAP\n\n");
        if let Some(r) = &rdap.registrar {
            md.push_str(&format!("- Rejestrator: {r}\n"));
        }
        if let Some(d) = &rdap.registered {
            md.push_str(&format!("- Rejestracja: {d}\n"));
        }
        if let Some(d) = &rdap.expires {
            md.push_str(&format!("- Wygasa: {d}\n"));
        }
        if !rdap.nameservers.is_empty() {
            md.push_str(&format!("- Nameservery: {}\n", rdap.nameservers.join(", ")));
        }
    }

    if !report.asn.is_empty() {
        md.push_str("\n## ASN i prefiksy\n\n");
        for asn in &report.asn {
            md.push_str(&format!(
                "- `{}` · AS{} {} — {}\n",
                asn.ip, asn.asn, asn.name, asn.description
            ));
        }
        if !report.prefixes.is_empty() {
            md.push_str(&format!("\nPrefiksy: {}\n", report.prefixes.join(", ")));
        }
    }

    if !report.shodan.is_empty() {
        md.push_str("\n## Shodan InternetDB (bez klucza)\n\n");
        for host in &report.shodan {
            md.push_str(&format!(
                "- `{}` · porty: {} · hosty: {}\n",
                host.ip,
                host.ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                if host.hostnames.is_empty() {
                    "—".to_string()
                } else {
                    host.hostnames.join(", ")
                }
            ));
            if !host.vulns.is_empty() {
                md.push_str(&format!("  - podatności: {}\n", host.vulns.join(", ")));
            }
        }
    }

    if !report.cloud.is_empty() {
        md.push_str("\n## Zasoby chmurowe (weryfikacja własności wymagana)\n\n");
        md.push_str("| Dostawca | Nazwa | Status | Typ |\n|---|---|---|---|\n");
        for hit in &report.cloud {
            md.push_str(&format!(
                "| {} | `{}` | {} | {} |\n",
                hit.provider, hit.name, hit.status, hit.kind
            ));
        }
    }

    if !report.code_hits.is_empty() {
        md.push_str("\n## Kod publiczny (grep.app / GitHub)\n\n");
        for hit in &report.code_hits {
            md.push_str(&format!(
                "- {} · `{}` · {}\n",
                hit.source, hit.repo, hit.path
            ));
        }
    }

    if !report.favicons.is_empty() {
        md.push_str("\n## Favicony\n\n");
        for group in &report.favicons {
            md.push_str(&format!(
                "- hash `{}` · hosty: {}\n",
                group.hash,
                group.hosts.join(", ")
            ));
            if !group.related.is_empty() {
                md.push_str(&format!(
                    "  - powiązane (Shodan): {}\n",
                    group.related.join(", ")
                ));
            }
        }
    }

    if !report.dorks.is_empty() {
        md.push_str("\n## Dorki\n\n");
        for dork in &report.dorks {
            md.push_str(&format!(
                "- **{}** — [{}]({})\n",
                dork.engine, dork.label, dork.url
            ));
        }
    }

    if !report.notes.is_empty() {
        md.push_str("\n## Uwagi\n\n");
        for note in &report.notes {
            md.push_str(&format!("- {note}\n"));
        }
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mmh3_known_vectors() {
        assert_eq!(mmh3_32(b"", 0), 0);
        assert_eq!(mmh3_32(b"hello", 0), 613_153_351);
        assert_eq!(mmh3_32(b"foo", 0), 4_138_058_784); // -156908512 as u32
    }

    #[test]
    fn favicon_hash_is_stable() {
        let a = favicon_hash(b"\x00\x01\x02\x03favicon-bytes");
        let b = favicon_hash(b"\x00\x01\x02\x03favicon-bytes");
        assert_eq!(a, b);
        assert!(a != 0);
    }

    #[test]
    fn cloud_candidates_are_deduped_and_bounded() {
        let names = cloud_candidates("allegro.pl");
        assert!(names.contains(&"allegro".to_string()));
        assert!(names.contains(&"allegro-dev".to_string()));
        assert!(names.len() <= MAX_CLOUD_NAMES);
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    #[test]
    fn dorks_include_github_and_google() {
        let list = dorks("example.com");
        assert!(list.iter().any(|d| d.engine == "GitHub"));
        assert!(list.iter().any(|d| d.engine == "Google"));
        assert!(list.iter().all(|d| d.url.starts_with("https://")));
    }
}
