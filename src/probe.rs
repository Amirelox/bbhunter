use colored::Colorize;
use futures::future::join_all;
use futures::stream::{self, StreamExt};
use reqwest::header::{HeaderName, HeaderValue};
use scraper::{Html, Selector};
use serde::Serialize;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::LazyLock;

use crate::dnsx::Resolver;
use crate::findings::{Findings, Severity, Stage};
use crate::http::{Fetched, Http, CORS_ORIGIN};
use crate::log;
use crate::tech;
use crate::util::{one_line, truncate};
/// A deliberately non-resolvable origin: if a server reflects it back in
/// Access-Control-Allow-Origin it will also reflect `https://attacker.example`.
const CORS_SENTINEL: &str = CORS_ORIGIN;

static TITLE_SELECTOR: LazyLock<Selector> = LazyLock::new(|| Selector::parse("title").unwrap());
static VERSION_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"\d+\.\d+(\.\d+)?").unwrap());

#[derive(Debug, Clone, Serialize)]
pub struct HostResult {
    pub host: String,
    pub ips: Vec<String>,
    pub cname: Option<String>,
    pub url: String,
    pub status: u16,
    pub final_url: String,
    pub title: String,
    pub server: String,
    pub tech: Vec<String>,
    pub content_type: String,
    pub body_len: usize,
    pub elapsed_ms: u128,
    /// (final_url + title) hash; equal values mean alias hosts.
    pub fingerprint: u64,
    pub alias_of: Option<String>,
    /// Open non-HTTP services for hosts that do not answer on 80/443.
    pub services: Vec<String>,
}

#[derive(Default)]
pub struct ProbeOutcome {
    pub hosts: Vec<HostResult>,
    pub findings: Findings,
}

fn fingerprint(final_url: &str, title: &str) -> u64 {
    let mut h = DefaultHasher::new();
    final_url.hash(&mut h);
    title.hash(&mut h);
    h.finish()
}

async fn open_services(host: &str) -> Vec<String> {
    let probes = [(21u16, "ftp"), (25, "smtp"), (143, "imap")];
    let results = join_all(probes.iter().map(|(port, name)| async move {
        let connect = tokio::net::TcpStream::connect((host, *port));
        match tokio::time::timeout(std::time::Duration::from_millis(1500), connect).await {
            Ok(Ok(_)) => Some((*name).to_string()),
            _ => None,
        }
    }))
    .await;
    results.into_iter().flatten().collect()
}

fn title_of(f: &Fetched) -> String {
    let doc = Html::parse_document(&f.body);
    doc.select(&TITLE_SELECTOR)
        .next()
        .map(|t| one_line(&t.text().collect::<String>()))
        .map(|t| truncate(&t, 120))
        .unwrap_or_default()
}

async fn probe_one(http: &Http, resolver: &Resolver, host: &str) -> Option<(HostResult, Findings)> {
    let dns_host = crate::util::host_of(host).unwrap_or_else(|| host.to_string());
    let dns = resolver.resolve(&dns_host).await;
    if dns.ips.is_empty() {
        return None;
    }

    let origin_header = [
        (
            HeaderName::from_static("origin"),
            HeaderValue::from_static(CORS_SENTINEL),
        ),
        (
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/html,*/*;q=0.8"),
        ),
    ];

    let mut last_err = String::new();
    let mut fetched: Option<(String, Fetched)> = None;
    for url in [format!("https://{host}"), format!("http://{host}")] {
        match http.fetch(&url, &origin_header, 512_000).await {
            Ok(f) => {
                fetched = Some((url, f));
                break;
            }
            Err(e) => last_err = format!("{e:#}"),
        }
    }

    let Some((url, f)) = fetched else {
        let services = open_services(&dns_host).await;
        if services.is_empty() {
            log::info(&format!("{host}: no HTTP response ({last_err})"));
            return None;
        }
        log::plus(&format!("{} non-HTTP ({})", host, services.join(", ")));
        let mut findings = Findings::with_stage(Stage::Probe);
        findings.add(
            Severity::Info,
            "services",
            &dns_host,
            &format!("tcp://{host}"),
            format!("Host bez HTTP, otwarte usługi: {}", services.join(", ")),
            "Sprawdź usługi bezpośrednio (ftp/smtp/imap), poza pipeline HTTP.",
        );
        return Some((
            HostResult {
                host: host.to_string(),
                ips: dns.ips,
                cname: dns.cname,
                url: format!("tcp://{host}"),
                status: 0,
                final_url: format!("tcp://{host}"),
                title: String::new(),
                server: String::new(),
                tech: services.clone(),
                content_type: String::new(),
                body_len: 0,
                elapsed_ms: 0,
                fingerprint: fingerprint(&format!("tcp://{host}"), ""),
                alias_of: None,
                services,
            },
            findings,
        ));
    };

    let mut findings = Findings::with_stage(Stage::Probe);
    let tech = tech::detect(&f.headers, &f.body);
    let status = f.status;
    let title = if f.is_html() {
        title_of(&f)
    } else {
        String::new()
    };

    let scheme_https = url.starts_with("https://");
    if f.is_html() && (200..400).contains(&status) {
        audit_headers(&f, &dns_host, &mut findings, scheme_https);
        audit_cookies(&f, &dns_host, &mut findings);
    }
    audit_cors(&f, &dns_host, &mut findings);
    audit_disclosure(&f, &dns_host, &mut findings);

    log::plus(&format!(
        "{} {}  {}  [{}]  {}",
        host,
        format!("[{}]", status).bright_black(),
        if title.is_empty() {
            "-".to_string()
        } else {
            truncate(&title, 60)
        },
        tech.join(","),
        f.final_url.trim_end_matches('/')
    ));

    Some((
        HostResult {
            host: host.to_string(),
            ips: dns.ips,
            cname: dns.cname,
            url,
            status,
            final_url: f.final_url.clone(),
            title: title.clone(),
            server: tech::server_of(&f.headers),
            tech,
            content_type: f.content_type().to_string(),
            body_len: f.body_len,
            elapsed_ms: f.elapsed_ms,
            fingerprint: fingerprint(&f.final_url, &title),
            alias_of: None,
            services: Vec::new(),
        },
        findings,
    ))
}

fn audit_headers(f: &Fetched, host: &str, out: &mut Findings, https: bool) {
    let has = |name: &str| f.header(name).is_some();
    let url = &f.final_url;

    let csp = f.header("content-security-policy").unwrap_or("");
    let frame_protected = has("x-frame-options") || csp.contains("frame-ancestors");

    if !frame_protected {
        out.add(
            Severity::Low,
            "headers",
            host,
            url,
            "Brak ochrony przed clickjackingiem (X-Frame-Options / CSP frame-ancestors)",
            "Odpowiedź można osadzić w iframe na obcej stronie.",
        );
    }
    if https && !has("strict-transport-security") {
        out.add(
            Severity::Low,
            "headers",
            host,
            url,
            "Brak nagłówka HSTS",
            "Brak Strict-Transport-Security; możliwe zejście do HTTP.",
        );
    }
    if csp.is_empty() {
        out.add(
            Severity::Medium,
            "headers",
            host,
            url,
            "Brak Content-Security-Policy",
            "Brak CSP, więc wstrzyknięcie HTML/JS nie ma łagodzenia po stronie przeglądarki.",
        );
    } else if csp.contains("unsafe-inline") || csp.contains("unsafe-eval") {
        out.add(
            Severity::Low,
            "headers",
            host,
            url,
            "Słaby Content-Security-Policy",
            truncate(csp, 200),
        );
    }
    if !has("x-content-type-options") {
        out.add(
            Severity::Low,
            "headers",
            host,
            url,
            "Brak X-Content-Type-Options: nosniff",
            "Starsze przeglądarki mogą zgadywać typ MIME.",
        );
    }
    if !has("referrer-policy") {
        out.add(
            Severity::Info,
            "headers",
            host,
            url,
            "Brak Referrer-Policy",
            "Referrer może wynieść pełne adresy (z tokenami) do stron trzecich.",
        );
    }
    if !has("permissions-policy") && !has("feature-policy") {
        out.add(
            Severity::Info,
            "headers",
            host,
            url,
            "Brak Permissions-Policy",
            "Uprawnienia do kamery, mikrofonu i lokalizacji nie są ograniczone.",
        );
    }
}

fn audit_cookies(f: &Fetched, host: &str, out: &mut Findings) {
    for raw in f.headers.get_all("set-cookie").iter() {
        let Ok(value) = raw.to_str() else { continue };
        let lower = value.to_ascii_lowercase();
        let name = value.split('=').next().unwrap_or("?").trim().to_string();
        let sensitive = ["sess", "sid", "token", "auth", "jwt", "login", "remember"]
            .iter()
            .any(|k| lower.contains(k));
        if !sensitive {
            continue;
        }
        let mut problems = Vec::new();
        if !lower.contains("secure") {
            problems.push("no Secure flag");
        }
        if !lower.contains("httponly") {
            problems.push("no HttpOnly");
        }
        if !lower.contains("samesite") {
            problems.push("no SameSite");
        }
        if problems.is_empty() {
            continue;
        }
        out.add(
            Severity::Low,
            "cookies",
            host,
            &f.final_url,
            format!(
                "Ciasteczko sesji `{name}` bez flag: {}",
                problems.join(", ")
            ),
            truncate(value, 200),
        );
    }
}

fn audit_cors(f: &Fetched, host: &str, out: &mut Findings) {
    let acao = f
        .header("access-control-allow-origin")
        .unwrap_or("")
        .trim()
        .to_string();
    let credentials = f
        .header("access-control-allow-credentials")
        .unwrap_or("")
        .eq_ignore_ascii_case("true");

    if acao.is_empty() {
        return;
    }
    if acao == CORS_SENTINEL {
        out.add(
            Severity::High,
            "cors",
            host,
            &f.final_url,
            if credentials {
                "CORS odbija dowolny Origin z poświadczeniami"
            } else {
                "CORS odbija dowolny Origin"
            },
            format!(
                "Wysłany Origin: {CORS_SENTINEL} → Access-Control-Allow-Origin: {acao}, poświadczenia: {credentials}"
            ),
        );
    } else if acao == "*" && credentials {
        out.add(
            Severity::High,
            "cors",
            host,
            &f.final_url,
            "CORS z wildcardem i poświadczeniami",
            "Access-Control-Allow-Origin: * together with Allow-Credentials: true",
        );
    }
}

fn audit_disclosure(f: &Fetched, host: &str, out: &mut Findings) {
    for header in ["server", "x-powered-by", "x-aspnet-version", "x-generator"] {
        if let Some(value) = f.header(header) {
            if let Some(m) = VERSION_RE.find(value) {
                out.add(
                    Severity::Info,
                    "disclosure",
                    host,
                    &f.final_url,
                    format!("Ujawniona wersja w `{header}`"),
                    format!("{value} (version {})", m.as_str()),
                );
            }
        }
    }
    if let Some(debug) = f.header("x-debug-token") {
        out.add(
            Severity::Low,
            "disclosure",
            host,
            &f.final_url,
            "Wystawiony nagłówek debugowania",
            truncate(debug, 120),
        );
    }
    let lower = f.body.to_ascii_lowercase();
    for (needle, label) in [
        ("whitelabel error page", "strona błędu Spring Boot"),
        ("stack trace:", "stack trace w odpowiedzi"),
        ("sql syntax", "błąd SQL w odpowiedzi"),
        (
            "traceback (most recent call last)",
            "traceback Pythona w odpowiedzi",
        ),
        ("<b>fatal error</b>", "fatal error PHP w odpowiedzi"),
    ] {
        if lower.contains(needle) {
            out.add(
                Severity::Medium,
                "disclosure",
                host,
                &f.final_url,
                format!("Wyciek błędu: {label}"),
                truncate(&f.body[..f.body.len().min(400)], 200),
            );
            break;
        }
    }
}

pub async fn probe(
    http: &Http,
    resolver: &Resolver,
    hosts: &[String],
    concurrency: usize,
) -> ProbeOutcome {
    log::stage(&format!("probing {} hosts", hosts.len()));
    let results: Vec<_> = stream::iter(hosts.iter().cloned())
        .map(|host| async move { probe_one(http, resolver, &host).await })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut outcome = ProbeOutcome::default();
    for item in results.into_iter().flatten() {
        outcome.hosts.push(item.0);
        outcome.findings.merge(item.1);
    }
    outcome.hosts.sort_by(|a, b| a.host.cmp(&b.host));
    outcome.findings.sort();
    log::ok(&format!(
        "{} live hosts, {} findings",
        outcome.hosts.len(),
        outcome.findings.len()
    ));
    outcome
}
