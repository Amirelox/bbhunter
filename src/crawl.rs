use futures::stream::{self, StreamExt};
use regex::Regex;
use reqwest::header::{HeaderName, HeaderValue};
use scraper::{Html, Selector};
use std::collections::{BTreeSet, VecDeque};
use std::sync::LazyLock;

use crate::http::{Http, CORS_ORIGIN};
use crate::log;
use crate::scope::Scope;
use crate::util;

static LINK_SELECTORS: &[&str] = &[
    "a[href]",
    "area[href]",
    "link[href]",
    "iframe[src]",
    "frame[src]",
];
static JS_SELECTOR: LazyLock<Selector> = LazyLock::new(|| Selector::parse("script[src]").unwrap());
static FORM_SELECTOR: LazyLock<Selector> = LazyLock::new(|| Selector::parse("form").unwrap());
static ENDPOINT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"["'\x60]((?:https?://[^"'\x60\s<>]+)|(?:/[A-Za-z0-9_\-./{}:$,]{3,}(?:\?[^"'\x60\s<>]*)?))["'\x60]"#)
        .unwrap()
});

static SECRET_RULES: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("klucz dostępu AWS", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        ("klucz Google API", r"AIza[0-9A-Za-z_\-]{35}"),
        ("klucz Stripe live", r"sk_live_[0-9a-zA-Z]{20,}"),
        ("token GitHub", r"gh[pousr]_[0-9A-Za-z]{36,}"),
        ("token Slack", r"xox[baprs]-[0-9A-Za-z\-]{10,}"),
        ("klucz Twilio", r"\bSK[0-9a-fA-F]{32}\b"),
        ("token Mapbox", r"\bpk\.[0-9A-Za-z]{50,}\b"),
        ("JWT", r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        ("klucz prywatny", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        (
            "prawdopodobny sekret API",
            r#"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token)["']?\s*[:=]\s*["']([A-Za-z0-9_\-]{16,})["']"#,
        ),
    ]
    .into_iter()
    .map(|(name, pat)| (name, Regex::new(pat).unwrap()))
    .collect()
});

const BINARY_EXT: &[&str] = &[
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".mp4", ".webm", ".mp3", ".wav", ".pdf", ".zip", ".rar", ".gz", ".7z", ".exe",
    ".dmg", ".apk", ".iso", ".bin",
];

#[derive(Debug, Clone)]
pub struct SecretHit {
    pub kind: String,
    pub url: String,
    pub preview: String,
}

#[derive(Debug, Default)]
pub struct CrawlResult {
    pub pages: BTreeSet<String>,
    pub urls: BTreeSet<String>,
    pub js: BTreeSet<String>,
    pub endpoints: BTreeSet<String>,
    pub forms: BTreeSet<String>,
    pub secrets: Vec<SecretHit>,
    pub cors_hits: Vec<(String, String)>,
    pub dir_listings: BTreeSet<String>,
}

impl CrawlResult {
    pub fn merge(&mut self, other: CrawlResult) {
        self.pages.extend(other.pages);
        self.urls.extend(other.urls);
        self.js.extend(other.js);
        self.endpoints.extend(other.endpoints);
        self.forms.extend(other.forms);
        self.dir_listings.extend(other.dir_listings);
        for hit in other.cors_hits {
            if !self.cors_hits.iter().any(|(u, _)| u == &hit.0) {
                self.cors_hits.push(hit);
            }
        }
        for s in other.secrets {
            if !self
                .secrets
                .iter()
                .any(|x| x.preview == s.preview && x.kind == s.kind)
            {
                self.secrets.push(s);
            }
        }
    }
}

fn is_binary(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    BINARY_EXT
        .iter()
        .any(|ext| lower.ends_with(ext) || lower.contains(&format!("{ext}?")))
}

pub fn interesting_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        "/api",
        "/v1",
        "/v2",
        "/v3",
        "/v4",
        "graphql",
        "/oauth",
        "/auth",
        "/token",
        "/upload",
        "/admin",
        "/internal",
        "/debug",
        "/rest/",
        "/rpc",
        "/graphql",
        "/sso",
        "/saml",
        "/json",
        "/export",
        "/download",
        "/invite",
        "/reset",
        "/password",
        "/user",
        "/account",
        "/pay",
        "/billing",
        "/webhook",
        "/callback",
        "/redirect",
        "/proxy",
        "/config",
        "/.well-known",
    ]
    .iter()
    .any(|needle| p.contains(needle))
}

fn redact(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.len() <= 12 {
        return format!("{}…", chars.iter().take(4).collect::<String>());
    }
    let head: String = chars.iter().take(6).collect();
    let tail: String = chars.iter().skip(chars.len() - 4).collect();
    format!("{head}…{tail} ({} chars)", chars.len())
}

fn scan_secrets(text: &str, url: &str, out: &mut Vec<SecretHit>, show: bool) {
    for (kind, re) in SECRET_RULES.iter() {
        for m in re.find_iter(text).take(3) {
            let raw = m.as_str();
            let preview = if show { raw.to_string() } else { redact(raw) };
            out.push(SecretHit {
                kind: (*kind).to_string(),
                url: url.to_string(),
                preview,
            });
        }
    }
}

fn extract_endpoints(text: &str, base: &str, out: &mut BTreeSet<String>) {
    let origin = util::origin(base);
    for cap in ENDPOINT_RE.captures_iter(text).take(4000) {
        let Some(m) = cap.get(1) else { continue };
        let raw = m.as_str();
        if raw.len() > 300 || raw.contains(" ") {
            continue;
        }
        let resolved = if raw.starts_with("http://") || raw.starts_with("https://") {
            raw.to_string()
        } else {
            format!("{origin}{raw}")
        };
        if interesting_path(&resolved)
            && !resolved.contains("w3.org")
            && !resolved.contains("schema.org")
        {
            out.insert(resolved);
        }
    }
}

pub async fn crawl_site(
    http: &Http,
    start: &str,
    max_pages: usize,
    show_secrets: bool,
    scope: &Scope,
) -> CrawlResult {
    let mut out = CrawlResult::default();
    let Some(root_host) = util::host_of(start) else {
        return out;
    };

    let mut queue: VecDeque<String> = VecDeque::from([start.to_string()]);
    let mut seen: BTreeSet<String> = BTreeSet::new();

    while let Some(page) = queue.pop_front() {
        if out.pages.len() >= max_pages.max(1) {
            break;
        }
        if !seen.insert(page.clone()) {
            continue;
        }
        let Some(host) = util::host_of(&page) else {
            continue;
        };
        if !scope.allows(&host) || is_binary(&page) {
            continue;
        }

        let origin_hdr = [(
            HeaderName::from_static("origin"),
            HeaderValue::from_static(CORS_ORIGIN),
        )];
        let Ok(f) = http.fetch(&page, &origin_hdr, 2_000_000).await else {
            continue;
        };

        // CORS matters most on JSON APIs, so check before the HTML filter.
        let acao = f.header("access-control-allow-origin").unwrap_or("").trim();
        let creds = f
            .header("access-control-allow-credentials")
            .unwrap_or("")
            .eq_ignore_ascii_case("true");
        if acao == CORS_ORIGIN || (acao == "*" && creds) {
            out.cors_hits.push((
                page.clone(),
                format!("Access-Control-Allow-Origin: {acao}, Allow-Credentials: {creds}"),
            ));
        }

        if !f.is_html() {
            continue;
        }
        out.pages.insert(page.clone());

        let lower_page = f.body.to_ascii_lowercase();
        if lower_page.contains("<title>index of /")
            || lower_page.contains("<title>directory listing for")
        {
            out.dir_listings.insert(page.clone());
        }

        let doc = Html::parse_document(&f.body);
        let base = f.final_url.clone();

        for sel_str in LINK_SELECTORS {
            let Ok(sel) = Selector::parse(sel_str) else {
                continue;
            };
            for el in doc.select(&sel) {
                let attr = if el.value().name() == "a" || el.value().name() == "area" {
                    "href"
                } else {
                    "src"
                };
                let Some(raw) = el.value().attr(attr) else {
                    continue;
                };
                if raw.starts_with("javascript:")
                    || raw.starts_with("mailto:")
                    || raw.starts_with("tel:")
                {
                    continue;
                }
                let Ok(base_url) = url::Url::parse(&base) else {
                    continue;
                };
                let Ok(joined) = base_url.join(raw) else {
                    continue;
                };
                if joined.scheme() != "http" && joined.scheme() != "https" {
                    continue;
                }
                let mut s = joined.to_string();
                if let Some(pos) = s.find('#') {
                    s.truncate(pos);
                }
                if is_binary(&s) {
                    continue;
                }
                if let Some(h) = util::host_of(&s) {
                    if !scope.allows(&h) {
                        continue;
                    }
                    out.urls.insert(s.clone());
                    if h == root_host && !seen.contains(&s) {
                        queue.push_back(s);
                    }
                }
            }
        }

        for el in doc.select(&JS_SELECTOR) {
            if let Some(src) = el.value().attr("src") {
                if let Ok(base_url) = url::Url::parse(&base) {
                    if let Ok(joined) = base_url.join(src) {
                        out.js.insert(joined.to_string());
                    }
                }
            }
        }

        for el in doc.select(&FORM_SELECTOR) {
            let action = el.value().attr("action").unwrap_or("").to_string();
            let method = el.value().attr("method").unwrap_or("get").to_uppercase();
            let inputs: Vec<String> = el
                .select(&Selector::parse("input[name], textarea[name], select[name]").unwrap())
                .filter_map(|i| i.value().attr("name").map(str::to_string))
                .collect();
            let abs = url::Url::parse(&base)
                .ok()
                .and_then(|b| b.join(&action).ok())
                .map(|u| u.to_string())
                .unwrap_or(action);
            out.forms
                .insert(format!("{method} {abs} [{}]", inputs.join(",")));
        }

        extract_endpoints(&f.body, &base, &mut out.endpoints);
        scan_secrets(&f.body, &page, &mut out.secrets, show_secrets);
    }

    // Pull referenced JS bundles and mine them for endpoints / keys.
    let js_list: Vec<String> = out.js.iter().take(25).cloned().collect();
    for js in js_list {
        let Some(h) = util::host_of(&js) else {
            continue;
        };
        if !scope.allows(&h) {
            continue;
        }
        let Ok(f) = http.fetch(&js, &[], 3_000_000).await else {
            continue;
        };
        if f.status >= 400 {
            continue;
        }
        extract_endpoints(&f.body, &js, &mut out.endpoints);
        scan_secrets(&f.body, &js, &mut out.secrets, show_secrets);
    }

    out
}

pub async fn crawl_many(
    http: &Http,
    starts: &[String],
    max_pages: usize,
    concurrency: usize,
    show_secrets: bool,
    scope: &Scope,
) -> CrawlResult {
    log::stage(&format!(
        "crawling {} sites (max {max_pages} pages each)",
        starts.len()
    ));
    let results: Vec<CrawlResult> = stream::iter(starts.iter().cloned())
        .map(|u| async move { crawl_site(http, &u, max_pages, show_secrets, scope).await })
        .buffer_unordered(concurrency.max(1))
        .collect()
        .await;

    let mut merged = CrawlResult::default();
    for r in results {
        merged.merge(r);
    }
    log::ok(&format!(
        "{} pages, {} urls, {} js files, {} endpoints, {} secrets",
        merged.pages.len(),
        merged.urls.len(),
        merged.js.len(),
        merged.endpoints.len(),
        merged.secrets.len()
    ));
    merged
}
