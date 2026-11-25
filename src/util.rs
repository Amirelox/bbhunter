/// Registrable-domain suffixes we treat as multi-label. Deliberately small:
/// it only needs to be good enough to derive a root domain for passive
/// subdomain enumeration.
const MULTI_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "co.jp", "ne.jp", "com.br", "co.za",
    "com.pl", "net.pl", "org.pl", "gov.pl", "com.tr", "co.in", "co.nz", "com.sg", "com.hk",
    "co.kr", "com.cn", "com.ar", "com.co", "co.il", "com.ua", "co.id", "com.my", "com.ph",
    "com.vn", "co.th", "com.pk", "com.eg", "com.sa", "com.ng", "co.ke", "com.tw",
];

pub fn is_ip(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

/// Turn arbitrary user input (`https://A.example.com/path`, `a.example.com:8443`)
/// into a bare lowercase hostname. Returns None for comments/empty input.
pub fn normalize_host(input: &str) -> Option<String> {
    let raw = input.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }

    if let Ok(u) = url::Url::parse(raw) {
        if let Some(h) = u.host_str() {
            let h = h.trim_end_matches('.').to_ascii_lowercase();
            return (!h.is_empty()).then_some(h);
        }
    }

    let s = raw.to_ascii_lowercase();
    let s = s.split('/').next().unwrap_or("");
    let s = s.split('?').next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or(s);
    let host = match s.rsplit_once(':') {
        Some((h, port)) if !h.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => h,
        _ => s,
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return None;
    }
    if !host.contains('.') && host != "localhost" {
        return None;
    }
    Some(host.to_string())
}

pub fn host_of(input: &str) -> Option<String> {
    if let Ok(u) = url::Url::parse(input) {
        return u.host_str().map(|h| h.to_ascii_lowercase());
    }
    normalize_host(input)
}

pub fn registrable(host: &str) -> String {
    if is_ip(host) {
        return host.to_string();
    }
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    if labels.len() <= 2 {
        return host.to_string();
    }
    let last_two = format!("{}.{}", labels[labels.len() - 2], labels[labels.len() - 1]);
    if MULTI_SUFFIXES.contains(&last_two.as_str()) && labels.len() >= 3 {
        format!("{}.{}", labels[labels.len() - 3], last_two)
    } else {
        last_two
    }
}

/// `https://a.example.com/x?y=1` -> `https://a.example.com`
pub fn origin(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(u) => {
            let host = u.host_str().unwrap_or_default();
            match u.port() {
                Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
                None => format!("{}://{}", u.scheme(), host),
            }
        }
        Err(_) => url.trim_end_matches('/').to_string(),
    }
}

/// Like [`normalize_host`] but keeps an explicit non-default port:
/// `https://A.example.com:8443/x` -> `a.example.com:8443`.
pub fn authority_of(input: &str) -> Option<String> {
    let raw = input.trim();
    if raw.is_empty() || raw.starts_with('#') {
        return None;
    }
    if let Ok(u) = url::Url::parse(raw) {
        if let Some(h) = u.host_str() {
            let h = h.trim_end_matches('.').to_ascii_lowercase();
            return Some(match u.port() {
                Some(p) => format!("{h}:{p}"),
                None => h,
            });
        }
    }
    let s = raw.to_ascii_lowercase();
    let s = s.split('/').next().unwrap_or("");
    let s = s.split('?').next().unwrap_or("");
    let s = s.rsplit('@').next().unwrap_or(s);
    let s = s.trim_end_matches('.');
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() && !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, Some(p))
        }
        _ => (s, None),
    };
    if host.is_empty() {
        return None;
    }
    if !host.contains('.') && host != "localhost" {
        return None;
    }
    Some(match port {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    })
}

pub fn slug(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "target".to_string()
    } else {
        trimmed
    }
}

pub fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

pub fn one_line(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_hosts() {
        assert_eq!(
            normalize_host("https://API.Example.com/x?a=1").unwrap(),
            "api.example.com"
        );
        assert_eq!(normalize_host("example.com:8443").unwrap(), "example.com");
        assert_eq!(normalize_host("  example.com. ").unwrap(), "example.com");
        assert_eq!(normalize_host("user@example.com").unwrap(), "example.com");
        assert!(normalize_host("# comment").is_none());
        assert!(normalize_host("notahost").is_none());
    }

    #[test]
    fn finds_registrable_domain() {
        assert_eq!(registrable("a.b.example.com"), "example.com");
        assert_eq!(registrable("x.example.co.uk"), "example.co.uk");
        assert_eq!(registrable("example.com"), "example.com");
    }

    #[test]
    fn builds_origins() {
        assert_eq!(
            origin("https://a.example.com/x?y=1"),
            "https://a.example.com"
        );
        assert_eq!(origin("http://127.0.0.1:8765/x"), "http://127.0.0.1:8765");
        assert_eq!(
            authority_of("https://A.example.com:8443/x?y=1").unwrap(),
            "a.example.com:8443"
        );
    }
}
