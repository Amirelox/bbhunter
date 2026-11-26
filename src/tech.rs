use reqwest::header::HeaderMap;
use std::collections::BTreeSet;

/// Cheap, explainable fingerprinting: header names/values plus body markers.
/// No external database needed, easy to extend.
const HEADER_RULES: &[(&str, &str, &str)] = &[
    ("server", "cloudflare", "Cloudflare"),
    ("server", "nginx", "nginx"),
    ("server", "apache", "Apache"),
    ("server", "microsoft-iis", "IIS"),
    ("server", "litespeed", "LiteSpeed"),
    ("server", "openresty", "OpenResty"),
    ("server", "caddy", "Caddy"),
    ("server", "gunicorn", "Gunicorn"),
    ("server", "nginx/openresty", "OpenResty"),
    ("x-powered-by", "php", "PHP"),
    ("x-powered-by", "asp.net", "ASP.NET"),
    ("x-powered-by", "express", "Express"),
    ("x-powered-by", "servlet", "Java Servlet"),
    ("x-aspnet-version", "", "ASP.NET"),
    ("x-generator", "drupal", "Drupal"),
    ("x-drupal-cache", "", "Drupal"),
    ("x-shopify-stage", "", "Shopify"),
    ("x-vercel-id", "", "Vercel"),
    ("x-amz-cf-id", "", "AWS CloudFront"),
    ("x-azure-ref", "", "Azure Front Door"),
    ("x-goog-generation", "", "Google Cloud Storage"),
    ("x-served-by", "fastly", "Fastly"),
    ("via", "varnish", "Varnish"),
    ("x-nf-request-id", "", "Netlify"),
    ("x-github-request-id", "", "GitHub Pages"),
    ("x-jsd-version", "", "jsDelivr"),
    ("x-citrix", "", "Citrix"),
    ("x-frame-options", "deny", ""),
];

const BODY_RULES: &[(&str, &str)] = &[
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("/sites/default/files", "Drupal"),
    ("__next_data__", "Next.js"),
    ("__nuxt", "Nuxt"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
    ("data-v-", "Vue.js"),
    ("_astro/", "Astro"),
    ("svelte", "Svelte"),
    ("shopify.theme", "Shopify"),
    ("cdn.shopify.com", "Shopify"),
    ("magento", "Magento"),
    ("csrf-token", "Rails/Laravel"),
    ("laravel_session", "Laravel"),
    ("jsessionid", "Java"),
    ("phpsessid", "PHP"),
    ("asp.net_sessionid", "ASP.NET"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
    ("jenkins", "Jenkins"),
    ("gitlab", "GitLab"),
    ("jira", "Jira"),
    ("confluence", "Confluence"),
    ("swagger-ui", "Swagger UI"),
    ("redoc", "Redoc"),
    ("whitelabel error page", "Spring Boot"),
    ("phpmyadmin", "phpMyAdmin"),
    ("/dana-na/", "Pulse Secure"),
    ("netscaler", "Citrix NetScaler"),
    ("big-ip", "F5 BIG-IP"),
    ("aem/", "Adobe Experience Manager"),
    ("/content/dam/", "Adobe Experience Manager"),
    ("salesforce", "Salesforce"),
    ("tableau", "Tableau"),
    ("/owa/", "Microsoft Exchange"),
    ("autodiscover", "Microsoft Exchange"),
    ("powered by discourse", "Discourse"),
    ("xenforo", "XenForo"),
    ("vbulletin", "vBulletin"),
];

const URL_RULES: &[(&str, &str)] = &[
    ("/_next/", "Next.js"),
    ("/wp-content/", "WordPress"),
    ("/wp-includes/", "WordPress"),
    ("/sites/default/files/", "Drupal"),
    ("/sites/default/", "Drupal"),
    ("/_nuxt/", "Nuxt"),
    ("/_app/", "SvelteKit"),
    ("/@vite/", "Vite"),
    ("/static/js/main.", "React"),
    ("/static/css/main.", "React"),
    ("/assets/application-", "Rails"),
    ("/packs/", "Webpack/Rails"),
    ("/cdn-cgi/", "Cloudflare"),
    ("/akamai/", "Akamai"),
    ("/swagger-ui/", "Swagger UI"),
    ("/openapi.json", "OpenAPI"),
    ("/graphql", "GraphQL"),
    ("/actuator/", "Spring Boot"),
    ("/wp-json/", "WordPress REST"),
    ("/umbraco/", "Umbraco"),
    ("/typo3/", "TYPO3"),
];

/// URL/asset fingerprints that are only visible after crawling or path checks.
pub fn detect_urls<'a>(urls: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut tech: BTreeSet<String> = BTreeSet::new();
    for raw in urls {
        let lower = raw.to_ascii_lowercase();
        for (needle, label) in URL_RULES {
            if lower.contains(needle) {
                tech.insert((*label).to_string());
            }
        }
    }
    tech.into_iter().collect()
}

pub fn merge(into: &mut Vec<String>, extra: impl IntoIterator<Item = String>) {
    for item in extra {
        if !into.iter().any(|v| v == &item) {
            into.push(item);
        }
    }
    into.sort();
}

/// Passive edge detection: we only look at headers, cookies and a few body
/// markers. No extra request, no fingerprinting payloads.
pub fn detect_waf(headers: &HeaderMap, body: &str) -> Option<String> {
    let value = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let has = |name: &str| headers.contains_key(name);
    let server = value("server");
    let cookie = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(";")
        .to_ascii_lowercase();
    let lower = body.to_ascii_lowercase();

    if has("cf-ray") || server.contains("cloudflare") || cookie.contains("__cf_bm") {
        return Some("Cloudflare".to_string());
    }
    if has("x-akamai") || has("akamai-grn") || server.contains("akamai") {
        return Some("Akamai".to_string());
    }
    if has("x-amz-cf-id") || server.contains("cloudfront") {
        return Some("AWS CloudFront".to_string());
    }
    if has("x-amzn-waf") || has("x-amz-waf") {
        return Some("AWS WAF".to_string());
    }
    if has("x-azure-ref") {
        return Some("Azure Front Door".to_string());
    }
    if has("x-fastly") || value("x-served-by").contains("fastly") {
        return Some("Fastly".to_string());
    }
    if has("x-iinfo")
        || cookie.contains("incap_ses")
        || cookie.contains("visid_incap")
        || lower.contains("incapsula incident id")
    {
        return Some("Imperva".to_string());
    }
    if has("x-sucuri") {
        return Some("Sucuri".to_string());
    }
    if has("x-wa-info") || server.contains("big-ip") {
        return Some("F5 BIG-IP".to_string());
    }
    if has("x-vercel-id") {
        return Some("Vercel".to_string());
    }
    if has("x-nf-request-id") {
        return Some("Netlify".to_string());
    }
    if has("x-sigsci") {
        return Some("Signal Sciences".to_string());
    }
    if has("x-reblaze") {
        return Some("Reblaze".to_string());
    }
    if server.contains("barracuda") {
        return Some("Barracuda".to_string());
    }
    if server.contains("modsecurity") || lower.contains("request rejected by mod_security") {
        return Some("ModSecurity".to_string());
    }
    if lower.contains("attention required! | cloudflare") {
        return Some("Cloudflare".to_string());
    }
    None
}

pub fn detect(headers: &HeaderMap, body: &str) -> Vec<String> {
    let mut tech: BTreeSet<String> = BTreeSet::new();
    let lower_body = body.to_ascii_lowercase();

    for (header, needle, label) in HEADER_RULES {
        if label.is_empty() {
            continue;
        }
        if let Some(value) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            let value = value.to_ascii_lowercase();
            if needle.is_empty() || value.contains(needle) {
                tech.insert((*label).to_string());
            }
        }
    }

    for (needle, label) in BODY_RULES {
        if lower_body.contains(needle) {
            tech.insert((*label).to_string());
        }
    }

    // Cookies often reveal the backend framework more reliably than headers.
    for cookie in headers.get_all("set-cookie").iter() {
        if let Ok(value) = cookie.to_str() {
            let value = value.to_ascii_lowercase();
            for (needle, label) in [
                ("laravel_session", "Laravel"),
                ("phpsessid", "PHP"),
                ("jsessionid", "Java"),
                ("asp.net_sessionid", "ASP.NET"),
                ("connect.sid", "Express"),
                ("django", "Django"),
                ("csrftoken", "Django"),
                ("wordpress_", "WordPress"),
                ("_shopify", "Shopify"),
            ] {
                if value.contains(needle) {
                    tech.insert(label.to_string());
                }
            }
        }
    }

    tech.into_iter().collect()
}

pub fn server_of(headers: &HeaderMap) -> String {
    headers
        .get("server")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderValue};

    #[test]
    fn detects_cloudflare_and_waf_headers() {
        let mut h = HeaderMap::new();
        h.insert("cf-ray", HeaderValue::from_static("abc"));
        assert_eq!(detect_waf(&h, ""), Some("Cloudflare".to_string()));
        let mut h = HeaderMap::new();
        h.insert("x-iinfo", HeaderValue::from_static("1"));
        assert_eq!(detect_waf(&h, ""), Some("Imperva".to_string()));
    }

    #[test]
    fn detects_static_frameworks_from_urls() {
        let t = detect_urls([
            "https://example.test/_next/static/chunks/main.js",
            "https://example.test/wp-content/themes/x.css",
            "https://example.test/_nuxt/app.js",
        ]);
        assert!(t.contains(&"Next.js".to_string()));
        assert!(t.contains(&"WordPress".to_string()));
        assert!(t.contains(&"Nuxt".to_string()));
    }
}
