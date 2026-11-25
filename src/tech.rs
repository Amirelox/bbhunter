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
