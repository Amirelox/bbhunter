use std::collections::{BTreeMap, BTreeSet};

use crate::util;

pub const ADMIN: &str = "admin-panels";
pub const DEBUG: &str = "debug-staging";
pub const AUTH: &str = "auth-endpoints";
pub const API: &str = "api-endpoints";
pub const PAYMENT: &str = "payment-checkout";
pub const UPLOAD: &str = "file-upload";
pub const REDIRECT: &str = "redirect-params";
pub const PARAMS: &str = "urls-with-params";
pub const ACCOUNT: &str = "user-account";

pub const ALL_BUCKETS: &[&str] = &[
    ADMIN, DEBUG, AUTH, API, PAYMENT, UPLOAD, REDIRECT, PARAMS, ACCOUNT,
];

const REDIRECT_KEYS: &[&str] = &[
    "url",
    "uri",
    "next",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "return",
    "returnurl",
    "return_url",
    "returnto",
    "callback",
    "continue",
    "dest",
    "destination",
    "target",
    "redir",
    "rurl",
    "link",
    "out",
    "view",
    "goto",
    "forward",
    "back",
];

const ENV_LABELS: &[&str] = &[
    "dev",
    "dev1",
    "dev2",
    "develop",
    "staging",
    "stage",
    "stg",
    "stg1",
    "test",
    "test1",
    "test2",
    "testing",
    "qa",
    "qa1",
    "uat",
    "preprod",
    "pre",
    "demo",
    "sandbox",
    "beta",
    "alpha",
    "preview",
    "review",
    "canary",
    "legacy",
    "old",
    "old1",
    "jenkins",
    "gitlab",
    "jira",
    "confluence",
    "grafana",
    "kibana",
    "sonar",
    "nexus",
    "artifactory",
    "rancher",
    "vault",
    "phpmyadmin",
];

const ADMIN_TOOLS: &[&str] = &[
    "admin",
    "administrator",
    "wp-admin",
    "wp-login",
    "dashboard",
    "panel",
    "manage",
    "management",
    "console",
    "cpanel",
    "webadmin",
    "backoffice",
    "internal",
    "staff",
    "adminer",
    "phpmyadmin",
];

fn label_hit(label: &str, needle: &str) -> bool {
    if label == needle {
        return true;
    }
    if let Some(rest) = label.strip_prefix(needle) {
        if rest.starts_with('-')
            || rest.starts_with('_')
            || rest.chars().all(|c| c.is_ascii_digit())
        {
            return true;
        }
    }
    if let Some(rest) = label.strip_suffix(needle) {
        if rest.ends_with('-') || rest.ends_with('_') {
            return true;
        }
    }
    false
}

#[derive(Default)]
pub struct Triage {
    buckets: BTreeMap<String, BTreeSet<String>>,
}

impl Triage {
    fn insert(&mut self, bucket: &str, value: impl Into<String>) {
        self.buckets
            .entry(bucket.to_string())
            .or_default()
            .insert(value.into());
    }

    pub fn add_host(&mut self, host: &str) {
        let Some(first) = host.split('.').next() else {
            return;
        };
        let labels: Vec<&str> = host.split('.').collect();
        if ENV_LABELS
            .iter()
            .any(|n| labels.iter().any(|l| label_hit(l, n)))
        {
            self.insert(DEBUG, format!("https://{host}"));
        }
        if ADMIN_TOOLS.iter().any(|n| label_hit(first, n)) {
            self.insert(ADMIN, format!("https://{host}"));
        }
    }

    pub fn add_url(&mut self, raw: &str) {
        let Ok(u) = url::Url::parse(raw) else { return };
        let path = u.path().to_ascii_lowercase();
        let full = format!(
            "{}{}",
            path,
            u.query().map(|q| format!("?{q}")).unwrap_or_default()
        );

        if ADMIN_TOOLS.iter().any(|n| path.contains(n)) {
            self.insert(ADMIN, raw);
        }
        if [
            "/oauth",
            "/sso",
            "/saml",
            "/login",
            "/signin",
            "/auth",
            "/token",
            "/password",
            "/reset",
            "/mfa",
            "/2fa",
        ]
        .iter()
        .any(|n| path.contains(n))
        {
            self.insert(AUTH, raw);
        }
        if [
            "/api/", "/api", "/graphql", "/rest/", "/rpc/", "/v1/", "/v2/", "/v3/",
        ]
        .iter()
        .any(|n| path.contains(n) || full.starts_with(n))
        {
            self.insert(API, raw);
        }
        if [
            "/pay",
            "/checkout",
            "/billing",
            "/invoice",
            "/stripe",
            "/cart",
            "/order",
        ]
        .iter()
        .any(|n| path.contains(n))
        {
            self.insert(PAYMENT, raw);
        }
        if ["/upload", "/import", "/attachment", "/file"]
            .iter()
            .any(|n| path.contains(n))
        {
            self.insert(UPLOAD, raw);
        }
        if [
            "/user",
            "/account",
            "/profile",
            "/settings",
            "/me/",
            "/invite",
        ]
        .iter()
        .any(|n| path.contains(n))
        {
            self.insert(ACCOUNT, raw);
        }

        let keys: Vec<String> = u
            .query_pairs()
            .map(|(k, _)| k.to_ascii_lowercase())
            .collect();
        if !keys.is_empty() {
            self.insert(PARAMS, raw);
            if keys.iter().any(|k| REDIRECT_KEYS.contains(&k.as_str())) {
                self.insert(REDIRECT, format!("{raw}  [keys: {}]", keys.join(",")));
            }
        }
    }

    pub fn add_all(&mut self, urls: impl IntoIterator<Item = String>) {
        for u in urls {
            self.add_url(&u);
        }
    }

    pub fn get(&self, bucket: &str) -> Option<&BTreeSet<String>> {
        self.buckets.get(bucket)
    }

    pub fn total(&self) -> usize {
        self.buckets.values().map(|v| v.len()).sum()
    }

    /// Interesting hosts get priority when we must cap how many hosts we probe
    /// with the sensitive-path checks.
    pub fn prioritized_hosts(&self, live: &[String], limit: usize) -> Vec<String> {
        let mut prioritized: Vec<String> = Vec::new();
        let mut rest: Vec<String> = Vec::new();
        for host in live {
            let interesting = [ADMIN, DEBUG, AUTH, API].iter().any(|b| {
                self.get(b).is_some_and(|s| {
                    s.iter().any(|v| {
                        util::authority_of(v).as_deref() == Some(host.as_str())
                            || util::host_of(v).as_deref() == Some(host.as_str())
                    })
                })
            });
            if interesting {
                prioritized.push(host.clone());
            } else {
                rest.push(host.clone());
            }
        }
        prioritized.extend(rest);
        prioritized.truncate(limit);
        prioritized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_urls() {
        let mut t = Triage::default();
        t.add_url("https://x.example.com/api/v2/users?id=1&next=/home");
        t.add_url("https://x.example.com/wp-admin/");
        t.add_url("https://x.example.com/checkout/pay");
        assert!(t.get(API).unwrap().len() == 1);
        assert!(t.get(ADMIN).unwrap().len() == 1);
        assert!(t.get(PAYMENT).unwrap().len() == 1);
        assert!(t.get(PARAMS).unwrap().len() == 1);
        assert!(t.get(REDIRECT).unwrap().len() == 1);
    }

    #[test]
    fn classifies_hosts() {
        let mut t = Triage::default();
        t.add_host("dev-api.example.com");
        t.add_host("www.example.com");
        assert_eq!(t.get(DEBUG).unwrap().len(), 1);
        // "latest" must not be read as "test".
        let mut t2 = Triage::default();
        t2.add_host("latest.example.com");
        assert!(t2.get(DEBUG).is_none());
    }
}
