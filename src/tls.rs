use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::stream::{self, StreamExt};
use openssl::asn1::Asn1Time;
use openssl::nid::Nid;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion};
use serde::Serialize;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

use crate::findings::{Findings, Severity, Stage};
use crate::log;
use crate::probe::HostResult;
use crate::scope::Scope;
use crate::util;

#[derive(Debug, Clone, Serialize)]
pub struct TlsResult {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub version: String,
    pub cipher: String,
    pub issuer: String,
    pub subject: String,
    pub expires: String,
    pub san: Vec<String>,
    pub weak_versions: Vec<String>,
    pub expired: bool,
    pub hostname_match: bool,
}

#[derive(Default)]
pub struct TlsScan {
    pub results: Vec<TlsResult>,
    pub findings: Findings,
    pub san: BTreeSet<String>,
    pub checked: usize,
}

struct Handshake {
    version: String,
    cipher: String,
    cert: Option<openssl::x509::X509>,
}

fn connector(legacy: Option<SslVersion>) -> Result<SslConnector> {
    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_verify(SslVerifyMode::NONE);
    if let Some(version) = legacy {
        builder.set_min_proto_version(Some(version))?;
        builder.set_max_proto_version(Some(version))?;
        builder.set_security_level(0);
        builder.set_cipher_list("ALL:@SECLEVEL=0")?;
    } else {
        builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    }
    Ok(builder.build())
}

async fn handshake(
    hostname: &str,
    ip: IpAddr,
    port: u16,
    legacy: Option<SslVersion>,
    timeout: Duration,
) -> Result<Handshake> {
    let connector = connector(legacy)?;
    let ssl = connector
        .configure()
        .and_then(|c| c.into_ssl(hostname))
        .context("TLS config")?;
    let tcp = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .context("TLS connect timeout")?
        .context("TLS connect")?;
    let mut stream = SslStream::new(ssl, tcp)?;
    tokio::time::timeout(timeout, Pin::new(&mut stream).connect())
        .await
        .context("TLS handshake timeout")?
        .context("TLS handshake")?;
    let version = stream.ssl().version_str().to_string();
    let cipher = stream
        .ssl()
        .current_cipher()
        .map(|c| c.name().to_string())
        .unwrap_or_default();
    let cert = stream.ssl().peer_certificate();
    Ok(Handshake {
        version,
        cipher,
        cert,
    })
}

pub fn name_matches(host: &str, pattern: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.ends_with(&format!(".{suffix}"))
            && host.matches('.').count() == suffix.matches('.').count() + 1
    } else {
        host == pattern
    }
}

fn cert_names(cert: &openssl::x509::X509) -> (Vec<String>, String, String) {
    let mut names = BTreeSet::new();
    if let Some(sans) = cert.subject_alt_names() {
        for name in sans.iter() {
            if let Some(dns) = name.dnsname() {
                names.insert(dns.trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    let cn = |name: &openssl::x509::X509NameRef| {
        name.entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().to_string().ok())
            .unwrap_or_default()
    };
    let subject = cn(cert.subject_name());
    let issuer = cn(cert.issuer_name());
    if names.is_empty() && !subject.is_empty() {
        names.insert(subject.to_ascii_lowercase());
    }
    (names.into_iter().collect(), issuer, subject)
}

pub fn weak_cipher(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("rc4")
        || n.contains("3des")
        || n.contains("des-")
        || n.contains("null")
        || n.contains("export")
        || n.contains("md5")
        || n.ends_with("-sha")
        || n.contains("-cbc-")
}

async fn probe_tls(
    host: String,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> Option<(TlsResult, Findings, BTreeSet<String>)> {
    let hostname = util::host_of(&host).unwrap_or_else(|| host.clone());
    let std = handshake(&hostname, ip, port, None, timeout).await.ok()?;
    let (san, issuer, subject) = std.cert.as_ref().map(cert_names).unwrap_or_default();
    let mut weak_versions = Vec::new();
    for (version, label) in [
        (SslVersion::TLS1, "TLS 1.0"),
        (SslVersion::TLS1_1, "TLS 1.1"),
    ] {
        if handshake(&hostname, ip, port, Some(version), timeout)
            .await
            .is_ok()
        {
            weak_versions.push(label.to_string());
        }
    }
    let hostname_match =
        san.is_empty() || san.iter().any(|pattern| name_matches(&hostname, pattern));
    let expired = match std.cert.as_ref() {
        Some(cert) => Asn1Time::days_from_now(0)
            .ok()
            .and_then(|now| cert.not_after().compare(&now).ok())
            .map(|o| o == Ordering::Less)
            .unwrap_or(false),
        None => false,
    };
    let expires = std
        .cert
        .as_ref()
        .map(|c| c.not_after().to_string())
        .unwrap_or_default();

    let mut findings = Findings::with_stage(Stage::Tls);
    let has_port = host
        .rsplit_once(':')
        .map(|(_, p)| p.parse::<u16>().is_ok())
        .unwrap_or(false);
    let url = if has_port {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{port}/")
    };
    if expired {
        findings.add(
            Severity::High,
            "tls",
            &host,
            &url,
            "Certyfikat TLS wygasł",
            format!("notAfter: {expires}"),
        );
    }
    if !hostname_match {
        findings.add(
            Severity::Medium,
            "tls",
            &host,
            &url,
            "Certyfikat nie obejmuje tego hosta",
            format!("SAN: {}", san.join(", ")),
        );
    }
    if weak_versions.iter().any(|v| v == "TLS 1.0") {
        findings.add(
            Severity::Medium,
            "tls",
            &host,
            &url,
            "Obsługiwany przestarzały TLS 1.0",
            "Serwer przyjął handshake TLS 1.0.",
        );
    } else if weak_versions.iter().any(|v| v == "TLS 1.1") {
        findings.add(
            Severity::Low,
            "tls",
            &host,
            &url,
            "Obsługiwany przestarzały TLS 1.1",
            "Serwer przyjął handshake TLS 1.1.",
        );
    }
    if weak_cipher(&std.cipher) {
        findings.add(
            Severity::Medium,
            "tls",
            &host,
            &url,
            "Słaby szyfr TLS",
            format!("Negocjowany szyfr: {}", std.cipher),
        );
    }

    let result = TlsResult {
        host,
        ip: ip.to_string(),
        port,
        version: std.version,
        cipher: std.cipher,
        issuer,
        subject,
        expires,
        san: san.clone(),
        weak_versions,
        expired,
        hostname_match,
    };
    Some((result, findings, san.into_iter().collect()))
}

pub async fn scan(
    hosts: &[HostResult],
    limit: usize,
    concurrency: usize,
    timeout_secs: u64,
    scope: &Scope,
    cancel: &AtomicBool,
) -> TlsScan {
    let mut targets: Vec<(String, IpAddr, u16)> = Vec::new();
    let mut seen = BTreeSet::new();
    for h in hosts.iter().filter(|h| h.alias_of.is_none()) {
        let hostname = util::host_of(&h.host).unwrap_or_else(|| h.host.clone());
        if targets.len() >= limit.max(1) || !seen.insert(h.host.clone()) || !scope.allows(&hostname)
        {
            continue;
        }
        let Some(ip) = h.ips.iter().find_map(|v| v.parse::<IpAddr>().ok()) else {
            continue;
        };
        let url = if h.final_url.starts_with("https://") {
            &h.final_url
        } else {
            &h.url
        };
        let port = url::Url::parse(url)
            .ok()
            .and_then(|u| u.port_or_known_default())
            .unwrap_or(443);
        if port == 443 || h.final_url.starts_with("https://") || h.url.starts_with("https://") {
            targets.push((h.host.clone(), ip, port));
        }
    }

    let timeout = Duration::from_secs(timeout_secs.clamp(2, 10));
    let checked = targets.len();
    let results = stream::iter(targets.into_iter().map(|(host, ip, port)| async move {
        if cancel.load(AtomicOrdering::Relaxed) {
            return None;
        }
        probe_tls(host, ip, port, timeout).await
    }))
    .buffer_unordered(concurrency.clamp(1, 32))
    .filter_map(|x| async move { x })
    .collect::<Vec<_>>()
    .await;

    let mut out = TlsScan {
        checked,
        ..Default::default()
    };
    for (result, findings, san) in results {
        log::plus(&format!(
            "{}:{} TLS {} / {}{}",
            result.host,
            result.port,
            result.version,
            result.cipher,
            if result.weak_versions.is_empty() {
                String::new()
            } else {
                format!(" · {}", result.weak_versions.join(", "))
            }
        ));
        out.san.extend(san);
        out.findings.merge(findings);
        out.results.push(result);
    }
    out.results.sort_by(|a, b| a.host.cmp(&b.host));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_names_match_one_label() {
        assert!(name_matches("api.example.com", "*.example.com"));
        assert!(!name_matches("a.b.example.com", "*.example.com"));
        assert!(name_matches("example.com", "example.com"));
        assert!(!name_matches("example.org", "example.com"));
    }

    #[test]
    fn weak_ciphers_are_flagged() {
        assert!(weak_cipher("ECDHE-RSA-AES128-SHA"));
        assert!(weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA"));
        assert!(!weak_cipher("TLS_AES_256_GCM_SHA384"));
    }
}
