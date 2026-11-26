use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::findings::{Findings, Severity, Stage};
use crate::log;
use crate::probe::HostResult;
use crate::scope::Scope;
use crate::util;

/// Common services on the public edge. Deliberately short: the point is a
/// useful first pass, not a 65k-port sweep on every host.
pub const DEFAULT_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 1521, 2049, 2375, 3000, 3306,
    3389, 5432, 5900, 6379, 7001, 8000, 8008, 8080, 8081, 8443, 9000, 9090, 9200, 11211, 27017,
];

const HTTP_PORTS: &[u16] = &[80, 3000, 8000, 8008, 8080, 8081, 8888, 9000, 9090];
const TLS_PORTS: &[u16] = &[443, 8443, 9443];

#[derive(Debug, Clone, Serialize)]
pub struct PortOpen {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub banner: String,
}

#[derive(Default)]
pub struct PortScan {
    pub open: Vec<PortOpen>,
    pub findings: Findings,
    pub checked: usize,
    pub hosts: usize,
}

pub fn parse_ports(spec: &str) -> anyhow::Result<Vec<u16>> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(DEFAULT_PORTS.to_vec());
    }
    let mut ports = BTreeSet::new();
    for chunk in spec.split([',', ' ', ';']).filter(|s| !s.trim().is_empty()) {
        if let Some((a, b)) = chunk.split_once('-') {
            let start: u16 = a.trim().parse()?;
            let end: u16 = b.trim().parse()?;
            if start == 0 || end < start {
                anyhow::bail!("invalid port range {chunk:?}");
            }
            for p in start..=end {
                ports.insert(p);
            }
        } else {
            let p: u16 = chunk.trim().parse()?;
            if p == 0 {
                anyhow::bail!("port 0 is not valid");
            }
            ports.insert(p);
        }
    }
    if ports.is_empty() {
        anyhow::bail!("empty port list");
    }
    Ok(ports.into_iter().collect())
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        80 => "http",
        110 => "pop3",
        139 => "netbios",
        143 => "imap",
        443 => "https",
        445 => "smb",
        993 => "imaps",
        995 => "pop3s",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        2375 => "docker",
        3000 => "http",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        7001 => "weblogic",
        8000 => "http",
        8008 => "http",
        8080 => "http",
        8081 => "http",
        8443 => "https-alt",
        8888 => "http",
        9000 => "http",
        9090 => "http",
        9200 => "elasticsearch",
        9443 => "https-alt",
        11211 => "memcached",
        27017 => "mongodb",
        _ => "tcp",
    }
}

fn risk(port: u16) -> Option<(Severity, &'static str)> {
    match port {
        2375 => Some((Severity::High, "Docker API bezpośrednio na sieci")),
        6379 => Some((Severity::High, "Redis bezpośrednio na sieci")),
        9200 => Some((Severity::High, "Elasticsearch bezpośrednio na sieci")),
        11211 => Some((Severity::High, "Memcached bezpośrednio na sieci")),
        27017 => Some((Severity::High, "MongoDB bezpośrednio na sieci")),
        3306 => Some((Severity::Medium, "MySQL widoczny z sieci")),
        5432 => Some((Severity::Medium, "PostgreSQL widoczny z sieci")),
        1433 => Some((Severity::Medium, "MSSQL widoczny z sieci")),
        1521 => Some((Severity::Medium, "Oracle widoczny z sieci")),
        5900 => Some((Severity::Medium, "VNC widoczny z sieci")),
        3389 => Some((Severity::Medium, "RDP widoczny z sieci")),
        7001 => Some((Severity::Medium, "WebLogic widoczny z sieci")),
        445 => Some((Severity::Medium, "SMB widoczny z sieci")),
        22 | 21 | 23 | 139 | 2049 => None,
        _ => None,
    }
}

async fn banner(stream: &mut TcpStream, host: &str, port: u16) -> String {
    if TLS_PORTS.contains(&port) {
        return String::new();
    }
    let http = HTTP_PORTS.contains(&port);
    let request = format!(
        "HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: bbhunter/0.1\r\nConnection: close\r\n\r\n"
    );
    if http {
        let _ = tokio::time::timeout(
            Duration::from_millis(700),
            stream.write_all(request.as_bytes()),
        )
        .await;
    }
    let mut buf = [0u8; 1024];
    let mut read = tokio::time::timeout(Duration::from_millis(900), stream.read(&mut buf)).await;
    if !http && matches!(read, Ok(Ok(0)) | Err(_)) && service_name(port) == "tcp" {
        let _ = tokio::time::timeout(
            Duration::from_millis(700),
            stream.write_all(request.as_bytes()),
        )
        .await;
        read = tokio::time::timeout(Duration::from_millis(900), stream.read(&mut buf)).await;
    }
    let Ok(Ok(n)) = read else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&buf[..n]);
    let joined = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(3)
        .collect::<Vec<_>>()
        .join(" | ");
    util::truncate(&joined.replace(['\r', '\u{0}'], ""), 180)
}

fn service_from_banner(port: u16, banner: &str) -> String {
    if service_name(port) != "tcp" || banner.is_empty() {
        return service_name(port).to_string();
    }
    let b = banner.to_ascii_lowercase();
    if b.starts_with("ssh-") {
        "ssh"
    } else if b.starts_with("http/") || b.contains("server:") {
        "http"
    } else if b.starts_with("220") {
        "ftp/smtp"
    } else {
        "tcp"
    }
    .to_string()
}

async fn probe_port(host: String, ip: IpAddr, port: u16, timeout: Duration) -> Option<PortOpen> {
    let mut stream = tokio::time::timeout(timeout, TcpStream::connect((ip, port)))
        .await
        .ok()?
        .ok()?;
    let banner = banner(&mut stream, &host, port).await;
    Some(PortOpen {
        host,
        ip: ip.to_string(),
        port,
        service: service_from_banner(port, &banner),
        banner,
    })
}

/// TCP connect scan + small, non-invasive banner grab. This is a connect scan
/// (the OS completes the handshake); it does not require raw sockets or root.
pub async fn scan(
    hosts: &[HostResult],
    limit: usize,
    spec: &str,
    concurrency: usize,
    timeout_secs: u64,
    scope: &Scope,
    cancel: &AtomicBool,
) -> anyhow::Result<PortScan> {
    let ports = parse_ports(spec)?;
    let mut targets: Vec<(String, IpAddr)> = Vec::new();
    let mut seen_hosts = HashSet::new();
    let mut seen_ip = HashSet::new();
    for h in hosts.iter().filter(|h| h.alias_of.is_none()) {
        if !seen_hosts.insert(h.host.clone()) {
            continue;
        }
        let hostname = util::host_of(&h.host).unwrap_or_else(|| h.host.clone());
        if !scope.allows(&hostname) {
            continue;
        }
        let Some(ip) = h.ips.iter().find_map(|v| v.parse::<IpAddr>().ok()) else {
            continue;
        };
        if !seen_ip.insert(ip) {
            continue;
        }
        targets.push((h.host.clone(), ip));
        if targets.len() >= limit.max(1) {
            break;
        }
    }

    let mut out = PortScan {
        hosts: targets.len(),
        ..Default::default()
    };
    let tasks: Vec<(String, IpAddr, u16)> = targets
        .iter()
        .flat_map(|(host, ip)| ports.iter().map(move |p| (host.clone(), *ip, *p)))
        .collect();
    out.checked = tasks.len();

    let results = stream::iter(tasks.into_iter().map(|(host, ip, port)| {
        let timeout = Duration::from_secs(timeout_secs.clamp(1, 4));
        async move {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            probe_port(host, ip, port, timeout).await
        }
    }))
    .buffer_unordered(concurrency.clamp(1, 128))
    .filter_map(|x| async move { x })
    .collect::<Vec<PortOpen>>()
    .await;

    out.open = results;
    out.open
        .sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
    let mut findings = Findings::with_stage(Stage::Ports);
    for open in &out.open {
        log::plus(&format!(
            "{}:{} open ({}){}",
            open.host,
            open.port,
            open.service,
            if open.banner.is_empty() {
                String::new()
            } else {
                format!(" · {}", open.banner)
            }
        ));
        if let Some((severity, detail)) = risk(open.port) {
            let evidence = if open.banner.is_empty() {
                detail.to_string()
            } else {
                format!("{detail}. Banner: {}", open.banner)
            };
            findings.add(
                severity,
                "open-service",
                &open.host,
                &format!("tcp://{}:{}", open.ip, open.port),
                format!("Otwarty port {} ({})", open.port, open.service),
                evidence,
            );
        }
    }
    out.findings = findings;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ranges_and_dedupes() {
        let p = parse_ports("80, 443, 8000-8002, 443").unwrap();
        assert_eq!(p, vec![80, 443, 8000, 8001, 8002]);
    }

    #[test]
    fn empty_spec_uses_default() {
        assert_eq!(parse_ports("").unwrap(), DEFAULT_PORTS);
    }

    #[test]
    fn rejects_invalid_ranges() {
        assert!(parse_ports("10-5").is_err());
        assert!(parse_ports("0").is_err());
    }
}
