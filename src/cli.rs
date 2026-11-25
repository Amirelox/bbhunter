use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::log;
use crate::scope::Scope;
use crate::util::{authority_of, normalize_host, registrable};

#[derive(Parser, Debug)]
#[command(
    name = "bbhunter",
    version,
    about = "All-in-one bug bounty recon toolkit — for authorized targets only",
    after_help = "Examples:\n  \
        bbhunter recon -d example.com --scope scope.txt --brute --wayback\n  \
        bbhunter subs  -d example.com --scope scope.txt\n  \
        bbhunter probe -l subdomains.txt --scope scope.txt\n  \
        bbhunter crawl -l live_hosts.txt --scope scope.txt\n  \
        bbhunter paths -u https://example.com --scope scope.txt\n  \
        bbhunter serve --port 8080\n  \
        bbhunter osint -d example.com --scope scope.txt -l live_hosts.txt\n\n\
        Scope is mandatory unless --no-scope-check is passed."
)]
pub struct Cli {
    /// Allowlist file (domains or globs). Required for any real target.
    #[arg(long, global = true, value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Disable the allowlist. Only for your own lab / localhost.
    #[arg(long, global = true)]
    pub no_scope_check: bool,

    /// Number of concurrent workers.
    #[arg(long, global = true, default_value_t = 20)]
    pub concurrency: usize,

    /// Global request rate cap, requests per second (0 = unlimited).
    #[arg(long, global = true, default_value_t = 25)]
    pub rate: u32,

    /// Per-request timeout in seconds.
    #[arg(long, global = true, default_value_t = 10)]
    pub timeout: u64,

    /// Output directory.
    #[arg(short = 'o', long, global = true, default_value = "./bbhunter-out")]
    pub out: PathBuf,

    /// Print full secret values instead of redacting them.
    #[arg(long, global = true)]
    pub show_secrets: bool,

    /// Route every request through a proxy, e.g. http://127.0.0.1:8080 (Burp).
    #[arg(long, global = true, value_name = "URL", env = "BBHUNTER_PROXY")]
    pub proxy: Option<String>,

    /// Extra header for every request, repeatable: -H "Authorization: Bearer ...".
    #[arg(
        short = 'H',
        long = "header",
        global = true,
        value_name = "\"Name: Value\""
    )]
    pub header: Vec<String>,

    /// Only print findings, not per-host progress.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,

    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Passive (+ optional brute-force) subdomain enumeration.
    Subs(SubsArgs),
    /// HTTP probe: status, title, tech stack, header/cookie/CORS findings.
    Probe(TargetArgs),
    /// Crawl sites and mine URLs, endpoints, forms and JS for secrets.
    Crawl(CrawlArgs),
    /// Fixed list of well-known sensitive paths (one GET each).
    Paths(PathsArgs),
    /// Historical URLs from the Wayback Machine CDX index.
    Urls(TargetArgs),
    /// Full pipeline: subs -> probe -> crawl -> paths -> triage -> report.
    Recon(ReconArgs),
    /// Local web UI: run scans from the browser at 127.0.0.1.
    Serve(ServeArgs),
    /// OSINT: passive DNS, RDAP, ASN, archives, dorks, cloud buckets, favicons.
    Osint(OsintArgs),
}

#[derive(Args, Debug, Clone, Default)]
pub struct TargetArgs {
    /// Target domain(s).
    #[arg(short = 'd', long = "domain", value_name = "DOMAIN")]
    pub domains: Vec<String>,

    /// File with one host/URL per line.
    #[arg(short = 'l', long = "list", value_name = "FILE")]
    pub list: Option<PathBuf>,

    /// Target URL(s).
    #[arg(short = 'u', long = "url", value_name = "URL")]
    pub urls: Vec<String>,
}

fn read_list(path: &Path) -> Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read target list {}", path.display()))?;
    Ok(text
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

impl TargetArgs {
    fn raw(&self) -> Result<Vec<String>> {
        let mut items = Vec::new();
        items.extend(self.domains.iter().cloned());
        items.extend(self.urls.iter().cloned());
        if let Some(path) = &self.list {
            items.extend(read_list(path)?);
        }
        Ok(items)
    }

    /// Every input reduced to `host[:port]`, filtered through the allowlist.
    pub fn hosts(&self, scope: &Scope) -> Result<Vec<String>> {
        let mut hosts: BTreeSet<String> = BTreeSet::new();
        let mut refused = 0usize;
        for item in self.raw()? {
            let Some(authority) = authority_of(&item) else {
                continue;
            };
            let Some(host) = normalize_host(&authority) else {
                continue;
            };
            if scope.allows(&host) {
                hosts.insert(authority);
            } else {
                refused += 1;
                log::warn(&format!("out of scope, skipped: {host}"));
            }
        }
        if refused > 0 && hosts.is_empty() {
            bail!("every target was outside the scope allowlist");
        }
        if hosts.is_empty() {
            bail!("no targets given (use -d DOMAIN, -u URL or -l FILE)");
        }
        Ok(hosts.into_iter().collect())
    }

    /// Full URLs suitable for crawling/probing, preserving any given path.
    pub fn urls(&self, scope: &Scope) -> Result<Vec<String>> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        for item in self.raw()? {
            let with_scheme = if item.starts_with("http://") || item.starts_with("https://") {
                item.clone()
            } else if let Some(authority) = authority_of(&item) {
                format!("https://{authority}")
            } else {
                continue;
            };
            let Some(host) = crate::util::host_of(&with_scheme) else {
                continue;
            };
            if scope.allows(&host) {
                out.insert(with_scheme);
            } else {
                log::warn(&format!("out of scope, skipped: {host}"));
            }
        }
        if out.is_empty() {
            bail!("no in-scope URLs to work with");
        }
        Ok(out.into_iter().collect())
    }

    /// Registrable root domains, used by passive enumeration.
    pub fn roots(&self, scope: &Scope) -> Result<Vec<String>> {
        let hosts = self.hosts(scope)?;
        let mut roots: BTreeSet<String> = BTreeSet::new();
        for h in hosts {
            if let Some(bare) = normalize_host(&h) {
                roots.insert(registrable(&bare));
            }
        }
        Ok(roots.into_iter().collect())
    }
}

#[derive(Args, Debug)]
pub struct OsintArgs {
    #[command(flatten)]
    pub targets: TargetArgs,

    /// How many input hosts get a favicon hash.
    #[arg(long, default_value_t = 40)]
    pub favicon_hosts: usize,

    /// Skip S3/GCS/Azure candidate checks.
    #[arg(long)]
    pub no_cloud: bool,

    /// Skip dork generation and public code search.
    #[arg(long)]
    pub no_dorks: bool,

    /// Skip favicon hashing.
    #[arg(long)]
    pub no_favicon: bool,
}

#[derive(Args, Debug)]
pub struct ServeArgs {
    /// Port for the local UI.
    #[arg(long, default_value_t = 8080)]
    pub port: u16,

    /// Address to bind. Keep 127.0.0.1 unless you know why.
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
}

#[derive(Args, Debug)]
pub struct SubsArgs {
    #[command(flatten)]
    pub targets: TargetArgs,

    /// Also brute-force a common-name wordlist.
    #[arg(long)]
    pub brute: bool,

    /// Extra brute-force wordlist (one label per line).
    #[arg(long, value_name = "FILE")]
    pub wordlist: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CrawlArgs {
    #[command(flatten)]
    pub targets: TargetArgs,

    /// Max pages per site.
    #[arg(long, default_value_t = 30)]
    pub max_pages: usize,
}

#[derive(Args, Debug)]
pub struct PathsArgs {
    #[command(flatten)]
    pub targets: TargetArgs,

    /// Max hosts to check.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// High rate, shallow crawl, no deep recursion.
    Fast,
    /// Current defaults.
    Balanced,
    /// More pages and depth, same polite rate.
    Deep,
}

#[derive(Args, Debug)]
pub struct ReconArgs {
    #[command(flatten)]
    pub targets: TargetArgs,

    /// Run the brute-force wordlist during subdomain enumeration.
    #[arg(long)]
    pub brute: bool,

    /// Extra brute-force wordlist.
    #[arg(long, value_name = "FILE")]
    pub wordlist: Option<PathBuf>,

    /// Max pages crawled per site.
    #[arg(long, default_value_t = 30)]
    pub max_pages: usize,

    /// Max live hosts that get the sensitive-path checks.
    #[arg(long, default_value_t = 25)]
    pub paths_hosts: usize,

    /// Add Wayback Machine URLs to the URL corpus.
    #[arg(long)]
    pub wayback: bool,

    /// Skip the sensitive-path checks.
    #[arg(long)]
    pub skip_paths: bool,

    /// Max sites to crawl per round.
    #[arg(long, default_value_t = 40)]
    pub crawl_hosts: usize,

    /// Do not follow hosts discovered while scanning.
    #[arg(long = "no-recurse")]
    pub no_recurse: bool,

    /// Total hosts to scan across all rounds (0 = unlimited).
    #[arg(long, default_value_t = 500)]
    pub max_hosts: usize,

    /// Discovery hops beyond the initial host list.
    #[arg(long, default_value_t = 2)]
    pub depth: usize,

    /// Skip the OSINT stage (it runs by default).
    #[arg(long = "no-osint")]
    pub no_osint: bool,

    /// Speed profile; explicit non-default flags win.
    #[arg(long, value_enum, default_value_t = Profile::Balanced)]
    pub profile: Profile,
}
