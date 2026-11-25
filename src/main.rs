mod cache;
mod cli;
mod crawl;
mod dnsx;
mod findings;
mod http;
mod log;
mod osint;
mod paths;
mod pipeline;
mod probe;
mod report;
mod scope;
mod subs;
mod tech;
mod triage;
mod util;
mod wayback;
mod web;

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use cli::{Cli, Cmd, PathsArgs, Profile, ReconArgs, SubsArgs, TargetArgs};
use crawl::CrawlResult;
use dnsx::Resolver;
use findings::{Findings, Stage};
use http::Http;
use paths::PathScan;
use scope::Scope;
use triage::Triage;
use util::slug;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    log::set_quiet(cli.quiet);
    if let Err(e) = run(cli).await {
        log::err(&format!("{e:#}"));
        std::process::exit(1);
    }
}

fn banner() {
    if log::quiet() {
        return;
    }
    eprintln!(
        "{}",
        r#"
  _     _     _             _
 | |__ | |__ | |__  _   _ _ __ | |_ ___ _ __
 | '_ \| '_ \| '_ \| | | | '_ \| __/ _ \ '__|
 | |_) | |_) | | | | |_| | | | | ||  __/ |
 |_.__/|_.__/|_| |_|\__,_|_| |_|\__\___|_|
"#
        .bright_cyan()
    );
    eprintln!(
        "  recon toolkit {}  ·  authorized targets only\n",
        env!("CARGO_PKG_VERSION").bright_black()
    );
}

async fn run(cli: Cli) -> Result<()> {
    banner();

    let Cli {
        scope,
        no_scope_check,
        mut concurrency,
        mut rate,
        mut timeout,
        out,
        show_secrets,
        quiet: _,
        proxy,
        header,
        mut cmd,
    } = cli;

    if let Cmd::Recon(args) = &mut cmd {
        match args.profile {
            Profile::Fast => {
                if rate == 25 {
                    rate = 100;
                }
                if concurrency == 20 {
                    concurrency = 64;
                }
                if timeout == 10 {
                    timeout = 6;
                }
                if args.max_pages == 30 {
                    args.max_pages = 10;
                }
                if args.crawl_hosts == 40 {
                    args.crawl_hosts = 20;
                }
                if args.paths_hosts == 25 {
                    args.paths_hosts = 12;
                }
                if args.depth == 2 {
                    args.depth = 1;
                }
            }
            Profile::Deep => {
                if args.max_pages == 30 {
                    args.max_pages = 60;
                }
                if args.crawl_hosts == 40 {
                    args.crawl_hosts = 80;
                }
                if args.paths_hosts == 25 {
                    args.paths_hosts = 40;
                }
                if args.depth == 2 {
                    args.depth = 3;
                }
            }
            Profile::Balanced => {}
        }
    }

    // `serve` takes the scope from each scan request, so it must not require a CLI file.
    let serving = matches!(cmd, Cmd::Serve(_));
    let scope = if serving {
        Scope::from_text("", false)?
    } else {
        Scope::open(scope.as_deref(), !no_scope_check)?
    };
    if !scope.is_enforced() && !serving {
        log::warn("scope enforcement is DISABLED — you are responsible for having permission");
    }

    let extra_headers = http::parse_headers(&header)?;
    if !extra_headers.is_empty() {
        log::info(&format!(
            "sending {} custom header(s) on every request",
            extra_headers.len()
        ));
    }
    if let Some(p) = &proxy {
        log::info(&format!("proxying all traffic through {p}"));
    }

    let http = Http::new(concurrency, rate, timeout, proxy.as_deref(), &extra_headers)?;
    let resolver = Resolver::new();

    match cmd {
        Cmd::Subs(a) => cmd_subs(&http, &resolver, &scope, &out, a).await,
        Cmd::Probe(a) => cmd_probe(&http, &resolver, &scope, &out, concurrency, a).await,
        Cmd::Crawl(a) => {
            cmd_crawl(
                &http,
                &scope,
                &out,
                concurrency,
                show_secrets,
                a.targets,
                a.max_pages,
            )
            .await
        }
        Cmd::Paths(a) => cmd_paths(&http, &scope, &out, concurrency, a).await,
        Cmd::Urls(a) => cmd_urls(&http, &scope, &out, a).await,
        Cmd::Recon(a) => {
            cmd_recon(&http, &resolver, &scope, &out, concurrency, show_secrets, a).await
        }
        Cmd::Serve(a) => web::serve(&resolver, out.clone(), a).await,
        Cmd::Osint(a) => cmd_osint(&http, &resolver, &scope, &out, a).await,
    }
}

async fn cmd_osint(
    http: &Http,
    resolver: &Resolver,
    scope: &Scope,
    out: &Path,
    args: cli::OsintArgs,
) -> Result<()> {
    let roots = args.targets.roots(scope)?;
    let hosts = args.targets.hosts(scope)?;
    for root in &roots {
        let opts = osint::Options {
            cloud: !args.no_cloud,
            dorks: !args.no_dorks,
            favicon: !args.no_favicon,
            favicon_hosts: args.favicon_hosts,
            skip_passive: false,
        };
        let report = osint::run(http, resolver, scope, root, &hosts, &opts).await?;
        let dir = out.join(util::slug(root)).join("osint");
        fs::create_dir_all(&dir)?;
        fs::write(dir.join("osint.md"), osint::markdown(&report))?;
        fs::write(
            dir.join("osint.json"),
            serde_json::to_string_pretty(&report)?,
        )?;
        write_lines(
            &dir.join("subdomains.txt"),
            report.subdomains.iter().cloned(),
        )?;
        write_lines(
            &dir.join("cloud.txt"),
            report
                .cloud
                .iter()
                .map(|c| format!("{}\t{}\t{}\t{}", c.provider, c.name, c.status, c.kind)),
        )?;
        write_lines(
            &dir.join("dorks.txt"),
            report
                .dorks
                .iter()
                .map(|d| format!("{}\t{}\t{}", d.engine, d.label, d.url)),
        )?;
        write_lines(
            &dir.join("favicons.txt"),
            report
                .favicons
                .iter()
                .map(|f| format!("{}\t{}", f.hash, f.hosts.join(","))),
        )?;
        for host in &report.new_subdomains {
            println!("{host}");
        }
        log::ok(&format!("OSINT -> {}", dir.display()));
    }
    Ok(())
}

fn label(input: &str) -> String {
    let authority = util::authority_of(input).unwrap_or_else(|| input.to_string());
    slug(&authority)
}

fn target_dir(out: &Path, hosts: &[String]) -> PathBuf {
    let name = match hosts.len() {
        0 => "target".to_string(),
        1 => label(&hosts[0]),
        _ => {
            let bare = util::normalize_host(&hosts[0]).unwrap_or_else(|| hosts[0].clone());
            slug(&util::registrable(&bare))
        }
    };
    out.join(name)
}

fn write_lines(path: &Path, lines: impl IntoIterator<Item = String>) -> Result<usize> {
    let mut buf = String::new();
    let mut n = 0;
    for line in lines {
        buf.push_str(&line);
        buf.push('\n');
        n += 1;
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, buf).with_context(|| format!("writing {}", path.display()))?;
    Ok(n)
}

async fn cmd_subs(
    http: &Http,
    resolver: &Resolver,
    scope: &Scope,
    out: &Path,
    args: SubsArgs,
) -> Result<()> {
    let inputs = args.targets.hosts(scope)?;
    let roots = args.targets.roots(scope)?;
    let enumerable: Vec<String> = roots
        .iter()
        .filter(|r| !util::is_ip(r) && r.as_str() != "localhost")
        .cloned()
        .collect();
    if enumerable.is_empty() {
        log::warn("IP/localhost target: passive sources do not apply, returning the input hosts");
    }

    let mut all: BTreeSet<String> = BTreeSet::new();
    for root in &enumerable {
        let report = subs::enumerate(
            http,
            resolver,
            root,
            args.brute,
            args.wordlist.as_deref(),
            scope,
        )
        .await?;
        all.extend(report.hosts);
    }

    let mut hosts: Vec<String> = all.into_iter().collect();
    if hosts.is_empty() {
        hosts = inputs;
    }
    let dir = target_dir(out, &roots);
    write_lines(&dir.join("subdomains.txt"), hosts.iter().cloned())?;
    log::ok(&format!(
        "{} hosts -> {}",
        hosts.len(),
        dir.join("subdomains.txt").display()
    ));

    // Data on stdout, logs on stderr: `bbhunter subs ... | httpx`.
    let mut stdout = String::new();
    for h in &hosts {
        stdout.push_str(h);
        stdout.push('\n');
    }
    print!("{stdout}");
    Ok(())
}

async fn cmd_probe(
    http: &Http,
    resolver: &Resolver,
    scope: &Scope,
    out: &Path,
    concurrency: usize,
    args: TargetArgs,
) -> Result<()> {
    let hosts = args.hosts(scope)?;
    let outcome = probe::probe(http, resolver, &hosts, concurrency).await;
    let dir = target_dir(out, &hosts);

    let crawl = CrawlResult::default();
    let paths = PathScan::default();
    let triage = Triage::default();
    let wayback = BTreeSet::new();
    let no_notes: Vec<String> = Vec::new();
    let data = report::ReportData {
        target: label(&hosts[0]),
        scope_enforced: scope.is_enforced(),
        started: now(),
        subdomains: &hosts,
        hosts: &outcome.hosts,
        crawl: &crawl,
        paths: &paths,
        findings: &outcome.findings,
        triage: &triage,
        wayback: &wayback,
        notes: &no_notes,
        osint: None,
    };
    report::write_all(&dir, &data)?;
    Ok(())
}

async fn cmd_crawl(
    http: &Http,
    scope: &Scope,
    out: &Path,
    concurrency: usize,
    show_secrets: bool,
    targets: TargetArgs,
    max_pages: usize,
) -> Result<()> {
    let urls = targets.urls(scope)?;
    let crawl = crawl::crawl_many(http, &urls, max_pages, concurrency, show_secrets, scope).await;

    let mut triage = Triage::default();
    triage.add_all(crawl.urls.iter().cloned());
    triage.add_all(crawl.endpoints.iter().cloned());

    let dir = target_dir(out, &urls);
    let no_subs: Vec<String> = Vec::new();
    let no_hosts: Vec<probe::HostResult> = Vec::new();
    let paths = PathScan::default();
    let wayback = BTreeSet::new();
    let findings = Findings::with_stage(Stage::Crawl);
    let no_notes: Vec<String> = Vec::new();
    let data = report::ReportData {
        target: label(&urls[0]),
        scope_enforced: scope.is_enforced(),
        started: now(),
        subdomains: &no_subs,
        hosts: &no_hosts,
        crawl: &crawl,
        paths: &paths,
        findings: &findings,
        triage: &triage,
        wayback: &wayback,
        notes: &no_notes,
        osint: None,
    };
    report::write_all(&dir, &data)?;
    Ok(())
}

async fn cmd_paths(
    http: &Http,
    scope: &Scope,
    out: &Path,
    concurrency: usize,
    args: PathsArgs,
) -> Result<()> {
    let urls = args.targets.urls(scope)?;
    let bases: Vec<String> = urls
        .iter()
        .map(|u| util::origin(u))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(args.limit)
        .collect();
    let paths = paths::run_many(http, &bases, concurrency, scope, &[]).await;

    let dir = target_dir(out, &bases);
    let crawl = CrawlResult::default();
    let no_subs: Vec<String> = Vec::new();
    let no_hosts: Vec<probe::HostResult> = Vec::new();
    let triage = Triage::default();
    let wayback = BTreeSet::new();
    let no_notes: Vec<String> = Vec::new();
    let data = report::ReportData {
        target: label(&bases[0]),
        scope_enforced: scope.is_enforced(),
        started: now(),
        subdomains: &no_subs,
        hosts: &no_hosts,
        crawl: &crawl,
        paths: &paths,
        findings: &paths.findings,
        triage: &triage,
        wayback: &wayback,
        notes: &no_notes,
        osint: None,
    };
    report::write_all(&dir, &data)?;
    Ok(())
}

async fn cmd_urls(http: &Http, scope: &Scope, out: &Path, args: TargetArgs) -> Result<()> {
    let roots = args.roots(scope)?;
    let mut all: BTreeSet<String> = BTreeSet::new();
    for root in &roots {
        all.extend(wayback::wayback(http, root, 20000, scope).await);
    }
    let urls: Vec<String> = all.into_iter().collect();
    let dir = target_dir(out, &roots);
    write_lines(&dir.join("wayback_urls.txt"), urls.iter().cloned())?;
    for u in &urls {
        println!("{u}");
    }
    log::ok(&format!(
        "{} urls -> {}",
        urls.len(),
        dir.join("wayback_urls.txt").display()
    ));
    Ok(())
}

async fn cmd_recon(
    http: &Http,
    resolver: &Resolver,
    scope: &Scope,
    out: &Path,
    concurrency: usize,
    show_secrets: bool,
    args: ReconArgs,
) -> Result<()> {
    // One report per registrable domain, even when the user passes several
    // domains or a mixed host list.
    let inputs = args.targets.hosts(scope)?;
    let mut groups: std::collections::BTreeMap<String, Vec<String>> =
        std::collections::BTreeMap::new();
    for host in inputs {
        let bare = util::normalize_host(&host).unwrap_or_else(|| host.clone());
        let root = util::registrable(&bare);
        groups.entry(root).or_default().push(host);
    }

    let total = groups.len();
    let mut failures = 0usize;
    for (index, (root, hosts)) in groups.into_iter().enumerate() {
        if total > 1 {
            log::stage(&format!("cel {}/{}: {root}", index + 1, total));
        }
        let group_args = ReconArgs {
            targets: TargetArgs {
                domains: Vec::new(),
                list: None,
                urls: hosts,
            },
            ..args.clone()
        };
        let cancel = std::sync::atomic::AtomicBool::new(false);
        if let Err(e) = pipeline::recon(
            http,
            resolver,
            scope,
            out,
            concurrency,
            show_secrets,
            group_args,
            &cancel,
            &[],
        )
        .await
        {
            log::err(&format!("{root}: {e:#}"));
            failures += 1;
        }
    }

    if failures > 0 {
        anyhow::bail!("{failures} z {total} celów zakończyło się błędem");
    }
    Ok(())
}

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}
