use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cli::ReconArgs;
use crate::crawl;
use crate::dnsx::Resolver;
use crate::findings::{Findings, Severity, Stage};
use crate::http::Http;
use crate::log;
use crate::osint;
use crate::paths::{self, PathScan};
use crate::probe::{self, HostResult};
use crate::report;
use crate::scope::Scope;
use crate::subs;
use crate::triage::Triage;
use crate::util;
use crate::wayback;

/// Hosts that appear in URLs or redirect targets and are not known yet.
/// The scope allowlist decides what may enter the frontier.
fn harvest_hosts(
    scope: &Scope,
    urls: impl IntoIterator<Item = String>,
    redirects: impl IntoIterator<Item = String>,
    seen: &BTreeSet<String>,
    known: &BTreeSet<String>,
) -> Vec<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for url in urls.into_iter().chain(redirects) {
        let Some(authority) = util::authority_of(&url) else {
            continue;
        };
        let Some(host) = util::normalize_host(&authority) else {
            continue;
        };
        if !seen.contains(&authority) && !known.contains(&authority) && scope.allows(&host) {
            out.insert(authority);
        }
    }
    out.into_iter().collect()
}

/// Full recon pipeline, shared by the CLI and the local web UI.
/// The parameter list is the full run context; grouping it would add a struct
/// with no behaviour.
#[allow(clippy::too_many_arguments)]
///
/// Discovery is recursive: every host that turns up in a crawled page, a JS
/// file, robots/sitemap or a redirect enters the next round and goes through
/// the same stages, until the depth or host budget is reached.
pub async fn recon(
    http: &Http,
    resolver: &Resolver,
    scope: &Scope,
    out: &Path,
    concurrency: usize,
    show_secrets: bool,
    args: ReconArgs,
    cancel: &AtomicBool,
    extra_paths: &[String],
) -> Result<PathBuf> {
    let started = now();
    let inputs = args.targets.hosts(scope)?;
    let roots: BTreeSet<String> = inputs
        .iter()
        .filter_map(|h| util::normalize_host(h))
        .map(|h| util::registrable(&h))
        .collect();
    let target_name = util::slug(
        roots
            .iter()
            .next()
            .cloned()
            .unwrap_or_else(|| {
                util::normalize_host(&inputs[0]).unwrap_or_else(|| inputs[0].clone())
            })
            .as_str(),
    );

    // 0. OSINT pre-scan: extra passive sources, RDAP, cloud names, dorks.
    //    ASN/favicons run after the probe, when every live host is known.
    let mut osint_reports: Vec<(String, osint::OsintReport)> = Vec::new();
    let mut known: BTreeSet<String> = BTreeSet::new();
    let mut cancelled = false;
    let osint_opts = osint::Options {
        cloud: true,
        dorks: true,
        favicon: true,
        favicon_hosts: 80,
        skip_passive: true,
    };
    if cancel.load(Ordering::Relaxed) {
        cancelled = true;
    }
    if !args.no_osint && !cancelled {
        log::stage("OSINT pre-scan (extra passive sources, RDAP, cloud, dorks)");
        for root in &roots {
            match osint::pre(http, resolver, scope, root, &inputs, &osint_opts).await {
                Ok(rep) => {
                    known.extend(rep.subdomains.iter().cloned());
                    let summary = rep.summary();
                    log::ok(&format!(
                        "OSINT: {} subdomen, {} kandydatów chmury",
                        summary.subdomains, summary.cloud
                    ));
                    osint_reports.push((root.clone(), rep));
                }
                Err(e) => log::warn(&format!("OSINT failed for {root}: {e:#}")),
            }
        }
    }

    // 1. Passive enumeration becomes the first frontier.
    let enumerable: Vec<String> = roots
        .iter()
        .filter(|r| !util::is_ip(r) && r.as_str() != "localhost")
        .cloned()
        .collect();
    if enumerable.is_empty() {
        log::info("IP/localhost target: skipping passive subdomain enumeration");
    }
    for root in &enumerable {
        match subs::enumerate(
            http,
            resolver,
            root,
            args.brute,
            args.wordlist.as_deref(),
            scope,
        )
        .await
        {
            Ok(r) => known.extend(r.hosts),
            Err(e) => log::warn(&format!("subdomain enumeration failed for {root}: {e:#}")),
        }
    }
    known.extend(inputs.iter().cloned());

    // 2. Historical URLs are collected once and also seed the frontier.
    let mut wayback_urls: BTreeSet<String> = BTreeSet::new();
    if args.wayback {
        for root in &enumerable {
            wayback_urls.extend(wayback::wayback(http, root, 20000, scope).await);
        }
        for url in &wayback_urls {
            if let Some(host) = util::host_of(url) {
                if scope.allows(&host) {
                    known.insert(host);
                }
            }
        }
    }

    let mut triage = Triage::default();
    triage.add_all(wayback_urls.iter().cloned());

    let mut findings = Findings::default();
    let mut crawl_all = crawl::CrawlResult::default();
    let mut paths_all = PathScan::default();
    let mut hosts: Vec<HostResult> = Vec::new();

    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut alias_primaries: BTreeMap<u64, String> = BTreeMap::new();
    let mut frontier: Vec<String> = known.iter().cloned().collect();
    let recursive = !args.no_recurse;
    let max_hosts = args.max_hosts.max(1);
    let mut hop = 0usize;
    let mut truncated = false;
    let mut stopped_at_depth = false;
    let mut skipped_by_flag = false;

    loop {
        if frontier.is_empty() {
            break;
        }
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }

        // Take this round's batch, respecting the global host budget.
        let mut batch: Vec<String> = Vec::new();
        for host in std::mem::take(&mut frontier) {
            if seen.len() >= max_hosts {
                truncated = true;
                break;
            }
            if seen.insert(host.clone()) {
                batch.push(host);
            }
        }
        if batch.is_empty() {
            break;
        }

        log::info(&format!(
            "runda {}: {} hostów (rekurencja: {})",
            hop + 1,
            batch.len(),
            if recursive { "tak" } else { "nie" }
        ));

        // 3. Probe every host in the batch.
        let mut outcome = probe::probe(http, resolver, &batch, concurrency).await;
        findings.merge(std::mem::take(&mut outcome.findings));
        for h in &outcome.hosts {
            triage.add_host(&h.host);
        }

        // Alias detection: hosts that end up on the same final URL with the same
        // title are one asset. Keep the first as primary and mark the rest.
        for h in outcome.hosts.iter_mut() {
            if h.status == 0 {
                continue;
            }
            match alias_primaries.entry(h.fingerprint) {
                std::collections::btree_map::Entry::Vacant(v) => {
                    v.insert(h.host.clone());
                }
                std::collections::btree_map::Entry::Occupied(o) => {
                    h.alias_of = Some(o.get().clone());
                }
            }
        }

        let bases: BTreeMap<String, String> = outcome
            .hosts
            .iter()
            .map(|h| (h.host.clone(), h.url.clone()))
            .collect();
        let live: Vec<String> = outcome
            .hosts
            .iter()
            .filter(|h| h.status > 0 && h.alias_of.is_none())
            .map(|h| h.host.clone())
            .collect();

        // 4. Crawl the most interesting live hosts of this batch.
        let crawlable: Vec<String> = outcome
            .hosts
            .iter()
            .filter(|h| (200..400).contains(&h.status) && h.alias_of.is_none())
            .map(|h| h.host.clone())
            .collect();
        let crawl_targets: Vec<String> = triage
            .prioritized_hosts(&crawlable, args.crawl_hosts)
            .iter()
            .filter_map(|h| bases.get(h).cloned())
            .collect();
        let crawl = crawl::crawl_many(
            http,
            &crawl_targets,
            args.max_pages,
            concurrency,
            show_secrets,
            scope,
        )
        .await;

        // 5. Low-hanging checks on this batch.
        let mut paths = if args.skip_paths {
            PathScan::default()
        } else {
            let picked = triage.prioritized_hosts(&live, args.paths_hosts);
            let picked_bases: Vec<String> = picked
                .iter()
                .filter_map(|h| bases.get(h).cloned())
                .collect();
            paths::run_many(http, &picked_bases, concurrency, scope, extra_paths).await
        };
        findings.merge(std::mem::take(&mut paths.findings));

        // 6. Crawl-derived findings.
        let mut crawl_findings = Findings::with_stage(Stage::Crawl);
        for s in &crawl.secrets {
            let severity = match s.kind.as_str() {
                "klucz dostępu AWS" | "klucz Stripe live" | "klucz prywatny" | "token GitHub"
                | "token Slack" | "klucz Twilio" => Severity::High,
                _ => Severity::Medium,
            };
            crawl_findings.add(
                severity,
                "secret-in-js",
                &util::host_of(&s.url).unwrap_or_default(),
                &s.url,
                format!("{} w JavaScripcie", s.kind),
                s.preview.clone(),
            );
        }
        for (url, detail) in &crawl.cors_hits {
            crawl_findings.add(
                Severity::High,
                "cors",
                &util::host_of(url).unwrap_or_default(),
                url,
                "CORS odbija dowolny Origin (endpoint z crawla)",
                detail.clone(),
            );
        }
        for url in &crawl.dir_listings {
            crawl_findings.add(
                Severity::Low,
                "directory-listing",
                &util::host_of(url).unwrap_or_default(),
                url,
                "Włączone listowanie katalogu",
                "Pobrana strona to indeks katalogu.",
            );
        }
        findings.merge(crawl_findings);

        // 7. Everything this round produced: URLs and the hosts behind them.
        let mut round_urls: BTreeSet<String> = BTreeSet::new();
        round_urls.extend(crawl.urls.iter().cloned());
        round_urls.extend(crawl.endpoints.iter().cloned());
        round_urls.extend(paths.extra_urls.iter().cloned());
        triage.add_all(round_urls.iter().cloned());

        let redirects: Vec<String> = outcome.hosts.iter().map(|h| h.final_url.clone()).collect();
        let new_hosts = harvest_hosts(scope, round_urls.iter().cloned(), redirects, &seen, &known);

        known.extend(new_hosts.iter().cloned());
        hosts.extend(outcome.hosts);
        crawl_all.merge(crawl);
        paths_all.merge(paths);

        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        if new_hosts.is_empty() {
            break;
        }
        if !recursive {
            skipped_by_flag = true;
            break;
        }
        if hop >= args.depth {
            stopped_at_depth = true;
            break;
        }
        hop += 1;
        log::ok(&format!("{} nowych hostów w kolejce", new_hosts.len()));
        frontier = new_hosts;
    }

    findings.sort();
    hosts.sort_by(|a, b| a.host.cmp(&b.host));

    // 8. OSINT enrichment over every live host: ASN, InternetDB, favicons,
    //    reverse IP and certificate SANs. Then persist the artefacts.
    let live_primaries: Vec<String> = hosts
        .iter()
        .filter(|h| h.status > 0 && h.alias_of.is_none())
        .map(|h| h.host.clone())
        .collect();
    let mut osint_final: Option<osint::OsintReport> = None;
    for (root, mut rep) in osint_reports {
        if let Err(e) = osint::enrich(
            http,
            resolver,
            scope,
            &mut rep,
            &live_primaries,
            &osint_opts,
        )
        .await
        {
            log::warn(&format!("OSINT enrich failed for {root}: {e:#}"));
        }
        let dir = if roots.len() == 1 {
            out.join(&target_name).join("osint")
        } else {
            out.join(&target_name).join("osint").join(util::slug(&root))
        };
        if let Err(e) = osint::write_artifacts(&dir, &rep) {
            log::warn(&format!("osint artifacts: {e:#}"));
        }
        log::ok(&format!(
            "OSINT: {} hostów z ASN, {} favicon, {} powiązanych",
            rep.host_asn.len(),
            rep.favicons.len(),
            rep.related.len()
        ));
        osint_final = Some(rep);
    }

    // 9. Report
    let mut notes: Vec<String> = Vec::new();
    if !scope.is_enforced() {
        notes.push(
            "Zakres nie był wymuszony. Upewnij się, że masz zgodę na testowanie tych hostów."
                .to_string(),
        );
    }
    if cancelled {
        notes.push(
            "Skan zatrzymany przez użytkownika; raport zawiera dane z ukończonych etapów."
                .to_string(),
        );
    }
    if truncated {
        notes.push(format!(
            "Osiągnięto limit {max_hosts} hostów. Zwiększ --max-hosts, aby przeskanować resztę."
        ));
    }
    if stopped_at_depth {
        notes.push(format!(
            "Rekurencję zatrzymano na --depth {}. W kolejce zostały nowe hosty.",
            args.depth
        ));
    }
    if skipped_by_flag {
        notes
            .push("Rekurencja była wyłączona (--no-recurse); odkryte hosty pominięto.".to_string());
    }
    if args.skip_paths {
        notes.push(
            "Pominięto sprawdzenia ścieżek (--skip-paths), więc stacja paths w śledzeniu pokrycia jest pusta."
                .to_string(),
        );
    }
    if args.wayback && wayback_urls.is_empty() {
        notes.push("Wayback Machine nie zwrócił URL-i dla tego celu.".to_string());
    }
    if hosts.is_empty() {
        notes.push(
            "Żaden host nie odpowiedział po HTTP. Sprawdź DNS, firewall i --timeout.".to_string(),
        );
    } else if crawl_all.pages.is_empty() {
        notes.push(
            "Crawl nie pobrał żadnej strony HTML — cele mogą zwracać tylko JSON albo blokować ruch."
                .to_string(),
        );
    }

    let display_target = if inputs.len() == 1 {
        inputs[0].clone()
    } else {
        target_name.clone()
    };

    let subdomains: Vec<String> = known.into_iter().collect();
    let dir = out.join(&target_name);
    let data = report::ReportData {
        target: display_target,
        scope_enforced: scope.is_enforced(),
        started,
        subdomains: &subdomains,
        hosts: &hosts,
        crawl: &crawl_all,
        paths: &paths_all,
        findings: &findings,
        triage: &triage,
        wayback: &wayback_urls,
        notes: &notes,
        osint: osint_final.as_ref(),
    };
    report::write_all(&dir, &data)?;

    log::ok(&format!(
        "gotowe: {} hostów, {} ustaleń",
        hosts.len(),
        findings.len()
    ));
    Ok(dir)
}

fn now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(rules: &str) -> Scope {
        Scope::from_text(rules, true).unwrap()
    }

    #[test]
    fn harvest_takes_only_new_in_scope_hosts() {
        let scope = scope("example.com\n");
        let mut seen = BTreeSet::new();
        seen.insert("www.example.com".to_string());
        let mut known = BTreeSet::new();
        known.insert("www.example.com".to_string());

        let urls = vec![
            "https://dev.example.com/a".to_string(),
            "https://api.example.com/v1".to_string(),
            "https://evil.net/x".to_string(),
            "https://www.example.com/known".to_string(),
        ];
        let redirects = vec!["https://stage.example.com/".to_string()];

        let found = harvest_hosts(&scope, urls, redirects, &seen, &known);
        assert_eq!(
            found,
            vec![
                "api.example.com".to_string(),
                "dev.example.com".to_string(),
                "stage.example.com".to_string()
            ]
        );
    }

    #[test]
    fn harvest_respects_scope_glob_and_apex() {
        let scope = scope("*.lab.example\n");
        let empty_seen = BTreeSet::new();
        let empty_known = BTreeSet::new();
        let found = harvest_hosts(
            &scope,
            vec![
                "https://a.lab.example/".to_string(),
                "https://lab.example/".to_string(),
            ],
            Vec::new(),
            &empty_seen,
            &empty_known,
        );
        assert_eq!(found, vec!["a.lab.example".to_string()]);
    }
}
