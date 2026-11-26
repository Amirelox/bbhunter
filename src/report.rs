use anyhow::{Context, Result};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::crawl::CrawlResult;
use crate::findings::{Finding, Findings, Severity, Stage};
use crate::osint;
use crate::paths::PathScan;
use crate::probe::HostResult;
use crate::triage::{self, Triage};

const FONTS_CSS: &str = include_str!("../design/fonts.css");
const TOKENS_CSS: &str = include_str!("../design/tokens.css");
const REPORT_CSS: &str = include_str!("../design/report.css");

pub struct ReportData<'a> {
    pub target: String,
    pub scope_enforced: bool,
    pub started: String,
    pub subdomains: &'a [String],
    pub hosts: &'a [HostResult],
    pub crawl: &'a CrawlResult,
    pub paths: &'a PathScan,
    pub findings: &'a Findings,
    pub triage: &'a Triage,
    pub wayback: &'a BTreeSet<String>,
    pub notes: &'a [String],
    pub osint: Option<&'a osint::OsintReport>,
}

// ---------------------------------------------------------------- helpers

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Polska odmiana: 1 → one, 2–4 → few, 5+ (i 12–14) → many.
fn plural<'a>(n: usize, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let m10 = n % 10;
    let m100 = n % 100;
    if n == 1 {
        one
    } else if (2..=4).contains(&m10) && !(12..=14).contains(&m100) {
        few
    } else {
        many
    }
}

fn sev_name(sev: Severity) -> &'static str {
    match sev {
        Severity::High => "wysokie",
        Severity::Medium => "średnie",
        Severity::Low => "niskie",
        Severity::Info => "informacyjne",
    }
}

/// Przymiotnik w liczbie mnogiej: 1–4 „wysokie”, 5+ „wysokich”.
fn sev_adj(n: usize, sev: Severity) -> &'static str {
    let few = n == 1 || ((2..=4).contains(&(n % 10)) && !(12..=14).contains(&(n % 100)));
    match (sev, few) {
        (Severity::High, true) => "wysokie",
        (Severity::High, false) => "wysokich",
        (Severity::Medium, true) => "średnie",
        (Severity::Medium, false) => "średnich",
        (Severity::Low, true) => "niskie",
        (Severity::Low, false) => "niskich",
        (Severity::Info, true) => "informacyjne",
        (Severity::Info, false) => "informacyjnych",
    }
}

fn headline_phrase(n: usize, sev: Severity) -> String {
    let (one, few, many) = match sev {
        Severity::High => ("wysokie ustalenie", "wysokie ustalenia", "wysokich ustaleń"),
        Severity::Medium => ("średnie ustalenie", "średnie ustalenia", "średnich ustaleń"),
        Severity::Low => ("niskie ustalenie", "niskie ustalenia", "niskich ustaleń"),
        Severity::Info => (
            "informacyjne ustalenie",
            "informacyjne ustalenia",
            "informacyjnych ustaleń",
        ),
    };
    plural(n, one, few, many).to_string()
}

fn sev_at(index: usize) -> Severity {
    match index {
        0 => Severity::High,
        1 => Severity::Medium,
        2 => Severity::Low,
        _ => Severity::Info,
    }
}

fn counts(findings: &Findings) -> [usize; 4] {
    let mut c = [0usize; 4];
    for f in findings.items() {
        let i = match f.severity {
            Severity::High => 0,
            Severity::Medium => 1,
            Severity::Low => 2,
            Severity::Info => 3,
        };
        c[i] += 1;
    }
    c
}

fn stage_counts(findings: &Findings, stage: Stage) -> [usize; 4] {
    let mut c = [0usize; 4];
    for f in findings.items().iter().filter(|f| f.stage == stage) {
        let i = match f.severity {
            Severity::High => 0,
            Severity::Medium => 1,
            Severity::Low => 2,
            Severity::Info => 3,
        };
        c[i] += 1;
    }
    c
}

fn worst(counts: [usize; 4]) -> &'static str {
    if counts[0] > 0 {
        "high"
    } else if counts[1] > 0 {
        "medium"
    } else if counts[2] > 0 {
        "low"
    } else {
        "none"
    }
}

fn sev_parts(counts: [usize; 4]) -> Vec<(Severity, usize)> {
    let mut parts: Vec<(Severity, usize)> = Vec::new();
    for (i, n) in counts.iter().enumerate() {
        if *n > 0 {
            parts.push((sev_at(i), *n));
        }
    }
    parts
}

fn primary_hosts<'a>(data: &'a ReportData<'_>) -> Vec<&'a HostResult> {
    data.hosts.iter().filter(|h| h.alias_of.is_none()).collect()
}

fn all_urls(data: &ReportData) -> BTreeSet<String> {
    let mut urls: BTreeSet<String> = BTreeSet::new();
    urls.extend(data.crawl.urls.iter().cloned());
    urls.extend(data.crawl.endpoints.iter().cloned());
    urls.extend(data.paths.extra_urls.iter().cloned());
    urls.extend(data.wayback.iter().cloned());
    urls
}

fn split_port(target: &str) -> (String, Option<String>) {
    match target.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), Some(port.to_string()))
        }
        _ => (target.to_string(), None),
    }
}

/// Display label for a finding category. JSON keeps the stable English key.
fn category_label(cat: &str) -> &str {
    match cat {
        "headers" => "nagłówki",
        "cookies" => "ciasteczka",
        "cors" => "CORS",
        "disclosure" => "ujawnienie",
        "exposed-git" => "repozytorium git",
        "exposed-config" => "konfiguracja",
        "exposed-meta" => "metadane",
        "exposed-vcs" => "kontrola wersji",
        "exposed-credentials" => "poświadczenia",
        "exposed-debug" => "debug",
        "exposed-metrics" => "metryki",
        "api-docs" => "dokumentacja API",
        "auth-surface" => "powierzchnia logowania",
        "meta" => "meta",
        "directory-listing" => "listowanie katalogu",
        "secret-in-js" => "sekret w JS",
        other => other,
    }
}

/// `2026-11-24 20:25:52` → `24 lis 2026, 20:25`.
fn pl_datetime(stamp: &str) -> String {
    let parts: Vec<&str> = stamp
        .split(['-', ' ', ':'])
        .filter(|p| !p.is_empty())
        .collect();
    if parts.len() < 5 {
        return stamp.to_string();
    }
    let (y, m, d, h, min) = (parts[0], parts[1], parts[2], parts[3], parts[4]);
    let months = [
        "sty", "lut", "mar", "kwi", "maj", "cze", "lip", "sie", "wrz", "paź", "lis", "gru",
    ];
    let month = m
        .parse::<usize>()
        .ok()
        .and_then(|i| months.get(i.saturating_sub(1)))
        .copied()
        .unwrap_or(m);
    format!("{d} {month} {y}, {h}:{min}")
}

fn stage_label(stage: Stage) -> &'static str {
    match stage {
        Stage::Probe => "sonda",
        Stage::Crawl => "crawl",
        Stage::Paths => "ścieżki",
    }
}

fn status_class(code: u16) -> &'static str {
    if code == 0 {
        return "0";
    }
    match code / 100 {
        2 => "2",
        3 => "3",
        4 => "4",
        _ => "5",
    }
}

fn link(url: &str, label: &str) -> String {
    format!(
        r#"<a href="{}" rel="noreferrer">{}</a>"#,
        esc(url),
        esc(label)
    )
}

/// Lead items may carry a suffix such as `  [keys: id,next]`; link only the URL part.
fn lead_href(item: &str) -> Option<&str> {
    let candidate = item.split("  [").next().unwrap_or(item).trim();
    if url::Url::parse(candidate).is_ok() {
        Some(candidate)
    } else {
        None
    }
}

// ------------------------------------------------------------------ parts

fn render_trace(data: &ReportData) -> String {
    let probe = stage_counts(data.findings, Stage::Probe);
    let crawl = stage_counts(data.findings, Stage::Crawl);
    let paths = stage_counts(data.findings, Stage::Paths);

    type Station = (
        usize,
        &'static str,
        &'static str,
        Vec<(Severity, usize)>,
        &'static str,
    );
    let stations: [Station; 4] = [
        (
            data.subdomains.len(),
            plural(data.subdomains.len(), "subdomena", "subdomeny", "subdomen"),
            "none",
            Vec::new(),
            "wejście skanu",
        ),
        (
            primary_hosts(data).len(),
            plural(primary_hosts(data).len(), "host", "hosty", "hostów"),
            worst(probe),
            sev_parts(probe),
            "brak ustaleń",
        ),
        (
            data.crawl.pages.len(),
            plural(data.crawl.pages.len(), "strona", "strony", "stron"),
            worst(crawl),
            sev_parts(crawl),
            "brak ustaleń",
        ),
        (
            data.paths.checked,
            plural(data.paths.checked, "ścieżka", "ścieżki", "ścieżek"),
            worst(paths),
            sev_parts(paths),
            "brak ustaleń",
        ),
    ];

    let mut items = String::new();
    for (value, noun, sev, parts, empty) in stations {
        let line = if parts.is_empty() {
            esc(empty)
        } else {
            parts
                .iter()
                .map(|(sev, n)| {
                    format!(
                        "<span class=\"sevpart {}\">{} {}</span>",
                        sev.as_str(),
                        n,
                        esc(sev_adj(*n, *sev))
                    )
                })
                .collect::<Vec<_>>()
                .join(" · ")
        };
        items.push_str(&format!(
            r#"<li class="st" data-sev="{sev}">
  <p class="st__num num">{value}</p>
  <p class="st__label">{noun}</p>
  <p class="st__sev">{line}</p>
</li>
"#,
            sev = sev,
            value = value,
            noun = esc(noun),
            line = line,
        ));
    }

    format!(
        r#"<section class="trace" aria-labelledby="trace-title">
  <div class="wrap">
    <h2 id="trace-title" class="sr-only">Pokrycie skanu</h2>
    <ol class="trace__list">
{items}    </ol>
  </div>
</section>"#
    )
}

fn render_ledger(data: &ReportData) -> String {
    if data.findings.is_empty() {
        let hosts = format!(
            "{} {}",
            data.hosts.len(),
            plural(data.hosts.len(), "hoście", "hostach", "hostach")
        );
        let paths = format!(
            "{} {}",
            data.paths.checked,
            plural(data.paths.checked, "ścieżce", "ścieżkach", "ścieżkach")
        );
        return format!(
            r#"<div class="note">
  <p class="note__title">Brak ustaleń z automatycznych sprawdzeń</p>
  <p class="note__body">Nie znaleziono ustaleń w {hosts} i {paths}. Przejrzyj leady poniżej — to adresy zebrane z HTML-a i JS-a, które warto otworzyć ręcznie.</p>
</div>"#
        );
    }

    let mut groups: Vec<(&Finding, Vec<String>)> = Vec::new();
    let mut index: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for f in data.findings.items() {
        let key = (
            f.severity.as_str().to_string(),
            f.title.clone(),
            f.category.clone(),
        );
        match index.get(&key) {
            Some(&i) => groups[i].1.push(f.host.clone()),
            None => {
                index.insert(key, groups.len());
                groups.push((f, vec![f.host.clone()]));
            }
        }
    }

    let mut rows = String::new();
    for (f, hosts) in groups {
        let host_cell = if hosts.len() > 1 {
            format!(
                "{}<span class=\"alias-note\">+{} hostów</span>",
                esc(&hosts[0]),
                hosts.len() - 1
            )
        } else {
            esc(&hosts[0])
        };
        rows.push_str(&format!(
            r#"<tr data-sev="{sev}">
  <td class="c-sev"><span class="sev">{sev_name}</span></td>
  <td class="c-find">
    <span class="find__title">{title}</span>
    <span class="find__path">{url} · {category}</span>
  </td>
  <td class="c-host cell-host">{host_cell}</td>
  <td class="c-stage cell-stage">{stage}</td>
</tr>
"#,
            sev = f.severity.as_str(),
            sev_name = sev_name(f.severity),
            title = esc(&f.title),
            url = link(&f.url, &f.url),
            category = esc(category_label(&f.category)),
            host_cell = host_cell,
            stage = stage_label(f.stage),
        ));
    }

    format!(
        r#"<table class="ledger">
  <caption class="sr-only">Ustalenia z automatycznych sprawdzeń, od najwyższej wagi</caption>
  <thead>
    <tr>
      <th scope="col" class="c-sev">Waga</th>
      <th scope="col">Ustalenie</th>
      <th scope="col" class="c-host">Host</th>
      <th scope="col" class="c-stage">Etap</th>
    </tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>"#
    )
}

fn render_hosts(data: &ReportData) -> String {
    if data.hosts.is_empty() {
        return r#"<div class="note">
  <p class="note__title">Brak odpowiedzi po HTTP</p>
  <p class="note__body">Żaden host nie odpowiedział w limicie czasu. Sprawdź rozwiązywanie DNS, firewall i wartość --timeout, potem uruchom probe ponownie.</p>
</div>"#
            .to_string();
    }

    let mut aliases: BTreeMap<&str, Vec<&HostResult>> = BTreeMap::new();
    for h in data.hosts.iter() {
        if let Some(primary) = &h.alias_of {
            aliases.entry(primary.as_str()).or_default().push(h);
        }
    }
    let primaries: Vec<&HostResult> = data.hosts.iter().filter(|h| h.alias_of.is_none()).collect();

    let mut rows = String::new();
    for h in primaries.iter().copied() {
        let tech = if !h.services.is_empty() {
            h.services.join(" · ")
        } else if h.tech.is_empty() {
            "—".to_string()
        } else {
            h.tech.join(" · ")
        };
        let title = if h.status == 0 {
            "host bez HTTP".to_string()
        } else if h.title.is_empty() {
            "—".to_string()
        } else {
            h.title.clone()
        };
        let alias_line = match aliases.get(h.host.as_str()) {
            Some(list) if !list.is_empty() => {
                let names: Vec<&str> = list.iter().take(4).map(|a| a.host.as_str()).collect();
                let extra = list.len().saturating_sub(4);
                format!(
                    "<span class=\"alias-note\">aliasy: {}{}</span>",
                    esc(&names.join(", ")),
                    if extra > 0 {
                        format!(" +{extra}")
                    } else {
                        String::new()
                    }
                )
            }
            _ => String::new(),
        };
        rows.push_str(&format!(
            r#"<tr>
  <td class="c-name"><span class="cell-name">{host}</span>{alias_line}</td>
  <td class="c-status"><span class="status" data-class="{cls}">{code}</span></td>
  <td class="c-tech cell-tech">{tech}</td>
  <td class="c-title cell-title">{title}</td>
</tr>
"#,
            host = esc(&h.host),
            cls = status_class(h.status),
            code = if h.status == 0 {
                "—".to_string()
            } else {
                h.status.to_string()
            },
            tech = esc(&tech),
            title = esc(&title),
        ));
    }

    format!(
        r#"<table class="hosts">
  <caption class="sr-only">Hosty, które odpowiedziały po HTTP</caption>
  <thead>
    <tr>
      <th scope="col" class="c-name">Host</th>
      <th scope="col" class="c-status">Status</th>
      <th scope="col" class="c-tech">Technologie</th>
      <th scope="col" class="c-title">Tytuł</th>
    </tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>"#
    )
}

fn render_leads(data: &ReportData) -> String {
    let mut buckets: Vec<(&str, &BTreeSet<String>)> = triage::ALL_BUCKETS
        .iter()
        .filter_map(|b| data.triage.get(b).map(|items| (*b, items)))
        .collect();
    buckets.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));

    if buckets.is_empty() {
        return r#"<div class="note">
  <p class="note__title">Brak leadów</p>
  <p class="note__body">Crawl nie zebrał adresów z parametrami, endpointów ani paneli. Zwiększ --max-pages albo dodaj adresy przez -l.</p>
</div>"#
            .to_string();
    }

    let mut out = String::from(r#"<div class="leads">"#);
    for (bucket, items) in buckets {
        let mut list = String::new();
        for item in items.iter() {
            match lead_href(item) {
                Some(href) => list.push_str(&format!("<li>{}</li>\n", link(href, item))),
                None => list.push_str(&format!("<li><span>{}</span></li>\n", esc(item))),
            }
        }
        out.push_str(&format!(
            r#"<details class="lead">
  <summary><span class="lead__name">{bucket}</span><span class="lead__n">{n}</span></summary>
  <ul class="lead__list">
{list}  </ul>
</details>
"#,
            bucket = esc(bucket),
            n = items.len(),
            list = list,
        ));
    }
    out.push_str("</div>");
    out
}

fn render_rail(data: &ReportData, urls: &BTreeSet<String>) -> String {
    let mut out = String::from(r#"<aside class="rail" aria-label="Podsumowanie skanu">"#);

    // Zasięg
    let rows = [
        (
            plural(data.subdomains.len(), "subdomena", "subdomeny", "subdomen"),
            data.subdomains.len(),
        ),
        (
            plural(primary_hosts(data).len(), "host", "hosty", "hostów"),
            primary_hosts(data).len(),
        ),
        (
            plural(urls.len(), "adres URL", "adresy URL", "adresów URL"),
            urls.len(),
        ),
        (
            plural(
                data.crawl.endpoints.len(),
                "endpoint",
                "endpointy",
                "endpointów",
            ),
            data.crawl.endpoints.len(),
        ),
        (
            plural(data.crawl.js.len(), "plik JS", "pliki JS", "plików JS"),
            data.crawl.js.len(),
        ),
        (
            plural(
                data.crawl.secrets.len(),
                "potencjalny sekret",
                "potencjalne sekrety",
                "potencjalnych sekretów",
            ),
            data.crawl.secrets.len(),
        ),
    ];
    let alias_count = data.hosts.iter().filter(|h| h.alias_of.is_some()).count();
    let mut rows_html = String::new();
    for (label, n) in rows {
        rows_html.push_str(&format!(
            "<li><span>{}</span><span class=\"n\">{}</span></li>\n",
            esc(label),
            n
        ));
    }
    if alias_count > 0 {
        rows_html.push_str(&format!(
            "<li><span>aliasy</span><span class=\"n\">{alias_count}</span></li>\n"
        ));
    }
    out.push_str(&format!(
        r#"<section aria-label="Zasięg">
  <p class="rail__label"><span class="tick" aria-hidden="true"></span>Zasięg</p>
  <ul class="rows">
{rows_html}  </ul>
</section>"#
    ));

    // Statusy
    let mut by_class = [0usize; 4]; // 2xx,3xx,4xx,5xx
    for h in data.hosts {
        match status_class(h.status) {
            "2" => by_class[0] += 1,
            "3" => by_class[1] += 1,
            "4" => by_class[2] += 1,
            _ => by_class[3] += 1,
        }
    }
    let max = by_class.iter().copied().max().unwrap_or(0).max(1);
    let labels = [
        ("2xx", None::<&str>),
        ("3xx", None),
        ("4xx", Some("medium")),
        ("5xx", Some("high")),
    ];
    let mut bars = String::new();
    for (i, (label, sev)) in labels.iter().enumerate() {
        let n = by_class[i];
        let width = if n == 0 { 0 } else { (n * 100 / max).max(4) };
        let attr = match sev {
            Some(s) => format!(" data-sev=\"{s}\""),
            None => String::new(),
        };
        bars.push_str(&format!(
            "<li{attr}><span class=\"bars__label\">{label}</span><span class=\"bars__bar\"><i style=\"--v:{width}%\"></i></span><span class=\"bars__n\">{n}</span></li>\n"
        ));
    }
    out.push_str(&format!(
        r#"<section aria-label="Statusy odpowiedzi">
  <p class="rail__label"><span class="tick" aria-hidden="true"></span>Statusy</p>
  <ul class="bars">
{bars}  </ul>
</section>"#
    ));

    // OSINT
    if let Some(o) = data.osint {
        let summary = o.summary();
        let rows = [
            ("subdomeny", summary.subdomains),
            ("kandydaci chmury", summary.cloud),
            ("dorki", summary.dorks),
            ("trafienia w kodzie", summary.code_hits),
            ("favicony", summary.favicons),
        ];
        let mut html = String::new();
        for (label, n) in rows {
            html.push_str(&format!(
                "<li><span>{}</span><span class=\"n\">{}</span></li>\n",
                esc(label),
                n
            ));
        }
        out.push_str(&format!(
            r#"<section aria-label="OSINT">
  <p class="rail__label"><span class="tick" aria-hidden="true"></span>OSINT</p>
  <ul class="rows">
{html}  </ul>
</section>"#
        ));
    }

    // Uwagi
    if !data.notes.is_empty() {
        let mut list = String::new();
        for note in data.notes {
            list.push_str(&format!("<li>{}</li>\n", esc(note)));
        }
        out.push_str(&format!(
            r#"<section aria-label="Uwagi skanu">
  <p class="rail__label"><span class="tick" aria-hidden="true"></span>Uwagi</p>
  <ul class="note__list">
{list}  </ul>
</section>"#
        ));
    }

    out.push_str("</aside>");
    out
}

fn render_footer(data: &ReportData) -> String {
    let mut extra = String::new();
    if !data.scope_enforced {
        extra.push_str(
            "<p><strong>Zakres nie był wymuszony.</strong> Skan uruchomiono z --no-scope-check. Przed zgłoszeniem sprawdź, czy program obejmuje te hosty.</p>\n",
        );
    }
    format!(
        r#"<footer class="footer">
  <div class="wrap">
    <p>Wyniki automatyczne to tropy, nie potwierdzone podatności. Otwórz każdy wysoko oceniony wiersz w Burpie i potwierdź wpływ, zanim zgłosisz.</p>
    <p class="mono">bbhunter {version} · wygenerowano {started}</p>
{extra}  </div>
</footer>"#,
        version = env!("CARGO_PKG_VERSION"),
        started = esc(&pl_datetime(&data.started)),
        extra = extra,
    )
}

fn render_osint(o: &osint::OsintReport) -> String {
    let mut body = String::new();

    if let Some(r) = &o.rdap {
        let mut kv = String::new();
        if let Some(v) = &r.registrar {
            kv.push_str(&format!("<dt>Rejestrator</dt><dd>{}</dd>", esc(v)));
        }
        if let Some(v) = &r.registered {
            kv.push_str(&format!("<dt>Rejestracja</dt><dd>{}</dd>", esc(v)));
        }
        if let Some(v) = &r.expires {
            kv.push_str(&format!("<dt>Wygasa</dt><dd>{}</dd>", esc(v)));
        }
        if !r.nameservers.is_empty() {
            kv.push_str(&format!(
                "<dt>Nameservery</dt><dd>{}</dd>",
                esc(&r.nameservers.join(", "))
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>RDAP</h3><dl class=\"kv\">{kv}</dl></div>"
        ));
    }

    if !o.asn.is_empty() {
        let mut seen: BTreeSet<(u32, String)> = BTreeSet::new();
        let mut rows = String::new();
        for a in &o.asn {
            let prefix = a.prefixes.first().cloned().unwrap_or_default();
            if !seen.insert((a.asn, prefix.clone())) {
                continue;
            }
            rows.push_str(&format!(
                "<tr><td class=\"mono\">AS{}</td><td>{}</td><td class=\"mono\">{}</td></tr>",
                a.asn,
                esc(&a.name),
                esc(&prefix)
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>ASN i prefiksy</h3><table class=\"hosts\"><thead><tr><th>ASN</th><th>Operator</th><th>Prefiks</th></tr></thead><tbody>{rows}</tbody></table></div>"
        ));
    }

    if !o.cloud.is_empty() {
        let mut rows = String::new();
        for c in &o.cloud {
            rows.push_str(&format!(
                "<tr><td>{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td>{}</td><td>{}</td></tr>",
                esc(c.provider),
                esc(&c.name),
                c.status,
                esc(c.kind),
                if c.mentions_domain { "tak" } else { "—" }
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>Kandydaci w chmurze</h3><table class=\"hosts\"><thead><tr><th>Dostawca</th><th>Nazwa</th><th>HTTP</th><th>Status</th><th>Domena w listingu</th></tr></thead><tbody>{rows}</tbody></table><p class=\"alias-note\">Istnienie nazwy nie potwierdza własności; sprawdź przed zgłoszeniem.</p></div>"
        ));
    }

    if !o.favicons.is_empty() {
        let mut rows = String::new();
        for g in &o.favicons {
            rows.push_str(&format!(
                "<li><span class=\"mono\">{}</span> · {}</li>",
                g.hash,
                esc(&g.hosts.join(", "))
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>Favicony</h3><ul class=\"lead__list\">{rows}</ul></div>"
        ));
    }

    if !o.related.is_empty() {
        let mut rows = String::new();
        for r in &o.related {
            rows.push_str(&format!(
                "<li><span class=\"mono\">{}</span> · <span class=\"tag{}\">{}</span> · {}</li>",
                esc(&r.name),
                if r.in_scope { " tag--in" } else { "" },
                if r.in_scope {
                    "w zakresie"
                } else {
                    "poza zakresem"
                },
                esc(r.source)
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>Powiązane hosty</h3><ul class=\"lead__list\">{rows}</ul></div>"
        ));
    }

    if !o.dorks.is_empty() {
        let mut rows = String::new();
        for d in &o.dorks {
            rows.push_str(&format!(
                "<li><a href=\"{}\" rel=\"noreferrer\">{} — {}</a></li>",
                esc(&d.url),
                esc(d.engine),
                esc(d.label)
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>Dorki</h3><ul class=\"lead__list\">{rows}</ul></div>"
        ));
    }

    if !o.code_hits.is_empty() {
        let mut rows = String::new();
        for h in &o.code_hits {
            rows.push_str(&format!(
                "<li><a href=\"{}\" rel=\"noreferrer\">{}</a> · <span class=\"mono\">{}</span></li>",
                esc(&h.url),
                esc(&h.repo),
                esc(&h.path)
            ));
        }
        body.push_str(&format!(
            "<div class=\"osint-sub\"><h3>Kod publiczny</h3><ul class=\"lead__list\">{rows}</ul></div>"
        ));
    }

    if body.is_empty() {
        return String::new();
    }

    format!(
        r#"<section class="block" aria-labelledby="osint-title">
  <div class="block__head">
    <h2 id="osint-title"><span class="tick" aria-hidden="true"></span>OSINT</h2>
    <p class="block__meta">{}</p>
  </div>
  {body}
</section>"#,
        o.subdomains.len()
    )
}

fn render_weights(data: &ReportData) -> String {
    let c = counts(data.findings);
    let total: usize = c.iter().sum();
    if total == 0 {
        return r#"<section class="weights" aria-label="Rozkład wag">
  <div class="wrap weights__inner"><p class="weights__title">rozkład wag</p><p class="weights__empty">brak ustaleń · czysty przebieg</p></div>
</section>"#
            .to_string();
    }

    let parts = [
        ("high", c[0], "wysokie"),
        ("medium", c[1], "średnie"),
        ("low", c[2], "niskie"),
        ("info", c[3], "informacyjne"),
    ];
    let bars = parts
        .iter()
        .filter(|(_, n, _)| *n > 0)
        .map(|(key, n, _)| {
            format!(
                "<span data-sev=\"{key}\" style=\"width:{:.2}%\"></span>",
                (*n as f64 / total as f64) * 100.0
            )
        })
        .collect::<String>();
    let legend = parts
        .iter()
        .map(|(key, n, label)| {
            format!(
                "<li><span class=\"weights__dot\" data-sev=\"{key}\"></span><span class=\"weights__n\">{n}</span><span>{label}</span></li>"
            )
        })
        .collect::<String>();

    format!(
        r#"<section class="weights" aria-label="Rozkład wag">
  <div class="wrap weights__inner">
    <p class="weights__title">rozkład wag</p>
    <div class="weights__bar" aria-hidden="true">{bars}</div>
    <ul class="weights__legend">{legend}</ul>
  </div>
</section>"#
    )
}

// ------------------------------------------------------------------- html

fn html(data: &ReportData) -> String {
    let urls = all_urls(data);
    let c = counts(data.findings);
    let total = data.findings.len();

    let (head_sev, head_n) = if c[0] > 0 {
        (Some(Severity::High), c[0])
    } else if c[1] > 0 {
        (Some(Severity::Medium), c[1])
    } else if c[2] > 0 {
        (Some(Severity::Low), c[2])
    } else if c[3] > 0 {
        (Some(Severity::Info), c[3])
    } else {
        (None, 0)
    };

    let (target_host, port) = split_port(&data.target);
    let port_html = port
        .map(|p| format!(r#"<span class="target__port">:{}</span>"#, esc(&p)))
        .unwrap_or_default();
    let figure_label = match head_sev {
        Some(sev) => headline_phrase(head_n, sev),
        None => "ustaleń".to_string(),
    };
    let osint_section = data.osint.map(render_osint).unwrap_or_default();
    let figure_of = if total == 0 {
        "automatyczne sprawdzenia".to_string()
    } else {
        format!(
            "łącznie {} {}",
            total,
            plural(total, "ustalenie", "ustalenia", "ustaleń")
        )
    };

    let scope_text = if data.scope_enforced {
        "zakres wymuszony"
    } else {
        "zakres bez wymuszania"
    };

    format!(
        r##"<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="theme-color" content="#151a13">
<meta name="robots" content="noindex">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%23151a13'/%3E%3Crect x='8' y='8' width='16' height='16' fill='none' stroke='%23c8f36a'/%3E%3Crect x='13' y='13' width='6' height='6' fill='%23c8f36a'/%3E%3C/svg%3E">
<title>Raport rekonesansu — {target} · bbhunter</title>
<style>
{fonts}
{tokens}
{report_css}
</style>
</head>
<body>
<a class="skip" href="#tresc">Przejdź do treści</a>

<header class="masthead">
  <div class="wrap masthead__bar">
    <p class="brandline"><span class="brandline__mark" aria-hidden="true"></span>bbhunter <span class="brandline__sep">·</span><span class="brandline__label">raport rekonesansu</span></p>
    <button class="print" type="button" title="Drukuj raport lub zapisz jako PDF" onclick="window.print()">Drukuj / PDF</button>
  </div>
  <div class="wrap masthead__inner">
    <div>
      <p class="kicker">wynik przebiegu</p>
      <h1 class="target">{target_host}{port_html}</h1>
      <p class="submeta">{started} · {scope_text} · {hosts_n} {hosts_word}</p>
    </div>
    <div class="figure" data-sev="{head_sev_token}">
      <p class="figure__num num">{head_n}</p>
      <div>
        <p class="figure__label">{figure_label}</p>
        <p class="figure__of">{figure_of}</p>
      </div>
    </div>
  </div>
</header>

{weights}
{trace}

<main id="tresc" class="wrap layout">
  <div class="col-main">
    <section class="block" aria-labelledby="findings-title">
      <div class="block__head">
        <h2 id="findings-title"><span class="tick" aria-hidden="true"></span>Ustalenia</h2>
        <p class="block__meta">{total}</p>
      </div>
      {ledger}
    </section>

    <section class="block" aria-labelledby="hosts-title">
      <div class="block__head">
        <h2 id="hosts-title"><span class="tick" aria-hidden="true"></span>Hosty</h2>
        <p class="block__meta">{hosts_n}</p>
      </div>
      {hosts}
    </section>

    <section class="block" aria-labelledby="leads-title">
      <div class="block__head">
        <h2 id="leads-title"><span class="tick" aria-hidden="true"></span>Leady według rodzaju</h2>
        <p class="block__meta">{leads_n}</p>
      </div>
      {leads}
    </section>
    {osint_section}
  </div>

  {rail}
</main>

{footer}
</body>
</html>
"##,
        target = esc(&data.target),
        target_host = esc(&target_host),
        port_html = port_html,
        started = esc(&pl_datetime(&data.started)),
        scope_text = scope_text,
        hosts_n = primary_hosts(data).len(),
        hosts_word = plural(primary_hosts(data).len(), "host", "hosty", "hostów"),
        head_sev_token = head_sev.map(|s| s.as_str()).unwrap_or("none"),
        head_n = head_n,
        figure_label = esc(&figure_label),
        figure_of = esc(&figure_of),
        weights = render_weights(data),
        trace = render_trace(data),
        total = total,
        ledger = render_ledger(data),
        hosts = render_hosts(data),
        leads = render_leads(data),
        leads_n = data.triage.total(),
        osint_section = osint_section,
        rail = render_rail(data, &urls),
        footer = render_footer(data),
        fonts = FONTS_CSS,
        tokens = TOKENS_CSS,
        report_css = REPORT_CSS,
    )
}

// --------------------------------------------------------------- markdown

fn markdown(data: &ReportData) -> String {
    let urls = all_urls(data);
    let c = counts(data.findings);
    let mut md = String::new();

    md.push_str(&format!("# Raport rekonesansu — {}\n\n", data.target));
    md.push_str(&format!("- Wygenerowano: {}\n", pl_datetime(&data.started)));
    md.push_str(&format!(
        "- Zakres: {}\n",
        if data.scope_enforced {
            "wymuszony"
        } else {
            "bez wymuszania (--no-scope-check)"
        }
    ));
    md.push_str(&format!("- Subdomeny: {}\n", data.subdomains.len()));
    md.push_str(&format!("- Hosty: {}\n", data.hosts.len()));
    md.push_str(&format!("- Adresy URL: {}\n", urls.len()));
    md.push_str(&format!("- Endpointy: {}\n", data.crawl.endpoints.len()));
    md.push_str(&format!("- Pliki JS: {}\n", data.crawl.js.len()));
    md.push_str(&format!("- Sekrety: {}\n", data.crawl.secrets.len()));
    md.push_str(&format!(
        "- Ustalenia: {} wysokich, {} średnich, {} niskich, {} informacyjnych\n\n",
        c[0], c[1], c[2], c[3]
    ));

    if !data.notes.is_empty() {
        md.push_str("## Uwagi\n\n");
        for note in data.notes {
            md.push_str(&format!("- {note}\n"));
        }
        md.push('\n');
    }

    md.push_str("## Ustalenia\n\n");
    if data.findings.is_empty() {
        md.push_str("_Brak ustaleń z automatycznych sprawdzeń._\n\n");
    } else {
        md.push_str("| Waga | Ustalenie | Host | Etap |\n|---|---|---|---|\n");
        for f in data.findings.items() {
            md.push_str(&format!(
                "| {} | {} — {} | `{}` | {} |\n",
                sev_name(f.severity),
                f.title.replace('|', "\\|"),
                f.url,
                f.host,
                stage_label(f.stage)
            ));
        }
        md.push('\n');
    }

    md.push_str("## Hosty\n\n");
    if data.hosts.is_empty() {
        md.push_str("_Brak odpowiedzi po HTTP._\n\n");
    } else {
        md.push_str("| Host | Status | Technologie | Tytuł |\n|---|---|---|---|\n");
        for h in data.hosts {
            let tech = if h.tech.is_empty() {
                "—".to_string()
            } else {
                h.tech.join(" · ")
            };
            md.push_str(&format!(
                "| `{}` | {} | {} | {} |\n",
                h.host,
                h.status,
                tech,
                h.title.replace('|', "\\|")
            ));
        }
        md.push('\n');
    }

    md.push_str("## Leady\n\n");
    let mut buckets: Vec<(&str, &BTreeSet<String>)> = triage::ALL_BUCKETS
        .iter()
        .filter_map(|b| data.triage.get(b).map(|items| (*b, items)))
        .collect();
    buckets.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
    if buckets.is_empty() {
        md.push_str("_Brak leadów._\n\n");
    } else {
        for (bucket, items) in buckets {
            md.push_str(&format!("### {} ({})\n\n", bucket, items.len()));
            for item in items.iter().take(40) {
                md.push_str(&format!("- {item}\n"));
            }
            if items.len() > 40 {
                md.push_str(&format!("- … i {} więcej\n", items.len() - 40));
            }
            md.push('\n');
        }
    }

    if let Some(o) = data.osint {
        md.push_str("## OSINT\n\n");
        if let Some(r) = &o.rdap {
            if let Some(v) = &r.registrar {
                md.push_str(&format!("- Rejestrator: {v}\n"));
            }
            if let Some(v) = &r.registered {
                md.push_str(&format!("- Rejestracja: {v}\n"));
            }
        }
        if !o.asn.is_empty() {
            let names: Vec<String> = o
                .asn
                .iter()
                .map(|a| format!("AS{} {}", a.asn, a.name))
                .collect();
            md.push_str(&format!("- ASN: {}\n", names.join(", ")));
        }
        if !o.cloud.is_empty() {
            md.push_str(&format!("- Kandydaci chmury: {}\n", o.cloud.len()));
        }
        if !o.favicons.is_empty() {
            md.push_str(&format!("- Grupy favicon: {}\n", o.favicons.len()));
        }
        if !o.related.is_empty() {
            md.push_str(&format!("- Powiązane hosty: {}\n", o.related.len()));
        }
        md.push_str("- Szczegóły: `osint/osint.md`\n\n");
    }

    md.push_str("## Co dalej\n\n");
    md.push_str("1. Potwierdź każdy wysoki i średni wiersz ręcznie w Burpie.\n");
    md.push_str("2. Zacznij od `interesting/auth-endpoints.txt`, `interesting/admin-panels.txt` i endpointów API.\n");
    md.push_str("3. Dla każdego sekretu sprawdź, czy klucz żyje i jaki ma zakres uprawnień.\n");
    md.push_str("4. Wrzuć `urls.txt` w swój workflow fuzzowania parametrów.\n");
    md
}

// --------------------------------------------------------------- zapis

fn write_list(path: &Path, items: impl IntoIterator<Item = impl AsRef<str>>) -> Result<usize> {
    let mut count = 0;
    let mut buf = String::new();
    for item in items {
        let s = item.as_ref();
        if s.is_empty() {
            continue;
        }
        buf.push_str(s);
        buf.push('\n');
        count += 1;
    }
    fs::write(path, buf).with_context(|| format!("writing {}", path.display()))?;
    Ok(count)
}

pub fn write_all(outdir: &Path, data: &ReportData) -> Result<PathBuf> {
    fs::create_dir_all(outdir).with_context(|| format!("creating {}", outdir.display()))?;
    let urls = all_urls(data);

    write_list(&outdir.join("subdomains.txt"), data.subdomains.iter())?;
    write_list(&outdir.join("urls.txt"), urls.iter())?;
    write_list(&outdir.join("js_files.txt"), data.crawl.js.iter())?;
    write_list(&outdir.join("endpoints.txt"), data.crawl.endpoints.iter())?;
    write_list(&outdir.join("forms.txt"), data.crawl.forms.iter())?;
    write_list(
        &outdir.join("secrets.txt"),
        data.crawl
            .secrets
            .iter()
            .map(|s| format!("{}  {}  {}", s.kind, s.url, s.preview)),
    )?;

    let live_lines: Vec<String> = data
        .hosts
        .iter()
        .map(|h| {
            format!(
                "{}\t{}\t{}\t{}\t{}",
                h.host,
                h.status,
                h.tech.join(","),
                h.title,
                h.final_url
            )
        })
        .collect();
    write_list(&outdir.join("live_hosts.txt"), live_lines.iter())?;

    let mut jsonl = String::new();
    for h in data.hosts {
        jsonl.push_str(&serde_json::to_string(h)?);
        jsonl.push('\n');
    }
    fs::write(outdir.join("hosts.jsonl"), jsonl)?;

    fs::write(
        outdir.join("findings.json"),
        serde_json::to_string_pretty(data.findings.items())?,
    )?;
    fs::write(outdir.join("report.md"), markdown(data))?;
    fs::write(outdir.join("report.html"), html(data))?;

    let interesting = outdir.join("interesting");
    fs::create_dir_all(&interesting)?;
    for bucket in triage::ALL_BUCKETS {
        if let Some(items) = data.triage.get(bucket) {
            write_list(&interesting.join(format!("{bucket}.txt")), items.iter())?;
        }
    }

    let c = counts(data.findings);
    let manifest = json!({
        "tool": "bbhunter",
        "version": env!("CARGO_PKG_VERSION"),
        "language": "pl",
        "target": data.target,
        "generated": data.started,
        "scope_enforced": data.scope_enforced,
        "counts": {
            "subdomains": data.subdomains.len(),
            "live_hosts": primary_hosts(data).len(),
            "aliases": data.hosts.iter().filter(|h| h.alias_of.is_some()).count(),
            "urls": urls.len(),
            "endpoints": data.crawl.endpoints.len(),
            "js_files": data.crawl.js.len(),
            "secrets": data.crawl.secrets.len(),
            "findings_high": c[0],
            "findings_medium": c[1],
            "findings_low": c[2],
            "findings_info": c[3],
        }
    });
    fs::write(
        outdir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    println!(
        "\n  {} subdomains · {} live · {} urls · {} endpoints · {} js · {} secrets",
        data.subdomains.len(),
        data.hosts.len(),
        urls.len(),
        data.crawl.endpoints.len(),
        data.crawl.js.len(),
        data.crawl.secrets.len()
    );
    println!(
        "  findings: {} high, {} medium, {} low, {} info",
        c[0], c[1], c[2], c[3]
    );
    if c[0] + c[1] > 0 {
        println!("\n  top findings:");
        for f in data
            .findings
            .items()
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .take(12)
        {
            println!(
                "   • [{}] {}  {}",
                f.severity.as_str().to_uppercase(),
                f.title,
                f.url
            );
        }
    }
    println!(
        "\n  report: {}\n  html:   {}\n",
        outdir.join("report.md").display(),
        outdir.join("report.html").display()
    );

    Ok(outdir.to_path_buf())
}
