use std::collections::BTreeSet;

use crate::http::Http;
use crate::log;
use crate::scope::Scope;
use crate::util;

/// Historical URLs from the Wayback CDX index, split into year ranges.
/// A single 20k query is a reliable timeout; three smaller ones are not.
pub async fn wayback(http: &Http, root: &str, limit: usize, scope: &Scope) -> BTreeSet<String> {
    log::stage(&format!("wayback CDX: *.{root}"));
    let mut out = BTreeSet::new();
    let per_range = limit.clamp(500, 8000);

    for (from, to) in [("2018", "2020"), ("2021", "2023"), ("2024", "2026")] {
        let url = format!(
            "https://web.archive.org/cdx/search/cdx?url=*.{root}&output=txt&fl=original\
             &collapse=urlkey&filter=statuscode:200&limit={per_range}&from={from}&to={to}"
        );
        match http.source_body(&url, 6_000_000).await {
            Ok(body) => {
                for line in body.lines() {
                    let line = line.trim();
                    if !line.starts_with("http") {
                        continue;
                    }
                    if let Some(host) = util::host_of(line) {
                        if scope.allows(&host) {
                            out.insert(line.to_string());
                        }
                    }
                }
            }
            Err(e) => log::warn(&format!("wayback {from}-{to} failed: {e:#}")),
        }
    }

    log::ok(&format!("{} archived urls", out.len()));
    out
}
