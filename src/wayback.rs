use std::collections::BTreeSet;

use crate::http::Http;
use crate::log;
use crate::scope::Scope;
use crate::util;

/// Historical URLs from the Wayback CDX index. Only metadata (URL strings) is
/// fetched, never the archived pages themselves.
pub async fn wayback(http: &Http, root: &str, limit: usize, scope: &Scope) -> BTreeSet<String> {
    log::stage(&format!("wayback CDX: *.{root}"));
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url=*.{root}&output=txt&fl=original\
         &collapse=urlkey&filter=statuscode:200&limit={limit}&from=2018"
    );
    let mut out = BTreeSet::new();
    match http.fetch(&url, &[], 6_000_000).await {
        Ok(f) if f.status == 200 => {
            for line in f.body.lines() {
                let line = line.trim();
                if !line.starts_with("http") {
                    continue;
                }
                if let Some(h) = util::host_of(line) {
                    if scope.allows(&h) {
                        out.insert(line.to_string());
                    }
                }
            }
            log::ok(&format!("{} archived urls", out.len()));
        }
        Ok(f) => log::warn(&format!("wayback returned HTTP {}", f.status)),
        Err(e) => log::warn(&format!("wayback failed: {e:#}")),
    }
    out
}
