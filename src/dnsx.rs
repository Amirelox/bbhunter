use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::{config::ResolverConfig, config::ResolverOpts, TokioAsyncResolver};

#[derive(Clone)]
pub struct Resolver {
    inner: TokioAsyncResolver,
}

#[derive(Debug, Clone, Default)]
pub struct DnsInfo {
    pub ips: Vec<String>,
    pub cname: Option<String>,
}

impl Resolver {
    pub fn new() -> Self {
        // System resolvers by default, with a small cache.
        let mut opts = ResolverOpts::default();
        opts.cache_size = 8192;
        opts.timeout = std::time::Duration::from_secs(3);
        opts.attempts = 2;
        opts.num_concurrent_reqs = 128;
        Self {
            inner: TokioAsyncResolver::tokio(ResolverConfig::default(), opts),
        }
    }

    pub async fn resolve(&self, host: &str) -> DnsInfo {
        let (addrs, cname) = tokio::join!(
            self.inner.lookup_ip(host),
            self.inner.lookup(host, RecordType::CNAME)
        );
        let mut info = DnsInfo::default();
        if let Ok(addrs) = addrs {
            let mut ips: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            ips.sort();
            ips.dedup();
            info.ips = ips;
        }
        if let Ok(cname) = cname {
            if let Some(rec) = cname.iter().next() {
                info.cname = Some(rec.to_string().trim_end_matches('.').to_string());
            }
        }
        info
    }

    /// A fast path for brute-force candidates: no CNAME query, only addresses.
    pub async fn resolve_ips(&self, host: &str) -> Vec<String> {
        match self.inner.lookup_ip(host).await {
            Ok(addrs) => {
                let mut ips: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
                ips.sort();
                ips.dedup();
                ips
            }
            Err(_) => Vec::new(),
        }
    }

    /// IPs served for a randomly named subdomain, used to detect DNS wildcards
    /// so brute-force results are not flooded with false positives.
    pub async fn wildcard_ips(&self, domain: &str) -> Vec<String> {
        let probes = [
            format!("bbhunter-{:08x}.{domain}", fastrand::u32(..)),
            format!("bbhunter-{:08x}.{domain}", fastrand::u32(..)),
            format!("bbhunter-{:08x}.{domain}", fastrand::u32(..)),
        ];
        let results =
            futures::future::join_all(probes.iter().map(|probe| self.resolve_ips(probe))).await;
        let mut found: Vec<String> = results.into_iter().flatten().collect();
        found.sort();
        found.dedup();
        found
    }
}

pub fn looks_wildcard(ips: &[String], wildcard: &[String]) -> bool {
    !ips.is_empty() && !wildcard.is_empty() && ips.iter().all(|ip| wildcard.contains(ip))
}
