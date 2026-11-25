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
        opts.num_concurrent_reqs = 48;
        Self {
            inner: TokioAsyncResolver::tokio(ResolverConfig::default(), opts),
        }
    }

    pub async fn resolve(&self, host: &str) -> DnsInfo {
        let mut info = DnsInfo::default();
        if let Ok(addrs) = self.inner.lookup_ip(host).await {
            let mut ips: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
            ips.sort();
            ips.dedup();
            info.ips = ips;
        }
        if let Ok(cname) = self.inner.lookup(host, RecordType::CNAME).await {
            if let Some(rec) = cname.iter().next() {
                info.cname = Some(rec.to_string().trim_end_matches('.').to_string());
            }
        }
        info
    }

    /// IPs served for a randomly named subdomain, used to detect DNS wildcards
    /// so brute-force results are not flooded with false positives.
    pub async fn wildcard_ips(&self, domain: &str) -> Vec<String> {
        let mut found: Vec<String> = Vec::new();
        for _ in 0..3 {
            let probe = format!("bbhunter-{:08x}.{domain}", fastrand::u32(..));
            let info = self.resolve(&probe).await;
            found.extend(info.ips);
        }
        found.sort();
        found.dedup();
        found
    }
}

pub fn looks_wildcard(ips: &[String], wildcard: &[String]) -> bool {
    !ips.is_empty() && !wildcard.is_empty() && ips.iter().all(|ip| wildcard.contains(ip))
}
