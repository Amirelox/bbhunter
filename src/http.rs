use anyhow::{Context, Result};
use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, Semaphore};

/// Deliberately non-resolvable origin, reflected back by broken CORS configs.
pub const CORS_ORIGIN: &str = "https://bbhunter.invalid";

/// Shared HTTP layer: one connection pool, a global concurrency cap and a
/// token-bucket-ish rate limiter so scans stay polite.
#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    sem: Arc<Semaphore>,
    limiter: Arc<RateLimiter>,
}

#[derive(Debug, Clone)]
pub struct Fetched {
    pub final_url: String,
    pub status: u16,
    pub headers: HeaderMap,
    /// Lossy UTF-8 decode of (at most) the requested amount of body.
    pub body: String,
    /// Raw bytes of the same body, needed for binary assets like favicons.
    pub bytes: Vec<u8>,
    pub body_len: usize,
    pub elapsed_ms: u128,
}

impl Fetched {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub fn content_type(&self) -> &str {
        self.header("content-type").unwrap_or("")
    }

    pub fn is_html(&self) -> bool {
        self.content_type().contains("html")
    }
}

struct RateLimiter {
    interval: Duration,
    next: Mutex<Instant>,
}

impl RateLimiter {
    fn new(rps: u32) -> Self {
        let interval = if rps == 0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(1.0 / rps as f64)
        };
        Self {
            interval,
            next: Mutex::new(Instant::now()),
        }
    }

    async fn acquire(&self) {
        if self.interval.is_zero() {
            return;
        }
        let mut next = self.next.lock().await;
        let now = Instant::now();
        if *next > now {
            tokio::time::sleep(*next - now).await;
        }
        *next = Instant::now() + self.interval;
    }
}

pub const UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 \
(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 bbhunter/0.1";

/// Parse repeated `-H "Name: Value"` CLI arguments.
pub fn parse_headers(raw: &[String]) -> Result<Vec<(HeaderName, HeaderValue)>> {
    let mut out = Vec::new();
    for item in raw {
        let (name, value) = item
            .split_once(':')
            .with_context(|| format!("header must look like \"Name: Value\", got {item:?}"))?;
        let name = HeaderName::from_bytes(name.trim().as_bytes())
            .with_context(|| format!("invalid header name: {name:?}"))?;
        let value = HeaderValue::from_str(value.trim())
            .with_context(|| format!("invalid header value for {name}"))?;
        out.push((name, value));
    }
    Ok(out)
}

impl Http {
    pub fn new(
        concurrency: usize,
        rps: u32,
        timeout_secs: u64,
        proxy: Option<&str>,
        extra_headers: &[(HeaderName, HeaderValue)],
    ) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs.max(1)))
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::limited(10))
            .pool_max_idle_per_host(2)
            .cookie_store(true)
            .danger_accept_invalid_certs(true);

        if let Some(proxy) = proxy {
            builder = builder.proxy(
                reqwest::Proxy::all(proxy).with_context(|| format!("bad proxy URL {proxy}"))?,
            );
        }

        let mut headers = HeaderMap::new();
        let has_ua = extra_headers
            .iter()
            .any(|(k, _)| k.as_str().eq_ignore_ascii_case("user-agent"));
        if !has_ua {
            headers.insert(reqwest::header::USER_AGENT, HeaderValue::from_static(UA));
        }
        for (k, v) in extra_headers {
            headers.insert(k.clone(), v.clone());
        }
        builder = builder.default_headers(headers);

        let client = builder.build().context("building http client")?;
        Ok(Self {
            client,
            sem: Arc::new(Semaphore::new(concurrency.max(1) * 2)),
            limiter: Arc::new(RateLimiter::new(rps)),
        })
    }

    pub async fn get(&self, url: &str) -> Result<Fetched> {
        self.fetch(url, &[], 1_500_000).await
    }

    /// HEAD request: existence checks without downloading a body.
    pub async fn head(&self, url: &str) -> Result<Fetched> {
        self.request(reqwest::Method::HEAD, url, &[], 0).await
    }

    pub async fn fetch(
        &self,
        url: &str,
        headers: &[(HeaderName, HeaderValue)],
        max_body: usize,
    ) -> Result<Fetched> {
        self.request(reqwest::Method::GET, url, headers, max_body)
            .await
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        headers: &[(HeaderName, HeaderValue)],
        max_body: usize,
    ) -> Result<Fetched> {
        let _permit = self.sem.acquire().await.context("semaphore closed")?;
        self.limiter.acquire().await;

        let started = Instant::now();
        let mut req = self.client.request(method, url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        let resp = req.send().await.with_context(|| format!("GET {url}"))?;

        let status = resp.status().as_u16();
        let final_url = resp.url().to_string();
        let resp_headers = resp.headers().clone();

        let mut buf: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.with_context(|| format!("reading body of {url}"))?;
            let room = max_body.saturating_sub(buf.len());
            if room == 0 {
                break;
            }
            if chunk.len() > room {
                buf.extend_from_slice(&chunk[..room]);
                break;
            }
            buf.extend_from_slice(&chunk);
        }

        let body_len = buf.len();
        Ok(Fetched {
            final_url,
            status,
            headers: resp_headers,
            body: String::from_utf8_lossy(&buf).to_string(),
            bytes: buf,
            body_len,
            elapsed_ms: started.elapsed().as_millis(),
        })
    }
}
