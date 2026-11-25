use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Serialize, Deserialize)]
struct Entry {
    ts: u64,
    body: String,
}

fn cache_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("BBHUNTER_CACHE") {
        return PathBuf::from(dir);
    }
    match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(".cache/bbhunter"),
        Err(_) => PathBuf::from(".bbhunter-cache"),
    }
}

fn key(url: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    url.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Cached response body for idempotent sources. Missing or stale entries return None.
pub fn get(url: &str) -> Option<String> {
    let path = cache_dir().join(format!("{}.json", key(url)));
    let text = std::fs::read_to_string(path).ok()?;
    let entry: Entry = serde_json::from_str(&text).ok()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    if now.saturating_sub(entry.ts) > TTL_SECS {
        return None;
    }
    Some(entry.body)
}

pub fn put(url: &str, body: &str) {
    let dir = cache_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if let Ok(text) = serde_json::to_string(&Entry {
        ts: now,
        body: body.to_string(),
    }) {
        let _ = std::fs::write(dir.join(format!("{}.json", key(url))), text);
    }
}
