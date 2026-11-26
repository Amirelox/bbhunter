use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use futures::stream::{self, StreamExt};
use image::codecs::jpeg::JpegEncoder;
use serde::Serialize;

use crate::log;
use crate::probe::HostResult;
use crate::scope::Scope;
use crate::util;

#[derive(Debug, Clone, Serialize)]
pub struct Screenshot {
    pub host: String,
    pub url: String,
    pub file: String,
    #[serde(skip)]
    pub thumb: String,
}

#[derive(Default)]
pub struct ShotScan {
    pub shots: Vec<Screenshot>,
    pub notes: Vec<String>,
}

fn browser() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("BBHUNTER_CHROME") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    for candidate in [
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "chrome",
        "msedge",
    ] {
        if let Ok(out) = std::process::Command::new(candidate)
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
        {
            if out.success() {
                return Some(PathBuf::from(candidate));
            }
        }
    }
    None
}

fn thumbnail(png: &[u8]) -> Option<(String, usize, usize)> {
    let img = image::load_from_memory(png).ok()?;
    let thumb = img.thumbnail(720, 450);
    let mut jpeg = Vec::new();
    JpegEncoder::new_with_quality(&mut jpeg, 68)
        .encode_image(&thumb.to_rgb8())
        .ok()?;
    Some((
        base64::engine::general_purpose::STANDARD.encode(jpeg),
        thumb.width() as usize,
        thumb.height() as usize,
    ))
}

async fn capture(chrome: &Path, host: String, url: String, outdir: PathBuf) -> Option<Screenshot> {
    std::fs::create_dir_all(&outdir).ok()?;
    let name = format!(
        "{}-{:06x}.png",
        util::slug(&host),
        fastrand::u32(..) & 0xffffff
    );
    let path = outdir.join(&name);
    let profile = std::env::temp_dir().join(format!("bbhunter-shot-{:06x}", fastrand::u32(..)));
    let mut cmd = tokio::process::Command::new(chrome);
    cmd.args([
        "--headless=new",
        "--no-sandbox",
        "--ignore-certificate-errors",
        "--allow-insecure-localhost",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--hide-scrollbars",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        "--disable-sync",
        "--metrics-recording-only",
        "--safebrowsing-disable-auto-update",
        "--run-all-compositor-stages-before-draw",
        "--virtual-time-budget=3500",
        "--window-size=1440,900",
    ])
    .arg(format!("--user-data-dir={}", profile.display()))
    .arg(format!("--screenshot={}", path.display()))
    .arg(&url)
    .stdin(Stdio::null())
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .kill_on_drop(true);
    let status = tokio::time::timeout(Duration::from_secs(22), cmd.status()).await;
    let _ = std::fs::remove_dir_all(&profile);
    let ok = matches!(status, Ok(Ok(s)) if s.success());
    if !ok || !path.is_file() {
        return None;
    }
    let png = std::fs::read(&path).ok()?;
    let (thumb, _, _) = thumbnail(&png)?;
    Some(Screenshot {
        host,
        url,
        file: format!("screenshots/{name}"),
        thumb,
    })
}

pub async fn scan(
    hosts: &[HostResult],
    outdir: &Path,
    limit: usize,
    scope: &Scope,
    cancel: &AtomicBool,
) -> ShotScan {
    let mut out = ShotScan::default();
    let Some(chrome) = browser() else {
        out.notes.push(
            "Pominięto zrzuty ekranu: brak Chromium (ustaw BBHUNTER_CHROME albo zainstaluj chromium)."
                .to_string(),
        );
        return out;
    };
    let mut targets: Vec<(String, String)> = Vec::new();
    for h in hosts
        .iter()
        .filter(|h| h.alias_of.is_none() && h.status > 0)
    {
        let hostname = util::host_of(&h.host).unwrap_or_else(|| h.host.clone());
        if !scope.allows(&hostname) || h.final_url.is_empty() {
            continue;
        }
        targets.push((h.host.clone(), h.final_url.clone()));
        if targets.len() >= limit.max(1) {
            break;
        }
    }
    if targets.is_empty() {
        out.notes
            .push("Brak hostów HTTP do sfotografowania.".to_string());
        return out;
    }
    let shots = stream::iter(targets.into_iter().map(|(host, url)| {
        let chrome = chrome.clone();
        let outdir = outdir.to_path_buf();
        async move {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            let shot = capture(&chrome, host, url, outdir).await;
            if shot.is_none() {
                log::warn("zrzut ekranu nie powstał");
            }
            shot
        }
    }))
    .buffer_unordered(2)
    .filter_map(|x| async move { x })
    .collect::<Vec<_>>()
    .await;
    out.shots = shots;
    out.shots.sort_by(|a, b| a.host.cmp(&b.host));
    if out.shots.is_empty() {
        out.notes
            .push("Nie udało się wykonać żadnego zrzutu ekranu.".to_string());
    }
    out
}
