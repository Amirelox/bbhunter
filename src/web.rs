use anyhow::{Context, Result};
use axum::{
    extract::{Path as AxPath, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, UNIX_EPOCH};

use crate::cli::{ReconArgs, ServeArgs, TargetArgs};
use crate::dnsx::Resolver;
use crate::http::Http;
use crate::log;
use crate::pipeline;
use crate::scope::Scope;
use crate::util;

const PAGE: &str = include_str!("ui/index.html");
const UI_CSS: &str = include_str!("ui/ui.css");
const UI_JS: &str = include_str!("ui/ui.js");
const FONTS_CSS: &str = include_str!("../design/fonts.css");
const TOKENS_CSS: &str = include_str!("../design/tokens.css");

#[derive(Serialize, Deserialize, Clone)]
struct Settings {
    rate: u32,
    concurrency: usize,
    timeout: u64,
    max_pages: usize,
    max_hosts: usize,
    depth: usize,
    osint: bool,
    recursion: bool,
    paths: bool,
    proxy: Option<String>,
    #[serde(default)]
    extra_paths: Vec<String>,
    #[serde(default = "default_true")]
    ports: bool,
    #[serde(default)]
    ports_list: String,
    #[serde(default = "default_true")]
    tls: bool,
    #[serde(default = "default_true")]
    vhosts: bool,
    #[serde(default = "default_true")]
    discovery: bool,
    #[serde(default)]
    discovery_paths: Vec<String>,
    #[serde(default = "default_true")]
    screenshots: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            rate: 25,
            concurrency: 20,
            timeout: 10,
            max_pages: 30,
            max_hosts: 500,
            depth: 2,
            osint: true,
            recursion: true,
            paths: true,
            proxy: None,
            extra_paths: Vec::new(),
            ports: true,
            ports_list: String::new(),
            tls: true,
            vhosts: true,
            discovery: true,
            discovery_paths: Vec::new(),
            screenshots: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct NamedScope {
    id: String,
    name: String,
    rules: String,
}

#[derive(Serialize, Deserialize, Default)]
struct ScopeStore {
    scopes: Vec<NamedScope>,
}

struct App {
    resolver: Resolver,
    out: PathBuf,
    job: Mutex<Option<Job>>,
    cancel: Arc<AtomicBool>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Running,
    Done,
    Error,
    Stopped,
}

struct Job {
    id: String,
    run_id: Option<String>,
    target: String,
    status: Status,
    started: Instant,
    finished: Option<Instant>,
    report: Option<PathBuf>,
    osint: Option<PathBuf>,
    error: Option<String>,
    counts: Option<Value>,
    logs: Vec<String>,
    stop_requested: bool,
}

#[derive(Deserialize)]
struct ScanReq {
    target: String,
    scope: String,
    #[serde(default)]
    brute: bool,
    #[serde(default)]
    wayback: bool,
    #[serde(default = "default_true")]
    osint: bool,
    max_pages: Option<usize>,
    max_hosts: Option<usize>,
    depth: Option<usize>,
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
struct StatusResp {
    id: String,
    target: String,
    status: Status,
    stage: String,
    elapsed: u64,
    logs: Vec<String>,
    counts: Option<Value>,
    report: Option<String>,
    osint: Option<String>,
    run_id: Option<String>,
    error: Option<String>,
    stop_requested: bool,
}

#[derive(Serialize)]
struct RunRow {
    id: String,
    target: String,
    generated: String,
    counts: Value,
    has_osint: bool,
    has_report: bool,
    modified: u64,
}

fn page() -> String {
    let css = format!("{FONTS_CSS}\n{TOKENS_CSS}\n{UI_CSS}");
    PAGE.replace("/*__CSS__*/", &css)
        .replace("/*__JS__*/", UI_JS)
}

async fn index() -> Response {
    ([(header::CACHE_CONTROL, "no-store")], Html(page())).into_response()
}

async fn favicon() -> StatusCode {
    StatusCode::NO_CONTENT
}

fn bad(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": message.into() })),
    )
        .into_response()
}

fn settings_path(out: &Path) -> PathBuf {
    out.join("settings.json")
}

fn load_settings(out: &Path) -> Settings {
    std::fs::read_to_string(settings_path(out))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_settings(out: &Path, settings: &Settings) -> Result<()> {
    std::fs::create_dir_all(out)?;
    std::fs::write(settings_path(out), serde_json::to_string_pretty(settings)?)?;
    Ok(())
}

fn scopes_path(out: &Path) -> PathBuf {
    out.join("scopes.json")
}

fn load_scopes(out: &Path) -> ScopeStore {
    std::fs::read_to_string(scopes_path(out))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

fn safe_id(id: &str) -> bool {
    !id.is_empty() && !id.contains('/') && !id.contains("..") && !id.contains('\\')
}

fn run_dir(out: &Path, id: &str) -> Option<PathBuf> {
    if !safe_id(id) {
        return None;
    }
    let dir = out.join(id);
    dir.is_dir().then_some(dir)
}

fn list_runs(out: &Path) -> Vec<RunRow> {
    let mut rows = Vec::new();
    let Ok(entries) = std::fs::read_dir(out) else {
        return rows;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(id) = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(path.join("manifest.json")) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let modified = std::fs::metadata(path.join("manifest.json"))
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        rows.push(RunRow {
            id,
            target: value
                .get("target")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            generated: value
                .get("generated")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            counts: value.get("counts").cloned().unwrap_or(json!({})),
            has_osint: path.join("osint/osint.json").exists(),
            has_report: path.join("report.html").exists(),
            modified,
        });
    }
    rows.sort_by(|a, b| b.modified.cmp(&a.modified));
    rows
}

async fn api_runs(State(app): State<Arc<App>>) -> Response {
    Json(list_runs(&app.out)).into_response()
}

async fn api_findings(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    match std::fs::read_to_string(dir.join("findings.json")) {
        Ok(text) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            text,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "brak findings.json").into_response(),
    }
}

async fn api_hosts(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    let Ok(text) = std::fs::read_to_string(dir.join("hosts.jsonl")) else {
        return Json(json!([])).into_response();
    };
    let hosts: Vec<Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .collect();
    Json(hosts).into_response()
}

async fn api_run_osint(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    match std::fs::read_to_string(dir.join("osint/osint.json")) {
        Ok(text) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            text,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "brak OSINT").into_response(),
    }
}

async fn run_screenshot(
    State(app): State<Arc<App>>,
    AxPath((id, name)): AxPath<(String, String)>,
) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return (StatusCode::NOT_FOUND, "brak pliku").into_response();
    }
    match std::fs::read(dir.join("screenshots").join(&name)) {
        Ok(bytes) => ([(header::CONTENT_TYPE, "image/png")], bytes).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "brak zrzutu").into_response(),
    }
}

async fn run_report(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    match std::fs::read_to_string(dir.join("report.html")) {
        Ok(html) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "brak raportu").into_response(),
    }
}

async fn run_markdown(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    match std::fs::read_to_string(dir.join("report.md")) {
        Ok(md) => ([(header::CONTENT_TYPE, "text/markdown; charset=utf-8")], md).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "brak raportu").into_response(),
    }
}

async fn api_run_log(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    match std::fs::read_to_string(dir.join("run.log")) {
        Ok(text) => ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], text).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "brak logu").into_response(),
    }
}

async fn api_triage_get(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    let text =
        std::fs::read_to_string(dir.join("triage.json")).unwrap_or_else(|_| "{}".to_string());
    let value: Value = serde_json::from_str(&text).unwrap_or(json!({}));
    Json(value).into_response()
}

async fn api_triage_put(
    State(app): State<Arc<App>>,
    AxPath(id): AxPath<String>,
    Json(body): Json<Value>,
) -> Response {
    let Some(dir) = run_dir(&app.out, &id) else {
        return (StatusCode::NOT_FOUND, "brak przebiegu").into_response();
    };
    match std::fs::write(dir.join("triage.json"), body.to_string()) {
        Ok(_) => Json(json!({"ok": true})).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn api_scopes(State(app): State<Arc<App>>) -> Response {
    Json(load_scopes(&app.out)).into_response()
}

async fn api_scopes_put(State(app): State<Arc<App>>, Json(store): Json<ScopeStore>) -> Response {
    match serde_json::to_string_pretty(&store)
        .map_err(anyhow::Error::from)
        .and_then(|text| std::fs::write(scopes_path(&app.out), text).map_err(anyhow::Error::from))
    {
        Ok(_) => Json(store).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn api_settings(State(app): State<Arc<App>>) -> Response {
    Json(load_settings(&app.out)).into_response()
}

async fn api_settings_put(State(app): State<Arc<App>>, Json(settings): Json<Settings>) -> Response {
    match save_settings(&app.out, &settings) {
        Ok(_) => Json(settings).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn api_keys() -> Response {
    Json(json!({
        "shodan": std::env::var("SHODAN_API_KEY").is_ok(),
        "securitytrails": std::env::var("SECURITYTRAILS_API_KEY").is_ok(),
        "virustotal": std::env::var("VT_API_KEY").is_ok(),
        "github": std::env::var("GITHUB_TOKEN").is_ok(),
    }))
    .into_response()
}

fn read_counts(dir: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(dir.join("manifest.json")).ok()?;
    let value: Value = serde_json::from_str(&text).ok()?;
    value.get("counts").cloned()
}

async fn start_scan(State(app): State<Arc<App>>, Json(req): Json<ScanReq>) -> Response {
    let Some(authority) = util::authority_of(&req.target) else {
        return bad("Podaj poprawną domenę, np. example.com.");
    };
    let Some(host) = util::normalize_host(&authority) else {
        return bad("Podaj poprawną domenę, np. example.com.");
    };

    let scope_text = if req.scope.trim().is_empty() {
        host.clone()
    } else {
        req.scope.clone()
    };
    let scope = match Scope::from_text(&scope_text, true) {
        Ok(s) => s,
        Err(e) => return bad(format!("{e:#}")),
    };
    if !scope.allows(&host) {
        return bad(format!(
            "Cel {host} jest poza zakresem. Dopisz go do listy zakresu."
        ));
    }

    let settings = load_settings(&app.out);

    let id = format!("{:012x}", fastrand::u64(..));
    {
        let mut guard = app.job.lock().expect("job mutex");
        if let Some(job) = guard.as_ref() {
            if job.status == Status::Running {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "error": "Skan już trwa. Poczekaj albo zatrzymaj go." })),
                )
                    .into_response();
            }
        }
        *guard = Some(Job {
            id: id.clone(),
            run_id: None,
            target: authority.clone(),
            status: Status::Running,
            started: Instant::now(),
            finished: None,
            report: None,
            osint: None,
            error: None,
            counts: None,
            logs: Vec::new(),
            stop_requested: false,
        });
    }
    app.cancel.store(false, Ordering::Relaxed);
    log::start_capture();

    let http = match Http::new(
        settings.concurrency,
        settings.rate,
        settings.timeout,
        settings.proxy.as_deref(),
        &[],
    ) {
        Ok(h) => h,
        Err(e) => {
            log::stop_capture();
            let mut guard = app.job.lock().expect("job mutex");
            if let Some(job) = guard.as_mut() {
                job.status = Status::Error;
                job.error = Some(format!("{e:#}"));
                job.finished = Some(Instant::now());
            }
            return bad(format!("Nie mogę zbudować klienta HTTP: {e:#}"));
        }
    };

    let args = ReconArgs {
        targets: TargetArgs {
            domains: vec![authority],
            list: None,
            urls: Vec::new(),
        },
        brute: req.brute,
        wordlist: None,
        max_pages: req.max_pages.unwrap_or(settings.max_pages).clamp(1, 200),
        paths_hosts: 25,
        wayback: req.wayback,
        skip_paths: !settings.paths,
        crawl_hosts: 40,
        no_recurse: !settings.recursion,
        max_hosts: req.max_hosts.unwrap_or(settings.max_hosts).clamp(1, 5000),
        depth: req.depth.unwrap_or(settings.depth).clamp(0, 5),
        no_osint: !(req.osint && settings.osint),
        skip_ports: !settings.ports,
        ports: settings.ports_list.clone(),
        skip_tls: !settings.tls,
        skip_vhosts: !settings.vhosts,
        skip_discovery: !settings.discovery,
        discovery_wordlist: None,
        skip_screenshots: !settings.screenshots,
        profile: crate::cli::Profile::Balanced,
    };
    let extra_paths = settings.extra_paths.clone();
    let discovery_paths = settings.discovery_paths.clone();

    let app2 = app.clone();
    tokio::spawn(async move {
        let result = pipeline::recon(
            &http,
            &app2.resolver,
            &scope,
            &app2.out,
            settings.concurrency,
            false,
            args,
            &app2.cancel,
            &extra_paths,
            &discovery_paths,
        )
        .await;
        let snapshot = log::snapshot();
        {
            let mut guard = app2.job.lock().expect("job mutex");
            if let Some(job) = guard.as_mut() {
                if let Some((_, lines)) = snapshot {
                    job.logs = lines;
                }
                match result {
                    Ok(dir) => {
                        job.status = if job.stop_requested {
                            Status::Stopped
                        } else {
                            Status::Done
                        };
                        job.run_id = dir.file_name().and_then(|n| n.to_str()).map(str::to_string);
                        job.counts = read_counts(&dir);
                        job.report = Some(dir.join("report.html"));
                        let osint = dir.join("osint/osint.json");
                        if osint.exists() {
                            job.osint = Some(osint);
                        }
                        let _ = std::fs::write(dir.join("run.log"), job.logs.join("\n"));
                    }
                    Err(e) => {
                        job.status = Status::Error;
                        job.error = Some(format!("{e:#}"));
                        let _ = std::fs::create_dir_all(&app2.out);
                        let _ = std::fs::write(
                            app2.out.join(format!("failed-{}.log", job.id)),
                            job.logs.join("\n"),
                        );
                    }
                }
                job.finished = Some(Instant::now());
            }
        }
        log::stop_capture();
    });

    (StatusCode::ACCEPTED, Json(json!({ "id": id }))).into_response()
}

async fn scan_status(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let guard = app.job.lock().expect("job mutex");
    let Some(job) = guard.as_ref() else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "brak skanu" })),
        )
            .into_response();
    };
    if job.id != id {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "nie ma takiego skanu" })),
        )
            .into_response();
    }

    let (stage, logs) = if job.status == Status::Running {
        log::snapshot().unwrap_or_else(|| ("".to_string(), Vec::new()))
    } else {
        (String::new(), job.logs.clone())
    };
    let end = job.finished.unwrap_or_else(Instant::now);
    let elapsed = end.duration_since(job.started).as_secs();

    Json(StatusResp {
        id: job.id.clone(),
        target: job.target.clone(),
        status: job.status,
        stage,
        elapsed,
        logs,
        counts: job.counts.clone(),
        report: job.report.as_ref().map(|_| {
            job.run_id
                .as_ref()
                .map(|rid| format!("/runs/{rid}/report"))
                .unwrap_or_else(|| format!("/report/{id}"))
        }),
        osint: job.osint.as_ref().map(|_| format!("/osint/{id}")),
        run_id: job.run_id.clone(),
        error: job.error.clone(),
        stop_requested: job.stop_requested,
    })
    .into_response()
}

async fn current_job(State(app): State<Arc<App>>) -> Response {
    let guard = app.job.lock().expect("job mutex");
    let Some(job) = guard.as_ref() else {
        return Json(Value::Null).into_response();
    };
    let (stage, logs) = if job.status == Status::Running {
        log::snapshot().unwrap_or_else(|| ("".to_string(), Vec::new()))
    } else {
        (String::new(), job.logs.clone())
    };
    let end = job.finished.unwrap_or_else(Instant::now);
    Json(json!({
        "id": job.id,
        "target": job.target,
        "status": job.status,
        "stage": stage,
        "elapsed": end.duration_since(job.started).as_secs(),
        "logs": logs,
        "counts": job.counts,
        "report": job.report.as_ref().map(|_| {
            job.run_id
                .as_ref()
                .map(|rid| format!("/runs/{rid}/report"))
                .unwrap_or_else(|| format!("/report/{}", job.id))
        }),
        "osint": job.osint.as_ref().map(|_| format!("/osint/{}", job.id)),
        "run_id": job.run_id,
        "error": job.error,
        "stop_requested": job.stop_requested,
    }))
    .into_response()
}

async fn stop_scan(State(app): State<Arc<App>>) -> Response {
    let mut guard = app.job.lock().expect("job mutex");
    match guard.as_mut() {
        Some(job) if job.status == Status::Running => {
            job.stop_requested = true;
            app.cancel.store(true, Ordering::Relaxed);
            Json(json!({"ok": true, "stopping": true})).into_response()
        }
        _ => Json(json!({"ok": false, "stopping": false})).into_response(),
    }
}

async fn osint_json(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let path = {
        let guard = app.job.lock().expect("job mutex");
        guard
            .as_ref()
            .filter(|j| j.id == id)
            .and_then(|j| j.osint.clone())
    };
    let Some(path) = path else {
        return (StatusCode::NOT_FOUND, "OSINT nie był uruchomiony.").into_response();
    };
    match std::fs::read_to_string(&path) {
        Ok(json) => (
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            json,
        )
            .into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Brak pliku OSINT.").into_response(),
    }
}

async fn report(State(app): State<Arc<App>>, AxPath(id): AxPath<String>) -> Response {
    let path = {
        let guard = app.job.lock().expect("job mutex");
        guard
            .as_ref()
            .filter(|j| j.id == id)
            .and_then(|j| j.report.clone())
    };
    let Some(path) = path else {
        return (StatusCode::NOT_FOUND, "Raport nie jest gotowy.").into_response();
    };
    match std::fs::read_to_string(&path) {
        Ok(html) => ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "Plik raportu zniknął.").into_response(),
    }
}

pub async fn serve(resolver: &Resolver, out: PathBuf, args: ServeArgs) -> Result<()> {
    std::fs::create_dir_all(&out).ok();
    if !settings_path(&out).exists() {
        save_settings(&out, &Settings::default())?;
    }

    let app = Arc::new(App {
        resolver: resolver.clone(),
        out,
        job: Mutex::new(None),
        cancel: Arc::new(AtomicBool::new(false)),
    });

    let router = Router::new()
        .route("/", get(index))
        .route("/api/scan", post(start_scan))
        .route("/api/scan/stop", post(stop_scan))
        .route("/api/scan/{id}", get(scan_status))
        .route("/api/job", get(current_job))
        .route("/api/runs", get(api_runs))
        .route("/api/runs/{id}/findings", get(api_findings))
        .route("/api/runs/{id}/hosts", get(api_hosts))
        .route("/api/runs/{id}/osint", get(api_run_osint))
        .route("/api/runs/{id}/log", get(api_run_log))
        .route(
            "/api/runs/{id}/triage",
            get(api_triage_get).put(api_triage_put),
        )
        .route("/api/scopes", get(api_scopes).put(api_scopes_put))
        .route("/api/settings", get(api_settings).put(api_settings_put))
        .route("/api/keys", get(api_keys))
        .route("/runs/{id}/report", get(run_report))
        .route("/runs/{id}/markdown", get(run_markdown))
        .route("/runs/{id}/screenshots/{name}", get(run_screenshot))
        .route("/report/{id}", get(report))
        .route("/osint/{id}", get(osint_json))
        .route("/favicon.ico", get(favicon))
        .with_state(app);

    let addr = format!("{}:{}", args.bind, args.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("nie mogę zająć {addr} — zmień --port"))?;

    println!("\n  bbhunter UI: http://{addr}");
    println!(
        "  serwer słucha tylko na {}; zakres nadal obowiązuje\n",
        args.bind
    );

    axum::serve(listener, router)
        .await
        .context("serwer HTTP zatrzymany")?;
    Ok(())
}
