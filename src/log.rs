use colored::Colorize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

static QUIET: AtomicBool = AtomicBool::new(false);

/// In-memory mirror of the log, used by the local web UI.
#[derive(Default)]
struct Capture {
    stage: String,
    lines: Vec<String>,
}

static CAPTURE: OnceLock<Mutex<Option<Capture>>> = OnceLock::new();

fn capture() -> &'static Mutex<Option<Capture>> {
    CAPTURE.get_or_init(|| Mutex::new(None))
}

pub fn start_capture() {
    if let Ok(mut guard) = capture().lock() {
        *guard = Some(Capture::default());
    }
}

pub fn stop_capture() {
    if let Ok(mut guard) = capture().lock() {
        *guard = None;
    }
}

/// Last stage key plus every line recorded since `start_capture`.
pub fn snapshot() -> Option<(String, Vec<String>)> {
    capture()
        .lock()
        .ok()
        .and_then(|guard| guard.as_ref().map(|c| (c.stage.clone(), c.lines.clone())))
}

fn record(line: String) {
    if let Ok(mut guard) = capture().lock() {
        if let Some(c) = guard.as_mut() {
            c.lines.push(line);
        }
    }
}

fn stage_key(title: &str) -> &'static str {
    let t = title.to_ascii_lowercase();
    if t.contains("osint") {
        "osint"
    } else if t.contains("subdomain") {
        "subs"
    } else if t.contains("probing") {
        "probe"
    } else if t.contains("crawling") {
        "crawl"
    } else if t.contains("low-hanging") {
        "paths"
    } else if t.contains("port scan")
        || t.contains("tls")
        || t.contains("virtual host")
        || t.contains("content discovery")
        || t.contains("zrzuty")
    {
        "modules"
    } else {
        "other"
    }
}

pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::Relaxed);
}

pub fn quiet() -> bool {
    QUIET.load(Ordering::Relaxed)
}

/// A pipeline stage header.
pub fn stage(title: &str) {
    if let Ok(mut guard) = capture().lock() {
        if let Some(c) = guard.as_mut() {
            c.stage = stage_key(title).to_string();
            c.lines.push(format!("==> {title}"));
        }
    }
    if !quiet() {
        eprintln!("\n{} {}", "==>".bright_cyan().bold(), title.bold());
    }
}

pub fn info(msg: &str) {
    record(format!("[*] {msg}"));
    if !quiet() {
        eprintln!("{} {}", "[*]".bright_black(), msg);
    }
}

pub fn ok(msg: &str) {
    record(format!("[+] {msg}"));
    if !quiet() {
        eprintln!("{} {}", "[+]".green().bold(), msg);
    }
}

pub fn plus(msg: &str) {
    record(format!("[>] {msg}"));
    if !quiet() {
        eprintln!("{} {}", "[>]".bright_blue(), msg);
    }
}

pub fn warn(msg: &str) {
    record(format!("[!] {msg}"));
    if !quiet() {
        eprintln!("{} {}", "[!]".yellow().bold(), msg);
    }
}

pub fn err(msg: &str) {
    record(format!("[-] {msg}"));
    eprintln!("{} {}", "[-]".red().bold(), msg);
}

pub fn found(severity: &str, title: &str, where_: &str) {
    record(format!("[!] {severity:>6}  {title}  {where_}"));
    if quiet() {
        return;
    }
    let tag = match severity {
        "high" => "HIGH".red().bold(),
        "medium" => "MED".yellow().bold(),
        "low" => "LOW".bright_blue().bold(),
        _ => "INFO".bright_black(),
    };
    eprintln!(
        "{} {:>4}  {}  {}",
        "[!]".magenta(),
        tag,
        title,
        where_.bright_black()
    );
}
