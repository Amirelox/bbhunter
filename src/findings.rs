use serde::Serialize;
use std::collections::HashSet;

/// Which recon stage produced a finding. Shown in the report ledger and used
/// to attribute findings to stations in the coverage trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Stage {
    #[default]
    Probe,
    Crawl,
    Paths,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub stage: Stage,
    pub severity: Severity,
    pub category: String,
    pub host: String,
    pub url: String,
    pub title: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Default)]
pub struct Findings {
    active_stage: Option<Stage>,
    items: Vec<Finding>,
    seen: HashSet<(String, String, String)>,
}

impl Findings {
    pub fn with_stage(stage: Stage) -> Self {
        Self {
            active_stage: Some(stage),
            items: Vec::new(),
            seen: HashSet::new(),
        }
    }

    pub fn push(&mut self, mut f: Finding) {
        f.stage = self.active_stage.unwrap_or_default();
        let severity = f.severity.as_str();
        let title = f.title.clone();
        let url = f.url.clone();
        if self.insert(f) {
            crate::log::found(severity, &title, &url);
        }
    }

    /// Returns true when the finding was new.
    fn insert(&mut self, f: Finding) -> bool {
        let key = (f.url.clone(), f.category.clone(), f.title.clone());
        if self.seen.insert(key) {
            self.items.push(f);
            true
        } else {
            false
        }
    }

    pub fn add(
        &mut self,
        severity: Severity,
        category: &str,
        host: &str,
        url: &str,
        title: impl Into<String>,
        evidence: impl Into<String>,
    ) {
        self.push(Finding {
            stage: self.active_stage.unwrap_or_default(),
            severity,
            category: category.to_string(),
            host: host.to_string(),
            url: url.to_string(),
            title: title.into(),
            evidence: evidence.into(),
        });
    }

    /// Absorb findings without re-printing them. Stages of the incoming
    /// findings are preserved, so a merged set still knows who found what.
    pub fn merge(&mut self, other: Findings) {
        for f in other.items {
            self.insert(f);
        }
    }

    pub fn items(&self) -> &[Finding] {
        &self.items
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn sort(&mut self) {
        self.items.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.host.cmp(&b.host))
                .then_with(|| a.url.cmp(&b.url))
                .then_with(|| a.title.cmp(&b.title))
        });
    }
}
