use anyhow::{bail, Context, Result};
use globset::{GlobBuilder, GlobMatcher};
use std::path::Path;

/// Hard allowlist gate. Every outbound request resolves a host and asks this
/// type first, so a typo in a wordlist cannot turn into traffic against a
/// third party.
pub struct Scope {
    matchers: Vec<GlobMatcher>,
    excludes: Vec<GlobMatcher>,
    enforced: bool,
}

impl Scope {
    pub fn open(path: Option<&Path>, enforced: bool) -> Result<Self> {
        if !enforced {
            return Ok(Self {
                matchers: Vec::new(),
                excludes: Vec::new(),
                enforced: false,
            });
        }
        let Some(path) = path else {
            bail!(
                "no scope file given.\n\
                 Refusing to scan without an allowlist. Create one (see scope.example.txt) and pass --scope <file>,\n\
                 or pass --no-scope-check if the target is your own lab."
            );
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read scope file {}", path.display()))?;
        Self::from_text(&text, true)
    }

    /// Build a scope from rules supplied at runtime (web form, tests).
    pub fn from_text(text: &str, enforced: bool) -> Result<Self> {
        if !enforced {
            return Ok(Self {
                matchers: Vec::new(),
                excludes: Vec::new(),
                enforced: false,
            });
        }
        let mut matchers = Vec::new();
        let mut excludes = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (target, exclude) = match line.strip_prefix('!').or_else(|| line.strip_prefix('-'))
            {
                Some(rest) => (rest.trim(), true),
                None => (line, false),
            };
            if target.is_empty() {
                continue;
            }
            let rule = target.to_ascii_lowercase();
            let patterns: Vec<String> = if rule.contains('*') {
                vec![rule]
            } else {
                vec![rule.clone(), format!("*.{rule}")]
            };
            for p in patterns {
                let matcher = GlobBuilder::new(&p)
                    .literal_separator(false)
                    .backslash_escape(false)
                    .build()
                    .with_context(|| format!("bad scope rule: {p}"))?
                    .compile_matcher();
                if exclude {
                    excludes.push(matcher);
                } else {
                    matchers.push(matcher);
                }
            }
        }
        if matchers.is_empty() {
            bail!("lista zakresu jest pusta — dodaj co najmniej jedną domenę");
        }
        Ok(Self {
            matchers,
            excludes,
            enforced: true,
        })
    }

    pub fn is_enforced(&self) -> bool {
        self.enforced
    }

    pub fn allows(&self, host: &str) -> bool {
        if !self.enforced {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if self.excludes.iter().any(|m| m.is_match(&host)) {
            return false;
        }
        self.matchers.iter().any(|m| m.is_match(&host))
    }

    /// Filter a list, reporting what was dropped.
    pub fn filter(&self, hosts: impl IntoIterator<Item = String>) -> (Vec<String>, usize) {
        let mut kept = Vec::new();
        let mut dropped = 0usize;
        for h in hosts {
            if self.allows(&h) {
                kept.push(h);
            } else {
                dropped += 1;
            }
        }
        (kept, dropped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn scope_with(rules: &str) -> Scope {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "bbhunter-scope-{}-{}.txt",
            std::process::id(),
            fastrand::u64(..)
        ));
        std::fs::File::create(&p)
            .unwrap()
            .write_all(rules.as_bytes())
            .unwrap();
        let s = Scope::open(Some(&p), true).unwrap();
        let _ = std::fs::remove_file(&p);
        s
    }

    #[test]
    fn allows_apex_and_children() {
        let s = scope_with("example.com\n");
        assert!(s.allows("example.com"));
        assert!(s.allows("api.example.com"));
        assert!(s.allows("a.b.example.com"));
        assert!(!s.allows("example.com.evil.net"));
        assert!(!s.allows("notexample.com"));
    }

    #[test]
    fn exclusions_win() {
        let s = scope_with("example.com\n!dev.example.com\n");
        assert!(s.allows("api.example.com"));
        assert!(!s.allows("dev.example.com"));
        assert!(!s.allows("dev.example.com.evil.net"));
    }

    #[test]
    fn glob_rules() {
        let s = scope_with("*.example.org\napi-*.lab.net\n");
        assert!(s.allows("x.example.org"));
        assert!(!s.allows("example.org"));
        assert!(s.allows("api-3.lab.net"));
    }
}
