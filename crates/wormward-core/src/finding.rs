use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    ContentSignature,
    Artifact,
    GitignoreInjection,
    NpmPackage,
    IocDomain,
    GitReflog,
    /// A payload marker found in a past commit via `git log --all -S` — the working tree/tips are
    /// clean but the infection is still reachable via `git checkout`. Advisory, non-remediable.
    HistoryHit,
    /// A commit whose author and committer timestamps diverge far beyond a normal rebase — a tell
    /// of anti-dated / clock-manipulated commits (e.g. `temp_auto_push.bat`). Advisory.
    DateSkew,
    Analyzer,
    Capability,
    /// A GitHub account-persistence finding (over-privileged token, injected SSH key, rogue
    /// self-hosted runner, exfil webhook, …) — surfaced by the read-only account audit.
    AccountAudit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnlineVerdict {
    pub malicious: bool,
    pub severity: Option<String>,
    pub osm_url: String,
    pub threat_id: Option<String>,
    pub message: Option<String>,
}

/// A one-line source excerpt anchoring a finding to WHERE it matched: the 1-based line number
/// and a short window of that line's text around the match. Long lines are windowed, never
/// dumped — a minified line can be 100KB+ and would swamp any report or UI.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Excerpt {
    pub line: usize,
    pub text: String,
}

impl Excerpt {
    /// Context window: chars kept before / from the match. Total ≈ a small readable snippet.
    const BACK: usize = 40;
    const FWD: usize = 120;

    /// Build the excerpt for the match at byte `offset` in `content`. Out-of-range or mid-char
    /// offsets snap to the nearest valid boundary instead of panicking, so callers can pass any
    /// position a matcher reported.
    pub fn at(content: &str, offset: usize) -> Excerpt {
        let mut off = offset.min(content.len());
        while off > 0 && !content.is_char_boundary(off) {
            off -= 1;
        }
        let line = content[..off].bytes().filter(|&b| b == b'\n').count() + 1;
        let start = content[..off].rfind('\n').map(|i| i + 1).unwrap_or(0);
        let end = content[off..].find('\n').map(|i| off + i).unwrap_or(content.len());
        let line_str = content[start..end].trim_end_matches('\r');
        let trimmed = line_str.trim();
        if trimmed.chars().count() <= Self::BACK + Self::FWD {
            return Excerpt { line, text: trimmed.to_string() };
        }
        // Huge (minified) line: keep a window around the match, elided on the cut side(s).
        // `off` and `start` are both char boundaries of `content`, so `rel` is one of `line_str`.
        let rel = (off - start).min(line_str.len());
        let idxs: Vec<usize> = line_str.char_indices().map(|(i, _)| i).collect();
        let pos = idxs.partition_point(|&i| i < rel);
        let w_from = pos.saturating_sub(Self::BACK);
        let w_to = (pos + Self::FWD).min(idxs.len());
        let b_from = idxs[w_from];
        let b_to = if w_to == idxs.len() { line_str.len() } else { idxs[w_to] };
        let mut text = String::new();
        if w_from > 0 {
            text.push('…');
        }
        text.push_str(&line_str[b_from..b_to]);
        if w_to < idxs.len() {
            text.push('…');
        }
        Excerpt { line, text }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub campaign: String,
    pub severity: Severity,
    pub repo: PathBuf,
    pub file: Option<PathBuf>,
    pub signature_id: String,
    pub kind: FindingKind,
    pub evidence: String,
    pub remediable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<OnlineVerdict>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    /// Where the match sits in `file`: 1-based line + a short snippet. Populated by the
    /// content-based passes; `None` where no position exists (artifact presence, reflog, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excerpt: Option<Excerpt>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_serializes_lowercase() {
        let json = serde_json::to_string(&Severity::Critical).unwrap();
        assert_eq!(json, "\"critical\"");
    }

    #[test]
    fn finding_kind_serializes_snake_case() {
        let json = serde_json::to_string(&FindingKind::ContentSignature).unwrap();
        assert_eq!(json, "\"content_signature\"");
    }

    #[test]
    fn capability_kind_serializes() {
        let json = serde_json::to_string(&FindingKind::Capability).unwrap();
        assert_eq!(json, "\"capability\"");
    }

    #[test]
    fn account_audit_kind_serializes() {
        let json = serde_json::to_string(&FindingKind::AccountAudit).unwrap();
        assert_eq!(json, "\"account_audit\"");
    }

    #[test]
    fn history_hit_kind_serializes() {
        assert_eq!(serde_json::to_string(&FindingKind::HistoryHit).unwrap(), "\"history_hit\"");
    }

    #[test]
    fn date_skew_kind_serializes() {
        assert_eq!(serde_json::to_string(&FindingKind::DateSkew).unwrap(), "\"date_skew\"");
    }

    fn sample_finding(online: Option<OnlineVerdict>) -> Finding {
        Finding {
            campaign: "c".into(),
            severity: Severity::High,
            repo: PathBuf::from("/r"),
            file: None,
            signature_id: "s".into(),
            kind: FindingKind::NpmPackage,
            evidence: "e".into(),
            remediable: false,
            online,
            git_ref: None,
            excerpt: None,
        }
    }

    #[test]
    fn online_field_omitted_when_none() {
        let json = serde_json::to_string(&sample_finding(None)).unwrap();
        assert!(!json.contains("online"));
    }

    #[test]
    fn excerpt_at_computes_line_and_short_line_text() {
        let content = "line one\nconst x = EVIL_MARKER;\nline three\n";
        let off = content.find("EVIL_MARKER").unwrap();
        let e = Excerpt::at(content, off);
        assert_eq!(e.line, 2);
        assert_eq!(e.text, "const x = EVIL_MARKER;");
    }

    #[test]
    fn excerpt_at_windows_a_huge_line_around_the_match() {
        // A minified line can be 100KB+ — the excerpt must be a small window around the match,
        // elided on both sides, never the whole line.
        let content = format!("short();\n{}EVIL_MARKER{}", "a".repeat(5000), "b".repeat(5000));
        let off = content.find("EVIL_MARKER").unwrap();
        let e = Excerpt::at(&content, off);
        assert_eq!(e.line, 2);
        assert!(e.text.contains("EVIL_MARKER"), "window must include the match: {}", e.text);
        assert!(e.text.chars().count() <= 165, "window must stay small, got {}", e.text.len());
        assert!(e.text.starts_with('…') && e.text.ends_with('…'), "elided: {}", e.text);
    }

    #[test]
    fn excerpt_at_is_utf8_boundary_safe() {
        // Multi-byte chars around the window edges must not panic on slicing.
        let content = format!("{}EVIL{}", "é".repeat(300), "漢".repeat(300));
        let off = content.find("EVIL").unwrap();
        let e = Excerpt::at(&content, off);
        assert!(e.text.contains("EVIL"));
        // Offsets past the end or mid-char snap instead of panicking.
        let _ = Excerpt::at(&content, content.len() + 10);
        let _ = Excerpt::at(&content, 1); // inside 'é'
    }

    #[test]
    fn excerpt_field_omitted_when_none_and_serialized_when_set() {
        let json = serde_json::to_string(&sample_finding(None)).unwrap();
        assert!(!json.contains("excerpt"));
        let mut f = sample_finding(None);
        f.excerpt = Some(Excerpt { line: 3, text: "evil()".into() });
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(v["excerpt"]["line"], 3);
        assert_eq!(v["excerpt"]["text"], "evil()");
    }

    #[test]
    fn online_field_present_when_set() {
        let f = sample_finding(Some(OnlineVerdict {
            malicious: true,
            severity: Some("high".into()),
            osm_url: "https://osm/x".into(),
            threat_id: Some("t".into()),
            message: None,
        }));
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(v["online"]["malicious"], true);
    }

    #[test]
    fn git_ref_omitted_when_none() {
        let json = serde_json::to_string(&sample_finding(None)).unwrap();
        assert!(!json.contains("git_ref"));
    }

    #[test]
    fn git_ref_present_when_set() {
        let mut f = sample_finding(None);
        f.git_ref = Some("origin/evil".into());
        let v: serde_json::Value = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(v["git_ref"], "origin/evil");
    }
}
