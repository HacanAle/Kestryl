//! New versions from GitHub Releases. There is no Kestryl server: once a day Kestryl asks
//! GitHub's public API for the latest release of the repository and compares its version.
//!
//! Installing goes through the Tauri updater plugin, which downloads the setup named in the
//! release's `latest.json` and installs it only when its signature matches the public key
//! built into Kestryl (`plugins.updater.pubkey` in tauri.conf.json). Releases made before the
//! signing key was set up have no `latest.json`; then, and for the portable exe, Kestryl only
//! points to the release page.

use crate::util::*;
use serde::Serialize;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const REPO: &str = "HacanAle/Kestryl";
const API: &str = "https://api.github.com/repos/HacanAle/Kestryl/releases/latest";
pub const PAGE: &str = "https://github.com/HacanAle/Kestryl/releases/latest";
/// Ko-fi page shown in Settings → Support Kestryl.
pub const SUPPORT: &str = "https://ko-fi.com/N5G22AX1Z7";

pub static STATE: Mutex<State> = Mutex::new(State::new());

#[derive(Clone, Debug, Serialize, Default, PartialEq)]
pub struct Release {
    /// "1.8.1" (without the v).
    pub version: String,
    /// The release notes (Markdown, shown as plain text).
    pub notes: String,
    /// The release page.
    pub url: String,
    pub published: String,
    /// The release carries latest.json, so the signed in-app install can work.
    pub signed: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct State {
    /// Newest release, when it is newer than this copy.
    pub available: Option<Release>,
    /// Last successful check (ms).
    pub checked: u64,
    pub checking: bool,
    pub err: String,
    /// Downloading or starting the installer.
    pub installing: bool,
}

impl State {
    const fn new() -> Self {
        State { available: None, checked: 0, checking: false, err: String::new(), installing: false }
    }
}

pub fn current() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// "v1.10.2" / "1.10.2-beta" -> [1, 10, 2]. None when it is not a version.
fn parts(v: &str) -> Option<Vec<u64>> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let core = v.split(['-', '+']).next()?;
    let p: Option<Vec<u64>> = core.split('.').map(|x| x.parse().ok()).collect();
    p.filter(|p| !p.is_empty() && p.len() <= 4)
}

/// `latest` is a newer version than `cur` (numeric, part by part: 1.10.0 > 1.9.9).
pub fn newer(latest: &str, cur: &str) -> bool {
    match (parts(latest), parts(cur)) {
        (Some(mut a), Some(mut b)) => {
            let n = a.len().max(b.len());
            a.resize(n, 0);
            b.resize(n, 0);
            a > b
        }
        _ => false,
    }
}

/// Reads GitHub's answer for the latest release.
pub fn parse_release(v: &Value) -> Option<Release> {
    if v["draft"].as_bool() == Some(true) || v["prerelease"].as_bool() == Some(true) {
        return None;
    }
    let tag = v["tag_name"].as_str()?;
    parts(tag)?;
    let signed = v["assets"].as_array().into_iter().flatten().any(|a| a["name"].as_str() == Some("latest.json"));
    // Only the part written for people: the download table and checks follow "### Downloads".
    let body = v["body"].as_str().unwrap_or("").replace("\r\n", "\n");
    let notes = body.split("\n### Downloads").next().unwrap_or("").trim().chars().take(4000).collect();
    let url = v["html_url"].as_str().unwrap_or(PAGE);
    Some(Release {
        version: tag.trim_start_matches(['v', 'V']).to_string(),
        notes,
        url: if url.starts_with("https://github.com/") { url.to_string() } else { PAGE.to_string() },
        published: v["published_at"].as_str().unwrap_or("").to_string(),
        signed,
    })
}

/// Asks GitHub for the latest release. Some(release) when it is newer than this copy.
pub fn check() -> Result<Option<Release>, String> {
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS: {e}"))?;
    let agent = ureq::AgentBuilder::new()
        .tls_connector(Arc::new(tls))
        .timeout(Duration::from_secs(30))
        .user_agent(&format!("Kestryl/{}", current()))
        .build();
    let r = agent.get(API).set("Accept", "application/vnd.github+json").call();
    let v: Value = match r {
        Ok(r) => {
            let text = r.into_string().map_err(|e| format!("could not read GitHub's answer ({e})"))?;
            serde_json::from_str(&text).map_err(|e| format!("unexpected answer from GitHub ({e})"))?
        }
        Err(ureq::Error::Status(404, _)) => return Ok(None), // no release yet
        Err(ureq::Error::Status(403 | 429, _)) => return Err("GitHub's limit for checks from this network was reached; Kestryl tries again later".into()),
        Err(ureq::Error::Status(code, _)) => return Err(format!("GitHub answered HTTP {code}")),
        Err(ureq::Error::Transport(t)) => return Err(format!("could not reach GitHub ({})", t.kind())),
    };
    Ok(parse_release(&v).filter(|r| newer(&r.version, current())))
}

/// Installed with Setup (it leaves uninstall.exe next to Kestryl.exe), not the portable exe.
pub fn installed() -> bool {
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.join("uninstall.exe").is_file())).unwrap_or(false)
}

/// Runs one check and records the result. The new release, if any.
pub fn run_check() -> Option<Release> {
    if let Ok(mut s) = STATE.lock() {
        s.checking = true;
    }
    let r = check();
    let mut s = STATE.lock().unwrap_or_else(|e| e.into_inner());
    s.checking = false;
    match r {
        Ok(rel) => {
            s.checked = now_ms();
            s.err.clear();
            s.available = rel.clone();
            rel
        }
        Err(e) => {
            log(&format!("update check: {e}"));
            s.err = e;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions() {
        assert!(newer("v1.8.1", "1.8.0"));
        assert!(newer("1.10.0", "1.9.9"));
        assert!(newer("2.0", "1.99.99"));
        assert!(!newer("v1.8.0", "1.8.0"));
        assert!(!newer("1.7.9", "1.8.0"));
        assert!(!newer("nightly", "1.8.0"));
        assert!(newer("v1.9.0-beta", "1.8.0"));
    }

    #[test]
    fn release_from_github() {
        let v = json!({
            "tag_name": "v1.9.0", "draft": false, "prerelease": false,
            "html_url": "https://github.com/HacanAle/Kestryl/releases/tag/v1.9.0",
            "published_at": "2026-12-01T10:00:00Z",
            "body": "### Fixed\r\n- Things.\r\n\r\n### Downloads\r\n\r\n| File | |",
            "assets": [{ "name": "Kestryl_1.9.0_x64-setup.exe" }, { "name": "latest.json" }]
        });
        let r = parse_release(&v).unwrap();
        assert_eq!(r.version, "1.9.0");
        assert_eq!(r.notes, "### Fixed\n- Things.");
        assert!(r.signed);
        let mut v2 = v.clone();
        v2["assets"] = json!([{ "name": "Kestryl_1.9.0_x64-setup.exe" }]);
        v2["html_url"] = json!("https://evil.example/");
        let r2 = parse_release(&v2).unwrap();
        assert!(!r2.signed);
        assert_eq!(r2.url, PAGE);
        v2["prerelease"] = json!(true);
        assert!(parse_release(&v2).is_none());
    }
}
