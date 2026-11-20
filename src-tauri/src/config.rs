use crate::engine::Alert;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Config {
    /// Per-program upload (internet, last 60 s) that raises an alert.
    pub upload_mb: u64,
    pub popups: bool,
    /// Lowest severity that gets a pop-up (1 low, 2 medium, 3 high).
    pub popup_min: u8,
    /// Lower-case exe paths whose traffic never raises alerts.
    pub trusted: Vec<String>,
    pub muted: Vec<String>,
    pub domain_blocks: Vec<DomainBlock>,
    /// Programs already seen online (for "first time online").
    pub known: Vec<String>,
    /// First run: learn what is normal silently until this time.
    pub learning_until: u64,
    /// UI colours: kestryl | dark | light | system (older palettes mist/slate/sky/sage read as dark).
    pub theme: String,
    /// The user picked `theme` in Settings. Until then Kestryl's own theme is used, also for
    /// configs written by older versions (which saved "dark" without anyone choosing it).
    pub theme_chosen: bool,
    /// Free abuse.ch Auth-Key: adds the ThreatFox list of control servers and malware hashes.
    pub abuse_key: String,
    /// Trusted IPs, ranges and domains: never alerted, hidden unless `show`.
    pub trusted_dests: Vec<TrustedDest>,
    /// Watch which programs open password, cookie, wallet and document files.
    pub file_watch: bool,
    /// What each trusted program was when it was trusted ("signed:Publisher" or
    /// "unsigned:<size>:<mtime>"); a change suspends the trust.
    pub trusted_fp: HashMap<String, String>,
    /// What the security checks found the first time, so changes can be reported.
    pub baseline: Baseline,
    /// UI: the full technical view (ports, PIDs, DNS, raw connections) instead of the simple one.
    pub advanced: bool,
    /// Watch the clipboard for swapped wallet addresses and bank account numbers.
    pub clip_guard: bool,
    /// Analytics blocking per item id ("windows", "edge", ..., "servers").
    pub analytics: HashMap<String, AnalyticsState>,
    /// HTTPS decryption: password hash, lock-out, and what to undo after a crash.
    pub decrypt: crate::decrypt::Cfg,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct AnalyticsState {
    pub on: bool,
    pub t: u64,
    /// What was there before (registry values, service start types, rules), for undo.
    pub backup: serde_json::Value,
    pub errors: Vec<String>,
}

/// Snapshot of security settings. Maps hold "first seen" times (0 = there from the start).
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Baseline {
    pub set: bool,
    pub roots: HashMap<String, u64>,
    pub hosts: HashMap<String, u64>,
    pub startup: HashMap<String, u64>,
    pub exclusions: HashMap<String, u64>,
    /// Exclusions can only be read as administrator; false until they were.
    pub excl_known: bool,
    pub proxy: String,
    pub dns: Vec<String>,
    pub rtp: Option<bool>,
    pub fw_on: Vec<String>,
    pub rdp: Option<bool>,
    /// Startup entries the user marked as their own ("Mark as mine").
    pub ack: Vec<String>,
    /// 2 = services, drivers, WMI, Winlogon, IFEO and AppInit are in the baseline too.
    pub startup_v: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct TrustedDest {
    pub target: String,
    #[serde(default)]
    pub show: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DomainBlock {
    pub domain: String,
    pub id: String,
    pub ips: Vec<String>,
    /// Part of "Block analytics" (known analytics servers), not a block the user made.
    #[serde(default)]
    pub tracker: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            upload_mb: 20,
            popups: true,
            popup_min: 2,
            trusted: vec![],
            muted: vec![],
            domain_blocks: vec![],
            known: vec![],
            learning_until: 0,
            theme: DEFAULT_THEME.into(),
            theme_chosen: false,
            abuse_key: String::new(),
            trusted_dests: vec![],
            file_watch: true,
            trusted_fp: HashMap::new(),
            baseline: Baseline::default(),
            advanced: false,
            clip_guard: true,
            analytics: HashMap::new(),
            decrypt: crate::decrypt::Cfg::default(),
        }
    }
}

fn local_appdata() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

pub fn dir() -> PathBuf {
    local_appdata().join("Kestryl")
}

/// The theme everyone starts with, until they pick one in Settings.
pub const DEFAULT_THEME: &str = "kestryl";

/// Returns the config and whether this is the first run.
pub fn load() -> (Config, bool) {
    match std::fs::read_to_string(dir().join("config.json")) {
        Ok(s) => (parse(&s), false),
        Err(_) => (Config::default(), true),
    }
}

fn parse(s: &str) -> Config {
    let mut c: Config = serde_json::from_str(s).unwrap_or_default();
    if !c.theme_chosen {
        c.theme = DEFAULT_THEME.into();
    }
    c
}

fn write_atomic(name: &str, data: &str) {
    write_atomic_in(&dir(), name, data);
}

pub fn write_atomic_in(d: &std::path::Path, name: &str, data: &str) {
    let _ = std::fs::create_dir_all(d);
    let tmp = d.join(format!("{name}.tmp"));
    if std::fs::write(&tmp, data).is_ok() {
        let _ = std::fs::rename(&tmp, d.join(name));
    }
}

pub fn save(cfg: &Config) {
    if let Ok(s) = serde_json::to_string_pretty(cfg) {
        write_atomic("config.json", &s);
    }
}

pub fn load_alerts() -> Vec<Alert> {
    std::fs::read_to_string(dir().join("alerts.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_alerts(a: &[Alert]) {
    if let Ok(s) = serde_json::to_string(a) {
        write_atomic("alerts.json", &s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kestryl_theme_until_the_user_picks_one() {
        assert_eq!(Config::default().theme, "kestryl");
        // Older versions saved "dark" for everyone, chosen or not.
        assert_eq!(parse(r#"{"theme":"dark","upload_mb":30}"#).theme, "kestryl");
        assert_eq!(parse(r#"{"theme":"dark","upload_mb":30}"#).upload_mb, 30);
        // A theme picked in Settings stays.
        assert_eq!(parse(r#"{"theme":"dark","theme_chosen":true}"#).theme, "dark");
        assert_eq!(parse(r#"{"theme":"system","theme_chosen":true}"#).theme, "system");
        assert_eq!(parse("not json").theme, "kestryl");
    }
}
