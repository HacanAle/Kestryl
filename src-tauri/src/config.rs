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
    /// The user picked `theme` in Settings. Until then the app follows Windows' light/dark
    /// setting, also for configs written by older versions (which saved a theme without anyone
    /// choosing it).
    pub theme_chosen: bool,
    /// Home country picked in Settings ("JP"); empty = Windows' region setting.
    pub home_country: String,
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
    /// Pop up every time any program, browsers included, turns the camera on.
    pub cam_notify: bool,
    /// The same for the microphone (off by default: calls and voice chat turn it on all day).
    pub mic_notify: bool,
    /// Check GitHub once a day for a new Kestryl release.
    pub update_check: bool,
    /// The newest version already announced (one pop-up per version).
    pub update_seen: String,
    /// Known-safe services (Google, Microsoft 365, Windows Update, Apple) quiet "unusual
    /// destination" alerts for normal programs.
    pub safe_on: bool,
    /// Known-safe services switched off one by one (`safe::SERVICES` ids).
    pub safe_off: Vec<String>,
    /// Analytics blocking per item id ("windows", "edge", ..., "servers").
    pub analytics: HashMap<String, AnalyticsState>,
    /// HTTPS decryption: password hash, lock-out, and what to undo after a crash.
    pub decrypt: crate::decrypt::Cfg,
    /// Settings this version does not know (written by a newer or older Kestryl), kept as
    /// they are so saving here never wipes them.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
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
            home_country: String::new(),
            abuse_key: String::new(),
            trusted_dests: vec![],
            file_watch: true,
            trusted_fp: HashMap::new(),
            baseline: Baseline::default(),
            advanced: false,
            clip_guard: true,
            cam_notify: true,
            mic_notify: false,
            update_check: true,
            update_seen: String::new(),
            safe_on: true,
            safe_off: vec![],
            analytics: HashMap::new(),
            decrypt: crate::decrypt::Cfg::default(),
            extra: serde_json::Map::new(),
        }
    }
}

fn local_appdata() -> PathBuf {
    std::env::var_os("LOCALAPPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir)
}

pub fn dir() -> PathBuf {
    local_appdata().join("Kestryl")
}

/// The theme everyone starts with, until they pick one in Settings: Windows' light/dark mode.
pub const DEFAULT_THEME: &str = "system";

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
    fn follows_windows_until_the_user_picks_a_theme() {
        assert_eq!(Config::default().theme, "system");
        // Older versions saved a theme for everyone, chosen or not.
        assert_eq!(parse(r#"{"theme":"kestryl","upload_mb":30}"#).theme, "system");
        assert_eq!(parse(r#"{"theme":"dark","upload_mb":30}"#).upload_mb, 30);
        // A theme picked in Settings stays.
        assert_eq!(parse(r#"{"theme":"dark","theme_chosen":true}"#).theme, "dark");
        assert_eq!(parse(r#"{"theme":"kestryl","theme_chosen":true}"#).theme, "kestryl");
        assert_eq!(parse("not json").theme, "system");
    }

    #[test]
    fn home_country_defaults_to_windows() {
        assert_eq!(Config::default().home_country, "");
        assert_eq!(parse(r#"{"home_country":"JP"}"#).home_country, "JP");
    }

    #[test]
    fn keeps_settings_it_does_not_know() {
        let c = parse(r#"{"home_country":"GB","from_a_newer_version":{"a":1}}"#);
        let out: serde_json::Value = serde_json::from_str(&serde_json::to_string(&c).unwrap()).unwrap();
        assert_eq!(out["from_a_newer_version"]["a"], 1);
        assert_eq!(out["home_country"], "GB");
        assert!(out.get("extra").is_none());
    }
}
