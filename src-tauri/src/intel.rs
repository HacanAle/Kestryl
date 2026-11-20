//! Known-bad servers from free public lists, so an alert can say "this is a known
//! AsyncRAT control server" instead of guessing from behaviour. Lists are downloaded every
//! 12 hours (plain HTTPS GETs: nothing about this PC is sent) and cached in
//! %LOCALAPPDATA%\Kestryl\intel\, so a restart works offline.
//!
//! Free without an account: abuse.ch Feodo Tracker, C2IntelFeeds, Spamhaus DROP and
//! Emerging Threats. With a free abuse.ch Auth-Key (Settings) also ThreatFox, the
//! biggest list of remote-access-trojan and stealer control servers and file hashes.

use crate::util::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

/// Set by "Update now" in Settings; the refresh loop checks it every second.
pub static REFRESH_NOW: AtomicBool = AtomicBool::new(false);
const MAX_AGE_MS: u64 = 12 * 3600 * 1000;

#[derive(Clone, Copy, PartialEq)]
enum Format {
    /// One IP per line.
    Ips,
    /// "ip-or-domain,description" per line.
    Csv,
    /// Spamhaus: "1.10.16.0/20 ; SBL256894".
    Drop,
    /// ThreatFox API JSON (needs the Auth-Key).
    ThreatFox,
}

pub struct Source {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    url: &'static str,
    fmt: Format,
    pub sev: u8,
}

pub const SOURCES: [Source; 6] = [
    Source { id: "feodo", name: "abuse.ch Feodo Tracker", desc: "botnet control servers", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", fmt: Format::Ips, sev: 3 },
    Source { id: "c2ip", name: "C2IntelFeeds", desc: "malware control servers seen in the last 30 days", url: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv", fmt: Format::Csv, sev: 3 },
    Source { id: "c2dom", name: "C2IntelFeeds", desc: "malware control domains seen in the last 30 days", url: "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/domainC2s-30day-filter-abused.csv", fmt: Format::Csv, sev: 3 },
    Source { id: "drop", name: "Spamhaus DROP", desc: "networks run by criminals (hijacked or rented for spam and malware)", url: "https://www.spamhaus.org/drop/drop.txt", fmt: Format::Drop, sev: 2 },
    Source { id: "et", name: "Emerging Threats", desc: "hacked machines seen attacking others", url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", fmt: Format::Ips, sev: 2 },
    Source { id: "threatfox", name: "abuse.ch ThreatFox", desc: "remote-access trojan, stealer and botnet control servers of the last 7 days", url: "https://threatfox-api.abuse.ch/api/v1/", fmt: Format::ThreatFox, sev: 3 },
];

#[derive(Clone, Debug)]
struct Entry {
    src: usize,
    /// Malware family or the list's own note ("AsyncRAT", "Possible Cobaltstrike C2 IP").
    what: String,
}

/// A match: which list, what it says, how bad.
#[derive(Clone, Debug, Serialize)]
pub struct Hit {
    pub list: &'static str,
    pub desc: &'static str,
    pub what: String,
    pub sev: u8,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ListInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub n: usize,
    /// When the cached copy was downloaded (ms), 0 = never.
    pub t: u64,
    pub err: String,
}

#[derive(Default)]
pub struct Intel {
    ips: HashMap<IpAddr, Entry>,
    nets: Vec<((IpAddr, u8), Entry)>,
    domains: HashMap<String, Entry>,
    hashes: HashMap<String, Entry>,
    pub lists: Vec<ListInfo>,
    pub demo: bool,
}

impl Intel {
    pub fn size(&self) -> usize {
        self.ips.len() + self.nets.len() + self.domains.len() + self.hashes.len()
    }

    fn hit(e: &Entry) -> Hit {
        let s = &SOURCES[e.src];
        Hit { list: s.name, desc: s.desc, what: e.what.clone(), sev: s.sev }
    }

    pub fn ip(&self, ip: &IpAddr) -> Option<Hit> {
        let ip = norm_ip(*ip);
        if scope(&ip) != Scope::Internet {
            return None;
        }
        if let Some(e) = self.ips.get(&ip) {
            return Some(Self::hit(e));
        }
        self.nets.iter().find(|(n, _)| net_contains(n, &ip)).map(|(_, e)| Self::hit(e))
    }

    /// The name itself or any parent domain (evil.example.net matches example.net).
    pub fn domain(&self, name: &str) -> Option<Hit> {
        let mut n = name.trim_end_matches('.').to_ascii_lowercase();
        loop {
            if let Some(e) = self.domains.get(&n) {
                return Some(Self::hit(e));
            }
            match n.split_once('.') {
                Some((_, rest)) if rest.contains('.') => n = rest.to_string(),
                _ => return None,
            }
        }
    }

    pub fn hash(&self, sha256: &str) -> Option<Hit> {
        self.hashes.get(&sha256.to_ascii_lowercase()).map(Self::hit)
    }

    fn add_ip(&mut self, src: usize, s: &str, what: &str) {
        if let Ok(ip) = s.trim().parse::<IpAddr>() {
            let ip = norm_ip(ip);
            if scope(&ip) == Scope::Internet {
                self.ips.entry(ip).or_insert(Entry { src, what: what.to_string() });
            }
        }
    }

    fn add_domain(&mut self, src: usize, s: &str, what: &str) {
        let d = s.trim().trim_end_matches('.').to_ascii_lowercase();
        if d.contains('.') && !d.contains(['/', ' ', ':']) && !big_site(&d) {
            self.domains.entry(d).or_insert(Entry { src, what: what.to_string() });
        }
    }

    /// Adds one downloaded list. Returns how many entries it had.
    fn load(&mut self, src: usize, text: &str) -> usize {
        let before = self.size();
        match SOURCES[src].fmt {
            Format::Ips => {
                for l in text.lines() {
                    let l = l.trim();
                    if !l.is_empty() && !l.starts_with('#') {
                        self.add_ip(src, l, "");
                    }
                }
            }
            Format::Csv => {
                for l in text.lines() {
                    let l = l.trim();
                    if l.is_empty() || l.starts_with('#') {
                        continue;
                    }
                    let (k, note) = l.split_once(',').unwrap_or((l, ""));
                    // Domain fronting entries name big CDNs that front the real server: not malicious themselves.
                    if note.to_ascii_lowercase().contains("front") {
                        continue;
                    }
                    if k.parse::<IpAddr>().is_ok() {
                        self.add_ip(src, k, note.trim());
                    } else {
                        self.add_domain(src, k, note.trim());
                    }
                }
            }
            Format::Drop => {
                for l in text.lines() {
                    let l = l.trim();
                    if l.is_empty() || l.starts_with(';') {
                        continue;
                    }
                    let (net, note) = l.split_once(';').unwrap_or((l, ""));
                    if let Some(n) = parse_net(net.trim()) {
                        self.nets.push((n, Entry { src, what: note.trim().to_string() }));
                    }
                }
            }
            Format::ThreatFox => {
                let v: Value = serde_json::from_str(text).unwrap_or_default();
                for x in v["data"].as_array().cloned().unwrap_or_default() {
                    let ioc = x["ioc"].as_str().unwrap_or("");
                    let what = x["malware_printable"].as_str().unwrap_or("").to_string();
                    let cc = x["threat_type"].as_str() == Some("botnet_cc");
                    match x["ioc_type"].as_str().unwrap_or("") {
                        // Payload URLs often sit on big legit hosts (GitHub, Discord CDN): only control servers count.
                        "ip:port" if cc => {
                            let ip = ioc.rsplit_once(':').map(|(a, _)| a).unwrap_or(ioc).trim_matches(['[', ']']);
                            self.add_ip(src, ip, &what);
                        }
                        "domain" if cc => self.add_domain(src, ioc, &what),
                        "sha256_hash" => {
                            self.hashes.entry(ioc.to_ascii_lowercase()).or_insert(Entry { src, what });
                        }
                        _ => {}
                    }
                }
            }
        }
        self.size() - before
    }
}

/// Sites so big that a list naming them is about one abused page, never the whole site.
fn big_site(d: &str) -> bool {
    const BIG: [&str; 24] = [
        "google.com", "googleapis.com", "gstatic.com", "microsoft.com", "windows.net", "azureedge.net", "azurewebsites.net",
        "live.com", "office.com", "amazonaws.com", "cloudfront.net", "akamaiedge.net", "akamaihd.net", "cloudflare.com",
        "github.com", "githubusercontent.com", "discord.com", "discordapp.com", "telegram.org", "dropbox.com",
        "apple.com", "facebook.com", "baidubce.com", "fastly.net",
    ];
    BIG.iter().any(|b| domain_is(d, b))
}

fn dir() -> std::path::PathBuf {
    crate::config::dir().join("intel")
}

fn cache_file(id: &str) -> std::path::PathBuf {
    dir().join(format!("{id}.txt"))
}

fn mtime_ms(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn agent() -> Result<ureq::Agent, String> {
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .tls_connector(Arc::new(tls))
        .timeout(Duration::from_secs(40))
        .user_agent("Kestryl/0.1")
        .build())
}

fn fetch(agent: &ureq::Agent, s: &Source, key: &str) -> Result<String, String> {
    let r = if s.fmt == Format::ThreatFox {
        agent
            .post(s.url)
            .set("Auth-Key", key)
            .set("Content-Type", "application/json")
            .send_string(&json!({ "query": "get_iocs", "days": 7 }).to_string())
    } else {
        agent.get(s.url).call()
    };
    let body = match r {
        Ok(r) => r.into_string().map_err(|e| e.to_string())?,
        Err(ureq::Error::Status(401 | 403, _)) => return Err("the abuse.ch Auth-Key was refused".into()),
        Err(ureq::Error::Status(code, _)) => return Err(format!("the list's server answered HTTP {code}")),
        Err(ureq::Error::Transport(t)) => return Err(format!("could not reach the list ({})", t.kind())),
    };
    if s.fmt == Format::ThreatFox {
        let v: Value = serde_json::from_str(&body).map_err(|e| format!("unexpected answer ({e})"))?;
        let st = v["query_status"].as_str().unwrap_or("");
        if st != "ok" {
            return Err(format!("ThreatFox said: {}", if st.is_empty() { "no data" } else { st }));
        }
    }
    Ok(body)
}

/// Builds the lookup tables from the cached lists (`errs` = last download errors by id).
pub fn build(key_set: bool, errs: &HashMap<&'static str, String>) -> Intel {
    let mut i = Intel::default();
    for (src, s) in SOURCES.iter().enumerate() {
        if s.fmt == Format::ThreatFox && !key_set {
            continue;
        }
        let p = cache_file(s.id);
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let n = if text.is_empty() { 0 } else { i.load(src, &text) };
        i.lists.push(ListInfo { id: s.id, name: s.name, desc: s.desc, n, t: mtime_ms(&p), err: errs.get(s.id).cloned().unwrap_or_default() });
    }
    i
}

/// Downloads every list older than 12 hours (all of them when `force`). True when it tried any.
pub fn refresh(key: &str, force: bool, errs: &mut HashMap<&'static str, String>) -> bool {
    let _ = std::fs::create_dir_all(dir());
    let agent = match agent() {
        Ok(a) => a,
        Err(e) => {
            log(&format!("threat lists: {e}"));
            return false;
        }
    };
    let now = now_ms();
    let mut tried = false;
    for s in SOURCES.iter() {
        if s.fmt == Format::ThreatFox && key.is_empty() {
            continue;
        }
        let p = cache_file(s.id);
        if !force && now.saturating_sub(mtime_ms(&p)) < MAX_AGE_MS {
            continue;
        }
        tried = true;
        match fetch(&agent, s, key) {
            Ok(body) => {
                crate::config::write_atomic_in(&dir(), &format!("{}.txt", s.id), &body);
                errs.remove(s.id);
            }
            Err(e) => {
                log(&format!("threat list {}: {e}", s.id));
                errs.insert(s.id, e);
            }
        }
    }
    tried
}

/// The --simulate demo: made-up entries matching the demo's fake malware.
pub fn demo() -> Intel {
    let mut i = Intel { demo: true, ..Default::default() };
    i.load(1, "198.51.100.7,AsyncRAT control server (demo)\n");
    i.load(5, r#"{"query_status":"ok","data":[{"ioc":"api.storage-sync.net","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"Lumma Stealer (demo)"}]}"#);
    for (k, s) in SOURCES.iter().enumerate() {
        i.lists.push(ListInfo { id: s.id, name: s.name, desc: s.desc, n: if k == 1 || k == 5 { 1 } else { 0 }, t: now_ms(), err: String::new() });
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_parse_and_match() {
        let mut i = Intel::default();
        assert_eq!(i.load(0, "# Feodo\n162.243.103.246\n10.0.0.1\nnot-an-ip\n"), 1); // private address ignored
        i.load(1, "#ip,ioc\n1.117.74.144,Possible Cobaltstrike C2 IP\n");
        i.load(2, "1.win-faw.win,Possible Cobalt Strike C2 Domain\napi.baidubce.com,Possible Cobalt Strike C2 Fronting Domain\nsub.github.com,x\n");
        i.load(3, "; Spamhaus DROP\n1.10.16.0/20 ; SBL256894\n");
        i.load(5, r#"{"query_status":"ok","data":[
            {"ioc":"203.0.113.9:4782","ioc_type":"ip:port","threat_type":"botnet_cc","malware_printable":"Quasar RAT"},
            {"ioc":"https://raw.githubusercontent.com/x/y.exe","ioc_type":"url","threat_type":"payload_delivery","malware_printable":"X"},
            {"ioc":"evil-c2.example","ioc_type":"domain","threat_type":"botnet_cc","malware_printable":"AsyncRAT"},
            {"ioc":"ABCDEF0123","ioc_type":"sha256_hash","threat_type":"payload","malware_printable":"Remcos"}]}"#);
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(i.ip(&ip("162.243.103.246")).unwrap().list, "abuse.ch Feodo Tracker");
        assert_eq!(i.ip(&ip("1.117.74.144")).unwrap().what, "Possible Cobaltstrike C2 IP");
        assert_eq!(i.ip(&ip("1.10.20.5")).unwrap().sev, 2); // inside a DROP range
        assert_eq!(i.ip(&ip("203.0.113.9")).unwrap().what, "Quasar RAT");
        assert!(i.ip(&ip("8.8.8.8")).is_none());
        assert!(i.domain("x.1.win-faw.win").is_some()); // subdomain of a listed name
        assert!(i.domain("api.baidubce.com").is_none()); // fronting entry skipped
        assert!(i.domain("sub.github.com").is_none()); // big site never listed whole
        assert!(i.domain("raw.githubusercontent.com").is_none()); // payload URLs ignored
        assert_eq!(i.domain("evil-c2.example").unwrap().what, "AsyncRAT");
        assert_eq!(i.hash("abcdef0123").unwrap().what, "Remcos");
        assert!(i.domain("win").is_none());
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// Run by hand: cargo test --lib live_ -- --ignored --nocapture (downloads the keyless lists, writes nothing).
    #[test]
    #[ignore]
    fn live_lists_download_and_parse() {
        let a = agent().unwrap();
        for (k, s) in SOURCES.iter().enumerate().filter(|(_, s)| s.fmt != Format::ThreatFox) {
            let body = fetch(&a, s, "").unwrap_or_else(|e| panic!("{}: {e}", s.id));
            let mut i = Intel::default();
            let n = i.load(k, &body);
            println!("{:8} {:6} entries ({} bytes)", s.id, n, body.len());
            assert!(n > 0, "{} parsed to nothing", s.id);
        }
    }
}
