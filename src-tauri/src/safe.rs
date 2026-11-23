//! Known-safe services: addresses that belong to the big companies' OWN services, from the lists
//! they publish themselves. Connections to them are tagged, and the alerts that only say "this
//! destination looks unusual" (timer check-ins, bare IPs, odd ports) stay quiet for normal
//! programs. Nothing is ever "100 % safe", so:
//!
//! - cloud customer ranges are left out: anyone can rent a server at Google Cloud, Azure or AWS,
//!   and malware control servers often sit there. Google publishes all its addresses (goog.json)
//!   and its Cloud customer ranges (cloud.json); its own services are the first minus the second.
//! - CDNs that carry everyone's content (Cloudflare, Akamai, CloudFront) are not listed at all.
//! - Uploads, password-file theft, email/FTP from odd programs, file-sharing sites and known
//!   malware servers still alert: stealers upload to Google Drive and OneDrive too.
//! - Unsigned programs, programs in Temp or Downloads, scripts and Windows tools get no quiet.

use crate::util::*;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;

pub static REFRESH_NOW: AtomicBool = AtomicBool::new(false);
const MAX_AGE_MS: u64 = 24 * 3600 * 1000;

/// Alert types a known-safe destination keeps quiet (for normal, signed programs).
pub const QUIET: [&str; 3] = ["beacon", "bare_ip", "odd_port"];

pub struct Service {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub source: &'static str,
}

pub const SERVICES: [Service; 4] = [
    Service {
        id: "google",
        name: "Google",
        desc: "Search, Gmail, YouTube, Maps, Play, Chrome and Android updates, Google APIs. Google Cloud customer servers are left out.",
        source: "https://www.gstatic.com/ipranges/goog.json minus https://www.gstatic.com/ipranges/cloud.json",
    },
    Service {
        id: "microsoft",
        name: "Microsoft 365",
        desc: "Outlook and Exchange Online, Teams, SharePoint, OneDrive and Office sign-in, from Microsoft's official list. Azure customer servers are not in it.",
        source: "https://endpoints.office.com/endpoints/worldwide",
    },
    Service {
        id: "windows",
        name: "Windows Update and Defender",
        desc: "Windows Update, Delivery Optimization, Defender updates and SmartScreen, matched by their Microsoft names (they are served from shared networks, so not by address).",
        source: "Microsoft's documented Windows Update and Defender endpoints (built in)",
    },
    Service {
        id: "apple",
        name: "Apple",
        desc: "Apple's own 17.0.0.0/8 network: iCloud, App Store, Apple Music, software updates.",
        source: "Apple's registered address block (built in)",
    },
];

/// Windows Update / Defender names (a name matches itself and its subdomains).
const WINDOWS_DOMAINS: [&str; 13] = [
    "windowsupdate.com",
    "update.microsoft.com",
    "delivery.mp.microsoft.com",
    "do.dsp.mp.microsoft.com",
    "tsfe.trafficshaping.dsp.mp.microsoft.com",
    "emdl.ws.microsoft.com",
    "wdcp.microsoft.com",
    "wdcpalt.microsoft.com",
    "wd.microsoft.com",
    "definitionupdates.microsoft.com",
    "smartscreen.microsoft.com",
    "smartscreen-prod.microsoft.com",
    "checkappexec.microsoft.com",
];

const APPLE: [&str; 1] = ["17.0.0.0/8"];

const GOOG_URL: &str = "https://www.gstatic.com/ipranges/goog.json";
const CLOUD_URL: &str = "https://www.gstatic.com/ipranges/cloud.json";
/// The client request id is a fixed GUID, the same for every copy: nothing about this PC.
const M365_URL: &str = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7";

#[derive(Clone, Debug, Serialize)]
pub struct ListInfo {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    pub source: &'static str,
    /// Address ranges (or names, for Windows).
    pub n: usize,
    /// Google Cloud customer ranges left out.
    pub excluded: usize,
    /// When the list was downloaded (ms); 0 = built in / never.
    pub t: u64,
    pub err: String,
}

#[derive(Default)]
pub struct Safe {
    /// (range, index into SERVICES)
    nets: Vec<((IpAddr, u8), u8)>,
    /// Google Cloud customer ranges: inside Google's space, but not Google's own services.
    cloud: Vec<(IpAddr, u8)>,
    pub lists: Vec<ListInfo>,
}

/// What the list says about one address (Settings → Test an address).
#[derive(Debug, PartialEq)]
pub enum Verdict {
    Safe(u8, String),
    /// In Google's space, but a Google Cloud customer range.
    Cloud(String),
    /// Matched by its DNS name.
    Name(u8, String),
    Unknown,
}

pub fn svc_index(id: &str) -> Option<u8> {
    SERVICES.iter().position(|s| s.id == id).map(|i| i as u8)
}

fn fmt_net(n: &(IpAddr, u8)) -> String {
    format!("{}/{}", n.0, n.1)
}

impl Safe {
    /// The service an address belongs to (by address, or by the DNS name it was looked up as).
    pub fn lookup(&self, ip: &IpAddr, name: Option<&str>) -> Option<u8> {
        match self.verdict(ip, name) {
            Verdict::Safe(i, _) | Verdict::Name(i, _) => Some(i),
            _ => None,
        }
    }

    pub fn verdict(&self, ip: &IpAddr, name: Option<&str>) -> Verdict {
        let ip = norm_ip(*ip);
        if let Some(n) = name {
            if let Some(d) = WINDOWS_DOMAINS.iter().find(|d| domain_is(n, d)) {
                return Verdict::Name(svc_index("windows").unwrap_or(0), (*d).to_string());
            }
        }
        // The most specific range wins.
        let Some((net, svc)) = self.nets.iter().filter(|(n, _)| net_contains(n, &ip)).max_by_key(|(n, _)| n.1) else {
            return Verdict::Unknown;
        };
        if SERVICES[*svc as usize].id == "google" {
            if let Some(c) = self.cloud.iter().find(|c| net_contains(c, &ip)) {
                return Verdict::Cloud(fmt_net(c));
            }
        }
        Verdict::Safe(*svc, fmt_net(net))
    }

    /// Every range (or name) of one service, for the viewer.
    pub fn entries(&self, svc: u8) -> Vec<String> {
        if SERVICES.get(svc as usize).is_some_and(|s| s.id == "windows") {
            return WINDOWS_DOMAINS.iter().map(|d| format!("{d} (and its subdomains)")).collect();
        }
        self.nets.iter().filter(|(_, s)| *s == svc).map(|(n, _)| fmt_net(n)).collect()
    }

    pub fn excluded(&self) -> Vec<String> {
        self.cloud.iter().map(fmt_net).collect()
    }
}

/// "ipv4Prefix"/"ipv6Prefix" entries of Google's lists.
fn google_prefixes(text: &str) -> Vec<(IpAddr, u8)> {
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    v["prefixes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p["ipv4Prefix"].as_str().or_else(|| p["ipv6Prefix"].as_str()))
        .filter_map(parse_net)
        .collect()
}

/// Every "ips" entry of Microsoft's 365 endpoint list.
fn m365_prefixes(text: &str) -> Vec<(IpAddr, u8)> {
    let v: Value = serde_json::from_str(text).unwrap_or(Value::Null);
    let mut out: Vec<(IpAddr, u8)> = v
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|e| e["ips"].as_array().cloned().unwrap_or_default())
        .filter_map(|s| s.as_str().and_then(parse_net))
        .collect();
    out.sort();
    out.dedup();
    out
}

fn dir() -> std::path::PathBuf {
    crate::config::dir().join("safe")
}

fn cache(name: &str) -> std::path::PathBuf {
    dir().join(format!("{name}.json"))
}

fn mtime_ms(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Builds the list from texts (Google all, Google Cloud, Microsoft 365) and their times.
pub fn from_texts(goog: &str, cloud: &str, m365: &str, times: [u64; 2], errs: &HashMap<&'static str, String>) -> Safe {
    let mut s = Safe::default();
    let gi = svc_index("google").unwrap_or(0);
    let mi = svc_index("microsoft").unwrap_or(1);
    let ai = svc_index("apple").unwrap_or(3);
    let g = google_prefixes(goog);
    s.cloud = google_prefixes(cloud);
    let m = m365_prefixes(m365);
    let counts = [g.len(), m.len(), WINDOWS_DOMAINS.len(), APPLE.len()];
    s.nets.extend(g.into_iter().map(|n| (n, gi)));
    s.nets.extend(m.into_iter().map(|n| (n, mi)));
    s.nets.extend(APPLE.iter().filter_map(|a| parse_net(a)).map(|n| (n, ai)));
    for (i, svc) in SERVICES.iter().enumerate() {
        s.lists.push(ListInfo {
            id: svc.id,
            name: svc.name,
            desc: svc.desc,
            source: svc.source,
            n: counts[i],
            excluded: if svc.id == "google" { s.cloud.len() } else { 0 },
            t: match svc.id {
                "google" => times[0],
                "microsoft" => times[1],
                _ => 0,
            },
            err: errs.get(svc.id).cloned().unwrap_or_default(),
        });
    }
    s
}

/// The saved copies (and the built-in parts).
pub fn build(errs: &HashMap<&'static str, String>) -> Safe {
    let read = |n: &str| std::fs::read_to_string(cache(n)).unwrap_or_default();
    from_texts(&read("google"), &read("google-cloud"), &read("microsoft"), [mtime_ms(&cache("google")), mtime_ms(&cache("microsoft"))], errs)
}

fn get(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    match agent.get(url).call() {
        Ok(r) => crate::intel::read_body(r),
        Err(ureq::Error::Status(code, _)) => Err(format!("the server answered HTTP {code}")),
        Err(ureq::Error::Transport(t)) => Err(format!("could not reach it ({})", t.kind())),
    }
}

/// Downloads lists older than a day (all when `force`). True when it tried any.
pub fn refresh(force: bool, errs: &mut HashMap<&'static str, String>) -> bool {
    let _ = std::fs::create_dir_all(dir());
    let agent = match crate::intel::agent() {
        Ok(a) => a,
        Err(e) => {
            log(&format!("safe lists: {e}"));
            return false;
        }
    };
    let now = now_ms();
    let stale = |n: &str| force || now.saturating_sub(mtime_ms(&cache(n))) >= MAX_AGE_MS;
    let mut tried = false;
    if stale("google") {
        tried = true;
        // Both Google lists or neither: all of Google without the Cloud list would count
        // customer servers as Google's own.
        let both = get(&agent, GOOG_URL).and_then(|g| get(&agent, CLOUD_URL).map(|c| (g, c)));
        match both {
            Ok((g, c)) if google_prefixes(&g).len() >= 10 && google_prefixes(&c).len() >= 10 => {
                crate::config::write_atomic_in(&dir(), "google-cloud.json", &c);
                crate::config::write_atomic_in(&dir(), "google.json", &g);
                errs.remove("google");
            }
            Ok(_) => {
                errs.insert("google", "Google's list came back empty or changed format".into());
            }
            Err(e) => {
                log(&format!("safe list google: {e}"));
                errs.insert("google", e);
            }
        }
    }
    if stale("microsoft") {
        tried = true;
        match get(&agent, M365_URL) {
            Ok(m) if m365_prefixes(&m).len() >= 10 => {
                crate::config::write_atomic_in(&dir(), "microsoft.json", &m);
                errs.remove("microsoft");
            }
            Ok(_) => {
                errs.insert("microsoft", "Microsoft's list came back empty or changed format".into());
            }
            Err(e) => {
                log(&format!("safe list microsoft: {e}"));
                errs.insert("microsoft", e);
            }
        }
    }
    tried
}

/// Settings → Test an address.
pub fn explain(s: &Safe, ip: &IpAddr, name: Option<&str>, on: bool, off: &[String]) -> Value {
    let v = s.verdict(ip, name);
    let svc_on = |i: u8| on && !off.iter().any(|o| o == SERVICES[i as usize].id);
    match v {
        Verdict::Safe(i, range) => json!({
            "safe": svc_on(i), "service": SERVICES[i as usize].name, "range": range,
            "text": format!("{ip} is in {range}, one of {}'s own ranges.{}", SERVICES[i as usize].name,
                if svc_on(i) { "" } else { " That service is switched off here, so it is treated like any other address." }),
        }),
        Verdict::Name(i, d) => json!({
            "safe": svc_on(i), "service": SERVICES[i as usize].name, "range": d,
            "text": format!("{ip} was looked up as a {d} name ({}).", SERVICES[i as usize].name),
        }),
        Verdict::Cloud(range) => json!({
            "safe": false, "service": "", "range": range,
            "text": format!("{ip} is in {range}, a Google Cloud range that Google rents to its customers. Anyone can run a server there, so it is not counted as safe."),
        }),
        Verdict::Unknown => json!({
            "safe": false, "service": "", "range": "",
            "text": format!("{ip} is not on any known-safe list."),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sample() -> Safe {
        let goog = r#"{"prefixes":[{"ipv4Prefix":"8.8.8.0/24"},{"ipv4Prefix":"34.0.0.0/15"},{"ipv4Prefix":"142.250.0.0/15"},{"ipv6Prefix":"2001:4860::/32"}]}"#;
        let cloud = r#"{"prefixes":[{"ipv4Prefix":"34.0.0.0/16","service":"Google Cloud","scope":"us"}]}"#;
        let m365 = r#"[{"id":1,"ips":["40.92.0.0/15","2603:1006::/40"]},{"id":2,"urls":["x.office.com"]},{"id":3,"ips":["40.92.0.0/15"]}]"#;
        from_texts(goog, cloud, m365, [1, 2], &HashMap::new())
    }

    #[test]
    fn own_services_but_never_cloud_customers() {
        let s = sample();
        assert_eq!(s.lookup(&ip("8.8.8.8"), None), svc_index("google"));
        assert_eq!(s.lookup(&ip("142.251.1.1"), None), svc_index("google"));
        assert_eq!(s.lookup(&ip("2001:4860:4860::8888"), None), svc_index("google"));
        // 34.0.x.x is a Google Cloud customer range: never safe.
        assert_eq!(s.verdict(&ip("34.0.5.5"), None), Verdict::Cloud("34.0.0.0/16".into()));
        assert_eq!(s.lookup(&ip("34.1.5.5"), None), svc_index("google"));
        assert_eq!(s.lookup(&ip("40.93.1.1"), None), svc_index("microsoft"));
        assert_eq!(s.lookup(&ip("17.253.1.1"), None), svc_index("apple"));
        assert_eq!(s.lookup(&ip("1.1.1.1"), None), None);
        // Windows Update by name, whatever the address.
        assert_eq!(s.lookup(&ip("203.0.113.9"), Some("2.dl.delivery.mp.microsoft.com")), svc_index("windows"));
        assert_eq!(s.lookup(&ip("203.0.113.9"), Some("windowsupdate.com.evil.example")), None);
        assert_eq!(s.lists.iter().find(|l| l.id == "microsoft").unwrap().n, 2, "duplicates dropped");
        assert_eq!(s.lists.iter().find(|l| l.id == "google").unwrap().excluded, 1);
        assert_eq!(s.entries(svc_index("apple").unwrap()), vec!["17.0.0.0/8"]);
    }

    #[test]
    fn explained() {
        let s = sample();
        let off = vec!["microsoft".to_string()];
        assert_eq!(explain(&s, &ip("8.8.4.4"), None, true, &off)["safe"], false); // 8.8.4.0 is not in the sample
        assert_eq!(explain(&s, &ip("8.8.8.8"), None, true, &off)["safe"], true);
        assert_eq!(explain(&s, &ip("40.92.1.1"), None, true, &off)["safe"], false, "switched off");
        assert_eq!(explain(&s, &ip("8.8.8.8"), None, false, &[])["safe"], false, "feature off");
        assert!(explain(&s, &ip("34.0.0.9"), None, true, &[])["text"].as_str().unwrap().contains("Google Cloud"));
    }

    #[test]
    fn builtins_without_downloads() {
        let s = from_texts("", "", "", [0, 0], &HashMap::new());
        assert_eq!(s.lookup(&ip("17.1.2.3"), None), svc_index("apple"));
        assert_eq!(s.lookup(&ip("8.8.8.8"), None), None);
        assert_eq!(s.lists.len(), SERVICES.len());
    }
}
