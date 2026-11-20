//! "Which company, which country": an offline lookup from IP address to the country it is
//! in and the company that runs it, so the app can say "70% went to Microsoft in the
//! Netherlands" instead of listing addresses. Data: DB-IP Lite (IP to Country Lite and
//! IP to ASN Lite, CC BY 4.0, https://db-ip.com), downloaded once a month as two
//! compressed CSV files into %LOCALAPPDATA%\Kestryl\geo\. Lookups never leave the PC.

use crate::util::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

pub static REFRESH_NOW: AtomicBool = AtomicBool::new(false);
/// The last download problem ("" = none), shown in Settings.
pub static ERR: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
/// The files are published monthly; refreshed when older than this.
const MAX_AGE_MS: u64 = 30 * 24 * 3600 * 1000;
pub const ATTRIBUTION: &str = "IP Geolocation by DB-IP (db-ip.com), CC BY 4.0";

#[derive(Default)]
pub struct Geo {
    /// (first, last, country) ranges, sorted. IPv6 keeps the top 64 bits (networks are
    /// never assigned in smaller pieces than that).
    v4c: Vec<(u32, u32, [u8; 2])>,
    v6c: Vec<(u64, u64, [u8; 2])>,
    /// (first, last, index into `orgs`).
    v4a: Vec<(u32, u32, u32)>,
    v6a: Vec<(u64, u64, u32)>,
    /// (AS number, registered name).
    orgs: Vec<(u32, String)>,
    pub country_t: u64,
    pub asn_t: u64,
    pub demo: bool,
    /// Demo only: fixed answers for the made-up addresses of --simulate.
    fake: HashMap<IpAddr, (&'static str, &'static str)>,
}

fn v6top(ip: &std::net::Ipv6Addr) -> u64 {
    (u128::from(*ip) >> 64) as u64
}

fn find<T: Copy + Ord, V: Copy>(v: &[(T, T, V)], x: T) -> Option<V> {
    let i = v.partition_point(|r| r.0 <= x);
    let r = v.get(i.checked_sub(1)?)?;
    (x <= r.1).then_some(r.2)
}

impl Geo {
    pub fn ready(&self) -> bool {
        self.demo || !self.v4c.is_empty()
    }

    /// Two-letter country code ("JP"), if known.
    pub fn country(&self, ip: &IpAddr) -> Option<String> {
        let ip = norm_ip(*ip);
        if let Some((cc, _)) = self.fake.get(&ip) {
            return Some(cc.to_string());
        }
        if scope(&ip) != Scope::Internet {
            return None;
        }
        let c = match ip {
            IpAddr::V4(v) => find(&self.v4c, u32::from(v)),
            IpAddr::V6(v) => find(&self.v6c, v6top(&v)),
        }?;
        (c != *b"ZZ").then(|| String::from_utf8_lossy(&c).into_owned())
    }

    /// The company that runs this address, as registered ("Microsoft Corporation").
    pub fn org_raw(&self, ip: &IpAddr) -> Option<(u32, &str)> {
        let ip = norm_ip(*ip);
        if let Some((_, org)) = self.fake.get(&ip) {
            return Some((0, org));
        }
        if scope(&ip) != Scope::Internet {
            return None;
        }
        let i = match ip {
            IpAddr::V4(v) => find(&self.v4a, u32::from(v)),
            IpAddr::V6(v) => find(&self.v6a, v6top(&v)),
        }?;
        self.orgs.get(i as usize).map(|(a, n)| (*a, n.as_str()))
    }

    /// (country code, short company name, AS number): what the UI shows next to an address.
    pub fn lookup(&self, ip: &IpAddr) -> (String, String, u32) {
        let (asn, org) = self.org_raw(ip).map(|(a, o)| (a, short_org(o))).unwrap_or((0, String::new()));
        (self.country(ip).unwrap_or_default(), org, asn)
    }

    pub fn info(&self) -> Value {
        let err = ERR.lock().map(|e| e.clone()).unwrap_or_default();
        json!({ "ready": self.ready(), "country_t": self.country_t, "asn_t": self.asn_t, "ranges": self.v4c.len() + self.v6c.len(),
                "companies": self.orgs.len(), "err": err, "demo": self.demo, "attribution": ATTRIBUTION })
    }
}

/// Big hosting and delivery networks: their name says who runs the server, not whose site
/// or service it is (Cloudflare serves millions of sites).
pub fn is_host(org: &str) -> bool {
    matches!(
        org,
        "Akamai" | "Cloudflare" | "Fastly" | "Amazon" | "Edgio" | "CDN77" | "Bunny" | "StackPath" | "OVH" | "Hetzner" | "DigitalOcean"
            | "Linode" | "Vultr" | "Contabo" | "Leaseweb" | "Oracle" | "Alibaba" | "Tencent" | "Google Cloud" | "Microsoft Azure"
            | "M247" | "Hostinger" | "Scaleway" | "G-Core Labs" | "Zenlayer" | "IONOS" | "Choopa"
    )
}

/// "Amazon.com, Inc." -> "Amazon", "Akamai International B.V." -> "Akamai".
pub fn short_org(raw: &str) -> String {
    let l = raw.to_lowercase();
    const BRANDS: [(&str, &str); 34] = [
        ("amazon", "Amazon"), ("akamai", "Akamai"), ("cloudflare", "Cloudflare"), ("fastly", "Fastly"), ("google", "Google"),
        ("microsoft", "Microsoft"), ("facebook", "Meta (Facebook)"), ("meta platforms", "Meta (Facebook)"), ("apple", "Apple"),
        ("netflix", "Netflix"), ("valve", "Valve (Steam)"), ("zoom", "Zoom"), ("telegram", "Telegram"), ("bytedance", "ByteDance (TikTok)"),
        ("tiktok", "ByteDance (TikTok)"), ("alibaba", "Alibaba"), ("tencent", "Tencent"), ("oracle", "Oracle"), ("digitalocean", "DigitalOcean"),
        ("ovh", "OVH"), ("hetzner", "Hetzner"), ("linode", "Linode"), ("the constant company", "Vultr"), ("vultr", "Vultr"),
        ("choopa", "Vultr"), ("contabo", "Contabo"), ("leaseweb", "Leaseweb"), ("edgecast", "Edgio"), ("limelight", "Edgio"),
        ("edgio", "Edgio"), ("datacamp", "CDN77"), ("bunny", "Bunny"), ("dropbox", "Dropbox"), ("twitter", "X (Twitter)"),
    ];
    if let Some((_, b)) = BRANDS.iter().find(|(k, _)| l.contains(k)) {
        return b.to_string();
    }
    let mut s = raw.trim().trim_matches('"').to_string();
    const SUFFIX: [&str; 35] = [
        ", inc.", ", inc", " inc.", " inc", ", llc", " llc", " l.l.c.", ", ltd.", " ltd.", " ltd", " limited", " corporation", " corp.",
        " corp", " gmbh", " b.v.", " bv", " s.a.", " sa", " sas", " ag", " co., ltd", " co.,ltd", " co. ltd", " pty", " k.k.", " plc",
        " ab", " oy", " s.p.a.", " srl", " s.r.o.", " sp. z o.o.", " a.s.", " co",
    ];
    loop {
        let low = s.to_lowercase();
        match SUFFIX.iter().find(|x| low.ends_with(*x) && s.len() > x.len() + 2) {
            Some(x) => {
                s.truncate(s.len() - x.len());
                s = s.trim_end_matches([',', ' ', '.']).to_string();
            }
            None => break,
        }
    }
    s
}

/// One CSV line of DB-IP: first,last,rest (rest may be quoted with "" escapes).
fn split3(line: &str) -> Option<(&str, &str, &str)> {
    let mut it = line.splitn(3, ',');
    Some((it.next()?, it.next()?, it.next()?))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    match s.strip_prefix('"').and_then(|x| x.strip_suffix('"')) {
        Some(x) => x.replace("\"\"", "\""),
        None => s.to_string(),
    }
}

fn gunzip(bytes: &[u8]) -> Result<String, String> {
    let mut s = String::new();
    flate2::read::GzDecoder::new(bytes).read_to_string(&mut s).map_err(|e| format!("damaged download ({e})"))?;
    Ok(s)
}

impl Geo {
    fn load_country(&mut self, text: &str) {
        for line in text.lines() {
            let Some((a, b, cc)) = split3(line) else { continue };
            let cc = cc.trim().as_bytes();
            if cc.len() != 2 {
                continue;
            }
            let c = [cc[0], cc[1]];
            match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
                (Ok(IpAddr::V4(x)), Ok(IpAddr::V4(y))) => self.v4c.push((u32::from(x), u32::from(y), c)),
                (Ok(IpAddr::V6(x)), Ok(IpAddr::V6(y))) => self.v6c.push((v6top(&x), v6top(&y), c)),
                _ => {}
            }
        }
        self.v4c.sort_unstable_by_key(|r| r.0);
        self.v6c.sort_unstable_by_key(|r| r.0);
        self.v6c.dedup_by_key(|r| r.0);
    }

    fn load_asn(&mut self, text: &str) {
        let mut idx: HashMap<(u32, String), u32> = HashMap::new();
        for line in text.lines() {
            let Some((a, b, rest)) = split3(line) else { continue };
            let (asn, name) = rest.split_once(',').unwrap_or((rest, ""));
            let asn: u32 = asn.trim().parse().unwrap_or(0);
            let name = unquote(name);
            let n = self.orgs.len() as u32;
            let i = *idx.entry((asn, name.clone())).or_insert_with(|| n);
            if i == n {
                self.orgs.push((asn, name));
            }
            match (a.parse::<IpAddr>(), b.parse::<IpAddr>()) {
                (Ok(IpAddr::V4(x)), Ok(IpAddr::V4(y))) => self.v4a.push((u32::from(x), u32::from(y), i)),
                (Ok(IpAddr::V6(x)), Ok(IpAddr::V6(y))) => self.v6a.push((v6top(&x), v6top(&y), i)),
                _ => {}
            }
        }
        self.v4a.sort_unstable_by_key(|r| r.0);
        self.v6a.sort_unstable_by_key(|r| r.0);
        self.v6a.dedup_by_key(|r| r.0);
    }
}

fn dir() -> std::path::PathBuf {
    crate::config::dir().join("geo")
}

fn mtime_ms(p: &std::path::Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Builds the lookup tables from the downloaded files (empty if there are none yet).
pub fn build() -> Geo {
    let mut g = Geo::default();
    for (kind, f) in [("country", "country.csv.gz"), ("asn", "asn.csv.gz")] {
        let p = dir().join(f);
        let Ok(bytes) = std::fs::read(&p) else { continue };
        match gunzip(&bytes) {
            Ok(text) if kind == "country" => {
                g.load_country(&text);
                g.country_t = mtime_ms(&p);
            }
            Ok(text) => {
                g.load_asn(&text);
                g.asn_t = mtime_ms(&p);
            }
            Err(e) => {
                log(&format!("geo {f}: {e}"));
                let _ = std::fs::remove_file(&p); // downloaded again next time
            }
        }
    }
    g
}

/// Downloads the monthly files when missing or older than a month (or `force`).
/// Ok(true) when something new was saved.
pub fn refresh(force: bool) -> Result<bool, String> {
    let _ = std::fs::create_dir_all(dir());
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS: {e}"))?;
    let agent = ureq::AgentBuilder::new().tls_connector(Arc::new(tls)).timeout(Duration::from_secs(120)).user_agent("Kestryl/0.1").build();
    let (day, _) = local_day_hour();
    let (y, m): (i32, u32) = (day[..4].parse().unwrap_or(2026), day[5..7].parse().unwrap_or(1));
    let prev = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
    let mut saved = false;
    let mut errs = Vec::new();
    for (kind, f) in [("country", "country.csv.gz"), ("asn", "asn.csv.gz")] {
        let p = dir().join(f);
        if !force && now_ms().saturating_sub(mtime_ms(&p)) < MAX_AGE_MS {
            continue;
        }
        // This month's file appears in the first days of the month; until then, last month's.
        let mut got = None;
        for (yy, mm) in [(y, m), prev] {
            let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{yy:04}-{mm:02}.csv.gz");
            match agent.get(&url).call() {
                Ok(r) => {
                    let mut buf = Vec::new();
                    if r.into_reader().take(64 * 1024 * 1024).read_to_end(&mut buf).is_ok() && gunzip(&buf).is_ok() {
                        got = Some(buf);
                        break;
                    }
                }
                Err(ureq::Error::Status(404, _)) => continue,
                Err(e) => {
                    errs.push(format!("{kind}: {}", match e {
                        ureq::Error::Status(c, _) => format!("HTTP {c}"),
                        ureq::Error::Transport(t) => t.kind().to_string(),
                    }));
                    break;
                }
            }
        }
        if let Some(buf) = got {
            let tmp = dir().join(format!("{f}.tmp"));
            if std::fs::write(&tmp, &buf).is_ok() && std::fs::rename(&tmp, &p).is_ok() {
                saved = true;
            }
        }
    }
    if errs.is_empty() {
        Ok(saved)
    } else {
        Err(format!("could not download the country/company data ({})", errs.join("; ")))
    }
}

/// The --simulate demo: the made-up addresses get made-up places.
pub fn demo() -> Geo {
    let mut g = Geo { demo: true, ..Default::default() };
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    for (a, cc, org) in [
        ("203.0.113.5", "US", "Cloudflare, Inc."),
        ("203.0.113.20", "US", "Amazon.com, Inc."),
        ("203.0.113.21", "GB", "Telegram Messenger Inc"),
        ("203.0.113.50", "US", "Google LLC"),
        ("203.0.113.51", "JP", "Google LLC"),
        ("203.0.113.60", "RU", "Hosting Ltd"),
        ("203.0.113.70", "DE", "philandro Software GmbH"),
        ("203.0.113.80", "NL", "Mail Relay B.V."),
        ("203.0.113.90", "SG", "DigitalOcean, LLC"),
        ("198.51.100.7", "RU", "Bulletproof Networks Ltd"),
        ("198.51.100.23", "BR", "Residential ISP S.A."),
    ] {
        g.fake.insert(ip(a), (cc, org));
    }
    g
}

/// The user's own country from Windows' region setting ("JP"), to tell home from abroad.
#[cfg(windows)]
pub fn home_country() -> String {
    let mut buf = [0u16; 16];
    let n = unsafe { windows::Win32::Globalization::GetUserDefaultGeoName(&mut buf) };
    if n <= 1 {
        return String::new();
    }
    let s = String::from_utf16_lossy(&buf[..(n as usize - 1).min(16)]);
    if s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic()) {
        s.to_uppercase()
    } else {
        String::new()
    }
}
#[cfg(not(windows))]
pub fn home_country() -> String {
    String::new()
}

/// "Where did my data go" for one day: sent and received per country and per company,
/// with the sites and programs behind each. LAN traffic is left out.
pub fn data_map(g: &Geo, d: &crate::history::Day) -> Value {
    #[derive(Default)]
    struct Acc<'a> {
        out: u64,
        inn: u64,
        sites: HashMap<&'a str, u64>,
        progs: HashMap<&'a str, (u64, &'a str)>,
        other: HashMap<String, u64>,
    }
    let mut cc: HashMap<String, Acc> = HashMap::new();
    let mut org: HashMap<String, Acc> = HashMap::new();
    let (mut total_out, mut total_in, mut unknown_out) = (0u64, 0u64, 0u64);
    for r in d.rows.iter().filter(|r| !r.lan) {
        total_out += r.out;
        total_in += r.inn;
        let Ok(ip) = r.ip.parse::<IpAddr>() else {
            unknown_out += r.out;
            continue;
        };
        let (c, o, _) = g.lookup(&ip);
        let c = if c.is_empty() { "??".to_string() } else { c };
        let o = if o.is_empty() { "Unknown".to_string() } else { o };
        for (map, key, other) in [(&mut cc, c.clone(), o.clone()), (&mut org, o.clone(), c.clone())] {
            let a = map.entry(key).or_default();
            a.out += r.out;
            a.inn += r.inn;
            *a.sites.entry(r.dest.as_str()).or_default() += r.out + r.inn / 16;
            let p = a.progs.entry(r.key.as_str()).or_insert((0, r.name.as_str()));
            p.0 += r.out;
            *a.other.entry(other).or_default() += r.out + r.inn / 16;
        }
    }
    let top = |m: &HashMap<&str, u64>, n: usize| -> Vec<String> {
        let mut v: Vec<(&&str, &u64)> = m.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        v.into_iter().take(n).map(|(k, _)| k.to_string()).collect()
    };
    let list = |m: HashMap<String, Acc>, is_org: bool| -> Vec<Value> {
        let mut v: Vec<(String, Acc)> = m.into_iter().collect();
        v.sort_by(|a, b| (b.1.out + b.1.inn / 16).cmp(&(a.1.out + a.1.inn / 16)).then(a.0.cmp(&b.0)));
        v.into_iter()
            .take(80)
            .map(|(k, a)| {
                let mut progs: Vec<(&&str, &(u64, &str))> = a.progs.iter().collect();
                progs.sort_by(|x, y| y.1 .0.cmp(&x.1 .0));
                let mut other: Vec<(&String, &u64)> = a.other.iter().collect();
                other.sort_by(|x, y| y.1.cmp(x.1));
                json!({
                    "key": k, "out": a.out, "in": a.inn, "host": is_org && is_host(&k),
                    "sites": top(&a.sites, 6), "n_sites": a.sites.len(),
                    "progs": progs.iter().take(5).map(|(key, (b, name))| json!({ "key": key, "name": name, "out": b })).collect::<Vec<_>>(),
                    "n_progs": a.progs.len(),
                    // countries of a company / companies in a country
                    "with": other.iter().take(5).map(|(k, _)| k.to_string()).collect::<Vec<_>>(),
                })
            })
            .collect()
    };
    json!({
        "day": d.day, "out": total_out, "in": total_in, "unknown_out": unknown_out,
        "countries": list(cc, false), "orgs": list(org, true),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookups_and_names() {
        let mut g = Geo::default();
        g.load_country("1.0.0.0,1.0.0.255,AU\n8.8.8.0,8.8.8.255,US\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n10.0.0.0,10.255.255.255,ZZ\n");
        g.load_asn("8.8.8.0,8.8.8.255,15169,\"Google LLC\"\n13.107.0.0,13.107.255.255,8068,\"Microsoft Corporation\"\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,\"Google LLC\"\n");
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(g.country(&ip("8.8.8.8")).as_deref(), Some("US"));
        assert_eq!(g.country(&ip("8.8.9.1")), None, "outside every range");
        assert_eq!(g.country(&ip("2001:4860:4860::8888")).as_deref(), Some("US"));
        assert_eq!(g.lookup(&ip("8.8.8.8")), ("US".to_string(), "Google".to_string(), 15169));
        assert_eq!(g.lookup(&ip("13.107.4.52")).1, "Microsoft");
        assert_eq!(g.lookup(&ip("192.168.1.1")).1, "", "private addresses are never looked up");
        assert_eq!(g.orgs.len(), 2, "same company stored once");
        assert_eq!(short_org("Akamai International B.V."), "Akamai");
        assert_eq!(short_org("ARTERIA Networks Corporation"), "ARTERIA Networks");
        assert_eq!(short_org("Gtelecom Pty Ltd"), "Gtelecom");
        assert_eq!(short_org("NTT Communications Co., Ltd."), "NTT Communications");
        assert_eq!(unquote("\"Foo \"\"Bar\"\", Inc.\""), "Foo \"Bar\", Inc.");
        assert!(is_host("Cloudflare") && !is_host("Google"));
    }

    #[test]
    fn data_map_groups_by_country_and_company() {
        let g = demo();
        let mut d = crate::history::Day::new("2026-11-19".into());
        d.add("c:\\a\\x.exe", "x.exe", "storage-sync.net", "203.0.113.60", 443, false, false, 5 * MB, KB, 2, 1);
        d.add("c:\\a\\y.exe", "y.exe", "google.com", "203.0.113.50", 443, false, false, MB, 20 * MB, 3, 2);
        d.add("c:\\a\\y.exe", "y.exe", "192.168.1.9", "192.168.1.9", 445, false, true, 9 * MB, 0, 3, 3);
        let m = data_map(&g, &d);
        assert_eq!(m["out"], 6 * MB, "LAN left out");
        assert_eq!(m["countries"][0]["key"], "RU");
        assert_eq!(m["countries"][0]["progs"][0]["name"], "x.exe");
        assert_eq!(m["orgs"].as_array().unwrap().iter().find(|o| o["key"] == "Google").unwrap()["in"], 20 * MB);
    }
}
