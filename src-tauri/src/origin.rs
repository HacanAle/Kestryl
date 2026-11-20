//! "Where did this program come from?" Browsers, mail and chat apps attach a small note to
//! every file they download (the Zone.Identifier stream, "Mark of the Web") with the site it
//! came from. Kestryl reads that note, plus where the file lives and when it arrived, so a
//! program can be described as "downloaded from free-pdf-tools.xyz on 3 Nov".

use crate::detect::{self, Class};
use crate::util::*;
use serde_json::{json, Value};

/// Parsed Zone.Identifier: (zone id, HostUrl, ReferrerUrl).
pub fn parse_zone(text: &str) -> (Option<u32>, String, String) {
    let (mut zone, mut host, mut refr) = (None, String::new(), String::new());
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        // Some browsers end the value with a NUL character.
        let v: String = v.trim().chars().filter(|c| !c.is_control()).collect();
        match k.trim().to_ascii_lowercase().as_str() {
            "zoneid" => zone = v.parse().ok(),
            "hosturl" => host = v,
            "referrerurl" => refr = v,
            _ => {}
        }
    }
    (zone, host, refr)
}

/// "https://dl.example.com/x/setup.exe?token=..." -> "dl.example.com"; "" for about:internet etc.
pub fn url_host(u: &str) -> String {
    let u = u.trim().strip_prefix("blob:").unwrap_or(u.trim());
    let Some((scheme, rest)) = u.split_once("://") else { return String::new() };
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https" | "ftp") {
        return String::new();
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host); // user:pass@host
    let host = if host.starts_with('[') { host } else { host.split(':').next().unwrap_or(host) };
    host.to_ascii_lowercase()
}

/// "cdn.example.com" -> "example.com"; an IP address stays as it is.
fn site_of(host: &str) -> String {
    if host.trim_matches(['[', ']']).parse::<std::net::IpAddr>().is_ok() {
        host.to_string()
    } else {
        base_domain(host)
    }
}

/// A URL without its query string (download links often carry access tokens).
fn short_url(u: &str) -> String {
    let base = u.split(['?', '#']).next().unwrap_or(u);
    base.chars().take(180).collect()
}

fn created_ms(path: &str) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.created())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What is known about where a program file came from.
/// kind: download | windows | installed | store | local | gone.
pub fn origin(path: &str) -> Value {
    if path.is_empty() {
        return json!({ "kind": "windows" });
    }
    let p = std::path::Path::new(path);
    if !p.is_file() {
        return json!({ "kind": "gone" });
    }
    let created = created_ms(path);
    let zone = std::fs::read_to_string(format!("{path}:Zone.Identifier")).ok();
    if let Some(text) = zone {
        let (zone, host_url, refr) = parse_zone(&text);
        let host = url_host(&host_url);
        let rhost = url_host(&refr);
        let site = site_of(if host.is_empty() { &rhost } else { &host });
        return json!({
            "kind": "download", "zone": zone, "internet": zone == Some(3) || zone == Some(4),
            "host": host, "site": site, "url": short_url(&host_url), "referrer": short_url(&refr), "created": created,
        });
    }
    let lower = path.to_lowercase();
    let kind = if lower.contains("\\windowsapps\\") {
        "store"
    } else {
        match detect::classify(&lower) {
            Class::System => "windows",
            Class::Installed => "installed",
            _ => "local",
        }
    };
    json!({ "kind": kind, "created": created })
}

/// The --simulate demo: made-up download records for its fake programs.
pub fn demo(path: &str) -> Value {
    let name = path.rsplit('\\').next().unwrap_or("").to_lowercase();
    let now = now_ms();
    let dl = |host: &str, url: &str, refr: &str, days: u64| {
        json!({ "kind": "download", "zone": 3, "internet": true, "host": host, "site": base_domain(host), "url": url, "referrer": refr, "created": now - days * 86_400_000 })
    };
    match name.as_str() {
        "invoice_viewer.exe" => dl("files.invoice-portal.top", "https://files.invoice-portal.top/dl/invoice_viewer.exe", "https://mail.google.com/", 0),
        "syncsvc.exe" => dl("cdn.discordapp.com", "https://cdn.discordapp.com/attachments/1182/free_robux_generator.zip", "", 3),
        "svc_helper.exe" => dl("raw.githubusercontent.com", "https://raw.githubusercontent.com/x/y/main/svc_helper.exe", "", 0),
        "anydesk.exe" => dl("download.anydesk.com", "https://download.anydesk.com/AnyDesk.exe", "https://anydesk.com/en/downloads", 1),
        "updater.exe" => json!({ "kind": "local", "created": now - 2 * 86_400_000 }),
        _ => {
            let lower = path.to_lowercase();
            json!({ "kind": match detect::classify(&lower) { Class::System => "windows", Class::Installed => "installed", _ => "local" }, "created": now - 40 * 86_400_000u64 })
        }
    }
}

/// One line for an alert: "downloaded from example.com" (empty when unknown).
pub fn summary(v: &Value) -> String {
    match v["kind"].as_str() {
        Some("download") => {
            let site = v["site"].as_str().unwrap_or("");
            if site.is_empty() {
                "downloaded from the internet (site not recorded)".into()
            } else {
                format!("downloaded from {site}")
            }
        }
        Some("store") => "installed from the Microsoft Store".into(),
        Some("windows") => "part of Windows".into(),
        Some("installed") => "installed in Program Files".into(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zone_identifier() {
        let (z, h, r) = parse_zone("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://www.example.com/page\r\nHostUrl=https://cdn.example.com/dl/setup.exe?sig=abc\r\n");
        assert_eq!(z, Some(3));
        assert_eq!(url_host(&h), "cdn.example.com");
        assert_eq!(url_host(&r), "www.example.com");
        assert_eq!(short_url(&h), "https://cdn.example.com/dl/setup.exe");
        assert_eq!(url_host("about:internet"), "");
        assert_eq!(url_host("blob:https://web.whatsapp.com/1234-abcd"), "web.whatsapp.com");
        assert_eq!(url_host("https://user:pw@files.example.org:8443/a"), "files.example.org");
    }

    #[test]
    #[ignore]
    fn live_origin_of_a_download() {
        // Files in the user's Downloads folder carry their source site. Only counts are
        // printed: file names and sites are the user's private business.
        let dl = std::path::Path::new(&std::env::var("USERPROFILE").unwrap()).join("Downloads");
        let (mut n, mut with_site, mut bad) = (0, 0, 0);
        for e in std::fs::read_dir(dl).unwrap().flatten().take(200) {
            if e.path().is_file() {
                let o = origin(&e.path().display().to_string());
                if o["kind"] == "download" {
                    n += 1;
                    let site = o["site"].as_str().unwrap_or("");
                    with_site += usize::from(!site.is_empty());
                    bad += usize::from(o["url"].as_str().unwrap_or("").chars().any(char::is_control) || site.starts_with('.'));
                }
            }
        }
        println!("{n} downloaded files, {with_site} with a site, {bad} malformed");
        assert_eq!(bad, 0);
        assert_eq!(origin(r"C:\Windows\notepad.exe")["kind"], "windows");
        assert_eq!(site_of("192.168.1.50"), "192.168.1.50");
    }
}
