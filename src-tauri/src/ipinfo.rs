//! "Get IP info": public facts about a remote address from two free, keyless HTTPS services.
//! - ipinfo.io: hostname, ISP/ASN, city/country, timezone.
//! - RDAP (rdap.org -> the regional registry, e.g. ARIN/RIPE/APNIC): who registered the
//!   address block, its range, and the abuse contact. This is the official registry data.
//! Only the looked-up IP is sent. Requests come from kestryl.exe itself (not PowerShell),
//! so Script lockdown does not get in the way.

use crate::util::*;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

const CACHE_MS: u64 = 60 * 60 * 1000;

fn cache() -> &'static Mutex<HashMap<IpAddr, (u64, Value)>> {
    static C: OnceLock<Mutex<HashMap<IpAddr, (u64, Value)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn agent() -> Result<ureq::Agent, String> {
    let tls = native_tls::TlsConnector::new().map_err(|e| format!("TLS: {e}"))?;
    Ok(ureq::AgentBuilder::new()
        .tls_connector(Arc::new(tls))
        .timeout(Duration::from_secs(10))
        .user_agent("Kestryl/0.1")
        .build())
}

fn get_json(agent: &ureq::Agent, url: &str) -> Result<Value, String> {
    match agent.get(url).set("Accept", "application/rdap+json, application/json").call() {
        Ok(r) => {
            let s = r.into_string().map_err(|e| e.to_string())?;
            serde_json::from_str(&s).map_err(|e| format!("unexpected answer ({e})"))
        }
        Err(ureq::Error::Status(429, _)) => Err("rate limit reached, try again in a while".into()),
        Err(ureq::Error::Status(404, _)) => Err("no record for this address".into()),
        Err(ureq::Error::Status(code, _)) => Err(format!("the service answered HTTP {code}")),
        Err(ureq::Error::Transport(t)) => Err(format!("could not reach the service ({})", t.kind())),
    }
}

fn s(v: &Value) -> String {
    v.as_str().unwrap_or("").to_string()
}

fn vcard(e: &Value, key: &str) -> String {
    let Some(props) = e["vcardArray"][1].as_array() else { return String::new() };
    for p in props {
        if p[0].as_str() == Some(key) {
            return match &p[3] {
                Value::String(x) => x.clone(),
                Value::Array(a) => a.iter().filter_map(|x| x.as_str()).filter(|x| !x.is_empty()).collect::<Vec<_>>().join(", "),
                _ => String::new(),
            };
        }
    }
    String::new()
}

/// (roles, name, email) of every entity, including nested ones (ARIN nests abuse contacts).
fn walk(ents: &Value, out: &mut Vec<(Vec<String>, String, String)>) {
    for e in ents.as_array().into_iter().flatten() {
        let roles = e["roles"].as_array().into_iter().flatten().filter_map(|r| r.as_str().map(String::from)).collect();
        out.push((roles, vcard(e, "fn"), vcard(e, "email")));
        walk(&e["entities"], out);
    }
}

pub fn summarize_rdap(v: &Value) -> Value {
    let mut ents = Vec::new();
    walk(&v["entities"], &mut ents);
    let with_role = |role: &str| ents.iter().find(|(r, n, _)| r.iter().any(|x| x == role) && !n.is_empty()).map(|e| e.1.clone());
    let owner = with_role("registrant").or_else(|| with_role("administrative")).or_else(|| with_role("technical"));
    let abuse = ents.iter().find(|(r, _, m)| r.iter().any(|x| x == "abuse") && !m.is_empty()).map(|e| e.2.clone());
    let cidrs: Vec<String> = v["cidr0_cidrs"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|c| {
            let pre = c["v4prefix"].as_str().or_else(|| c["v6prefix"].as_str()).unwrap_or("");
            format!("{pre}/{}", c["length"].as_u64().unwrap_or(0))
        })
        .collect();
    let event = |action: &str| {
        v["events"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["eventAction"].as_str() == Some(action))
            .and_then(|e| e["eventDate"].as_str())
            .map(|d| d.chars().take(10).collect::<String>())
    };
    let remarks: Vec<String> = v["remarks"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|r| r["description"].as_array().cloned().unwrap_or_default())
        .filter_map(|d| d.as_str().map(|x| x.trim().to_string()))
        .filter(|d| !d.is_empty())
        .take(3)
        .collect();
    let range = match (v["startAddress"].as_str(), v["endAddress"].as_str()) {
        (Some(a), Some(b)) => format!("{a} – {b}"),
        _ => String::new(),
    };
    json!({
        "name": s(&v["name"]), "handle": s(&v["handle"]), "type": s(&v["type"]),
        "owner": owner, "abuse": abuse, "cidr": cidrs.join(", "), "range": range,
        "country": s(&v["country"]), "registered": event("registration"), "changed": event("last changed"),
        "registry": s(&v["port43"]), "remarks": remarks,
    })
}

/// --simulate: made-up details, so the demo never contacts the internet.
pub fn demo(raw: &str) -> Result<Value, String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| format!("\"{}\" is not an IP address.", raw.trim()))?;
    let ip = norm_ip(ip);
    if scope(&ip) != Scope::Internet {
        return Err(format!("{ip} is not a public internet address."));
    }
    let range = match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(_) => format!("{ip}/64"),
    };
    Ok(json!({
        "ip": ip.to_string(), "demo": true,
        "geo": { "org": "AS64500 Example Hosting (simulated)", "city": "Amsterdam", "region": "North Holland", "country": "NL", "timezone": "Europe/Amsterdam" },
        "rdap": { "owner": "Example Hosting B.V. (simulated)", "name": "EXAMPLE-HOSTING", "cidr": range, "country": "NL",
                  "abuse": "abuse@example-hosting.example", "registered": "2019-04-02", "registry": "RIPE NCC (simulated)" },
    }))
}

pub fn lookup(raw: &str) -> Result<Value, String> {
    let ip: IpAddr = raw.trim().parse().map_err(|_| format!("\"{}\" is not an IP address.", raw.trim()))?;
    let ip = norm_ip(ip);
    match scope(&ip) {
        Scope::Internet => {}
        Scope::Lan => return Err(format!("{ip} is a private address inside a local network; public registries have nothing on it.")),
        _ => return Err(format!("{ip} is a loopback, multicast or broadcast address, not a host on the internet.")),
    }
    let now = now_ms();
    if let Some((t, v)) = cache().lock().unwrap_or_else(|p| p.into_inner()).get(&ip) {
        if *t + CACHE_MS > now {
            return Ok(v.clone());
        }
    }
    let agent = agent()?;
    let (geo, rdap) = std::thread::scope(|sc| {
        let a = sc.spawn(|| get_json(&agent, &format!("https://ipinfo.io/{ip}/json")));
        let b = sc.spawn(|| get_json(&agent, &format!("https://rdap.org/ip/{ip}")).map(|v| summarize_rdap(&v)));
        (
            a.join().unwrap_or_else(|_| Err("lookup crashed".into())),
            b.join().unwrap_or_else(|_| Err("lookup crashed".into())),
        )
    });
    if let (Err(a), Err(b)) = (&geo, &rdap) {
        return Err(format!("Both lookups failed. ipinfo.io: {a}. Registry: {b}."));
    }
    let geo = geo.map(|g| {
        let mut m = serde_json::Map::new();
        for k in ["hostname", "city", "region", "country", "loc", "org", "postal", "timezone", "anycast", "bogon"] {
            if !g[k].is_null() {
                m.insert(k.into(), g[k].clone());
            }
        }
        Value::Object(m)
    });
    let out = json!({
        "ip": ip.to_string(),
        "geo": geo.as_ref().ok(), "geo_error": geo.as_ref().err(),
        "rdap": rdap.as_ref().ok(), "rdap_error": rdap.as_ref().err(),
    });
    cache().lock().unwrap_or_else(|p| p.into_inner()).insert(ip, (now, out.clone()));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdap_summary() {
        let v: Value = serde_json::from_str(r#"{
          "handle": "NET-8-8-8-0-2", "name": "GOGL", "type": "DIRECT ALLOCATION",
          "startAddress": "8.8.8.0", "endAddress": "8.8.8.255", "port43": "whois.arin.net",
          "cidr0_cidrs": [{"v4prefix": "8.8.8.0", "length": 24}],
          "events": [{"eventAction": "registration", "eventDate": "2014-03-14T16:52:05-04:00"},
                     {"eventAction": "last changed", "eventDate": "2014-03-14T16:52:05-04:00"}],
          "remarks": [{"description": ["Google public DNS"]}],
          "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Google LLC"]]],
                        "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Abuse"], ["email", {}, "text", "network-abuse@google.com"]]]}]}]
        }"#).unwrap();
        let r = summarize_rdap(&v);
        assert_eq!(r["owner"], "Google LLC");
        assert_eq!(r["abuse"], "network-abuse@google.com");
        assert_eq!(r["cidr"], "8.8.8.0/24");
        assert_eq!(r["range"], "8.8.8.0 – 8.8.8.255");
        assert_eq!(r["registered"], "2014-03-14");
        assert_eq!(r["remarks"][0], "Google public DNS");
    }

    #[test]
    fn refuses_private() {
        assert!(lookup("192.168.1.1").unwrap_err().contains("private"));
        assert!(lookup("nope").is_err());
    }

    /// Live network test, run by hand: cargo test --lib live_lookup -- --ignored --nocapture
    #[test]
    #[ignore]
    fn live_lookup() {
        for ip in ["8.8.8.8", "1.1.1.1", "203.0.113.5"] {
            match lookup(ip) {
                Ok(v) => println!("{ip} -> {v}"),
                Err(e) => println!("{ip} -> ERR {e}"),
            }
        }
    }
}
