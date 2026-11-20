//! "Peek": a short packet capture of one connection with Windows' own Packet Monitor
//! (pktmon, part of Windows 10 2004 and later, no driver to install), then a look at what
//! the bytes are:
//! - standard encryption (TLS, QUIC, SSH): which version and the real server name,
//! - plain text (HTTP, FTP, mail, DNS): shown as sent, passwords and cookies hidden,
//! - anything else: random-looking bytes mean a home-made encrypted channel.
//! Nothing is decrypted. The capture files are deleted afterwards.

use crate::util::*;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static RUNNING: AtomicBool = AtomicBool::new(false);
const KEEP: usize = 16 * 1024;

fn pktmon(args: &[&str]) -> Result<String, String> {
    let mut cmd = std::process::Command::new(system_exe("PktMon.exe"));
    cmd.args(args).stdin(std::process::Stdio::null());
    hide_window(&mut cmd);
    let out = own_output(&mut cmd).map_err(|e| format!("Could not run pktmon (Windows Packet Monitor): {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() {
        Ok(text)
    } else {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let msg = if !err.is_empty() { err } else if !text.is_empty() { text } else { format!("exit code {:?}", out.status.code()) };
        Err(format!("pktmon {}: {}", args.first().unwrap_or(&""), msg.lines().next().unwrap_or("")))
    }
}

/// Captures traffic to/from `ip` (optionally one port) for `secs` seconds and explains it.
pub fn capture(ip: &str, port: Option<u16>, secs: u64) -> Result<Value, String> {
    let addr: IpAddr = ip.trim().parse().map_err(|_| format!("\"{ip}\" is not an IP address."))?;
    let addr = norm_ip(addr);
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err("Another peek is still running; wait for it to finish.".into());
    }
    let res = run_capture(addr, port, secs);
    RUNNING.store(false, Ordering::SeqCst);
    res
}

fn run_capture(addr: IpAddr, port: Option<u16>, secs: u64) -> Result<Value, String> {
    // A new folder in Windows' own Temp (not the user's %TEMP%, where any program the user
    // runs could plant a link and make the elevated pktmon write over another file).
    let dir = windows_dir().join("Temp").join(format!("kestryl-peek-{}-{}", std::process::id(), now_ms()));
    std::fs::create_dir(&dir).map_err(|e| format!("Could not make a folder for the capture: {e}"))?;
    let res = capture_in(&dir, addr, port, secs);
    let _ = std::fs::remove_file(dir.join("peek.etl"));
    let _ = std::fs::remove_file(dir.join("peek.pcapng"));
    let _ = std::fs::remove_dir(&dir);
    res
}

fn capture_in(dir: &std::path::Path, addr: IpAddr, port: Option<u16>, secs: u64) -> Result<Value, String> {
    let etl = dir.join("peek.etl");
    let pcap = dir.join("peek.pcapng");
    let ips = addr.to_string();
    let ports = port.map(|p| p.to_string()).unwrap_or_default();
    let _ = pktmon(&["filter", "remove"]);
    let mut fargs = vec!["filter", "add", "Kestryl-peek", "-i", ips.as_str()];
    if port.is_some() {
        fargs.extend(["-p", ports.as_str()]);
    }
    pktmon(&fargs)?;
    let etl_s = etl.display().to_string();
    if let Err(e) = pktmon(&["start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", &etl_s, "--file-size", "64"]) {
        let _ = pktmon(&["filter", "remove"]);
        return Err(format!("Packet capture could not start. Is another capture (pktmon, netsh trace) running? {e}"));
    }
    std::thread::sleep(Duration::from_secs(secs));
    let stop = pktmon(&["stop"]);
    let _ = pktmon(&["filter", "remove"]);
    stop?;
    let pcap_s = pcap.display().to_string();
    let conv = pktmon(&["etl2pcap", &etl_s, "--out", &pcap_s]);
    let data = std::fs::read(&pcap);
    let _ = std::fs::remove_file(&etl);
    let _ = std::fs::remove_file(&pcap);
    conv?;
    let data = data.map_err(|e| format!("Could not read the capture: {e}"))?;
    Ok(analyze(addr, port, secs, &parse_pcapng(&data), false))
}

// ---------------------------------------------------------------- pcapng

pub struct Pkt {
    pub link: u16,
    pub data: Vec<u8>,
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn be16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]))
}
fn be32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

/// Packets from a little-endian pcapng file (what pktmon writes).
pub fn parse_pcapng(b: &[u8]) -> Vec<Pkt> {
    let mut out = Vec::new();
    let mut links: Vec<u16> = Vec::new();
    let mut i = 0usize;
    while i + 12 <= b.len() {
        let (Some(t), Some(len)) = (le32(b, i), le32(b, i + 4)) else { break };
        let len = len as usize;
        if len < 12 || len % 4 != 0 || i + len > b.len() {
            break;
        }
        let body = &b[i + 8..i + len - 4];
        match t {
            0x0A0D_0D0A => links.clear(),
            1 => {
                if let Some(l) = body.get(0..2) {
                    links.push(u16::from_le_bytes([l[0], l[1]]));
                }
            }
            6 if body.len() >= 20 => {
                let ifc = le32(body, 0).unwrap_or(0) as usize;
                let cap = le32(body, 12).unwrap_or(0) as usize;
                if let Some(d) = body.get(20..20 + cap) {
                    out.push(Pkt { link: links.get(ifc).copied().unwrap_or(1), data: d.to_vec() });
                }
            }
            3 if body.len() >= 4 => out.push(Pkt { link: links.first().copied().unwrap_or(1), data: body[4..].to_vec() }),
            _ => {}
        }
        i += len;
    }
    out
}

struct Seg<'a> {
    src: IpAddr,
    dst: IpAddr,
    tcp: bool,
    sport: u16,
    dport: u16,
    seq: u32,
    payload: &'a [u8],
}

/// Ethernet (or raw IP) -> IPv4/IPv6 -> TCP/UDP.
fn decode(p: &Pkt) -> Option<Seg<'_>> {
    let d = &p.data[..];
    let raw_ip = |d: &[u8]| matches!(d.first().map(|b| b >> 4), Some(4) | Some(6));
    let ip = if p.link == 1 && !(raw_ip(d) && d.len() > 20 && be16(d, 12).is_some_and(|e| e != 0x0800 && e != 0x86dd && e != 0x8100)) {
        let mut o = 12;
        let mut et = be16(d, o)?;
        while et == 0x8100 || et == 0x88a8 {
            o += 4;
            et = be16(d, o)?;
        }
        if et != 0x0800 && et != 0x86dd {
            return None;
        }
        d.get(o + 2..)?
    } else {
        d
    };
    let (src, dst, proto, l4) = match ip.first()? >> 4 {
        4 => {
            let ihl = ((ip[0] & 0x0f) as usize) * 4;
            let total = (be16(ip, 2)? as usize).min(ip.len());
            if ihl < 20 || ihl > total {
                return None;
            }
            let s: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            let t: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
            (IpAddr::from(s), IpAddr::from(t), *ip.get(9)?, &ip[ihl..total])
        }
        6 => {
            let plen = be16(ip, 4)? as usize;
            let s: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let t: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            (IpAddr::from(s), IpAddr::from(t), *ip.get(6)?, ip.get(40..(40 + plen).min(ip.len()))?)
        }
        _ => return None,
    };
    let (src, dst) = (norm_ip(src), norm_ip(dst));
    match proto {
        6 => {
            let off = ((*l4.get(12)? >> 4) as usize) * 4;
            if off < 20 || off > l4.len() {
                return None;
            }
            Some(Seg { src, dst, tcp: true, sport: be16(l4, 0)?, dport: be16(l4, 2)?, seq: be32(l4, 4)?, payload: &l4[off..] })
        }
        17 if l4.len() >= 8 => Some(Seg { src, dst, tcp: false, sport: be16(l4, 0)?, dport: be16(l4, 2)?, seq: 0, payload: &l4[8..] }),
        _ => None,
    }
}

// ---------------------------------------------------------------- what the bytes are

fn entropy_bytes(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    let mut c = [0u32; 256];
    for x in b {
        c[*x as usize] += 1;
    }
    let n = b.len() as f64;
    c.iter().filter(|x| **x > 0).map(|x| {
        let p = *x as f64 / n;
        -p * p.log2()
    }).sum()
}

fn printable(b: &[u8]) -> f64 {
    if b.is_empty() {
        return 0.0;
    }
    b.iter().filter(|c| matches!(**c, 9 | 10 | 13 | 32..=126)).count() as f64 / b.len() as f64
}

/// Readable text with the login for the server itself blanked: FTP/POP PASS, SMTP AUTH
/// (and the two base64 lines after AUTH LOGIN), Authorization headers and cookies.
fn text(b: &[u8], max: usize) -> String {
    let s: String = b.iter().take(max).filter(|c| **c != b'\r').map(|&c| if c == b'\n' || c == b'\t' || (32..127).contains(&c) { c as char } else { '·' }).collect();
    let mut after_login = 0;
    s.lines()
        .map(|l| {
            let low = l.to_ascii_lowercase();
            if after_login > 0 && !l.trim().is_empty() {
                after_login -= 1;
                return "•••••• (login, hidden by Kestryl)".to_string();
            }
            if low.trim_end() == "auth login" {
                after_login = 2;
                return l.to_string();
            }
            for p in ["pass ", "auth plain ", "authorization: ", "proxy-authorization: ", "cookie: ", "set-cookie: "] {
                if low.starts_with(p) {
                    return format!("{}•••••• (hidden by Kestryl)", &l[..p.len()]);
                }
            }
            l.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn hex(b: &[u8], n: usize) -> String {
    b.chunks(16)
        .take(n.div_ceil(16))
        .map(|c| {
            let h: Vec<String> = c.iter().map(|x| format!("{x:02x}")).collect();
            let a: String = c.iter().map(|&x| if (32..127).contains(&x) { x as char } else { '.' }).collect();
            format!("{:<48} {a}", h.join(" "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Server name and ALPN from a TLS ClientHello (possibly spread over several segments).
fn client_hello(b: &[u8]) -> Option<(String, String)> {
    if b.len() < 43 || b[0] != 0x16 || b[5] != 0x01 {
        return None;
    }
    let mut o = 9 + 2 + 32;
    o += 1 + *b.get(o)? as usize; // session id
    o += 2 + be16(b, o)? as usize; // cipher suites
    o += 1 + *b.get(o)? as usize; // compression
    let end = (o + 2 + be16(b, o)? as usize).min(b.len());
    o += 2;
    let (mut sni, mut alpn) = (String::new(), String::new());
    while o + 4 <= end {
        let (t, l) = (be16(b, o)?, be16(b, o + 2)? as usize);
        let d = b.get(o + 4..(o + 4 + l).min(b.len()))?;
        match t {
            0 if d.len() >= 5 && d[2] == 0 => {
                let n = be16(d, 3)? as usize;
                if let Some(nm) = d.get(5..5 + n) {
                    sni = String::from_utf8_lossy(nm).into_owned();
                }
            }
            16 if d.len() > 2 => {
                let (mut p, mut names) = (2, Vec::new());
                while p < d.len() {
                    let n = d[p] as usize;
                    if let Some(x) = d.get(p + 1..p + 1 + n) {
                        names.push(String::from_utf8_lossy(x).into_owned());
                    }
                    p += 1 + n;
                }
                alpn = names.join(", ");
            }
            _ => {}
        }
        o += 4 + l;
    }
    Some((sni, alpn))
}

/// TLS version the server picked, from its ServerHello.
fn server_hello(b: &[u8]) -> Option<&'static str> {
    if b.len() < 43 || b[0] != 0x16 || b[5] != 0x02 {
        return None;
    }
    let legacy = be16(b, 9)?;
    let mut o = 9 + 2 + 32;
    o += 1 + *b.get(o)? as usize;
    o += 3; // cipher suite + compression
    if let Some(ext) = be16(b, o) {
        let end = (o + 2 + ext as usize).min(b.len());
        o += 2;
        while o + 4 <= end {
            let (t, l) = (be16(b, o)?, be16(b, o + 2)? as usize);
            if t == 43 && l == 2 && be16(b, o + 4)? == 0x0304 {
                return Some("1.3");
            }
            o += 4 + l;
        }
    }
    Some(match legacy {
        0x0303 => "1.2",
        0x0302 => "1.1",
        0x0301 => "1.0",
        _ => "old",
    })
}

fn dns_qname(b: &[u8]) -> Option<String> {
    let mut o = 12;
    let mut labels = Vec::new();
    loop {
        let n = *b.get(o)? as usize;
        if n == 0 || n & 0xC0 != 0 || labels.len() > 30 {
            break;
        }
        labels.push(String::from_utf8_lossy(b.get(o + 1..o + 1 + n)?).into_owned());
        o += 1 + n;
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

#[derive(Default)]
struct Conv {
    tcp: bool,
    lport: u16,
    rport: u16,
    out: Vec<u8>,
    inn: Vec<u8>,
    out_bytes: u64,
    in_bytes: u64,
    packets: u32,
    first_out: Vec<u8>,
    names: Vec<String>,
    seen: HashSet<(bool, u32, usize)>,
}

const METHODS: [&str; 9] = ["GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "PROPFIND "];

fn judge(c: &Conv) -> Value {
    let (o, i) = (&c.out[..], &c.inn[..]);
    let starts = |b: &[u8], p: &str| b.len() >= p.len() && b[..p.len()].eq_ignore_ascii_case(p.as_bytes());
    let has = |b: &[u8], p: &str| b.windows(p.len()).any(|w| w.eq_ignore_ascii_case(p.as_bytes()));
    let base = json!({ "proto": if c.tcp { "tcp" } else { "udp" }, "lport": c.lport, "rport": c.rport, "out": c.out_bytes, "in": c.in_bytes, "packets": c.packets });
    let mut v = base;
    let mut set = |kind: &str, verdict: &str, summary: String| {
        v["kind"] = json!(kind);
        v["verdict"] = json!(verdict);
        v["summary"] = json!(summary);
    };
    if c.out_bytes == 0 && c.in_bytes == 0 {
        set("none", "empty", "Connected, but no data was sent or received during the capture.".into());
        return v;
    }
    if !c.tcp {
        if c.rport == 53 || c.lport == 53 {
            set("dns", "plain", "DNS name lookups (not encrypted). The names are listed below.".into());
            v["names"] = json!(c.names);
        } else if c.rport == 443 && c.first_out.first().is_some_and(|b| b & 0x80 != 0) {
            set("quic", "encrypted", "Standard encryption: QUIC (HTTP/3, the newer form of HTTPS). Nobody on the way, Kestryl included, can read the contents.".into());
        } else if matches!(c.rport, 51820 | 500 | 4500 | 1194) {
            set("vpn", "encrypted", "A VPN tunnel (WireGuard, IPsec or OpenVPN): encrypted.".into());
        } else if entropy_bytes(&c.first_out) > 7.0 || (c.first_out.len() < 400 && entropy_bytes(o) > 7.2) {
            set("custom", "custom", "Not a standard protocol, and the data looks random: it is encrypted or compressed in the program's own way. Games, calls and VPNs do this over UDP; malware does it to hide.".into());
            v["hex"] = json!(hex(o, 128));
        } else {
            set("unknown", "unknown", "An unknown protocol over UDP. Sample bytes below.".into());
            v["hex"] = json!(hex(o, 128));
            v["text_out"] = json!(text(o, 1200));
        }
        return v;
    }
    if o.first() == Some(&0x16) || i.first() == Some(&0x16) {
        let (sni, alpn) = client_hello(o).unwrap_or_default();
        let ver = server_hello(i).unwrap_or("");
        let what = if ver.is_empty() { "TLS".to_string() } else { format!("TLS {ver}") };
        let to = if sni.is_empty() { "the server".to_string() } else { sni.clone() };
        set("tls", "encrypted", format!("Standard HTTPS encryption ({what}) to {to}. Nobody on the way, Kestryl included, can read the contents.{}", if matches!(ver, "1.0" | "1.1" | "old") { " This is an outdated TLS version." } else { "" }));
        v["sni"] = json!(sni);
        v["alpn"] = json!(alpn);
        v["tls"] = json!(ver);
        return v;
    }
    if starts(o, "SSH-") || starts(i, "SSH-") {
        set("ssh", "encrypted", "An SSH session: encrypted remote command line or file transfer.".into());
        return v;
    }
    if METHODS.iter().any(|m| starts(o, m)) || starts(i, "HTTP/1.") {
        set("http", "plain", "Not encrypted: plain HTTP. Anyone on the network path can read and change this. What was sent is shown below exactly as sent (only login headers and cookies are blanked).".into());
        v["text_out"] = json!(text(o, 3000));
        v["text_in"] = json!(text(i, 1500));
        return v;
    }
    if starts(i, "220") || has(o, "EHLO ") || has(o, "HELO ") || has(o, "USER ") {
        let smtp = has(o, "EHLO ") || has(o, "HELO ") || has(o, "MAIL FROM");
        let tls = has(o, "STARTTLS") || has(o, "AUTH TLS");
        let kind = if smtp { "smtp" } else { "ftp" };
        let what = if smtp { "Email (SMTP)" } else { "FTP file transfer" };
        if tls {
            set(kind, "encrypted", format!("{what}: it switched to encryption (STARTTLS) after the greeting, so only the first commands are readable."));
        } else {
            set(kind, "plain", format!("Not encrypted: {what}. Anyone on the network path can read it. What was sent is shown below exactly as sent; only the login to the server itself is blanked."));
        }
        v["text_out"] = json!(text(o, 3000));
        v["text_in"] = json!(text(i, 1200));
        return v;
    }
    if starts(i, "+OK") || starts(i, "* OK") {
        set("mail", "plain", "Not encrypted: reading email (POP3/IMAP) without TLS. Shown below; only the login to the server itself is blanked.".into());
        v["text_out"] = json!(text(o, 2000));
        v["text_in"] = json!(text(i, 1200));
        return v;
    }
    let sample = if o.is_empty() { i } else { o };
    if entropy_bytes(&sample[..sample.len().min(4096)]) > 7.2 && sample.len() >= 64 {
        set("custom", "custom", "Not a standard protocol, and the data looks random: it is encrypted or compressed in the program's own way (not HTTPS). Normal apps rarely do this over TCP; remote-access trojans and malware control channels often do.".into());
        v["hex"] = json!(hex(sample, 128));
    } else if printable(sample) > 0.85 {
        set("text", "plain", "Not a standard protocol, but readable text, so not encrypted. Shown below.".into());
        v["text_out"] = json!(text(o, 3000));
        v["text_in"] = json!(text(i, 1500));
    } else {
        set("unknown", "unknown", "An unknown binary protocol (not standard encryption, not plain text). Sample bytes below.".into());
        v["hex"] = json!(hex(sample, 128));
    }
    v
}

/// Groups packets into conversations with `target` and judges each one.
pub fn analyze(target: IpAddr, port: Option<u16>, secs: u64, pkts: &[Pkt], demo: bool) -> Value {
    let mut convs: Vec<Conv> = Vec::new();
    let mut idx: HashMap<(bool, u16, u16), usize> = HashMap::new();
    let mut total = 0u32;
    for p in pkts {
        let Some(s) = decode(p) else { continue };
        let out = s.dst == target;
        if !out && s.src != target {
            continue;
        }
        let (lport, rport) = if out { (s.sport, s.dport) } else { (s.dport, s.sport) };
        if port.is_some_and(|pp| pp != rport && pp != lport) {
            continue;
        }
        let k = (s.tcp, lport, rport);
        let i = *idx.entry(k).or_insert_with(|| {
            convs.push(Conv { tcp: s.tcp, lport, rport, ..Default::default() });
            convs.len() - 1
        });
        let c = &mut convs[i];
        // the same segment can be logged on more than one adapter layer
        if s.tcp && !s.payload.is_empty() && !c.seen.insert((out, s.seq, s.payload.len())) {
            continue;
        }
        total += 1;
        c.packets += 1;
        let pl = s.payload;
        if out {
            c.out_bytes += pl.len() as u64;
            if c.first_out.is_empty() && !pl.is_empty() {
                c.first_out = pl[..pl.len().min(2048)].to_vec();
            }
            if c.out.len() < KEEP {
                c.out.extend_from_slice(&pl[..pl.len().min(KEEP - c.out.len())]);
            }
            if !s.tcp && (rport == 53 || lport == 53) {
                if let Some(n) = dns_qname(pl) {
                    if !c.names.contains(&n) && c.names.len() < 50 {
                        c.names.push(n);
                    }
                }
            }
        } else {
            c.in_bytes += pl.len() as u64;
            if c.inn.len() < KEEP {
                c.inn.extend_from_slice(&pl[..pl.len().min(KEEP - c.inn.len())]);
            }
        }
    }
    let mut list: Vec<Value> = convs.iter().map(judge).collect();
    let rank = |v: &Value| match v["verdict"].as_str() {
        Some("plain") => 0,
        Some("custom") => 1,
        Some("unknown") => 2,
        Some("encrypted") => 3,
        _ => 4,
    };
    list.sort_by_key(|v| (rank(v), std::cmp::Reverse(v["out"].as_u64().unwrap_or(0))));
    let verdict = list.first().map(|v| v["verdict"].as_str().unwrap_or("empty").to_string()).unwrap_or_else(|| "empty".into());
    let (o, i) = convs.iter().fold((0u64, 0u64), |a, c| (a.0 + c.out_bytes, a.1 + c.in_bytes));
    let summary = match verdict.as_str() {
        "empty" if total == 0 => "Nothing was captured. The program may not have sent anything during the capture: use it while Peek runs, or capture longer.".to_string(),
        "empty" => "Connections were made, but no data went through during the capture.".to_string(),
        "plain" => "Some of this traffic is NOT encrypted: its contents are shown below.".to_string(),
        "custom" => "This traffic uses its own encryption instead of a standard one. Its contents can't be read; that alone is unusual for normal apps.".to_string(),
        "unknown" => "This traffic uses an unknown protocol. Sample bytes are shown below.".to_string(),
        _ => "All of this traffic uses standard encryption. Its contents can't be read; the server names show where it really goes.".to_string(),
    };
    json!({ "ip": target.to_string(), "port": port, "secs": secs, "packets": total, "out": o, "in": i,
            "verdict": verdict, "summary": summary, "convs": list, "demo": demo })
}

// ---------------------------------------------------------------- test data / demo

/// An Ethernet + IPv4 + TCP frame (for tests and the --simulate demo).
pub fn tcp_frame(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 12];
    f.extend_from_slice(&0x0800u16.to_be_bytes());
    let total = (20 + 20 + payload.len()) as u16;
    f.extend_from_slice(&[0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 6, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&seq.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0, 0, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

/// A minimal TLS 1.3 ClientHello with a server name and ALPN.
pub fn client_hello_bytes(sni: &str) -> Vec<u8> {
    let mut ext = Vec::new();
    let n = sni.as_bytes();
    ext.extend_from_slice(&0u16.to_be_bytes());
    ext.extend_from_slice(&((n.len() + 5) as u16).to_be_bytes());
    ext.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
    ext.push(0);
    ext.extend_from_slice(&(n.len() as u16).to_be_bytes());
    ext.extend_from_slice(n);
    ext.extend_from_slice(&[0, 16, 0, 5, 0, 3, 2, b'h', b'2']);
    let mut hs = vec![3, 3];
    hs.extend_from_slice(&[7u8; 32]);
    hs.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
    hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ext);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&((hs.len() + 4) as u16).to_be_bytes());
    rec.extend_from_slice(&[1, 0, (hs.len() >> 8) as u8, hs.len() as u8]);
    rec.extend_from_slice(&hs);
    rec
}

fn server_hello_13() -> Vec<u8> {
    let mut hs = vec![3, 3];
    hs.extend_from_slice(&[9u8; 32]);
    hs.extend_from_slice(&[0, 0x13, 0x01, 0]);
    let ext = [0u8, 43, 0, 2, 3, 4];
    hs.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ext);
    let mut rec = vec![0x16, 3, 3];
    rec.extend_from_slice(&((hs.len() + 4) as u16).to_be_bytes());
    rec.extend_from_slice(&[2, 0, (hs.len() >> 8) as u8, hs.len() as u8]);
    rec.extend_from_slice(&hs);
    rec
}

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// --simulate: a made-up capture that fits the demo program at this address.
pub fn demo(ip: &str, port: Option<u16>) -> Value {
    let me = [192, 168, 1, 10];
    let addr: IpAddr = ip.parse().unwrap_or(IpAddr::from([203, 0, 113, 50]));
    let them = match norm_ip(addr) {
        IpAddr::V4(v) => v.octets(),
        _ => [203, 0, 113, 50],
    };
    let rport = port.unwrap_or(443);
    let mut pk = Vec::new();
    let mut add = |out: bool, seq: u32, data: &[u8]| {
        let f = if out { tcp_frame(me, them, 50200, rport, seq, data) } else { tcp_frame(them, me, rport, 50200, seq, data) };
        pk.push(Pkt { link: 1, data: f });
    };
    match rport {
        587 | 25 => {
            add(false, 1, b"220 smtp.mail-relay.example ESMTP ready\r\n");
            add(true, 1, b"EHLO DESKTOP-4F2K\r\nAUTH LOGIN\r\nbGFiNDJAbWFpbC1yZWxheS5leGFtcGxl\r\nc2VjcmV0MTIz\r\n");
            add(true, 40, b"MAIL FROM:<lab42@mail-relay.example>\r\nRCPT TO:<drop.box77@mail-relay.example>\r\nDATA\r\n");
            add(true, 140, crate::detect::rules().demo_mail.as_bytes());
        }
        4444 | 1337 | 5552 => {
            add(true, 1, &noise(900, 7));
            add(false, 1, &noise(300, 11));
        }
        _ => {
            let host = match ip {
                "203.0.113.5" => "transfer.sh",
                "203.0.113.60" => "api.storage-sync.net",
                "203.0.113.70" => "relay-7f3a.net.anydesk.com",
                "203.0.113.21" => "api.telegram.org",
                _ => "www.google.com",
            };
            let ch = client_hello_bytes(host);
            add(true, 1, &ch);
            add(false, 1, &server_hello_13());
            add(true, 1 + ch.len() as u32, &[0x17, 3, 3, 0, 200]);
            add(true, 6 + ch.len() as u32, &noise(1400, 5));
        }
    }
    analyze(addr, port, 20, &pk, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut b = Vec::new();
        let block = |b: &mut Vec<u8>, t: u32, body: &[u8]| {
            let mut body = body.to_vec();
            while body.len() % 4 != 0 {
                body.push(0);
            }
            let len = (body.len() + 12) as u32;
            b.extend_from_slice(&t.to_le_bytes());
            b.extend_from_slice(&len.to_le_bytes());
            b.extend_from_slice(&body);
            b.extend_from_slice(&len.to_le_bytes());
        };
        block(&mut b, 0x0A0D0D0A, &[0x4D, 0x3C, 0x2B, 0x1A, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        block(&mut b, 1, &[1, 0, 0, 0, 0, 0, 0, 0]);
        for f in frames {
            let mut e = Vec::new();
            e.extend_from_slice(&0u32.to_le_bytes());
            e.extend_from_slice(&[0; 8]);
            e.extend_from_slice(&(f.len() as u32).to_le_bytes());
            e.extend_from_slice(&(f.len() as u32).to_le_bytes());
            e.extend_from_slice(f);
            block(&mut b, 6, &e);
        }
        b
    }

    const ME: [u8; 4] = [192, 168, 1, 10];
    const SRV: [u8; 4] = [203, 0, 113, 9];

    #[test]
    fn tls_split_hello_gives_server_name() {
        let ch = client_hello_bytes("files.example.net");
        let (a, b) = ch.split_at(30);
        let frames = vec![
            tcp_frame(ME, SRV, 50000, 443, 1, a),
            tcp_frame(ME, SRV, 50000, 443, 1 + a.len() as u32, b),
            tcp_frame(ME, SRV, 50000, 443, 1 + a.len() as u32, b), // same segment logged twice
            tcp_frame(SRV, ME, 443, 50000, 1, &server_hello_13()),
        ];
        let pk = parse_pcapng(&pcapng(&frames));
        assert_eq!(pk.len(), 4);
        let v = analyze("203.0.113.9".parse().unwrap(), Some(443), 10, &pk, false);
        assert_eq!(v["verdict"], "encrypted");
        assert_eq!(v["convs"][0]["sni"], "files.example.net");
        assert_eq!(v["convs"][0]["tls"], "1.3");
        assert_eq!(v["convs"][0]["alpn"], "h2");
        assert_eq!(v["packets"], 3, "duplicate segment dropped");
    }

    #[test]
    fn plain_http_ftp_and_custom() {
        let frames = vec![
            tcp_frame(ME, SRV, 50001, 80, 1, b"POST /upload HTTP/1.1\r\nHost: drop.example\r\nAuthorization: Basic dXNlcjpwYXNz\r\nCookie: sid=abc\r\n\r\nuser=a&data=secret"),
            tcp_frame(SRV, ME, 21, 50002, 1, b"220 FTP ready\r\n"),
            tcp_frame(ME, SRV, 50002, 21, 1, b"USER demo\r\nPASS secret123\r\nSTOR report.txt\r\n"),
            tcp_frame(ME, SRV, 50003, 4444, 1, &noise(1000, 3)),
        ];
        let v = analyze("203.0.113.9".parse().unwrap(), None, 10, &parse_pcapng(&pcapng(&frames)), false);
        assert_eq!(v["verdict"], "plain");
        let by = |k: &str| v["convs"].as_array().unwrap().iter().find(|c| c["kind"] == k).cloned().unwrap();
        let http = by("http");
        let t = http["text_out"].as_str().unwrap();
        assert!(t.contains("POST /upload") && t.contains("data=secret"), "{t}");
        assert!(!t.contains("dXNlcjpwYXNz") && !t.contains("sid=abc"), "auth and cookie hidden: {t}");
        let ftp = by("ftp")["text_out"].as_str().unwrap().to_string();
        assert!(ftp.contains("STOR report.txt") && !ftp.contains("secret123"), "{ftp}");
        let smtp = text(b"EHLO x\r\nAUTH LOGIN\r\ndXNlcg==\r\ncGFzcw==\r\nMAIL FROM:<a@b>\r\n", 500);
        assert!(!smtp.contains("dXNlcg==") && !smtp.contains("cGFzcw==") && smtp.contains("MAIL FROM"), "{smtp}");
        assert_eq!(by("custom")["rport"], 4444);
    }

    #[test]
    fn demo_results() {
        assert_eq!(demo("203.0.113.80", Some(587))["verdict"], "plain");
        assert_eq!(demo("198.51.100.7", Some(4444))["verdict"], "custom");
        let v = demo("203.0.113.60", Some(443));
        assert_eq!(v["convs"][0]["sni"], "api.storage-sync.net");
    }
}
