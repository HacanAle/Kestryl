//! HTTPS decryption sessions: see what one chosen program really sends inside its encrypted
//! (HTTPS) connections, for a few minutes, protected so nobody can switch it on quietly.
//!
//! How it works: Kestryl runs a small proxy on 127.0.0.1 and points Windows' proxy setting
//! at it. For the one program you picked, it ends the encryption at the proxy with a
//! certificate from a temporary certificate authority, records each request, and encrypts
//! it again towards the real server (whose certificate is checked as usual). Every other
//! program's connections pass through untouched, still encrypted end to end.
//!
//! Protection:
//! - a decryption password (stored only as an Argon2id hash), asked for every session, with
//!   a lock-out after repeated wrong tries; administrator rights as well;
//! - the certificate authority is made fresh in memory for each session, so its private key
//!   never touches the disk and is gone when the session ends; the certificate is trusted by
//!   Windows only during the session, and removed (and the proxy setting restored) at the
//!   end, on quit, or at the next start after a crash;
//! - one program only, at most 30 minutes, a red banner while it runs, and every session is
//!   written to the alert history;
//! - what was seen stays in memory only; passwords, cookies and tokens are hidden unless the
//!   password is typed again.
//! Programs that pin their own certificate (banking apps, some updaters) refuse the
//! temporary certificate; Kestryl then lets their later connections through undecrypted.

use crate::engine::{lock, Shared};
use crate::util::*;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const SUBJECT: &str = "Kestryl temporary HTTPS inspection";
pub const MAX_MIN: u64 = 30;
const BODY_KEEP: usize = 64 * 1024;
const LOG_MAX: usize = 400;
const FAILS_BEFORE_LOCK: u32 = 5;
const LOCK_MS: u64 = 10 * 60_000;

// ------------------------------------------------------------------ password

pub fn hash_password(pw: &str) -> Result<String, String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default().hash_password(pw.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| e.to_string())
}

pub fn verify_hash(hash: &str, pw: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(hash).is_ok_and(|h| argon2::Argon2::default().verify_password(pw.as_bytes(), &h).is_ok())
}

/// Saved decryption settings (config.json "decrypt").
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct Cfg {
    /// Argon2id hash of the decryption password ("" = not set up yet).
    pub hash: String,
    pub fails: u32,
    pub locked_until: u64,
    /// Proxy settings to put back, kept while a session runs (survives a crash).
    pub restore: Option<ProxyBackup>,
    /// Thumbprint of the temporary certificate while a session runs.
    pub tp: String,
}

/// Checks the password against the saved hash, counting failures. Ok(()) or a message.
pub fn check_password(c: &mut Cfg, pw: &str, now: u64) -> Result<(), String> {
    if c.hash.is_empty() {
        return Err("Set a decryption password first.".into());
    }
    if c.locked_until > now {
        return Err(format!("Too many wrong passwords. Try again in {} minutes.", (c.locked_until - now).div_ceil(60_000)));
    }
    if verify_hash(&c.hash, pw) {
        c.fails = 0;
        return Ok(());
    }
    c.fails += 1;
    if c.fails >= FAILS_BEFORE_LOCK {
        c.fails = 0;
        c.locked_until = now + LOCK_MS;
        return Err("Wrong password. Decryption is locked for 10 minutes.".into());
    }
    Err(format!("Wrong password ({} tr{} left before a 10-minute lock).", FAILS_BEFORE_LOCK - c.fails, if FAILS_BEFORE_LOCK - c.fails == 1 { "y" } else { "ies" }))
}

pub fn password_rules(pw: &str) -> Result<(), String> {
    if pw.chars().count() < 8 {
        return Err("Use at least 8 characters.".into());
    }
    if pw.chars().all(|c| c.is_ascii_digit()) {
        return Err("Use letters as well as digits.".into());
    }
    Ok(())
}

// ------------------------------------------------------------------ shared state

/// The running session, as the UI and the engine see it.
#[derive(Serialize, Clone, Debug, Default)]
pub struct Info {
    pub id: u64,
    /// Lower-case path of the program being decrypted.
    pub exe: String,
    pub name: String,
    pub start: u64,
    pub until: u64,
    pub port: u16,
    pub tp: String,
    pub sim: bool,
}

struct Live {
    info: Info,
    stop: tokio::sync::watch::Sender<bool>,
}

static LIVE: Mutex<Option<Live>> = Mutex::new(None);
static LOG: Mutex<VecDeque<Entry>> = Mutex::new(VecDeque::new());
static SEQ: AtomicU64 = AtomicU64::new(0);
/// Local port of each connection the proxy opened to a real server -> (program it is for,
/// time it closed or 0). The kernel trace sees those connections as Kestryl's; this puts
/// their bytes back on the program they belong to.
static PORTS: Mutex<Option<HashMap<u16, (u32, u64)>>> = Mutex::new(None);

fn locked<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The program a proxy connection (by Kestryl's local port) really belongs to.
pub fn client_of(lport: u16) -> Option<u32> {
    if lport == 0 {
        return None;
    }
    locked(&PORTS).as_ref()?.get(&lport).map(|x| x.0)
}

fn port_open(lport: u16, pid: u32) {
    let now = now_ms();
    let mut g = locked(&PORTS);
    let m = g.get_or_insert_with(HashMap::new);
    m.retain(|_, (_, closed)| *closed == 0 || *closed + 60_000 > now);
    m.insert(lport, (pid, 0));
}

fn port_closed(lport: u16) {
    if let Some(m) = locked(&PORTS).as_mut() {
        if let Some(e) = m.get_mut(&lport) {
            e.1 = now_ms();
        }
    }
}

pub fn current() -> Option<Info> {
    locked(&LIVE).as_ref().map(|l| l.info.clone())
}

// ------------------------------------------------------------------ recorded requests

#[derive(Clone, Debug, Default)]
pub struct Entry {
    pub id: u64,
    pub t: u64,
    pub pid: u32,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub size: u64,
    pub done: bool,
    pub status: u16,
    pub resp_type: String,
    pub resp_size: u64,
    /// Not a request: what happened to a connection (refused certificate, ...).
    pub note: String,
}

fn push_entry(e: Entry) -> u64 {
    let id = SEQ.fetch_add(1, Ordering::Relaxed) + 1;
    let mut g = locked(&LOG);
    g.push_back(Entry { id, ..e });
    while g.len() > LOG_MAX {
        g.pop_front();
    }
    id
}

fn with_entry(id: u64, f: impl FnOnce(&mut Entry)) {
    if let Some(e) = locked(&LOG).iter_mut().rev().find(|e| e.id == id) {
        f(e);
    }
}

pub fn clear_log() {
    locked(&LOG).clear();
}

fn sensitive(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    ["pass", "pwd", "token", "secret", "auth", "session", "cookie", "apikey", "api_key", "api-key", "otp", "cvv", "cvc", "card", "ssn", "credential", "bearer", "signature"]
        .iter()
        .any(|w| n.contains(w))
        || n == "key"
        || n == "pin"
        || n.ends_with("_key")
        || n.ends_with("-key")
}

fn hidden(v: &str) -> String {
    format!("hidden ({} characters)", v.chars().count())
}

fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => match (hex(b[i + 1]), hex(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h * 16 + l);
                    i += 2;
                }
                _ => out.push(b'%'),
            },
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// "a=1&password=x" -> lines "a = 1", "password = hidden (1 characters)"; (text, hidden count).
fn form_lines(q: &str, reveal: bool) -> (String, usize) {
    let mut n = 0;
    let lines: Vec<String> = q
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            let (k, v) = (url_decode(k), url_decode(v));
            if !reveal && sensitive(&k) && !v.is_empty() {
                n += 1;
                format!("{k} = {}", hidden(&v))
            } else {
                format!("{k} = {v}")
            }
        })
        .collect();
    (lines.join("\n"), n)
}

fn mask_json(v: &mut Value, reveal: bool, n: &mut usize) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if !reveal && sensitive(k) && (x.is_string() || x.is_number()) {
                    *n += 1;
                    let s = x.as_str().map(String::from).unwrap_or_else(|| x.to_string());
                    *x = Value::String(hidden(&s));
                } else {
                    mask_json(x, reveal, n);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| mask_json(x, reveal, n)),
        _ => {}
    }
}

fn header<'a>(h: &'a [(String, String)], name: &str) -> &'a str {
    h.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str()).unwrap_or("")
}

/// What a request body is, in words: (kind, text to show, hidden values).
fn describe_body(e: &Entry, reveal: bool) -> (String, String, usize) {
    if e.size == 0 {
        return ("empty".into(), String::new(), 0);
    }
    let ctype = header(&e.headers, "content-type").to_ascii_lowercase();
    let enc = header(&e.headers, "content-encoding").to_ascii_lowercase();
    let mut body = e.body.clone();
    let mut note = String::new();
    if enc.contains("gzip") {
        let mut s = Vec::new();
        use std::io::Read;
        if flate2::read::GzDecoder::new(&body[..]).read_to_end(&mut s).is_ok() || !s.is_empty() {
            body = s;
            note = "(sent gzip-compressed, shown unpacked) ".into();
        }
    } else if !enc.is_empty() && enc != "identity" {
        return ("compressed".into(), format!("Sent {}-compressed, {}; Kestryl cannot unpack this format.", enc, fmt_bytes(e.size)), 0);
    }
    let cut = if (e.size as usize) > body.len() { format!("\n… ({} of {} shown)", fmt_bytes(body.len() as u64), fmt_bytes(e.size)) } else { String::new() };
    if ctype.contains("x-www-form-urlencoded") {
        let (t, n) = form_lines(&String::from_utf8_lossy(&body), reveal);
        return ("form".into(), format!("{note}{t}{cut}"), n);
    }
    if ctype.contains("json") || body.first().is_some_and(|c| *c == b'{' || *c == b'[') {
        if let Ok(mut v) = serde_json::from_slice::<Value>(&body) {
            let mut n = 0;
            mask_json(&mut v, reveal, &mut n);
            let t: String = serde_json::to_string_pretty(&v).unwrap_or_default().chars().take(16_000).collect();
            return ("json".into(), format!("{note}{t}{cut}"), n);
        }
    }
    if ctype.contains("multipart/form-data") {
        let boundary = ctype.split("boundary=").nth(1).unwrap_or("").trim_matches('"').to_string();
        let raw = header(&e.headers, "content-type");
        let b = raw.split("boundary=").nth(1).unwrap_or(&boundary).trim_matches('"');
        let text = String::from_utf8_lossy(&body);
        let mut parts = Vec::new();
        for p in text.split(&format!("--{b}")).filter(|p| p.contains("Content-Disposition") || p.contains("content-disposition")) {
            let (h, v) = p.split_once("\r\n\r\n").unwrap_or((p, ""));
            let v = v.trim_end_matches("\r\n");
            let field = |k: &str| h.split(';').find_map(|x| x.trim().strip_prefix(&format!("{k}=")).map(|s| s.trim_matches('"').to_string())).unwrap_or_default();
            let (name, file) = (field("name"), field("filename"));
            let printable = v.chars().take(400).all(|c| !c.is_control() || c == '\n' || c == '\r' || c == '\t');
            parts.push(if !file.is_empty() {
                format!("FILE \"{file}\" (field {name}, {})", fmt_bytes(v.len() as u64))
            } else if !reveal && sensitive(&name) {
                format!("{name} = {}", hidden(v))
            } else if printable {
                format!("{name} = {}", v.chars().take(400).collect::<String>())
            } else {
                format!("{name} = binary, {}", fmt_bytes(v.len() as u64))
            });
        }
        return ("files".into(), format!("{note}{}{cut}", parts.join("\n")), 0);
    }
    let printable = body.iter().take(4096).filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace() || **c >= 0x80).count();
    let sample = body.len().min(4096).max(1);
    if printable * 100 / sample >= 92 {
        let t: String = String::from_utf8_lossy(&body).chars().take(16_000).collect();
        return ("text".into(), format!("{note}{t}{cut}"), 0);
    }
    let ent = {
        let mut c = [0u32; 256];
        for b in &body {
            c[*b as usize] += 1;
        }
        let n = body.len() as f64;
        c.iter().filter(|x| **x > 0).map(|&x| -(x as f64 / n) * (x as f64 / n).log2()).sum::<f64>()
    };
    let hex: String = body.iter().take(48).map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    let what = if ent > 7.5 { "random-looking: compressed or encrypted again inside HTTPS" } else { "binary data" };
    ("binary".into(), format!("{} of {what}.\nFirst bytes: {hex}", fmt_bytes(e.size)), 0)
}

fn view(e: &Entry, reveal: bool) -> Value {
    let mut hidden_n = 0;
    let headers: Vec<Value> = e
        .headers
        .iter()
        .map(|(k, v)| {
            let secret = matches!(k.to_ascii_lowercase().as_str(), "authorization" | "proxy-authorization" | "cookie" | "x-api-key" | "x-auth-token" | "x-access-token" | "x-csrf-token" | "x-xsrf-token")
                || sensitive(k);
            if secret && !reveal {
                hidden_n += 1;
                json!([k, hidden(v)])
            } else {
                json!([k, v])
            }
        })
        .collect();
    let (path, query) = e.path.split_once('?').unwrap_or((&e.path, ""));
    let (q, qn) = form_lines(query, reveal);
    let (kind, body, bn) = describe_body(e, reveal);
    json!({
        "id": e.id, "t": e.t, "pid": e.pid, "name": e.name, "host": e.host, "port": e.port, "tls": e.tls,
        "method": e.method, "path": path, "query": q, "headers": headers, "size": e.size, "done": e.done,
        "kind": kind, "body": body, "status": e.status, "resp_type": e.resp_type, "resp_size": e.resp_size,
        "note": e.note, "hidden": hidden_n + qn + bn,
    })
}

/// Recorded requests, newest first. `reveal` shows passwords, cookies and tokens.
pub fn entries(reveal: bool) -> Value {
    Value::Array(locked(&LOG).iter().rev().map(|e| view(e, reveal)).collect())
}

// ------------------------------------------------------------------ passive HTTP/1.1 reader

#[derive(Clone, Copy, Debug, PartialEq)]
enum St {
    Head,
    Fixed(u64),
    ChunkSize,
    ChunkData(u64),
    ChunkEnd,
    Trailer,
    UntilClose,
    Opaque,
}

#[derive(Debug, PartialEq)]
pub enum Ev {
    Head(String, Vec<(String, String)>),
    Body(Vec<u8>),
    End,
}

/// Reads a copy of one direction of an HTTP/1.1 connection and reports message heads and
/// bodies. Never alters or holds up the traffic; anything it cannot parse it stops reading.
pub struct Reader {
    buf: Vec<u8>,
    st: St,
    req: bool,
    /// Request methods, in order, so a response knows whether it has a body (HEAD).
    methods: Arc<Mutex<VecDeque<String>>>,
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

impl Reader {
    pub fn new(req: bool, methods: Arc<Mutex<VecDeque<String>>>) -> Self {
        Reader { buf: Vec::new(), st: St::Head, req, methods }
    }

    pub fn opaque(&mut self) {
        self.st = St::Opaque;
        self.buf.clear();
    }

    pub fn feed(&mut self, data: &[u8], out: &mut Vec<Ev>) {
        if self.st == St::Opaque {
            return;
        }
        if self.st == St::UntilClose {
            out.push(Ev::Body(data.to_vec()));
            return;
        }
        self.buf.extend_from_slice(data);
        let mut i = 0;
        loop {
            let rest = &self.buf[i..];
            match self.st {
                St::Head => {
                    let Some(end) = find(rest, b"\r\n\r\n") else {
                        if rest.len() > 64 * 1024 {
                            self.opaque();
                            return;
                        }
                        break;
                    };
                    let head = String::from_utf8_lossy(&rest[..end]).into_owned();
                    i += end + 4;
                    let mut lines = head.split("\r\n");
                    let first = lines.next().unwrap_or("").to_string();
                    let headers: Vec<(String, String)> =
                        lines.filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect();
                    let te = header(&headers, "transfer-encoding").to_ascii_lowercase().contains("chunked");
                    let cl: Option<u64> = header(&headers, "content-length").parse().ok();
                    let next = if self.req {
                        let method = first.split(' ').next().unwrap_or("").to_string();
                        locked(&self.methods).push_back(method);
                        if te {
                            St::ChunkSize
                        } else {
                            match cl {
                                Some(n) if n > 0 => St::Fixed(n),
                                _ => St::Head,
                            }
                        }
                    } else {
                        let status: u16 = first.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                        if (100..200).contains(&status) && status != 101 {
                            out.push(Ev::Head(first, headers));
                            continue; // informational: the real response follows
                        }
                        let method = locked(&self.methods).pop_front().unwrap_or_default();
                        if status == 101 {
                            St::Opaque
                        } else if method == "HEAD" || status == 204 || status == 304 {
                            St::Head
                        } else if te {
                            St::ChunkSize
                        } else {
                            match cl {
                                Some(0) => St::Head,
                                Some(n) => St::Fixed(n),
                                None => St::UntilClose,
                            }
                        }
                    };
                    out.push(Ev::Head(first, headers));
                    if next == St::Head {
                        out.push(Ev::End);
                    }
                    self.st = next;
                    if matches!(next, St::Opaque | St::UntilClose) {
                        let tail = self.buf[i..].to_vec();
                        self.buf.clear();
                        if next == St::UntilClose && !tail.is_empty() {
                            out.push(Ev::Body(tail));
                        }
                        return;
                    }
                }
                St::Fixed(n) | St::ChunkData(n) => {
                    if rest.is_empty() {
                        break;
                    }
                    let take = (n as usize).min(rest.len());
                    out.push(Ev::Body(rest[..take].to_vec()));
                    i += take;
                    let left = n - take as u64;
                    self.st = match (self.st, left) {
                        (St::Fixed(_), 0) => {
                            out.push(Ev::End);
                            St::Head
                        }
                        (St::Fixed(_), l) => St::Fixed(l),
                        (_, 0) => St::ChunkEnd,
                        (_, l) => St::ChunkData(l),
                    };
                }
                St::ChunkSize => {
                    let Some(end) = find(rest, b"\r\n") else { break };
                    let line = String::from_utf8_lossy(&rest[..end]).into_owned();
                    i += end + 2;
                    match u64::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16) {
                        Ok(0) => self.st = St::Trailer,
                        Ok(n) => self.st = St::ChunkData(n),
                        Err(_) => {
                            self.opaque();
                            return;
                        }
                    }
                }
                St::ChunkEnd => {
                    if rest.len() < 2 {
                        break;
                    }
                    i += 2;
                    self.st = St::ChunkSize;
                }
                St::Trailer => {
                    let Some(end) = find(rest, b"\r\n") else { break };
                    i += end + 2;
                    if end == 0 {
                        out.push(Ev::End);
                        self.st = St::Head;
                    }
                }
                St::UntilClose | St::Opaque => break,
            }
        }
        self.buf.drain(..i);
    }
}

// ------------------------------------------------------------------ certificates

pub struct Ca {
    cert: rcgen::Certificate,
    key: rcgen::KeyPair,
    leaf_key: rcgen::KeyPair,
    pub der: Vec<u8>,
    days: (i64, i64),
    cache: Mutex<HashMap<String, Arc<rustls::ServerConfig>>>,
}

/// Days since 1970 -> (year, month, day) for a certificate date.
fn ymd(day: i64) -> (i32, u8, u8) {
    let (y, m, d) = civil_from_days(day);
    (y as i32, m as u8, d as u8)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

impl Ca {
    /// A new certificate authority, valid from yesterday to the day after the session ends.
    pub fn new(minutes: u64) -> Result<Ca, String> {
        use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
        let today = (now_ms() / 86_400_000) as i64;
        let days = (today - 1, today + 2 + (minutes as i64) / 1440);
        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut p = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, SUBJECT);
        dn.push(DnType::OrganizationName, "Kestryl (this PC only, deleted after the session)");
        p.distinguished_name = dn;
        p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let (a, b) = (ymd(days.0), ymd(days.1));
        p.not_before = rcgen::date_time_ymd(a.0, a.1, a.2);
        p.not_after = rcgen::date_time_ymd(b.0, b.1, b.2);
        let cert = p.self_signed(&key).map_err(|e| e.to_string())?;
        let der = cert.der().to_vec();
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        Ok(Ca { cert, key, leaf_key, der, days, cache: Mutex::new(HashMap::new()) })
    }

    #[cfg(test)]
    pub fn pem(&self) -> String {
        self.cert.pem()
    }

    /// TLS settings for pretending to be `host` to the program (HTTP/1.1 only, so the
    /// requests can be read).
    fn server_config(&self, host: &str) -> Result<Arc<rustls::ServerConfig>, String> {
        if let Some(c) = locked(&self.cache).get(host) {
            return Ok(c.clone());
        }
        use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyUsagePurpose};
        let mut p = CertificateParams::new(vec![host.to_string()]).map_err(|e| e.to_string())?;
        p.distinguished_name.push(DnType::CommonName, host);
        let (a, b) = (ymd(self.days.0), ymd(self.days.1));
        p.not_before = rcgen::date_time_ymd(a.0, a.1, a.2);
        p.not_after = rcgen::date_time_ymd(b.0, b.1, b.2);
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = p.signed_by(&self.leaf_key, &self.cert, &self.key).map_err(|e| e.to_string())?;
        let chain = vec![leaf.der().clone(), CertificateDer::from(self.der.clone())];
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(|e| e.to_string())?;
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let cfg = Arc::new(cfg);
        locked(&self.cache).insert(host.to_string(), cfg.clone());
        Ok(cfg)
    }
}

/// TLS settings towards the real servers: Windows' trusted roots (minus our own), HTTP/1.1.
fn client_config(own_der: &[u8]) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_native_certs::load_native_certs().certs {
        if c.as_ref() != own_der {
            let _ = roots.add(c);
        }
    }
    if roots.is_empty() {
        return Err("could not read Windows' trusted certificates".into());
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

// ------------------------------------------------------------------ Windows: trust store, proxy

/// Adds the certificate to the computer's trusted roots (administrator) without a temp file
/// (an elevated program reading a file others can write could be tricked). Returns its thumbprint.
fn install_ca(der: &[u8]) -> Result<String, String> {
    let tp = run_ps(&format!(
        "$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String('{}'))\n$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')\n$s.Open('ReadWrite'); $s.Add($c); $s.Close(); $c.Thumbprint",
        b64(der)
    ))?;
    if tp.len() != 40 {
        return Err(format!("unexpected answer from the certificate store: {tp}"));
    }
    Ok(tp)
}

/// Removes the session certificate (by thumbprint) and any leftover Kestryl inspection certificate.
pub fn remove_ca(tp: &str) -> Result<(), String> {
    run_ps(&format!(
        "$s = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','LocalMachine')\n$s.Open('ReadWrite')\n@($s.Certificates | Where-Object {{ $_.Thumbprint -eq {} -or $_.Subject -like '*CN={}*' }}) | ForEach-Object {{ $s.Remove($_) }}\n$s.Close()",
        ps_quote(tp),
        SUBJECT
    ))
    .map(|_| ())
}

/// The user's proxy settings before a session, put back afterwards exactly.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct ProxyBackup {
    pub enable: Option<u32>,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub pac: Option<String>,
    pub blob: Option<Vec<u8>>,
}

const INET: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

#[cfg(windows)]
fn proxy_snapshot() -> ProxyBackup {
    use winreg::enums::HKEY_CURRENT_USER;
    let hk = winreg::RegKey::predef(HKEY_CURRENT_USER);
    let Ok(k) = hk.open_subkey(INET) else { return ProxyBackup::default() };
    ProxyBackup {
        enable: k.get_value("ProxyEnable").ok(),
        server: k.get_value("ProxyServer").ok(),
        bypass: k.get_value("ProxyOverride").ok(),
        pac: k.get_value("AutoConfigURL").ok(),
        blob: k.open_subkey("Connections").ok().and_then(|c| c.get_raw_value("DefaultConnectionSettings").ok()).map(|v| v.bytes.to_vec()),
    }
}

#[cfg(windows)]
fn notify_proxy() {
    use windows::Win32::Networking::WinInet::{InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED};
    unsafe {
        let _ = InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0);
        let _ = InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

/// Points Windows' proxy (the one browsers and most apps follow) at 127.0.0.1:port.
#[cfg(windows)]
fn set_proxy(port: u16, old: &ProxyBackup) -> Result<(), String> {
    use windows::core::PWSTR;
    use windows::Win32::Networking::WinInet::*;
    let server = format!("127.0.0.1:{port}");
    let bypass = match old.bypass.as_deref().filter(|b| !b.is_empty()) {
        Some(b) if b.contains("<local>") => b.to_string(),
        Some(b) => format!("{b};<local>"),
        None => "<local>".to_string(),
    };
    let mut srv: Vec<u16> = server.encode_utf16().chain(Some(0)).collect();
    let mut byp: Vec<u16> = bypass.encode_utf16().chain(Some(0)).collect();
    let mut opts = [
        INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_FLAGS, Value: INTERNET_PER_CONN_OPTIONW_0 { dwValue: PROXY_TYPE_PROXY | PROXY_TYPE_DIRECT } },
        INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_PROXY_SERVER, Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: PWSTR(srv.as_mut_ptr()) } },
        INTERNET_PER_CONN_OPTIONW { dwOption: INTERNET_PER_CONN_PROXY_BYPASS, Value: INTERNET_PER_CONN_OPTIONW_0 { pszValue: PWSTR(byp.as_mut_ptr()) } },
    ];
    let list = INTERNET_PER_CONN_OPTION_LISTW {
        dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
        pszConnection: PWSTR::null(),
        dwOptionCount: opts.len() as u32,
        dwOptionError: 0,
        pOptions: opts.as_mut_ptr(),
    };
    unsafe {
        InternetSetOptionW(None, INTERNET_OPTION_PER_CONNECTION_OPTION, Some(&list as *const _ as *const _), list.dwSize).map_err(|e| format!("could not set the proxy: {e}"))?;
    }
    notify_proxy();
    Ok(())
}

/// Puts the proxy settings back exactly as they were.
#[cfg(windows)]
pub fn restore_proxy(b: &ProxyBackup) {
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    let hk = winreg::RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(k) = hk.open_subkey_with_flags(INET, KEY_READ | KEY_WRITE) {
        let _ = match b.enable {
            Some(v) => k.set_value("ProxyEnable", &v),
            None => k.delete_value("ProxyEnable"),
        };
        for (name, v) in [("ProxyServer", &b.server), ("ProxyOverride", &b.bypass), ("AutoConfigURL", &b.pac)] {
            let _ = match v {
                Some(s) => k.set_value(name, s),
                None => k.delete_value(name),
            };
        }
        if let (Some(blob), Ok(c)) = (&b.blob, k.open_subkey_with_flags("Connections", KEY_READ | KEY_WRITE)) {
            let _ = c.set_raw_value("DefaultConnectionSettings", &winreg::RegValue { bytes: blob.clone().into(), vtype: RegType::REG_BINARY });
        }
    }
    notify_proxy();
}

#[cfg(not(windows))]
fn proxy_snapshot() -> ProxyBackup {
    ProxyBackup::default()
}
#[cfg(not(windows))]
fn set_proxy(_port: u16, _old: &ProxyBackup) -> Result<(), String> {
    Err("Windows only".into())
}
#[cfg(not(windows))]
pub fn restore_proxy(_b: &ProxyBackup) {}

// ------------------------------------------------------------------ the proxy

pub struct Ctx {
    /// Lower-case path of the one program to decrypt.
    pub exe: String,
    pub port: u16,
    pub ca: Ca,
    client: Arc<rustls::ClientConfig>,
    /// Hosts whose program refused the temporary certificate: passed through from then on.
    pinned: Mutex<HashSet<String>>,
}

/// The program behind a connection to the proxy, from the TCP table.
fn client_pid(peer_port: u16, proxy_port: u16) -> u32 {
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
    let Ok(socks) = get_sockets_info(AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6, ProtocolFlags::TCP) else { return 0 };
    socks
        .into_iter()
        .find_map(|s| match &s.protocol_socket_info {
            ProtocolSocketInfo::Tcp(t) if t.local_port == peer_port && t.remote_port == proxy_port => s.associated_pids.first().copied(),
            _ => None,
        })
        .unwrap_or(0)
}

async fn read_head(s: &mut TcpStream) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = find(&buf, b"\r\n\r\n") {
            let rest = buf.split_off(i + 4);
            return Ok((buf, rest));
        }
        if buf.len() > 32 * 1024 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
    }
}

fn split_host_port(s: &str, default: u16) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest.split_once(']').unwrap_or((rest, ""));
        return (h.to_string(), p.trim_start_matches(':').parse().unwrap_or(default));
    }
    match s.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') => (h.to_string(), p.parse().unwrap_or(default)),
        _ => (s.to_string(), default),
    }
}

/// While alive, the upstream connection on this local port counts as the client program's.
struct PortGuard(u16);

impl Drop for PortGuard {
    fn drop(&mut self) {
        port_closed(self.0);
    }
}

async fn connect_up(host: &str, port: u16, pid: u32) -> std::io::Result<(TcpStream, PortGuard)> {
    let s = tokio::time::timeout(Duration::from_secs(15), TcpStream::connect((host, port))).await.map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let lport = s.local_addr().map(|a| a.port()).unwrap_or(0);
    port_open(lport, pid);
    let _ = s.set_nodelay(true);
    Ok((s, PortGuard(lport)))
}

fn apply(evs: Vec<Ev>, req: bool, ids: &Mutex<VecDeque<u64>>, cur: &mut u64, base: &Entry) {
    for ev in evs {
        match ev {
            Ev::Head(first, headers) if req => {
                let mut it = first.splitn(3, ' ');
                let method = it.next().unwrap_or("").to_string();
                let mut path = it.next().unwrap_or("").to_string();
                // absolute form (plain HTTP through a proxy) -> path only
                if let Some(x) = path.strip_prefix("http://").or_else(|| path.strip_prefix("https://")) {
                    path = x.find('/').map(|i| x[i..].to_string()).unwrap_or_else(|| "/".into());
                }
                let host = match header(&headers, "host") {
                    "" => base.host.clone(),
                    h => split_host_port(h, base.port).0,
                };
                *cur = push_entry(Entry { t: now_ms(), method, path, headers, host, ..base.clone() });
                locked(ids).push_back(*cur);
            }
            Ev::Head(first, headers) => {
                let status: u16 = first.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                if (100..200).contains(&status) && status != 101 {
                    continue;
                }
                *cur = locked(ids).pop_front().unwrap_or(0);
                let ct = header(&headers, "content-type").split(';').next().unwrap_or("").to_string();
                with_entry(*cur, |e| {
                    e.status = status;
                    e.resp_type = ct;
                });
            }
            Ev::Body(b) => with_entry(*cur, |e| {
                if req {
                    e.size += b.len() as u64;
                    let room = BODY_KEEP.saturating_sub(e.body.len());
                    e.body.extend_from_slice(&b[..room.min(b.len())]);
                } else {
                    e.resp_size += b.len() as u64;
                }
            }),
            Ev::End if req => with_entry(*cur, |e| e.done = true),
            Ev::End => {}
        }
    }
}

/// Relays both directions unchanged and reads a copy of each.
async fn relay<C, S>(client: C, server: S, base: Entry, first: Vec<u8>)
where
    C: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut sr, mut sw) = tokio::io::split(server);
    let methods = Arc::new(Mutex::new(VecDeque::new()));
    let ids = Arc::new(Mutex::new(VecDeque::new()));
    let up = async {
        let mut r = Reader::new(true, methods.clone());
        let mut cur = 0u64;
        let mut buf = vec![0u8; 16 * 1024];
        let mut evs = Vec::new();
        if !first.is_empty() {
            r.feed(&first, &mut evs);
            apply(std::mem::take(&mut evs), true, &ids, &mut cur, &base);
            if sw.write_all(&first).await.is_err() {
                return;
            }
        }
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if sw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            r.feed(&buf[..n], &mut evs);
            apply(std::mem::take(&mut evs), true, &ids, &mut cur, &base);
        }
        let _ = sw.shutdown().await;
    };
    let down = async {
        let mut r = Reader::new(false, methods.clone());
        let mut cur = 0u64;
        let mut buf = vec![0u8; 16 * 1024];
        let mut evs = Vec::new();
        loop {
            let n = match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if cw.write_all(&buf[..n]).await.is_err() {
                break;
            }
            r.feed(&buf[..n], &mut evs);
            apply(std::mem::take(&mut evs), false, &ids, &mut cur, &base);
        }
        let _ = cw.shutdown().await;
    };
    tokio::join!(up, down);
}

async fn tunnel(mut client: TcpStream, mut up: TcpStream, first: &[u8]) {
    if !first.is_empty() && up.write_all(first).await.is_err() {
        return;
    }
    let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
}

async fn handle(mut client: TcpStream, peer: SocketAddr, ctx: Arc<Ctx>) {
    let _ = client.set_nodelay(true);
    let Ok((head, rest)) = read_head(&mut client).await else { return };
    let text = String::from_utf8_lossy(&head).into_owned();
    let first = text.lines().next().unwrap_or("").to_string();
    let mut parts = first.split(' ');
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let pid = client_pid(peer.port(), ctx.port);
    let exe = exe_of_pid(pid);
    let name = exe.rsplit('\\').next().unwrap_or("").to_string();
    let chosen = !exe.is_empty() && exe.to_lowercase() == ctx.exe;
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443);
        let (up, _guard) = match connect_up(&host, port, pid).await {
            Ok(u) => u,
            Err(_) => {
                let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                return;
            }
        };
        if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
            return;
        }
        let pinned = locked(&ctx.pinned).contains(&host);
        if !chosen || pinned {
            return tunnel(client, up, &rest).await;
        }
        let base = Entry { pid, name: name.clone(), host: host.clone(), port, tls: true, ..Default::default() };
        // The real server first: its certificate must be valid, exactly as for the program.
        let sn = match ServerName::try_from(host.clone()) {
            Ok(s) => s,
            Err(_) => return tunnel(client, up, &rest).await,
        };
        let server = match tokio_rustls::TlsConnector::from(ctx.client.clone()).connect(sn, up).await {
            Ok(s) => s,
            Err(e) => {
                push_entry(Entry { t: now_ms(), note: format!("The server's certificate is not valid ({e}). Kestryl refused the connection, as {name} itself would have."), ..base });
                return;
            }
        };
        let sc = match ctx.ca.server_config(&host) {
            Ok(c) => c,
            Err(_) => return,
        };
        let tls = match tokio_rustls::TlsAcceptor::from(sc).accept(client).await {
            Ok(t) => t,
            Err(_) => {
                locked(&ctx.pinned).insert(host.clone());
                push_entry(Entry {
                    t: now_ms(),
                    note: format!("{name} refused Kestryl's temporary certificate for {host} (it checks its own). Its next connections to {host} are let through without decryption."),
                    ..base
                });
                return;
            }
        };
        relay(tls, server, base, Vec::new()).await;
    } else {
        // Plain HTTP through the proxy: "GET http://host/path HTTP/1.1".
        let Some(rest_url) = target.strip_prefix("http://") else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
            return;
        };
        let (hp, path) = match rest_url.find('/') {
            Some(i) => (&rest_url[..i], &rest_url[i..]),
            None => (rest_url, "/"),
        };
        let (host, port) = split_host_port(hp, 80);
        let Ok((mut up, _guard)) = connect_up(&host, port, pid).await else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
            return;
        };
        // One request per connection, so a reused proxy connection can't reach the wrong site.
        let mut out = format!("{method} {path} {}\r\n", parts.next().unwrap_or("HTTP/1.1"));
        for l in text.split("\r\n").skip(1).filter(|l| !l.is_empty()) {
            let k = l.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
            if !matches!(k.as_str(), "connection" | "proxy-connection" | "keep-alive" | "proxy-authorization") {
                out += l;
                out += "\r\n";
            }
        }
        out += "Connection: close\r\n\r\n";
        let mut first = out.into_bytes();
        first.extend_from_slice(&rest);
        if !chosen {
            let _ = up.write_all(&first).await;
            let _ = tokio::io::copy_bidirectional(&mut client, &mut up).await;
            return;
        }
        let base = Entry { pid, name, host, port, tls: false, ..Default::default() };
        relay(client, up, base, first).await;
    }
}

async fn serve(listener: std::net::TcpListener, ctx: Arc<Ctx>, mut stop: tokio::sync::watch::Receiver<bool>) {
    let _ = listener.set_nonblocking(true);
    let Ok(listener) = tokio::net::TcpListener::from_std(listener) else { return };
    loop {
        tokio::select! {
            r = listener.accept() => {
                if let Ok((sock, peer)) = r {
                    // Only programs on this PC: the listener is on 127.0.0.1 anyway.
                    if peer.ip().is_loopback() {
                        tokio::spawn(handle(sock, peer, ctx.clone()));
                    }
                }
            }
            _ = stop.changed() => break,
        }
    }
}

/// Starts the proxy on its own runtime thread; returns the stop switch.
fn launch(listener: std::net::TcpListener, ctx: Arc<Ctx>) -> Result<tokio::sync::watch::Sender<bool>, String> {
    let (tx, rx) = tokio::sync::watch::channel(false);
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).thread_name("kestryl-decrypt").enable_all().build().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        rt.block_on(serve(listener, ctx, rx));
        rt.shutdown_timeout(Duration::from_secs(1));
    });
    Ok(tx)
}

// ------------------------------------------------------------------ sessions

/// Starts a session for one program (administrator; the caller checked the password).
pub fn start(eng: &Shared, exe: &str, name: &str, minutes: u64) -> Result<Info, String> {
    if locked(&LIVE).is_some() {
        return Err("A decryption session is already running.".into());
    }
    let minutes = minutes.clamp(1, MAX_MIN);
    let now = now_ms();
    let exe_l = exe.to_lowercase();
    let sim = lock(eng).sim;
    let id = now;
    if sim {
        let info = Info { id, exe: exe_l, name: name.into(), start: now, until: now + minutes * 60_000, port: 0, tp: String::new(), sim: true };
        let (tx, _) = tokio::sync::watch::channel(false);
        *locked(&LIVE) = Some(Live { info: info.clone(), stop: tx });
        demo_entries(name);
        return Ok(info);
    }
    if exe.is_empty() || !std::path::Path::new(exe).is_file() {
        return Err("Pick a program that is a file on this PC.".into());
    }
    let ca = Ca::new(minutes)?;
    let client = client_config(&ca.der)?;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| format!("could not open the local proxy: {e}"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let backup = proxy_snapshot();
    // Saved first: if Kestryl dies mid-session, the next start puts everything back.
    let cfg = {
        let mut e = lock(eng);
        e.cfg.decrypt.restore = Some(backup.clone());
        e.take_cfg_for_save()
    };
    crate::config::save(&cfg);
    let tp = match install_ca(&ca.der) {
        Ok(tp) => tp,
        Err(err) => {
            finish_cleanup(eng, "");
            return Err(format!("Windows refused the temporary certificate: {err}"));
        }
    };
    {
        let mut e = lock(eng);
        e.cfg.decrypt.tp = tp.clone();
        crate::config::save(&e.take_cfg_for_save());
    }
    if let Err(err) = set_proxy(port, &backup) {
        finish_cleanup(eng, &tp);
        return Err(err);
    }
    let ctx = Arc::new(Ctx { exe: exe_l.clone(), port, ca, client, pinned: Mutex::new(HashSet::new()) });
    let stop = match launch(listener, ctx) {
        Ok(s) => s,
        Err(err) => {
            finish_cleanup(eng, &tp);
            return Err(err);
        }
    };
    let info = Info { id, exe: exe_l, name: name.into(), start: now, until: now + minutes * 60_000, port, tp, sim: false };
    *locked(&LIVE) = Some(Live { info: info.clone(), stop });
    clear_log();
    // Its open connections were made before the proxy: close them so it reconnects through it.
    let pids = lock(eng).pids_of(exe);
    for p in pids {
        crate::firewall::drop_tcp(Some(p), None);
    }
    Ok(info)
}

/// Proxy back, certificate gone, saved state cleared.
fn finish_cleanup(eng: &Shared, tp: &str) {
    let backup = lock(eng).cfg.decrypt.restore.clone();
    if let Some(b) = &backup {
        restore_proxy(b);
    }
    if let Err(e) = remove_ca(tp) {
        log(&format!("removing the inspection certificate failed: {e}"));
    }
    let cfg = {
        let mut e = lock(eng);
        e.cfg.decrypt.restore = None;
        e.cfg.decrypt.tp.clear();
        e.take_cfg_for_save()
    };
    if !lock(eng).sim {
        crate::config::save(&cfg);
    }
}

/// Ends the running session (if any). Returns the session that ended.
pub fn stop(eng: &Shared) -> Option<Info> {
    let live = locked(&LIVE).take()?;
    let _ = live.stop.send(true);
    if !live.info.sim {
        finish_cleanup(eng, &live.info.tp);
    }
    Some(live.info)
}

/// At start: a session cut short by a crash or power loss is cleaned up.
pub fn cleanup_after_crash(eng: &Shared) {
    let (pending, tp) = {
        let e = lock(eng);
        (e.cfg.decrypt.restore.is_some() || !e.cfg.decrypt.tp.is_empty(), e.cfg.decrypt.tp.clone())
    };
    if pending {
        log("an HTTPS decryption session did not end normally: restoring the proxy and removing its certificate");
        finish_cleanup(eng, &tp);
    }
}

fn demo_entries(name: &str) {
    clear_log();
    let now = now_ms();
    let h = |v: &[(&str, &str)]| v.iter().map(|(k, x)| (k.to_string(), x.to_string())).collect::<Vec<_>>();
    let b = |s: &str| s.as_bytes().to_vec();
    let base = Entry { pid: 90001, name: name.into(), tls: true, port: 443, done: true, ..Default::default() };
    let boundary = "----kestryl-demo";
    let multi = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"hwid\"\r\n\r\nDESKTOP-4F7Q-90A1\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"Chrome_passwords.txt\"\r\nContent-Type: text/plain\r\n\r\n{}\r\n--{boundary}--\r\n", "x".repeat(18_000));
    for e in [
        Entry { t: now - 9000, host: "api.ipify.org".into(), method: "GET".into(), path: "/?format=json".into(), headers: h(&[("Host", "api.ipify.org"), ("User-Agent", "Go-http-client/1.1")]), status: 200, resp_type: "application/json".into(), resp_size: 21, ..base.clone() },
        Entry {
            t: now - 6000, host: "transfer.sh".into(), method: "POST".into(), path: "/upload".into(),
            headers: h(&[("Host", "transfer.sh"), ("Content-Type", &format!("multipart/form-data; boundary={boundary}")), ("Authorization", "Bearer 9f2c1d0e7a")]),
            body: b(&multi), size: multi.len() as u64, status: 200, resp_type: "text/plain".into(), resp_size: 46, ..base.clone()
        },
        Entry {
            t: now - 3000, host: "api.telegram.org".into(), method: "POST".into(), path: "/bot7712:AAH-demo/sendMessage".into(),
            headers: h(&[("Host", "api.telegram.org"), ("Content-Type", "application/x-www-form-urlencoded")]),
            body: b("chat_id=55120&text=New+victim%3A+DESKTOP-4F7Q+%2F+Japan&password=Summer2026!"), size: 76, status: 200, resp_type: "application/json".into(), resp_size: 310, ..base.clone()
        },
        Entry { t: now - 1000, host: "www.google.com".into(), note: format!("{name} refused Kestryl's temporary certificate for www.google.com (it checks its own). Its next connections to www.google.com are let through without decryption."), ..base.clone() },
    ] {
        push_entry(e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(chunks: &[&[u8]], req: bool, methods: &Arc<Mutex<VecDeque<String>>>) -> Vec<Ev> {
        let mut r = Reader::new(req, methods.clone());
        let mut out = Vec::new();
        for c in chunks {
            r.feed(c, &mut out);
        }
        out
    }

    #[test]
    fn reads_requests_and_responses() {
        let m = Arc::new(Mutex::new(VecDeque::new()));
        // Two requests on one connection, the first split mid-head and mid-body.
        let ev = run(&[b"POST /a HTTP/1.1\r\nHost: x\r\nContent-Len", b"gth: 5\r\n\r\nhel", b"loGET /b HTTP/1.1\r\nHost: x\r\n\r\n"], true, &m);
        let heads: Vec<&String> = ev.iter().filter_map(|e| if let Ev::Head(f, _) = e { Some(f) } else { None }).collect();
        assert_eq!(heads, vec!["POST /a HTTP/1.1", "GET /b HTTP/1.1"]);
        let body: Vec<u8> = ev.iter().flat_map(|e| if let Ev::Body(b) = e { b.clone() } else { vec![] }).collect();
        assert_eq!(body, b"hello");
        assert_eq!(ev.iter().filter(|e| **e == Ev::End).count(), 2);
        // Responses: chunked, then one to a HEAD-like request without a body.
        m.lock().unwrap().clear();
        m.lock().unwrap().extend(["POST".to_string(), "HEAD".to_string()]);
        let ev = run(&[b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n"], false, &m);
        let body: Vec<u8> = ev.iter().flat_map(|e| if let Ev::Body(b) = e { b.clone() } else { vec![] }).collect();
        assert_eq!(body, b"Wikipedia");
        assert_eq!(ev.iter().filter(|e| **e == Ev::End).count(), 2, "HEAD response has no body despite Content-Length");
    }

    #[test]
    fn hides_secrets_until_revealed() {
        let e = Entry {
            method: "POST".into(),
            path: "/login?next=/home&token=abc".into(),
            headers: vec![("Content-Type".into(), "application/x-www-form-urlencoded".into()), ("Cookie".into(), "sid=1".into())],
            body: b"user=alice&password=hunter2".to_vec(),
            size: 27,
            ..Default::default()
        };
        let v = view(&e, false);
        assert!(v["body"].as_str().unwrap().contains("user = alice"));
        assert!(v["body"].as_str().unwrap().contains("password = hidden (7 characters)"));
        assert!(v["query"].as_str().unwrap().contains("token = hidden"));
        assert_eq!(v["hidden"], 3, "cookie, token, password");
        let r = view(&e, true);
        assert!(r["body"].as_str().unwrap().contains("password = hunter2"));
        let j = Entry { headers: vec![("Content-Type".into(), "application/json".into())], body: br#"{"email":"a@b.c","auth":{"pin":"1234"}}"#.to_vec(), size: 40, ..Default::default() };
        let v = view(&j, false);
        assert!(v["body"].as_str().unwrap().contains("\"pin\": \"hidden (4 characters)\""));
        assert!(v["body"].as_str().unwrap().contains("a@b.c"));
    }

    #[test]
    fn password_and_lockout() {
        let mut c = Cfg { hash: hash_password("correct horse").unwrap(), ..Default::default() };
        assert!(check_password(&mut c, "correct horse", 1000).is_ok());
        for _ in 0..4 {
            assert!(check_password(&mut c, "nope", 1000).is_err());
        }
        assert!(check_password(&mut c, "nope", 1000).unwrap_err().contains("locked"));
        assert!(check_password(&mut c, "correct horse", 2000).unwrap_err().contains("Try again"), "locked even with the right one");
        assert!(check_password(&mut c, "correct horse", 1000 + LOCK_MS + 1).is_ok());
        assert!(password_rules("12345678").is_err() && password_rules("short").is_err() && password_rules("long enough").is_ok());
    }

    #[test]
    fn certificates() {
        let ca = Ca::new(10).unwrap();
        assert!(ca.pem().contains("BEGIN CERTIFICATE"));
        let c = ca.server_config("example.com").unwrap();
        assert_eq!(c.alpn_protocols, vec![b"http/1.1".to_vec()]);
        assert!(ca.server_config("203.0.113.9").is_ok(), "IP address hosts work too");
        assert_eq!(split_host_port("example.com:8443", 443), ("example.com".into(), 8443));
        assert_eq!(split_host_port("[2001:db8::1]:443", 80), ("2001:db8::1".into(), 443));
    }

    /// Run by hand (NOT elevated is fine: no certificate is installed and the proxy setting is
    /// not touched). Starts the proxy for this test program only, sends a form through it with
    /// a TLS client that trusts only the session certificate (as a browser would during a
    /// session), and checks the form was read and the real answer came back. The test program
    /// is a Kestryl build, so a running Kestryl monitor does not alert on it.
    #[test]
    #[ignore]
    fn live_decrypts_a_program() {
        let ca = Ca::new(5).unwrap();
        let ca_der = ca.der.clone();
        let upstream = client_config(&ca.der).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let me = std::env::current_exe().unwrap().display().to_string().to_lowercase();
        let ctx = Arc::new(Ctx { exe: me, port, ca, client: upstream, pinned: Mutex::new(HashSet::new()) });
        let stop = launch(listener, ctx).unwrap();
        clear_log();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca_der)).unwrap();
        let cc = rustls::ClientConfig::builder_with_provider(provider()).with_safe_default_protocol_versions().unwrap().with_root_certificates(roots).with_no_client_auth();
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let answer = rt.block_on(async move {
            let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            s.write_all(b"CONNECT postman-echo.com:443 HTTP/1.1\r\nHost: postman-echo.com:443\r\n\r\n").await.unwrap();
            let mut head = [0u8; 39];
            s.read_exact(&mut head).await.unwrap();
            assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(cc)).connect(ServerName::try_from("postman-echo.com").unwrap(), s).await.expect("our certificate was accepted");
            let body = "user=alice&password=hunter2";
            let req = format!("POST /post HTTP/1.1\r\nHost: postman-echo.com\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut out = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(20), tls.read_to_end(&mut out)).await;
            String::from_utf8_lossy(&out).into_owned()
        });
        println!("answer: {}", answer.chars().take(300).collect::<String>());
        std::thread::sleep(Duration::from_millis(300));
        let log = entries(false);
        println!("{}", serde_json::to_string_pretty(&log).unwrap());
        let _ = stop.send(true);
        assert!(answer.starts_with("HTTP/1.1 200"), "the real server answered through the proxy");
        assert!(answer.contains("hunter2"), "postman-echo echoes the form back");
        let e = log.as_array().unwrap().iter().find(|e| e["method"] == "POST").expect("the POST was recorded");
        assert_eq!(e["host"], "postman-echo.com");
        assert!(e["body"].as_str().unwrap().contains("user = alice"));
        assert!(e["body"].as_str().unwrap().contains("password = hidden"));
        assert_eq!(e["status"], 200);
        assert!(e["resp_size"].as_u64().unwrap() > 0);
    }
}
