//! In-memory model of who talks to whom, fed by ETW / socket polling / file events,
//! plus alerting, the daily history and the security-check results.

use crate::config::Config;
use crate::detect::{self, Class, Finding, FlowFacts, ProcView, Script, Secret};
use crate::{away, clip};
use crate::history::{self, Day};
use crate::intel::{self, Intel};
use crate::scan::Scan;
use crate::sensors::{self, Use};
use crate::util::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

pub type Shared = Arc<Mutex<Engine>>;

pub fn lock(e: &Shared) -> MutexGuard<'_, Engine> {
    e.lock().unwrap_or_else(|p| p.into_inner())
}

const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
const MAX_FLOWS: usize = 8000;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub pid: u32,
    pub proto: Proto,
    pub ip: IpAddr,
    /// Remote port; for incoming connections the local port the other device connected to.
    pub port: u16,
    /// Another device opened this connection to this PC.
    pub inb: bool,
}

#[derive(Debug)]
pub struct Flow {
    pub out: u64,
    pub inb: u64,
    pub first: u64,
    pub last: u64,
    pub connects: VecDeque<u64>,
    pub open: bool,
    pub rate_out: u64,
    pub rate_in: u64,
    tick_out: u64,
    tick_in: u64,
    pub new_connect: bool,
    pub new_bytes: bool,
    /// Destination is a trusted IP/domain (never alerted).
    pub trusted: bool,
    /// Trusted and its "show traffic" switch is off: left out of every view and total.
    pub hidden: bool,
    /// A known-safe service (index into `safe::SERVICES`), when that feature is on.
    pub safe: Option<u8>,
    /// Bytes [out, in] already written to the daily history.
    hist: [u64; 2],
}

impl Flow {
    fn new(now: u64) -> Self {
        Flow {
            out: 0,
            inb: 0,
            first: now,
            last: now,
            connects: VecDeque::new(),
            open: false,
            rate_out: 0,
            rate_in: 0,
            tick_out: 0,
            tick_in: 0,
            new_connect: true, // first sighting is evaluated like a connect
            new_bytes: false,
            trusted: false,
            hidden: false,
            safe: None,
            hist: [0, 0],
        }
    }
}

/// The folder every Kestryl build of this copy lives in: for a dev build the project's
/// `target\` folder (debug and release builds side by side), otherwise the exe's folder.
fn own_root(own_exe: &str) -> String {
    if let Some(i) = own_exe.find("\\target\\") {
        return own_exe[..i + 8].to_string();
    }
    match own_exe.rfind('\\') {
        Some(i) => own_exe[..=i].to_string(),
        None => String::new(),
    }
}

/// Parsed form of `Config::trusted_dests`.
#[derive(Clone, Debug)]
pub enum TrustRule {
    Net((IpAddr, u8), bool),
    Domain(String, bool),
}

/// The known-safe service an address belongs to, if that feature and service are switched on.
fn safe_pick(s: &crate::safe::Safe, cfg: &Config, dns: &HashMap<IpAddr, String>, ip: &IpAddr) -> Option<u8> {
    if !cfg.safe_on {
        return None;
    }
    let i = s.lookup(ip, dns.get(ip).map(String::as_str))?;
    (!cfg.safe_off.iter().any(|o| o == crate::safe::SERVICES[i as usize].id)).then_some(i)
}

/// (trusted, hidden) for an address, using the IP rules and the name DNS gave it.
fn trust_for(rules: &[TrustRule], dns: &HashMap<IpAddr, String>, ip: &IpAddr) -> (bool, bool) {
    if rules.is_empty() {
        return (false, false);
    }
    let name = dns.get(ip);
    for r in rules {
        let (hit, show) = match r {
            TrustRule::Net(n, show) => (net_contains(n, ip), *show),
            TrustRule::Domain(d, show) => (name.is_some_and(|x| domain_is(x, d)), *show),
        };
        if hit {
            return (true, !show);
        }
    }
    (false, false)
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub cmd: String,
    pub parent: u32,
    pub parent_name: String,
    pub started: u64,
    pub exited: bool,
    /// When Kestryl saw the process gone (ms, 0 = running or not known). Windows reuses
    /// process ids, so a file open that arrives well after this came from a newer process.
    #[serde(skip)]
    pub gone: u64,
    pub sim: bool,
}

impl ProcInfo {
    pub fn exe_key(&self) -> String {
        if self.exe.is_empty() {
            self.name.to_lowercase()
        } else {
            self.exe.to_lowercase()
        }
    }
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct SigInfo {
    pub status: String,
    pub signer: String,
}

#[derive(Default, Debug)]
pub struct PStat {
    pub out: u64,
    pub inb: u64,
    pub rate_out: u64,
    pub rate_in: u64,
    tick_out: u64,
    tick_in: u64,
    inet_out: u64,
    inet_in: u64,
    tick_iout: u64,
    tick_iin: u64,
    /// Internet bytes (out, in) per second, last 60 s.
    win: VecDeque<(u64, u64)>,
    pub last: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct DnsEntry {
    pub t: u64,
    pub pid: u32,
    pub name: String,
    pub answers: Vec<String>,
    pub status: u32,
    pub flag: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Alert {
    pub id: u64,
    pub t: u64,
    pub last: u64,
    pub count: u32,
    pub sev: u8,
    pub rule: String,
    pub title: String,
    pub why: String,
    pub pid: u32,
    pub name: String,
    pub exe: String,
    pub signer: String,
    pub parent: String,
    pub cmd: String,
    pub ip: String,
    pub domain: String,
    pub port: u16,
    pub bytes_out: u64,
    pub read: bool,
    pub key: String,
    pub sim: bool,
    /// Files involved (passwords, cookies, documents...).
    pub files: Vec<String>,
    /// Windows services inside the process (svchost.exe).
    pub service: String,
    /// Not about one program: a Windows setting or Kestryl itself.
    pub system: bool,
    /// Where the program file came from ("downloaded from example.com").
    pub origin: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Listener {
    pub pid: u32,
    pub proto: Proto,
    pub addr: String,
    pub port: u16,
    pub exposed: bool,
}

#[derive(Clone, Debug, Serialize, Default)]
pub struct Adapter {
    pub name: String,
    pub mac: String,
    pub ips: Vec<String>,
    pub rx_rate: u64,
    pub tx_rate: u64,
    pub rx_total: u64,
    pub tx_total: u64,
}

#[derive(Default, Debug, Serialize, Clone)]
pub struct Stats {
    pub events: u64,
    pub dns_events: u64,
    pub parse_errors: u64,
    pub last_error: String,
    pub file_events: u64,
    pub file_hits: u64,
}

/// Is monitoring itself intact? Filled by the health check every 10 s.
#[derive(Default, Debug, Serialize, Clone)]
pub struct Health {
    /// ETW sessions alive (None = not checked / not expected).
    pub net: Option<bool>,
    pub files: Option<bool>,
    pub files_error: String,
    /// Events Windows dropped because the PC was too busy (both sessions).
    pub lost: u64,
    pub restarts: u32,
    pub blind: bool,
    pub checked: u64,
}

#[derive(Default, Clone)]
pub struct Dest {
    pub ip: String,
    pub domain: String,
    pub port: u16,
    pub bytes: u64,
}

struct DnsPending {
    t: u64,
    pid: u32,
    q: String,
    burst: bool,
    n: usize,
    /// The name is on a list of known malware servers.
    intel: Option<intel::Hit>,
}

/// A connection to a listed server, waiting for the process details: (pid, incoming, ip, domain, port, bytes out, list entry).
type IntelPending = (u32, bool, IpAddr, String, u16, u64, intel::Hit);

/// Events about a process can arrive this long (ms) after it exited; later ones with the same
/// process id belong to a newer process.
const REUSE_GAP: u64 = 3000;

/// A file open from the kernel file trace that matched a pattern; judged once the
/// process is known.
pub struct FileEvt {
    pub t: u64,
    pub pid: u32,
    pub path: String,
    pub secret: Option<Secret>,
    pub doc: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SecretHit {
    pub t: u64,
    pub kind: &'static str,
    pub label: &'static str,
    pub path: String,
    #[serde(skip)]
    base_out: u64,
    pub uploaded: bool,
}

/// Documents/photos one program opened within a few minutes.
struct DocWin {
    t0: u64,
    seen: HashSet<u64>,
    sample: Vec<String>,
    collected: u64,
    base_out: u64,
    reported: bool,
}

pub struct Engine {
    pub flows: HashMap<FlowKey, Flow>,
    pub procs: HashMap<u32, ProcInfo>,
    pub pstats: HashMap<u32, PStat>,
    pub sigs: HashMap<String, SigInfo>,
    pub dns: HashMap<IpAddr, String>,
    pub dns_log: VecDeque<DnsEntry>,
    dns_pids: HashSet<u32>,
    dns_pending: Vec<DnsPending>,
    burst: HashMap<(u32, String), VecDeque<(u64, String)>>,
    pub alerts: VecDeque<Alert>,
    seq: u64,
    pub notify: Vec<Alert>,
    pub cfg: Config,
    pub known: HashSet<String>,
    pub history: VecDeque<[u64; 2]>,
    pub up: u64,
    pub down: u64,
    pub adapters: Vec<Adapter>,
    pub local_ips: HashSet<IpAddr>,
    pub listeners: Vec<Listener>,
    /// TCP ports listening on a network-facing address: a connection on one of these is incoming.
    pub listen_ports: HashSet<u16>,
    /// (pid, remote ip, remote port, local port) of connections other devices opened.
    inbound_conns: HashSet<(u32, IpAddr, u16, u16)>,
    prev_open: HashSet<FlowKey>,
    first_poll: bool,
    pub totals: [u64; 2],
    pub stats: Stats,
    pub mode: String,
    pub elevated: bool,
    pub etw_error: String,
    pub sim: bool,
    /// Blocked domains whose IP list grew and needs a firewall refresh.
    pub fw_updates: Vec<String>,
    pub dirty_alerts: bool,
    pub dirty_cfg: bool,
    pub last_toast: Option<Alert>,
    /// Kestryl's own process and exe: their traffic (IP lookups) is shown but never judged,
    /// including a --simulate demo or a second copy of the same exe.
    pub own_pid: u32,
    pub own_exe: String,
    trust_rules: Vec<TrustRule>,
    /// Trusted programs whose file changed since they were trusted.
    pub trust_broken: HashSet<String>,
    pub file_pending: Vec<FileEvt>,
    pub secrets: HashMap<u32, Vec<SecretHit>>,
    docs: HashMap<u32, DocWin>,
    /// Windows services per process id (svchost.exe hosts many).
    pub services: HashMap<u32, Vec<String>>,
    /// Remote-control tools running right now: (pid, process name, product).
    pub remote_running: Vec<(u32, String, &'static str)>,
    pub today: Day,
    /// Finished days waiting to be saved (the date changed).
    pub done_days: Vec<Day>,
    /// Demo only: a made-up earlier day so the History tab has something to switch to.
    pub sim_days: Vec<Day>,
    pub hist_dirty: bool,
    /// Kestryl firewall rule ids last seen (None until the first look).
    fw_known: Option<HashSet<String>>,
    pub audit: Value,
    pub audit_t: u64,
    pub audit_error: String,
    pub health: Health,
    ticks: u64,
    /// Process starts from the kernel trace: pid -> (time, parent pid, exe path). Names
    /// programs that exit before they could be looked up (Docker's helpers, one-shot tools).
    pub proc_starts: HashMap<u32, (u64, u32, String)>,
    /// Exe paths that still need a signature check (picked up by the process loop).
    pub sig_queue: Vec<String>,
    /// The folder every Kestryl build of this copy lives in (dev builds: ...\target\).
    own_root: String,
    /// Pop-up guard: last pop-up per rule+program, and recent pop-up times.
    popped: HashMap<String, u64>,
    pop_log: VecDeque<u64>,
    /// Program blocks in Windows Firewall: exe key (lowercase) -> rule id.
    pub blocked_apps: HashMap<String, String>,
    /// IP / range blocks in Windows Firewall: (rule id, network).
    pub blocked_nets: Vec<(String, (IpAddr, u8))>,
    /// Connections seen moving data despite a block (pid, remote ip): the main loop
    /// closes them. A new firewall rule only stops new connections, and a blocked
    /// domain's new address is added to its rule a moment after the program used it.
    pub drops: Vec<(u32, IpAddr)>,
    dropped: HashMap<(u32, IpAddr), u64>,
    /// Lists of known malware servers (intel.rs), swapped in whole after each download.
    pub intel: Arc<Intel>,
    /// Known-safe services (Google, Microsoft 365, Windows Update, Apple).
    pub safe: Arc<crate::safe::Safe>,
    intel_pending: Vec<IntelPending>,
    /// Defender scans and hashes per exe key; paths waiting for their scan.
    pub scans: HashMap<String, Scan>,
    pub scan_queue: Vec<String>,
    /// Camera / microphone use as Windows records it, and what is on right now.
    pub sensor_uses: Vec<Use>,
    sensor_on: HashSet<(&'static str, String)>,
    /// When each program's camera / microphone pop-up was last shown (so a flickering
    /// on/off doesn't pop up again and again).
    sensor_popped: HashMap<(&'static str, String), u64>,
    /// Country and company of addresses (offline, geo.rs); swapped in whole after a download.
    pub geo: Arc<crate::geo::Geo>,
    /// This PC's country from Windows' region setting ("JP").
    pub home: String,
    /// "While you were away": the period in progress, internet bytes per process per minute
    /// for the last 15 minutes (to count from the last input, not from when it was noticed),
    /// and the finished reports.
    pub away: Option<away::Session>,
    minutes: VecDeque<(u64, HashMap<u32, (u64, u64)>)>,
    presence_t: u64,
    pub away_reports: VecDeque<away::Report>,
    pub away_dirty: bool,
    /// Last payment detail seen on the clipboard (clipboard guard), for 3 s.
    clip_last: Option<clip::Seen>,
    /// Where program files came from (Mark of the Web), per exe key.
    origins: HashMap<String, Value>,
}

impl Engine {
    pub fn new(cfg: Config, alerts: Vec<Alert>) -> Self {
        let seq = alerts.iter().map(|a| a.id).max().unwrap_or(0);
        // "pid 1234" entries came from programs that exited before they could be named.
        let known = cfg.known.iter().filter(|k| !k.starts_with("pid ")).cloned().collect();
        let (day, _) = local_day_hour();
        let own_exe = std::env::current_exe().map(|p| p.display().to_string().to_lowercase()).unwrap_or_default();
        let mut e = Engine {
            flows: HashMap::new(),
            procs: HashMap::new(),
            pstats: HashMap::new(),
            sigs: HashMap::new(),
            dns: HashMap::new(),
            dns_log: VecDeque::new(),
            dns_pids: HashSet::new(),
            dns_pending: Vec::new(),
            burst: HashMap::new(),
            alerts: alerts.into_iter().filter(|a| !a.sim).collect(),
            seq,
            notify: Vec::new(),
            cfg,
            known,
            history: VecDeque::new(),
            up: 0,
            down: 0,
            adapters: Vec::new(),
            local_ips: HashSet::new(),
            listeners: Vec::new(),
            listen_ports: HashSet::new(),
            inbound_conns: HashSet::new(),
            prev_open: HashSet::new(),
            first_poll: true,
            totals: [0, 0],
            stats: Stats::default(),
            mode: "starting".into(),
            elevated: false,
            etw_error: String::new(),
            sim: false,
            fw_updates: Vec::new(),
            dirty_alerts: false,
            dirty_cfg: false,
            last_toast: None,
            own_pid: std::process::id(),
            own_root: own_root(&own_exe),
            own_exe,
            trust_rules: Vec::new(),
            trust_broken: HashSet::new(),
            file_pending: Vec::new(),
            secrets: HashMap::new(),
            docs: HashMap::new(),
            services: HashMap::new(),
            remote_running: Vec::new(),
            today: Day::new(day),
            done_days: Vec::new(),
            sim_days: Vec::new(),
            hist_dirty: false,
            fw_known: None,
            audit: Value::Null,
            audit_t: 0,
            audit_error: String::new(),
            health: Health::default(),
            ticks: 0,
            proc_starts: HashMap::new(),
            sig_queue: Vec::new(),
            popped: HashMap::new(),
            pop_log: VecDeque::new(),
            blocked_apps: HashMap::new(),
            blocked_nets: Vec::new(),
            drops: Vec::new(),
            dropped: HashMap::new(),
            intel: Arc::new(Intel::default()),
            safe: Arc::new(crate::safe::from_texts("", "", "", [0, 0], &HashMap::new())),
            intel_pending: Vec::new(),
            scans: HashMap::new(),
            scan_queue: Vec::new(),
            sensor_uses: Vec::new(),
            sensor_on: HashSet::new(),
            sensor_popped: HashMap::new(),
            geo: Arc::new(crate::geo::Geo::default()),
            home: String::new(),
            away: None,
            minutes: VecDeque::new(),
            presence_t: 0,
            away_reports: VecDeque::new(),
            away_dirty: false,
            clip_last: None,
            origins: HashMap::new(),
        };
        e.rebuild_trust();
        // Alerts an older version raised about Kestryl itself.
        let keep: VecDeque<Alert> = e.alerts.iter().filter(|a| a.exe.is_empty() || !e.is_own_exe(&a.exe.to_lowercase())).cloned().collect();
        e.alerts = keep;
        e
    }

    /// Call after `cfg.trusted_dests` changes.
    pub fn rebuild_trust(&mut self) {
        self.trust_rules = self
            .cfg
            .trusted_dests
            .iter()
            .map(|t| match parse_net(&t.target) {
                Some(n) => TrustRule::Net(n, t.show),
                None => TrustRule::Domain(t.target.to_lowercase(), t.show),
            })
            .collect();
    }

    /// Drops addresses that never belong in a domain block (root and .com/.net name
    /// servers that slipped in from DNS referrals). Queues a firewall refresh if any did.
    pub fn clean_domain_blocks(&mut self) {
        for b in self.cfg.domain_blocks.iter_mut() {
            let n = b.ips.len();
            b.ips.retain(|i| i.parse::<IpAddr>().is_ok_and(|ip| !detect::is_dns_infra(&ip)));
            if b.ips.len() != n && !self.fw_updates.contains(&b.domain) {
                self.fw_updates.push(b.domain.clone());
                self.dirty_cfg = true;
            }
        }
    }

    /// Takes the program and IP blocks from a firewall rule list (`firewall::list`).
    pub fn set_blocks(&mut self, v: &Value) {
        self.blocked_apps.clear();
        self.blocked_nets.clear();
        for r in v["rules"].as_array().into_iter().flatten() {
            let (id, target) = (r["id"].as_str().unwrap_or(""), r["target"].as_str().unwrap_or(""));
            if r["enabled"].as_bool() == Some(false) || id.is_empty() {
                continue;
            }
            match r["kind"].as_str() {
                Some("app") => {
                    self.blocked_apps.insert(target.to_lowercase(), id.to_string());
                }
                Some("ip") => {
                    if let Some(n) = parse_net(target) {
                        self.blocked_nets.push((id.to_string(), n));
                    }
                }
                _ => {}
            }
        }
    }

    /// Running processes of this exe (to close their connections).
    pub fn pids_of(&self, exe: &str) -> Vec<u32> {
        let k = exe.to_lowercase();
        self.procs.values().filter(|p| !p.exited && p.exe_key() == k).map(|p| p.pid).collect()
    }

    /// Queues every connection that moved data in the last 2 s although its program,
    /// IP or domain is blocked. Each one at most every 2 s.
    fn enforce_blocks(&mut self, now: u64) {
        if self.sim || (self.blocked_apps.is_empty() && self.blocked_nets.is_empty() && self.cfg.domain_blocks.is_empty()) {
            return;
        }
        let dom: HashSet<IpAddr> =
            self.cfg.domain_blocks.iter().flat_map(|b| b.ips.iter().filter_map(|i| i.parse::<IpAddr>().ok())).map(norm_ip).collect();
        for (k, f) in &self.flows {
            if k.inb || f.last + 2000 < now || k.ip.is_loopback() {
                continue;
            }
            let app = self.procs.get(&k.pid).is_some_and(|p| self.blocked_apps.contains_key(&p.exe_key()));
            if !(app || dom.contains(&k.ip) || self.blocked_nets.iter().any(|(_, n)| net_contains(n, &k.ip))) {
                continue;
            }
            if self.dropped.get(&(k.pid, k.ip)).is_some_and(|t| t + 2000 > now) {
                continue;
            }
            self.dropped.insert((k.pid, k.ip), now);
            self.drops.push((k.pid, k.ip));
        }
        self.dropped.retain(|_, t| *t + 60_000 > now);
    }

    /// (trusted, hidden) for a DNS name (domain rules only).
    pub fn name_trust(&self, name: &str) -> (bool, bool) {
        for r in &self.trust_rules {
            if let TrustRule::Domain(d, show) = r {
                if domain_is(name, d) {
                    return (true, !show);
                }
            }
        }
        (false, false)
    }

    /// A program a trusted destination must not hide or silence: unsigned, in a temp or
    /// download folder, a script host or Windows tool, or not checked yet.
    fn untrusty_pid(&self, pid: u32) -> bool {
        match self.view(pid) {
            None => true,
            Some(v) => v.shady() || v.sig == "pending" || v.script != Script::None,
        }
    }

    fn ensure_flow(&mut self, now: u64, key: FlowKey) -> &mut Flow {
        if !self.flows.contains_key(&key) {
            let (mut trusted, mut hidden) = trust_for(&self.trust_rules, &self.dns, &key.ip);
            if trusted && self.untrusty_pid(key.pid) {
                (trusted, hidden) = (false, false);
            }
            let mut f = Flow::new(now);
            f.trusted = trusted;
            f.hidden = hidden;
            f.safe = safe_pick(&self.safe, &self.cfg, &self.dns, &key.ip);
            self.flows.insert(key, f);
        }
        self.flows.get_mut(&key).expect("just inserted")
    }

    pub fn is_local(&self, ip: &IpAddr) -> bool {
        self.local_ips.contains(&norm_ip(*ip))
    }

    /// Kestryl itself, or another build of this same copy (a debug build or the --simulate
    /// demo next to the release exe). Their IP-info lookups are Kestryl's, not a threat.
    pub fn is_own_exe(&self, k: &str) -> bool {
        if self.own_exe.is_empty() || k.is_empty() {
            return false;
        }
        let file = k.rsplit('\\').next().unwrap_or("");
        k == self.own_exe || (!self.own_root.is_empty() && k.starts_with(&self.own_root) && file.starts_with("kestryl") && file.ends_with(".exe"))
    }

    /// Kestryl's own work, never judged: this process, a program it started itself (its
    /// PowerShell checks, Defender scans, Packet Monitor), or another build of this copy.
    pub fn is_own_pid(&self, pid: u32) -> bool {
        if pid == self.own_pid {
            return true;
        }
        match self.procs.get(&pid) {
            Some(p) if p.sim => false,
            Some(p) => is_own_child(pid) || self.is_own_exe(&p.exe_key()),
            None => is_own_child(pid),
        }
    }

    /// Exe keys of Kestryl builds that are running now.
    fn own_keys(&self) -> HashSet<String> {
        let mut s: HashSet<String> = self.procs.values().map(|p| p.exe_key()).filter(|k| self.is_own_exe(k)).collect();
        if !self.own_exe.is_empty() {
            s.insert(self.own_exe.clone());
        }
        s
    }

    pub fn is_trusted(&self, exe_key: &str) -> bool {
        self.is_own_exe(exe_key) || (self.cfg.trusted.iter().any(|t| t == exe_key) && !self.trust_broken.contains(exe_key))
    }

    fn trusted_set(&self) -> HashSet<String> {
        let mut s: HashSet<String> = self.cfg.trusted.iter().filter(|t| !self.trust_broken.contains(*t)).cloned().collect();
        s.extend(self.own_keys());
        s
    }

    pub fn view(&self, pid: u32) -> Option<ProcView> {
        let info = self.procs.get(&pid)?;
        let name = info.name.to_lowercase();
        let exe_key = info.exe_key();
        let (sig, class) = if pid == 0 || pid == 4 {
            ("signed".to_string(), Class::System)
        } else {
            let class = detect::classify(&info.exe.to_lowercase());
            let sig = if info.exe.is_empty() {
                "unknown".to_string()
            } else {
                self.sigs.get(&exe_key).map(|s| s.status.clone()).unwrap_or_else(|| "pending".into())
            };
            (sig, class)
        };
        Some(ProcView {
            script: detect::script_kind(&name),
            browser: detect::is_browser(&name),
            name,
            exe_key,
            sig,
            class,
        })
    }

    // ---------------------------------------------------------------- ingest

    fn is_inbound(&self, pid: u32, ip: &IpAddr, rport: u16, lport: u16) -> bool {
        lport != 0 && (self.listen_ports.contains(&lport) || self.inbound_conns.contains(&(pid, *ip, rport, lport)))
    }

    /// Bytes of one packet. `port` is the remote port, `lport` the local one (0 = unknown).
    #[allow(clippy::too_many_arguments)]
    pub fn on_packet(&mut self, now: u64, pid: u32, proto: Proto, ip: IpAddr, port: u16, lport: u16, size: u64, outbound: bool) {
        let ip = norm_ip(ip);
        let sc = scope(&ip);
        if sc == Scope::Loopback {
            return;
        }
        let inb = proto == Proto::Tcp && self.is_inbound(pid, &ip, port, lport);
        let key = FlowKey { pid, proto, ip, port: if inb { lport } else { port }, inb };
        let f = self.ensure_flow(now, key);
        if outbound {
            f.out += size;
            f.new_bytes = true;
        } else {
            f.inb += size;
            if inb {
                f.new_bytes = true;
            }
        }
        f.last = now;
        if f.hidden {
            return; // trusted and not shown: not counted in any total
        }
        let p = self.pstats.entry(pid).or_default();
        p.last = now;
        if outbound {
            p.out += size;
            self.totals[0] += size;
            if sc == Scope::Internet {
                p.inet_out += size;
            }
        } else {
            p.inb += size;
            self.totals[1] += size;
            if sc == Scope::Internet {
                p.inet_in += size;
            }
        }
        if sc == Scope::Internet {
            if let Some(a) = self.away.as_mut() {
                let x = a.by_pid.entry(pid).or_default();
                if outbound {
                    x.out += size;
                    *x.dests.entry(ip).or_default() += size;
                } else {
                    x.inn += size;
                }
            }
        }
    }

    pub fn on_connect(&mut self, now: u64, pid: u32, proto: Proto, ip: IpAddr, port: u16) {
        let ip = norm_ip(ip);
        if scope(&ip) == Scope::Loopback {
            return;
        }
        let f = self.ensure_flow(now, FlowKey { pid, proto, ip, port, inb: false });
        f.connects.push_back(now);
        if f.connects.len() > 24 {
            f.connects.pop_front();
        }
        f.new_connect = true;
        f.open = true;
        f.last = now;
        if !f.hidden {
            self.pstats.entry(pid).or_default().last = now;
        }
    }

    /// Another device's connection to this PC was accepted (TCP accept event).
    pub fn on_accept(&mut self, now: u64, pid: u32, ip: IpAddr, rport: u16, lport: u16) {
        let ip = norm_ip(ip);
        if scope(&ip) == Scope::Loopback || !self.listen_ports.contains(&lport) {
            return; // only count it when something really listens on that port
        }
        if self.inbound_conns.len() > 20_000 {
            self.inbound_conns.clear();
        }
        self.inbound_conns.insert((pid, ip, rport, lport));
        let f = self.ensure_flow(now, FlowKey { pid, proto: Proto::Tcp, ip, port: lport, inb: true });
        f.connects.push_back(now);
        if f.connects.len() > 24 {
            f.connects.pop_front();
        }
        f.new_connect = true;
        f.open = true;
        f.last = now;
        if !f.hidden {
            self.pstats.entry(pid).or_default().last = now;
        }
    }

    pub fn on_dns(&mut self, now: u64, pid: u32, name: &str, ips: Vec<IpAddr>, status: u32) {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return;
        }
        self.stats.dns_events += 1;
        if self.dns.len() > 50_000 {
            self.dns.clear();
        }
        let mut answers = Vec::new();
        for ip in ips {
            let ip = norm_ip(ip);
            // A failed lookup or a referral can list root / TLD name servers: not this name's address.
            if status != 0 || detect::is_dns_infra(&ip) {
                continue;
            }
            self.dns.insert(ip, name.clone());
            answers.push(ip.to_string());
        }
        let mut flag = String::new();
        let name_trusted = self.name_trust(&name).0;
        if let Some(h) = self.intel.domain(&name).filter(|_| !name_trusted && status == 0 && !self.is_own_pid(pid)) {
            self.dns_pending.push(DnsPending { t: now, pid, q: name.clone(), burst: false, n: 0, intel: Some(h) });
            flag = "known malware server".into();
        } else if name_trusted {
            // trusted: no tunnelling checks
        } else if let Some((len, _)) = detect::dns_long_label(&name) {
            self.dns_pending.push(DnsPending { t: now, pid, q: name.clone(), burst: false, n: len, intel: None });
            flag = "unusual name".into();
        }
        let base = base_domain(&name);
        if base != name && !name_trusted {
            let q = self.burst.entry((pid, base.clone())).or_default();
            q.push_back((now, name.clone()));
            while q.front().is_some_and(|(t, _)| *t + MIN < now) || q.len() > 400 {
                q.pop_front();
            }
            let uniq: HashSet<&String> = q.iter().map(|(_, n)| n).collect();
            if uniq.len() >= detect::dns_burst_threshold() {
                let n = uniq.len();
                q.clear();
                self.dns_pending.push(DnsPending { t: now, pid, q: base.clone(), burst: true, n, intel: None });
                flag = "many subdomains".into();
            }
        }
        for b in self.cfg.domain_blocks.iter_mut() {
            if domain_is(&name, &b.domain) {
                let mut changed = false;
                for a in &answers {
                    if !b.ips.contains(a) {
                        b.ips.push(a.clone());
                        changed = true;
                    }
                }
                if changed && !self.fw_updates.contains(&b.domain) {
                    self.fw_updates.push(b.domain.clone());
                    self.dirty_cfg = true;
                }
            }
        }
        self.dns_pids.insert(pid);
        self.dns_log.push_front(DnsEntry { t: now, pid, name, answers, status, flag });
        self.dns_log.truncate(3000);
    }

    /// Socket-table poll: which TCP connections are open right now, as
    /// (pid, remote ip, remote port, local port). In limited mode (no ETW) this is also
    /// how new connections are noticed.
    pub fn sync_open(&mut self, now: u64, open: HashSet<(u32, IpAddr, u16, u16)>, count_new: bool) {
        let first_poll = self.first_poll;
        let mut keys = HashSet::new();
        for &(pid, ip, rport, lport) in &open {
            let ip = norm_ip(ip);
            if scope(&ip) == Scope::Loopback {
                continue;
            }
            let inb = self.is_inbound(pid, &ip, rport, lport);
            let key = FlowKey { pid, proto: Proto::Tcp, ip, port: if inb { lport } else { rport }, inb };
            keys.insert(key);
            let isnew = !self.prev_open.contains(&key);
            let f = self.ensure_flow(now, key);
            f.open = true;
            if isnew && count_new && !first_poll {
                f.connects.push_back(now);
                if f.connects.len() > 24 {
                    f.connects.pop_front();
                }
                f.new_connect = true;
                f.last = now;
            }
            if f.hidden {
                continue;
            }
            let flast = f.last;
            let p = self.pstats.entry(pid).or_default();
            if isnew {
                p.last = p.last.max(flast);
            }
        }
        for (k, f) in self.flows.iter_mut() {
            if k.proto == Proto::Tcp && !self.procs.get(&k.pid).is_some_and(|p| p.sim) {
                f.open = keys.contains(k);
            }
        }
        self.prev_open = keys;
        self.first_poll = false;
    }

    /// A process started (kernel process trace): remember its path and parent, and drop a
    /// stale entry left by an earlier process with the same id.
    pub fn on_proc_start(&mut self, now: u64, pid: u32, ppid: u32, exe: String) {
        if self.proc_starts.len() > 20_000 {
            self.proc_starts.retain(|_, s| s.0 + 10 * MIN > now);
        }
        if self.procs.get(&pid).is_some_and(|p| !p.sim && (p.exited || !p.exe.eq_ignore_ascii_case(&exe))) {
            self.procs.remove(&pid);
        }
        crate::util::own_child_reused(pid, now);
        self.proc_starts.insert(pid, (now, ppid, exe));
    }

    /// Process details from its start event (for programs that are already gone).
    pub fn info_from_start(&self, pid: u32) -> Option<ProcInfo> {
        let (_, ppid, exe) = self.proc_starts.get(&pid)?;
        let base = |p: &str| p.rsplit('\\').next().unwrap_or(p).to_string();
        let parent_name = self
            .procs
            .get(ppid)
            .map(|p| p.name.clone())
            .or_else(|| self.proc_starts.get(ppid).map(|s| base(&s.2)))
            .unwrap_or_default();
        Some(ProcInfo { pid, name: base(exe), exe: exe.clone(), parent: *ppid, parent_name, ..Default::default() })
    }

    /// Adds process details learnt from a start event, and queues its signature check.
    fn adopt_start(&mut self, pid: u32) -> bool {
        let Some(info) = self.info_from_start(pid) else { return false };
        let key = info.exe_key();
        if !self.sigs.contains_key(&key) {
            self.sigs.insert(key, SigInfo { status: "pending".into(), signer: String::new() });
            self.sig_queue.push(info.exe.clone());
        }
        self.procs.insert(pid, info);
        true
    }

    /// A file open from the kernel file trace that matched a secret or document pattern.
    pub fn on_file(&mut self, now: u64, pid: u32, path: String, secret: Option<Secret>, doc: bool) {
        self.stats.file_hits += 1;
        if self.file_pending.len() < 20_000 {
            self.file_pending.push(FileEvt { t: now, pid, path, secret, doc });
        }
    }

    /// PIDs we have traffic for but no process details yet.
    pub fn unknown_pids(&self) -> Vec<u32> {
        let mut v: HashSet<u32> = HashSet::new();
        let files = self.file_pending.iter().map(|f| &f.pid);
        for pid in self.pstats.keys().chain(self.dns_pids.iter()).chain(self.listeners.iter().map(|l| &l.pid)).chain(files) {
            if !self.procs.contains_key(pid) {
                v.insert(*pid);
            }
        }
        v.into_iter().collect()
    }

    // ---------------------------------------------------------------- analysis

    pub fn tick(&mut self, now: u64) {
        self.ticks += 1;
        // Trusted destinations never hide or silence a shady program.
        let pids: HashSet<u32> = self.flows.keys().map(|k| k.pid).collect();
        let untrusty: HashSet<u32> = pids.into_iter().filter(|p| self.untrusty_pid(*p)).collect();
        let (rules, dns) = (&self.trust_rules, &self.dns);
        for (k, f) in self.flows.iter_mut() {
            let (t, h) = trust_for(rules, dns, &k.ip);
            (f.trusted, f.hidden) = if t && untrusty.contains(&k.pid) { (false, false) } else { (t, h) };
            f.rate_out = f.out - f.tick_out;
            f.rate_in = f.inb - f.tick_in;
            f.tick_out = f.out;
            f.tick_in = f.inb;
        }
        let minute = now / MIN * MIN;
        if self.minutes.back().is_none_or(|(m, _)| *m != minute) {
            self.minutes.push_back((minute, HashMap::new()));
            while self.minutes.len() > 16 {
                self.minutes.pop_front();
            }
        }
        let bucket = &mut self.minutes.back_mut().expect("just pushed").1;
        for (pid, p) in self.pstats.iter_mut() {
            p.rate_out = p.out - p.tick_out;
            p.rate_in = p.inb - p.tick_in;
            p.tick_out = p.out;
            p.tick_in = p.inb;
            let d = (p.inet_out - p.tick_iout, p.inet_in - p.tick_iin);
            p.win.push_back(d);
            if d != (0, 0) {
                let b = bucket.entry(*pid).or_default();
                b.0 += d.0;
                b.1 += d.1;
            }
            p.tick_iout = p.inet_out;
            p.tick_iin = p.inet_in;
            if p.win.len() > 60 {
                p.win.pop_front();
            }
        }
        if self.ticks % 5 == 0 {
            self.fold_away(false);
        }

        self.enforce_blocks(now);
        self.process_files(now);
        if self.ticks % 10 == 0 {
            self.check_trust(now);
        }
        let trusted_keys = self.trusted_set();
        let own_keys = self.own_keys();
        let views: HashMap<u32, ProcView> =
            self.pstats.keys().filter_map(|&pid| self.view(pid).map(|v| (pid, v))).collect();
        let learning = now < self.cfg.learning_until;
        let mut found: Vec<(u32, Finding, Dest)> = Vec::new();
        let own: HashSet<u32> = self.flows.keys().map(|k| k.pid).chain(self.pstats.keys().copied()).filter(|p| self.is_own_pid(*p)).collect();

        for (k, f) in self.flows.iter_mut() {
            if !(f.new_bytes || f.new_connect) {
                continue;
            }
            if f.new_connect && f.safe.is_none() {
                // The DNS answer may have come after the flow was first seen.
                f.safe = safe_pick(&self.safe, &self.cfg, &self.dns, &k.ip);
            }
            if f.new_connect && !own.contains(&k.pid) {
                let dom = self.dns.get(&k.ip).cloned().unwrap_or_default();
                if let Some(h) = self.intel.ip(&k.ip).or_else(|| if dom.is_empty() { None } else { self.intel.domain(&dom) }) {
                    self.intel_pending.push((k.pid, k.inb, k.ip, dom, k.port, f.out, h));
                }
            }
            if own.contains(&k.pid) || f.trusted {
                f.new_bytes = false;
                f.new_connect = false;
                continue;
            }
            let Some(v) = views.get(&k.pid) else {
                if f.first + 30_000 < now {
                    f.new_bytes = false;
                    f.new_connect = false;
                }
                continue;
            };
            if v.sig == "pending" && f.first + 15_000 > now {
                continue; // wait for the signature check
            }
            let internet = scope(&k.ip) == Scope::Internet;
            let domain = self.dns.get(&k.ip).map(String::as_str).unwrap_or("");
            let dest = Dest { ip: k.ip.to_string(), domain: domain.to_string(), port: k.port, bytes: f.out };
            let trusted = trusted_keys.contains(&v.exe_key);
            let facts = FlowFacts {
                ip: k.ip,
                port: k.port,
                udp: k.proto == Proto::Udp,
                domain,
                out: f.out,
                inb: f.inb,
                new_connect: f.new_connect,
                connects: &f.connects,
            };
            if k.inb {
                if !trusted {
                    for fd in detect::inbound_rules(v, &facts) {
                        found.push((k.pid, fd, dest.clone()));
                    }
                }
            } else {
                if internet && !own_keys.contains(&v.exe_key) && !v.exe_key.starts_with("pid ") && !self.known.contains(&v.exe_key) {
                    self.known.insert(v.exe_key.clone());
                    self.dirty_cfg = true;
                    if !learning {
                        found.push((
                            k.pid,
                            Finding {
                                rule: "new_app",
                                sev: 1,
                                title: format!("{} went online for the first time", v.name),
                                why: "Kestryl has not seen this program use the internet before. Usually a new or updated app; worth a look if you don't recognise it.".into(),
                                group: "first".into(),
                            },
                            dest.clone(),
                        ));
                    }
                }
                if internet && !trusted {
                    // A known-safe service only quiets "unusual destination" alerts, and only
                    // for normal programs (never unsigned, Temp/Downloads, scripts, Windows tools).
                    let quiet = f.safe.is_some() && !(v.shady() || v.sig == "pending" || v.script != Script::None);
                    for fd in detect::flow_rules(v, &facts) {
                        if quiet && crate::safe::QUIET.contains(&fd.rule) {
                            continue;
                        }
                        found.push((k.pid, fd, dest.clone()));
                    }
                }
            }
            f.new_bytes = false;
            f.new_connect = false;
        }

        // Per program over the last minute: big uploads, and remote-control tools streaming a screen.
        let threshold = self.cfg.upload_mb.max(1) * MB;
        for (pid, p) in self.pstats.iter() {
            let (wo, wi) = p.win.iter().fold((0u64, 0u64), |a, x| (a.0 + x.0, a.1 + x.1));
            if wo < detect::SESSION_BYTES.min(threshold) || own.contains(pid) {
                continue;
            }
            let Some(v) = views.get(pid) else { continue };
            if trusted_keys.contains(&v.exe_key) {
                continue;
            }
            let (label, d) = self.top_dest(&[*pid], now, wo);
            if let Some(tool) = detect::remote_tool(&v.name) {
                if wo >= detect::SESSION_BYTES {
                    found.push((*pid, detect::remote_session_finding(v, tool, wo, &label), d.clone()));
                }
            }
            if wo >= threshold {
                if let Some(fd) = detect::upload_rule(v, wo, wi, threshold, &label) {
                    found.push((*pid, fd, d));
                }
            }
        }

        let pending = std::mem::take(&mut self.dns_pending);
        for d in pending {
            if self.is_own_pid(d.pid) || self.name_trust(&d.q).0 {
                continue;
            }
            let v = views.get(&d.pid).cloned().or_else(|| self.view(d.pid));
            let v = match v {
                Some(v) => v,
                None if d.t + 5000 > now => {
                    self.dns_pending.push(d); // process details not resolved yet
                    continue;
                }
                None => ProcView {
                    name: format!("pid {}", d.pid),
                    exe_key: format!("pid {}", d.pid),
                    sig: "unknown".into(),
                    class: Class::Unknown,
                    script: Script::None,
                    browser: false,
                },
            };
            if d.intel.is_none() && self.is_trusted(&v.exe_key) {
                continue;
            }
            let fd = if let Some(h) = &d.intel {
                Some(detect::intel_dns_finding(&v, &d.q, h))
            } else if d.burst {
                detect::dns_burst_finding(&v, &d.q, d.n)
            } else {
                Some(detect::dns_long_finding(&v, &d.q, d.n))
            };
            if let Some(fd) = fd {
                found.push((d.pid, fd, Dest { domain: d.q.clone(), ..Default::default() }));
            }
        }

        // Connections to listed servers (also ones found when a new list arrived).
        let pending = std::mem::take(&mut self.intel_pending);
        for (pid, inb, ip, domain, port, out, h) in pending {
            let name = views.get(&pid).map(|v| v.name.clone()).or_else(|| self.procs.get(&pid).map(|p| p.name.clone()));
            let name = match name {
                Some(n) => n,
                None if self.ticks % 600 != 0 => {
                    self.intel_pending.push((pid, inb, ip, domain, port, out, h)); // process details not resolved yet
                    continue;
                }
                None => format!("pid {pid}"),
            };
            let dest = if domain.is_empty() { ip.to_string() } else { format!("{domain} ({ip})") };
            found.push((pid, detect::intel_finding(&name, inb, &dest, port, &h), Dest { ip: ip.to_string(), domain, port, bytes: out }));
        }

        for (pid, fd, d) in found {
            self.raise(now, pid, fd, d);
        }
        self.correlate(now);
        self.flush_history(now);
        self.prune(now);
    }

    /// Where most of these programs' internet upload went in the last minute.
    fn top_dest(&self, pids: &[u32], now: u64, bytes: u64) -> (String, Dest) {
        let top = self
            .flows
            .iter()
            .filter(|(k, f)| pids.contains(&k.pid) && !f.trusted && f.last + MIN >= now && scope(&k.ip) == Scope::Internet)
            .max_by_key(|(_, f)| f.out);
        match top {
            Some((k, _)) => {
                let dom = self.dns.get(&k.ip).cloned().unwrap_or_default();
                let label = if dom.is_empty() { format!("{}:{}", k.ip, k.port) } else { dom.clone() };
                (label, Dest { ip: k.ip.to_string(), domain: dom, port: k.port, bytes })
            }
            None => ("an unknown destination".to_string(), Dest { bytes, ..Default::default() }),
        }
    }

    /// The program and the programs it started.
    fn family(&self, pid: u32) -> Vec<u32> {
        let mut v = vec![pid];
        v.extend(self.procs.values().filter(|p| p.parent == pid && p.pid != pid && !p.exited).map(|p| p.pid));
        v
    }

    /// Internet bytes sent so far by a program and its children.
    fn family_out(&self, pid: u32) -> u64 {
        self.family(pid).iter().filter_map(|p| self.pstats.get(p)).map(|s| s.inet_out).sum()
    }

    fn process_files(&mut self, now: u64) {
        if self.file_pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.file_pending);
        for ev in pending {
            if ev.pid == self.own_pid || ev.pid <= 4 {
                continue;
            }
            let stale = self.procs.get(&ev.pid).is_none_or(|p| p.exited && p.exe.is_empty());
            if stale && !self.adopt_start(ev.pid) && !self.procs.contains_key(&ev.pid) {
                if ev.t + 5000 > now {
                    self.file_pending.push(ev); // process details not resolved yet
                }
                continue;
            }
            // Windows reuses process ids. A file open that arrives seconds after the program with
            // this id was seen gone came from a newer program whose start event is late: forget
            // the old one rather than blame it (a closed Kestryl PowerShell check got the blame for
            // a Docker helper reading .docker\config.json).
            if let Some(gone) = self.procs.get(&ev.pid).filter(|p| !p.sim && p.exited && p.gone != 0 && ev.t > p.gone + REUSE_GAP).map(|p| p.gone) {
                self.procs.remove(&ev.pid);
                if self.proc_starts.get(&ev.pid).is_some_and(|s| s.0 <= gone) {
                    self.proc_starts.remove(&ev.pid); // the old program's start
                }
                if ev.t + 5000 > now {
                    self.file_pending.push(ev);
                }
                continue;
            }
            if self.is_own_pid(ev.pid) {
                continue; // Kestryl and its own PowerShell checks
            }
            let Some(info) = self.procs.get(&ev.pid) else { continue };
            let exe = info.exe.to_lowercase();
            let unknown = info.exe.is_empty();
            let Some(v) = self.view(ev.pid) else { continue };
            if v.sig == "pending" && ev.t + 15_000 > now {
                self.file_pending.push(ev);
                continue;
            }
            if detect::file_silent(&v.name, &exe) || (v.class == Class::System && v.script == Script::None) || self.is_trusted(&v.exe_key) {
                continue;
            }
            match ev.secret {
                Some(s) if !detect::secret_owner(s.kind, &v.name, &exe) => self.on_secret(now, ev.pid, &v, s, ev.path, unknown),
                Some(_) => {}
                None if ev.doc && !detect::is_sync_client(&v.name) => self.on_doc(now, ev.pid, ev.path),
                None => {}
            }
        }
    }

    /// `unknown`: the program could not be identified (it was gone too fast); one quiet note
    /// for all of those instead of an alert per process.
    fn on_secret(&mut self, now: u64, pid: u32, v: &ProcView, s: Secret, path: String, unknown: bool) {
        let base_out = self.family_out(pid);
        let hits = self.secrets.entry(pid).or_default();
        if let Some(h) = hits.iter_mut().find(|h| h.kind == s.kind) {
            h.t = now;
            return;
        }
        hits.push(SecretHit { t: now, kind: s.kind, label: s.label, path: path.clone(), base_out, uploaded: false });
        let mut fd = detect::secret_read_finding(v, &s, &path);
        if unknown {
            fd.sev = 1;
            fd.title = format!("A program that closed too fast to identify opened {}", s.label);
            fd.why = format!("A short-lived program opened {path}. It exited before Kestryl could see which program it was. Developer tools and their background helpers do this all the time; if this keeps appearing and you use no such tools, run a full virus scan.");
        }
        self.raise_full(now, pid, fd, Dest::default(), vec![path]);
    }

    fn on_doc(&mut self, now: u64, pid: u32, path: String) {
        let base = self.family_out(pid);
        let d = self.docs.entry(pid).or_insert_with(|| DocWin {
            t0: now,
            seen: HashSet::new(),
            sample: Vec::new(),
            collected: 0,
            base_out: 0,
            reported: false,
        });
        if d.collected == 0 && d.t0 + 5 * MIN < now {
            d.t0 = now;
            d.seen.clear();
            d.sample.clear();
        }
        if d.seen.insert(fnv(&path.to_lowercase())) {
            if d.sample.len() < 8 {
                d.sample.push(path);
            }
            if d.seen.len() >= detect::DOCS_COLLECT && d.collected == 0 {
                d.collected = now;
                d.base_out = base;
            }
        }
    }

    /// File reads followed by uploads: "read your passwords, then sent 180 KB out".
    fn correlate(&mut self, now: u64) {
        if self.secrets.is_empty() && self.docs.is_empty() {
            return;
        }
        let trusted = self.trusted_set();
        let mut out: Vec<(u32, Finding, Dest, Vec<String>)> = Vec::new();
        let pids: Vec<u32> = self.secrets.keys().copied().collect();
        for pid in pids {
            let sent_now = self.family_out(pid);
            let mut fire: Option<(&'static str, String, u64)> = None;
            if let Some(hits) = self.secrets.get_mut(&pid) {
                hits.retain(|h| h.t + HOUR > now);
                for h in hits.iter_mut() {
                    if !h.uploaded && h.t + 10 * MIN >= now && sent_now >= h.base_out + 8 * KB {
                        h.uploaded = true;
                        if fire.is_none() {
                            fire = Some((h.label, h.path.clone(), sent_now - h.base_out));
                        }
                    }
                }
            }
            if let Some((label, path, sent)) = fire {
                let Some(v) = self.view(pid) else { continue };
                if trusted.contains(&v.exe_key) {
                    continue;
                }
                let (dl, d) = self.top_dest(&self.family(pid), now, sent);
                out.push((pid, detect::secret_upload_finding(&v, label, &path, sent, &dl), d, vec![path]));
            }
        }
        self.secrets.retain(|_, h| !h.is_empty());

        let pids: Vec<u32> = self.docs.keys().copied().collect();
        for pid in pids {
            let sent_now = self.family_out(pid);
            let mut fire = None;
            if let Some(d) = self.docs.get_mut(&pid) {
                if d.collected > 0 && !d.reported && d.collected + 10 * MIN >= now && sent_now >= d.base_out + 2 * MB {
                    d.reported = true;
                    fire = Some((d.seen.len(), sent_now - d.base_out, d.sample.clone()));
                }
            }
            if let Some((n, sent, files)) = fire {
                let Some(v) = self.view(pid) else { continue };
                if trusted.contains(&v.exe_key) {
                    continue;
                }
                let (dl, d) = self.top_dest(&self.family(pid), now, sent);
                out.push((pid, detect::docs_upload_finding(&v, n, sent, &dl), d, files));
            }
        }
        self.docs.retain(|_, d| if d.collected > 0 { d.collected + 30 * MIN > now } else { d.t0 + 5 * MIN > now });
        for (pid, fd, d, files) in out {
            self.raise_full(now, pid, fd, d, files);
        }
    }

    /// What a trusted program's file is: its publisher, or (unsigned) size and date.
    fn fingerprint(&self, key: &str) -> Option<String> {
        let sig = self.sigs.get(key)?;
        match sig.status.as_str() {
            "pending" | "" => None,
            "signed" => Some(format!("signed:{}", sig.signer)),
            st => {
                let (len, mt) = match std::fs::metadata(key) {
                    Ok(m) => (m.len(), m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())),
                    Err(_) => (0, 0), // gone or unreadable: also "not the same file"
                };
                Some(format!("{st}:{len}:{mt}"))
            }
        }
    }

    /// Trust follows the file: a trusted program that was replaced or lost its signature
    /// is watched again (and reported once).
    fn check_trust(&mut self, now: u64) {
        let fp_text = |fp: &str| match fp.strip_prefix("signed:") {
            Some(s) => format!("signed by {s}"),
            None => {
                let mut it = fp.split(':');
                let st = it.next().unwrap_or("");
                let size = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                format!("{st}, {}", fmt_bytes(size))
            }
        };
        for key in self.cfg.trusted.clone() {
            let Some(fp) = self.fingerprint(&key) else { continue };
            match self.cfg.trusted_fp.get(&key).cloned() {
                None => {
                    self.cfg.trusted_fp.insert(key, fp);
                    self.dirty_cfg = true;
                }
                Some(old) if old != fp && !self.trust_broken.contains(&key) => {
                    self.trust_broken.insert(key.clone());
                    let name = std::path::Path::new(&key).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or(key.clone());
                    let fd = Finding {
                        rule: "trust_broken",
                        sev: if old.starts_with("signed:") { 3 } else { 2 },
                        title: format!("{name} changed since you trusted it"),
                        why: format!("You trusted {name}, but its file is not the same any more ({} → {}). Kestryl watches it again until you trust it again. Updates do this too; if {name} did not just update, check it.", fp_text(&old), fp_text(&fp)),
                        group: "trust".into(),
                    };
                    let pid = self.procs.values().find(|p| p.exe_key() == key).map(|p| p.pid);
                    match pid {
                        Some(pid) => self.raise(now, pid, fd, Dest::default()),
                        None => self.raise_sys(now, fd, &name),
                    }
                }
                _ => {}
            }
        }
    }

    /// Adds this second's bytes to today's history (and starts a new day at midnight).
    fn flush_history(&mut self, now: u64) {
        let (day, hour) = local_day_hour();
        if day != self.today.day {
            let old = std::mem::replace(&mut self.today, Day::new(day));
            if !old.rows.is_empty() || old.totals() != (0, 0) {
                self.done_days.push(old);
            }
            self.hist_dirty = true;
        }
        for (k, f) in self.flows.iter_mut() {
            let (dout, din) = (f.out - f.hist[0], f.inb - f.hist[1]);
            if dout == 0 && din == 0 {
                continue;
            }
            if f.hidden {
                f.hist = [f.out, f.inb];
                continue;
            }
            let Some(info) = self.procs.get(&k.pid) else { continue }; // wait for the name
            f.hist = [f.out, f.inb];
            let dest = self.dns.get(&k.ip).map(|d| base_domain(d)).unwrap_or_else(|| k.ip.to_string());
            let lan = scope(&k.ip) != Scope::Internet;
            self.today.add(&info.exe_key(), &info.name, &dest, &k.ip.to_string(), k.port, k.inb, lan, dout, din, hour, now);
            self.hist_dirty = true;
        }
    }

    fn prune(&mut self, now: u64) {
        self.flows.retain(|_, f| f.open || f.last + 15 * MIN > now);
        if self.flows.len() > MAX_FLOWS {
            let mut old: Vec<(u64, FlowKey)> =
                self.flows.iter().filter(|(_, f)| !f.open).map(|(k, f)| (f.last, *k)).collect();
            old.sort_by_key(|x| x.0);
            for (_, k) in old.into_iter().take(self.flows.len() - MAX_FLOWS) {
                self.flows.remove(&k);
            }
        }
        let flow_pids: HashSet<u32> = self.flows.keys().map(|k| k.pid).collect();
        self.pstats.retain(|pid, p| flow_pids.contains(pid) || p.last + 15 * MIN > now);
        self.burst.retain(|_, q| q.back().is_some_and(|(t, _)| *t + MIN > now));
        if self.ticks % 60 == 0 {
            self.proc_starts.retain(|_, s| s.0 + 30 * MIN > now);
            self.popped.retain(|_, t| *t + 10 * MIN > now);
        }
        let listen: HashSet<u32> = self.listeners.iter().map(|l| l.pid).collect();
        let recent_dns: HashSet<u32> = self.dns_log.iter().take(500).map(|d| d.pid).collect();
        self.dns_pids.retain(|p| recent_dns.contains(p));
        let files: HashSet<u32> = self.secrets.keys().chain(self.docs.keys()).copied().collect();
        self.procs.retain(|pid, p| {
            p.sim
                || !p.exited
                || self.pstats.contains_key(pid)
                || listen.contains(pid)
                || recent_dns.contains(pid)
                || files.contains(pid)
        });
    }

    // ---------------------------------------------------------------- alerts

    fn raise(&mut self, now: u64, pid: u32, fd: Finding, d: Dest) {
        self.raise_full(now, pid, fd, d, Vec::new());
    }

    /// Folds a repeat into an alert from the last 30 minutes. True when it did.
    fn merge_repeat(&mut self, now: u64, key: &str, fd: &Finding, bytes: u64) -> bool {
        let Some(a) = self.alerts.iter_mut().find(|a| a.key == key && a.last + 30 * MIN > now) else { return false };
        if a.last + MIN <= now {
            a.count += 1;
            a.read = false;
        }
        a.last = now;
        // Keep the worst / biggest version (a 60 s window shrinks again after an upload).
        if fd.sev > a.sev || (fd.sev == a.sev && bytes >= a.bytes_out) {
            if fd.sev > a.sev {
                a.read = false;
            }
            a.sev = fd.sev;
            a.title = fd.title.clone();
            a.why = fd.why.clone();
        }
        a.bytes_out = a.bytes_out.max(bytes);
        self.dirty_alerts = true;
        true
    }

    fn push_alert(&mut self, a: Alert) {
        let now = a.t;
        if self.cfg.popups && a.sev >= self.cfg.popup_min {
            // Pop-up guard: one per rule and program every 10 minutes, at most 4 a minute.
            let pk = format!("{}|{}", a.rule, if a.exe.is_empty() { a.name.to_lowercase() } else { a.exe.to_lowercase() });
            while self.pop_log.front().is_some_and(|t| *t + MIN <= now) {
                self.pop_log.pop_front();
            }
            let recent = self.popped.get(&pk).is_some_and(|t| *t + 10 * MIN > now);
            if !recent && self.pop_log.len() < 4 {
                self.popped.insert(pk, now);
                self.pop_log.push_back(now);
                self.notify.push(a.clone());
            }
        }
        self.alerts.push_front(a);
        // Full: drop the oldest read low/medium alerts first, so a flood can't push out a high one.
        while self.alerts.len() > 500 {
            let i = self
                .alerts
                .iter()
                .rposition(|x| x.sev < 3 && x.read)
                .or_else(|| self.alerts.iter().rposition(|x| x.sev < 3))
                .unwrap_or(self.alerts.len() - 1);
            self.alerts.remove(i);
        }
        self.dirty_alerts = true;
    }

    fn raise_full(&mut self, now: u64, pid: u32, fd: Finding, d: Dest, files: Vec<String>) {
        // Kestryl never alerts about itself or the programs it runs for its own checks.
        if self.cfg.muted.iter().any(|m| m == fd.rule) || self.is_own_pid(pid) {
            return;
        }
        let info = self.procs.get(&pid).cloned().unwrap_or_else(|| ProcInfo {
            pid,
            name: format!("pid {pid}"),
            ..Default::default()
        });
        let exe_key = info.exe_key();
        // Programs that could not be identified share one alert instead of one per process id.
        let who = if info.exe.is_empty() && info.name.starts_with("pid ") { "unidentified".to_string() } else { exe_key.clone() };
        let key = format!("{}|{}|{}", fd.rule, who, fd.group);
        if self.merge_repeat(now, &key, &fd, d.bytes) {
            return;
        }
        self.seq += 1;
        let sig = self.sigs.get(&exe_key).cloned().unwrap_or_default();
        let parent = if info.parent_name.is_empty() {
            String::new()
        } else {
            format!("{} (pid {})", info.parent_name, info.parent)
        };
        let service = self.services.get(&pid).map(|s| s.iter().take(4).cloned().collect::<Vec<_>>().join(", ")).unwrap_or_default();
        let origin = if info.exe.is_empty() { String::new() } else { crate::origin::summary(&self.origin_of(&info.exe)) };
        let a = Alert {
            id: self.seq,
            t: now,
            last: now,
            count: 1,
            sev: fd.sev,
            rule: fd.rule.into(),
            title: fd.title,
            why: fd.why,
            pid,
            name: info.name.clone(),
            exe: info.exe.clone(),
            signer: if sig.status == "signed" { sig.signer } else { sig.status },
            parent,
            cmd: info.cmd.chars().take(800).collect(),
            ip: d.ip,
            domain: d.domain,
            port: d.port,
            bytes_out: d.bytes,
            read: false,
            key,
            sim: info.sim,
            files,
            service,
            system: false,
            origin,
        };
        self.push_alert(a);
    }

    /// An alert about Windows itself (settings, firewall, monitoring), not one program.
    pub fn raise_sys(&mut self, now: u64, fd: Finding, who: &str) {
        if self.cfg.muted.iter().any(|m| m == fd.rule) {
            return;
        }
        let key = format!("{}|sys|{}", fd.rule, fd.group);
        if self.merge_repeat(now, &key, &fd, 0) {
            return;
        }
        self.seq += 1;
        let a = Alert {
            id: self.seq,
            t: now,
            last: now,
            count: 1,
            sev: fd.sev,
            rule: fd.rule.into(),
            title: fd.title,
            why: fd.why,
            name: who.to_string(),
            key,
            sim: self.sim,
            system: true,
            ..Default::default()
        };
        self.push_alert(a);
    }

    /// An alert about a program file: tied to its running process when there is one.
    fn raise_exe(&mut self, now: u64, exe: &str, fd: Finding, d: Dest) {
        if let Some(pid) = self.pids_of(exe).first().copied() {
            return self.raise_full(now, pid, fd, d, Vec::new());
        }
        if self.cfg.muted.iter().any(|m| m == fd.rule) || self.is_own_exe(&exe.to_lowercase()) {
            return;
        }
        let key = format!("{}|{}|{}", fd.rule, exe.to_lowercase(), fd.group);
        if self.merge_repeat(now, &key, &fd, d.bytes) {
            return;
        }
        self.seq += 1;
        let sig = self.sigs.get(&exe.to_lowercase()).cloned().unwrap_or_default();
        let origin = crate::origin::summary(&self.origin_of(exe));
        let a = Alert {
            origin,
            id: self.seq,
            t: now,
            last: now,
            count: 1,
            sev: fd.sev,
            rule: fd.rule.into(),
            title: fd.title,
            why: fd.why,
            name: exe.rsplit('\\').next().unwrap_or(exe).to_string(),
            exe: exe.to_string(),
            signer: if sig.status == "signed" { sig.signer } else { sig.status },
            ip: d.ip,
            domain: d.domain,
            port: d.port,
            key,
            sim: self.sim,
            ..Default::default()
        };
        self.push_alert(a);
    }

    // ---------------------------------------------------------------- threat lists, scans, camera

    /// New known-safe lists.
    pub fn set_safe(&mut self, s: Arc<crate::safe::Safe>) {
        self.safe = s;
        self.refresh_safe();
    }

    /// Call after the known-safe switches change.
    pub fn refresh_safe(&mut self) {
        for (k, f) in self.flows.iter_mut() {
            f.safe = safe_pick(&self.safe, &self.cfg, &self.dns, &k.ip);
        }
    }

    /// A new Kestryl release: one alert and pop-up per version.
    pub fn announce_update(&mut self, now: u64, version: &str, notes: &str) {
        if self.cfg.update_seen == version {
            return;
        }
        self.cfg.update_seen = version.to_string();
        self.dirty_cfg = true;
        let first: String = notes
            .lines()
            .map(|l| l.trim().trim_start_matches(['#', '-', '*', ' ']).trim())
            .filter(|l| !l.is_empty())
            .take(4)
            .collect::<Vec<_>>()
            .join(" · ");
        let first: String = first.chars().take(400).collect();
        self.raise_sys(now, Finding {
            rule: "update",
            sev: 1,
            title: format!("Kestryl {version} is available"),
            why: format!("You have Kestryl {}. {}Update from this alert or from Settings → Updates. The update comes from Kestryl's GitHub releases.",
                crate::update::current(), if first.is_empty() { String::new() } else { format!("What's new: {first} ") }),
            group: version.to_string(),
        }, "Kestryl");
        if let Some(a) = self.alerts.iter().find(|a| a.rule == "update" && a.last == now).cloned() {
            if !self.notify.iter().any(|x| x.id == a.id) {
                self.notify.push(a);
            }
        }
    }

    /// New threat lists: also checks every connection and name seen so far.
    pub fn set_intel(&mut self, intel: Arc<Intel>) {
        self.intel = intel;
        let mut hits = Vec::new();
        for (k, f) in &self.flows {
            if self.is_own_pid(k.pid) {
                continue;
            }
            let dom = self.dns.get(&k.ip).cloned().unwrap_or_default();
            if let Some(h) = self.intel.ip(&k.ip).or_else(|| if dom.is_empty() { None } else { self.intel.domain(&dom) }) {
                hits.push((k.pid, k.inb, k.ip, dom, k.port, f.out, h));
            }
        }
        self.intel_pending.extend(hits);
    }

    /// Queues an exe for a hash + Defender scan (once per file version).
    pub fn queue_scan(&mut self, exe: &str) {
        let k = exe.to_lowercase();
        // Scanned already, unless the file changed since (an update, or a replaced file).
        let done = self.scans.get(&k).is_some_and(|s| s.state == "running" || s.stamp == crate::scan::stamp(exe));
        if exe.is_empty() || done || self.scan_queue.iter().any(|q| q.eq_ignore_ascii_case(exe)) {
            return;
        }
        self.scan_queue.push(exe.to_string());
    }

    /// Next file to scan; marks it running.
    pub fn next_scan(&mut self) -> Option<String> {
        if self.scan_queue.is_empty() {
            return None;
        }
        let p = self.scan_queue.remove(0);
        self.scans.insert(p.to_lowercase(), Scan { state: "running".into(), ..Default::default() });
        Some(p)
    }

    /// A finished scan: alerts when Defender found something or the hash is a listed malware file.
    pub fn on_scan(&mut self, now: u64, exe: &str, mut r: Scan) {
        r.t = now;
        let name = exe.rsplit('\\').next().unwrap_or(exe).to_string();
        if !r.sha256.is_empty() {
            if let Some(h) = self.intel.hash(&r.sha256) {
                let what = if h.what.is_empty() { "malware".to_string() } else { h.what.clone() };
                self.raise_exe(now, exe, Finding {
                    rule: "malware_hash",
                    sev: 3,
                    title: format!("{name} is a known malware file ({what})"),
                    why: format!("The SHA-256 fingerprint of {exe} is on the {} list as {what}. This exact file has been seen in attacks. End and block it, then run a Microsoft Defender Offline scan (Windows Security → Virus & threat protection → Scan options).", h.list),
                    group: "hash".into(),
                }, Dest::default());
            }
        }
        if r.state == "threat" {
            self.raise_exe(now, exe, Finding {
                rule: "defender_found",
                sev: 3,
                title: format!("Microsoft Defender: {name} is {}", r.threat),
                why: format!("Kestryl asked Microsoft Defender to scan {exe} and Defender recognised it as {}. Kestryl only reports; it never deletes files. End and block the program, then open Windows Security → Virus & threat protection → Scan options → Microsoft Defender Offline scan, which removes it before Windows starts.", r.threat),
                group: "defender".into(),
            }, Dest::default());
        }
        self.scans.insert(exe.to_lowercase(), r);
    }

    /// The user asked to be told every time this kind of sensor turns on.
    fn sensor_notify(&self, kind: &str) -> bool {
        if kind == "camera" { self.cfg.cam_notify } else { self.cfg.mic_notify }
    }

    /// Shows the camera / microphone alert just raised for `u` as a pop-up, whatever the
    /// pop-up severity setting, when the user wants to hear about every use.
    fn sensor_popup(&mut self, now: u64, u: &Use, name: &str) {
        if !self.sensor_notify(u.kind) {
            return;
        }
        let id = (u.kind, u.key());
        if self.sensor_popped.get(&id).is_some_and(|t| *t + MIN > now) {
            return;
        }
        let Some(a) = self.alerts.iter().find(|a| {
            a.last == now && (a.rule == "cam_mic" || a.rule == "cam_mic_use") && (a.exe.eq_ignore_ascii_case(&u.app) || a.name == name)
        }) else {
            return; // muted
        };
        let a = a.clone();
        self.sensor_popped.insert(id, now);
        if !self.notify.iter().any(|x| x.id == a.id) {
            self.notify.push(a);
        }
    }

    /// Camera and microphone use from the registry (every few seconds).
    pub fn on_sensors(&mut self, now: u64, uses: Vec<Use>) {
        for u in uses.iter().filter(|u| u.active()) {
            let id = (u.kind, u.key());
            if self.sensor_on.contains(&id) {
                continue;
            }
            let key = u.key();
            if self.is_own_exe(&key) {
                self.sensor_on.insert(id);
                continue;
            }
            let name = if u.packaged { sensors::label(u) } else { key.rsplit('\\').next().unwrap_or(&key).to_string() };
            let what = if u.kind == "camera" { "camera" } else { "microphone" };
            let page = if u.kind == "camera" { "Camera" } else { "Microphone" };
            // Store apps, call / browser / recording programs and trusted programs: a notice, not
            // a warning, and only when the user wants to hear about every use.
            if u.packaged || sensors::expected(&name) || self.is_trusted(&key) {
                self.sensor_on.insert(id);
                if !self.sensor_notify(u.kind) {
                    continue;
                }
                let (title, why) = match sensors::browser(&name) {
                    Some(b) => (
                        format!("{b} turned on your {what}"),
                        format!("A website open in {b} is using the {what}. Windows only records the browser, not the tab: look for the {what} icon in the address bar or on the tab to see which site it is, and click it to stop or block it. If you did not just allow a site to use it, close that tab. Settings → Privacy & security → {page} lists every app that used it. You can turn these notices off in Kestryl Settings → Protection."),
                    ),
                    None => (
                        format!("{name} turned on your {what}"),
                        format!("Windows reports that {} started using the {what}. It is {}, so this is a notice rather than a warning. If you did not just start a call, a recording or the app's {what} feature, close it. Settings → Privacy & security → {page} lists every app that used it. You can turn these notices off in Kestryl Settings → Protection.",
                            u.app, if u.packaged { "a Microsoft Store app" } else if self.is_trusted(&key) { "a program you trusted" } else { "a program people use for calls, meetings or recording" }),
                    ),
                };
                let fd = Finding { rule: "cam_mic_use", sev: 1, title, why, group: u.kind.into() };
                if u.packaged {
                    let mut fd = fd;
                    fd.group = format!("{}|{}", u.kind, u.key());
                    self.raise_sys(now, fd, &name);
                } else {
                    self.raise_exe(now, &u.app, fd, Dest::default());
                }
                self.sensor_popup(now, u, &name);
                continue;
            }
            let sig = self.sigs.get(&key).map(|s| s.status.clone());
            if sig.as_deref().map_or(true, |s| s == "pending") && u.start + 20_000 > now {
                if sig.is_none() {
                    self.sigs.insert(key.clone(), crate::engine::SigInfo { status: "pending".into(), signer: String::new() });
                    self.sig_queue.push(u.app.clone());
                }
                continue; // judged once the signature check is back
            }
            self.sensor_on.insert(id);
            let sig = sig.unwrap_or_else(|| "unknown".into());
            let class = detect::classify(&key);
            let (mut sev, reason) = match class {
                Class::Risky => (3, "It runs from a temp, download or bare AppData folder."),
                _ if matches!(sig.as_str(), "unsigned" | "invalid" | "untrusted") => (2, "It is not signed by a known publisher."),
                // Signed per-user installs (chat and meeting apps in AppData) are normal callers too.
                Class::System | Class::Installed | Class::User if sig == "signed" => (1, "It is signed by its publisher, so probably a feature you use."),
                _ => (2, "It is not a program Kestryl knows for calls or recording."),
            };
            let sending: u64 = self.pids_of(&key).iter().filter_map(|p| self.pstats.get(p)).map(|p| p.win.iter().map(|x| x.0).sum::<u64>()).sum();
            let busy = sending >= MB;
            if busy {
                sev = (sev + 1).min(3);
            }
            self.raise_exe(now, &u.app, Finding {
                rule: "cam_mic",
                sev,
                title: format!("{name} turned on your {what}"),
                why: format!("Windows reports that {} started using the {what}. {reason}{} Remote-access trojans switch on the camera and microphone to spy. If you are not in a call or recording with it, end it and block it. Settings → Privacy & security → {} shows and controls which apps may use it.",
                    u.app, if busy { format!(" It sent {} in the last minute.", fmt_bytes(sending)) } else { String::new() }, page),
                group: u.kind.into(),
            }, Dest::default());
            self.sensor_popup(now, u, &name);
        }
        self.sensor_popped.retain(|_, t| *t + 10 * MIN > now);
        self.sensor_on.retain(|(k, a)| uses.iter().any(|u| u.active() && u.kind == *k && u.key() == *a));
        self.sensor_uses = uses;
    }

    // ---------------------------------------------------------------- while you were away

    /// Screen lock and keyboard/mouse idle time, every few seconds.
    pub fn on_presence(&mut self, now: u64, locked: bool, idle: u64) {
        self.presence_t = now;
        let away_now = locked || idle >= away::IDLE_MS;
        if self.away.is_none() && away_now {
            // From the last keyboard or mouse input (at most 15 minutes back, the per-minute record).
            let start = now.saturating_sub(idle.min(15 * MIN));
            let mut s = away::Session { start, why: if locked { "locked" } else { "idle" }, ..Default::default() };
            for (m, per) in &self.minutes {
                if *m + MIN > start {
                    for (pid, (o, i)) in per {
                        let a = s.by_pid.entry(*pid).or_default();
                        a.out += o;
                        a.inn += i;
                    }
                }
            }
            self.away = Some(s);
        } else if self.away.is_some() && !locked && idle < 60_000 {
            self.finish_away(now);
        }
    }

    /// Moves per-process counts onto programs while the process is still known (`all`: also
    /// the ones that can no longer be named).
    fn fold_away(&mut self, all: bool) {
        let Some(mut s) = self.away.take() else { return };
        let pids: Vec<u32> = s.by_pid.keys().copied().collect();
        for pid in pids {
            let info = self.procs.get(&pid).cloned().or_else(|| self.info_from_start(pid));
            let Some(info) = info.or_else(|| all.then(|| ProcInfo { pid, name: format!("pid {pid}"), ..Default::default() })) else { continue };
            let Some(acc) = s.by_pid.remove(&pid) else { continue };
            let key = info.exe_key();
            let own = self.is_own_pid(pid);
            let trusted = self.is_trusted(&key);
            // A program that could not be identified counts as one to look at.
            let shady = self.view(pid).map(|v| v.shady() || v.script != Script::None).unwrap_or(!own && pid > 4);
            let p = s.progs.entry(key).or_insert_with(|| away::ProgAcc { name: info.name.clone(), own, trusted, shady, ..Default::default() });
            p.out += acc.out;
            p.inn += acc.inn;
            for (ip, b) in acc.dests {
                let label = self.dns.get(&ip).map(|d| base_domain(d)).unwrap_or_else(|| ip.to_string());
                p.dests.entry(label).or_insert((ip, 0)).1 += b;
            }
        }
        self.away = Some(s);
    }

    /// You are back: the report, and an alert when something was sent meanwhile.
    fn finish_away(&mut self, now: u64) {
        self.fold_away(true);
        let Some(s) = self.away.take() else { return };
        if now < s.start + away::MIN_MS {
            return;
        }
        let mut progs: Vec<away::ProgReport> = s
            .progs
            .into_iter()
            .filter(|(_, p)| p.out + p.inn > 0)
            .map(|(key, p)| {
                let mut dests: Vec<(String, (IpAddr, u64))> = p.dests.into_iter().collect();
                dests.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
                let dests = dests
                    .into_iter()
                    .take(4)
                    .map(|(dest, (ip, out))| {
                        let (cc, org, _) = self.geo.lookup(&ip);
                        away::DestReport { dest, cc, org, out }
                    })
                    .collect();
                let flagged = !p.own && !p.trusted && p.shady && p.out >= 512 * KB;
                away::ProgReport { key, name: p.name, out: p.out, inn: p.inn, dests, own: p.own, trusted: p.trusted, flagged }
            })
            .collect();
        progs.sort_by(|a, b| b.flagged.cmp(&a.flagged).then(b.out.cmp(&a.out)).then(b.inn.cmp(&a.inn)));
        let (out, inn) = progs.iter().fold((0, 0), |a, p| (a.0 + p.out, a.1 + p.inn));
        let flagged = progs.iter().any(|p| p.flagged);
        progs.truncate(12);
        let r = away::Report { id: now, start: s.start, end: now, why: s.why.into(), out, inn, progs, flagged, sim: self.sim };
        let others: u64 = r.progs.iter().filter(|p| !p.own).map(|p| p.out).sum();
        if others >= MB || flagged {
            let n = r.progs.iter().filter(|p| !p.own && p.out > 0).count();
            let who: Vec<String> = r
                .progs
                .iter()
                .filter(|p| !p.own && p.out >= 64 * KB)
                .take(4)
                .map(|p| {
                    let to = p.dests.first().map(|d| format!(" to {}{}", d.dest, if d.cc.is_empty() { String::new() } else { format!(" ({})", d.cc) })).unwrap_or_default();
                    format!("{} sent {}{to}", p.name, fmt_bytes(p.out))
                })
                .collect();
            let fd = Finding {
                rule: "away_upload",
                sev: if flagged { 2 } else { 1 },
                title: format!("While you were away ({}), {} sent {}", away::fmt_dur(now - s.start), if n == 1 { "1 program".to_string() } else { format!("{n} programs") }, fmt_bytes(others)),
                why: format!(
                    "Nobody was using this PC (it was {}). Meanwhile: {}. {}",
                    if s.why == "locked" { "locked" } else { "left idle" },
                    who.join("; "),
                    if flagged {
                        "At least one of them is unsigned, a script, or runs from a temp or download folder. Look at it on the Status page (While you were away) and block it unless you know it."
                    } else {
                        "Backups, cloud sync, updates and chat apps do this. Check it if you don't recognise a program."
                    }
                ),
                group: format!("away{}", r.id),
            };
            self.raise_sys(now, fd, "While you were away");
        }
        self.away_reports.push_front(r);
        self.away_reports.truncate(away::KEEP);
        self.away_dirty = true;
    }

    // ---------------------------------------------------------------- clipboard guard

    /// A wallet address or IBAN appeared on the clipboard (clip.rs).
    pub fn on_clipboard(&mut self, s: clip::Seen) {
        if !self.cfg.clip_guard {
            return;
        }
        let now = s.t;
        let prev = self.clip_last.replace(s.clone());
        let name_of = |exe: &str, pid: u32| {
            if !exe.is_empty() {
                exe.rsplit('\\').next().unwrap_or(exe).to_string()
            } else if pid == 0 {
                "a program that hid its name".to_string()
            } else {
                format!("pid {pid}")
            }
        };
        let owner = name_of(&s.owner_exe, s.owner);
        if clip::relay_tool(&owner.to_lowercase()) || (s.owner != 0 && self.is_own_pid(s.owner)) {
            return;
        }
        // 1. Swapped: the same kind of detail, different value, within 3 s, from another program.
        if let Some(p) = prev.filter(|p| p.kind == s.kind && p.hash != s.hash && s.t <= p.t + 3000 && (s.owner == 0 || s.owner != p.owner)) {
            let before = name_of(&p.owner_exe, p.owner);
            let fd = Finding {
                rule: "clipboard_swap",
                sev: 3,
                title: format!("A copied {} was swapped on the clipboard", s.kind),
                why: format!(
                    "You copied {} (in {before}), and {} ms later {owner} replaced it with a different one: {}. This is how \"clipper\" malware steals payments: you paste the attacker's address without noticing. Do not send anything to what you just pasted. Copy the address again and compare every character; end and block {owner}, then run a full virus scan.",
                    p.masked,
                    s.t - p.t,
                    s.masked
                ),
                group: "clip".into(),
            };
            return self.raise_clip(now, s.owner, &s.owner_exe, fd);
        }
        // 2. Put there from the background by an unsigned or risky program.
        if s.owner != 0 && s.owner != s.fg && !s.owner_exe.is_empty() {
            let key = s.owner_exe.to_lowercase();
            let sig = self.sigs.get(&key).map(|x| x.status.clone());
            if sig.is_none() {
                self.sigs.insert(key.clone(), SigInfo { status: "pending".into(), signer: String::new() });
                self.sig_queue.push(s.owner_exe.clone());
            }
            let risky = detect::classify(&key) == Class::Risky || matches!(sig.as_deref(), Some("unsigned" | "invalid"));
            if risky && !self.is_trusted(&key) {
                let fd = Finding {
                    rule: "clipboard_swap",
                    sev: 3,
                    title: format!("{owner} put a {} on your clipboard from the background", s.kind),
                    why: format!(
                        "{owner} is not the window you were using, yet it placed {} on the clipboard. {} Clipper malware does this to make you paste the attacker's address. Compare what you paste with the original before sending anything, and end and block {owner} if you don't know it.",
                        s.masked,
                        if detect::classify(&key) == Class::Risky { "It runs from a temp, download or bare AppData folder." } else { "It is not signed by a publisher." }
                    ),
                    group: "clip-bg".into(),
                };
                self.raise_clip(now, s.owner, &s.owner_exe, fd);
            }
        }
    }

    fn raise_clip(&mut self, now: u64, pid: u32, exe: &str, fd: Finding) {
        if pid == 0 {
            return self.raise_sys(now, fd, "Clipboard");
        }
        if !self.procs.contains_key(&pid) && !exe.is_empty() {
            let name = exe.rsplit('\\').next().unwrap_or(exe).to_string();
            self.procs.insert(pid, ProcInfo { pid, name, exe: exe.to_string(), ..Default::default() });
        }
        self.raise_full(now, pid, fd, Dest::default(), Vec::new());
    }

    // ---------------------------------------------------------------- origins

    /// Where a program file came from (cached; Mark of the Web never changes for a file).
    pub fn origin_of(&mut self, exe: &str) -> Value {
        if exe.is_empty() {
            return json!({ "kind": "windows" });
        }
        let k = exe.to_lowercase();
        if let Some(v) = self.origins.get(&k) {
            return v.clone();
        }
        let v = if self.sim { crate::origin::demo(exe) } else { crate::origin::origin(exe) };
        if self.origins.len() > 2000 {
            self.origins.clear();
        }
        self.origins.insert(k, v.clone());
        v
    }

    // ---------------------------------------------------------------- security checks

    /// Results of the periodic security check: report what changed since last time.
    pub fn apply_audit(&mut self, now: u64, mut v: Value) {
        // Kestryl's own start-up task, its publisher certificate, its temporary decryption
        // certificate and proxy: never findings.
        for it in v["startup"].as_array_mut().into_iter().flatten() {
            let exe = it["exe"].as_str().unwrap_or("").to_lowercase();
            if !exe.is_empty() && self.is_own_exe(&exe) {
                it["own"] = json!(true);
            }
        }
        // The root that signed the running kestryl.exe (matched by thumbprint, so a look-alike
        // certificate named "Kestryl" is still reported).
        let self_tp = v["selfTp"].as_str().unwrap_or("").to_string();
        if !self_tp.is_empty() {
            for r in v["roots"].as_array_mut().into_iter().flatten() {
                if r["tp"].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&self_tp)) {
                    r["own"] = json!(true);
                }
            }
        }
        if let Some(d) = crate::decrypt::current().filter(|d| !d.sim) {
            for r in v["roots"].as_array_mut().into_iter().flatten() {
                if r["tp"].as_str().is_some_and(|t| t.eq_ignore_ascii_case(&d.tp)) || r["subject"].as_str().is_some_and(|s| s.contains(crate::decrypt::SUBJECT)) {
                    r["own"] = json!(true);
                }
            }
            if v["proxy"]["server"].as_str().is_some_and(|s| s.contains(&format!("127.0.0.1:{}", d.port))) {
                v["proxy"]["own"] = json!(true);
            }
        }
        let first = !self.cfg.baseline.set || self.sim;
        let finds = crate::audit::diff(&mut self.cfg.baseline, &mut v, first, now);
        self.dirty_cfg = true;
        for fd in finds {
            self.raise_sys(now, fd, "Windows");
        }
        if let Some(ids) = v["fwRules"].as_array() {
            let ids: Vec<String> = ids.iter().filter_map(|x| x.as_str().map(String::from)).collect();
            self.fw_check(now, ids);
        }
        self.audit = v;
        self.audit_t = now;
        self.audit_error.clear();
    }

    /// "Mark as mine" on a startup entry: no longer reported as risky.
    pub fn ack_startup(&mut self, key: &str, on: bool) {
        self.cfg.baseline.ack.retain(|k| k != key);
        if on {
            self.cfg.baseline.ack.push(key.to_string());
        }
        self.dirty_cfg = true;
        if let Some(items) = self.audit["startup"].as_array_mut() {
            for it in items.iter_mut().filter(|it| it["key"].as_str() == Some(key)) {
                it["acked"] = json!(on);
                if on {
                    it["risk"] = json!("ok");
                }
            }
        }
    }

    /// Kestryl's firewall rules that disappeared without Kestryl removing them.
    pub fn fw_check(&mut self, now: u64, ids: Vec<String>) {
        let cur: HashSet<String> = ids.into_iter().collect();
        if let Some(known) = &self.fw_known {
            let gone: Vec<&String> = known.iter().filter(|k| !cur.contains(*k)).collect();
            if !gone.is_empty() && !self.sim {
                let n = gone.len();
                self.raise_sys(
                    now,
                    Finding {
                        rule: "fw_rules_removed",
                        sev: 3,
                        title: format!("{n} of Kestryl's firewall block{} {} deleted", if n == 1 { "" } else { "s" }, if n == 1 { "was" } else { "were" }),
                        why: "Blocks that Kestryl created in Windows Firewall were removed, but not from Kestryl. Malware deletes blocks so it can reach the internet again. If you removed them yourself in Windows Firewall, ignore this; otherwise check the Blocking tab and block the program again.".into(),
                        group: "fw".into(),
                    },
                    "Windows Firewall",
                );
            }
        }
        self.fw_known = Some(cur);
    }

    /// Kestryl removed these rules itself (prefix match, e.g. all script-lockdown rules).
    pub fn fw_forget(&mut self, prefix: &str) {
        if let Some(k) = self.fw_known.as_mut() {
            k.retain(|id| !id.starts_with(prefix));
        }
    }

    // ---------------------------------------------------------------- views for the UI

    fn proc_name(&self, pid: u32) -> String {
        self.procs.get(&pid).map(|p| p.name.clone()).unwrap_or_else(|| format!("pid {pid}"))
    }

    pub fn snapshot(&self, now: u64) -> Value {
        let mut per: HashMap<u32, (usize, usize, bool, usize)> = HashMap::new();
        let mut hidden_flows = 0usize;
        for (k, f) in &self.flows {
            if f.hidden {
                hidden_flows += 1;
                continue;
            }
            let e = per.entry(k.pid).or_default();
            e.0 += 1;
            if f.open {
                e.1 += 1;
            }
            if scope(&k.ip) == Scope::Internet {
                e.2 = true;
            }
            if k.inb && f.open {
                e.3 += 1;
            }
        }
        let mut alert_by: HashMap<String, usize> = HashMap::new();
        for a in self.alerts.iter().filter(|a| !a.read) {
            let k = if a.exe.is_empty() { a.name.to_lowercase() } else { a.exe.to_lowercase() };
            *alert_by.entry(k).or_default() += 1;
        }
        let procs: Vec<Value> = self
            .pstats
            .iter()
            .map(|(pid, p)| {
                let info = self.procs.get(pid);
                let v = self.view(*pid);
                let (n, open, inet, inb) = per.get(pid).copied().unwrap_or_default();
                let key = v.as_ref().map(|v| v.exe_key.clone()).unwrap_or_default();
                let sig = self.sigs.get(&key);
                let name_l = info.map(|i| i.name.to_lowercase()).unwrap_or_default();
                json!({
                    "pid": pid,
                    "name": info.map(|i| i.name.clone()).unwrap_or_else(|| format!("pid {pid}")),
                    "exe": info.map(|i| i.exe.clone()).unwrap_or_default(),
                    "cmd": info.map(|i| i.cmd.clone()).unwrap_or_default(),
                    "parent": info.map(|i| i.parent).unwrap_or(0),
                    "parent_name": info.map(|i| i.parent_name.clone()).unwrap_or_default(),
                    "exited": info.map(|i| i.exited).unwrap_or(false),
                    "sim": info.map(|i| i.sim).unwrap_or(false),
                    "sig": v.as_ref().map(|v| v.sig.clone()).unwrap_or_else(|| "pending".into()),
                    "signer": sig.map(|s| s.signer.clone()).unwrap_or_default(),
                    "class": v.as_ref().map(|v| v.class).unwrap_or(Class::Unknown),
                    "script": v.as_ref().map(|v| v.script).unwrap_or(Script::None),
                    "browser": v.as_ref().map(|v| v.browser).unwrap_or(false),
                    "trusted": self.is_trusted(&key),
                    "own": self.is_own_pid(*pid),
                    "trust_broken": self.trust_broken.contains(&key),
                    "out": p.out, "in": p.inb, "rate_out": p.rate_out, "rate_in": p.rate_in,
                    "flows": n, "open": open, "internet": inet, "incoming": inb, "last": p.last,
                    "alerts": alert_by.get(&key).copied().unwrap_or(0),
                    "services": self.services.get(pid).cloned().unwrap_or_default(),
                    "remote": detect::remote_tool(&name_l),
                    "secrets": self.secrets.get(pid).map(|h| h.len()).unwrap_or(0),
                })
            })
            .collect();
        let hist: Vec<[u64; 2]> = self.history.iter().rev().take(120).rev().copied().collect();
        json!({
            "now": now,
            "mode": self.mode,
            "elevated": self.elevated,
            "etw_error": self.etw_error,
            "sim": self.sim,
            "stats": self.stats,
            "health": self.health,
            "file_watch": self.cfg.file_watch,
            "up": self.up, "down": self.down,
            "history": hist,
            "totals": self.totals,
            "procs": procs,
            "unread": self.alerts.iter().filter(|a| !a.read).count(),
            "unread_high": self.alerts.iter().filter(|a| !a.read && a.sev >= 3).count(),
            "learning": now < self.cfg.learning_until,
            "popups": self.cfg.popups,
            "hidden_flows": hidden_flows,
            "decrypt": crate::decrypt::current(),
        })
    }

    pub fn flow_rows(&self, pid: Option<u32>) -> Value {
        let mut rows: Vec<(&FlowKey, &Flow)> =
            self.flows.iter().filter(|(k, f)| !f.hidden && pid.is_none_or(|p| k.pid == p)).collect();
        rows.sort_by(|a, b| b.1.last.cmp(&a.1.last));
        let v: Vec<Value> = rows
            .into_iter()
            .take(800)
            .map(|(k, f)| {
                let udp = k.proto == Proto::Udp;
                let domain = self.dns.get(&k.ip).cloned().unwrap_or_default();
                let (cc, org, _) = self.geo.lookup(&k.ip);
                json!({
                    "pid": k.pid, "name": self.proc_name(k.pid), "proto": k.proto,
                    "ip": k.ip.to_string(), "port": k.port, "inb": k.inb,
                    "cc": cc, "org": org, "host": crate::geo::is_host(&org),
                    "analytics": crate::analytics::is_analytics(&domain),
                    "domain": domain,
                    "service": service(k.port, udp), "enc": encryption(k.port, udp),
                    "scope": scope(&k.ip),
                    "out": f.out, "in": f.inb, "rate_out": f.rate_out, "rate_in": f.rate_in,
                    "first": f.first, "last": f.last, "open": f.open, "connects": f.connects.len(),
                    "trusted": f.trusted,
                    "safe": f.safe.map(|i| crate::safe::SERVICES[i as usize].name),
                })
            })
            .collect();
        Value::Array(v)
    }

    pub fn dns_rows(&self) -> Value {
        let v: Vec<Value> = self
            .dns_log
            .iter()
            .filter_map(|d| {
                let (trusted, hidden) = self.name_trust(&d.name);
                (!hidden).then_some((d, trusted))
            })
            .take(1500)
            .map(|(d, trusted)| {
                json!({ "t": d.t, "pid": d.pid, "proc": self.proc_name(d.pid), "name": d.name,
                        "answers": d.answers, "status": d.status, "flag": d.flag, "trusted": trusted })
            })
            .collect();
        Value::Array(v)
    }

    pub fn network_rows(&self) -> Value {
        // One row per program/port (IPv4 and IPv6 sockets merged).
        let mut merged: Vec<(&Listener, Vec<&str>)> = Vec::new();
        for l in &self.listeners {
            match merged.iter_mut().find(|(m, _)| m.pid == l.pid && m.proto == l.proto && m.port == l.port && m.exposed == l.exposed) {
                Some((_, addrs)) => addrs.push(&l.addr),
                None => merged.push((l, vec![&l.addr])),
            }
        }
        let mut ls: Vec<Value> = merged
            .into_iter()
            .map(|(l, addrs)| {
                let exe = self.procs.get(&l.pid).map(|p| p.exe.as_str()).unwrap_or("");
                json!({ "pid": l.pid, "name": self.proc_name(l.pid), "exe": exe, "proto": l.proto,
                        "addr": addrs.join(", "), "port": l.port, "exposed": l.exposed })
            })
            .collect();
        ls.sort_by_key(|v| (!v["exposed"].as_bool().unwrap_or(false), v["port"].as_u64().unwrap_or(0)));
        json!({ "adapters": self.adapters, "listeners": ls })
    }

    /// What this PC did with an address: which programs, ports, bytes, and names that pointed to it.
    pub fn ip_usage(&self, ip: IpAddr) -> Value {
        let ip = norm_ip(ip);
        let ips = ip.to_string();
        let mut flows: Vec<(&FlowKey, &Flow)> = self.flows.iter().filter(|(k, _)| k.ip == ip).collect();
        flows.sort_by(|a, b| b.1.last.cmp(&a.1.last));
        let rows: Vec<Value> = flows
            .iter()
            .map(|(k, f)| {
                json!({ "pid": k.pid, "name": self.proc_name(k.pid), "proto": k.proto, "port": k.port, "inb": k.inb,
                        "service": service(k.port, k.proto == Proto::Udp), "out": f.out, "in": f.inb,
                        "open": f.open, "last": f.last })
            })
            .collect();
        let mut names: Vec<String> = self.dns.get(&ip).cloned().into_iter().collect();
        for d in &self.dns_log {
            if d.answers.iter().any(|a| *a == ips) && !names.contains(&d.name) {
                names.push(d.name.clone());
            }
            if names.len() >= 8 {
                break;
            }
        }
        json!({ "flows": rows, "names": names })
    }

    /// Extra details for the program panel: services, sensitive files, documents.
    pub fn proc_extra(&mut self, pid: u32) -> Value {
        let docs = self.docs.get(&pid).map(|d| json!({ "n": d.seen.len(), "sample": d.sample, "collected": d.collected > 0 }));
        let exe = self.procs.get(&pid).map(|p| p.exe.clone()).unwrap_or_default();
        let origin = self.origin_of(&exe);
        json!({
            "origin": origin,
            "services": self.services.get(&pid).cloned().unwrap_or_default(),
            "secrets": self.secrets.get(&pid).cloned().unwrap_or_default(),
            "docs": docs,
            "scan": self.procs.get(&pid).and_then(|p| self.scans.get(&p.exe_key())),
        })
    }

    /// Everything the Status page needs, in one go.
    pub fn status(&mut self, now: u64) -> Value {
        // Where each program to review came from (read once per file, then cached).
        let review_keys: Vec<String> = self.known.iter().filter(|k| k.contains('\\') && !self.is_own_exe(k)).cloned().collect();
        let from: HashMap<String, Value> = review_keys.iter().map(|k| (k.clone(), self.origin_of(k))).collect();
        let map = crate::geo::data_map(&self.geo, &self.today);
        let mut v = self.status_view(now, &from);
        v["away"] = json!(self.away_reports.iter().take(10).collect::<Vec<_>>());
        v["away_now"] = json!(self.away.as_ref().map(|s| s.start));
        v["decrypt"] = json!(crate::decrypt::current());
        v["clip_guard"] = json!(self.cfg.clip_guard);
        v["analytics_on"] = json!(self.cfg.analytics.values().filter(|a| a.on).count());
        v["home"] = json!(self.home);
        v["geo"] = self.geo.info();
        v["map"] = json!({ "countries": map["countries"].as_array().map(|a| a.iter().take(6).cloned().collect::<Vec<_>>()),
                           "orgs": map["orgs"].as_array().map(|a| a.iter().take(6).cloned().collect::<Vec<_>>()), "out": map["out"] });
        v
    }

    fn status_view(&self, now: u64, from: &HashMap<String, Value>) -> Value {
        let day_ago = now.saturating_sub(24 * HOUR);
        let recent: Vec<&Alert> = self.alerts.iter().filter(|a| a.last >= day_ago).collect();
        let count = |s: u8| recent.iter().filter(|a| a.sev == s).count();
        let mut top: Vec<&&Alert> = recent.iter().filter(|a| !a.read && a.sev >= 2).collect();
        top.sort_by(|a, b| b.sev.cmp(&a.sev).then(b.last.cmp(&a.last)));
        let top: Vec<Value> = top
            .iter()
            .take(6)
            .map(|a| json!({ "id": a.id, "sev": a.sev, "rule": a.rule, "title": a.title, "name": a.name, "last": a.last, "sim": a.sim }))
            .collect();
        let week = now.saturating_sub(7 * 24 * HOUR);
        let file_alerts: Vec<Value> = self
            .alerts
            .iter()
            .filter(|a| a.last >= week && matches!(a.rule.as_str(), "secret_read" | "secret_upload" | "docs_upload"))
            .take(20)
            .map(|a| json!({ "id": a.id, "sev": a.sev, "rule": a.rule, "title": a.title, "name": a.name, "last": a.last, "read": a.read, "files": a.files }))
            .collect();
        let sessions: Vec<Value> = self
            .alerts
            .iter()
            .filter(|a| a.last >= day_ago && matches!(a.rule.as_str(), "remote_session" | "inbound"))
            .take(10)
            .map(|a| json!({ "id": a.id, "sev": a.sev, "title": a.title, "name": a.name, "last": a.last, "ip": a.ip }))
            .collect();
        let remote: Vec<Value> = self
            .remote_running
            .iter()
            .map(|(pid, name, label)| {
                let (wo, open) = match self.pstats.get(pid) {
                    Some(p) => (p.win.iter().map(|x| x.0).sum::<u64>(), self.flows.iter().any(|(k, f)| k.pid == *pid && f.open)),
                    None => (0, false),
                };
                json!({ "pid": pid, "name": name, "label": label, "out_min": wo, "online": open, "active": wo >= detect::SESSION_BYTES })
            })
            .collect();
        let incoming: Vec<Value> = self
            .flows
            .iter()
            .filter(|(k, f)| k.inb && f.open && !f.hidden)
            .take(30)
            .map(|(k, f)| json!({ "pid": k.pid, "name": self.proc_name(k.pid), "ip": k.ip.to_string(), "port": k.port,
                                  "scope": scope(&k.ip), "out": f.out, "in": f.inb, "service": service(k.port, false) }))
            .collect();
        let risky: Vec<Value> = self
            .pstats
            .keys()
            .filter_map(|pid| {
                let v = self.view(*pid)?;
                let online = self.flows.iter().any(|(k, f)| k.pid == *pid && !f.hidden && f.last + 5 * MIN > now && scope(&k.ip) == Scope::Internet);
                (online && v.shady() && !self.is_trusted(&v.exe_key) && !self.is_own_pid(*pid)).then(|| {
                    json!({ "pid": pid, "name": self.proc_name(*pid), "exe": self.procs.get(pid).map(|p| p.exe.clone()).unwrap_or_default(),
                            "sig": v.sig, "class": v.class, "script": v.script })
                })
            })
            .collect();
        let mut review: Vec<Value> = self
            .known
            .iter()
            .filter_map(|k| {
                let class = detect::classify(k);
                let sig = self.sigs.get(k);
                let st = sig.map(|s| s.status.as_str()).unwrap_or("unknown");
                if class == Class::System || (class == Class::Installed && st == "signed") || !k.contains('\\') || self.is_own_exe(k) {
                    return None;
                }
                let risk = if class == Class::Risky || st == "invalid" {
                    "high"
                } else if matches!(st, "unsigned" | "untrusted") {
                    "med"
                } else {
                    "ok"
                };
                Some(json!({ "exe": k, "class": class, "sig": st, "signer": sig.map(|s| s.signer.clone()).unwrap_or_default(),
                             "risk": risk, "trusted": self.is_trusted(k), "exists": std::path::Path::new(k).exists(),
                             "blocked": self.blocked_apps.get(&k.to_lowercase()), "from": from.get(k) }))
            })
            .collect();
        let rank = |v: &Value| match v["risk"].as_str() {
            Some("high") => 0,
            Some("med") => 1,
            _ => 2,
        };
        review.sort_by(|a, b| rank(a).cmp(&rank(b)).then(a["exe"].as_str().cmp(&b["exe"].as_str())));
        json!({
            "now": now, "mode": self.mode, "elevated": self.elevated, "sim": self.sim,
            "learning": now < self.cfg.learning_until, "etw_error": self.etw_error,
            "stats": self.stats, "health": self.health, "file_watch": self.cfg.file_watch,
            "alerts": { "high": count(3), "med": count(2), "low": count(1),
                        "unread": self.alerts.iter().filter(|a| !a.read).count(), "top": top },
            "today": history::summary(&self.today),
            "file_alerts": file_alerts,
            "remote": remote, "sessions": sessions, "incoming": incoming,
            "risky": risky,
            "known_total": self.known.len(), "review": review,
            "trust_broken": self.trust_broken.iter().collect::<Vec<_>>(),
            "audit": self.audit, "audit_t": self.audit_t, "audit_error": self.audit_error,
            "intel": { "lists": self.intel.lists, "size": self.intel.size(), "demo": self.intel.demo },
            "intel_alerts": self.alerts.iter().filter(|a| a.last >= week && matches!(a.rule.as_str(), "known_bad" | "malware_hash")).take(10)
                .map(|a| json!({ "id": a.id, "sev": a.sev, "title": a.title, "name": a.name, "last": a.last, "ip": a.ip, "domain": a.domain })).collect::<Vec<_>>(),
            "scans": { "done": self.scans.values().filter(|s| s.state != "running").count(), "queued": self.scan_queue.len(),
                       "threats": self.scans.iter().filter(|(_, s)| s.state == "threat").map(|(k, s)| json!({ "exe": k, "threat": s.threat, "t": s.t })).collect::<Vec<_>>() },
            "sensors": self.sensor_uses.iter().filter(|u| u.active() || u.stop + 30 * 24 * HOUR > now)
                .map(|u| json!({ "kind": u.kind, "app": u.app, "name": sensors::label(u), "packaged": u.packaged, "start": u.start, "stop": u.stop, "active": u.active() })).collect::<Vec<_>>(),
            "cam_alerts": self.alerts.iter().filter(|a| a.last >= week && a.rule == "cam_mic").take(10)
                .map(|a| json!({ "id": a.id, "sev": a.sev, "title": a.title, "name": a.name, "last": a.last })).collect::<Vec<_>>(),
        })
    }

    pub fn take_cfg_for_save(&mut self) -> Config {
        let mut c = self.cfg.clone();
        let mut k: Vec<String> = self.known.iter().cloned().collect();
        k.sort();
        c.known = k;
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eng() -> Engine {
        let mut e = Engine::new(Config::default(), vec![]);
        e.procs.insert(
            7,
            ProcInfo { pid: 7, name: "invoice.exe".into(), exe: r"C:\Users\a\Downloads\invoice.exe".into(), ..Default::default() },
        );
        e.sigs.insert(r"c:\users\a\downloads\invoice.exe".into(), SigInfo { status: "unsigned".into(), signer: String::new() });
        e
    }

    fn add_proc(e: &mut Engine, pid: u32, name: &str, exe: &str, sig: &str, signer: &str) {
        e.procs.insert(pid, ProcInfo { pid, name: name.into(), exe: exe.into(), ..Default::default() });
        e.sigs.insert(exe.to_lowercase(), SigInfo { status: sig.into(), signer: signer.into() });
    }

    #[test]
    fn upload_raises_once_and_groups_repeats() {
        let mut e = eng();
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        e.on_dns(1000, 7, "transfer.sh.", vec!["::ffff:203.0.113.5".parse().unwrap()], 0);
        e.on_connect(1000, 7, Proto::Tcp, ip, 443);
        let mut t = 1000;
        for _ in 0..30 {
            t += 1000;
            e.on_packet(t, 7, Proto::Tcp, ip, 443, 50001, MB, true);
            e.tick(t);
        }
        let rules: Vec<&str> = e.alerts.iter().map(|a| a.rule.as_str()).collect();
        assert!(rules.contains(&"exfil_site"), "{rules:?}");
        assert!(rules.contains(&"upload"), "{rules:?}");
        assert!(rules.contains(&"risky_folder"), "{rules:?}");
        assert_eq!(rules.iter().filter(|r| **r == "upload").count(), 1);
        let ex = e.alerts.iter().find(|a| a.rule == "exfil_site").unwrap();
        assert_eq!(ex.domain, "transfer.sh");
        assert_eq!(ex.sev, 3);
        assert!(e.notify.iter().any(|a| a.rule == "exfil_site"));
        // and the day's history has it
        assert!(e.today.rows.iter().any(|r| r.dest == "transfer.sh" && r.out == 30 * MB));
    }

    #[test]
    fn trusted_and_loopback_are_quiet() {
        let mut e = eng();
        e.cfg.trusted.push(r"c:\users\a\downloads\invoice.exe".into());
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        e.on_connect(1000, 7, Proto::Tcp, ip, 4444);
        e.on_packet(1000, 7, Proto::Tcp, "127.0.0.1".parse().unwrap(), 80, 50002, MB, true);
        e.tick(2000);
        assert!(e.alerts.iter().all(|a| a.rule == "new_app"));
        assert_eq!(e.totals[0], 0);
    }

    #[test]
    fn trusted_destinations_are_hidden_and_quiet() {
        let mut e = eng();
        // a signed program in Program Files: trusted destinations apply to it
        add_proc(&mut e, 8, "app.exe", r"C:\Program Files\App\app.exe", "signed", "App Inc");
        e.cfg.trusted_dests.push(crate::config::TrustedDest { target: "transfer.sh".into(), show: false });
        e.cfg.trusted_dests.push(crate::config::TrustedDest { target: "198.51.100.0/24".into(), show: true });
        e.rebuild_trust();
        e.on_dns(1000, 8, "eu.transfer.sh", vec!["203.0.113.5".parse().unwrap()], 0);
        e.on_connect(1000, 8, Proto::Tcp, "203.0.113.5".parse().unwrap(), 443);
        e.on_packet(1500, 8, Proto::Tcp, "203.0.113.5".parse().unwrap(), 443, 50003, 30 * MB, true);
        e.on_connect(1000, 8, Proto::Tcp, "198.51.100.7".parse().unwrap(), 4444);
        e.tick(2000);
        assert!(e.alerts.iter().all(|a| a.rule == "new_app"), "{:?}", e.alerts.iter().map(|a| &a.rule).collect::<Vec<_>>());
        assert_eq!(e.totals[0], 0, "hidden upload must not count");
        let rows = e.flow_rows(None);
        let ips: Vec<&str> = rows.as_array().unwrap().iter().map(|r| r["ip"].as_str().unwrap()).collect();
        assert_eq!(ips, vec!["198.51.100.7"], "shown trusted range stays visible, hidden one does not");
        assert_eq!(rows[0]["trusted"], true);
        assert_eq!(e.dns_rows().as_array().unwrap().len(), 0);
        // switching "show traffic" on brings it back on the next tick
        e.cfg.trusted_dests[0].show = true;
        e.rebuild_trust();
        e.tick(3000);
        assert_eq!(e.flow_rows(None).as_array().unwrap().len(), 2);
    }

    #[test]
    fn trusted_destination_never_hides_a_shady_program() {
        let mut e = eng(); // pid 7: unsigned, in Downloads
        e.cfg.trusted_dests.push(crate::config::TrustedDest { target: "drive.example".into(), show: false });
        e.rebuild_trust();
        let ip: IpAddr = "203.0.113.30".parse().unwrap();
        e.on_dns(1000, 7, "upload.drive.example", vec![ip], 0);
        e.on_connect(1000, 7, Proto::Tcp, ip, 443);
        e.on_packet(1200, 7, Proto::Tcp, ip, 443, 50004, 3 * MB, true);
        e.tick(2000);
        assert_eq!(e.totals[0], 3 * MB, "shady program's upload stays visible");
        assert!(e.alerts.iter().any(|a| a.rule == "risky_folder"), "{:?}", e.alerts.iter().map(|a| &a.rule).collect::<Vec<_>>());
        assert_eq!(e.flow_rows(None).as_array().unwrap().len(), 1);
    }

    #[test]
    fn known_safe_services_quiet_only_unusual_destination_alerts() {
        let goog = r#"{"prefixes":[{"ipv4Prefix":"142.250.0.0/15"},{"ipv4Prefix":"34.0.0.0/15"}]}"#;
        let cloud = r#"{"prefixes":[{"ipv4Prefix":"34.0.0.0/16"}]}"#;
        let run = |on: bool, pid: u32, ip: &str| {
            let mut e = eng(); // pid 7: unsigned, in Downloads
            add_proc(&mut e, 8, "app.exe", r"C:\Program Files\App\app.exe", "signed", "App Inc");
            e.known.insert(r"c:\program files\app\app.exe".into());
            e.known.insert(r"c:\users\a\downloads\invoice.exe".into());
            e.cfg.safe_on = on;
            e.set_safe(Arc::new(crate::safe::from_texts(goog, cloud, "", [0, 0], &HashMap::new())));
            let ip: IpAddr = ip.parse().unwrap();
            e.on_connect(1000, pid, Proto::Tcp, ip, 443);
            e.on_packet(1200, pid, Proto::Tcp, ip, 443, 50005, 2 * MB, true);
            e.tick(2000);
            let rows = e.flow_rows(None);
            (e.alerts.iter().map(|a| a.rule.clone()).collect::<Vec<_>>(), rows[0]["safe"].clone())
        };
        // A signed program sending to a bare Google address: tagged and quiet.
        let (rules, tag) = run(true, 8, "142.250.1.1");
        assert!(!rules.iter().any(|r| r == "bare_ip"), "{rules:?}");
        assert_eq!(tag, "Google");
        // Feature off: the same alert as before.
        let (rules, tag) = run(false, 8, "142.250.1.1");
        assert!(rules.iter().any(|r| r == "bare_ip"), "{rules:?}");
        assert!(tag.is_null());
        // A Google Cloud customer address is not Google's own.
        let (rules, tag) = run(true, 8, "34.0.1.1");
        assert!(rules.iter().any(|r| r == "bare_ip"), "{rules:?}");
        assert!(tag.is_null());
        // An unsigned program in Downloads gets no quiet, even to Google.
        let (rules, _) = run(true, 7, "142.250.1.1");
        assert!(rules.iter().any(|r| r == "bare_ip"), "{rules:?}");
    }

    #[test]
    fn update_is_announced_once_per_version() {
        let mut e = eng();
        e.cfg.popup_min = 3;
        e.announce_update(1000, "9.9.0", "### Fixed\n- Camera pop-ups.\n");
        e.announce_update(5000, "9.9.0", "");
        let a: Vec<&Alert> = e.alerts.iter().filter(|a| a.rule == "update").collect();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].title, "Kestryl 9.9.0 is available");
        assert!(a[0].why.contains("Fixed · Camera pop-ups."), "{}", a[0].why);
        assert_eq!(e.notify.len(), 1, "pops up whatever the pop-up level");
        e.announce_update(9000, "9.9.1", "");
        assert_eq!(e.alerts.iter().filter(|a| a.rule == "update").count(), 2);
    }

    #[test]
    fn own_exe_is_never_judged() {
        let mut e = eng();
        e.own_exe = r"c:\users\a\downloads\invoice.exe".into(); // pretend pid 7 is another Kestryl copy
        e.on_dns(1000, 7, "ipinfo.io", vec!["203.0.113.9".parse().unwrap()], 0);
        e.on_connect(1000, 7, Proto::Tcp, "203.0.113.9".parse().unwrap(), 443);
        e.tick(2000);
        assert!(e.alerts.is_empty(), "{:?}", e.alerts.iter().map(|a| &a.rule).collect::<Vec<_>>());
    }

    #[test]
    fn dns_burst() {
        let mut e = eng();
        for i in 0..45 {
            e.on_dns(1000 + i, 7, &format!("q{i:03}x9f2k.d.exfil-example.net"), vec![], 9003);
        }
        e.tick(2000);
        assert!(e.alerts.iter().any(|a| a.rule == "dns_tunnel" && a.sev == 3));
    }

    #[test]
    fn domain_block_learns_new_ips() {
        let mut e = eng();
        e.cfg.domain_blocks.push(crate::config::DomainBlock { domain: "bad.example".into(), id: "x".into(), ips: vec!["1.1.1.1".into()], tracker: false });
        e.on_dns(1, 7, "cdn.bad.example", vec!["2.2.2.2".parse().unwrap()], 0);
        assert_eq!(e.fw_updates, vec!["bad.example".to_string()]);
        assert_eq!(e.cfg.domain_blocks[0].ips.len(), 2);
    }

    #[test]
    fn dns_referrals_never_feed_a_domain_block() {
        let mut e = eng();
        e.cfg.domain_blocks.push(crate::config::DomainBlock {
            domain: "msn.com".into(),
            id: "x".into(),
            ips: vec!["13.69.116.110".into(), "198.41.0.4".into(), "192.41.162.30".into()],
            tracker: false,
        });
        e.clean_domain_blocks();
        assert_eq!(e.cfg.domain_blocks[0].ips, vec!["13.69.116.110".to_string()], "root and .com servers removed");
        assert_eq!(e.fw_updates, vec!["msn.com".to_string()], "the firewall rule is rewritten");
        e.fw_updates.clear();
        e.on_dns(1, 7, "browser.events.data.msn.com", vec!["199.7.83.42".parse().unwrap(), "192.48.79.30".parse().unwrap()], 0);
        e.on_dns(2, 7, "browser.events.data.msn.com", vec!["20.184.175.9".parse().unwrap()], 9003);
        assert!(e.fw_updates.is_empty() && e.cfg.domain_blocks[0].ips.len() == 1, "{:?}", e.cfg.domain_blocks[0].ips);
        e.on_dns(3, 7, "browser.events.data.msn.com", vec!["20.184.175.1".parse().unwrap()], 0);
        assert_eq!(e.cfg.domain_blocks[0].ips.len(), 2);
    }

    #[test]
    fn traffic_past_a_block_is_closed() {
        let mut e = eng();
        add_proc(&mut e, 8, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "signed", "Google LLC");
        e.set_blocks(&json!({ "rules": [
            { "id": "Kestryl-app-1", "kind": "app", "target": r"C:\Users\a\Downloads\invoice.exe", "enabled": true },
            { "id": "Kestryl-ip-2", "kind": "ip", "target": "203.0.113.0/24", "enabled": true },
            { "id": "Kestryl-ip-3", "kind": "ip", "target": "198.51.100.1", "enabled": false },
        ] }));
        e.cfg.domain_blocks.push(crate::config::DomainBlock { domain: "bad.example".into(), id: "d".into(), ips: vec![], tracker: false });
        let (blocked_net, free, off): (IpAddr, IpAddr, IpAddr) =
            ("203.0.113.7".parse().unwrap(), "93.184.216.34".parse().unwrap(), "198.51.100.1".parse().unwrap());
        e.on_packet(1000, 7, Proto::Tcp, free, 443, 50000, 900, true); // blocked program, any address
        e.on_packet(1000, 8, Proto::Tcp, blocked_net, 443, 50001, 900, true); // blocked range
        e.on_packet(1000, 8, Proto::Tcp, free, 443, 50002, 900, true); // nothing blocked
        e.on_packet(1000, 8, Proto::Tcp, off, 443, 50003, 900, true); // rule switched off
        e.tick(1500);
        let mut d = std::mem::take(&mut e.drops);
        d.sort();
        assert_eq!(d, vec![(7, free), (8, blocked_net)]);
        // A blocked domain's new address: closed as soon as it is used, before the rule catches up.
        let fresh: IpAddr = "20.184.175.1".parse().unwrap();
        e.on_dns(1600, 8, "api.bad.example", vec![fresh], 0);
        e.on_packet(1700, 8, Proto::Tcp, fresh, 443, 50004, 2261, true);
        e.on_packet(1700, 7, Proto::Tcp, free, 443, 50000, 900, true);
        e.tick(2000);
        assert_eq!(e.drops, vec![(8, fresh)], "the blocked program was closed under 2 s ago");
        e.drops.clear();
        e.tick(9000);
        assert!(e.drops.is_empty(), "nothing moved since");
        // The review list shows blocked programs as blocked.
        e.known.insert(r"c:\users\a\downloads\invoice.exe".into());
        let st = e.status(9000);
        let r = st["review"].as_array().unwrap().iter().find(|r| r["exe"] == r"c:\users\a\downloads\invoice.exe").unwrap().clone();
        assert_eq!(r["blocked"], "Kestryl-app-1");
    }

    #[test]
    fn incoming_connections_are_marked_and_judged() {
        let mut e = eng();
        add_proc(&mut e, 900, "svchost.exe", r"C:\Windows\System32\svchost.exe", "signed", "Microsoft Windows");
        e.listen_ports.insert(3389);
        let ip: IpAddr = "198.51.100.23".parse().unwrap();
        e.on_accept(1000, 900, ip, 51514, 3389);
        e.on_packet(1100, 900, Proto::Tcp, ip, 51514, 3389, 400 * KB, true);
        e.on_packet(1100, 900, Proto::Tcp, ip, 51515, 3389, 100 * KB, true); // second connection, same row
        e.tick(2000);
        let rows = e.flow_rows(None);
        let rows = rows.as_array().unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["inb"], true);
        assert_eq!(rows[0]["port"], 3389);
        assert_eq!(rows[0]["out"], 500 * KB);
        let a = e.alerts.iter().find(|a| a.rule == "inbound").expect("inbound alert");
        assert_eq!(a.sev, 3);
        // an accept on a port nobody listens on is ignored (it was an outgoing connection)
        e.on_accept(1000, 900, ip, 443, 50999);
        assert!(!e.flows.keys().any(|k| k.port == 50999));
    }

    #[test]
    fn password_read_then_upload() {
        let mut e = eng();
        add_proc(&mut e, 31, "syncsvc.exe", r"C:\Users\a\AppData\Roaming\SyncSvc\syncsvc.exe", "unsigned", "");
        add_proc(&mut e, 32, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", "signed", "Google LLC");
        let path = detect::rules().samples.iter().find(|(k, _)| k == "passwords").map(|(_, p)| p.clone()).unwrap();
        let s = detect::secret_file(&path.to_lowercase());
        e.on_file(1000, 32, path.clone(), s, false); // the browser itself: fine
        e.on_file(1000, 31, path.clone(), s, false);
        e.tick(1500);
        let read = e.alerts.iter().find(|a| a.rule == "secret_read").expect("secret_read");
        assert_eq!(read.sev, 3);
        assert_eq!(read.pid, 31);
        assert_eq!(read.files, vec![path.clone()]);
        let ip: IpAddr = "203.0.113.60".parse().unwrap();
        e.on_dns(2000, 31, "api.storage-sync.example", vec![ip], 0);
        e.on_connect(2000, 31, Proto::Tcp, ip, 443);
        e.on_packet(2500, 31, Proto::Tcp, ip, 443, 50010, 180 * KB, true);
        e.tick(3000);
        let up = e.alerts.iter().find(|a| a.rule == "secret_upload").expect("secret_upload");
        assert_eq!(up.sev, 3);
        assert_eq!(up.domain, "api.storage-sync.example");
        assert_eq!(e.alerts.iter().filter(|a| a.rule.starts_with("secret")).count(), 2);
    }

    #[test]
    fn documents_collected_then_uploaded() {
        let mut e = eng();
        add_proc(&mut e, 41, "helper.exe", r"C:\Users\a\AppData\Roaming\Helper\helper.exe", "unsigned", "");
        for i in 0..25 {
            e.on_file(1000 + i, 41, format!(r"C:\Users\a\Documents\file{i}.docx"), None, true);
        }
        e.tick(2000);
        assert!(e.alerts.is_empty());
        let ip: IpAddr = "203.0.113.90".parse().unwrap();
        e.on_packet(2500, 41, Proto::Tcp, ip, 443, 50020, 3 * MB, true);
        e.tick(3000);
        let a = e.alerts.iter().find(|a| a.rule == "docs_upload").expect("docs_upload");
        assert_eq!(a.sev, 3);
        assert!(a.title.contains("25"));
    }

    #[test]
    fn remote_tool_streaming_the_screen() {
        let mut e = eng();
        add_proc(&mut e, 51, "AnyDesk.exe", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", "signed", "philandro Software GmbH");
        let ip: IpAddr = "203.0.113.70".parse().unwrap();
        e.on_connect(1000, 51, Proto::Tcp, ip, 443);
        for t in 1..=10 {
            e.on_packet(1000 + t * 1000, 51, Proto::Tcp, ip, 443, 50030, 120 * KB, true);
            e.tick(1000 + t * 1000);
        }
        let a = e.alerts.iter().find(|a| a.rule == "remote_session").expect("remote_session");
        assert_eq!(a.sev, 3);
        assert!(a.title.starts_with("AnyDesk"));
    }

    #[test]
    fn replaced_trusted_program_loses_trust() {
        let mut e = eng();
        add_proc(&mut e, 61, "tool.exe", r"C:\Program Files\Tool\tool.exe", "signed", "Tool Ltd");
        let key = r"c:\program files\tool\tool.exe".to_string();
        e.cfg.trusted.push(key.clone());
        for t in 1..=10 {
            e.tick(t * 1000);
        }
        assert_eq!(e.cfg.trusted_fp.get(&key).map(String::as_str), Some("signed:Tool Ltd"));
        assert!(e.is_trusted(&key));
        e.sigs.insert(key.clone(), SigInfo { status: "invalid".into(), signer: String::new() });
        for t in 11..=20 {
            e.tick(t * 1000);
        }
        assert!(!e.is_trusted(&key));
        assert!(e.alerts.iter().any(|a| a.rule == "trust_broken" && a.sev == 3));
    }

    #[test]
    fn short_lived_programs_are_named_and_grouped() {
        let mut e = eng();
        let path = detect::rules().samples.iter().find(|(k, _)| k == "keys").map(|(_, p)| p.clone()).unwrap();
        let s = detect::secret_file(&path.to_lowercase());
        // 50 helper runs of a tool in its real install folder: named from the start event, owner -> silent
        for i in 0..50u32 {
            let pid = 5000 + i;
            e.on_proc_start(1000, pid, 4, r"C:\Program Files\Docker\Docker\resources\bin\docker.exe".into());
            e.on_file(1000, pid, path.clone(), s, false);
        }
        // 50 unidentifiable ones (no start event, no process): one quiet grouped note
        for i in 0..50u32 {
            e.on_file(1000, 7000 + i, path.clone(), s, false);
        }
        e.procs.extend((0..50u32).map(|i| (7000 + i, ProcInfo { pid: 7000 + i, name: format!("pid {}", 7000 + i), exited: true, ..Default::default() })));
        e.tick(1500);
        // the helper's signature check comes back: Docker Inc, in Program Files -> its own file, silent
        assert!(e.sig_queue.iter().any(|q| q.ends_with("docker.exe")));
        e.sigs.insert(r"c:\program files\docker\docker\resources\bin\docker.exe".into(), SigInfo { status: "signed".into(), signer: "Docker Inc".into() });
        e.tick(9000);
        let reads: Vec<&Alert> = e.alerts.iter().filter(|a| a.rule == "secret_read").collect();
        assert_eq!(reads.len(), 1, "{:?}", reads.iter().map(|a| (&a.name, a.sev)).collect::<Vec<_>>());
        assert_eq!(reads[0].sev, 1);
        assert!(reads[0].count >= 1);
        assert!(e.notify.is_empty(), "no pop-ups for these");
        assert!(e.procs.get(&5000).is_some_and(|p| p.name == "docker.exe"));
        assert!(e.file_pending.is_empty(), "everything judged");
    }

    #[test]
    fn popup_flood_guard_and_cap_keep_high_alerts() {
        let mut e = eng();
        let fd = |sev: u8, g: &str| Finding { rule: "inbound", sev, title: "t".into(), why: "w".into(), group: g.to_string() };
        e.raise_sys(1000, fd(3, "keep-me"), "Windows");
        for i in 0..700 {
            e.raise_sys(2000 + i, fd(2, &format!("g{i}")), "Windows");
        }
        assert_eq!(e.alerts.len(), 500);
        assert!(e.alerts.iter().any(|a| a.key.ends_with("keep-me")), "the high alert survives the flood");
        assert_eq!(e.notify.len(), 1, "one pop-up per rule and program every 10 minutes");
    }

    #[test]
    fn other_builds_of_kestryl_are_kestryl() {
        let mut e = eng();
        e.own_exe = r"c:\proj\kestryl\src-tauri\target\release\kestryl.exe".into();
        e.own_root = own_root(&e.own_exe);
        assert_eq!(e.own_root, r"c:\proj\kestryl\src-tauri\target\");
        assert!(e.is_own_exe(r"c:\proj\kestryl\src-tauri\target\debug\kestryl.exe"));
        assert!(e.is_own_exe(r"c:\proj\kestryl\src-tauri\target\release\kestryl.v5.exe"));
        assert!(!e.is_own_exe(r"c:\users\a\downloads\kestryl.exe"));
        e.procs.insert(70, ProcInfo { pid: 70, name: "kestryl.exe".into(), exe: r"C:\proj\kestryl\src-tauri\target\debug\kestryl.exe".into(), ..Default::default() });
        e.on_dns(1000, 70, "ipinfo.io", vec!["203.0.113.9".parse().unwrap()], 0);
        e.on_connect(1000, 70, Proto::Tcp, "203.0.113.9".parse().unwrap(), 443);
        e.tick(20_000);
        assert!(e.alerts.is_empty(), "{:?}", e.alerts.iter().map(|a| &a.rule).collect::<Vec<_>>());
        assert_eq!(own_root(r"c:\tools\kestryl\kestryl.exe"), r"c:\tools\kestryl\");
    }

    #[test]
    fn own_publisher_root_is_not_a_finding() {
        let mut e = eng();
        let sample = || {
            json!({
                "defender": { "rtp": true, "sigAge": 1 }, "exclOk": true, "exclusions": [],
                "firewall": [{ "name": "Private", "on": true }],
                "roots": [{ "tp": "AA", "subject": "CN=Good Root", "key": false }],
                "proxy": { "on": false, "server": "", "pac": "", "winhttp": "" }, "hosts": [], "startup": [], "dns": [],
                "rdp": false, "fwRules": [], "selfTp": "",
            })
        };
        e.apply_audit(1000, sample()); // first look: the baseline, silent
        let mut v = sample();
        let roots = v["roots"].as_array_mut().unwrap();
        roots.push(json!({ "tp": "BB", "subject": "CN=Kestryl", "key": false })); // signed kestryl.exe
        roots.push(json!({ "tp": "CC", "subject": "CN=Kestryl", "key": false })); // a look-alike
        v["selfTp"] = json!("bb");
        e.apply_audit(2000, v);
        let found: Vec<&String> = e.alerts.iter().filter(|a| a.rule == "root_cert").map(|a| &a.title).collect();
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(e.audit["roots"][1]["own"], true);
        assert!(e.audit["roots"][2]["own"].is_null());
    }

    #[test]
    fn firewall_rules_removed_elsewhere() {
        let mut e = eng();
        e.fw_check(1000, vec!["Kestryl-app-1".into(), "Kestryl-script-2".into(), "Kestryl-ip-3".into()]);
        e.fw_forget("Kestryl-script-");
        e.fw_check(2000, vec!["Kestryl-app-1".into()]);
        let a = e.alerts.iter().find(|a| a.rule == "fw_rules_removed").expect("alert");
        assert!(a.title.starts_with("1 of"), "{}", a.title); // only the ip rule; the script one was ours
        assert!(a.system);
    }

    #[test]
    fn camera_use_by_unexpected_programs() {
        let mut e = eng();
        let now = 10 * MIN;
        e.sigs.insert(r"c:\users\a\appdata\local\temp\x.exe".into(), SigInfo { status: "unsigned".into(), signer: String::new() });
        e.sigs.insert(r"c:\users\a\appdata\local\programs\chat\chat.exe".into(), SigInfo { status: "signed".into(), signer: "Chat Inc".into() });
        let u = |app: &str, stop: u64| Use { kind: "camera", app: app.into(), packaged: false, start: now - 5000, stop };
        e.on_sensors(now, vec![
            u(r"C:\Users\a\AppData\Local\Temp\x.exe", 0),
            u(r"C:\Users\a\AppData\Local\Programs\Chat\chat.exe", 0),
            u(r"C:\Program Files\Zoom\bin\Zoom.exe", 0),
            u(r"C:\Users\a\AppData\Local\Temp\old.exe", now - 1000),
        ]);
        let cam: Vec<&Alert> = e.alerts.iter().filter(|a| a.rule == "cam_mic").collect();
        assert_eq!(cam.len(), 2, "{cam:?}"); // Zoom is expected, old.exe is no longer on
        assert!(cam.iter().any(|a| a.sev == 3 && a.name == "x.exe"));
        assert!(cam.iter().any(|a| a.sev == 1 && a.name == "chat.exe"));
        e.on_sensors(now + 3000, vec![u(r"C:\Users\a\AppData\Local\Temp\x.exe", 0)]);
        assert_eq!(e.alerts.iter().filter(|a| a.rule == "cam_mic").count(), 2); // still on: no repeat
    }

    #[test]
    fn camera_notice_for_browsers_and_call_apps() {
        let mut e = eng();
        e.cfg.popup_min = 3; // the notice pops up whatever the pop-up level
        let now = 10 * MIN;
        let chrome = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
        let cam = |app: &str, packaged: bool, start: u64, stop: u64| Use { kind: "camera", app: app.into(), packaged, start, stop };
        e.on_sensors(now, vec![cam(chrome, false, now - 2000, 0), cam("Microsoft.WindowsCamera_8wekyb3d8bbwe", true, now - 2000, 0)]);
        let n: Vec<&Alert> = e.alerts.iter().filter(|a| a.rule == "cam_mic_use").collect();
        assert_eq!(n.len(), 2, "{n:?}");
        assert!(n.iter().any(|a| a.title == "Google Chrome turned on your camera" && a.sev == 1));
        assert!(n.iter().any(|a| a.name == "WindowsCamera"));
        assert_eq!(e.notify.len(), 2);
        // Still on: nothing new. Off, then on again two minutes later: one more pop-up, same alert.
        e.notify.clear();
        e.on_sensors(now + 3000, vec![cam(chrome, false, now - 2000, 0)]);
        assert!(e.notify.is_empty());
        e.on_sensors(now + 6000, vec![cam(chrome, false, now - 2000, now + 5000)]);
        e.on_sensors(now + 2 * MIN, vec![cam(chrome, false, now + 2 * MIN - 1000, 0)]);
        assert_eq!(e.notify.len(), 1);
        assert_eq!(e.alerts.iter().filter(|a| a.rule == "cam_mic_use").count(), 2);
        // Microphone notices are off by default, and the camera ones can be turned off.
        e.notify.clear();
        e.on_sensors(now + 3 * MIN, vec![Use { kind: "microphone", app: chrome.into(), packaged: false, start: now + 3 * MIN - 1000, stop: 0 }]);
        assert!(e.notify.is_empty());
        e.cfg.cam_notify = false;
        e.on_sensors(now + 20 * MIN, vec![]);
        e.on_sensors(now + 21 * MIN, vec![cam(chrome, false, now + 21 * MIN - 1000, 0)]);
        assert!(e.notify.is_empty());
    }

    #[test]
    fn known_malware_server_from_a_list() {
        let mut e = eng();
        add_proc(&mut e, 300, "ok.exe", r"C:\Program Files\Ok\ok.exe", "signed", "Ok Inc");
        e.cfg.trusted.push(r"c:\program files\ok\ok.exe".into()); // even a trusted program is reported
        e.set_intel(Arc::new(crate::intel::demo()));
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        e.on_connect(MIN, 300, Proto::Tcp, ip, 4444);
        e.tick(MIN + 1000);
        let a = e.alerts.iter().find(|a| a.rule == "known_bad").expect("alert");
        assert_eq!(a.sev, 3);
        assert!(a.why.contains("AsyncRAT"), "{}", a.why);
        e.on_dns(2 * MIN, 300, "api.storage-sync.net", vec![], 0);
        e.tick(2 * MIN + 1000);
        assert!(e.alerts.iter().any(|a| a.rule == "known_bad" && a.domain == "api.storage-sync.net"));
    }

    #[test]
    fn programs_kestryl_runs_itself_never_alert() {
        let mut e = eng();
        // A PowerShell that Kestryl started for its own check, going online and opening files.
        add_proc(&mut e, 4242, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "signed", "Microsoft Windows");
        crate::util::own_child_started(4242);
        let ip: IpAddr = "203.0.113.44".parse().unwrap();
        e.on_dns(MIN, 4242, "api.ipify.org", vec![ip], 0);
        e.on_connect(MIN, 4242, Proto::Tcp, ip, 4444);
        e.on_packet(MIN, 4242, Proto::Tcp, ip, 4444, 50010, 30 * MB, true);
        e.tick(MIN + 1000);
        crate::util::own_child_exited(4242);
        e.tick(MIN + 2000);
        assert!(e.alerts.is_empty(), "{:?}", e.alerts.iter().map(|a| &a.rule).collect::<Vec<_>>());
        assert!(!e.known.contains(r"c:\windows\system32\windowspowershell\v1.0\powershell.exe"), "not learnt as a program that goes online");
        // The same PowerShell started by someone else is judged as usual.
        add_proc(&mut e, 4343, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "signed", "Microsoft Windows");
        e.on_connect(MIN, 4343, Proto::Tcp, ip, 4444);
        e.tick(MIN + 3000);
        assert!(e.alerts.iter().any(|a| a.pid == 4343 && a.rule == "bad_port"));
    }

    #[test]
    fn reused_process_id_does_not_blame_the_old_program() {
        let mut e = eng();
        let cfg = r"C:\Users\a\.docker\config.json".to_string();
        let s = detect::secret_file(&cfg.to_lowercase());
        assert!(s.is_some());
        // A PowerShell check Kestryl ran a while ago: gone, its record kept for its traffic.
        add_proc(&mut e, 4646, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "signed", "Microsoft Windows");
        e.procs.get_mut(&4646).unwrap().exited = true;
        e.procs.get_mut(&4646).unwrap().gone = 10_000;
        // A short-lived helper got the same id and read a key file; its start event comes late.
        e.on_file(20_000, 4646, cfg.clone(), s, false);
        e.tick(20_500);
        let docker = r"C:\Program Files\Docker\Docker\resources\bin\docker.exe";
        e.on_proc_start(21_000, 4646, 4, docker.into());
        e.sigs.insert(docker.to_lowercase(), SigInfo { status: "signed".into(), signer: "Docker Inc".into() });
        e.tick(21_500);
        assert!(!e.alerts.iter().any(|a| a.name == "powershell.exe"), "{:?}", e.alerts.iter().map(|a| &a.title).collect::<Vec<_>>());
        // A program that read the file just before it exited is still judged.
        add_proc(&mut e, 4747, "grabber.exe", r"C:\Users\a\Downloads\grabber.exe", "unsigned", "");
        e.procs.get_mut(&4747).unwrap().exited = true;
        e.procs.get_mut(&4747).unwrap().gone = 30_000;
        e.on_file(31_000, 4747, cfg.clone(), s, false);
        e.tick(31_500);
        assert!(e.alerts.iter().any(|a| a.rule == "secret_read" && a.name == "grabber.exe"));
    }

    #[test]
    fn reused_id_of_a_kestryl_check_is_not_trusted() {
        crate::util::own_child_started(4848);
        crate::util::own_child_exited(4848);
        let now = crate::util::now_ms();
        let mut e = eng();
        // The quick check's own start event, arriving just after it exited.
        e.on_proc_start(now + 500, 4848, 4, r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into());
        assert!(crate::util::is_own_child(4848));
        // A different program that got the same id later is judged like any other.
        e.on_proc_start(now + 10_000, 4848, 4, r"C:\Users\a\Downloads\evil.exe".into());
        assert!(!crate::util::is_own_child(4848));
    }

    #[test]
    fn away_report_counts_what_was_sent() {
        let mut e = eng(); // pid 7: unsigned, in Downloads
        add_proc(&mut e, 8, "OneDrive.exe", r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "signed", "Microsoft Corporation");
        let t0 = 100 * MIN;
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        e.on_dns(t0, 7, "upload.example.net", vec![ip], 0);
        e.on_presence(t0, true, 0); // locked
        for i in 0..10 {
            e.on_packet(t0 + i * 1000, 7, Proto::Tcp, ip, 443, 50020, 300 * KB, true);
            e.on_packet(t0 + i * 1000, 8, Proto::Tcp, "203.0.113.6".parse().unwrap(), 443, 50021, 5 * MB, true);
            e.tick(t0 + i * 1000);
        }
        e.on_presence(t0 + 30 * MIN, false, 1000); // back
        let r = e.away_reports.front().expect("a report");
        assert_eq!(r.why, "locked");
        assert_eq!(r.out, 10 * 300 * KB + 50 * MB);
        let up = r.progs.iter().find(|p| p.name == "invoice.exe").unwrap();
        assert!(up.flagged, "unsigned program in Downloads sending while away");
        assert_eq!(up.dests[0].dest, "example.net");
        assert!(!r.progs.iter().find(|p| p.name == "OneDrive.exe").unwrap().flagged);
        let a = e.alerts.iter().find(|a| a.rule == "away_upload").expect("alert");
        assert_eq!(a.sev, 2);
        assert!(a.title.contains("30 min"), "{}", a.title);
        // A short absence is not reported.
        e.on_presence(t0 + 40 * MIN, true, 0);
        e.on_presence(t0 + 41 * MIN, false, 0);
        assert_eq!(e.away_reports.len(), 1);
    }

    #[test]
    fn clipboard_swap_is_caught() {
        let mut e = eng();
        let seen = |t, hash, owner: u32, exe: &str, fg| crate::clip::Seen { t, kind: "Bitcoin address", hash, masked: format!("bc1q…{hash}"), owner, owner_exe: exe.into(), fg };
        // You copy an address in the browser, then copy another one there: fine.
        e.on_clipboard(seen(1000, 1, 50, r"C:\Program Files\Google\Chrome\Application\chrome.exe", 50));
        e.on_clipboard(seen(2000, 2, 50, r"C:\Program Files\Google\Chrome\Application\chrome.exe", 50));
        assert!(e.alerts.is_empty());
        // A background program replaces it 300 ms later.
        e.on_clipboard(seen(9000, 3, 50, r"C:\Program Files\Google\Chrome\Application\chrome.exe", 50));
        e.on_clipboard(seen(9300, 4, 7, r"C:\Users\a\Downloads\invoice.exe", 50));
        let a = e.alerts.iter().find(|a| a.rule == "clipboard_swap").expect("alert");
        assert_eq!((a.sev, a.pid), (3, 7));
        assert!(a.why.contains("bc1q…3") && a.why.contains("bc1q…4"), "{}", a.why);
        // Switched off: nothing.
        let mut e = eng();
        e.cfg.clip_guard = false;
        e.on_clipboard(seen(1000, 1, 50, "", 50));
        e.on_clipboard(seen(1200, 2, 7, "", 50));
        assert!(e.alerts.is_empty());
    }
}
