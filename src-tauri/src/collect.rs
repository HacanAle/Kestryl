//! Data sources: ETW (kernel network + DNS client, and kernel file opens), socket-table
//! polling, process details, Windows services, Authenticode checks, and the --simulate feed.

use crate::detect;
use crate::engine::{lock, Listener, ProcInfo, Proto, Shared, SigInfo};
use crate::history::Day;
use crate::util::*;
use ferrisetw::parser::Parser;
use ferrisetw::provider::{EventFilter, Provider};
use ferrisetw::trace::{LoggingMode, TraceProperties};
use ferrisetw::{EventRecord, SchemaLocator, UserTrace};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::OnceLock;
use std::time::Duration;

pub const SESSION: &str = "Kestryl-Monitor";
pub const FILE_SESSION: &str = "Kestryl-Files";
const KERNEL_NETWORK: &str = "7dd42a49-5329-4832-8dfd-43d979153a88";
const DNS_CLIENT: &str = "1c95126e-7eea-49a9-a3fe-a378b03ddb4d";
const KERNEL_FILE: &str = "edd08927-9cc4-4e65-b970-c2560fb5c289";
const KERNEL_PROCESS: &str = "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716";

/// File-open events seen (all of them, before filtering).
pub static FILE_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Starts one real-time ETW session (needs admin). Events arrive on ferrisetw's thread.
/// Process starts are an extra; if Windows refuses them, monitoring starts without.
pub fn start_etw(eng: &Shared) -> Result<(), String> {
    match start_session(eng, true) {
        Ok(()) => Ok(()),
        Err(first) => {
            log(&format!("ETW session with process starts failed ({first}); starting without them"));
            start_session(eng, false)
        }
    }
}

fn start_session(eng: &Shared, with_procs: bool) -> Result<(), String> {
    let _ = ferrisetw::trace::stop_trace_by_name(SESSION); // left over from a crash
    let e1 = eng.clone();
    let net = Provider::by_guid(KERNEL_NETWORK)
        .any(0x30) // IPv4 | IPv6
        .level(5)
        .add_filter(EventFilter::ByEventIds(vec![10, 11, 12, 15, 26, 27, 28, 31, 42, 43, 58, 59]))
        .add_callback(move |r: &EventRecord, s: &SchemaLocator| on_net(&e1, r, s))
        .build();
    let e2 = eng.clone();
    let dns = Provider::by_guid(DNS_CLIENT)
        .any(u64::MAX)
        .level(5)
        .add_filter(EventFilter::ByEventIds(vec![3008]))
        .add_callback(move |r: &EventRecord, s: &SchemaLocator| on_dns(&e2, r, s))
        .build();
    let mut builder = UserTrace::new().named(SESSION.to_string()).enable(net).enable(dns);
    if with_procs {
        // Process starts: the path of every program as it starts, so even ones that exit
        // within a second (a stealer, Docker's helpers) have a name and a parent.
        let e3 = eng.clone();
        let procs = Provider::by_guid(KERNEL_PROCESS)
            .any(0x10) // WINEVENT_KEYWORD_PROCESS
            .level(4)
            .add_filter(EventFilter::ByEventIds(vec![1]))
            .add_callback(move |r: &EventRecord, s: &SchemaLocator| on_proc_start(&e3, r, s))
            .build();
        builder = builder.enable(procs);
    }
    let trace = builder.start_and_process().map_err(|e| format!("{e:?}"))?;
    // Dropping the handle would stop the session; it lives until stop_etw().
    Box::leak(Box::new(trace));
    Ok(())
}

pub fn stop_etw() {
    let _ = ferrisetw::trace::stop_trace_by_name(SESSION);
}

/// Second session for file opens (busy: kept apart so it can never crowd out network events).
pub fn start_files(eng: &Shared) -> Result<(), String> {
    let _ = ferrisetw::trace::stop_trace_by_name(FILE_SESSION);
    let e = eng.clone();
    let prov = Provider::by_guid(KERNEL_FILE)
        .any(0x80) // KERNEL_FILE_KEYWORD_CREATE
        .level(4)
        .add_filter(EventFilter::ByEventIds(vec![12]))
        .add_callback(move |r: &EventRecord, s: &SchemaLocator| on_file(&e, r, s))
        .build();
    let props = TraceProperties {
        buffer_size: 64,
        min_buffer: 16,
        max_buffer: 128,
        flush_timer: Duration::from_secs(1),
        log_file_mode: LoggingMode::EVENT_TRACE_REAL_TIME_MODE,
    };
    let trace = UserTrace::new()
        .named(FILE_SESSION.to_string())
        .set_trace_properties(props)
        .enable(prov)
        .start_and_process()
        .map_err(|e| format!("{e:?}"))?;
    Box::leak(Box::new(trace));
    Ok(())
}

pub fn stop_files() {
    let _ = ferrisetw::trace::stop_trace_by_name(FILE_SESSION);
}

/// Is an ETW session still running? Ok((events lost, real-time buffers lost)) or the
/// Windows error (4201 = no such session: someone stopped it).
#[cfg(windows)]
pub fn session_query(name: &str) -> Result<(u32, u32), u32> {
    use windows::Win32::System::Diagnostics::Etw::{ControlTraceW, CONTROLTRACE_HANDLE, EVENT_TRACE_CONTROL_QUERY, EVENT_TRACE_PROPERTIES};
    #[repr(C)]
    struct Props {
        p: EVENT_TRACE_PROPERTIES,
        names: [u16; 1024],
    }
    let mut props: Props = unsafe { std::mem::zeroed() };
    props.p.Wnode.BufferSize = std::mem::size_of::<Props>() as u32;
    props.p.LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
    props.p.LogFileNameOffset = props.p.LoggerNameOffset + 1024;
    let w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let r = unsafe { ControlTraceW(CONTROLTRACE_HANDLE { Value: 0 }, windows::core::PCWSTR(w.as_ptr()), &mut props.p, EVENT_TRACE_CONTROL_QUERY) };
    if r.0 == 0 {
        Ok((props.p.EventsLost, props.p.RealTimeBuffersLost))
    } else {
        Err(r.0)
    }
}
#[cfg(not(windows))]
pub fn session_query(_name: &str) -> Result<(u32, u32), u32> {
    Err(1)
}

fn parse_ip(p: &Parser, name: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = p.try_parse::<IpAddr>(name) {
        return Ok(ip);
    }
    if let Ok(raw) = p.try_parse::<u32>(name) {
        return Ok(IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes())));
    }
    match p.try_parse::<Vec<u8>>(name) {
        Ok(b) if b.len() == 16 => {
            let a: [u8; 16] = b.try_into().unwrap_or([0; 16]);
            Ok(IpAddr::V6(Ipv6Addr::from(a)))
        }
        Ok(b) => Err(format!("{name}: {} bytes", b.len())),
        Err(e) => Err(format!("{name}: {e:?}")),
    }
}

fn on_net(eng: &Shared, r: &EventRecord, s: &SchemaLocator) {
    let id = r.event_id();
    let (proto, kind) = match id {
        10 | 26 => (Proto::Tcp, 0u8),
        11 | 27 => (Proto::Tcp, 1),
        12 | 28 => (Proto::Tcp, 2),
        15 | 31 => (Proto::Tcp, 3), // accepted: another device connected to us
        42 | 58 => (Proto::Udp, 0),
        43 | 59 => (Proto::Udp, 1),
        _ => return,
    };
    let parsed = (|| -> Result<(u32, u32, IpAddr, u16, IpAddr, u16), String> {
        let schema = s.event_schema(r).map_err(|e| format!("schema: {e:?}"))?;
        let p = Parser::create(r, &schema);
        let pid: u32 = p.try_parse("PID").unwrap_or_else(|_| r.process_id());
        let size: u32 = p.try_parse("size").map_err(|e| format!("size: {e:?}"))?;
        let daddr = parse_ip(&p, "daddr")?;
        let saddr = parse_ip(&p, "saddr")?;
        let dport: u16 = p.try_parse("dport").map_err(|e| format!("dport: {e:?}"))?;
        let sport: u16 = p.try_parse("sport").map_err(|e| format!("sport: {e:?}"))?;
        // Ports are logged in network byte order.
        Ok((pid, size, daddr, u16::from_be(dport), saddr, u16::from_be(sport)))
    })();
    let now = now_ms();
    let mut e = lock(eng);
    e.stats.events += 1;
    match parsed {
        Ok((pid, size, daddr, dport, saddr, sport)) => {
            // daddr is normally the remote end; if it is one of our own addresses, flip.
            let (ip, port, lport) =
                if e.is_local(&daddr) && !e.is_local(&saddr) { (saddr, sport, dport) } else { (daddr, dport, sport) };
            // During HTTPS decryption Kestryl's proxy makes the connections for a program:
            // its bytes are that program's, not Kestryl's.
            let pid = if pid == e.own_pid { crate::decrypt::client_of(lport).unwrap_or(pid) } else { pid };
            match kind {
                0 => e.on_packet(now, pid, proto, ip, port, lport, size as u64, true),
                1 => e.on_packet(now, pid, proto, ip, port, lport, size as u64, false),
                2 => e.on_connect(now, pid, proto, ip, port),
                _ => e.on_accept(now, pid, ip, port, lport),
            }
        }
        Err(m) => {
            e.stats.parse_errors += 1;
            if e.stats.last_error.is_empty() {
                e.stats.last_error = format!("event {id}: {m}");
                log(&format!("ETW parse error, event {id}: {m}"));
            }
        }
    }
}

pub fn parse_dns_results(s: &str) -> Vec<IpAddr> {
    s.split(';')
        .filter_map(|x| {
            let x = x.trim();
            x.strip_prefix("::ffff:").unwrap_or(x).parse::<IpAddr>().ok()
        })
        .collect()
}

fn on_dns(eng: &Shared, r: &EventRecord, s: &SchemaLocator) {
    if r.event_id() != 3008 {
        return;
    }
    let Ok(schema) = s.event_schema(r) else { return };
    let p = Parser::create(r, &schema);
    let name: String = p.try_parse("QueryName").unwrap_or_default();
    let status: u32 = p.try_parse("QueryStatus").unwrap_or(0);
    let results: String = p.try_parse("QueryResults").unwrap_or_default();
    let ips = parse_dns_results(&results);
    lock(eng).on_dns(now_ms(), r.process_id(), &name, ips, status);
}

fn on_proc_start(eng: &Shared, r: &EventRecord, s: &SchemaLocator) {
    if r.event_id() != 1 {
        return;
    }
    let Ok(schema) = s.event_schema(r) else { return };
    let p = Parser::create(r, &schema);
    let (Ok(pid), Ok(image)) = (p.try_parse::<u32>("ProcessID"), p.try_parse::<String>("ImageName")) else { return };
    let ppid: u32 = p.try_parse("ParentProcessID").unwrap_or(0);
    let exe = display_path(&image);
    lock(eng).on_proc_start(now_ms(), pid, ppid, exe);
}

/// Every file open on the PC passes through here; only the few that match a password,
/// cookie, wallet, key or document pattern are handed to the engine.
fn on_file(eng: &Shared, r: &EventRecord, s: &SchemaLocator) {
    FILE_EVENTS.fetch_add(1, Ordering::Relaxed);
    if r.event_id() != 12 {
        return;
    }
    let Ok(schema) = s.event_schema(r) else { return };
    let p = Parser::create(r, &schema);
    let Ok(name) = p.try_parse::<String>("FileName") else { return };
    let lower = name.to_ascii_lowercase();
    let secret = detect::secret_file(&lower);
    let doc = secret.is_none() && detect::user_doc(&lower);
    if secret.is_none() && !doc {
        return;
    }
    let path = display_path(&name);
    lock(eng).on_file(now_ms(), r.process_id(), path, secret, doc);
}

/// "\Device\HarddiskVolume3" -> "C:" for every drive letter.
fn device_map() -> &'static Vec<(String, String)> {
    static M: OnceLock<Vec<(String, String)>> = OnceLock::new();
    M.get_or_init(|| {
        #[allow(unused_mut)]
        let mut v = Vec::new();
        #[cfg(windows)]
        for l in b'A'..=b'Z' {
            let drive = format!("{}:", l as char);
            let w: Vec<u16> = drive.encode_utf16().chain(Some(0)).collect();
            let mut buf = [0u16; 512];
            let n = unsafe { windows::Win32::Storage::FileSystem::QueryDosDeviceW(windows::core::PCWSTR(w.as_ptr()), Some(&mut buf)) };
            if n > 0 {
                let end = buf.iter().position(|&c| c == 0).unwrap_or(n as usize);
                v.push((String::from_utf16_lossy(&buf[..end]).to_ascii_lowercase(), drive));
            }
        }
        v
    })
}

/// Kernel file path -> normal path with a drive letter.
pub fn display_path(p: &str) -> String {
    let l = p.to_ascii_lowercase();
    for (dev, drive) in device_map() {
        if l.starts_with(dev.as_str()) && l.as_bytes().get(dev.len()) == Some(&b'\\') {
            return format!("{drive}{}", &p[dev.len()..]);
        }
    }
    p.to_string()
}

/// Running Windows services per process id ("svchost.exe" -> which services it hosts).
#[cfg(windows)]
pub fn service_map() -> HashMap<u32, Vec<String>> {
    use windows::core::PCWSTR;
    use windows::Win32::System::Services::{
        CloseServiceHandle, EnumServicesStatusExW, OpenSCManagerW, ENUM_SERVICE_STATUS_PROCESSW, SC_ENUM_PROCESS_INFO,
        SC_MANAGER_ENUMERATE_SERVICE, SERVICE_ACTIVE, SERVICE_WIN32,
    };
    let mut map: HashMap<u32, Vec<String>> = HashMap::new();
    unsafe {
        let Ok(scm) = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ENUMERATE_SERVICE) else { return map };
        let (mut need, mut count, mut resume) = (0u32, 0u32, 0u32);
        let _ = EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, None, &mut need, &mut count, Some(&mut resume), PCWSTR::null());
        if need > 0 {
            // u64 storage: the records hold pointers and must be 8-byte aligned.
            let mut store = vec![0u64; (need as usize + 8192) / 8];
            let buf = std::slice::from_raw_parts_mut(store.as_mut_ptr() as *mut u8, store.len() * 8);
            resume = 0;
            if EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_ACTIVE, Some(buf), &mut need, &mut count, Some(&mut resume), PCWSTR::null()).is_ok() {
                let items = std::slice::from_raw_parts(store.as_ptr() as *const ENUM_SERVICE_STATUS_PROCESSW, count as usize);
                for it in items {
                    let pid = it.ServiceStatusProcess.dwProcessId;
                    if pid == 0 {
                        continue;
                    }
                    let disp = it.lpDisplayName.to_string().unwrap_or_default();
                    let name = it.lpServiceName.to_string().unwrap_or_default();
                    map.entry(pid).or_default().push(if disp.is_empty() { name } else { disp });
                }
            }
        }
        let _ = CloseServiceHandle(scm);
    }
    map
}
#[cfg(not(windows))]
pub fn service_map() -> HashMap<u32, Vec<String>> {
    HashMap::new()
}

/// Socket tables every 2 s: open TCP connections and listening ports.
pub fn poll_loop(eng: Shared, count_new: bool) {
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
    loop {
        let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
        let pf = ProtocolFlags::TCP | ProtocolFlags::UDP;
        if let Ok(socks) = get_sockets_info(af, pf) {
            let mut open = HashSet::new();
            let mut listen = Vec::new();
            for s in socks {
                let pid = s.associated_pids.first().copied().unwrap_or(0);
                match s.protocol_socket_info {
                    ProtocolSocketInfo::Tcp(t) => match t.state {
                        TcpState::Established => {
                            open.insert((pid, norm_ip(t.remote_addr), t.remote_port, t.local_port));
                        }
                        TcpState::Listen => listen.push(Listener {
                            pid,
                            proto: Proto::Tcp,
                            addr: t.local_addr.to_string(),
                            port: t.local_port,
                            exposed: !t.local_addr.is_loopback(),
                        }),
                        _ => {}
                    },
                    ProtocolSocketInfo::Udp(u) => {
                        if u.local_port < 49152 {
                            listen.push(Listener {
                                pid,
                                proto: Proto::Udp,
                                addr: u.local_addr.to_string(),
                                port: u.local_port,
                                exposed: !u.local_addr.is_loopback(),
                            });
                        }
                    }
                }
            }
            let mut e = lock(&eng);
            let mut ports: HashSet<u16> = listen.iter().filter(|l| l.proto == Proto::Tcp && l.exposed).map(|l| l.port).collect();
            if e.sim {
                ports.insert(3389); // the demo's fake Remote Desktop server
            }
            e.listen_ports = ports;
            e.sync_open(now_ms(), open, count_new);
            e.listeners = listen;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn make_info(sys: &sysinfo::System, pid: u32) -> ProcInfo {
    use sysinfo::Pid;
    match pid {
        0 => return ProcInfo { pid, name: "System Idle".into(), ..Default::default() },
        4 => return ProcInfo { pid, name: "System".into(), ..Default::default() },
        _ => {}
    }
    match sys.process(Pid::from_u32(pid)) {
        Some(p) => {
            let parent = p.parent().map(|x| x.as_u32()).unwrap_or(0);
            ProcInfo {
                pid,
                name: p.name().to_string_lossy().into_owned(),
                exe: p.exe().map(|x| x.display().to_string()).unwrap_or_default(),
                cmd: p.cmd().iter().map(|s| s.to_string_lossy()).collect::<Vec<_>>().join(" "),
                parent,
                parent_name: sys
                    .process(Pid::from_u32(parent))
                    .map(|pp| pp.name().to_string_lossy().into_owned())
                    .unwrap_or_default(),
                started: p.start_time(),
                exited: false,
                gone: 0,
                sim: false,
            }
        }
        None => ProcInfo { pid, name: format!("pid {pid}"), exited: true, ..Default::default() },
    }
}

/// Resolves process details for new PIDs, notices exits / PID reuse, and keeps the
/// lists of running remote-control tools and Windows services current.
pub fn proc_loop(eng: Shared, sig_tx: Sender<String>) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let mut sys = System::new();
    let kind = ProcessRefreshKind::nothing()
        .with_exe(UpdateKind::OnlyIfNotSet)
        .with_cmd(UpdateKind::OnlyIfNotSet);
    let mut last_full = 0u64;
    let mut last_svc = 0u64;
    loop {
        let (want, queued) = {
            let mut e = lock(&eng);
            (e.unknown_pids(), std::mem::take(&mut e.sig_queue))
        };
        for p in queued {
            let _ = sig_tx.send(p);
        }
        let now = now_ms();
        if now >= last_svc + 30_000 {
            last_svc = now;
            let svc = service_map();
            let mut e = lock(&eng);
            let keep: Vec<(u32, Vec<String>)> = if e.sim { e.services.iter().filter(|(p, _)| **p >= 90000).map(|(p, v)| (*p, v.clone())).collect() } else { vec![] };
            e.services = svc;
            e.services.extend(keep);
        }
        if !want.is_empty() || now >= last_full + 5000 {
            sys.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
            last_full = now;
            let infos: Vec<ProcInfo> = want.iter().map(|&pid| make_info(&sys, pid)).collect();
            let alive: HashMap<u32, u64> = sys.processes().iter().map(|(pid, p)| (pid.as_u32(), p.start_time())).collect();
            let remote: Vec<(u32, String, &'static str)> = sys
                .processes()
                .iter()
                .filter_map(|(pid, p)| {
                    let n = p.name().to_string_lossy().into_owned();
                    detect::remote_tool(&n.to_lowercase()).map(|l| (pid.as_u32(), n, l))
                })
                .collect();
            let mut e = lock(&eng);
            for mut i in infos {
                if i.exited && i.exe.is_empty() {
                    if let Some(s) = e.info_from_start(i.pid) {
                        i = ProcInfo { exited: true, ..s }; // gone already, but its start was seen
                    }
                }
                if i.exited {
                    i.gone = now;
                }
                if !i.exe.is_empty() {
                    let k = i.exe_key();
                    if !e.sigs.contains_key(&k) {
                        e.sigs.insert(k, SigInfo { status: "pending".into(), signer: String::new() });
                        let _ = sig_tx.send(i.exe.clone());
                    }
                }
                e.procs.insert(i.pid, i);
            }
            let mut reused = Vec::new();
            for (pid, p) in e.procs.iter_mut() {
                if p.sim || *pid == 0 || *pid == 4 {
                    continue;
                }
                match alive.get(pid) {
                    None if !p.exited => {
                        p.exited = true;
                        p.gone = now;
                    }
                    None => {}
                    Some(st) if p.started != 0 && *st != p.started => reused.push(*pid),
                    _ => {}
                }
            }
            for pid in reused {
                e.procs.remove(&pid);
            }
            let sim_remote: Vec<(u32, String, &'static str)> = e.remote_running.iter().filter(|r| r.0 >= 90000 && e.sim).cloned().collect();
            e.remote_running = remote;
            e.remote_running.extend(sim_remote);
        }
        std::thread::sleep(Duration::from_millis(700));
    }
}

/// Authenticode checks in batches through PowerShell (also covers catalog-signed Windows files).
pub fn sig_loop(eng: Shared, rx: Receiver<String>) {
    while let Ok(first) = rx.recv() {
        std::thread::sleep(Duration::from_millis(300));
        let mut batch = vec![first];
        while let Ok(p) = rx.try_recv() {
            batch.push(p);
            if batch.len() >= 60 {
                break;
            }
        }
        let list = batch.iter().map(|p| ps_quote(p)).collect::<Vec<_>>().join(",");
        let script = format!(
            r#"$o = foreach ($f in @({list})) {{
  try {{
    $s = Get-AuthenticodeSignature -LiteralPath $f; $n = ''
    if ($s.SignerCertificate) {{ $n = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }}
    [pscustomobject]@{{ p = $f; s = [string]$s.Status; n = $n }}
  }} catch {{ [pscustomobject]@{{ p = $f; s = 'Error'; n = '' }} }}
}}
ConvertTo-Json -InputObject @($o) -Compress"#
        );
        let res: Vec<serde_json::Value> = match run_ps(&script) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
            Err(e) => {
                log(&format!("signature check failed: {e}"));
                vec![]
            }
        };
        let mut e = lock(&eng);
        for p in &batch {
            let hit = res.iter().find(|v| v["p"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(p)));
            let (status, signer) = match hit {
                Some(v) => {
                    let st = match v["s"].as_str().unwrap_or("") {
                        "Valid" => "signed",
                        "NotSigned" => "unsigned",
                        "HashMismatch" => "invalid",
                        "NotTrusted" => "untrusted",
                        _ => "unknown",
                    };
                    (st.to_string(), v["n"].as_str().unwrap_or("").to_string())
                }
                None => ("unknown".to_string(), String::new()),
            };
            // Unsigned programs and anything in temp or download folders also get a Defender scan.
            let class = detect::classify(&p.to_lowercase());
            let scan = class != detect::Class::System && (class == detect::Class::Risky || matches!(status.as_str(), "unsigned" | "invalid" | "untrusted"));
            e.sigs.insert(p.to_lowercase(), SigInfo { status, signer });
            if scan && std::path::Path::new(p).is_file() {
                e.queue_scan(p);
            }
        }
    }
}

/// `--simulate`: fake programs doing bad things, to see alerts and pop-ups without real malware.
pub fn simulate(eng: Shared) {
    std::thread::sleep(Duration::from_secs(2));
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "user".into());
    let home = format!(r"C:\Users\{user}");
    let procs: [(u32, &str, String, &str, &str, &str); 8] = [
        (90001, "invoice_viewer.exe", format!(r"{home}\Downloads\invoice_viewer.exe"), "unsigned", "", "invoice_viewer.exe --silent"),
        (90002, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(), "signed", "Microsoft Windows", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA..."),
        (90003, "updater.exe", format!(r"{home}\AppData\Roaming\updater.exe"), "unsigned", "", "updater.exe"),
        (90004, "svc_helper.exe", format!(r"{home}\AppData\Local\Temp\svc_helper.exe"), "unsigned", "", "svc_helper.exe -q"),
        (90005, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(), "signed", "Google LLC", "chrome.exe"),
        (90006, "syncsvc.exe", format!(r"{home}\AppData\Roaming\SyncSvc\syncsvc.exe"), "unsigned", "", "syncsvc.exe /background"),
        (90007, "AnyDesk.exe", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe".into(), "signed", "philandro Software GmbH", "\"C:\\Program Files (x86)\\AnyDesk\\AnyDesk.exe\" --control"),
        (90008, "svchost.exe", r"C:\Windows\System32\svchost.exe".into(), "signed", "Microsoft Windows", "svchost.exe -k NetworkService -s TermService"),
    ];
    let ip = |s: &str| s.parse::<IpAddr>().unwrap();
    let now = now_ms();
    {
        let mut e = lock(&eng);
        e.set_intel(std::sync::Arc::new(crate::intel::demo()));
        for (pid, name, exe, sig, signer, cmd) in &procs {
            e.procs.insert(
                *pid,
                ProcInfo {
                    pid: *pid,
                    name: name.to_string(),
                    exe: exe.clone(),
                    cmd: cmd.to_string(),
                    parent: if *pid == 90008 { 90009 } else { 90000 },
                    parent_name: if *pid == 90008 { "services.exe".into() } else { "explorer.exe".into() },
                    started: 1,
                    exited: false,
                    gone: 0,
                    sim: true,
                },
            );
            e.sigs.insert(exe.to_lowercase(), SigInfo { status: sig.to_string(), signer: signer.to_string() });
            e.known.insert(exe.to_lowercase());
        }
        e.services.insert(90008, vec!["Remote Desktop Services".into()]);
        // Defender scans of the unsigned demo programs (made-up results), and camera / microphone use.
        for p in [format!(r"{home}\Downloads\invoice_viewer.exe"), format!(r"{home}\AppData\Roaming\SyncSvc\syncsvc.exe")] {
            e.queue_scan(&p);
        }
        let hr = 3_600_000;
        e.on_sensors(now, vec![
            crate::sensors::Use { kind: "microphone", app: format!(r"{home}\AppData\Roaming\updater.exe"), packaged: false, start: now - 90_000, stop: 0 },
            crate::sensors::Use { kind: "camera", app: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(), packaged: false, start: now - 26 * hr, stop: now - 25 * hr },
            crate::sensors::Use { kind: "camera", app: "Microsoft.WindowsCamera_8wekyb3d8bbwe".into(), packaged: true, start: now - 72 * hr, stop: now - 71 * hr },
        ]);
        e.remote_running.push((90007, "AnyDesk.exe".into(), "AnyDesk"));
        e.listen_ports.insert(3389);
        for i in 0..9 {
            e.on_connect(now - (8 - i) * 30_000, 90003, Proto::Tcp, ip("198.51.100.7"), 4444);
        }
        e.on_packet(now, 90003, Proto::Tcp, ip("198.51.100.7"), 4444, 50100, 2400, true);
        e.on_dns(now, 90002, "api.ipify.org", vec![ip("203.0.113.20")], 0);
        e.on_connect(now, 90002, Proto::Tcp, ip("203.0.113.20"), 443);
        e.on_dns(now, 90002, "api.telegram.org", vec![ip("203.0.113.21")], 0);
        e.on_connect(now, 90002, Proto::Tcp, ip("203.0.113.21"), 443);
        e.on_packet(now, 90002, Proto::Tcp, ip("203.0.113.21"), 443, 50101, 350 * KB, true);
        for i in 0..45u64 {
            let q = format!("{:016x}{:08x}.d.exfil-example.net", fnv(&i.to_string()), i * 7919);
            e.on_dns(now + i, 90004, &q, vec![], 9003);
        }
        e.on_dns(now, 90001, "transfer.sh", vec![ip("203.0.113.5")], 0);
        e.on_connect(now, 90001, Proto::Tcp, ip("203.0.113.5"), 443);
        e.on_dns(now, 90001, "smtp.mail-relay.example", vec![ip("203.0.113.80")], 0);
        e.on_connect(now, 90001, Proto::Tcp, ip("203.0.113.80"), 587);
        e.on_packet(now, 90001, Proto::Tcp, ip("203.0.113.80"), 587, 50102, 60 * KB, true);
        e.on_dns(now, 90005, "www.google.com", vec![ip("203.0.113.50")], 0);
        e.on_connect(now, 90005, Proto::Tcp, ip("203.0.113.50"), 443);
        // A stealer in a vendor-looking AppData folder reads browser passwords, then uploads.
        for kind in ["passwords", "browser_key", "cookies", "telegram"] {
            if let Some((_, p)) = detect::rules().samples.iter().find(|(k, _)| k == kind) {
                let f = p.replace(r"\Device\HarddiskVolume3", "C:").replace(r"C:\Users\a", &home);
                let s = detect::secret_file(&f.to_lowercase());
                e.on_file(now, 90006, f, s, false);
            }
        }
        // A program in Temp collects documents and photos.
        for i in 0..30 {
            let f = if i % 2 == 0 { format!(r"{home}\Documents\Scans\passport_{i}.pdf") } else { format!(r"{home}\Pictures\IMG_{:04}.jpg", 2000 + i) };
            e.on_file(now, 90004, f, None, true);
        }
        // Someone on the internet opens Remote Desktop to this PC.
        e.on_accept(now, 90008, ip("198.51.100.23"), 51514, 3389);
        // A demo-only change found by the security check.
        e.raise_sys(
            now,
            detect::Finding {
                rule: "startup_new",
                sev: 3,
                title: "New program set to start with Windows: updater".into(),
                why: format!(r"HKCU Run: {home}\AppData\Roaming\updater.exe --hidden. Starting with Windows is how most malware survives a restart. This one runs from a bare AppData folder and is unsigned. If you didn't just install something, check it in Task Manager → Startup apps, Task Scheduler, or Autoruns."),
                group: "sim-startup".into(),
            },
            "Windows",
        );
        // A made-up yesterday for the History tab, with something sent at night.
        let (today, _) = local_day_hour();
        if let Some(n) = day_number(&today) {
            let mut d = Day::new(day_string(n - 1));
            let t0 = now - 24 * 3600 * 1000;
            let up = format!(r"{home}\AppData\Roaming\updater.exe").to_lowercase();
            d.add(&up, "updater.exe", "198.51.100.7", "198.51.100.7", 4444, false, false, 46 * MB, 300 * KB, 3, t0);
            d.add(r"c:\program files\google\chrome\application\chrome.exe", "chrome.exe", "googlevideo.com", "203.0.113.51", 443, false, false, 12 * MB, 900 * MB, 20, t0);
            d.add(r"c:\program files\google\chrome\application\chrome.exe", "chrome.exe", "google.com", "203.0.113.50", 443, false, false, 3 * MB, 40 * MB, 10, t0);
            d.add("system", "System", "192.168.1.20", "192.168.1.20", 445, true, true, 120 * MB, 2 * MB, 14, t0);
            d.add(r"c:\program files\microsoft onedrive\onedrive.exe", "OneDrive.exe", "live.com", "203.0.113.50", 443, false, false, 260 * MB, 5 * MB, 2, t0);
            e.sim_days.push(d);
        }
        // Last night while the PC was locked: OneDrive synced, and the unsigned updater sent data.
        let t1 = now - 9 * 3_600_000;
        let r = crate::away::Report {
            id: t1 + 2 * 3_600_000,
            start: t1,
            end: t1 + 2 * 3_600_000 + 25 * 60_000,
            why: "locked".into(),
            out: 214 * MB,
            inn: 31 * MB,
            flagged: true,
            sim: true,
            progs: vec![
                crate::away::ProgReport {
                    key: format!(r"{home}\AppData\Roaming\updater.exe").to_lowercase(),
                    name: "updater.exe".into(),
                    out: 46 * MB,
                    inn: 300 * KB,
                    flagged: true,
                    dests: vec![crate::away::DestReport { dest: "198.51.100.7".into(), cc: "RU".into(), org: "Bulletproof Networks".into(), out: 46 * MB }],
                    ..Default::default()
                },
                crate::away::ProgReport {
                    key: r"c:\program files\microsoft onedrive\onedrive.exe".into(),
                    name: "OneDrive.exe".into(),
                    out: 168 * MB,
                    inn: 30 * MB,
                    dests: vec![crate::away::DestReport { dest: "live.com".into(), cc: "NL".into(), org: "Microsoft".into(), out: 168 * MB }],
                    ..Default::default()
                },
            ],
        };
        e.away_reports.push_front(r);
        // A clipper swapping a copied Bitcoin address.
        let user_copy = crate::clip::Seen {
            t: now,
            kind: "Bitcoin address",
            hash: 1,
            masked: "bc1qxy…0wlh".into(),
            owner: 90005,
            owner_exe: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
            fg: 90005,
        };
        e.on_clipboard(user_copy);
        e.on_clipboard(crate::clip::Seen {
            t: now + 420,
            kind: "Bitcoin address",
            hash: 2,
            masked: "bc1qxy…9wlh".into(),
            owner: 90006,
            owner_exe: format!(r"{home}\AppData\Roaming\SyncSvc\syncsvc.exe"),
            fg: 90005,
        });
    }
    let mut i = 0u64;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        let t = now_ms();
        let mut e = lock(&eng);
        if i < 25 {
            e.on_packet(t, 90001, Proto::Tcp, ip("203.0.113.5"), 443, 50103, 1_400_000, true);
            e.on_packet(t, 90001, Proto::Tcp, ip("203.0.113.5"), 443, 50103, 9_000, false);
        }
        if i == 4 {
            e.on_dns(t, 90006, "api.storage-sync.net", vec![ip("203.0.113.60")], 0);
            e.on_connect(t, 90006, Proto::Tcp, ip("203.0.113.60"), 443);
            e.on_packet(t, 90006, Proto::Tcp, ip("203.0.113.60"), 443, 50104, 184 * KB, true);
            e.on_packet(t, 90006, Proto::Tcp, ip("203.0.113.60"), 443, 50104, 3 * KB, false);
        }
        if (6..12).contains(&i) {
            e.on_packet(t, 90004, Proto::Tcp, ip("203.0.113.90"), 443, 50105, 600 * KB, true);
        }
        if i < 45 {
            e.on_dns(t, 90007, "relay-7f3a.net.anydesk.com", vec![ip("203.0.113.70")], 0);
            e.on_packet(t, 90007, Proto::Tcp, ip("203.0.113.70"), 443, 50106, 150 * KB, true);
            e.on_packet(t, 90007, Proto::Tcp, ip("203.0.113.70"), 443, 50106, 4 * KB, false);
            e.on_packet(t, 90008, Proto::Tcp, ip("198.51.100.23"), 51514, 3389, 90 * KB, true);
            e.on_packet(t, 90008, Proto::Tcp, ip("198.51.100.23"), 51514, 3389, 6 * KB, false);
        }
        e.on_packet(t, 90005, Proto::Tcp, ip("203.0.113.50"), 443, 50107, 3_000 + (i % 7) * 1500, true);
        e.on_packet(t, 90005, Proto::Tcp, ip("203.0.113.50"), 443, 50107, 40_000 + (i % 5) * 30_000, false);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn dns_results() {
        let v = super::parse_dns_results("type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800:220:1::248;");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].to_string(), "93.184.216.34");
    }

    #[test]
    fn device_paths_and_services() {
        let p = super::display_path(r"\Device\HarddiskVolume999\x.txt");
        assert_eq!(p, r"\Device\HarddiskVolume999\x.txt", "unknown device stays as is");
        let sys = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
        let mapped = super::device_map().iter().find(|(_, d)| d.eq_ignore_ascii_case(&sys)).cloned();
        if let Some((dev, drive)) = mapped {
            let k = format!("{dev}\\Users\\a\\x.txt");
            assert_eq!(super::display_path(&k), format!("{drive}\\Users\\a\\x.txt"));
        }
        let svc = super::service_map();
        assert!(svc.values().flatten().count() > 10, "running services: {}", svc.len());
    }
}
