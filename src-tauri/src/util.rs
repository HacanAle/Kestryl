use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

pub const KB: u64 = 1024;
pub const MB: u64 = 1024 * 1024;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Local date ("2026-11-13") and hour (0-23) right now.
#[cfg(windows)]
pub fn local_day_hour() -> (String, usize) {
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    (format!("{:04}-{:02}-{:02}", t.wYear, t.wMonth, t.wDay), t.wHour as usize)
}
#[cfg(not(windows))]
pub fn local_day_hour() -> (String, usize) {
    let s = now_ms() / 1000;
    let (y, m, d) = civil_from_days((s / 86400) as i64);
    (format!("{y:04}-{m:02}-{d:02}"), ((s % 86400) / 3600) as usize)
}

/// Days since 1970-01-01 for a date (proleptic Gregorian).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m as i64 + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

pub fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { yoe + era * 400 + 1 } else { yoe + era * 400 }, m, d)
}

/// "2026-11-13" -> days since epoch.
pub fn day_number(day: &str) -> Option<i64> {
    let mut it = day.split('-');
    let y = it.next()?.parse().ok()?;
    let m = it.next()?.parse().ok()?;
    let d = it.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d))
}

pub fn day_string(n: i64) -> String {
    let (y, m, d) = civil_from_days(n);
    format!("{y:04}-{m:02}-{d:02}")
}

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) -> plain IPv4, so DNS answers and sockets agree.
pub fn norm_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        _ => ip,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Loopback,
    Lan,
    Multicast,
    Internet,
}

pub fn scope(ip: &IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v) => scope_v4(v),
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return scope_v4(&v4);
            }
            let s0 = v.segments()[0];
            if v.is_loopback() || v.is_unspecified() {
                Scope::Loopback
            } else if s0 & 0xff00 == 0xff00 {
                Scope::Multicast
            } else if s0 & 0xffc0 == 0xfe80 || s0 & 0xfe00 == 0xfc00 {
                Scope::Lan
            } else {
                Scope::Internet
            }
        }
    }
}

fn scope_v4(v: &Ipv4Addr) -> Scope {
    let o = v.octets();
    if v.is_loopback() || v.is_unspecified() {
        Scope::Loopback
    } else if v.is_multicast() || v.is_broadcast() {
        Scope::Multicast
    } else if v.is_private() || v.is_link_local() || (o[0] == 100 && (o[1] & 0xc0) == 64) {
        Scope::Lan
    } else {
        Scope::Internet
    }
}

/// "1.2.3.4", "1.2.3.0/24", "2001:db8::/32" -> (address, prefix length).
pub fn parse_net(s: &str) -> Option<(IpAddr, u8)> {
    let (a, m) = s.trim().split_once('/').unwrap_or((s.trim(), ""));
    let ip = norm_ip(a.trim().parse().ok()?);
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = if m.is_empty() { max } else { m.trim().parse::<u8>().ok().filter(|l| *l <= max)? };
    Some((ip, len))
}

pub fn net_contains(net: &(IpAddr, u8), ip: &IpAddr) -> bool {
    match (net.0, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let m = if net.1 == 0 { 0 } else { u32::MAX << (32 - net.1) };
            u32::from(n) & m == u32::from(*i) & m
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let m = if net.1 == 0 { 0 } else { u128::MAX << (128 - net.1) };
            u128::from(n) & m == u128::from(*i) & m
        }
        _ => false,
    }
}

/// Shannon entropy in bits per character.
pub fn entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut c = [0u32; 256];
    for b in s.bytes() {
        c[b as usize] += 1;
    }
    let n = s.len() as f64;
    c.iter()
        .filter(|&&x| x > 0)
        .map(|&x| {
            let p = x as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// "a.b.example.co.uk" -> "example.co.uk", "x.y.example.com" -> "example.com" (rough, no PSL).
pub fn base_domain(name: &str) -> String {
    let n = name.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = n.split('.').collect();
    let l = labels.len();
    if l <= 2 {
        return n;
    }
    let sld = labels[l - 2];
    let cc = labels[l - 1].len() == 2;
    let take = if cc
        && matches!(
            sld,
            "co" | "com" | "net" | "org" | "gov" | "edu" | "ac" | "or" | "ne" | "go" | "gr" | "lg" | "ad" | "ed"
        ) {
        3
    } else {
        2
    };
    labels[l - take..].join(".")
}

/// true when `name` is `suffix` or a subdomain of it.
pub fn domain_is(name: &str, suffix: &str) -> bool {
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

pub fn service(port: u16, udp: bool) -> &'static str {
    if udp {
        return match port {
            53 => "DNS",
            67 | 68 => "DHCP",
            123 => "NTP",
            137 | 138 => "NetBIOS",
            443 => "QUIC",
            500 | 4500 => "IPsec",
            1194 => "OpenVPN",
            1900 => "SSDP",
            3478..=3481 | 19302..=19309 => "STUN",
            5353 => "mDNS",
            5355 => "LLMNR",
            51820 => "WireGuard",
            _ => "",
        };
    }
    match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 587 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        465 => "SMTPS",
        853 => "DNS over TLS",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "SQL Server",
        3306 => "MySQL",
        3389 => "Remote Desktop",
        5222 | 5223 => "XMPP",
        5228 => "Google push",
        5432 => "PostgreSQL",
        5938 => "TeamViewer",
        6379 => "Redis",
        7680 => "Delivery Optimization",
        8080 => "HTTP alt",
        8443 => "HTTPS alt",
        9001 | 9030 => "Tor relay",
        9050 | 9150 => "Tor proxy",
        _ => "",
    }
}

/// What we can say about encryption from the port alone (payloads are never read).
pub fn encryption(port: u16, udp: bool) -> &'static str {
    if udp {
        return match port {
            443 => "encrypted (QUIC)",
            51820 => "encrypted (WireGuard)",
            500 | 4500 => "encrypted (IPsec)",
            53 | 123 | 137 | 138 | 1900 | 5353 | 5355 => "plain",
            _ => "unknown",
        };
    }
    match port {
        443 | 8443 | 465 | 993 | 995 | 853 | 5223 | 5228 => "encrypted (TLS)",
        22 => "encrypted (SSH)",
        3389 => "encrypted (RDP)",
        20 | 21 | 23 | 25 | 80 | 110 | 143 | 8080 => "plain text",
        _ => "unknown",
    }
}

pub fn fmt_bytes(b: u64) -> String {
    let f = b as f64;
    if b >= 1 << 30 {
        format!("{:.1} GB", f / 1073741824.0)
    } else if b >= MB {
        format!("{:.1} MB", f / 1048576.0)
    } else if b >= KB {
        format!("{:.0} KB", f / 1024.0)
    } else {
        format!("{b} B")
    }
}

pub fn fmt_secs(s: f64) -> String {
    if s >= 120.0 {
        format!("{:.0} min", s / 60.0)
    } else {
        format!("{s:.0} s")
    }
}

/// PowerShell single-quoted literal. PowerShell also ends a single-quoted string at the
/// typographic quotes ‘ ’ ‚ ‛ (U+2018 to U+201B), so those are doubled as well: a program
/// file named `a’;code;’.exe` must stay one string and never run as code (Kestryl passes
/// the paths of every program it sees to an elevated PowerShell).
pub fn ps_quote(s: &str) -> String {
    let mut q = String::with_capacity(s.len() + 2);
    q.push('\'');
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            q.push(c);
        }
        q.push(c);
    }
    q.push('\'');
    q
}

/// The Windows folder from the API. Never from %SystemRoot% / %windir%: per-user environment
/// variables (HKCU\Environment) can override those, and any program the user runs can set them.
#[cfg(windows)]
pub fn windows_dir() -> std::path::PathBuf {
    let mut buf = [0u16; 260];
    let n = unsafe { windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n > buf.len() {
        return std::path::PathBuf::from(r"C:\Windows");
    }
    std::path::PathBuf::from(String::from_utf16_lossy(&buf[..n]))
}
#[cfg(not(windows))]
pub fn windows_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:\Windows")
}

/// A program in System32 by full path. A bare name ("powershell.exe") would be looked up in
/// Kestryl's own folder first, where another program could have put a file of that name.
pub fn system_exe(rel: &str) -> std::path::PathBuf {
    windows_dir().join("System32").join(rel)
}

/// "C:\Program Files", read from HKLM (only administrators can change it), not %ProgramFiles%.
pub fn program_files() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        let k = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows\CurrentVersion");
        if let Ok(p) = k.and_then(|k| k.get_value::<String, _>("ProgramFilesDir")) {
            if !p.trim().is_empty() {
                return std::path::PathBuf::from(p.trim());
            }
        }
    }
    let win = windows_dir();
    let drive = win.to_string_lossy().chars().take(2).collect::<String>();
    std::path::PathBuf::from(format!(r"{drive}\Program Files"))
}

/// true when `path` is inside Program Files or the Windows folder, which only
/// administrators can change.
pub fn in_protected_dir(path: &str) -> bool {
    let p = path.to_lowercase();
    [program_files(), windows_dir()].iter().any(|d| {
        let d = d.to_string_lossy().trim_end_matches('\\').to_lowercase();
        !d.is_empty() && p.starts_with(&format!("{d}\\"))
    })
}

pub fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        s.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    s
}

/// Programs Kestryl started itself (PowerShell checks, Defender scans, Packet Monitor), by
/// process id, with the time they exited (0 = still running). Their traffic and file opens
/// are Kestryl's own work and never raise alerts. Kept as an explicit list rather than
/// "parent is Kestryl", because malware can fake its parent process id.
static OWN_CHILDREN: std::sync::Mutex<Vec<(u32, u64)>> = std::sync::Mutex::new(Vec::new());

pub fn own_child_started(pid: u32) {
    let mut v = OWN_CHILDREN.lock().unwrap_or_else(|p| p.into_inner());
    let now = now_ms();
    // Exited a while ago: its events are long processed, and the id may be reused.
    v.retain(|(p, t)| *p != pid && (*t == 0 || *t + 120_000 > now));
    v.push((pid, 0));
}

pub fn own_child_exited(pid: u32) {
    let mut v = OWN_CHILDREN.lock().unwrap_or_else(|p| p.into_inner());
    for e in v.iter_mut().filter(|e| e.0 == pid && e.1 == 0) {
        e.1 = now_ms();
    }
}

/// A new process got the id of a program Kestryl ran earlier: it is not Kestryl's. (The start
/// event of a very quick check can arrive just after it exited, hence the margin.)
pub fn own_child_reused(pid: u32, now: u64) {
    let mut v = OWN_CHILDREN.lock().unwrap_or_else(|p| p.into_inner());
    v.retain(|(p, t)| !(*p == pid && *t != 0 && *t + 3000 < now));
}

/// Started by Kestryl, and running or exited less than two minutes ago (events about it can
/// arrive a little late).
pub fn is_own_child(pid: u32) -> bool {
    let now = now_ms();
    OWN_CHILDREN.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|(p, t)| *p == pid && (*t == 0 || *t + 120_000 > now))
}

/// `Command::output()` for a program Kestryl runs itself: registered as Kestryl's own while it runs.
pub fn own_output(cmd: &mut std::process::Command) -> std::io::Result<std::process::Output> {
    use std::process::Stdio;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    let child = cmd.spawn()?;
    let pid = child.id();
    own_child_started(pid);
    let out = child.wait_with_output();
    own_child_exited(pid);
    out
}

/// `Command::spawn()` for a program Kestryl starts and does not wait for (explorer.exe).
pub fn own_spawn(cmd: &mut std::process::Command) -> std::io::Result<()> {
    let child = cmd.spawn()?;
    own_child_started(child.id());
    Ok(())
}

/// Reads the script from stdin as UTF-8 bytes and runs it. Not `-Command -`: that decodes stdin
/// with the console code page, whose best-fit mapping turns quote look-alikes (U+2019) into a
/// real ' and would break `ps_quote`.
const PS_BOOT: &str = "$m = New-Object IO.MemoryStream; [Console]::OpenStandardInput().CopyTo($m); . ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString($m.ToArray())))";

/// Starts a hidden PowerShell running `script`. The script goes as plain UTF-8 text through
/// stdin to a short bootstrap: no length limit (a command line stops at 32,767 characters) and
/// never a temp file (Kestryl runs elevated, and a file could be swapped before PowerShell reads
/// it). No -EncodedCommand / base64 and no -ExecutionPolicy Bypass: that combination is what
/// malware loaders use, so antivirus heuristics flagged Kestryl as a backdoor. Neither is
/// needed: `-Command` text is not subject to the execution policy, and Windows' own modules
/// load under every policy.
fn ps_spawn(script: &str) -> std::io::Result<std::process::Child> {
    use std::process::Stdio;
    // Modules only from Windows' own folders (the user's Documents\WindowsPowerShell\Modules
    // would otherwise come first, and a fake "NetSecurity" there would run as administrator),
    // and the system folders from the API, not from variables the user can override.
    let wrapped = format!(
        "$env:PSModulePath = (Join-Path $PSHOME 'Modules') + ';' + (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'WindowsPowerShell\\Modules')\n$env:SystemRoot = [Environment]::GetFolderPath('Windows'); $env:windir = $env:SystemRoot\n$env:ProgramFiles = [Environment]::GetFolderPath('ProgramFiles'); $env:ProgramData = [Environment]::GetFolderPath('CommonApplicationData')\n$ProgressPreference='SilentlyContinue'\n[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false\ntry {{\n$ErrorActionPreference='Stop'\n{script}\n}} catch {{ [Console]::Out.Write('ERR:' + $_.Exception.Message); exit 1 }}"
    );
    let win = windows_dir();
    let ps_home = win.join(r"System32\WindowsPowerShell\v1.0");
    let mut cmd = std::process::Command::new(ps_home.join("powershell.exe"));
    cmd.env("SystemRoot", &win).env("windir", &win).env("PSModulePath", ps_home.join("Modules"));
    cmd.args(["-NoProfile", "-NonInteractive", "-Command", PS_BOOT])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    hide_window(&mut cmd);
    let mut child = cmd.spawn()?;
    own_child_started(child.id());
    if let Some(mut stdin) = child.stdin.take() {
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = stdin.write_all(wrapped.as_bytes()); // closed when dropped, ending CopyTo
        });
    }
    Ok(child)
}

/// Runs a PowerShell script hidden; returns stdout, or the exception message on failure.
pub fn run_ps(script: &str) -> Result<String, String> {
    let child = ps_spawn(script).map_err(|e| format!("Could not start PowerShell: {e}"))?;
    let pid = child.id();
    let out = child.wait_with_output();
    own_child_exited(pid);
    ps_result(out.map_err(|e| e.to_string())?)
}

/// Like `run_ps`, but gives up (and kills PowerShell) after `secs` seconds.
pub fn run_ps_timeout(script: &str, secs: u64) -> Result<String, String> {
    let child = ps_spawn(script).map_err(|e| format!("Could not start PowerShell: {e}"))?;
    let id = child.id();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = child.wait_with_output();
        own_child_exited(id);
        let _ = tx.send(r);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
        Ok(Ok(out)) => ps_result(out),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => {
            let mut k = std::process::Command::new(system_exe("taskkill.exe"));
            k.args(["/PID", &id.to_string(), "/T", "/F"]);
            hide_window(&mut k);
            let _ = k.output();
            Err(format!("PowerShell did not finish within {secs} s"))
        }
    }
}

fn ps_result(out: std::process::Output) -> Result<String, String> {
    let stdout = String::from_utf8_lossy(&out.stdout).trim_start_matches('\u{feff}').trim().to_string();
    if !out.status.success() {
        if let Some(i) = stdout.rfind("ERR:") {
            return Err(stdout[i + 4..].trim().to_string());
        }
        let err = String::from_utf8_lossy(&out.stderr);
        let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("PowerShell failed");
        return Err(first.trim().to_string());
    }
    Ok(stdout)
}

pub fn hide_window(cmd: &mut std::process::Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    #[cfg(not(windows))]
    let _ = cmd;
}

/// Full path of a running program's file ("" if it is gone or protected).
#[cfg(windows)]
pub fn exe_of_pid(pid: u32) -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid <= 4 {
        return String::new();
    }
    unsafe {
        let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else { return String::new() };
        let mut buf = [0u16; 1024];
        let mut n = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_FORMAT(0), windows::core::PWSTR(buf.as_mut_ptr()), &mut n).is_ok();
        let _ = CloseHandle(h);
        if ok {
            String::from_utf16_lossy(&buf[..n as usize])
        } else {
            String::new()
        }
    }
}
#[cfg(not(windows))]
pub fn exe_of_pid(_pid: u32) -> String {
    String::new()
}

#[cfg(windows)]
pub fn is_elevated() -> bool {
    unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() }
}
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    false
}

pub fn log(msg: &str) {
    use std::io::Write;
    let dir = crate::config::dir();
    let _ = std::fs::create_dir_all(&dir);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("kestryl.log")) {
        let _ = writeln!(f, "{} {}", now_ms() / 1000, msg);
    }
}

#[cfg(test)]
mod tests {

    #[test]
    #[cfg(windows)]
    fn long_scripts_go_through_stdin() {
        // ~60 KB once encoded: over Windows' command-line limit.
        let script = format!("# {}\n$x = 'k'\n'o' + $x + ([char]0x2192)", "x".repeat(24_000));
        assert_eq!(run_ps(&script).unwrap(), "ok\u{2192}");
        assert_eq!(run_ps("'short'").unwrap(), "short");
        assert!(run_ps(&format!("# {}\nthrow 'boom'", "y".repeat(24_000))).unwrap_err().contains("boom"));
    }

    use super::*;

    #[test]
    fn scopes() {
        assert_eq!(scope(&"8.8.8.8".parse().unwrap()), Scope::Internet);
        assert_eq!(scope(&"192.168.1.5".parse().unwrap()), Scope::Lan);
        assert_eq!(scope(&"127.0.0.1".parse().unwrap()), Scope::Loopback);
        assert_eq!(scope(&"239.255.255.250".parse().unwrap()), Scope::Multicast);
        assert_eq!(scope(&"fe80::1".parse().unwrap()), Scope::Lan);
        assert_eq!(scope(&"2606:4700::1111".parse().unwrap()), Scope::Internet);
        assert_eq!(norm_ip("::ffff:1.2.3.4".parse().unwrap()), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn domains() {
        assert_eq!(base_domain("a.b.example.com."), "example.com");
        assert_eq!(base_domain("x.example.co.uk"), "example.co.uk");
        assert_eq!(base_domain("example.com"), "example.com");
        assert!(domain_is("api.telegram.org", "telegram.org"));
        assert!(domain_is("telegram.org", "telegram.org"));
        assert!(!domain_is("nottelegram.org", "telegram.org"));
    }

    #[test]
    fn nets() {
        let n = parse_net("142.250.0.0/15").unwrap();
        assert!(net_contains(&n, &"142.251.10.1".parse().unwrap()));
        assert!(!net_contains(&n, &"142.252.0.1".parse().unwrap()));
        let one = parse_net("8.8.8.8").unwrap();
        assert!(net_contains(&one, &"8.8.8.8".parse().unwrap()) && !net_contains(&one, &"8.8.4.4".parse().unwrap()));
        assert!(net_contains(&parse_net("2001:db8::/32").unwrap(), &"2001:db8:1::5".parse().unwrap()));
        assert!(parse_net("google.com").is_none() && parse_net("1.2.3.4/40").is_none());
    }

    #[test]
    fn misc() {
        assert!(entropy("aaaa") < 0.01);
        assert!(entropy("a8f3k2m9x7q1z5w4") > 3.5);
        assert_eq!(b64(b"hello"), "aGVsbG8=");
        assert_eq!(fmt_bytes(1536), "2 KB");
        assert_eq!(ps_quote("it's"), "'it''s'");
    }

    #[test]
    fn dates() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(day_number("2026-11-13").map(day_string).as_deref(), Some("2026-11-13"));
        assert_eq!(day_string(day_number("2024-03-01").unwrap() - 1), "2024-02-29");
        assert_eq!(day_string(day_number("2026-01-01").unwrap() - 30), "2025-12-02");
        let (d, h) = local_day_hour();
        assert!(day_number(&d).is_some() && h < 24);
    }

    /// PowerShell treats ‘ ’ ‚ ‛ like ' : a file name with them must not break out of the quotes.
    #[test]
    fn ps_quote_typographic_quotes() {
        assert_eq!(ps_quote("a\u{2019}b"), "'a\u{2019}\u{2019}b'");
        assert_eq!(ps_quote("\u{2018}\u{201A}\u{201B}"), "'\u{2018}\u{2018}\u{201A}\u{201A}\u{201B}\u{201B}'");
        assert!(in_protected_dir(&system_exe("notepad.exe").to_string_lossy()));
        assert!(!in_protected_dir(r"C:\Users\someone\Downloads\x.exe"));
        assert!(!in_protected_dir(r"C:\Program Files Evil\x.exe"));
    }

    /// The real thing: PowerShell must get back exactly the hostile name, and run nothing.
    #[test]
    #[ignore]
    fn live_ps_quote_injection() {
        let name = "C:\\x\\a\u{2019};Write-Output 'PWNED';\u{2019}b'c\u{2018}d\u{201A}e\u{201B}f.exe";
        let out = run_ps(&format!("$o = @({}); 'n=' + $o.Count; $o[0]", ps_quote(name))).unwrap();
        assert!(!out.lines().any(|l| l == "PWNED"), "injected code ran: {out}");
        assert_eq!(out, format!("n=1\n{name}").replace('\n', "\r\n"), "round trip failed");
    }

    /// Scripts longer than a command line, non-ASCII text, errors and exit codes all survive the
    /// stdin bootstrap.
    #[test]
    #[ignore]
    fn live_ps_long_script_and_errors() {
        let filler = format!("# {}\n", "x".repeat(100)).repeat(400); // ~41k characters
        let out = run_ps(&format!("{filler}'Caf\u{e9} \u{65e5}\u{672c} ' + (1 + 2)")).unwrap();
        assert_eq!(out, "Caf\u{e9} \u{65e5}\u{672c} 3");
        let err = run_ps("throw 'boom'").unwrap_err();
        assert_eq!(err, "boom");
        let cmd = run_ps("(Get-NetFirewallProfile | Measure-Object).Count").unwrap();
        assert_eq!(cmd, "3", "NetSecurity module did not load");
    }
}
