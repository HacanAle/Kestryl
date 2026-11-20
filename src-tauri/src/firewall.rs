//! Blocking through Windows Firewall (rules live in the "Kestryl" group, so they
//! survive restarts and work even when Kestryl is closed), plus a few system queries.

use crate::util::*;
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::Path;

pub const GROUP: &str = "Kestryl";

pub fn rule_id(kind: &str, target: &str) -> String {
    format!("Kestryl-{kind}-{:016x}", fnv(&target.to_lowercase()))
}

pub fn is_own_rule(id: &str) -> bool {
    id.starts_with("Kestryl-")
}

fn file_name(p: &str) -> String {
    Path::new(p).file_name().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| p.to_string())
}

fn new_rule(id: &str, display: &str, desc: &str, target: &str) -> String {
    new_rule_dir(id, display, desc, "Outbound", target)
}

fn new_rule_dir(id: &str, display: &str, desc: &str, dir: &str, target: &str) -> String {
    format!(
        "Remove-NetFirewallRule -Name {id} -ErrorAction SilentlyContinue\nNew-NetFirewallRule -Name {id} -Group {g} -DisplayName {dn} -Description {d} -Direction {dir} -Action Block -Profile Any {target} | Out-Null\n",
        id = ps_quote(id),
        g = ps_quote(GROUP),
        dn = ps_quote(display),
        d = ps_quote(desc),
    )
}

pub fn block_app(exe: &str) -> Result<String, String> {
    if exe.is_empty() {
        return Err("This process has no file path (it is part of Windows), so it can't be blocked as a program. Block its destination instead.".into());
    }
    let name = file_name(exe);
    run_ps(&new_rule(
        &rule_id("app", exe),
        &format!("Kestryl: block {name}"),
        &format!("kestryl:app:{exe}"),
        &format!("-Program {}", ps_quote(exe)),
    ))?;
    Ok(format!("{name} can no longer send anything out."))
}

/// Inbound block on a local port: other devices can no longer connect to it, the program
/// keeps running. (Block rules win over any allow rule in Windows Firewall.)
pub fn block_port(proto: &str, port: u16) -> Result<String, String> {
    let proto = match proto.to_ascii_lowercase().as_str() {
        "tcp" => "TCP",
        "udp" => "UDP",
        _ => return Err(format!("Unknown protocol \"{proto}\".")),
    };
    if port == 0 {
        return Err("No port to block.".into());
    }
    let target = format!("{proto} {port}");
    run_ps(&new_rule_dir(
        &rule_id("port", &target),
        &format!("Kestryl: block incoming {target}"),
        &format!("kestryl:port:{target}"),
        "Inbound",
        &format!("-Protocol {proto} -LocalPort {port}"),
    ))?;
    Ok(format!("Other devices can no longer connect to {proto} port {port} on this PC. Undo on the Blocking tab."))
}

pub fn valid_ip(s: &str) -> bool {
    let s = s.trim();
    let (ip, mask) = s.split_once('/').unwrap_or((s, ""));
    ip.parse::<IpAddr>().is_ok() && (mask.is_empty() || mask.parse::<u8>().is_ok_and(|m| m <= 128))
}

pub fn block_ips(kind: &str, target: &str, ips: &[String]) -> Result<String, String> {
    if ips.is_empty() || !ips.iter().all(|i| valid_ip(i)) {
        return Err("No valid IP address to block.".into());
    }
    let list = ips.iter().map(|i| ps_quote(i)).collect::<Vec<_>>().join(",");
    let id = rule_id(kind, target);
    run_ps(&new_rule(
        &id,
        &format!("Kestryl: block {target}"),
        &format!("kestryl:{kind}:{target}"),
        &format!("-RemoteAddress @({list})"),
    ))?;
    Ok(id)
}

pub fn clean_domain(d: &str) -> Option<String> {
    let d = d.trim().to_ascii_lowercase();
    let d = d.split("://").last().unwrap_or("");
    let d = d.split(['/', ':', '?']).next().unwrap_or("").trim_end_matches('.');
    let ok = d.contains('.')
        && d.len() <= 253
        && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && d.parse::<IpAddr>().is_err();
    ok.then(|| d.to_string())
}

/// Resolves the domain now, merges IPs already seen in DNS answers, blocks them all.
pub fn block_domain(domain: &str, mut known: Vec<String>) -> Result<(String, Vec<String>), String> {
    use std::net::ToSocketAddrs;
    for host in [domain.to_string(), format!("www.{domain}")] {
        if let Ok(addrs) = (host.as_str(), 443).to_socket_addrs() {
            for a in addrs {
                let ip = norm_ip(a.ip());
                if scope(&ip) == Scope::Internet {
                    known.push(ip.to_string());
                }
            }
        }
    }
    known.sort();
    known.dedup();
    if known.is_empty() {
        return Err(format!("{domain} did not resolve to any address, so there is nothing to block yet."));
    }
    let id = block_ips("domain", domain, &known)?;
    Ok((id, known))
}

/// New address list for a blocked domain's rule. Creates the rule again if it is missing
/// (deleted, or caught between the remove and re-create of a second "Block").
pub fn update_ips(id: &str, domain: &str, ips: &[String]) -> Result<(), String> {
    let list = ips.iter().filter(|i| valid_ip(i)).map(|i| ps_quote(i)).collect::<Vec<_>>().join(",");
    if list.is_empty() {
        return Ok(());
    }
    // "Kestryl-tracker-..." for the analytics servers, "Kestryl-domain-..." for user blocks.
    let kind = id.split('-').nth(1).filter(|k| matches!(*k, "tracker" | "domain")).unwrap_or("domain");
    let display = if kind == "tracker" { format!("Kestryl: block {domain} (analytics)") } else { format!("Kestryl: block {domain}") };
    let create = new_rule(id, &display, &format!("kestryl:{kind}:{domain}"), &format!("-RemoteAddress @({list})"));
    run_ps(&format!(
        "if (Get-NetFirewallRule -Name {q} -ErrorAction SilentlyContinue) {{ Set-NetFirewallRule -Name {q} -RemoteAddress @({list}) }} else {{\n{create}}}",
        q = ps_quote(id)
    ))
    .map(|_| ())
}

pub fn remove(id: &str) -> Result<(), String> {
    if !is_own_rule(id) {
        return Err("Only rules created by Kestryl can be removed here.".into());
    }
    run_ps(&format!("Remove-NetFirewallRule -Name {}", ps_quote(id))).map(|_| ())
}

pub fn list() -> Result<Value, String> {
    let out = run_ps(
        r#"$r = @(Get-NetFirewallRule -Group 'Kestryl' -ErrorAction SilentlyContinue)
$o = @(foreach ($x in $r) { [pscustomobject]@{ id = $x.Name; name = $x.DisplayName; desc = $x.Description; enabled = [string]$x.Enabled } })
$p = @(Get-NetFirewallProfile | ForEach-Object { [pscustomobject]@{ name = $_.Name; enabled = [string]$_.Enabled; out = [string]$_.DefaultOutboundAction } })
ConvertTo-Json -InputObject ([pscustomobject]@{ rules = $o; profiles = $p }) -Compress -Depth 4"#,
    )?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("bad firewall output: {e}"))?;
    let mut rules = Vec::new();
    let mut lockdown = 0;
    for r in v["rules"].as_array().cloned().unwrap_or_default() {
        let desc = r["desc"].as_str().unwrap_or("");
        let mut parts = desc.splitn(3, ':');
        let (_, kind, target) = (parts.next(), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if kind == "script" {
            lockdown += 1;
        }
        rules.push(json!({ "id": r["id"], "name": r["name"], "kind": kind, "target": target,
                           "enabled": r["enabled"].as_str() == Some("True") }));
    }
    let profiles = v["profiles"].as_array().cloned().unwrap_or_default();
    let cut_off = profiles.iter().any(|p| p["out"].as_str() == Some("Block"));
    let fw_off: Vec<Value> = profiles.iter().filter(|p| p["enabled"].as_str() != Some("True")).map(|p| p["name"].clone()).collect();
    Ok(json!({ "rules": rules, "lockdown": lockdown > 0, "cut_off": cut_off, "profiles": profiles, "firewall_off": fw_off,
               "hosts": script_hosts() }))
}

/// Script engines and Windows tools malware uses to fetch or send data.
pub fn script_hosts() -> Vec<String> {
    let root = windows_dir().display().to_string();
    let mut v = Vec::new();
    for dir in ["System32", "SysWOW64"] {
        for f in [
            r"WindowsPowerShell\v1.0\powershell.exe",
            r"WindowsPowerShell\v1.0\powershell_ise.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "certutil.exe",
            "bitsadmin.exe",
            "regsvr32.exe",
            "rundll32.exe",
            "hh.exe",
            "cmstp.exe",
            r"wbem\WMIC.exe",
        ] {
            v.push(format!(r"{root}\{dir}\{f}"));
        }
    }
    for fw in [r"Microsoft.NET\Framework\v4.0.30319", r"Microsoft.NET\Framework64\v4.0.30319"] {
        for f in ["MSBuild.exe", "InstallUtil.exe", "RegAsm.exe", "RegSvcs.exe"] {
            v.push(format!(r"{root}\{fw}\{f}"));
        }
    }
    v.push(program_files().join(r"PowerShell\7\pwsh.exe").display().to_string());
    v.retain(|p| Path::new(p).exists());
    v
}

pub fn set_lockdown(on: bool) -> Result<String, String> {
    if !on {
        run_ps("Get-NetFirewallRule -Group 'Kestryl' -ErrorAction SilentlyContinue | Where-Object { $_.Description -like 'kestryl:script:*' } | Remove-NetFirewallRule")?;
        return Ok("Script lockdown is off. Scripts and Windows tools can reach the network again.".into());
    }
    let hosts = script_hosts();
    let mut s = String::new();
    for p in &hosts {
        s += &new_rule(
            &rule_id("script", p),
            &format!("Kestryl: script lockdown {}", file_name(p)),
            &format!("kestryl:script:{p}"),
            &format!("-Program {}", ps_quote(p)),
        );
    }
    run_ps(&s)?;
    Ok(format!("Script lockdown is on: {} script engines and Windows tools can no longer reach the network.", hosts.len()))
}

pub fn set_cutoff(on: bool) -> Result<String, String> {
    if on {
        run_ps("Set-NetFirewallProfile -All -DefaultOutboundAction Block")?;
        Ok("Internet cut off. Only parts of Windows with their own allow rules can still connect.".into())
    } else {
        run_ps("Set-NetFirewallProfile -All -DefaultOutboundAction NotConfigured")?;
        Ok("Internet restored.".into())
    }
}

pub fn autostart_on() -> bool {
    run_ps("if (Get-ScheduledTask -TaskName 'Kestryl' -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }")
        .map(|s| s == "yes")
        .unwrap_or(false)
}

/// Scheduled task at logon with highest privileges: full monitoring without a UAC prompt.
pub fn set_autostart(on: bool) -> Result<String, String> {
    if !on {
        run_ps("Unregister-ScheduledTask -TaskName 'Kestryl' -Confirm:$false -ErrorAction SilentlyContinue")?;
        return Ok("Kestryl will no longer start with Windows.".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?.display().to_string();
    // The account from the process token, not %USERNAME% (a variable the user can change).
    run_ps(&format!(
        r#"$u = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$a = New-ScheduledTaskAction -Execute {exe} -Argument '--hidden'
$t = New-ScheduledTaskTrigger -AtLogOn -User $u
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
$p = New-ScheduledTaskPrincipal -UserId $u -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName 'Kestryl' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null"#,
        exe = ps_quote(&exe)
    ))?;
    if !in_protected_dir(&exe) {
        let dir = Path::new(&exe).parent().map(|d| d.display().to_string()).unwrap_or_default();
        return Ok(format!(
            "Kestryl will start hidden in the tray, as administrator, when you sign in. Note: it runs from {dir}, a folder your own account can change, so another program could swap the file before your next sign-in. Install Kestryl with the setup (it goes to Program Files) to close that gap."
        ));
    }
    Ok("Kestryl will start hidden in the tray, as administrator, when you sign in.".into())
}

pub fn network_extra() -> Result<Value, String> {
    let out = run_ps(
        r#"$c = @(Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {
  [pscustomobject]@{
    alias = $_.InterfaceAlias; desc = $_.InterfaceDescription
    ipv4 = (@($_.IPv4Address | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength }) -join ', ')
    ipv6 = (@($_.IPv6Address | ForEach-Object { $_.IPAddress }) -join ', ')
    gateway = (@($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', ')
    dns = (@($_.DNSServer | Where-Object { $_.AddressFamily -eq 2 } | ForEach-Object { $_.ServerAddresses }) -join ', ')
    category = [string]$_.NetProfile.NetworkCategory; network = [string]$_.NetProfile.Name
  } })
$n = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
  $_.State -in 'Reachable','Stale','Delay','Probe' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and
  $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' -and -not $_.IPAddress.EndsWith('.255') } | ForEach-Object {
  [pscustomobject]@{ ip = $_.IPAddress; mac = $_.LinkLayerAddress; state = [string]$_.State; iface = $_.InterfaceAlias } })
$s = @(Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ pid = [int]$_.ProcessId; name = $_.Name; display = $_.DisplayName } })
ConvertTo-Json -InputObject ([pscustomobject]@{ config = $c; neighbors = $n; services = $s }) -Compress -Depth 4"#,
    )?;
    serde_json::from_str(&out).map_err(|e| format!("bad output: {e}"))
}

/// Ends open IPv4 TCP connections right away (a new firewall rule only stops new ones).
#[cfg(windows)]
pub fn drop_tcp(pid: Option<u32>, ip: Option<IpAddr>) -> usize {
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, TcpState};
    use windows::Win32::NetworkManagement::IpHelper::{SetTcpEntry, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCP_STATE_DELETE_TCB};
    let Ok(socks) = get_sockets_info(AddressFamilyFlags::IPV4, ProtocolFlags::TCP) else { return 0 };
    let mut n = 0;
    for s in socks {
        let ProtocolSocketInfo::Tcp(t) = &s.protocol_socket_info else { continue };
        if t.state != TcpState::Established {
            continue;
        }
        let spid = s.associated_pids.first().copied().unwrap_or(0);
        if pid.is_some_and(|p| p != spid) || ip.is_some_and(|i| norm_ip(i) != norm_ip(t.remote_addr)) {
            continue;
        }
        let (IpAddr::V4(l), IpAddr::V4(r)) = (t.local_addr, t.remote_addr) else { continue };
        if r.is_loopback() {
            continue;
        }
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { State: MIB_TCP_STATE_DELETE_TCB },
            dwLocalAddr: u32::from_ne_bytes(l.octets()),
            dwLocalPort: t.local_port.to_be() as u32,
            dwRemoteAddr: u32::from_ne_bytes(r.octets()),
            dwRemotePort: t.remote_port.to_be() as u32,
        };
        if unsafe { SetTcpEntry(&row) } == 0 {
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inputs() {
        assert_eq!(clean_domain("https://Pastebin.com/raw/x").as_deref(), Some("pastebin.com"));
        assert_eq!(clean_domain("1.2.3.4"), None);
        assert_eq!(clean_domain("bad domain.com"), None);
        assert!(valid_ip("203.0.113.0/24"));
        assert!(!valid_ip("203.0.113.0; rm"));
        assert!(rule_id("app", r"C:\X.exe").starts_with("Kestryl-app-"));
        assert!(is_own_rule("Kestryl-ip-1") && !is_own_rule("CoreNet-1"));
    }

    /// Run by hand, NOT elevated: every change must be refused by Windows
    /// (access denied), proving the PowerShell is well-formed.
    #[test]
    #[ignore]
    fn ps_reaches_windows_unelevated() {
        assert!(!crate::util::is_elevated(), "run this test without admin rights");
        let e = block_app(r"C:\kestryl-test\nonexistent.exe").unwrap_err();
        println!("block_app -> {e}");
        let e = set_autostart(true).unwrap_err();
        println!("autostart -> {e}");
        let e = update_ips("Kestryl-domain-0000000000000000", "test.invalid", &["203.0.113.1".into()]).unwrap_err();
        println!("update_ips -> {e}");
        let e = block_port("tcp", 65000).unwrap_err();
        println!("block_port -> {e}");
        let v = list().unwrap();
        println!("list -> {} rules, profiles {}", v["rules"].as_array().unwrap().len(), v["profiles"]);
        println!("autostart_on -> {}", autostart_on());
        let n = network_extra().unwrap();
        println!("network_extra -> {} adapters, {} services", n["config"].as_array().unwrap().len(), n["services"].as_array().unwrap().len());
    }
}
