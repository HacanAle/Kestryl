//! Security check of the PC itself, every 15 minutes and on demand: antivirus,
//! firewall, root certificates, proxy, hosts file, programs that start with Windows,
//! Remote Desktop, DNS servers, shared folders, Windows Update. Read-only.
//! The first run is remembered (config.json "baseline"); later runs report changes as
//! alerts, because malware changes exactly these settings.

use crate::config::Baseline;
use crate::detect::{self, Class, Finding};
use crate::util::*;
use serde_json::{json, Value};
use std::collections::HashSet;

const SCRIPT: &str = r#"
$r = [ordered]@{}
$r.computer = [string]$env:COMPUTERNAME
try {
  $m = Get-MpComputerStatus -ErrorAction Stop
  $r.defender = [pscustomobject]@{ am = [bool]$m.AMServiceEnabled; av = [bool]$m.AntivirusEnabled; rtp = [bool]$m.RealTimeProtectionEnabled
    tamper = [bool]$m.IsTamperProtected; sigAge = [int]$m.AntivirusSignatureAge; quickAge = [int64]$m.QuickScanAge; fullAge = [int64]$m.FullScanAge
    mode = [string]$m.AMRunningMode; version = [string]$m.AMProductVersion }
} catch { $r.defender = $null; $r.defenderError = $_.Exception.Message }
$r.exclusions = @(); $r.exclOk = $false
try {
  $p = Get-MpPreference -ErrorAction Stop
  $ex = @(@($p.ExclusionPath) + @($p.ExclusionProcess) + @($p.ExclusionExtension | Where-Object { $_ } | ForEach-Object { '*.' + $_ }) + @($p.ExclusionIpAddress)) | Where-Object { $_ }
  if (-not ($ex | Where-Object { "$_" -like 'N/A*' })) { $r.exclOk = $true; $r.exclusions = @($ex | ForEach-Object { [string]$_ }) }
} catch {}
$r.threats = @()
try {
  $names = @{}; Get-MpThreat -ErrorAction Stop | ForEach-Object { $names[[string]$_.ThreatID] = $_.ThreatName }
  $since = (Get-Date).AddDays(-30)
  $r.threats = @(Get-MpThreatDetection -ErrorAction Stop | Where-Object { $_.InitialDetectionTime -gt $since } | Sort-Object InitialDetectionTime -Descending | Select-Object -First 15 | ForEach-Object {
    [pscustomobject]@{ when = $_.InitialDetectionTime.ToString('o'); name = [string]$names[[string]$_.ThreatID]; res = (@($_.Resources) -join '; '); ok = [bool]$_.ActionSuccess; process = [string]$_.ProcessName } })
} catch {}
try { $r.av = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ name = [string]$_.displayName; state = [int64]$_.productState } }) } catch { $r.av = @() }
$r.firewall = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; on = ([string]$_.Enabled -eq 'True'); inb = [string]$_.DefaultInboundAction; outb = [string]$_.DefaultOutboundAction } })
$r.fwRules = @(Get-NetFirewallRule -Group 'Kestryl' -ErrorAction SilentlyContinue | ForEach-Object { [string]$_.Name })
$seen = @{}
$r.roots = @(foreach ($s in 'LocalMachine','CurrentUser') { Get-ChildItem "Cert:\$s\Root" -ErrorAction SilentlyContinue | Where-Object { -not $seen.ContainsKey($_.Thumbprint) } | ForEach-Object {
  $seen[$_.Thumbprint] = 1
  [pscustomobject]@{ store = $s; tp = [string]$_.Thumbprint; subject = [string]$_.Subject; issuer = [string]$_.Issuer; key = [bool]$_.HasPrivateKey; from = $_.NotBefore.ToString('yyyy-MM-dd'); to = $_.NotAfter.ToString('yyyy-MM-dd') } } })
$is = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
$wp = ''
$wh = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -ErrorAction SilentlyContinue).WinHttpSettings
if ($wh -and $wh.Length -ge 16) { $fl = [BitConverter]::ToInt32($wh, 8); $ln = [BitConverter]::ToInt32($wh, 12); if (($fl -band 2) -and $ln -gt 0 -and $wh.Length -ge 16 + $ln) { $wp = [Text.Encoding]::ASCII.GetString($wh, 16, $ln) } }
$r.proxy = [pscustomobject]@{ on = ([int]$is.ProxyEnable -eq 1); server = [string]$is.ProxyServer; pac = [string]$is.AutoConfigURL; winhttp = $wp }
$hp = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$r.hosts = @(Get-Content -LiteralPath $hp -ErrorAction SilentlyContinue | ForEach-Object { ($_ -replace '#.*$', '').Trim() } | Where-Object { $_ })
$st = New-Object System.Collections.ArrayList
function Add-St($where, $name, $cmd) {
  $c = [string]$cmd; $exe = ''
  if ($c -match '^\s*"([^"]+)"') { $exe = $matches[1] } elseif ($c -match '^\s*(.+?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|hta|scr|lnk|msi))(\s|,|$)') { $exe = $matches[1] } else { $exe = (($c.Trim()) -split '\s+')[0] }
  $exe = [Environment]::ExpandEnvironmentVariables($exe)
  if ($exe -and -not ($exe -match '[\\/]')) { $g = Get-Command $exe -ErrorAction SilentlyContinue | Select-Object -First 1; if ($g -and $g.Source) { $exe = $g.Source } }
  $sig = 'Missing'; $signer = ''
  if ($exe -and (Test-Path -LiteralPath $exe -PathType Leaf)) {
    try { $s = Get-AuthenticodeSignature -LiteralPath $exe; $sig = [string]$s.Status; if ($s.SignerCertificate) { $signer = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) } } catch { $sig = 'Error' }
  }
  [void]$st.Add([pscustomobject]@{ where = [string]$where; name = [string]$name; cmd = $c; exe = [string]$exe; sig = $sig; signer = [string]$signer })
}
foreach ($k in 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run') {
  $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
  $w = $k.Substring(0, 4) + ' ' + $k.Split('\')[-1] + $(if ($k -like '*WOW6432Node*') { ' (32-bit)' } else { '' })
  if ($p) { foreach ($n in $p.PSObject.Properties) { if ($n.Name -notin 'PSPath','PSParentPath','PSChildName','PSDrive','PSProvider') { Add-St $w $n.Name $n.Value } } }
}
$sh = $null
foreach ($d in @([Environment]::GetFolderPath('Startup'), [Environment]::GetFolderPath('CommonStartup'))) {
  if (-not $d) { continue }
  Get-ChildItem -LiteralPath $d -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object {
    $t = '"' + $_.FullName + '"'
    if ($_.Extension -eq '.lnk') { try { if (-not $sh) { $sh = New-Object -ComObject WScript.Shell }; $l = $sh.CreateShortcut($_.FullName); $t = ('"' + $l.TargetPath + '" ' + $l.Arguments).Trim() } catch {} }
    Add-St 'Startup folder' $_.Name $t
  }
}
$sr = $env:SystemRoot
# Tasks in \Microsoft\ are Windows' own; malware hides its tasks there, so the odd ones count:
# a program outside Windows / Program Files / Defender, or a hidden, encoded or downloading script.
$odd = { param($x, $a) ($x -match '[\\/]' -and $x -notlike "$sr\*" -and $x -notlike "$env:ProgramFiles\*" -and $x -notlike "${env:ProgramFiles(x86)}\*" -and $x -notlike "$env:ProgramData\Microsoft\Windows Defender\*") -or $x -like '*\Temp\*' -or $a -match '(?i)-enc|-w(indowstyle)? +h|hidden|https?://|frombase64|downloadstring|\biex\b' }
Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $tn = $_.TaskPath + $_.TaskName; $ms = $_.TaskPath -like '\Microsoft\*'
  foreach ($a in @($_.Actions)) { if ($a.Execute) {
    $x = $a.Execute.Trim('"')
    if (-not $ms -or (& $odd ([Environment]::ExpandEnvironmentVariables($x)) ([string]$a.Arguments))) { Add-St 'Task Scheduler' $tn (('"' + $x + '" ' + $a.Arguments).Trim()) }
  } }
}
# Services and drivers that start by themselves, outside the Windows folder.
$exeOf = { param($p) $p = [Environment]::ExpandEnvironmentVariables(([string]$p).Trim()); if ($p -match '^"([^"]+)"') { $matches[1] } elseif ($p -match '^(.+?\.(exe|sys|dll))\b') { $matches[1] } else { ($p -split '\s+')[0] } }
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -eq 'Auto' -and $_.PathName } | ForEach-Object {
  $x = & $exeOf $_.PathName
  if ($x -notlike "$sr\*" -or $x -like '*\Temp\*') { Add-St 'Service' ($_.DisplayName + ' (' + $_.Name + ')') $_.PathName }
}
Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.StartMode -in 'Boot','System','Auto' -and $_.PathName } | ForEach-Object {
  $p = ([string]$_.PathName) -replace '^\\\?\?\\', '' -replace '^\\SystemRoot\\', "$sr\" -replace '^(?i)system32\\', "$sr\System32\"
  if ($p -notlike "$sr\*") { Add-St 'Driver' ($_.DisplayName + ' (' + $_.Name + ')') ('"' + $p + '"') }
}
# WMI event subscriptions: run a command or script when something happens, with no file in any startup folder.
try { Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -ErrorAction Stop | ForEach-Object { Add-St 'WMI subscription' $_.Name $(if ($_.CommandLineTemplate) { $_.CommandLineTemplate } else { $_.ExecutablePath }) } } catch {}
try { Get-CimInstance -Namespace root/subscription -ClassName ActiveScriptEventConsumer -ErrorAction Stop | ForEach-Object { $s = [string]$_.ScriptText; Add-St 'WMI script' $_.Name $(if ($_.ScriptFileName) { $_.ScriptFileName } else { 'script: ' + $s.Substring(0, [Math]::Min(300, $s.Length)) }) } } catch {}
# Winlogon: what Windows itself starts at sign-in. Listed only when it differs from Windows' own.
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($wl) {
  $sh = ([string]$wl.Shell).Trim(); if ($sh -and $sh -notin 'explorer.exe', 'explorer') { Add-St 'Winlogon Shell' 'Shell' $sh }
  $ui = ([string]$wl.Userinit).Trim().TrimEnd(',').Trim(); if ($ui -and $ui -notin "$sr\system32\userinit.exe", 'userinit.exe', 'userinit') { Add-St 'Winlogon Userinit' 'Userinit' $ui }
}
$hw = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue
if ($hw -and $hw.Shell) { Add-St 'Winlogon Shell (user)' 'Shell' $hw.Shell }
# Image File Execution Options: a "debugger" starts instead of the named program.
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
  Get-ChildItem -LiteralPath $k -ErrorAction SilentlyContinue | ForEach-Object { $d = (Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction SilentlyContinue).Debugger; if ($d) { Add-St 'IFEO debugger' $_.PSChildName $d } }
}
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
  $p = Get-ItemProperty -LiteralPath $k -ErrorAction SilentlyContinue
  if ($p -and ([string]$p.AppInit_DLLs).Trim() -and [int]$p.LoadAppInit_DLLs -eq 1) { Add-St 'AppInit DLL' 'AppInit_DLLs' $p.AppInit_DLLs }
}
# Accessibility tools reachable at the sign-in screen: replaced by a copy of cmd.exe = no-password backdoor.
$acc = @{ 'sethc.exe' = 'sethc.exe'; 'utilman.exe' = 'utilman2.exe'; 'osk.exe' = 'osk.exe'; 'Magnify.exe' = 'ScreenMagnifier.exe'; 'Narrator.exe' = 'SR.exe'; 'DisplaySwitch.exe' = 'DisplaySwitch.exe'; 'AtBroker.exe' = 'ATBroker.exe' }
foreach ($n in $acc.Keys) {
  $p = Join-Path $sr "System32\$n"
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $of = [string](Get-Item -LiteralPath $p).VersionInfo.OriginalFilename -replace '(?i)\.mui$', ''
    $s = Get-AuthenticodeSignature -LiteralPath $p
    $swap = $of -and $of -ne $acc[$n]
    if ($s.Status -ne 'Valid' -or $swap) { Add-St 'Accessibility tool' $(if ($swap) { "$n (really $of)" } else { $n }) ('"' + $p + '"') }
  }
}
$r.startup = @($st)
$r.admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$ts = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
$r.rdp = ($null -ne $ts -and [int]$ts.fDenyTSConnections -eq 0)
$r.dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object { [pscustomobject]@{ iface = [string]$_.InterfaceAlias; servers = @($_.ServerAddresses | ForEach-Object { [string]$_ }) } })
$u = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
$r.uac = ($null -eq $u -or [int]$u.EnableLUA -ne 0)
$r.shares = @()
try { $r.shares = @(Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^([A-Za-z]|ADMIN|IPC|print)\$$' } | ForEach-Object { [pscustomobject]@{ name = [string]$_.Name; path = [string]$_.Path } }) } catch {}
try {
  $us = New-Object -ComObject Microsoft.Update.Session; $hs = $us.CreateUpdateSearcher(); $n = $hs.GetTotalHistoryCount()
  if ($n -gt 0) { $e = @($hs.QueryHistory(0, [Math]::Min($n, 30)) | Where-Object { $_.ResultCode -eq 2 } | Sort-Object Date -Descending | Select-Object -First 1); if ($e.Count -gt 0) { $r.lastUpdate = $e[0].Date.ToString('o') } }
} catch {}
# The certificate that signed kestryl.exe: its own publisher root is not a finding.
$r.selfTp = ''
if ($ownExe) { try { $r.selfTp = [string](Get-AuthenticodeSignature -LiteralPath $ownExe -ErrorAction Stop).SignerCertificate.Thumbprint } catch {} }
ConvertTo-Json -InputObject ([pscustomobject]$r) -Compress -Depth 5
"#;

pub fn run() -> Result<Value, String> {
    let exe = std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default();
    let out = run_ps_timeout(&format!("$ownExe = {}\n{SCRIPT}", ps_quote(&exe)), 180)?;
    serde_json::from_str(&out).map_err(|e| format!("unexpected security-check output: {e}"))
}

fn f(rule: &'static str, sev: u8, title: String, why: String, group: String) -> Finding {
    Finding { rule, sev, title, why, group }
}

/// "CN=Foo Root, O=Foo" -> "Foo Root".
fn cn(subject: &str) -> String {
    subject
        .split(',')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("CN=").or_else(|| p.strip_prefix("OU=")).or_else(|| p.strip_prefix("O=")))
        .unwrap_or(subject)
        .trim_matches('"')
        .to_string()
}

/// Well-known public DNS resolvers.
pub fn dns_label(ip: &str) -> Option<&'static str> {
    Some(match ip {
        "1.1.1.1" | "1.0.0.1" | "1.1.1.2" | "1.0.0.2" | "1.1.1.3" | "1.0.0.3" => "Cloudflare",
        "8.8.8.8" | "8.8.4.4" => "Google",
        "9.9.9.9" | "149.112.112.112" | "9.9.9.10" | "9.9.9.11" | "149.112.112.11" => "Quad9",
        "208.67.222.222" | "208.67.220.220" | "208.67.222.123" | "208.67.220.123" => "OpenDNS (Cisco)",
        "94.140.14.14" | "94.140.15.15" | "94.140.14.15" | "94.140.15.16" => "AdGuard",
        "76.76.2.0" | "76.76.10.0" => "Control D",
        "185.228.168.9" | "185.228.169.9" | "185.228.168.168" | "185.228.169.168" => "CleanBrowsing",
        "4.2.2.1" | "4.2.2.2" => "Lumen (Level 3)",
        _ if ip.starts_with("45.90.28.") || ip.starts_with("45.90.30.") => "NextDNS",
        _ => return None,
    })
}

const SECURITY_SITES: [&str; 22] = [
    "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "office.com", "defender", "virustotal.com",
    "avast.com", "avg.com", "kaspersky", "eset.com", "mcafee.com", "norton", "symantec", "malwarebytes",
    "bitdefender", "sophos", "trendmicro", "f-secure", "avira", "pandasecurity", "eset.",
];

/// Risk of one hosts-file mapping: "high" | "med" | "ok".
fn hosts_risk(ip: &str, host: &str) -> &'static str {
    // Security and Microsoft sites: blocking them stops updates, redirecting them is phishing.
    if SECURITY_SITES.iter().any(|s| host.contains(s)) && host != "localhost" {
        return "high";
    }
    // Pointing a name to this PC or the local network: developer tools, Docker, a NAS.
    match ip.parse::<std::net::IpAddr>().map(|a| scope(&a)) {
        Ok(Scope::Internet) => "med",
        _ => "ok",
    }
}

/// Words of Windows' own components that malware borrows for its startup entries.
const WINDOWS_WORDS: [&str; 14] = [
    "microsoft", "windows", "security", "defender", "svchost", "lsass", "csrss", "winlogon", "runtimebroker",
    "explorer", "update", "health", "system32", "dllhost",
];

/// Accessibility tools that run at the sign-in screen with full rights.
const ACCESS_TOOLS: [&str; 7] = ["sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe"];

/// Startup locations Kestryl already watched before services, WMI, Winlogon and IFEO were added.
const OLD_PLACES: [&str; 7] = ["HKCU Run", "HKCU RunOnce", "HKLM Run", "HKLM RunOnce", "HKLM Run (32-bit)", "Startup folder", "Task Scheduler"];

/// Risk of one entry, by where it is: ("high" | "med" | "ok", location, why).
fn startup_risk_at(wh: &str, name: &str, exe: &str, cmd: &str, sig: &str) -> (&'static str, Class, &'static str) {
    let base = startup_risk(name, exe, cmd, sig);
    let class = base.1;
    match wh {
        w if w.starts_with("Winlogon") => ("high", class, "changes what Windows itself starts at every sign-in (Winlogon). Normal PCs never change this; malware does, to start before everything else"),
        "Accessibility tool" => ("high", class, "replaced: at the sign-in screen, Shift pressed five times or the accessibility button opens this file with full rights and no password (the Sticky Keys backdoor)"),
        "IFEO debugger" if ACCESS_TOOLS.contains(&name.to_lowercase().as_str()) => ("high", class, "starts instead of an accessibility tool, so at the sign-in screen it opens with full rights and no password (the Sticky Keys backdoor)"),
        "WMI subscription" | "WMI script" if base.0 == "ok" => ("med", class, "runs a command whenever a WMI event fires. Malware hides here because most tools never look; normal software rarely does this"),
        "AppInit DLL" if base.0 == "ok" => ("med", class, "loads a DLL into every program that opens a window. An old technique, today mostly used by malware"),
        _ => base,
    }
}

/// Version numbers in paths ("...\\Platform\\4.18.26100.4-0\\", "updater 159.0.8140.0") become "#",
/// so an update of the same program does not count as a new startup entry.
pub fn norm_versions(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        // A digit right after another digit was already part of a shorter run that did not fold.
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_digit()) {
            let mut j = i;
            let mut dots = 0;
            while j < b.len() && (b[j].is_ascii_digit() || (b[j] == b'.' && j + 1 < b.len() && b[j + 1].is_ascii_digit())) {
                if b[j] == b'.' {
                    dots += 1;
                }
                j += 1;
            }
            if dots >= 2 {
                out.push('#');
                // "4.18.26100.4-0": the build suffix belongs to the version too
                while j + 1 < b.len() && b[j] == b'-' && b[j + 1].is_ascii_digit() {
                    j += 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                }
                i = j;
                continue;
            }
        }
        out.push(s[i..].chars().next().unwrap_or(' '));
        i += s[i..].chars().next().map(char::len_utf8).unwrap_or(1);
    }
    out
}

/// Risk of a program that starts with Windows: ("high" | "med" | "ok", location, why).
fn startup_risk(name: &str, exe: &str, cmd: &str, sig: &str) -> (&'static str, Class, &'static str) {
    let exe_l = exe.to_lowercase();
    let cmd_l = cmd.to_lowercase();
    let class = detect::classify(&exe_l);
    let file = exe_l.rsplit('\\').next().unwrap_or("");
    let name_l = name.to_lowercase();
    let scripty = ["powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "cmd.exe", "cmd /c", "certutil", "bitsadmin"].iter().any(|s| cmd_l.contains(s));
    let sneaky = ["http://", "https://", "-enc", " -e ", "frombase64", "downloadstring", "downloadfile", "iex", "invoke-expression", "\\appdata\\", "\\temp\\", "hidden", "javascript:", "vbscript:"]
        .iter()
        .any(|s| cmd_l.contains(s));
    let outside = !matches!(class, Class::System | Class::Installed);
    let disguised = outside && sig != "Valid" && WINDOWS_WORDS.iter().any(|w| name_l.contains(w) || file.contains(w));
    let missing = sig == "Missing";
    if disguised && missing {
        ("high", class, "named like part of Windows, but outside the Windows folder, and its file is gone: a typical leftover of removed malware that still runs at every sign-in")
    } else if disguised {
        ("high", class, "named like part of Windows, but outside the Windows folder and not signed by Microsoft")
    } else if class == Class::Risky {
        ("high", class, "runs from a temp, download or bare AppData folder")
    } else if sig == "HashMismatch" {
        ("high", class, "its digital signature is broken: the file was changed after signing")
    } else if scripty && sneaky {
        ("high", class, "starts a hidden, encoded or downloading script")
    } else if missing {
        ("med", class, "points to a file that no longer exists (left behind by something that was removed)")
    } else if outside && sig != "Valid" {
        ("med", class, "unsigned, in a user folder")
    } else {
        ("ok", class, "")
    }
}

/// Compares a check with the baseline (adding "seen" dates and risk notes to `v` for the
/// Status page), updates the baseline, and returns what changed for the worse.
pub fn diff(b: &mut Baseline, v: &mut Value, first: bool, now: u64) -> Vec<Finding> {
    let mut out = Vec::new();
    let quiet = first || !b.set;
    let stamp = if quiet { 0 } else { now };

    // Root certificates: a new one can read HTTPS traffic for whoever holds its key.
    if let Some(roots) = v["roots"].as_array_mut() {
        for r in roots.iter_mut() {
            let tp = r["tp"].as_str().unwrap_or("").to_string();
            if tp.is_empty() {
                continue;
            }
            // Kestryl's own temporary certificate of an HTTPS decryption session: not remembered.
            if r["own"].as_bool() == Some(true) {
                r["seen"] = json!(now);
                continue;
            }
            let seen = *b.roots.entry(tp.clone()).or_insert_with(|| {
                if !quiet {
                    let name = cn(r["subject"].as_str().unwrap_or(""));
                    let key = r["key"].as_bool().unwrap_or(false);
                    out.push(f(
                        "root_cert",
                        if key { 3 } else { 2 },
                        format!("A new root certificate was installed: {name}"),
                        format!("Root certificates decide which websites Windows trusts. A new one lets whoever holds its private key pose as any website to this PC and read its encrypted (HTTPS) traffic. Antivirus web shields, company networks and developer tools (Fiddler, mkcert) add them on purpose; spyware adds them to read your traffic.{} If you don't recognise it, remove it: Win+R → certmgr.msc → Trusted Root Certification Authorities.", if key { " Its private key is ON this PC, so a program here can read your HTTPS traffic right now." } else { "" }),
                        tp.clone(),
                    ));
                }
                stamp
            });
            r["seen"] = json!(seen);
        }
    }

    // Hosts file: name -> address overrides that apply before DNS.
    let mut hosts_v = Vec::new();
    for line in v["hosts"].as_array().cloned().unwrap_or_default() {
        let line = line.as_str().unwrap_or("").to_string();
        let mut parts = line.split_whitespace();
        let Some(ip) = parts.next() else { continue };
        for host in parts {
            let host = host.to_lowercase();
            let key = format!("{ip} {host}");
            let risk = hosts_risk(ip, &host);
            let seen = *b.hosts.entry(key.clone()).or_insert_with(|| {
                if !quiet {
                    let blocking = matches!(ip, "127.0.0.1" | "0.0.0.0" | "::1" | "::");
                    out.push(f(
                        "hosts_changed",
                        match risk { "high" => 3, "med" => 2, _ => 1 },
                        if blocking { format!("The hosts file now blocks {host}") } else { format!("The hosts file now sends {host} to {ip}") },
                        if blocking {
                            format!("A line was added to C:\\Windows\\System32\\drivers\\etc\\hosts that makes {host} unreachable. Ad blockers do this; malware does it to stop antivirus and Windows updates.{}", if risk == "high" { " This one blocks a security or Microsoft site." } else { "" })
                        } else {
                            format!("A line was added to C:\\Windows\\System32\\drivers\\etc\\hosts that sends {host} to {ip} instead of its real server. Developers do this for testing; attackers do it to send you to a fake copy of a site. If you didn't add it, remove the line (Notepad as administrator).")
                        },
                        key.clone(),
                    ));
                }
                stamp
            });
            hosts_v.push(json!({ "ip": ip, "host": host, "risk": risk, "seen": seen }));
        }
    }
    v["hosts_list"] = Value::Array(hosts_v);

    // Programs that start with Windows. The first check after the new places (services,
    // drivers, WMI, Winlogon, IFEO, AppInit, Windows' own task folder) were added learns them quietly.
    let admin = v["admin"].as_bool() == Some(true);
    let upgrade = b.startup_v < 2;
    if let Some(items) = v["startup"].as_array_mut() {
        for it in items.iter_mut() {
            let (wh, name, cmd) = (it["where"].as_str().unwrap_or(""), it["name"].as_str().unwrap_or(""), it["cmd"].as_str().unwrap_or(""));
            let (risk, class, why) = startup_risk_at(wh, name, it["exe"].as_str().unwrap_or(""), cmd, it["sig"].as_str().unwrap_or(""));
            let raw = format!("{wh}|{name}|{cmd}").to_lowercase();
            let key = norm_versions(&raw);
            // Kestryl's own "start with Windows" task is never a finding.
            let mine = it["own"].as_bool() == Some(true);
            let acked = mine || b.ack.contains(&key) || b.ack.contains(&raw);
            let risk = if acked { "ok" } else { risk };
            let new_place = !OLD_PLACES.contains(&wh) || name.to_lowercase().starts_with("\\microsoft\\");
            let quiet = quiet || (upgrade && new_place) || mine;
            // Entries saved before version numbers were folded move to their new key.
            if raw != key {
                if let Some(t) = b.startup.remove(&raw) {
                    b.startup.entry(key.clone()).or_insert(t);
                }
            }
            let seen = *b.startup.entry(key.clone()).or_insert_with(|| {
                if !quiet {
                    out.push(f(
                        "startup_new",
                        match risk { "high" => 3, "med" => 2, _ => 1 },
                        format!("New program set to start with Windows: {name}"),
                        format!("{wh}: {cmd}. Starting with Windows is how most malware survives a restart.{} If you didn't just install something, check it in Task Manager → Startup apps, Task Scheduler, or Autoruns.", if why.is_empty() { String::new() } else { format!(" Why it stands out: {}{}.", why[..1].to_uppercase(), &why[1..]) }),
                        key.clone(),
                    ));
                }
                if quiet { 0 } else { now }
            });
            it["risk"] = json!(risk);
            it["why"] = json!(why);
            it["class"] = json!(class);
            it["seen"] = json!(seen);
            it["key"] = json!(key);
            it["acked"] = json!(acked);
        }
    }
    // Services and WMI are only fully readable as administrator: learn them quietly until then.
    if admin {
        b.startup_v = 2;
    }

    // Defender exclusions (readable as administrator only).
    if v["exclOk"].as_bool() == Some(true) {
        let quiet_ex = quiet || !b.excl_known;
        let mut list = Vec::new();
        for x in v["exclusions"].as_array().cloned().unwrap_or_default() {
            let x = x.as_str().unwrap_or("").to_string();
            let seen = *b.exclusions.entry(x.to_lowercase()).or_insert_with(|| {
                if !quiet_ex {
                    out.push(f(
                        "defender_exclusion",
                        3,
                        format!("Windows Defender was told to skip {x}"),
                        "Antivirus exclusions make Defender ignore a folder, file type or program. Malware adds its own folder here so it is never scanned. If you or your IT did not add it, remove it: Windows Security → Virus & threat protection → Manage settings → Exclusions.".into(),
                        x.to_lowercase(),
                    ));
                }
                if quiet_ex { 0 } else { now }
            });
            list.push(json!({ "v": x, "seen": seen }));
        }
        b.excl_known = true;
        v["exclusions"] = Value::Array(list);
    }

    // Antivirus products registered with Windows Security Center.
    let mut other_av_on = false;
    if let Some(avs) = v["av"].as_array_mut() {
        for a in avs.iter_mut() {
            let st = a["state"].as_i64().unwrap_or(0);
            let on = (st >> 12) & 0xF == 1;
            let fresh = (st >> 4) & 0xF == 0;
            a["on"] = json!(on);
            a["uptodate"] = json!(fresh);
            if on && !a["name"].as_str().unwrap_or("").to_lowercase().contains("defender") {
                other_av_on = true;
            }
        }
    }
    v["other_av"] = json!(other_av_on);

    if let Some(rtp) = v["defender"]["rtp"].as_bool() {
        if b.rtp == Some(true) && !rtp && !quiet {
            out.push(f(
                "defender_off",
                if other_av_on { 1 } else { 3 },
                "Windows Defender real-time protection was turned off".into(),
                if other_av_on {
                    "Another antivirus is active, which normally switches Defender off. Fine if you installed it.".into()
                } else {
                    "Nothing is scanning new files any more. Malware turns this off first. Turn it back on: Windows Security → Virus & threat protection → Manage settings → Real-time protection.".into()
                },
                "rtp".into(),
            ));
        }
        b.rtp = Some(rtp);
    }

    // Windows Firewall profiles.
    let on_now: Vec<String> = v["firewall"]
        .as_array()
        .map(|a| a.iter().filter(|p| p["on"].as_bool() == Some(true)).filter_map(|p| p["name"].as_str().map(String::from)).collect())
        .unwrap_or_default();
    if v["firewall"].as_array().is_some_and(|a| !a.is_empty()) {
        if !quiet {
            for p in b.fw_on.iter().filter(|p| !on_now.contains(p)) {
                out.push(f(
                    "fw_off",
                    3,
                    format!("Windows Firewall was turned off ({p} networks)"),
                    "With the firewall off, Kestryl's blocks stop working and other devices can reach every listening program. Malware turns it off. Turn it back on: Windows Security → Firewall & network protection.".into(),
                    format!("fw-{p}"),
                ));
            }
        }
        b.fw_on = on_now;
    }

    // Proxy: everything the browser sends goes there first.
    let px = &v["proxy"];
    let pcur = format!(
        "{}|{}|{}|{}",
        px["on"].as_bool().unwrap_or(false),
        px["server"].as_str().unwrap_or(""),
        px["pac"].as_str().unwrap_or(""),
        px["winhttp"].as_str().unwrap_or("")
    );
    let active = px["on"].as_bool() == Some(true) || !px["pac"].as_str().unwrap_or("").is_empty() || !px["winhttp"].as_str().unwrap_or("").is_empty();
    // Kestryl's own proxy during an HTTPS decryption session is neither reported nor remembered.
    let own_proxy = px["own"].as_bool() == Some(true);
    if !quiet && !own_proxy && pcur != b.proxy && active {
        let target = [px["server"].as_str().unwrap_or(""), px["pac"].as_str().unwrap_or(""), px["winhttp"].as_str().unwrap_or("")]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("a proxy")
            .to_string();
        out.push(f(
            "proxy_changed",
            2,
            "Your internet proxy was changed".into(),
            format!("Web traffic now goes through {target} first. Company networks and some VPN or privacy tools set this; malware sets it to read or change what you browse. If you don't know it, turn it off: Settings → Network & internet → Proxy."),
            "proxy".into(),
        ));
    }
    if !own_proxy {
        b.proxy = pcur;
    }

    // DNS servers: report a public server that is neither well-known nor seen before.
    let mut dns_v = Vec::new();
    let mut known: HashSet<String> = b.dns.iter().cloned().collect();
    for iface in v["dns"].as_array().cloned().unwrap_or_default() {
        let mut servers = Vec::new();
        for s in iface["servers"].as_array().cloned().unwrap_or_default() {
            let ip = s.as_str().unwrap_or("").to_string();
            let sc = ip.parse::<std::net::IpAddr>().map(|a| scope(&a)).unwrap_or(Scope::Lan);
            let label = dns_label(&ip);
            let kind = if sc != Scope::Internet { "local" } else if label.is_some() { "known" } else { "unknown" };
            if known.insert(ip.clone()) && !quiet && kind == "unknown" {
                out.push(f(
                    "dns_changed",
                    2,
                    format!("A new DNS server is in use: {ip}"),
                    format!("{} now asks {ip} to turn names into addresses. Whoever runs a DNS server can send you to fake sites. VPNs and internet providers change it legitimately; malware and fake Wi-Fi hotspots do it to redirect you. Look it up with IP info on the Network tab.", iface["iface"].as_str().unwrap_or("A network adapter")),
                    ip.clone(),
                ));
            }
            servers.push(json!({ "ip": ip, "kind": kind, "label": label.unwrap_or("") }));
        }
        dns_v.push(json!({ "iface": iface["iface"], "servers": servers }));
    }
    let mut kv: Vec<String> = known.into_iter().collect();
    kv.sort();
    kv.truncate(100);
    b.dns = kv;
    v["dns"] = Value::Array(dns_v);

    if let Some(rdp) = v["rdp"].as_bool() {
        if b.rdp == Some(false) && rdp && !quiet {
            out.push(f(
                "rdp_on",
                2,
                "Remote Desktop was turned on".into(),
                "Anyone who can reach this PC and knows (or guesses) a Windows password can now log in remotely. Fine if you or your IT turned it on; otherwise turn it off: Settings → System → Remote Desktop.".into(),
                "rdp".into(),
            ));
        }
        b.rdp = Some(rdp);
    }

    b.set = true;
    out
}

/// A cheap fingerprint of the places programs use to start with Windows: the last-write
/// times of the Run, Services, Winlogon, IFEO and AppInit keys, and of the Startup and
/// Tasks folders. Checked every 20 s; a change runs the full security check right away
/// instead of waiting up to 15 minutes.
#[cfg(windows)]
pub fn quick_fingerprint() -> u64 {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};
    use winreg::RegKey;
    let mut acc = String::new();
    let keys: [(bool, &str); 11] = [
        (false, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (false, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (false, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (true, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (true, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (true, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (true, r"SYSTEM\CurrentControlSet\Services"),
        (true, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        (true, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        (true, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        (true, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
    ];
    for (lm, path) in keys {
        let root = RegKey::predef(if lm { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
        if let Ok(k) = root.open_subkey_with_flags(path, KEY_READ) {
            if let Ok(m) = k.query_info() {
                let ft = m.last_write_time;
                acc.push_str(&format!("{path}:{}:{}:{}:{};", ft.dwHighDateTime, ft.dwLowDateTime, m.sub_keys, m.values));
            }
        }
    }
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    if let Some(a) = std::env::var_os("APPDATA") {
        dirs.push(std::path::PathBuf::from(a).join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    // System folders from the API, not from variables a program could override to blind this.
    let drive = windows_dir().to_string_lossy().chars().take(2).collect::<String>();
    dirs.push(std::path::PathBuf::from(format!(r"{drive}\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")));
    // Every folder of the task store (needs administrator rights to read; without them it simply adds nothing).
    let mut stack = vec![windows_dir().join(r"System32\Tasks")];
    while let Some(d) = stack.pop() {
        dirs.push(d.clone());
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                if e.file_type().is_ok_and(|t| t.is_dir()) && dirs.len() + stack.len() < 2000 {
                    stack.push(e.path());
                }
            }
        }
    }
    for d in dirs {
        if let Ok(t) = std::fs::metadata(&d).and_then(|m| m.modified()) {
            acc.push_str(&format!("{}:{:?};", d.display(), t));
        }
    }
    fnv(&acc)
}

#[cfg(not(windows))]
pub fn quick_fingerprint() -> u64 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "defender": { "rtp": true, "sigAge": 1 },
            "exclOk": true, "exclusions": ["C:\\Tools"],
            "av": [{ "name": "Microsoft Defender Antivirus", "state": 397568 }],
            "firewall": [{ "name": "Domain", "on": true }, { "name": "Private", "on": true }, { "name": "Public", "on": true }],
            "roots": [{ "tp": "AA", "subject": "CN=Good Root, O=Good", "key": false }],
            "proxy": { "on": false, "server": "", "pac": "", "winhttp": "" },
            "hosts": ["127.0.0.1 localhost"],
            "startup": [{ "where": "HKCU Run", "name": "OneDrive", "cmd": "\"C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", "exe": "C:\\Users\\a\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "sig": "Valid" }],
            "dns": [{ "iface": "Wi-Fi", "servers": ["192.168.1.1"] }],
            "rdp": false,
            "fwRules": [],
        })
    }

    #[test]
    fn first_run_is_quiet_then_changes_alert() {
        let mut b = Baseline::default();
        let mut v = sample();
        assert!(diff(&mut b, &mut v, false, 1000).is_empty(), "first run sets the baseline silently");
        assert!(b.set && b.excl_known);
        assert_eq!(v["av"][0]["on"], true);
        assert_eq!(v["startup"][0]["risk"], "ok");

        let mut v = sample();
        v["roots"].as_array_mut().unwrap().push(json!({ "tp": "BB", "subject": "CN=Sneaky Proxy CA", "key": true }));
        v["exclusions"].as_array_mut().unwrap().push(json!("C:\\Users\\a\\AppData\\Roaming\\x"));
        v["firewall"][2]["on"] = json!(false);
        v["defender"]["rtp"] = json!(false);
        v["proxy"] = json!({ "on": true, "server": "127.0.0.1:8888", "pac": "", "winhttp": "" });
        v["hosts"].as_array_mut().unwrap().push(json!("203.0.113.66 www.mybank.example"));
        v["hosts"].as_array_mut().unwrap().push(json!("127.0.0.1 update.microsoft.com"));
        v["startup"].as_array_mut().unwrap().push(json!({ "where": "HKCU Run", "name": "svc", "cmd": "powershell -w hidden -enc AAAA", "exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "sig": "Valid" }));
        v["dns"][0]["servers"].as_array_mut().unwrap().push(json!("198.51.100.53"));
        v["rdp"] = json!(true);
        let found = diff(&mut b, &mut v, false, 2000);
        let rules: Vec<(&str, u8)> = found.iter().map(|f| (f.rule, f.sev)).collect();
        for want in [("root_cert", 3), ("defender_exclusion", 3), ("fw_off", 3), ("defender_off", 3), ("proxy_changed", 2), ("hosts_changed", 3), ("startup_new", 3), ("dns_changed", 2), ("rdp_on", 2)] {
            assert!(rules.contains(&want), "missing {want:?} in {rules:?}");
        }
        assert_eq!(rules.iter().filter(|r| r.0 == "hosts_changed").count(), 2);
        assert_eq!(v["roots"][1]["seen"], 2000);
        assert_eq!(v["roots"][0]["seen"], 0);
        // the same state again: nothing new
        let mut again = v.clone();
        again["exclusions"] = json!(["C:\\Tools", "C:\\Users\\a\\AppData\\Roaming\\x"]);
        again["dns"] = json!([{ "iface": "Wi-Fi", "servers": ["192.168.1.1", "198.51.100.53"] }]);
        assert!(diff(&mut b, &mut again, false, 3000).is_empty());
    }

    #[test]
    fn small_helpers() {
        assert_eq!(cn("CN=Foo Root CA, O=Foo Inc, C=US"), "Foo Root CA");
        assert_eq!(dns_label("45.90.28.10"), Some("NextDNS"));
        assert_eq!(hosts_risk("0.0.0.0", "ads.example.com"), "ok");
        assert_eq!(hosts_risk("0.0.0.0", "go.microsoft.com"), "high");
        assert_eq!(hosts_risk("192.168.1.5", "nas.home"), "ok");
        assert_eq!(hosts_risk("192.168.1.50", "host.docker.internal"), "ok");
        assert_eq!(hosts_risk("203.0.113.9", "app.example.com"), "med");
        assert_eq!(startup_risk("x", r"C:\Users\a\AppData\Local\Temp\x.exe", "x.exe", "NotSigned").0, "high");
        assert_eq!(startup_risk("App", r"C:\Program Files\App\app.exe", "app.exe", "Valid").0, "ok");
        assert_eq!(startup_risk("Tool", r"C:\Users\a\AppData\Roaming\Tool\tool.exe", "tool.exe", "NotSigned").0, "med");
        // Windows look-alikes outside the Windows folder: high, even more so when the file is gone
        let fake = startup_risk("SecurityHealthService", r"C:\ProgramData\Microsoft\Windows\SecurityHealth\SecurityHealthHost.exe", "x", "Missing");
        assert_eq!(fake.0, "high");
        assert!(fake.2.contains("leftover"));
        assert_eq!(startup_risk("OneDrive Standalone Update Task", r"C:\Users\a\AppData\Local\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe", "x", "Valid").0, "ok");
        assert_eq!(startup_risk("Old app", r"C:\Users\a\AppData\Local\Old\old.exe", "x", "Missing").0, "med");
    }

    #[test]
    fn versions_fold_and_places_have_their_own_risk() {
        assert_eq!(norm_versions(r"service|x|c:\programdata\microsoft\windows defender\platform\4.18.26100.4-0\msmpeng.exe"), r"service|x|c:\programdata\microsoft\windows defender\platform\#\msmpeng.exe");
        assert_eq!(norm_versions("googleupdaterservice159.0.8140.0 (x)|c:\\g\\159.0.8140.0\\updater.exe"), "googleupdaterservice# (x)|c:\\g\\#\\updater.exe");
        assert_eq!(norm_versions("hkcu run|app|\"c:\\app\\app.exe\" --port 8080"), "hkcu run|app|\"c:\\app\\app.exe\" --port 8080");
        let sys = r"C:\Windows\System32\userinit.exe";
        assert_eq!(startup_risk_at("Winlogon Userinit", "Userinit", sys, "C:\\Windows\\system32\\userinit.exe,C:\\x\\evil.exe", "Valid").0, "high");
        assert_eq!(startup_risk_at("Accessibility tool", "sethc.exe (really Cmd.Exe)", r"C:\Windows\System32\sethc.exe", "", "Valid").0, "high");
        assert_eq!(startup_risk_at("IFEO debugger", "sethc.exe", r"C:\Windows\System32\cmd.exe", "cmd.exe", "Valid").0, "high");
        assert_eq!(startup_risk_at("IFEO debugger", "taskmgr.exe", r"C:\Tools\procexp64.exe", r"C:\Tools\procexp64.exe", "Valid").0, "ok");
        assert_eq!(startup_risk_at("WMI subscription", "x", sys, "powershell -c 1", "Valid").0, "med");
        assert_eq!(startup_risk_at("Service", "Good (good)", r"C:\Program Files\Good\svc.exe", "x", "Valid").0, "ok");
    }

    #[test]
    fn new_places_are_learned_quietly_once() {
        let mut b = Baseline { set: true, ..Default::default() };
        b.startup.insert("hkcu run|onedrive|c:\\od\\25.1.2.3\\onedrive.exe".into(), 0);
        let mut v = sample();
        v["admin"] = json!(true);
        v["startup"] = json!([
            { "where": "Service", "name": "Evil (evil)", "cmd": "C:\\Users\\a\\AppData\\Local\\Temp\\e.exe", "exe": "C:\\Users\\a\\AppData\\Local\\Temp\\e.exe", "sig": "NotSigned" },
            { "where": "HKCU Run", "name": "OneDrive", "cmd": "C:\\od\\25.1.2.3\\onedrive.exe", "exe": "C:\\od\\25.1.2.3\\onedrive.exe", "sig": "Valid" },
        ]);
        let found = diff(&mut b, &mut v, false, 1000);
        assert!(found.iter().all(|f| f.rule != "startup_new"), "{found:?}");
        assert_eq!(b.startup_v, 2);
        assert!(b.startup.contains_key("hkcu run|onedrive|c:\\od\\#\\onedrive.exe")); // moved to the version-free key
        // next check: a new service is reported, an OneDrive update is not
        v["startup"] = json!([
            { "where": "Service", "name": "Other (other)", "cmd": "C:\\Users\\a\\AppData\\Local\\Temp\\o.exe", "exe": "C:\\Users\\a\\AppData\\Local\\Temp\\o.exe", "sig": "NotSigned" },
            { "where": "HKCU Run", "name": "OneDrive", "cmd": "C:\\od\\25.9.9.9\\onedrive.exe", "exe": "C:\\od\\25.9.9.9\\onedrive.exe", "sig": "Valid" },
        ]);
        let found = diff(&mut b, &mut v, false, 2000);
        let s: Vec<&Finding> = found.iter().filter(|f| f.rule == "startup_new").collect();
        assert_eq!(s.len(), 1, "{found:?}");
        assert_eq!(s[0].sev, 3);
    }
}
