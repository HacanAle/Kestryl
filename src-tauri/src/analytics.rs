//! "Block analytics": switches off the usage data (telemetry) that Windows, Edge, Office and
//! Chrome send home, with the official policy settings each product documents, plus a
//! firewall block on Windows' telemetry service and on the servers that only collect
//! telemetry. Every change is undone exactly: before setting a value Kestryl records what was
//! there (or that nothing was), and "off" puts that back.
//! Needs administrator rights. The hosts file is deliberately not used: Microsoft Defender
//! treats telemetry entries there as a hijack (SettingsModifier:Win32/HostsFileHijack).

use crate::util::*;
use serde_json::{json, Value};

pub struct Item {
    pub id: &'static str,
    pub name: &'static str,
    pub what: &'static str,
    /// What the user notices.
    pub side: &'static str,
    /// (registry key, DWORD value name, value)
    pub regs: &'static [(&'static str, &'static str, u32)],
    /// Windows services set to Disabled (and stopped).
    pub svcs: &'static [&'static str],
    /// Windows service whose outgoing traffic is blocked in the firewall.
    pub fw_service: Option<&'static str>,
}

pub const ITEMS: [Item; 4] = [
    Item {
        id: "windows",
        name: "Windows diagnostic data",
        what: "Sets Windows' diagnostic data to the lowest level the edition allows, turns off the advertising ID, tailored experiences, activity-history upload, app inventory, crash-report uploads and feedback prompts, stops the Connected User Experiences and Telemetry service (DiagTrack) and blocks it in the firewall.",
        side: "Feedback Hub can no longer send feedback, Windows Insider builds stop updating, and crash reports are not sent to Microsoft. Windows Update, Defender and the Store keep working.",
        regs: &[
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowTelemetry", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "DoNotShowFeedbackNotifications", 1),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "AllowDeviceNameInTelemetry", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "LimitDiagnosticLogCollection", 1),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection", "LimitDumpCollection", 1),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo", "DisabledByGroupPolicy", 1),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System", "UploadUserActivities", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\System", "PublishUserActivities", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat", "AITEnable", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat", "DisableInventory", 1),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting", "Disabled", 1),
            (r"HKCU:\Software\Policies\Microsoft\Windows\CloudContent", "DisableTailoredExperiencesWithDiagnosticData", 1),
        ],
        svcs: &["DiagTrack"],
        fw_service: Some("DiagTrack"),
    },
    Item {
        id: "edge",
        name: "Microsoft Edge",
        what: "Turns off Edge's diagnostic data, personalisation reporting, feedback, shopping assistant (which sends the pages you visit to Microsoft) and recommendations, and asks sites not to track you.",
        side: "Edge shows \"Your browser is managed by your organization\". That only means these settings are fixed; nothing else is managed.",
        regs: &[
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "DiagnosticData", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "PersonalizationReportingEnabled", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "UserFeedbackAllowed", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "EdgeShoppingAssistantEnabled", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "ShowRecommendationsEnabled", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "SpotlightExperiencesAndRecommendationsEnabled", 0),
            (r"HKLM:\SOFTWARE\Policies\Microsoft\Edge", "ConfigureDoNotTrack", 1),
        ],
        svcs: &[],
        fw_service: None,
    },
    Item {
        id: "office",
        name: "Microsoft Office",
        what: "Stops Word, Excel, Outlook and the other Office apps from sending usage telemetry, and turns off the feedback button and its screenshots.",
        side: "The \"Send feedback\" button in Office disappears. Documents, sign-in and OneDrive are not affected.",
        regs: &[
            (r"HKCU:\Software\Policies\Microsoft\Office\Common\ClientTelemetry", "SendTelemetry", 3),
            (r"HKCU:\Software\Policies\Microsoft\Office\16.0\Common\ClientTelemetry", "DisableTelemetry", 1),
            (r"HKCU:\Software\Policies\Microsoft\Office\16.0\Common\ClientTelemetry", "SendTelemetry", 3),
            (r"HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback", "Enabled", 0),
            (r"HKCU:\Software\Policies\Microsoft\Office\16.0\Common\Feedback", "IncludeScreenshot", 0),
        ],
        svcs: &[],
        fw_service: None,
    },
    Item {
        id: "chrome",
        name: "Google Chrome",
        what: "Turns off Chrome's usage statistics and crash reports, the \"make searches and browsing better\" upload of the pages you visit, feedback, and the extended Safe Browsing reports that send page content to Google.",
        side: "Chrome shows \"Managed by your organization\". Normal Safe Browsing protection stays on.",
        regs: &[
            (r"HKLM:\SOFTWARE\Policies\Google\Chrome", "MetricsReportingEnabled", 0),
            (r"HKLM:\SOFTWARE\Policies\Google\Chrome", "UrlKeyedAnonymizedDataCollectionEnabled", 0),
            (r"HKLM:\SOFTWARE\Policies\Google\Chrome", "UserFeedbackAllowed", 0),
            (r"HKLM:\SOFTWARE\Policies\Google\Chrome", "SafeBrowsingExtendedReportingEnabled", 0),
        ],
        svcs: &[],
        fw_service: None,
    },
];

/// Servers that do nothing but collect usage data: (blocked domain and its subdomains,
/// names to resolve now so the firewall rule has addresses from the start).
pub const SERVERS: [(&str, &[&str]); 8] = [
    ("events.data.microsoft.com", &["v10.events.data.microsoft.com", "v20.events.data.microsoft.com", "self.events.data.microsoft.com", "mobile.events.data.microsoft.com", "umwatson.events.data.microsoft.com", "browser.events.data.microsoft.com"]),
    ("vortex.data.microsoft.com", &["vortex.data.microsoft.com"]),
    ("vortex-win.data.microsoft.com", &["vortex-win.data.microsoft.com"]),
    ("telemetry.microsoft.com", &["watson.telemetry.microsoft.com", "oca.telemetry.microsoft.com", "telecommand.telemetry.microsoft.com"]),
    ("browser.events.data.msn.com", &["browser.events.data.msn.com"]),
    ("nexus.officeapps.live.com", &["nexus.officeapps.live.com", "nexusrules.officeapps.live.com"]),
    ("events.gfe.nvidia.com", &["events.gfe.nvidia.com"]),
    ("dc.services.visualstudio.com", &["dc.services.visualstudio.com"]),
];
pub const SERVERS_ID: &str = "servers";
pub const SERVERS_NAME: &str = "Known analytics servers (all programs)";
pub const SERVERS_WHAT: &str = "Blocks, for every program, the servers Microsoft (Windows, Office, Edge, Visual Studio Code), NVIDIA and other apps use only to collect usage data. Kestryl adds their new addresses as they show up.";
pub const SERVERS_SIDE: &str = "Nothing visible: these servers only receive statistics.";

pub fn item(id: &str) -> Option<&'static Item> {
    ITEMS.iter().find(|i| i.id == id)
}

/// Firewall rule id of an item's service block.
pub fn fw_id(id: &str) -> String {
    format!("Kestryl-analytics-{id}")
}

const HELPERS: &str = r#"$bk = New-Object System.Collections.ArrayList
function SetV($path, $name, $val) {
  try {
    $had = $false; $old = $null
    if (Test-Path -LiteralPath $path) {
      $p = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
      if ($p -and ($p.PSObject.Properties.Name -contains $name)) { $had = $true; $old = $p.$name }
    } else { New-Item -Path $path -Force | Out-Null }
    [void]$bk.Add([pscustomobject]@{ k = 'reg'; path = $path; name = $name; had = $had; old = $old })
    New-ItemProperty -LiteralPath $path -Name $name -PropertyType DWord -Value $val -Force | Out-Null
  } catch { [void]$bk.Add([pscustomobject]@{ k = 'err'; msg = "$path\$name : " + $_.Exception.Message }) }
}
function OffSvc($n) {
  try {
    $s = Get-Service -Name $n -ErrorAction SilentlyContinue
    if (-not $s) { return }
    [void]$bk.Add([pscustomobject]@{ k = 'svc'; name = $n; old = [string]$s.StartType; run = ($s.Status -eq 'Running') })
    Stop-Service -Name $n -Force -ErrorAction SilentlyContinue
    Set-Service -Name $n -StartupType Disabled
  } catch { [void]$bk.Add([pscustomobject]@{ k = 'err'; msg = "service $n : " + $_.Exception.Message }) }
}
function FwSvc($n, $id, $desc) {
  try {
    Remove-NetFirewallRule -Name $id -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $id -Group 'Kestryl' -DisplayName "Kestryl: block $n (analytics)" -Description $desc -Direction Outbound -Action Block -Profile Any -Program "$env:SystemRoot\System32\svchost.exe" -Service $n | Out-Null
    [void]$bk.Add([pscustomobject]@{ k = 'fw'; name = $id })
  } catch { [void]$bk.Add([pscustomobject]@{ k = 'err'; msg = "firewall $n : " + $_.Exception.Message }) }
}
"#;

/// PowerShell that applies one item and prints the list of what it changed (for undo).
pub fn apply_script(it: &Item) -> String {
    let mut s = String::from(HELPERS);
    for (path, name, val) in it.regs {
        s += &format!("SetV {} {} {val}\n", ps_quote(path), ps_quote(name));
    }
    for svc in it.svcs {
        s += &format!("OffSvc {}\n", ps_quote(svc));
    }
    if let Some(svc) = it.fw_service {
        s += &format!("FwSvc {} {} {}\n", ps_quote(svc), ps_quote(&fw_id(it.id)), ps_quote(&format!("kestryl:analytics:{}", it.id)));
    }
    s += "ConvertTo-Json -InputObject @($bk) -Compress -Depth 3";
    s
}

/// PowerShell that puts back what `apply_script` changed, newest change first.
pub fn restore_script(backup: &Value) -> String {
    format!(
        r#"# Windows PowerShell 5.1 hands a JSON array over as one object: unroll it.
$bk = @(ConvertFrom-Json -InputObject {} | ForEach-Object {{ $_ }})
[array]::Reverse($bk)
$errs = @()
foreach ($b in $bk) {{
  try {{
    if ($b.k -eq 'reg') {{
      if ($b.had) {{ New-ItemProperty -LiteralPath $b.path -Name $b.name -PropertyType DWord -Value $b.old -Force | Out-Null }}
      else {{ Remove-ItemProperty -LiteralPath $b.path -Name $b.name -ErrorAction SilentlyContinue }}
    }} elseif ($b.k -eq 'svc') {{
      if ($b.old -eq 'AutomaticDelayedStart') {{ sc.exe config $b.name start= delayed-auto | Out-Null }} else {{ Set-Service -Name $b.name -StartupType $b.old }}
      if ($b.run) {{ Start-Service -Name $b.name -ErrorAction SilentlyContinue }}
    }} elseif ($b.k -eq 'fw') {{ Remove-NetFirewallRule -Name $b.name -ErrorAction SilentlyContinue }}
  }} catch {{ $errs += $_.Exception.Message }}
}}
$errs -join '; '"#,
        ps_quote(&backup.to_string())
    )
}

/// Runs the apply script: Ok((backup to keep, problems)).
pub fn apply(it: &Item) -> Result<(Value, Vec<String>), String> {
    let out = run_ps_timeout(&apply_script(it), 90)?;
    let v: Value = serde_json::from_str(&out).map_err(|e| format!("unexpected output ({e})"))?;
    let all = match v {
        Value::Array(a) => a,
        o => vec![o],
    };
    let errs: Vec<String> = all.iter().filter(|b| b["k"] == "err").filter_map(|b| b["msg"].as_str().map(String::from)).collect();
    let backup: Vec<Value> = all.into_iter().filter(|b| b["k"] != "err").collect();
    Ok((Value::Array(backup), errs))
}

/// Puts back what `apply` changed for `it`. The backup is read from config.json, which lives
/// in the user's folder where any program the user runs can edit it, so only entries `apply`
/// could have written for this item are restored: its own registry values (as numbers), its
/// own services (to a normal start type) and its own firewall rule. Nothing else, whatever the
/// file says, is written as administrator.
pub fn restore(it: &Item, backup: &Value) -> Result<String, String> {
    let safe = sanitize_backup(it, backup);
    if safe.as_array().is_none_or(|a| a.is_empty()) {
        return Ok(String::new());
    }
    run_ps_timeout(&restore_script(&safe), 90)
}

pub fn sanitize_backup(it: &Item, backup: &Value) -> Value {
    let s = |b: &Value, k: &str| b[k].as_str().unwrap_or("").to_string();
    let ok = |b: &Value| -> bool {
        match b["k"].as_str() {
            Some("reg") => {
                let (path, name) = (s(b, "path"), s(b, "name"));
                it.regs.iter().any(|(p, n, _)| p.eq_ignore_ascii_case(&path) && n.eq_ignore_ascii_case(&name))
                    && (b["had"] != Value::Bool(true) || b["old"].as_i64().is_some_and(|v| v >= i32::MIN as i64 && v <= u32::MAX as i64))
            }
            Some("svc") => {
                it.svcs.iter().any(|x| x.eq_ignore_ascii_case(&s(b, "name")))
                    && matches!(s(b, "old").as_str(), "Automatic" | "AutomaticDelayedStart" | "Manual" | "Disabled")
            }
            Some("fw") => s(b, "name") == fw_id(it.id),
            _ => false,
        }
    };
    Value::Array(backup.as_array().map(|a| a.iter().filter(|b| ok(b)).cloned().collect()).unwrap_or_default())
}

/// Domains of usage-data services in general (also web analytics and crash reporters), to
/// label connections "usage data" in the UI. Not all of them are blocked.
const ANALYTICS: [&str; 24] = [
    "events.data.microsoft.com", "vortex.data.microsoft.com", "vortex-win.data.microsoft.com", "telemetry.microsoft.com",
    "browser.events.data.msn.com", "nexus.officeapps.live.com", "nexusrules.officeapps.live.com", "events.gfe.nvidia.com",
    "dc.services.visualstudio.com", "in.appcenter.ms", "app-measurement.com", "google-analytics.com", "analytics.google.com",
    "doubleclick.net", "sentry.io", "bugsnag.com", "api.segment.io", "mixpanel.com", "amplitude.com", "scorecardresearch.com",
    "hotjar.com", "clarity.ms", "telemetry.mozilla.org", "incoming.telemetry.mozilla.org",
];

pub fn is_analytics(domain: &str) -> bool {
    !domain.is_empty() && ANALYTICS.iter().any(|d| domain_is(domain, d))
}

pub fn list(state: &std::collections::HashMap<String, crate::config::AnalyticsState>) -> Value {
    let mut v: Vec<Value> = ITEMS
        .iter()
        .map(|i| {
            let s = state.get(i.id);
            json!({ "id": i.id, "name": i.name, "what": i.what, "side": i.side, "on": s.is_some_and(|s| s.on), "t": s.map(|s| s.t).unwrap_or(0),
                    "errors": s.map(|s| s.errors.clone()).unwrap_or_default() })
        })
        .collect();
    let s = state.get(SERVERS_ID);
    v.push(json!({ "id": SERVERS_ID, "name": SERVERS_NAME, "what": SERVERS_WHAT, "side": SERVERS_SIDE, "on": s.is_some_and(|s| s.on),
                   "t": s.map(|s| s.t).unwrap_or(0), "errors": s.map(|s| s.errors.clone()).unwrap_or_default(),
                   "domains": SERVERS.iter().map(|(d, _)| *d).collect::<Vec<_>>() }));
    Value::Array(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripts_and_labels() {
        let s = apply_script(item("windows").unwrap());
        assert!(s.contains("SetV 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' 'AllowTelemetry' 0"));
        assert!(s.contains("OffSvc 'DiagTrack'") && s.contains("FwSvc 'DiagTrack' 'Kestryl-analytics-windows'"));
        let r = restore_script(&json!([{ "k": "reg", "path": "HKCU:\\x", "name": "y", "had": false, "old": null }]));
        assert!(r.contains("ConvertFrom-Json -InputObject '[{"));
        assert!(is_analytics("v10.events.data.microsoft.com") && is_analytics("www.google-analytics.com"));
        assert!(!is_analytics("data.microsoft.com") && !is_analytics("settings-win.data.microsoft.com"));
    }

    /// A backup edited by another program must not make the elevated restore write anything
    /// the item never changed (UAC off, Defender off, another service, another rule).
    #[test]
    fn tampered_backup_is_ignored() {
        let it = item("windows").unwrap();
        let b = json!([
            { "k": "reg", "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "name": "AllowTelemetry", "had": true, "old": 3 },
            { "k": "reg", "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "name": "EnableLUA", "had": true, "old": 0 },
            { "k": "reg", "path": "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", "name": "AllowTelemetry", "had": true, "old": "evil" },
            { "k": "svc", "name": "DiagTrack", "old": "Automatic", "run": true },
            { "k": "svc", "name": "WinDefend", "old": "Disabled", "run": false },
            { "k": "svc", "name": "DiagTrack", "old": "Boot", "run": false },
            { "k": "fw", "name": "Kestryl-analytics-windows" },
            { "k": "fw", "name": "CoreNet-DHCP-In" },
            { "k": "other" }
        ]);
        let safe = sanitize_backup(it, &b);
        let a = safe.as_array().unwrap();
        assert_eq!(a.len(), 3, "{safe}");
        assert_eq!(a[0]["name"], "AllowTelemetry");
        assert_eq!(a[1]["name"], "DiagTrack");
        assert_eq!(a[2]["name"], "Kestryl-analytics-windows");
    }

    /// Run by hand, NOT elevated: applies and undoes a fake item under HKCU (no admin needed),
    /// proving the PowerShell records and restores values exactly.
    #[test]
    #[ignore]
    fn live_apply_and_restore_in_hkcu() {
        const TEST: Item = Item {
            id: "test",
            name: "test",
            what: "",
            side: "",
            regs: &[(r"HKCU:\Software\KestrylTest\Deep\Key", "A", 7), (r"HKCU:\Software\KestrylTest\Deep\Key", "B", 1)],
            svcs: &[],
            fw_service: None,
        };
        let _ = run_ps(r"Remove-Item -LiteralPath 'HKCU:\Software\KestrylTest' -Recurse -ErrorAction SilentlyContinue; New-Item -Path 'HKCU:\Software\KestrylTest\Deep\Key' -Force | Out-Null; New-ItemProperty -LiteralPath 'HKCU:\Software\KestrylTest\Deep\Key' -Name B -PropertyType DWord -Value 5 | Out-Null");
        let (backup, errs) = apply(&TEST).unwrap();
        assert!(errs.is_empty(), "{errs:?}");
        let now = run_ps(r"$p = Get-ItemProperty 'HKCU:\Software\KestrylTest\Deep\Key'; '' + $p.A + ',' + $p.B").unwrap();
        assert_eq!(now, "7,1");
        println!("backup: {backup}");
        restore(&TEST, &backup).unwrap();
        let back = run_ps(r"$p = Get-ItemProperty 'HKCU:\Software\KestrylTest\Deep\Key'; '' + ($null -eq $p.A) + ',' + $p.B").unwrap();
        assert_eq!(back, "True,5", "A removed again, B back to 5");
        let _ = run_ps(r"Remove-Item -LiteralPath 'HKCU:\Software\KestrylTest' -Recurse");
    }
}
